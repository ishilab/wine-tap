/*
 * libtcpserv.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "utils.h"
#include "libtcpserv.h"
#include "libworkqueue.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libtcpserv"

#define libtcpserv_priv_of(s) ((struct libtcpserv_priv*)&((s)->priv))

static struct {
    pthread_mutex_t mutex;
    bool is_initialized;

    struct libworkqueue_struct *workqueue;
} libtcpserv;

struct libtcpserv_priv {
    int sock;
    struct sockaddr_in addr;
    int listen_backlog;

    void* (*user_handler)(int, void*);
    void* user_arg;

    pthread_t listen_thread;
    pthread_mutex_t mutex;

    bool is_canceled;
};

static inline void debug_priv_mapping_info(struct libtcpserv_struct *s)
{
    const struct libtcpserv_priv *priv = libtcpserv_priv_of(s);
    print_log(MSG_DBG,
            "s: %p, priv: %p, "
            STRUCTURE_MEMBER_MAP_FMT(sock) ", "
            STRUCTURE_MEMBER_MAP_FMT(addr) ", "
            STRUCTURE_MEMBER_MAP_FMT(listen_backlog) ", "
            STRUCTURE_MEMBER_MAP_FMT(user_handler) ", "
            STRUCTURE_MEMBER_MAP_FMT(user_arg) ", "
            STRUCTURE_MEMBER_MAP_FMT(listen_thread) ", "
            STRUCTURE_MEMBER_MAP_FMT(mutex) ", "
            STRUCTURE_MEMBER_MAP_FMT(is_canceled) ", "
            "\n",
            s, priv,
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, sock),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, addr),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, listen_backlog),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, user_handler),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, user_arg),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, listen_thread),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, mutex),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libtcpserv_priv, is_canceled));
}

static inline void priv_lock(struct libtcpserv_priv *priv)
{
    pthread_mutex_lock(&priv->mutex);
}

static inline void priv_unlock(struct libtcpserv_priv *priv)
{
    pthread_mutex_unlock(&priv->mutex);
}

static inline bool get_is_canceled(struct libtcpserv_priv *priv)
{
    priv_lock(priv);
    bool is_canceled = priv->is_canceled;
    priv_unlock(priv);
    return is_canceled;
}

inline int libtcpserv_recv(struct libtcpserv_client_struct *cs, void *buf, size_t len)
{
    return recv(cs->sock, buf, len, 0);
}

inline int libtcpserv_send(struct libtcpserv_client_struct *cs, void *data, size_t len)
{
    return send(cs->sock, data, len, 0);
}

static bool libtcpclient_get_is_connected(struct libtcpserv_client_struct *cs)
{
    pthread_mutex_lock(&cs->mutex);
    bool is_connected = cs->is_connected;
    pthread_mutex_unlock(&cs->mutex);

    return is_connected;
}

static void* do_client_reconnect(void *arg)
{
    struct libtcpserv_client_struct *cs = (struct libtcpserv_client_struct*)arg;

    if (connect(cs->sock, (struct sockaddr*)&cs->addr, sizeof(cs->addr)) < 0) {
        sleep_pthread(3, 0, NULL, NULL);
        libworkqueue_enqueue_task(libtcpserv.workqueue, NULL, do_client_reconnect, cs);
    }
    else {
        pthread_mutex_lock(&cs->mutex);
        cs->is_connected = true;
        pthread_mutex_unlock(&cs->mutex);

        print_log(MSG_DBG, "msg: tcp client socket is reconnected.\n");
    }

    return NULL;
}

int libtcpserv_send_with_header(struct libtcpserv_client_struct *cs,
                                void *data, size_t len, uint32_t type)
{
    struct libtcpserv_msghdr *hdr = NULL;

    if (!(hdr = (struct libtcpserv_msghdr*)gc_calloc(1,
                    sizeof(struct libtcpserv_msghdr) + len)))
        return -ENOMEM;

    hdr->type = type;
    hdr->len = len;
    memcpy(hdr->data, data, len);

    if (libtcpclient_get_is_connected(cs)) {
        if (libtcpclient_send_all(cs, hdr, libtcpserv_len(hdr)) < 0) {
            pthread_mutex_lock(&cs->mutex);
            cs->is_connected = false;
            pthread_mutex_unlock(&cs->mutex);

            libworkqueue_enqueue_task(libtcpserv.workqueue,
                NULL, do_client_reconnect, cs);
        }
    }

    gc_free(hdr);

    return 0;
}

struct libtcpserv_client_struct* libtcpserv_connect(struct libtcpserv_config_struct *config)
{
    struct libtcpserv_client_struct *cs = NULL;

    if (!(cs = (struct libtcpserv_client_struct*)gc_calloc(1,
                    sizeof(struct libtcpserv_client_struct))))
        return NULL;

    cs->is_connected = false;
    pthread_mutex_init_errorcheck(&cs->mutex);

    if ((cs->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        goto error;

    cs->addr.sin_family = config->family;
    cs->addr.sin_port = htons(config->port);
    inet_pton(AF_INET, config->dest_addr, &cs->addr.sin_addr);

    // print_log(MSG_ERR, "Trying to connect to %s:%d\n", config->dest_addr, config->port);

    if (connect(cs->sock, (struct sockaddr*)&cs->addr, sizeof(cs->addr)) < 0)
        goto error_in_connect;

    cs->is_connected = true;

    print_log(MSG_ERR, "connected to %s:%d\n", config->dest_addr, config->port);

    return cs;

error_in_connect:
    close(cs->sock);
error:
    // print_log(MSG_ERR, "%s (code: %d)\n", strerror(errno), errno);
    gc_free(cs);
    return NULL;
}

void libtcpserv_disconnect(struct libtcpserv_client_struct *cs)
{
    close(cs->sock);
    gc_free(cs);
}

static void set_config(struct libtcpserv_priv *priv,
                       struct libtcpserv_config_struct *config)
{
    if (!priv || !config)
        return;

    memset(&priv->addr, 0, sizeof(struct sockaddr_in));

    priv->addr.sin_family = AF_INET;
    priv->addr.sin_addr.s_addr = INADDR_ANY;
    priv->addr.sin_port = htons(config->port);

    priv->listen_backlog = config->listen_backlog;

    priv->user_handler = config->func;
    priv->user_arg = config->arg;
}

static void* client_handler(void *arg)
{
    struct libtcpserv_client_struct *cs = (struct libtcpserv_client_struct*)arg;

    cs->user_handler(cs->sock, cs->user_arg);

    close(cs->sock);
    gc_free(cs);

    return NULL;
}

static void* listen_handler(void *arg)
{
    struct libtcpserv_priv *priv = (struct libtcpserv_priv*)arg;
    struct sockaddr_in addr = {0};
    socklen_t len = 0;
    int sock = 0;

    // Let this thread to be released immediately when pthread_cancel() is called
    // Note: Cleaning up the worker queues will be executed by libworkqueue_release()
    //       after the routine called pthread_cancel().
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &(int){0});

    while (!get_is_canceled(priv) &&
            (sock = accept(priv->sock, (struct sockaddr*)&addr, &len))) {
        struct libtcpserv_client_struct *cs =
            (struct libtcpserv_client_struct*)gc_calloc(1,
                    sizeof(struct libtcpserv_client_struct));

        if (!cs) {
            close(sock);
            continue;
        }

        // Pthread cancelation point
        pthread_testcancel();

        cs->user_handler = priv->user_handler;
        cs->user_arg = priv->user_arg;
        cs->sock = sock;
        memcpy(&cs->addr, &addr, sizeof(struct sockaddr_in));

        if (pthread_create(&cs->self_thread, NULL, client_handler, cs) < 0)
            print_log(MSG_DBG, "Could not accept request because of no memory.\n");
    }

    return NULL;
}

void libtcpserv_wait(struct libtcpserv_struct *s)
{
    struct libtcpserv_priv *priv = libtcpserv_priv_of(s);
    pthread_join(priv->listen_thread, NULL);
}

void libtcpserv_release(struct libtcpserv_struct *s)
{
    if (s) {
        struct libtcpserv_priv *priv = libtcpserv_priv_of(s);

        priv_lock(priv);
        priv->is_canceled = true;
        priv_unlock(priv);
    }
}

struct libtcpserv_struct* libtcpserv_new(struct libtcpserv_config_struct *config)
{
    struct libtcpserv_struct *s = NULL;
    struct libtcpserv_priv *priv = NULL;
    int yes = 1;

    if (!config)
        return NULL;

    if (!(s = (struct libtcpserv_struct*)gc_calloc(1,
                    sizeof(struct libtcpserv_struct) + sizeof(struct libtcpserv_priv))))
        return NULL;

    priv = libtcpserv_priv_of(s);

    set_config(priv, config);

    pthread_mutex_init(&priv->mutex, NULL);

    if ((priv->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        goto error;

    if (setsockopt(priv->sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
        print_log(MSG_WARN,
                "[libtcpserv] Server socket is allocated. But it is not reusable (reason: %s, code: %d).\n",
                strerror(errno), errno);
    }

    if (bind(priv->sock, (struct sockaddr*)&priv->addr, sizeof(priv->addr)) < 0)
        goto error;

    if (listen(priv->sock, priv->listen_backlog) < 0)
        goto error;

    if (pthread_create(&priv->listen_thread, NULL, listen_handler, (void*)priv) < 0)
        goto error;

#ifdef ENABLE_DEBUG
    debug_priv_mapping_info(s);
#endif

    return s;

error:
    print_log(MSG_DBG, "[libtcpserv] %s (code: %d)\n", strerror(errno), errno);
    gc_free(s);
    return NULL;
}

void libtcpserv_exit(struct libtcpserv_struct *s)
{
    struct libtcpserv_priv *priv = libtcpserv_priv_of(s);
    pthread_cancel(priv->listen_thread);
    libworkqueue_remove(libtcpserv.workqueue);
    gc_free(s);
}

int libtcpserv_init(void)
{
    if (libtcpserv.is_initialized)
        return 0;

    libworkqueue_init();

    libtcpserv.workqueue = libworkqueue_new();

    pthread_mutex_init(&libtcpserv.mutex, NULL);

    return 0;
}

#undef DEBUG_IDENTIFIER
