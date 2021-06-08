/*
 * libunserv.c
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
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <event.h>
#include "utils.h"
#include "common/message.h"
#include "libworkqueue.h"
#include "libunserv.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libunserv"

#define libunserv_priv_of(s) ((struct libunserv_priv*)&((s)->priv))

static struct {
    pthread_mutex_t mutex;
    bool is_initialized;
} libunserv;

struct libunserv_priv {
    int rx_sock;
    struct sockaddr_un src_addr;
    int listen_backlog;

    int tx_sock;
    struct sockaddr_un dest_addr;
    bool is_connected;
    bool is_reconnecting;

    void* (*do_recv_handler)(void*);
    void (*ev_recv_handler)(int, short, void*);
    void* user_arg;
    bool is_persist;

    pthread_mutex_t mutex;

    pthread_t listen_thread;
    pthread_mutex_t listen_thread_mutex;
    pthread_cond_t listen_thread_cond;

    struct libworkqueue_struct *workqueue;
    struct libutils_event_struct *event_base;
};

static void debug_priv_mapping_info(const struct libunserv_struct *s)
{
    const struct libunserv_priv *priv = libunserv_priv_of(s);
    print_log(MSG_DBG,
              "s: %p, priv: %p, "
              STRUCTURE_MEMBER_MAP_FMT(rx_sock) ", "
              STRUCTURE_MEMBER_MAP_FMT(src_addr) ", "
              STRUCTURE_MEMBER_MAP_FMT(listen_backlog) ", "
              STRUCTURE_MEMBER_MAP_FMT(tx_sock) ", "
              STRUCTURE_MEMBER_MAP_FMT(dest_addr) ", "
              STRUCTURE_MEMBER_MAP_FMT(is_connected) ", "
              STRUCTURE_MEMBER_MAP_FMT(do_recv_handler) ", "
              STRUCTURE_MEMBER_MAP_FMT(ev_recv_handler) ", "
              STRUCTURE_MEMBER_MAP_FMT(user_arg) ", "
              STRUCTURE_MEMBER_MAP_FMT(is_persist) ", "
              STRUCTURE_MEMBER_MAP_FMT(mutex) ", "
              STRUCTURE_MEMBER_MAP_FMT(listen_thread) ", "
              STRUCTURE_MEMBER_MAP_FMT(listen_thread_mutex) ", "
              STRUCTURE_MEMBER_MAP_FMT(listen_thread_cond) ", "
              STRUCTURE_MEMBER_MAP_FMT(workqueue) ", "
              STRUCTURE_MEMBER_MAP_FMT(event_base) "\n",
              // ===== format string ends here =====
              s, priv,
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, rx_sock),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, src_addr),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, listen_backlog),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, tx_sock),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, dest_addr),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, is_connected),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, do_recv_handler),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, ev_recv_handler),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, user_arg),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, is_persist),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, mutex),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, listen_thread),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, listen_thread_mutex),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, listen_thread_cond),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, workqueue),
              STRUCTURE_MEMBER_MAP_ARG(priv, struct libunserv_priv, event_base));
}

static void priv_lock(struct libunserv_priv *priv)
{
    pthread_mutex_lock(&priv->mutex);
}

static void priv_unlock(struct libunserv_priv *priv)
{
    pthread_mutex_unlock(&priv->mutex);
}

bool libunserv_is_connected(struct libunserv_struct *s)
{
    struct libunserv_priv *priv = libunserv_priv_of(s);

    priv_lock(priv);
    bool is_connected = priv->is_connected;
    priv_unlock(priv);

    return priv->is_connected;
}

int libunserv_get_sock(struct libunserv_struct *s)
{
    int sock = 0;

    if (s) {
        struct libunserv_priv *priv = libunserv_priv_of(s);
        sock = priv->tx_sock;
    }

    return sock;
}

inline int libunserv_recv(struct libunserv_client_struct *cs, void *buf, size_t len)
{
    return recv(cs->sock, buf, len, 0);
}

int libunserv_recv_all(struct libunserv_struct *s, void *data, int len)
{
    struct libunserv_priv *priv = libunserv_priv_of(s);
    return recv_all_stream(priv->tx_sock, data, len);
}

int libunclient_recv_all(struct libunserv_client_struct *cs, void *data, int len)
{
    return recv_all_stream(cs->sock, data, len);
}

inline int libunserv_send(struct libunserv_client_struct *cs, void *data, size_t len)
{
    return send(cs->sock, data, len, 0);
}

void libunserv_reconnect(struct libunserv_struct *s);
int libunserv_send_all(struct libunserv_struct *s, const void *data, int len)
{
    struct libunserv_priv *priv = libunserv_priv_of(s);
    int ret = -1;

    if (libunserv_is_connected(s)) {
        if ((ret = send_all_stream(priv->tx_sock, data, len)) < 0)
            libunserv_reconnect(s);
    }

    return ret;
}

int libunclient_send_all(struct libunserv_client_struct *cs, void *data, int len)
{
    print_log(MSG_DBG, "Sending %d bytes via %s\n", len, cs->dest_addr.sun_path);
    return send_all_dgram(cs->sock, data, len,
            (struct sockaddr*)&cs->dest_addr, sizeof(cs->dest_addr));
}

int libunserv_send_with_header(struct libunserv_client_struct *cs,
                                void *data, size_t len, uint32_t type)
{
    struct libunserv_msghdr *hdr = NULL;

    if (!(hdr = (struct libunserv_msghdr*)gc_calloc(1,
                    sizeof(struct libunserv_msghdr) + len)))
        return -ENOMEM;

    hdr->type = type;
    hdr->len = len;
    memcpy(hdr->data, data, len);

    libunclient_send_all(cs, hdr, libunserv_len(hdr));

    gc_free(hdr);

    return 0;
}

struct libunserv_thread_container {
    struct libunserv_priv *priv;
    int sock;

    pthread_t thread;
};

__attribute__((unused))
static void* do_execute_user_handler(void *arg)
{
    struct libunserv_thread_container *container = (struct libunserv_thread_container*)arg;
    struct libunserv_priv *priv = container->priv;

    print_log(MSG_DBG,
            "User handler starts now (handler_addr: %p)\n",
            priv->ev_recv_handler);

    if (priv->ev_recv_handler)
        priv->ev_recv_handler(container->sock, 0, priv->user_arg);

    priv_lock(priv);
    priv->is_connected = false;
    priv_unlock(priv);

    close(container->sock);
    gc_free(container);

    return NULL;
}

__attribute__((unused))
struct libunserv_client_struct* libunserv_connect(struct libunserv_config_struct *config, int retry_times)
{
    struct libunserv_client_struct *cs = NULL;

    if (!(cs = (struct libunserv_client_struct*)gc_calloc(1,
            sizeof(struct libunserv_client_struct))))
        return NULL;

    if ((cs->sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        goto error;

    cs->dest_addr.sun_family = AF_UNIX;
    strncpy(cs->dest_addr.sun_path, config->dest_path,
            min(SUNPATH_LEN, strlen(config->dest_path) + 1));
    cs->ev_recv_handler = config->ev_recv_handler;
    cs->user_arg = config->arg;

    print_log(MSG_DBG, "sunpath: %s\n", cs->dest_addr.sun_path);

    if (cs->ev_recv_handler) {
        // pthread
        // if (pthread_create(&cs->self_thread, NULL, client_handler, cs) < 0)
        //     goto error_in_connect;

        // Libevent
        if (!(cs->event_base = event_init()))
            goto error;

        struct event *ev = (struct event*)gc_calloc(1, sizeof(struct event));
        if (ev) {
            event_set(ev, cs->sock, EV_PERSIST | EV_READ, cs->ev_recv_handler, cs->user_arg);
            event_base_set(cs->event_base, ev);
            event_add(ev, NULL);
        }
    } else {
        print_log(MSG_DBG, "No user handler registered\n");
    }

    while (connect(cs->sock, (struct sockaddr*)&cs->dest_addr, sizeof(cs->dest_addr)) < 0) {
        if (retry_times-- > 0) {
            print_log(MSG_DBG, "Retrying to connect to the destination...\n");
            sleep(1);
        }
        else {
            goto error_in_connect;
        }
    }

    return cs;

error_in_connect:
    close(cs->sock);
error:
    print_log(MSG_ERR, "%s (code: %d)\n", strerror(errno), errno);
    gc_free(cs);
    return NULL;
}

void libunserv_disconnect(struct libunserv_client_struct *cs)
{
    close(cs->sock);
    gc_free(cs);
}

void libunserv_shutdown(struct libunserv_struct *s)
{
    if (!s)
        return ;

    struct libunserv_priv *priv = libunserv_priv_of(s);

    priv_lock(priv);

    libutils_event_shutdown(priv->event_base, priv->rx_sock);

    close(priv->rx_sock);

    priv->is_connected = false;

    priv_unlock(priv);
}

// Memo: There is not EV_CLOSED flag in event.h in linux 4.4.
__attribute__((unused))
static void close_handler(int sock, short int flag, void *arg)
{
    struct libunserv_priv *priv = (struct libunserv_priv*)arg;
    libutils_event_shutdown(priv->event_base, sock);
    close(sock);
}

static void* do_connect(void *);
static void tx_socket_close_handler(int sock, short int flag, void *arg)
{
    struct libunserv_priv *priv = (struct libunserv_priv*)arg;

    priv_lock(priv);
    priv->is_connected = false;
    priv_unlock(priv);

    libworkqueue_enqueue_task(priv->workqueue, NULL, do_connect, priv);

    print_log(MSG_DBG, "msg: Local TX socket is closed by remote host. Trying to reconnect the same destination.\n");
}

// static void* listen_handler(void *arg)
static void listen_handler(int sock, short int flag, void *arg)
{
    struct libunserv_priv *priv = (struct libunserv_priv*)arg;
    struct sockaddr_un addr = {0};
    socklen_t len = sizeof(addr);
    int client_sock = 0;

    if ((client_sock = accept(priv->rx_sock, (struct sockaddr*)&addr, &len)) == -1)
        goto error;

    print_log(MSG_DBG, "Connection request accepted\n");

    if (libutils_event_register(priv->event_base, client_sock, EV_READ | EV_PERSIST,
            priv->ev_recv_handler, priv->user_arg) < 0)
        goto error;

    return ;

error:
    print_log(MSG_DBG, "Connection request rejected (reason: %s, code: %d)\n",
            strerror(errno), errno);
}

void libunserv_wait(struct libunserv_struct *s)
{
    struct libunserv_priv *priv = libunserv_priv_of(s);
    // pthread_join(priv->listen_thread, NULL);
    libutils_event_wait(priv->event_base);
}

void libunserv_client_wait(struct libunserv_client_struct *cs)
{
    if (cs)
        event_base_dispatch(cs->event_base);
}

// In the first design, libunserv_client_new function makes a datagram socket to
// communicate with another client via a socket file. But because libevent does not support
// datagram sockets, I gave up to support it. This issue was already reported on libevent
// Github issues #537.

struct libunserv_client_struct* libunserv_client_new(struct libunserv_config_struct *config)
{
    struct libunserv_client_struct *cs = NULL;

    if (!(cs = (struct libunserv_client_struct*)gc_calloc(1,
            sizeof(struct libunserv_client_struct))))
        return NULL;

    if ((cs->sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
        goto error;

    cs->src_addr.sun_family = AF_UNIX;
    strncpy(cs->src_addr.sun_path, config->src_path,
            min(SUNPATH_LEN, strlen(config->src_path) + 1));

    cs->dest_addr.sun_family = AF_UNIX;
    strncpy(cs->dest_addr.sun_path, config->dest_path,
            min(SUNPATH_LEN, strlen(config->dest_path) + 1));

    cs->ev_recv_handler = config->ev_recv_handler;
    cs->user_arg = config->arg;

    unlink(config->src_path);
    if (bind(cs->sock, (struct sockaddr*)&cs->src_addr, sizeof(cs->src_addr)) < 0)
        goto error;

    if (cs->ev_recv_handler) {
        if (!(cs->event_base = event_init()))
            goto error;

        struct event *ev = NULL;
        if (!(ev = (struct event*)gc_calloc(1, sizeof(struct event))))
            goto error;

        event_set(ev, cs->sock, EV_PERSIST | EV_READ, cs->ev_recv_handler, cs->user_arg);
        event_base_set(cs->event_base, ev);
        event_add(ev, NULL);

        print_log(MSG_DBG, "recv_handler registered (addr: %p, dest_path: %s src_path: %s)\n",
                cs->ev_recv_handler, cs->dest_addr.sun_path, cs->src_addr.sun_path);
    } else {
        print_log(MSG_DBG, "No user handler registered\n");
    }

    return cs;

error:
    gc_free(cs);
    return NULL;
}

static void set_config(struct libunserv_priv *priv,
                       struct libunserv_config_struct *config)
{
    if (!priv || !config)
        return;

    memset(&priv->src_addr, 0, sizeof(struct sockaddr_in));

    priv->src_addr.sun_family = AF_UNIX;
    strncpy(priv->src_addr.sun_path, config->src_path,
            min((size_t)SUNPATH_LEN, strlen(config->src_path) + 1));

    priv->dest_addr.sun_family = AF_UNIX;
    strncpy(priv->dest_addr.sun_path, config->dest_path,
            min((size_t)SUNPATH_LEN, strlen(config->dest_path) + 1));

    priv->listen_backlog = config->listen_backlog;

    priv->do_recv_handler = config->do_recv_handler;
    priv->ev_recv_handler = config->ev_recv_handler;
    priv->user_arg = config->arg;
    priv->is_persist = config->is_persist;

    print_log(MSG_DBG, "dest_path: %s, src_path: %s\n",
            priv->dest_addr.sun_path, priv->src_addr.sun_path);
}

static void* do_connect(void *arg)
{
    struct libunserv_priv *priv = (struct libunserv_priv*)arg;

    if (connect(priv->tx_sock, (struct sockaddr*)&priv->dest_addr, sizeof(priv->dest_addr)) < 0) {
        sleep_pthread(5, 0, NULL, NULL);
        libworkqueue_enqueue_task(priv->workqueue, NULL, do_connect, priv);
    } else {
        print_log(MSG_DBG, "Connected to the local server (dest_sunpath: %s)\n",
                priv->dest_addr.sun_path);

        priv_lock(priv);
        priv->is_connected = true;
        priv->is_reconnecting = false;
        priv_unlock(priv);
    }

    return NULL;
}

void libunserv_reconnect(struct libunserv_struct *s)
{
    struct libunserv_priv *priv = libunserv_priv_of(s);

    priv_lock(priv);
    if (!priv->is_reconnecting) {
        priv->is_connected = false;
        priv->is_reconnecting = true;
        libworkqueue_enqueue_task(priv->workqueue, NULL, do_connect, priv);
    }
    priv_unlock(priv);
}

struct libunserv_struct* libunserv_new(struct libunserv_config_struct *config)
{
    struct libunserv_struct *s = NULL;
    struct libunserv_priv *priv = NULL;
    int yes = 1;

    if (!config)
        return NULL;

    if (!(s = (struct libunserv_struct*)gc_calloc(1,
                    sizeof(struct libunserv_struct) + sizeof(struct libunserv_priv))))
        return NULL;

    priv = libunserv_priv_of(s);

    //pthread_mutex_init(&priv->mutex, NULL);
    pthread_mutex_init_errorcheck(&priv->mutex);

    if (!(priv->workqueue = libworkqueue_new()))
        goto error;

    if (!(priv->event_base = libutils_event_new()))
        goto error;

    set_config(priv, config);

    // Initialize and launch the server instance
    if ((priv->rx_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        goto error;

    // Receive socket initialization
    if (setsockopt(priv->rx_sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
        print_log(MSG_WARN,
                "Server socket is allocated but not reusable (reason: %s, code: %d).\n",
                strerror(errno), errno);
    }

    if (is_file_exist(priv->src_addr.sun_path))
        remove(priv->src_addr.sun_path);

    if (bind(priv->rx_sock, (struct sockaddr*)&priv->src_addr, sizeof(priv->src_addr)) < 0)
        goto error;

    if (listen(priv->rx_sock, priv->listen_backlog) < 0)
        goto error;

    print_log(MSG_DBG, "listen_handler: %p\n", listen_handler);

    libutils_event_register(priv->event_base, priv->rx_sock,
            EV_READ | EV_PERSIST, listen_handler, priv);

    // libutils_event_register(priv->event_base, priv->rx_sock,
    //         EV_CLOSED, close_handler, priv);

    // Dispatch the event base
    libutils_event_dispatch(priv->event_base);

    // Transmit socket initialization
    if ((priv->tx_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        goto error;

    libutils_event_register(priv->event_base, priv->tx_sock,
            EV_CLOSED | EV_PERSIST, tx_socket_close_handler, priv);

    libworkqueue_enqueue_task(priv->workqueue, NULL, do_connect, priv);

    print_log(MSG_DBG, "Local domain server initialized successfully.\n");

#ifdef ENABLE_DEBUG
    debug_priv_mapping_info(s);
#endif

    return s;

error:
    print_log(MSG_ERR, "%s (code: %d)\n", strerror(errno), errno);

    if (priv->tx_sock >= 0)
        close(priv->tx_sock);
    if (priv->rx_sock >= 0)
        close(priv->rx_sock);
    if (priv->event_base)
        libutils_event_release(priv->event_base);
    if (priv->workqueue)
        libworkqueue_remove(priv->workqueue);

    gc_free(s);

    return NULL;
}

void libunserv_release(struct libunserv_struct *s)
{
    if (!s)
        return;

    print_log(MSG_DBG, "Stopping local domain server...\n");

    struct libunserv_priv *priv = libunserv_priv_of(s);

    priv_lock(priv);

    libworkqueue_remove(priv->workqueue);
    libutils_event_release(priv->event_base);

    if (is_file_exist(priv->src_addr.sun_path))
        remove(priv->src_addr.sun_path);

    priv_unlock(priv);

    gc_free(s);
}

int libunserv_init(void)
{
    if (libunserv.is_initialized)
        return 0;

    //pthread_mutex_init(&libunserv.mutex, NULL);
    pthread_mutex_init_errorcheck(&libunserv.mutex);

    libworkqueue_init();

    libutils_event_init();

    return 0;
}

void libunserv_exit(void)
{
    libutils_event_exit();
}

#undef DEBUG_IDENTIFIER
