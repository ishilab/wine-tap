//
// Created by Arata Kato on 2019-07-30.
//

#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "utils.h"
#include "libudpserv.h"

#define libudpserv_priv_of(s) ((struct libudpserv_priv*)&((s)->priv))

static struct {
    pthread_mutex_t mutex;
    bool is_initialized;

    int bcast_sock;
    bool enable_broadcast;
} libudpserv ;

struct libudpserv_priv {
    int sock;
    struct sockaddr_in addr;

    void* (*user_handler)(int, void*);
    void* user_arg;

    pthread_t listen_thread;
};

static int broadcast_all(void *data, size_t len, int port)
{
    const struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_BROADCAST),
        .sin_port = htons(port),
        .sin_zero = {0},
    };

    if (!libudpserv.is_initialized || !libudpserv.enable_broadcast)
        return -1;

    return libudpserv_send_all(libudpserv.bcast_sock, data, len, (struct sockaddr*)&dest_addr);
}

int libudpserv_broadcast_all(void *data, size_t len, int port)
{
    return broadcast_all(data, len, port);
}

struct libudpserv_client_struct*
libudpclient_setup(struct libudpserv_config_struct *config)
{
    struct libudpserv_client_struct *cs = NULL;

    if (!(cs = (struct libudpserv_client_struct*)gc_calloc(1,
            sizeof(struct libudpserv_client_struct))))
        return NULL;

    if ((cs->sock = socket(config->family, SOCK_DGRAM, 0)) < 0)
        goto error;

    cs->addr.sin_family = config->family;
    cs->addr.sin_port = htons(config->port);
    inet_pton(config->family, config->dest_addr, &cs->addr.sin_addr);

    return cs;

error:
    print_log(MSG_ERR, "[libudpserv] %s (code: %d)\n", strerror(errno), errno);
    gc_free(cs);
    return NULL;
}

void libudpclient_leave(struct libudpserv_client_struct *cs)
{
    close(cs->sock);
    gc_free(cs);
}

static void* listen_handler(void *arg)
{
    struct libudpserv_priv *priv = (struct libudpserv_priv*)arg;

    priv->user_handler(priv->sock, priv->user_arg);

    return NULL;
}

static void set_config(struct libudpserv_priv *priv,
                       struct libudpserv_config_struct *config)
{
    if (!priv || !config)
        return;

    memset(&priv->addr, 0, sizeof(struct sockaddr_in));

    priv->addr.sin_family = AF_INET;
    priv->addr.sin_addr.s_addr = htonl(INADDR_ANY);
    priv->addr.sin_port = htons(config->port);

    priv->user_handler = config->func;
    priv->user_arg = config->arg;
}

void libudpserv_wait(struct libudpserv_struct *s)
{
    if (!s)
        return;

    struct libudpserv_priv *priv = libudpserv_priv_of(s);
    pthread_join(priv->listen_thread, NULL);
}

struct libudpserv_struct* libudpserv_new(struct libudpserv_config_struct *config)
{
    struct libudpserv_priv *priv = NULL;
    struct libudpserv_struct *s = NULL;
    int yes = 1;

    if (!config)
        return NULL;

    if (!(s = (struct libudpserv_struct*)gc_calloc(1,
            sizeof(struct libudpserv_struct) + sizeof(struct libudpserv_priv))))
        return NULL;

    priv = libudpserv_priv_of(s);

    set_config(priv, config);

    if ((priv->sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        goto error;

    if (setsockopt(priv->sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
        print_log(MSG_WARN,
                  "[libudpserv] Server socket is allocated. But it is not reusable (reason: %s, code: %d).\n",
                  strerror(errno), errno);
    }

    if (bind(priv->sock, (struct sockaddr*)&priv->addr, sizeof(priv->addr)) < 0)
        goto error;

    if (pthread_create(&priv->listen_thread, NULL, listen_handler, (void*)priv) < 0)
        goto error;

    return s;

error:
    print_log(MSG_DBG, "[libudpserv] %s (code: %d)\n", strerror(errno), errno);
    gc_free(s);
    return NULL;
}

void libudpserv_release(struct libudpserv_struct *s)
{
    struct libudpserv_priv *priv = libudpserv_priv_of(s);
    close(priv->sock);
    gc_free(s);
}

void libudpserv_init(void)
{
    int enable_broadcast = 1;

    if (libudpserv.is_initialized)
        return;

    libudpserv.bcast_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int rc = setsockopt(libudpserv.bcast_sock, SOL_SOCKET, SO_BROADCAST,
            &enable_broadcast, sizeof(enable_broadcast));
    libudpserv.enable_broadcast = (libudpserv.bcast_sock > 0 && !rc);

    libudpserv.is_initialized = true;
}

void libudpserv_exit(void)
{

}
