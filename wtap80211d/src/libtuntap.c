/*
 * libtuntap.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <event.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "utils.h"
#include "libtuntap.h"

/* Pre 2.4.6 compatibility */
#ifndef OTUNSETNOCSUM
#define OTUNSETNOCSUM  (('T' << 8) | 200)
#define OTUNSETDEBUG   (('T' << 8) | 201)
#define OTUNSETIFF     (('T' << 8) | 202)
#define OTUNSETPERSIST (('T' << 8) | 203)
#define OTUNSETOWNER   (('T' << 8) | 204)
#endif

#define libtuntap_priv_of(s) \
    ((struct libtuntap_priv*)&((s)->data))

static struct {
    struct event_base *event_base;
    bool is_initialized;
} libtuntap;

struct libtuntap_priv {
    char ifname[IFNAMSIZ];
    int fd;

    struct event *handler_event;
    void (*recv_handler)(int, short, void*);
    void *arg;

    bool mode;
};

static int tuntap_alloc(char *ifname, bool mode)
{
    struct ifreq ifr;
    int err, fd = 0;

    memset(&ifr, 0, sizeof(struct ifreq));

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        return fd;

    ifr.ifr_flags = IFF_NO_PI | ((mode) ? IFF_TAP : IFF_TUN);
    strncpy(ifr.ifr_name, ifname,
            ((strlen(ifname) + 1) > IFNAMSIZ) ? IFNAMSIZ : strlen(ifname));

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        if (err == EBADFD) {
            /* Try old ioctl command */
            if ((err = ioctl(fd, OTUNSETIFF, (void*)&ifr)) < 0)
                goto error;
        } else {
            goto error;
        }
    }

    return fd;

error:
    close(fd);
    return err;
}

int libtuntap_recv(struct libtuntap_struct *s, char *buf, size_t len)
{
    struct libtuntap_priv *priv;

    if (!s || !buf || len < 1)
        return -EINVAL;

    priv = libtuntap_priv_of(s);

    return read(priv->fd, buf, len);
}

int libtuntap_send(struct libtuntap_struct *s, const char *data, size_t len)
{
    struct libtuntap_priv *priv;

    if (!s)
        return 0;

    priv = libtuntap_priv_of(s);

    return write(priv->fd, data, len);
}

int libtuntap_register_recv_handler(struct libtuntap_struct *s,
        void (*handler)(int, short, void*), void *arg)
{
    struct libtuntap_priv *priv;

    if (!s || !handler)
        return -EINVAL;

    priv = libtuntap_priv_of(s);

    priv->recv_handler = handler;
    priv->arg = arg;

    priv->handler_event = event_new(libtuntap.event_base,
            priv->fd, EV_PERSIST | EV_READ, handler, arg);

    if (event_add(priv->handler_event, NULL) < 0) {
        event_free(priv->handler_event);
        priv->handler_event = NULL;
        return -ENOMEM;
    }

    return 0;
}

void libtuntap_release(struct libtuntap_struct *s)
{
    struct libtuntap_priv *priv;

    if (!s)
        return ;

    priv = libtuntap_priv_of(s);

    if (priv->handler_event) {
        event_del(priv->handler_event);
        event_free(priv->handler_event);
    }

    gc_free(s);
}

__attribute__((malloc))
struct libtuntap_struct* libtuntap_new(char *ifname, bool mode)
{
    struct libtuntap_priv *priv;
    struct libtuntap_struct *s;

    if (!libtuntap.is_initialized)
        return NULL;

    s = (struct libtuntap_struct*)gc_calloc(1,
            sizeof(struct libtuntap_struct)
            + sizeof(struct libtuntap_priv));

    if (!s)
        return NULL;

    priv = libtuntap_priv_of(s);

    if (ifname) {
        strncpy(priv->ifname, ifname,
                ((strlen(ifname) + 1) > IFNAMSIZ) ? IFNAMSIZ : strlen(ifname));
    }
    priv->mode = mode;

    priv->fd = tuntap_alloc((priv->ifname) ? priv->ifname : NULL, priv->mode);
    if (priv->fd < 0) {
        gc_free(s);
        return NULL;
    }

    return s;
}

int libtuntap_init(void)
{
    if (libtuntap.is_initialized)
        return 0;

    if (!(libtuntap.event_base = event_init()))
        return -ENOMEM;

    libtuntap.is_initialized = true;

    return 0;
}

void libtuntap_exit(void)
{
    if (!libtuntap.is_initialized)
        return ;

    event_base_free(libtuntap.event_base);
}
