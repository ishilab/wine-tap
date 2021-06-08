/*
 * libtuntap.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef LIBTUNTAP_H
#define LIBTUNTAP_H

#include <stdbool.h>

struct libtuntap_struct {
    unsigned int type;
    char data[0];
};

extern int libtuntap_recv(struct libtuntap_struct *s, char *buf, size_t len);

extern int libtuntap_send(struct libtuntap_struct *s, const char *data, size_t len);

extern int libtuntap_register_recv_handler(struct libtuntap_struct *s,
        void (*handler)(int, short, void*), void *arg);

extern void libtuntap_release(struct libtuntap_struct *s);

extern struct libtuntap_struct* libtuntap_new(char *ifname, bool mode);

extern int libtuntap_init(void);

extern void libtuntap_exit(void);

#endif /* LIBTUNTAP_H */
