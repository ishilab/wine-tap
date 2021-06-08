/*
 * libudevmon.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef LIBUDEVMON_H
#define LIBUDEVMON_H

#include <net/if.h>
#include "utils.h"

struct libudevmon_struct {
    unsigned int type;
    char data[0];
};

#endif /* LIBUDEVMON_H */

extern bool libudevmon_has_multiple_devices(struct libudevmon_struct *s, const char** ifnames, int n);

extern bool libudevmon_has_device(struct libudevmon_struct *s, const char *ifname);

extern struct libudevmon_struct* libudevmon_new(const char *subtype);

extern void libudevmon_release(struct libudevmon_struct *s);

extern int libudevmon_init(void);

extern void libudevmon_exit(void);
