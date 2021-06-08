/*
 * tap.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef TAP_H
#define TAP_H

extern int tap_get_hwaddr(const char *ifname, char *hwaddr);

extern int tap_ifup(int fd);

extern int tap_ifup_name(char *ifname);

extern int tap_ifdown_name(char *ifname);

extern int tap_ifdown(int fd);

extern bool tap_set_persist(int fd, int flag);

extern bool tap_set_owner(int fd, uid_t uid);

extern int tap_set_ipaddr(char *ifname, int index);

extern int tap_alloc(char *dev);

extern int tap_iplink_setup(char *ifname);

extern int tap_release(int fd);

#endif /* TAP_H */
