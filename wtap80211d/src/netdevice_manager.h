/*
 * dev_mgmr.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef DEV_MGMR_H
#define DEV_MGMR_H

#include "utils.h"

#define NETDEV_UDEV_STATE_REG BIT(1)

int netdev_send_binary(char *addr, const char *buf, size_t n);

void netdev_notify_udev_action(const char *ifname, const char *action);

int netdev_add_device(char *addr);

void *do_netdev_add_multiple_devices(void *arg);

void *do_netdev_add_multiple_external_interfaces(void *arg);

int netdev_remove_device(char *addr);

void netdev_remove_all_devices(void);

int netdevice_manager_init(void);

void netdevice_manager_exit(void);

#endif /* DEV_MGMR_H */
