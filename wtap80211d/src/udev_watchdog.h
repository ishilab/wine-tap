/*
 * wtap80211d
 * udev_watcher.c
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef UDEV_WATCHER_H
#define UDEV_WATCHER_H

extern bool udev_has_device(const char *ifname, const char *subtype);

extern bool udev_has_multiple_devices(const char (*ifnames)[IFNAMSIZ], int n, const char *subtype);

extern int udev_watchdog_init(void);

extern void udev_watchdog_exit(void);

#endif /* UDEV_WATCHER_H */
