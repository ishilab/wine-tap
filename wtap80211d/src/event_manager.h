/*
 * event_manager.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef EVENT_MANAGER_H
#define EVENT_MANAGER_H

#include <linux/if.h>

#define MAX_EVENT 512

extern int register_signal_event(int, void (*)(int, short, void *), void *arg);

extern int register_timer_event(void (*)(int, short, void*), void*, long int , long int);

extern int register_event(int, int, void (*)(int, short, void *), void *arg);

extern void event_manager_dispatch(void);

extern int event_manager_init(void);

extern void event_manager_exit(void);

#endif /* EVENT_MANAGER_H */
