/*
 * rtnetlink_connector.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef RTNETLINK_CONNECTOR_H
#define RTNETLINK_CONNECTOR_H

extern bool rtnl_is_interface_active(const char *ifname);

extern int rtnetlink_connector_init(void);

#endif /* RTNETLINK_CONNECTOR_H */
