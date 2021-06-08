/*
 * genl.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef GENETLINK_CONNECTOR_H
#define GENETLINK_CONNECTOR_H

#include <netlink/cli/utils.h>
#include "utils.h"

#define GENL_STATE_UNSPEC        BIT(0)
#define GENL_STATE_STANDBY       BIT(1)
#define GENL_STATE_AUTH_REQUIRED BIT(2)
#define GENL_STATE_READY         BIT(3)

int genl_send_easy(int, int);

void wr_print_nlerr(int);

void print_nlmsg_header(const struct nlmsghdr *);

void print_genlmsg_header(const struct nlmsghdr *);

void print_nlattr_entry(const struct nlattr **);

void print_frame_message(const struct nlmsghdr *, const struct nlattr **);

int genl_send_auth_request(void);

size_t genl_get_ndev(void);

char* genl_get_addrs(void);

int genl_is_ready(void);

int genetlink_connector_init(const char *);

void genetlink_connector_exit(void);

#endif /* GENETLINK_CONNECTOR_H */
