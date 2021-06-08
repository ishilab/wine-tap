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

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netlink/route/link.h>
#include <netlink/route/tc.h>
#include <netlink/route/cls/u32.h>
#include <netlink/route/classifier.h>
#include <netlink/route/class.h>
#include <netlink/attr.h>

#include "utils.h"

struct rtnl_msg {
    struct nlmsghdr nlh;
    struct ifinfomsg ifinfo;
};

static struct rtnetlink_connector_struct {
    struct nl_sock *sock;
    struct nl_cache *cache;
    pthread_mutex_t mutex;
} rtnl_st ;

static struct nl_sock* rtnl_connect(void)
{
    struct nl_sock *sock = NULL;

    if (!(sock = nl_socket_alloc()))
        return NULL;

    if (nl_connect(sock, NETLINK_ROUTE) < 0)
        return NULL;

    return sock;
}

static unsigned int rtnl_get_flags(const char *ifname, unsigned int mask)
{
    struct nl_sock *sock = NULL;
    struct nl_cache *cache = NULL;
    struct rtnl_link *link = NULL;
    unsigned int flags = 0;

    if (!(sock = rtnl_connect()))
        return 0;

    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0) {
        nl_socket_free(sock);
        return 0;
    }

    if (!(link = rtnl_link_get_by_name(cache, ifname))) {
        nl_socket_free(sock);
        return 0;
    }

    flags = rtnl_link_get_flags(link);

    nl_socket_free(sock);

    return (flags & mask);
}

bool rtnl_is_interface_active(const char *ifname)
{
    return !!(rtnl_get_flags(ifname, IFF_UP));
}

int rtnetlink_connector_init(void)
{
    memset(&rtnl_st, 0, sizeof(rtnl_st));

    pthread_mutex_init(&rtnl_st.mutex, NULL);

    print_log(MSG_INFO, "[rtnetlink] rtnetlink is ready.\n");

    return 0;
}

void rtnetlink_connector_exit(void)
{
    nl_socket_free(rtnl_st.sock);
}
