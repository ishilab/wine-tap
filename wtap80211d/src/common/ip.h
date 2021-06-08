/*
 * ip.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef IP_H
#define IP_H

#include <stdint.h>

#define IEEE8023_TYPE_LEN 2

struct ipv4_hdr {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version: 4,
            ihl: 4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl: 4,
            version: 4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t flag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((aligned(2), packed));

#endif /* IP_H */
