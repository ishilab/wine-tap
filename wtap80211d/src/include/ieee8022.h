/*
 * ieee8022.h
 * Definitions of IEEE 802.2 LLC standards
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef IEEE8022_H
#define IEEE8022_H

#include <unistd.h>
#include <stdint.h>

struct ieee8022_hdr {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
    uint8_t oui[3];
    uint16_t type;
} __attribute__((aligned(2), packed));

#endif /* IEEE8022_H */
