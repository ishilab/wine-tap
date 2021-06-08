/*
 * ieee80211.h - Extended header of linux/ieee80211.h
 *
 * wtap80211 - Wireless network tap device for IEEE 802.11
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef IEEE80211_EXTENSION_H
#define IEEE80211_EXTENSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
#include <linux/nl80211.h>
#include "linux-3.10/mac80211.h"
#include "linux-3.10/ieee80211.h"

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)

// #include "linux-3.19/nl80211.h"
#include <linux/nl80211.h>
#include "linux-3.19/mac80211.h"
#include "linux-3.19/ieee80211.h"

#else

#include <linux/nl80211.h>
#include "linux-4.4/mac80211.h"
#include "linux-4.4/ieee80211.h"

#endif

#ifdef __cplusplus
};
#endif

#endif /* IEEE80211_EXTENSION_H */
