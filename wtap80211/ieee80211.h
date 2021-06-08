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

#ifndef IEEE80211EXT_H
#define IEEE80211EXT_H

#include <linux/ieee80211.h>

struct ieee80211_mgmt_ie {
    u8 eid;
    u8 len;
    u8 elm[0];
} __packed __aligned(2);

/*
 * ieee80211_is_qos - check if IEEE80211_STYPE_QOS_DATA
 * @fc: frame control bytes in little-endian byteoder
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static int ieee80211_is_qos(__le16 fc) {
    return ((fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
            cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA));
}
#else
static bool ieee80211_is_qos(__le16 fc) {
    return ((fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
            cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA));
}
#endif

/*
 * ieee80211_is_qos_no_data - check if IEEE80211_STYPE_QOS_DATA && 0x0040
 * @fc: frame control bytes in little-endian byteoder
 *
 * This function returns true when @fc is a qos frame without data fields.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static int ieee80211_is_qos_no_data(__le16 fc) {
    return ((fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
            cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | 0x0040));
}
#else
static bool ieee80211_is_qos_no_data(__le16 fc) {
    return ((fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
            cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | 0x0040));
}
#endif

/*
 * ieee80211_is_broadcast - check if @addr is the broadcast address
 * @addr: destination address of a frame
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static int ieee80211_is_broadcast(const u8 *addr)
{
    return ((*((u16*)(addr+0)) & *((u16*)(addr+2)) & *((u16*)(addr+4))) == 0xffff);
}
#else
static bool ieee80211_is_broadcast(const u8 *addr)
{
    return ((*((u16*)(addr+0)) & *((u16*)(addr+2)) & *((u16*)(addr+4))) == 0xffff);
}
#endif

#endif /* IEEE80211EXT_H */
