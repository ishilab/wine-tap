/*
 * utils.h
 * wtap80211 - Wireless network tap device for IEEE 802.11
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef UTILS_H
#define UTILS_H

#define CHAR2HEX(c) ((c) & 0xff)

#ifdef ENABLE_DEBUG
# define debug_msg(format, ...) \
    printk(KERN_DEBUG           \
            "wtap80211d: debug: %s: %d: " format "\n", \
            __func__, __LINE__, ##__VA_ARGS__)
#else
# define debug_msg(format, ...)
#endif

#define error_msg(format, ...) \
    printk(KERN_ERR             \
            "wtap80211d: error: %s: %d: " format "\n", \
            __func__, __LINE__, ##__VA_ARGS__)

#define warn_msg(format, ...) \
    printk(KERN_WARNING  \
            "wtap80211d: warning: %s: %d: " format "\n", \
            __func__, __LINE__, ##__VA_ARGS__)

#define info_msg(format, ...) \
    printk(KERN_INFO           \
            "wtap80211d:  info: %s: " format "\n", \
            __func__, ##__VA_ARGS__)

/*
 * ieee80211_fctl_index - indexes to identify the frame control field (debug use only)
 */
enum ieee80211_fctl_index {
    IEEE80211_FCTL_INDEX_DATA = 0,
    IEEE80211_FCTL_INDEX_DATA_QOS,
    IEEE80211_FCTL_INDEX_ASSOC_REQ,
    IEEE80211_FCTL_INDEX_ASSOC_RESP,
    IEEE80211_FCTL_INDEX_REASSOC_REQ,
    IEEE80211_FCTL_INDEX_REASSOC_RESP,
    IEEE80211_FCTL_INDEX_PROBE_REQ,
    IEEE80211_FCTL_INDEX_PROBE_RESP,
    IEEE80211_FCTL_INDEX_BEACON,
    IEEE80211_FCTL_INDEX_ATIM,
    IEEE80211_FCTL_INDEX_DIASSOC,
    IEEE80211_FCTL_INDEX_AUTH,
    IEEE80211_FCTL_INDEX_DEAUTH,
    IEEE80211_FCTL_INDEX_ACTION,
    IEEE80211_FCTL_INDEX_BACK_REQ,
    IEEE80211_FCTL_INDEX_BACK,
    IEEE80211_FCTL_INDEX_PSPOLL,
    IEEE80211_FCTL_INDEX_RTS,
    IEEE80211_FCTL_INDEX_CTS,
    IEEE80211_FCTL_INDEX_CFEND,
    IEEE80211_FCTL_INDEX_CFENDACK,
    IEEE80211_FCTL_INDEX_NULLFUNC,
    IEEE80211_FCTL_INDEX_QOS_NULLFUNC,

    __IEEE80211_FCTL_INDEX_MAX,
};
#define IEEE80211_FCTL_INDEX_MAX (__IEEE80211_FCTL_INDEX_MAX - 1)

extern const char *ieee80211_fctl_name[IEEE80211_FCTL_INDEX_MAX + 1];

extern const char *iftype_modes[NL80211_IFTYPE_MAX + 1];

extern inline int wtap_dbg_search_fctl(struct ieee80211_hdr *hdr);

extern inline void wtap_dbg_ieee80211_hdr(struct ieee80211_hdr *, struct ieee80211_tx_info *, struct ieee80211_rx_status *);

extern inline void wtap_dbg_ieee80211_mgmt(struct ieee80211_mgmt *mgmthdr);

extern inline void wtap_dbg_print_beacon(struct ieee80211_mgmt *mgmthdr);

extern inline void wtap_dbg_genl_hdr(struct nlmsghdr *nlhdr);

extern inline void wtap_dbg_ieee80211_binary(struct ieee80211_hdr *hdr, unsigned int len);

#endif /* UTILS_H */
