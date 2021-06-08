/*
 * utils.c
 * wtap80211 - Wireless network tap device for IEEE 802.11
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/version.h>

#include <net/mac80211.h>

#include <linux/netlink.h>
#include <net/genetlink.h>

#include "ieee80211.h"
#include "utils.h"

const char *ieee80211_fctl_name[IEEE80211_FCTL_INDEX_MAX + 1] = {
    [IEEE80211_FCTL_INDEX_DATA]         = "data",
    [IEEE80211_FCTL_INDEX_DATA_QOS]     = "data qos",
    [IEEE80211_FCTL_INDEX_ASSOC_REQ]    = "assoc req",
    [IEEE80211_FCTL_INDEX_ASSOC_RESP]   = "assoc resp",
    [IEEE80211_FCTL_INDEX_REASSOC_REQ]  = "reassoc req",
    [IEEE80211_FCTL_INDEX_REASSOC_RESP] = "reassoc resp",
    [IEEE80211_FCTL_INDEX_PROBE_REQ]    = "probe req",
    [IEEE80211_FCTL_INDEX_PROBE_RESP]   = "probe resp",
    [IEEE80211_FCTL_INDEX_BEACON]       = "beacon",
    [IEEE80211_FCTL_INDEX_ATIM]         = "atim",
    [IEEE80211_FCTL_INDEX_DIASSOC]      = "diassoc",
    [IEEE80211_FCTL_INDEX_AUTH]         = "auth",
    [IEEE80211_FCTL_INDEX_DEAUTH]       = "deauth",
    [IEEE80211_FCTL_INDEX_ACTION]       = "action",
    [IEEE80211_FCTL_INDEX_BACK_REQ]     = "back req",
    [IEEE80211_FCTL_INDEX_PSPOLL]       = "pspoll",
    [IEEE80211_FCTL_INDEX_RTS]          = "rts",
    [IEEE80211_FCTL_INDEX_CTS]          = "cts",
    [IEEE80211_FCTL_INDEX_CFEND]        = "cfend",
    [IEEE80211_FCTL_INDEX_CFENDACK]     = "cfendack",
    [IEEE80211_FCTL_INDEX_NULLFUNC]     = "nullfunc",
    [IEEE80211_FCTL_INDEX_QOS_NULLFUNC] = "qos nullfunc",
};

const char *iftype_modes[NL80211_IFTYPE_MAX + 1] = {
    [NL80211_IFTYPE_ADHOC]      = "ibss",
    [NL80211_IFTYPE_STATION]    = "managed",
    [NL80211_IFTYPE_AP]         = "master",
    [NL80211_IFTYPE_AP_VLAN]    = "master (vlan)",
    [NL80211_IFTYPE_WDS]        = "wds",
    [NL80211_IFTYPE_MONITOR]    = "monitor",
    [NL80211_IFTYPE_MESH_POINT] = "mesh",
    [NL80211_IFTYPE_P2P_CLIENT] = "p2p client",
    [NL80211_IFTYPE_P2P_GO]     = "p2p go",
    [NL80211_IFTYPE_P2P_DEVICE] = "p2p",
    [NL80211_IFTYPE_OCB]        = "ocb",
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static int (*ieee80211_iss[IEEE80211_FCTL_INDEX_MAX + 1])(__le16 fc);
#else
static bool (*ieee80211_iss[IEEE80211_FCTL_INDEX_MAX + 1])(__le16 fc);
#endif

inline int wtap_dbg_search_fctl(struct ieee80211_hdr *hdr)
{
    int i;
    for (i = 0; i < IEEE80211_FCTL_INDEX_MAX; ++i) {
        if (ieee80211_iss[i](hdr->frame_control))
            break;
    }
    return i;
}

inline void wtap_dbg_ieee80211_hdr(struct ieee80211_hdr *hdr,
        struct ieee80211_tx_info *tx_info,
        struct ieee80211_rx_status *rx_status)
{
    if (!hdr)
        return;

    if (!ieee80211_is_beacon(hdr->frame_control)) {
        if (tx_info) {
            debug_msg("TX frame info:");
        } else if (rx_status) {
            debug_msg("RX frame status: freq = %d [MHz], band = %d, signal = %d [dBm]",
                    rx_status->freq, rx_status->band, rx_status->signal);
        }

        debug_msg("  fc = %#x (%s), duration = %#x",
                hdr->frame_control, ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                hdr->duration_id);
        debug_msg("  addr1: %pM, addr2: %pM, addr3: %pM",
                hdr->addr1, hdr->addr2, hdr->addr3);
        debug_msg("  seq_ctrl = %u", hdr->seq_ctrl);
    }
}

inline void wtap_dbg_ieee80211_mgmt(struct ieee80211_mgmt *mgmthdr) {
    debug_msg("  fc = %#x, duration = %#x",
            mgmthdr->frame_control, mgmthdr->duration);
    debug_msg("  da: %pM, sa: %pM, bssid: %pM",
            mgmthdr->da, mgmthdr->sa, mgmthdr->bssid);
    debug_msg("  seq_ctrl = %u", mgmthdr->seq_ctrl);
}

inline void wtap_dbg_print_beacon(struct ieee80211_mgmt *mgmthdr) {
    struct ieee80211_mgmt_ie *ie = (void*)mgmthdr->u.beacon.variable;
    char ssid[IEEE80211_MAX_SSID_LEN + 1] = {0};

    memcpy(ssid, ie->elm, ie->len);

    if (mgmthdr->frame_control == 0x80) {
        if (printk_ratelimit()) {
            debug_msg("  fc = %#x, duration = %#x",
                    mgmthdr->frame_control, mgmthdr->duration);
            debug_msg("  da: %pM, sa: %pM, bssid: %pM",
                    mgmthdr->da, mgmthdr->sa, mgmthdr->bssid);
            debug_msg("  seq_ctrl = %u, timestamp = %llu, bcn_int = %u, cap_info = %#x",
                    mgmthdr->seq_ctrl, mgmthdr->u.beacon.timestamp,
                    mgmthdr->u.beacon.beacon_int, mgmthdr->u.beacon.capab_info);
            debug_msg("  eid = %u, len = %u, ssid = %s",
                    ie->eid, ie->len, ssid);
        }
    }
}

inline void wtap_dbg_genl_hdr(struct nlmsghdr *nlhdr)
{
    struct genlmsghdr *genlhdr = nlmsg_data(nlhdr);

    debug_msg("  nlhdr: len = %d, type = %u, seq = %u, pid = %u",
            nlhdr->nlmsg_len, nlhdr->nlmsg_type, nlhdr->nlmsg_seq, nlhdr->nlmsg_pid);
    debug_msg("  genlhdr: cmd = %d", genlhdr->cmd);
}

inline void wtap_dbg_ieee80211_binary(struct ieee80211_hdr *hdr,
        unsigned int len)
{
    unsigned int count = 0;

    if (++count > 10)
        return;

    if (printk_ratelimit()) {
        print_hex_dump(KERN_DEBUG, "ieee80211_frame: ",
                DUMP_PREFIX_ADDRESS,
                24, 1, hdr, len, true);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static int (*ieee80211_iss[IEEE80211_FCTL_INDEX_MAX + 1])(__le16 fc) = {
#else
static bool (*ieee80211_iss[IEEE80211_FCTL_INDEX_MAX + 1])(__le16 fc) = {
#endif
    /* Note that ieee80211_is_qos is only defined in wtap80211 */
    ieee80211_is_qos,
    ieee80211_is_data,
    ieee80211_is_assoc_req,
    ieee80211_is_assoc_resp,
    ieee80211_is_reassoc_req,
    ieee80211_is_reassoc_resp,
    ieee80211_is_probe_req,
    ieee80211_is_probe_resp,
    ieee80211_is_beacon,
    ieee80211_is_atim,
    ieee80211_is_disassoc,
    ieee80211_is_auth,
    ieee80211_is_deauth,
    ieee80211_is_action,
    ieee80211_is_back_req,
    ieee80211_is_back,
    ieee80211_is_pspoll,
    ieee80211_is_rts,
    ieee80211_is_cts,
    ieee80211_is_cfend,
    ieee80211_is_cfendack,
    ieee80211_is_nullfunc,
    ieee80211_is_qos_nullfunc,
};

