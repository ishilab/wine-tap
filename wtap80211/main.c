/*
 * main.c
 * wtap80211 - Wireless network tap device for IEEE 802.11
 *
 * Copyright (c) 2016 - 2021, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/crc32.h>

// Interfaces
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>

// IEEE 802.11
/* #include <linux/ieee80211.h> */
#include "ieee80211.h"

// mac80211
#include <net/mac80211.h>

// Generic Netlink
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <net/xfrm.h>

#include <linux/spinlock.h>
#include <linux/mutex.h>

// local header
#include "genl.h"
#include "utils.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
MODULE_LICENSE("Dual BSD/GPL");
#else
MODULE_LICENSE("GPL");
#endif

MODULE_AUTHOR("Arata Kato");
MODULE_DESCRIPTION("wtap80211: Wireless network tap device for IEEE 802.11");
MODULE_PARM_DESC(mode, "operation mode of wtap80211");

static int num_of_devices = 1;
module_param_named(devices, num_of_devices, int, 0444);
MODULE_PARM_DESC(devices, "the number of virtual wireless network devices");

static int num_of_channels = 2;
module_param_named(channels, num_of_channels, int, 0444);
MODULE_PARM_DESC(channels,
        "the number of simulteneous available channels of a device.");

static int use_p2p = 0;
module_param(use_p2p, int, 0444);
MODULE_PARM_DESC(use_p2p, "enable p2p mode.");

static int is_loopback_enabled = 0;
module_param(is_loopback_enabled, int, 0444);
MODULE_PARM_DESC(is_loopback_enabled,
        "If this parameter is larger than 0, all frames will be always loopbacked in wtap80211.");

static int is_hwaddr_fixed = 0;
module_param_named(hwaddr_fixed, is_hwaddr_fixed, int, 0444);
MODULE_PARM_DESC(hwaddr_fixed,
        "If non-zero, user-specified hwaddrs specified with @fixed_hwaddr_id option will be set to virtual interfaces.");

static int fixed_hwaddr[1024];
static int num_of_fixed_hwaddr;
module_param_array(fixed_hwaddr, int, &num_of_fixed_hwaddr, 0444);
MODULE_PARM_DESC(fixed_hwaddr,
        "[Beta] If @is_hwaddr_fixed is non-zero and this parameter is set, "
        "each virtual hwaddr except the last octet will be replaced with it "
        "(note: the number of the param must be just 1 or the same as @devices.)");

#define SET_HWADDR(addr, _addr1, _addr2, _addr3, _addr4, _addr5, _addr6) \
    do {                 \
        addr[0] = (_addr1); \
        addr[1] = (_addr2); \
        addr[2] = (_addr3); \
        addr[3] = (_addr4); \
        addr[4] = (_addr5); \
        addr[5] = (_addr6); \
    } while (0)


/* ------------------------------------------------------------------------------- */
/* Static parameters                                                               */
/* ------------------------------------------------------------------------------- */
#define MAX_QUEUE_SIZE 1024
#define SAFETY_QUEUE_SIZE 512

/* ------------------------------------------------------------------------------- */
/* Channels and rates                                                              */
/* ------------------------------------------------------------------------------- */
#define CHAN2G(_channel, _freq, _flags) { \
    .band             = IEEE80211_BAND_2GHZ, \
    .hw_value         = (_channel), \
    .center_freq      = (_freq), \
    .flags            = (_flags), \
    .max_antenna_gain = 0, \
    .max_power        = 30, \
}

#define CHAN5G(_channel, _flags) { \
    .band             = IEEE80211_BAND_5GHZ, \
    .hw_value         = (_channel), \
    .center_freq      = 5000 + (5 * (_channel)), \
    .flags            = (_flags), \
    .max_antenna_gain = 0, \
    .max_power        = 30, \
}

#define CHAN60G(_channel, _flags) { \
    .band             = IEEE80211_BAND_60GHZ, \
    .hw_value         = (_channel), \
    .center_freq      = 56160 + (2160 * (_channel)), \
    .flags            = (_flags), \
    .max_antenna_gain = 0, \
    .max_power        = 30, \
}

static struct ieee80211_channel wtap_supported_channels_2ghz[] = {/*{{{*/
    CHAN2G( 1, 2412, 0),
    CHAN2G( 2, 2417, 0),
    CHAN2G( 3, 2422, 0),
    CHAN2G( 4, 2427, 0),
    CHAN2G( 5, 2432, 0),
    CHAN2G( 6, 2437, 0),
    CHAN2G( 7, 2442, 0),
    CHAN2G( 8, 2447, 0),
    CHAN2G( 9, 2452, 0),
    CHAN2G(10, 2457, 0),
    CHAN2G(11, 2462, 0),
    CHAN2G(12, 2467, 0),
    CHAN2G(13, 2472, 0),
    CHAN2G(14, 2484, 0),
};/*}}}*/

static struct ieee80211_channel wtap_supported_channels_5ghz[] = {/*{{{*/
    CHAN5G( 34, 0),
    CHAN5G( 38, 0),
    CHAN5G( 42, 0),
    CHAN5G( 46, 0),

    /* IEEE 802.11n/ac */
    CHAN5G( 36, 0),
    CHAN5G( 40, 0),
    CHAN5G( 44, 0),
    CHAN5G( 48, 0),
    CHAN5G( 52, 0),
    CHAN5G( 56, 0),
    CHAN5G( 60, 0),
    CHAN5G( 64, 0),
    CHAN5G(100, 0),
    CHAN5G(104, 0),
    CHAN5G(108, 0),
    CHAN5G(112, 0),
    CHAN5G(116, 0),
    CHAN5G(120, 0),
    CHAN5G(124, 0),
    CHAN5G(128, 0),
    CHAN5G(132, 0),
    CHAN5G(136, 0),
    CHAN5G(140, 0),
    CHAN5G(149, 0),
    CHAN5G(153, 0),
    CHAN5G(157, 0),
    CHAN5G(161, 0),
    CHAN5G(165, 0),

    /* IEEE 802.11p */
    /* ITA-G5B */
    CHAN5G(170, 0),
    CHAN5G(171, 0),
    CHAN5G(172, 0),
    CHAN5G(173, 0),
    CHAN5G(174, 0),

    /* ITS-G5A */
    CHAN5G(175, 0),
    CHAN5G(176, 0),
    CHAN5G(177, 0),
    CHAN5G(178, 0),
    CHAN5G(179, 0),
    CHAN5G(180, 0),
    CHAN5G(181, 0),

    /* ITS-G5D */
    CHAN5G(182, 0),
    CHAN5G(183, 0),
    CHAN5G(184, 0),
    CHAN5G(185, 0),

    CHAN5G(188, 0),
    CHAN5G(192, 0),
    CHAN5G(196, 0),

    CHAN5G(200, 0),
    CHAN5G(204, 0),
    CHAN5G(208, 0),
    CHAN5G(212, 0),
    CHAN5G(216, 0),
};/*}}}*/

static struct ieee80211_channel wtap_supported_channels_60ghz[] = {/*{{{*/
    CHAN60G(1, 0),
    CHAN60G(2, 0),
    CHAN60G(3, 0),
    CHAN60G(4, 0),
};/*}}}*/

// Check short preamble
#define SHPCHECK(__hw_rate, __flags) \
    (((__flags) & IEEE80211_RATE_SHORT_PREAMBLE) ? ((__hw_rate) | 0x04) : 0)

// @hw_value, @hw_value_short: It is used to identify each information.
// These parameters is for driver use only.
#define RATE(_bitrate, _hw_rate, _flags) { \
    .bitrate = (_bitrate), \
    .flags = (_flags), \
    .hw_value = (_hw_rate), \
    .hw_value_short = (SHPCHECK(_hw_rate, _flags)) \
}

static struct ieee80211_rate __wtap_supported_rates[] = {/*{{{*/
    RATE( 10, 0x00, 0),
    RATE( 20, 0x01, IEEE80211_RATE_SHORT_PREAMBLE),
    RATE( 55, 0x02, IEEE80211_RATE_SHORT_PREAMBLE),
    RATE(110, 0x03, IEEE80211_RATE_SHORT_PREAMBLE),
    RATE( 60, 0x0b, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
    RATE( 90, 0x0f, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
    RATE(120, 0x0a, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
    RATE(180, 0x0e, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
    RATE(240, 0x09, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
    RATE(360, 0x0d, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
    RATE(480, 0x08, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
    RATE(540, 0x0c, (IEEE80211_RATE_SUPPORTS_5MHZ | IEEE80211_RATE_SUPPORTS_10MHZ)),
};/*}}}*/

#define wtap_supported_11g_rates (__wtap_supported_rates + 0)
#define wtap_supported_11g_rates_size (ARRAY_SIZE(__wtap_supported_rates))
#define wtap_supported_11a_rates (__wtap_supported_rates + 4)
#define wtap_supported_11a_rates_size (ARRAY_SIZE(__wtap_supported_rates) - 4)

static struct ieee80211_supported_band wtap_supported_band_2ghz = {/*{{{*/
    .channels = wtap_supported_channels_2ghz,
    .n_channels = ARRAY_SIZE(wtap_supported_channels_2ghz),
    .bitrates = wtap_supported_11g_rates,
    .n_bitrates = wtap_supported_11g_rates_size,
};/*}}}*/

static struct ieee80211_supported_band wtap_supported_band_5ghz = {/*{{{*/
    .channels = wtap_supported_channels_5ghz,
    .n_channels = ARRAY_SIZE(wtap_supported_channels_5ghz),
    .bitrates = wtap_supported_11a_rates,
    .n_bitrates = wtap_supported_11a_rates_size,
};/*}}}*/

static struct ieee80211_supported_band wtap_supported_band_60ghz = {/*{{{*/
    .channels = wtap_supported_channels_60ghz,
    .n_channels = ARRAY_SIZE(wtap_supported_channels_60ghz),
};/*}}}*/

#define IFACE_LIMIT_MAX_INTERFACES 1024
#define IFACE_LIMIT_DIFFERENT_CHANS 1

#define IFACE_DFS_LIMIT_MAX_INTERFACES 8
#define IFACE_DFS_LIMIT_DIFFERENT_CHANS 1

#define IFACE_P2P_LIMIT_MAX_INTERFACES 8
#define IFACE_P2P_LIMIT_DIFFERENT_CHANS 1
static const struct ieee80211_iface_limit wtap_iface_limits[] = {/*{{{*/
    {
        .max = 1,
        .types = BIT(NL80211_IFTYPE_ADHOC),
    },
    {
        .max = IFACE_LIMIT_MAX_INTERFACES,
        .types = BIT(NL80211_IFTYPE_STATION) |
            BIT(NL80211_IFTYPE_AP) |
            BIT(NL80211_IFTYPE_MESH_POINT) |
            BIT(NL80211_IFTYPE_P2P_CLIENT) |
            BIT(NL80211_IFTYPE_P2P_GO) |
            BIT(NL80211_IFTYPE_OCB),
    },
    {
        .max = 1,
        .types = BIT(NL80211_IFTYPE_P2P_DEVICE),
    },
};/*}}}*/

static const struct ieee80211_iface_limit wtap_iface_dfs_limits[] = {/*{{{*/
    {
        .max = IFACE_DFS_LIMIT_MAX_INTERFACES,
        .types = BIT(NL80211_IFTYPE_AP),
    },
};/*}}}*/

static const struct ieee80211_iface_combination wtap_iface_comb[] = {/*{{{*/
    {
        .limits = wtap_iface_limits,
        .n_limits = ARRAY_SIZE(wtap_iface_limits) - 1,
        .max_interfaces = IFACE_LIMIT_MAX_INTERFACES,
        .num_different_channels = IFACE_LIMIT_DIFFERENT_CHANS,
    },
    {
        .limits = wtap_iface_dfs_limits,
        .n_limits = ARRAY_SIZE(wtap_iface_dfs_limits),
        .max_interfaces = IFACE_DFS_LIMIT_MAX_INTERFACES,
        .num_different_channels = IFACE_DFS_LIMIT_DIFFERENT_CHANS,
        .radar_detect_widths = BIT(NL80211_CHAN_WIDTH_20_NOHT) |
            BIT(NL80211_CHAN_WIDTH_20) |
            BIT(NL80211_CHAN_WIDTH_40) |
            BIT(NL80211_CHAN_WIDTH_80) |
            BIT(NL80211_CHAN_WIDTH_160),
    },
};/*}}}*/

static const struct ieee80211_iface_combination wtap_iface_comb_p2p[] = {/*{{{*/
    {
        .limits = wtap_iface_limits,
        .n_limits = ARRAY_SIZE(wtap_iface_limits),
        .max_interfaces = IFACE_P2P_LIMIT_MAX_INTERFACES,
        .num_different_channels = IFACE_P2P_LIMIT_DIFFERENT_CHANS,
    },
    {
        .limits = wtap_iface_dfs_limits,
        .n_limits = ARRAY_SIZE(wtap_iface_dfs_limits),
        .max_interfaces = IFACE_DFS_LIMIT_MAX_INTERFACES,
        .num_different_channels = IFACE_DFS_LIMIT_DIFFERENT_CHANS,
        .radar_detect_widths = BIT(NL80211_CHAN_WIDTH_20_NOHT) |
            BIT(NL80211_CHAN_WIDTH_20)      |
            BIT(NL80211_CHAN_WIDTH_40)      |
            BIT(NL80211_CHAN_WIDTH_80)      |
            BIT(NL80211_CHAN_WIDTH_160),
    }
};/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Shared resources                                                                */
/* ------------------------------------------------------------------------------- */
static struct wtap_shared {/*{{{*/
    // Network interface information
    struct class *class;
    struct net_device *ndev;

    // Device list
    struct list_head dev_list;

    // Counters
    int dev_index;

    // Tasklet
    struct tasklet_struct tx_taskq;
    struct tasklet_struct rx_taskq;

    // Workqueue
    struct workqueue_struct *workqueue;

    // spinlock
    spinlock_t spinlock;

    // Mutex
    struct mutex mutex;

    // Netlink
    struct sock *nlsock;
    unsigned int seq;

    /* Note: sender portid has a type of u32 (unsigend int) */
    /* int portid; */
    u32 portid;

    struct genl_info genl_info;

} wtap_shared;/*}}}*/

static struct platform_driver wtap_platform_driver = {/*{{{*/
    .driver = {
        .name = "wtap80211",
        .owner = THIS_MODULE,
    },
};/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Private resources                                                               */
/* ------------------------------------------------------------------------------- */

/* Resouce status flags */
enum channel_status_id {
    CHANNEL_AVAILABLE   = BIT(0),
    HW_SCAN_SCHEDULED   = BIT(1),
    TX_BEACON_SCHEDULED = BIT(2),
};

struct packet_stats {/*{{{*/
    u64 bytes;       /* the total of bytes except for dropped bytes */
    u64 packets;     /* the total of all packets (= @transmitted + @dropped) */
    u64 dropped;     /* the number of dropped packets */
    u64 syserr;      /* the number of system errors */
};/*}}}*/

struct wtap_priv {/*{{{*/
    struct list_head list;

    struct ieee80211_hw *hw;
    struct device *dev;
    unsigned int index;

    // MAC address
    struct mac_address addresses[2];

    struct ieee80211_channel channels_2ghz[ARRAY_SIZE(wtap_supported_channels_2ghz)];
    struct ieee80211_channel channels_5ghz[ARRAY_SIZE(wtap_supported_channels_5ghz)];
    struct ieee80211_channel channels_60ghz[ARRAY_SIZE(wtap_supported_channels_60ghz)];
    struct ieee80211_rate rates[ARRAY_SIZE(__wtap_supported_rates)];
    struct ieee80211_supported_band bands[IEEE80211_NUM_BANDS];
    struct ieee80211_iface_combination iface_combination;
    struct ieee80211_channel *channel; // Current channel
    struct ieee80211_channel *tmp_channel;
    struct ieee80211_channel prev_channel;
    u32 channels;
    const struct ieee80211_regdomain *regd;
    bool is_set_prev_channel;
    int channel_status;

    // Properties for scanning
    struct cfg80211_scan_request *scan_request;
    struct ieee80211_vif *scan_vif;
    u8 scan_addr[ETH_ALEN];
    int scan_chan_idx;
    struct delayed_work hw_scan;
    unsigned int rx_filter;

    struct list_head vif_list;
    u32 assigned_vifs;

    struct delayed_work roc_done;
    struct delayed_work destroy_work;
    struct delayed_work rx_work;

    // Properties for beacon
    u64 beacon_interval;
    s64 beacon_delta;
    u64 abs_bcn_ts; // Absolute beacon trasmittion time
    struct tasklet_hrtimer beacon_timer;

    // tsf
    s64 tsf_offset;

    // Packet pending
    struct sk_buff_head pending;

    // Device status
    int power_level;
    bool started;
    bool idle;
    bool scanning;
    bool master;
    bool p2p;

    bool use_chanctx;
    bool p2p_device;
    bool destroy_on_close;

    // Mutex
    struct mutex mutex;

    // Stats
    spinlock_t stats_spinlock;
    unsigned int tx_bytes;
    unsigned int rx_bytes;
    unsigned int tx_packets;
    unsigned int rx_packets;
    unsigned int tx_dropped;
    unsigned int rx_dropped;
    unsigned int tx_failed;
    unsigned int rx_failed;

    struct {
        spinlock_t spinlock;
        struct packet_stats tx;
        struct packet_stats rx;
    } stat;

    // debugfs
    struct dentry *debugfs;
    u64 test_value;
    struct sk_buff_head last_tx_frames;
    struct sk_buff_head last_rx_frames;
};/*}}}*/

struct wtap_vif_priv {/*{{{*/
    struct list_head list;

    u32 id;

    struct ieee80211_chanctx_conf *chanctx_conf;
    struct wtap_chanctx_priv *chanctx;
    bool ctx_assigned;
    bool bss_joined;

    struct ieee80211_bss_conf bss_conf;

    u8 bssid[ETH_ALEN];
    bool assoc;
    u16 aid;
    bool use_cts_prot;
    bool use_short_preamble;
    bool use_short_slot;
    bool enable_beacon;
    u16 beacon_int;
    u32 basic_rates;
    bool idle;
    u8 ssid[IEEE80211_MAX_SSID_LEN];
    size_t ssid_len;
    bool hidden_ssid;
    u32 txpower;
};/*}}}*/

struct wtap_sta_priv {/*{{{*/
    u32 sta_id;
};/*}}}*/

struct wtap_chanctx_priv {/*{{{*/
    u32 ctx_id;
    int power_level;
};/*}}}*/

// Containers --------------------------------------------------------------------

struct wtap_frame_container {/*{{{*/
    struct ieee80211_hw *hw;
    struct sk_buff *skb;
    struct ieee80211_channel *channel;
    struct ieee80211_tx_info *tx_info;
    struct ieee80211_tx_control *tx_control;
    struct ieee80211_rx_status *rx_status;
};/*}}}*/

struct wtap_work_struct {/*{{{*/
    struct work_struct work;
    struct wtap_priv *priv;
    void *data;
    unsigned int datalen;
    struct ieee80211_channel *channel;
    struct ieee80211_tx_control *tx_control;
    struct ieee80211_rx_status *rx_status;
};/*}}}*/

/* ------------------------------------------------------------------------------- */
/* debugfs operations                                                              */
/* ------------------------------------------------------------------------------- */

/* simple_test */

static int wtap_fops_simple_test_read(void *data, u64 *val) {/*{{{*/
    struct wtap_priv *priv = data;
    *val = priv->test_value;
    debug_msg("debugfs read: priv->test_value = %llu", priv->test_value);
    return 0;
}/*}}}*/

static int wtap_fops_simple_test_write(void *data, u64 val) {/*{{{*/
    struct wtap_priv *priv = data;
    priv->test_value = val;
    debug_msg("debugfs write: priv->test_value = %llu", priv->test_value);
    return 0;
}/*}}}*/
DEFINE_SIMPLE_ATTRIBUTE(wtap_fops_simple_test,
        wtap_fops_simple_test_read, wtap_fops_simple_test_write, "%llu\n");

/* Main test */
static int wtap_fops_test_open(struct inode *inode, struct file *file) {/*{{{*/
    file->private_data = &inode->i_rdev;
    return 0;
}/*}}}*/

/* Memo: @len is the size of @buf */
static ssize_t wtap_fops_test_read(struct file *file, char __user *buf,/*{{{*/
        size_t len, loff_t *ppos)
{
    struct wtap_shared *shared = &wtap_shared;
    struct inode *inode = file->f_inode;
    struct wtap_priv *priv = inode->i_private;
    struct sk_buff *skb = NULL;

    return 0;

}/*}}}*/

static struct file_operations wtap_fops_test = {/*{{{*/
    .owner = THIS_MODULE,
    .read  = wtap_fops_test_read,
};/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Clock                                                                           */
/* ------------------------------------------------------------------------------- */
static inline u64 wtap_get_time_us(void) {/*{{{*/
    return ktime_to_us(ktime_get_real());
}/*}}}*/

static inline __le64 wtap_get_tsf_le64(struct wtap_priv *priv) {/*{{{*/
    u64 now = wtap_get_time_us();
    return cpu_to_le64(now + priv->tsf_offset);
}/*}}}*/

static inline u64 wtap_get_tsf(struct wtap_priv *priv) {/*{{{*/
    u64 now = wtap_get_time_us();
    return (now + priv->tsf_offset);
}/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Generic Netlink                                                                 */
/* ------------------------------------------------------------------------------- */

// Generic Netlink Family -------------------------------------------------------

static struct genl_family wtap_genl_family = {/*{{{*/
    .id = GENL_ID_GENERATE,
    .hdrsize = 0,
    .name = "wtap80211",
    .version = 20171201,
    .maxattr = WTAP_GENL_ATTR_MAX,
};/*}}}*/

// Netlink multicast groups -----------------------------------------------------

enum wtap_multicast_group_attrs {/*{{{*/
    WTAP_MCGRP_CONFIG,
    __WTAP_MCGRP_ATTR,
};/*}}}*/

static const struct genl_multicast_group wtap_genl_mcgrps[] = {/*{{{*/
    [WTAP_MCGRP_CONFIG] = { .name = "config", },
};/*}}}*/

// Generic Netlink Policy -------------------------------------------------------

static const struct nla_policy wtap_genl_policy[WTAP_GENL_ATTR_MAX + 1] = {/*{{{*/
    [WTAP_GENL_ATTR_AUTH_CHECKSUM] = { .type = NLA_U32 },
    [WTAP_GENL_ATTR_DOT_ELEVEN_FRAME] = {
        .type = NLA_BINARY, .len = IEEE80211_MAX_FRAME_LEN,
    },
    [WTAP_GENL_ATTR_FCS] = { .type = NLA_U32 },
    [WTAP_GENL_ATTR_TX_INFO] = {
        .type = NLA_BINARY, .len = sizeof(struct ieee80211_tx_info),
    },
    [WTAP_GENL_ATTR_RX_STATUS] = {
        .type = NLA_BINARY, .len = sizeof(struct ieee80211_rx_status),
    },
    [WTAP_GENL_ATTR_FREQUENCY] = { .type = NLA_U32, },
    [WTAP_GENL_ATTR_CHANNEL] = {
        .type = NLA_BINARY, .len = sizeof(struct ieee80211_channel),
    },
    [WTAP_GENL_ATTR_FLAGS] = { .type = NLA_U32 },

    [WTAP_GENL_ATTR_CONF_ADDR] = { .type = NLA_BINARY, .len = ETH_ALEN },
    [WTAP_GENL_ATTR_CONF_TYPE] = { .type = NLA_U32 },
    [WTAP_GENL_ATTR_CONF_CHANGED] = { .type = NLA_U32 },
    [WTAP_GENL_ATTR_CONF_PARAM] = { .type = NLA_BINARY, .len = 128 },
    [WTAP_GENL_ATTR_ADDRLIST] = { .type = NLA_BINARY },
};/*}}}*/

// Notifier block ---------------------------------------------------------------

static int wtap_genl_notify(struct notifier_block *nb,/*{{{*/
        unsigned long state,
        void *_notify)
{
    if (state != NETLINK_URELEASE) {
        return NOTIFY_DONE;
    }

    return NOTIFY_DONE;
}/*}}}*/

static struct notifier_block wtap_genl_notifier = {/*{{{*/
    .notifier_call = wtap_genl_notify,
};/*}}}*/

// Netlink message builder ------------------------------------------------------

static inline u8 get_active_freq(struct wtap_priv *priv) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    u8 freq = 0;

    spin_lock_bh(&shared->spinlock);

    if (priv->tmp_channel) {
        freq = priv->tmp_channel->center_freq;
    } else if (priv->channel) {
        freq = priv->channel->center_freq;
    }

    spin_unlock_bh(&shared->spinlock);

    return freq;
}/*}}}*/

static int wtap_append_auth_ack_to_genlmsg(struct sk_buff *skb,/*{{{*/
        void *_data)
{
    struct wtap_shared *shared = &wtap_shared;
    void *data = NULL;

    data = genlmsg_put(skb, shared->portid, 0,
            &wtap_genl_family, 0, WTAP_GENL_CMD_AUTH_ACK);
    if (!data) {
        genlmsg_cancel(skb,data);
        return -EINVAL;
    }

    genlmsg_end(skb, data);
    return 0;
}/*}}}*/

static void wtap_get_addrlist_all(char *buf);

static int wtap_append_addrlist(struct sk_buff *skb, void *data)/*{{{*/
{
    struct wtap_shared *shared = &wtap_shared;
    char *addrlist = NULL;
    void *payload = NULL;
    int err = 0;

    addrlist = (char*)kmalloc(num_of_devices * (sizeof(char) * ETH_ALEN), GFP_KERNEL);
    if (!addrlist)
        return -EINVAL;

    payload = genlmsg_put(skb, shared->portid, 0,
            &wtap_genl_family, 0, WTAP_GENL_CMD_AUTH_ACK);
    if (!payload) {
        genlmsg_cancel(skb, payload);
        return -EINVAL;
    }

    wtap_get_addrlist_all(addrlist);

    err = nla_put(skb, WTAP_GENL_ATTR_ADDRLIST,
            (ETH_ALEN * num_of_devices), addrlist);
    if (err < 0)
        return err;

    genlmsg_end(skb, payload);

    return 0;
}/*}}}*/

static int wtap_append_frame_to_genlmsg(struct sk_buff *skb,/*{{{*/
        void *_data)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_frame_container *cn =
        (struct wtap_frame_container*)_data;
    struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
    struct ieee80211_hw *hw = cn->hw;
    struct ieee80211_channel *channel = cn->channel;
    void *data = NULL;
    u32 freq = 0;
    int err = 0;

    data = genlmsg_put(skb, shared->portid, 0,
            &wtap_genl_family, 0, WTAP_GENL_CMD_TX_FRAME);
    if (!data) {
        genlmsg_cancel(skb, data);
        return -EINVAL;
    }

    err = nla_put(skb, WTAP_GENL_ATTR_DOT_ELEVEN_FRAME,
            cn->skb->len, cn->skb->data);
    if (err < 0) { return err; }

    err = nla_put(skb, WTAP_GENL_ATTR_TX_INFO,
            sizeof(*tx_info), tx_info);
    if (err < 0) { return err; }

    freq = get_active_freq(hw->priv);
    err = nla_put(skb, WTAP_GENL_ATTR_FREQUENCY, sizeof(freq), &freq);
    if (err < 0) { return err; }

    if (channel) {
        err = nla_put(skb, WTAP_GENL_ATTR_CHANNEL,
                sizeof(*channel), channel);
        if (err < 0) { return err; }
    }

    /*
     * debug_msg("  tx_info: flags = %#x, band = %d, queue = %d, ack_id = %d",
     *     tx_info->flags, tx_info->band, tx_info->hw_queue, tx_info->ack_frame_id);
     */

    genlmsg_end(skb, data);

    return 0;
}/*}}}*/

static struct sk_buff* wtap_build_genlmsg(/*{{{*/
        int (*genlmsg_formatter)(struct sk_buff *skb, void *data),
        void *data)
{
    struct wtap_frame_container *cn = data;
    struct sk_buff *skb = NULL;
    int err = 0;

    skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!skb) {
        return NULL;
    }

    if (genlmsg_formatter) {
        if ((err = genlmsg_formatter(skb, data)) < 0) {
            nlmsg_free(skb);
            return NULL;
        }
    }

    return skb;
}/*}}}*/

static void __wtap_tx(struct work_struct *_work) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_work_struct *work =
        container_of(_work, struct wtap_work_struct, work);
    struct wtap_priv *priv = work->priv;
    struct wtap_frame_container cn = {0};
    struct sk_buff *frame_skb = work->data;
    struct sk_buff *genl_skb = NULL;
    struct ieee80211_hdr *hdr = (void*)frame_skb->data;
    int err = 0;

    cn.hw = priv->hw;
    cn.skb = work->data;
    cn.channel = work->channel;

    debug_msg("__wtap_tx");
    ieee80211_free_txskb(priv->hw, work->data);
    kfree(_work);
    return ;

    genl_skb = wtap_build_genlmsg(wtap_append_frame_to_genlmsg, &cn);
    if (!genl_skb) {
        err = -ENOMEM;
        goto error;
    }

    err = genlmsg_unicast(&init_net, genl_skb, shared->portid);
    if (err != 0) {
        if (printk_ratelimit()) {
            error_msg("could not send %s frame (%pM -> %pM) to the user space.",
                    ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                    hdr->addr2, hdr->addr1);
        }
        goto error;
    }

    ieee80211_free_txskb(priv->hw, work->data);
    kfree(_work);

    return ;

error:
    ieee80211_free_txskb(priv->hw, work->data);
    spin_lock_bh(&shared->spinlock);
    priv->tx_dropped += frame_skb->len;
    priv->tx_failed++;
    spin_unlock_bh(&shared->spinlock);
    kfree(_work);
}/*}}}*/

static int _wtap_tx(struct ieee80211_hw *hw,/*{{{*/
        struct sk_buff *_skb,
        struct ieee80211_channel *channel)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct wtap_frame_container cn = {0};
    struct sk_buff *skb = NULL;
    struct ieee80211_hdr *hdr = (void*)_skb->data;
    int err = 0;

    cn.hw = hw;
    cn.skb = _skb;
    cn.channel = channel;

    skb = wtap_build_genlmsg(wtap_append_frame_to_genlmsg, &cn);
    if (!skb) {
        err = -ENOMEM;
        goto out_ieee80211_free_txskb;
    }

    err = genlmsg_unicast(&init_net, skb, shared->portid);
    if (err != 0) {
        if (printk_ratelimit()) {
            error_msg("could not send %s frame (%pM -> %pM) to the user space.",
                    ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                    hdr->addr2, hdr->addr1);
        }
        return err;
    }

    return 0;

out_ieee80211_free_txskb:
    ieee80211_free_txskb(hw, _skb);
    spin_lock_bh(&shared->spinlock);
    priv->tx_dropped += _skb->len;
    priv->tx_failed++;
    spin_unlock_bh(&shared->spinlock);
    return err;
}/*}}}*/

static u32 calc_fcs(const unsigned char *data, int len);
static void wtap_tx_frame_loopback(struct ieee80211_hw *hw,
                                   struct sk_buff *skb,
                                   struct ieee80211_channel *channel);
static int wtap_tx(struct ieee80211_hw *hw,/*{{{*/
        struct sk_buff *skb,
        struct ieee80211_channel *channel)
{
    const struct wtap_shared *shared = &wtap_shared;
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr*)skb->data;
    struct ieee80211_hdr *hdr_fcs = NULL;
    struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
    /* int size = skb->len + sizeof(*tx_info) + sizeof(u32) + sizeof(*channel); */
    size_t size = GENLMSG_DEFAULT_SIZE;
    struct sk_buff *genlskb = NULL;
    void *data = NULL;
    u32 freq = 0;
    u32 fcs = 0;
    u32 flags = 0;
    int err = 0;

    if (!(hdr_fcs = (struct ieee80211_hdr*)kmalloc(skb->len + sizeof(u32), GFP_KERNEL))) {
        warn_msg("[Warning] 802.11 frame does not have fcs field.");
        flags &= ~WTAP_FRAME_MSG_FLAG_FCS;
    } else {
        fcs = calc_fcs((const unsigned char*)skb->data, skb->len);
        memcpy(hdr_fcs, skb->data, skb->len);
        memcpy((char*)hdr_fcs + skb->len, &fcs, sizeof(fcs));
        flags |= WTAP_FRAME_MSG_FLAG_FCS;
    }

    if (is_loopback_enabled > 0) {
        wtap_tx_frame_loopback(hw, skb, channel);
    } else {
        struct nlmsghdr *nlhdr = NULL;
        struct genlmsghdr *genlhdr = NULL;

        if (!(genlskb = genlmsg_new(size, GFP_KERNEL)))
            goto drop;

        nlhdr = (struct nlmsghdr*)genlskb->data;
        genlhdr = (struct genlmsghdr*)nlmsg_data(nlhdr);

        data = genlmsg_put(genlskb, shared->genl_info.snd_portid, 0,
                &wtap_genl_family, 0, WTAP_GENL_CMD_TX_FRAME);
        if (!data) {
            err = -ENOMEM;
            goto out;
        }

        if (hdr_fcs) {
            if ((err = nla_put(genlskb, WTAP_GENL_ATTR_DOT_ELEVEN_FRAME,
                            skb->len + sizeof(fcs), hdr_fcs)) < 0)
                goto out;
        } else {
            if ((err = nla_put(genlskb, WTAP_GENL_ATTR_DOT_ELEVEN_FRAME,
                            skb->len, skb->data)) < 0)
                goto out;
        }

        if ((err = nla_put(genlskb, WTAP_GENL_ATTR_FCS, sizeof(u32), &fcs)) < 0)
            goto out;

        if ((err = nla_put(genlskb, WTAP_GENL_ATTR_FLAGS, sizeof(u32), &flags)) < 0)
            goto out;

        err = nla_put(genlskb, WTAP_GENL_ATTR_TX_INFO,
                sizeof(*tx_info), tx_info);
        if (err < 0)
            goto out;

        freq = get_active_freq(hw->priv);
        err = nla_put(genlskb, WTAP_GENL_ATTR_FREQUENCY, sizeof(freq), &freq);
        if (err < 0)
            goto out;

        if (channel) {
            err = nla_put(genlskb, WTAP_GENL_ATTR_CHANNEL,
                    sizeof(struct ieee80211_channel), channel);
            if (err < 0)
                goto out;
        }

        genlmsg_end(genlskb, data);

        if (!ieee80211_is_beacon(hdr->frame_control)) {
            debug_msg("TX frame message = {family_id = %d, portid = %u, "
                    "nlhdr: len = %d, type = %u, seq = %u, pid = %u, "
                    "genlhdr: cmd = %d, version = %d}",
                    wtap_genl_family.id, shared->portid,
                    nlhdr->nlmsg_len, nlhdr->nlmsg_type,
                    nlhdr->nlmsg_seq, nlhdr->nlmsg_pid,
                    genlhdr->cmd, genlhdr->version);
        }

        err = genlmsg_unicast(&init_net, genlskb, shared->genl_info.snd_portid);
        if (err < 0) {
            /*
             * Do not free genlskb by yourself because
             * nlmsg_free() is called in genlmsg_unicast().
             */
            goto drop;
        }
    }

    if (hdr_fcs)
        kfree(hdr_fcs);

    if (!ieee80211_is_beacon(hdr->frame_control)) {
        debug_msg("TX %s frame = {len = %u, freq = %d, flags = 0x%x, fc = %#04x, seq_ctrl = 0x%x fcs = 0x%x} "
                "(%pM -> %pM)",
                ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                skb->len, channel->center_freq, flags, hdr->frame_control,
                hdr->seq_ctrl, fcs, hdr->addr2, hdr->addr1);
    }

    return 0;

out:
    nlmsg_free(genlskb);

drop:
    /* ieee80211_free_txskb(hw, skb); */
    debug_msg("%s frame was dropped (err: %d)",
            ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)], err);
    return err;
}/*}}}*/

static int wtap_send_mgmt_msg(struct ieee80211_hw *hw,/*{{{*/
        u32 type, u32 changed,
        const void *conf, const u32 conf_len,
        struct genl_info *info)
{
    const struct wtap_shared *shared = &wtap_shared;
    struct sk_buff *genlskb = NULL;
    void *msghdr = NULL;
    int err = 0;

    if (!(type & ( WTAP_MGMT_MSG_TYPE_BSS_INFO
                    | WTAP_MGMT_MSG_TYPE_RX_FILTER
                    | WTAP_MGMT_MSG_TYPE_TX_QUEUE
                    | WTAP_MGMT_MSG_TYPE_HW_CONF
                    | WTAP_MGMT_MSG_TYPE_TX_CONF
                    | WTAP_MGMT_MSG_TYPE_HW_START
                    | WTAP_MGMT_MSG_TYPE_HW_STOP))) {
        return -EINVAL;
    }

    if (!conf || conf_len < 1) {
        return -EINVAL;
    }

    genlskb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!genlskb) {
        return -ENOMEM;
    }

    msghdr = genlmsg_put(genlskb, 0, 0, &wtap_genl_family, 0, WTAP_GENL_CMD_CONFIG);
    if (!msghdr) {
        err = -ENOMEM;
        goto error;
    }

    err = nla_put(genlskb, WTAP_GENL_ATTR_CONF_ADDR, ETH_ALEN, hw->wiphy->perm_addr);
    if (err < 0) { goto error; }

    err = nla_put_u32(genlskb, WTAP_GENL_ATTR_CONF_TYPE, type);
    if (err < 0) { goto error; }

    err = nla_put_u32(genlskb, WTAP_GENL_ATTR_CONF_CHANGED, changed);
    if (err < 0) { goto error; }

    err = nla_put(genlskb, WTAP_GENL_ATTR_CONF_PARAM, conf_len, conf);
    if (err < 0) { goto error; }

    genlmsg_end(genlskb, msghdr);

    err = genlmsg_unicast(&init_net, genlskb, shared->portid);
    if (err < 0) { return err; }

    return 0;

error:
    /* genlmsg_cancel(skb, msghdr); */
    nlmsg_free(genlskb);
    return err;
}/*}}}*/

// genl_ops ---------------------------------------------------------------------

static int wtap_genl_ops_config(struct sk_buff *skb,/*{{{*/
        struct genl_info *info)
{
    struct wtap_shared *shared = &wtap_shared;

    if (shared->portid != info->snd_portid) {
        return -EINVAL;
    }

    dev_kfree_skb(skb);

    return 0;
}/*}}}*/

static u32 calc_fcs(const unsigned char *data, int len)
{
    u32 checksum = 0;

    if (!data)
        return 0;

    checksum = crc32(0xffffffff, data, len);

    return ~checksum;
}

static bool validate_auth_checksum(u32 checksum)
{
    const char *keyword = "wtap80211";
    u32 valid_checksum = calc_fcs((const unsigned char*)keyword, strlen(keyword));

    info_msg("valid checksum: 0x%X, requester's checksum: 0x%X",
            valid_checksum, checksum);

    return (checksum == valid_checksum);
}

static int wtap_genl_ops_auth(struct sk_buff *_skb,/*{{{*/
        struct genl_info *info)
{
    struct wtap_shared *shared = &wtap_shared;
    struct nlmsghdr *nlhdr = (struct nlmsghdr*)_skb->data;
    struct genlmsghdr *genlhdr = (struct genlmsghdr*)nlmsg_data(nlhdr);
    struct sk_buff *skb = NULL;
    u32 *checksum = NULL;

    if (!info->attrs[WTAP_GENL_ATTR_AUTH_CHECKSUM]) {
        error_msg("Invalid auth message (checksum not found)");
        return -EINVAL;
    }

    if (!(checksum = nla_data(info->attrs[WTAP_GENL_ATTR_AUTH_CHECKSUM]))
            || !validate_auth_checksum(*checksum))
        return -EINVAL;

    spin_lock_bh(&shared->spinlock);
    shared->portid = info->snd_portid;
    memcpy(&shared->genl_info, info, sizeof(shared->genl_info));
    spin_unlock_bh(&shared->spinlock);

    debug_msg("Auth message received: family_id = %d, portid = %d\n"
              "                       snd_seq = %u, snd_portid = %u\n"
              "                       nlhdr: len = %d, type = %u, seq = %u, pid = %u\n"
              "                       genlhdr: cmd = %d, version = %d",
              /* wtap_genl_family.id, shared->portid, */
              wtap_genl_family.id, shared->genl_info.snd_portid,
              info->snd_seq, info->snd_portid,
              nlhdr->nlmsg_len, nlhdr->nlmsg_type, nlhdr->nlmsg_seq, nlhdr->nlmsg_pid,
              genlhdr->cmd, genlhdr->version);

    /* skb = wtap_build_genlmsg(wtap_append_auth_ack_to_genlmsg, NULL); */
    skb = wtap_build_genlmsg(wtap_append_addrlist, NULL);
    if (!skb) {
        return -ENOMEM;
    }

    if (genlmsg_unicast(&init_net, skb, shared->portid) < 0) {
        error_msg("could not send an ack for authentication.");
        return -EINVAL;
    }

    debug_msg("Auth ack message sent.");

    return 0;
}/*}}}*/

static int wtap_genl_ops_loopback(struct sk_buff *skb, struct genl_info *info)
{
    struct wtap_shared *shared = &wtap_shared;
    struct nlmsghdr *nlhdr = (struct nlmsghdr *)skb->data;
    struct genlmsghdr *genlhdr = (struct genlmsghdr *)nlmsg_data(nlhdr);

    return 0;
}

struct rx_iter_container {/*{{{*/
    struct ieee80211_channel *channel;
    u16 freq;
    bool is_active_iface_found;
    bool is_qos_enabled;
};/*}}}*/

static inline bool ieee80211_chans_compat(struct ieee80211_channel *chan1,/*{{{*/
        struct ieee80211_channel *chan2)
{
    return ((chan1 && chan2)?
            (chan1->center_freq == chan2->center_freq): false);
}/*}}}*/

static void isolate_skb(struct sk_buff *skb) {/*{{{*/

    /* Make the buffer be orphaned from a former owner. */
    skb_orphan(skb);

    /* Drop the destination of the buffer. */
    skb_dst_drop(skb);

    /* Reinitialize the mark */
    skb->mark = 0;

    /* Reset the secure path for xfrm */
    secpath_reset(skb);

    /* Reset the netfilter */
    nf_reset(skb);
}/*}}}*/

struct tx_iter_data {/*{{{*/
    struct ieee80211_channel *channel;
    bool receive;
};/*}}}*/

static void wtap_tx_iter(void *_data, u8 *addr, struct ieee80211_vif *vif) {/*{{{*/
    struct tx_iter_data *data = _data;

    if (!vif->chanctx_conf) {
        data->receive = false;
        return ;
    }

    if (!ieee80211_chans_compat(data->channel, rcu_dereference(vif->chanctx_conf)->def.chan)) {
        data->receive = false;
        return ;
    }

    data->receive = true;
}/*}}}*/

static void wtap_tx_frame_loopback(struct ieee80211_hw *hw,/*{{{*/
                                   struct sk_buff *skb,
                                   struct ieee80211_channel *channel)
{
    struct wtap_priv *rpriv = NULL;
    struct wtap_priv *priv = (struct wtap_priv*)hw->priv;
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr*)skb->data;
    struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
    struct ieee80211_rx_status rx_status = {0};
    u64 now = 0;

    rx_status.flag |= RX_FLAG_MACTIME_START;
    rx_status.freq = channel->center_freq;
    rx_status.band = channel->band;

    /*
     * if (priv->is_set_prev_channel) {
     *     rx_status.freq = priv->prev_channel.center_freq;
     *     rx_status.band = priv->prev_channel.band;
     * } else {
     *     rx_status.freq = channel->center_freq;
     *     rx_status.band = channel->band;
     * }
     */

    /*
     * If the frame will be transmitted using
     * IEEE 802.11ac (VHT mode) or IEEE 802.11n (HT mode),
     * this function sets a suitable rate based on the MCS index.
     * If not, this function sets a rate based on @channel.
     */
    if (tx_info->control.rates[0].flags & IEEE80211_TX_RC_VHT_MCS) {
        rx_status.rate_idx = ieee80211_rate_get_vht_mcs(&tx_info->control.rates[0]);
    } else {
        rx_status.rate_idx = tx_info->control.rates[0].idx;
    }

    /* Release the skb's information */
    isolate_skb(skb);

    /* Obtain absolute mactime */
    if (ieee80211_is_beacon(hdr->frame_control) ||
        ieee80211_is_probe_resp(hdr->frame_control)) {
        now = priv->abs_bcn_ts;
    } else {
        now = wtap_get_tsf(priv);
    }

    spin_lock(&wtap_shared.spinlock);
    list_for_each_entry(rpriv, &wtap_shared.dev_list, list) {
        struct sk_buff *cloned_skb = NULL;
        struct tx_iter_data tx_iter_data = {
            .receive = false,
            .channel = channel,
        };

        if (priv == rpriv) {
            continue;
        }

        if (!rpriv->started || (rpriv->idle && !rpriv->tmp_channel)) {
            continue;
        }

        /*
         * Search a suitable multi channel definition from a mcs list
         * if @channel does not match a single channel definition.
         */
        if (!ieee80211_chans_compat(channel, rpriv->tmp_channel) &&
            !ieee80211_chans_compat(channel, rpriv->channel)) {

            ieee80211_iterate_active_interfaces_atomic(
                    rpriv->hw, IEEE80211_IFACE_ITER_NORMAL,
                    wtap_tx_iter, &tx_iter_data);

            if (!tx_iter_data.receive)
                continue;
        }

        cloned_skb = skb_copy(skb, GFP_ATOMIC);
        if (!cloned_skb)
            continue;

        /* Update the mactime */
        rx_status.mactime = now + rpriv->abs_bcn_ts;

        memcpy(IEEE80211_SKB_RXCB(cloned_skb), &rx_status, sizeof(rx_status));

        ieee80211_rx_irqsafe(rpriv->hw, cloned_skb);
    }
    spin_unlock(&wtap_shared.spinlock);
}/*}}}*/

static void wtap_rx_active_iface_iterator(void *data, u8 *addr,/*{{{*/
        struct ieee80211_vif *vif)
{
    struct wtap_shared *shared = &wtap_shared;
    struct rx_iter_container *cn = data;
    struct wtap_vif_priv *vpriv = (struct wtap_vif_priv *)vif->drv_priv;
    struct ieee80211_channel *vif_chan = rcu_dereference(vif->chanctx_conf)->def.chan;

    cn->is_active_iface_found = false;

    if (!vif->chanctx_conf || !vpriv->ctx_assigned)
        return;

    if (cn->freq == vif_chan->center_freq)
        cn->is_active_iface_found = true;

    if (vpriv->bss_conf.qos)
        cn->is_qos_enabled = true;

}/*}}}*/

static void wtap_rx(struct wtap_priv *priv,/*{{{*/
        struct sk_buff *skb)
{
    /* ieee80211_rx_irqsafe(priv->hw, skb); */
    ieee80211_rx(priv->hw, skb);
}/*}}}*/

static bool is_src_hwaddr(struct wtap_priv *priv,/*{{{*/
        struct ieee80211_hdr *hdr)
{
    char *perm_addr = priv->hw->wiphy->perm_addr;
    char *sa = NULL;

    if (ieee80211_is_ctl(hdr->frame_control) ||
            ieee80211_is_mgmt(hdr->frame_control)) {
        sa = ((struct ieee80211_mgmt*)hdr)->sa;
    } else if (ieee80211_is_data(hdr->frame_control)) {
        sa = hdr->addr2;
    }

    return ((memcmp(sa, perm_addr, ETH_ALEN)) == 0);
}/*}}}*/

static bool is_rx_status_valid(struct wtap_priv *priv,/*{{{*/
        struct ieee80211_hdr *hdr,
        struct ieee80211_rx_status *rx_status)
{
    struct ieee80211_channel *channel = NULL;

    if (priv->channel) {
        channel = priv->channel;
    } else if (priv->tmp_channel) {
        channel = priv->tmp_channel;
    } else {
        struct rx_iter_container rx_iter_container = {
            .freq = rx_status->freq,
            .is_active_iface_found = false,
            .is_qos_enabled = false,
        };

        ieee80211_iterate_active_interfaces_atomic(priv->hw,
                IEEE80211_IFACE_ITER_NORMAL,
                wtap_rx_active_iface_iterator,
                &rx_iter_container);

        if (!rx_iter_container.is_active_iface_found)
            return false;

        return true;
    }

    if (channel->center_freq != rx_status->freq)
        return false;

    return true;
}/*}}}*/

static void wtap_rx_work(struct work_struct *_work) {/*{{{*/
    struct wtap_work_struct *work =
        container_of((void*)_work, struct wtap_work_struct, work);
    struct ieee80211_hdr *hdr = work->data;
    unsigned int frame_len = work->datalen;
    struct ieee80211_rx_status rx_status = {0};
    u64 now = 0;

    struct sk_buff *rx_skb = NULL;
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = NULL;
    bool is_received = false;

    memcpy(&rx_status, work->rx_status, sizeof(rx_status));

    /*
     * rx_skb = alloc_skb(frame_len, GFP_KERNEL);
     * if (!rx_skb) {
     *   error_msg("could not allocate memory for rx_skb.");
     *   goto out;
     * }
     * memcpy(skb_put(rx_skb, frame_len), hdr, frame_len);
     */

    if (!ieee80211_is_beacon(hdr->frame_control)) {
        debug_msg("(1)RX %s frame (len = %d) (%pM -> %pM)"
                " (freq = %d, band = %d, signal = %d)",
                ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                frame_len, hdr->addr2, hdr->addr1,
                rx_status.freq, rx_status.band, rx_status.signal);
    }

    return ;

    spin_lock_bh(&shared->spinlock);

    list_for_each_entry(priv, &shared->dev_list, list) {

        if (!priv->started || (priv->idle & !priv->tmp_channel))
            continue;

        if (is_src_hwaddr(priv, hdr))
            continue;

        if (!is_rx_status_valid(priv, hdr, &rx_status))
            continue;

        rx_skb = alloc_skb(frame_len, GFP_KERNEL);
        if (!rx_skb) {
            spin_unlock_bh(&shared->spinlock);
            goto out;
        }

        /*
         * if (ieee80211_is_beacon(hdr->frame_control) ||
         *     ieee80211_is_probe_resp(hdr->frame_control)) {
         *   now = priv->abs_bcn_ts;
         * } else {
         *   now = wtap_get_time_us();
         * }
         */

        now = wtap_get_time_us() + 1000;
        rx_status.mactime = now + priv->tsf_offset;

        memcpy(skb_put(rx_skb, frame_len), hdr, frame_len);
        memcpy(IEEE80211_SKB_RXCB(rx_skb), &rx_status, sizeof(rx_status));

        priv->rx_packets++;
        priv->rx_bytes += frame_len;
        wtap_rx(priv, rx_skb);
        is_received = true;

        if (!ieee80211_is_beacon(hdr->frame_control)) {
            debug_msg("(2)RX %s frame (len = %d) (%pM -> %pM)"
                    " (freq = %d, band = %d, signal = %d) (mt %llu [us])",
                    ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                    frame_len, hdr->addr2, hdr->addr1,
                    rx_status.freq, rx_status.band, rx_status.signal,
                    rx_status.mactime);
        }
    }

    spin_unlock_bh(&shared->spinlock);

out:
    kfree(_work);
}/*}}}*/

static struct wtap_priv* search_dst_hw(struct ieee80211_hdr *hdr)/*{{{*/
{
    struct wtap_priv *priv, *ret = NULL;
    u8 *da = ieee80211_get_DA(hdr);

    spin_lock_bh(&wtap_shared.spinlock);
    list_for_each_entry(priv, &wtap_shared.dev_list, list) {
        /* if (memcmp(priv->addresses[0].addr, hdr->addr1, ETH_ALEN) == 0) */
        if (memcmp(priv->addresses[0].addr, da, ETH_ALEN) == 0)
            ret = priv;
    }
    spin_unlock_bh(&wtap_shared.spinlock);

    return ret;
}/*}}}*/

static int wtap_rx_broadcast(struct genl_info *info)/*{{{*/
{
    struct ieee80211_hdr *hdr = nla_data(info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]);
    struct ieee80211_channel *channel = nla_data(info->attrs[WTAP_GENL_ATTR_CHANNEL]);
    struct ieee80211_tx_info *tx_info = nla_data(info->attrs[WTAP_GENL_ATTR_TX_INFO]);
    unsigned int frame_len = nla_len(info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]);
    struct ieee80211_rx_status rx_status = {0};
    struct sk_buff *rx_skb = NULL;
    struct wtap_priv *first, *priv = NULL;
    /* u64 now = 0; */
    unsigned int dev_count = 0;

    rx_status.flag |= RX_FLAG_MACTIME_START;
    rx_status.freq = channel->center_freq;
    rx_status.band = channel->band;

    if (tx_info->control.rates[0].flags & IEEE80211_TX_RC_VHT_MCS) {
        rx_status.rate_idx = ieee80211_rate_get_vht_mcs(&tx_info->control.rates[0]);
    } else {
        rx_status.rate_idx = tx_info->control.rates[0].idx;
    }

    /* spin_lock_bh(&wtap_shared.spinlock); */
    list_for_each_entry(priv, &wtap_shared.dev_list, list) {
        struct tx_iter_data tx_iter_data = {
            .receive = false,
            .channel = channel,
        };

        if (!priv->started || (priv->idle && !priv->tmp_channel))
            continue;

        /*
         * Search a suitable multi channel definition from a mcs list
         * if @channel does not match a single channel definition.
         */
        if (!ieee80211_chans_compat(channel, priv->tmp_channel) &&
                !ieee80211_chans_compat(channel, priv->channel)) {

            ieee80211_iterate_active_interfaces_atomic(
                    priv->hw, IEEE80211_IFACE_ITER_NORMAL,
                    wtap_tx_iter, &tx_iter_data);

            if (!tx_iter_data.receive)
                continue;
        }

        mutex_lock(&priv->mutex);

        /* Obtain absolute mactime */
        if (ieee80211_is_beacon(hdr->frame_control) ||
                ieee80211_is_probe_resp(hdr->frame_control)) {
            rx_status.mactime = (u64)priv->abs_bcn_ts;
        } else {
            rx_status.mactime = (u64)wtap_get_tsf(priv);
        }

        mutex_unlock(&priv->mutex);

        if (!(rx_skb = alloc_skb(frame_len, GFP_ATOMIC)))
            goto memory_error;

        memcpy(skb_put(rx_skb, frame_len), hdr, frame_len);

        memcpy(IEEE80211_SKB_RXCB(rx_skb), &rx_status, sizeof(rx_status));

        ieee80211_rx_irqsafe(priv->hw, rx_skb);

        dev_count++;
    }
    /* spin_unlock_bh(&wtap_shared.spinlock); */

memory_error:
    if (!ieee80211_is_beacon(hdr->frame_control)) {
        debug_msg("RX %s frame (broadcast/multicast) (len = %u) (fc = %#06x) on %d[MHz] (%pM -> %pM) "
                "(%d device(s) received)",
                ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                frame_len, hdr->frame_control, channel->center_freq,
                ieee80211_get_SA(hdr), ieee80211_get_DA(hdr), dev_count);
        // wtap_dbg_ieee80211_binary(hdr, frame_len);
    }

    return 0;

}/*}}}*/

static int wtap_genl_ops_rx_frame(struct sk_buff *skb, struct genl_info *info)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = NULL;
    struct ieee80211_hdr *hdr = NULL;
    struct ieee80211_channel *channel = NULL;
    struct ieee80211_tx_info *tx_info = NULL;
    struct ieee80211_rx_status rx_status = {0};
    unsigned int frame_len = 0;
    struct sk_buff *rx_skb = NULL;
    bool is_received = false;
    u64 now = 0;
    int err = 0;

    if (!info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME] ||
            !info->attrs[WTAP_GENL_ATTR_TX_INFO] ||
            !info->attrs[WTAP_GENL_ATTR_CHANNEL]) {
        error_msg("Invalid attributes.");
        return -EINVAL;
    }

    hdr = nla_data(info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]);
    frame_len = nla_len(info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]);
    channel = nla_data(info->attrs[WTAP_GENL_ATTR_CHANNEL]);
    tx_info = nla_data(info->attrs[WTAP_GENL_ATTR_TX_INFO]);

    if (frame_len < 1 || IEEE80211_MAX_FRAME_LEN < frame_len) {
        error_msg("frame_len is too short/long (frame_len = %u).", frame_len);
        return -EINVAL;
    }

    if (!ieee80211_is_beacon(hdr->frame_control)) {
        debug_msg("RX %s frame = {len = %u, fc = %#04x, freq = %d[MHz]} (%pM -> %pM)",
                ieee80211_fctl_name[wtap_dbg_search_fctl(hdr)],
                skb->len, hdr->frame_control, channel->center_freq,
                hdr->addr2, hdr->addr1);
    }

    rx_status.signal = (s8)channel->max_power;
    if (printk_ratelimit()) {
        debug_msg("Signal strength: %d", (int)rx_status.signal);
    }

    rx_status.flag |= RX_FLAG_MACTIME_START;

    if (tx_info->control.rates[0].flags & IEEE80211_TX_RC_VHT_MCS) {
        rx_status.rate_idx = ieee80211_rate_get_vht_mcs(&tx_info->control.rates[0]);
    } else {
        rx_status.rate_idx = tx_info->control.rates[0].idx;
    }

    if (!(priv = search_dst_hw(hdr))) {
        wtap_rx_broadcast(info);
        return 0;
    }

    if (!(rx_skb = alloc_skb(frame_len, GFP_KERNEL)))
        return -ENOMEM;

    memcpy(skb_put(rx_skb, frame_len), hdr, frame_len);

    /* Obtain absolute mactime */
    if (ieee80211_is_beacon(hdr->frame_control) ||
            ieee80211_is_probe_resp(hdr->frame_control)) {
        now = priv->abs_bcn_ts;
    } else {
        now = wtap_get_tsf(priv);
    }

    rx_status.mactime = now;

    if (priv->is_set_prev_channel) {
        rx_status.freq = priv->prev_channel.center_freq;
        rx_status.band = priv->prev_channel.band;
    } else {
        rx_status.freq = channel->center_freq;
        rx_status.band = channel->band;
    }

    memcpy(IEEE80211_SKB_RXCB(rx_skb), &rx_status, sizeof(rx_status));

    ieee80211_rx_irqsafe(priv->hw, rx_skb);

    return 0;
}

#define GENL_OPS(_cmd, _doit, _flags) \
{                                     \
    .cmd = (_cmd),                      \
    .policy = wtap_genl_policy,         \
    .doit = (_doit),                    \
    .flags = (_flags),                  \
}

static const struct genl_ops wtap_genl_ops[] = {/*{{{*/
    GENL_OPS(WTAP_GENL_CMD_CONFIG, wtap_genl_ops_config, GENL_ADMIN_PERM),
    GENL_OPS(WTAP_GENL_CMD_AUTH, wtap_genl_ops_auth, 0),
    GENL_OPS(WTAP_GENL_CMD_RX_FRAME, wtap_genl_ops_rx_frame, 0),
    GENL_OPS(WTAP_GENL_CMD_LOOPBACK, wtap_genl_ops_loopback, 0),
    /* GENL_OPS(WTAP_GENL_CMD_SYNC_REQ, wtap_genl_ops_sync_req, 0), */
};/*}}}*/

static int wtap_genl_init(void) {/*{{{*/
    int err = 0;

    err = genl_register_family_with_ops_groups(&wtap_genl_family,
            wtap_genl_ops, wtap_genl_mcgrps);
    if (err) {
        return -EINVAL;
    }

    err = netlink_register_notifier(&wtap_genl_notifier);
    if (err) {
        return -EINVAL;
    }

    return 0;
}/*}}}*/

static void wtap_genl_exit(void) {/*{{{*/
    // Unregister the notifier
    netlink_unregister_notifier(&wtap_genl_notifier);
    // Unregister the family
    genl_unregister_family(&wtap_genl_family);
}/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Remain on channel                                                               */
/* ------------------------------------------------------------------------------- */
static void wtap_roc_done(struct work_struct *work) {/*{{{*/
    struct wtap_priv *priv = container_of(work, struct wtap_priv, roc_done.work);

    mutex_lock(&priv->mutex);
    // Nofity the kernel that remain on channel expired.
    ieee80211_remain_on_channel_expired(priv->hw);
    priv->tmp_channel = NULL;
    mutex_unlock(&priv->mutex);

    info_msg("HWaddr = %pM: remain on channel expired.",
            priv->hw->wiphy->perm_addr);
}/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Scanning process                                                                */
/* ------------------------------------------------------------------------------- */
// Todo: Add a call to send a probe request
static void wtap_hw_scan_work(struct work_struct *work) {/*{{{*/
    struct wtap_priv *priv = container_of(work, struct wtap_priv, hw_scan.work);
    struct ieee80211_hw *hw = priv->hw;
    struct cfg80211_scan_request *request = priv->scan_request;
    int i, dwell = 0;

    mutex_lock(&priv->mutex);
    if (priv->scan_chan_idx >= request->n_channels) {
        ieee80211_scan_completed(hw, false);
        priv->scan_request = NULL;
        priv->scan_vif = NULL;
        priv->tmp_channel = NULL;
        priv->channel_status &= ~HW_SCAN_SCHEDULED;
        mutex_unlock(&priv->mutex);
        return ;
    }

    info_msg("scanning on %d[MHz]",
            request->channels[priv->scan_chan_idx]->center_freq);

    priv->tmp_channel = request->channels[priv->scan_chan_idx];
    if (priv->tmp_channel->flags & IEEE80211_CHAN_NO_IR || !request->n_ssids) {
        dwell = 120;
    } else {
        dwell = 40;

        // Send a probe request
        for (i = 0; i < request->n_ssids; ++i) {
            struct sk_buff *probe = NULL;

            probe = ieee80211_probereq_get(hw, priv->scan_addr,
                    request->ssids[i].ssid, request->ssids[i].ssid_len, request->ie_len);
            if (!probe)
                continue;

            if (request->ie_len) {
                memcpy(skb_put(probe, request->ie_len), request->ie, request->ie_len);
            }

            local_bh_disable();
            wtap_tx(hw, probe, priv->tmp_channel);
            local_bh_enable();
        }
    }
    ieee80211_queue_delayed_work(hw, &priv->hw_scan, msecs_to_jiffies(dwell));
    priv->scan_chan_idx++;
    mutex_unlock(&priv->mutex);
}/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Beacon                                                                          */
/* ------------------------------------------------------------------------------- */
static void wtap_tx_beacon(void *arg, u8 *addr, struct ieee80211_vif *vif) {/*{{{*/
    struct wtap_priv *priv = (struct wtap_priv*)arg;
    struct ieee80211_hw *hw = priv->hw;
    struct ieee80211_tx_info *info = NULL;
    struct ieee80211_rate *rate = NULL;
    struct ieee80211_mgmt *mgmthdr = NULL;
    struct sk_buff *skb = NULL;

    if (vif->type != NL80211_IFTYPE_AP &&
            vif->type != NL80211_IFTYPE_ADHOC &&
            vif->type != NL80211_IFTYPE_MESH_POINT &&
            vif->type != NL80211_IFTYPE_OCB) {
        return ;
    }

    skb = ieee80211_beacon_get(hw, vif);
    if (!skb) {
        priv->tmp_channel = NULL;
        return ;
    }

    mgmthdr = (struct ieee80211_mgmt*)skb->data;

    info = IEEE80211_SKB_CB(skb);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    if (hw->flags & IEEE80211_HW_SUPPORTS_RC_TABLE) {}
#endif

    // Set counterfeit transmission time
    priv->abs_bcn_ts = wtap_get_time_us();
    rate = ieee80211_get_tx_rate(hw, info);
    mgmthdr->u.beacon.timestamp = cpu_to_le64(priv->abs_bcn_ts +
            priv->tsf_offset + 24 * 8 * 10 / rate->bitrate);

    priv->tmp_channel = rcu_dereference(vif->chanctx_conf)->def.chan;

    wtap_tx(hw, skb, rcu_dereference(vif->chanctx_conf)->def.chan);

    if (vif->csa_active && ieee80211_csa_is_complete(vif)) {
        ieee80211_csa_finish(vif);
    }
}/*}}}*/

static enum hrtimer_restart wtap_beacon(struct hrtimer *timer) {/*{{{*/
    struct wtap_priv *priv =
        container_of(timer, struct wtap_priv, beacon_timer.timer);
    struct ieee80211_hw *hw = priv->hw;
    u64 beacon_interval = priv->beacon_interval;
    ktime_t next_beacon = {0};

    if (!priv->started) {
        return HRTIMER_NORESTART;
    }

    // Iterate over the interfaces associated with hardwares which is actice and
    // calls the callback for them.
    ieee80211_iterate_active_interfaces_atomic(hw,
            IEEE80211_IFACE_ITER_NORMAL, wtap_tx_beacon, priv);

    // Beacon at new TBTT + beacon interval
    // *TBTT - Target Beacon Transmittion Time
    if (priv->beacon_delta) {
        beacon_interval -= priv->beacon_delta;
        priv->beacon_delta = 0;
    }

    // Schedule next beacon
    next_beacon = ktime_add(hrtimer_get_expires(timer),
            ns_to_ktime(beacon_interval * 1000));
    tasklet_hrtimer_start(&priv->beacon_timer, next_beacon, HRTIMER_MODE_ABS);

    /*debug_msg("Beacon timer started.");*/

    return HRTIMER_NORESTART;
}/*}}}*/

static void wtap_enable_beacon_iterator(void *data,/*{{{*/
        u8 *mac,
        struct ieee80211_vif *vif)
{
    struct wtap_vif_priv *vp = (struct wtap_vif_priv*)vif->drv_priv;
    unsigned int *count = data;

    if (vp->enable_beacon) {
        (*count)++;
    }
}/*}}}*/

static void wtap_set_beacon_timer(struct wtap_priv *priv,/*{{{*/
        const enum hrtimer_mode mode)
{
    u64 tsf = wtap_get_time_us();
    u32 beacon_interval =
        (priv->beacon_interval)? priv->beacon_interval: 1000 * 1024;
    u64 tbtt = beacon_interval - do_div(tsf, beacon_interval);

    tasklet_hrtimer_start(&priv->beacon_timer,
            ns_to_ktime(tbtt * 1000),
            mode);
}/*}}}*/

/* ------------------------------------------------------------------------------- */
/* ieee80211 ops                                                                   */
/* ------------------------------------------------------------------------------- */

// Basic operations --------------------------------------------------------------

static void wtap_ops_tx(struct ieee80211_hw *hw,/*{{{*/
                        struct ieee80211_tx_control *control,
                        struct sk_buff *skb)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    struct ieee80211_chanctx_conf *chanctx_conf = NULL;
    struct ieee80211_channel *channel = NULL;
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr*)skb->data;
    static u16 seq = 0;
    int err = 0;

    if (WARN_ON(skb->len < 10))
        goto drop_packet;

    if (!priv->use_chanctx) {
        channel = priv->channel;
    } else if (info->hw_queue == 4) {
        channel = priv->tmp_channel;
    } else {
        chanctx_conf = rcu_dereference(info->control.vif->chanctx_conf);
        if (chanctx_conf) {
            channel = chanctx_conf->def.chan;
        } else {
            goto drop_packet;
        }
    }

    info->rate_driver_data[0] = channel;

    if (info->flags & IEEE80211_TX_CTL_ASSIGN_SEQ)
        hdr->seq_ctrl = cpu_to_le16(seq++);

    /* TX frame to the use space via Netlink. */
    if ((err = wtap_tx(hw, skb, channel)) < 0)
        goto drop_packet;

    spin_lock_bh(&priv->stat.spinlock);
    priv->stat.tx.bytes += skb->len;
    priv->stat.tx.packets++;
    spin_unlock_bh(&priv->stat.spinlock);

    spin_lock_bh(&shared->spinlock);
    memcpy(&priv->prev_channel, channel, sizeof(priv->prev_channel));
    priv->is_set_prev_channel = true;
    spin_unlock_bh(&shared->spinlock);

    ieee80211_tx_info_clear_status(info);

    /* Set a dummy tx status */
    info->control.rates[0].count = 1;
    info->control.rates[1].idx = -1;
    info->status.ack_signal = -30;

    if (!(info->flags & IEEE80211_TX_CTL_NO_ACK) && err == 0)
        info->flags |= IEEE80211_TX_STAT_ACK;

    ieee80211_tx_status_irqsafe(hw, skb);

    return ;

drop_packet:
    ieee80211_free_txskb(hw, skb);

    spin_lock_bh(&priv->stat.spinlock);
    priv->stat.tx.dropped++;
    priv->stat.tx.packets++;
    spin_unlock_bh(&priv->stat.spinlock);

}/*}}}*/

static int wtap_ops_start(struct ieee80211_hw *hw) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;

    spin_lock_bh(&shared->spinlock);
    priv->started = true;
    spin_unlock_bh(&shared->spinlock);

    info_msg("HWaddr = %pM started.", hw->wiphy->perm_addr);
    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_HW_START, 0,
            hw->wiphy->perm_addr, ETH_ALEN, NULL);

    return 0;
}/*}}}*/

static void wtap_ops_stop(struct ieee80211_hw *hw) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;

    // Stop beacon timer
    tasklet_hrtimer_cancel(&priv->beacon_timer);

    // Turn the device off
    spin_lock_bh(&shared->spinlock);
    priv->started = false;
    spin_unlock_bh(&shared->spinlock);

    info_msg("HWaddr = %pM stopped.", hw->wiphy->perm_addr);
    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_HW_STOP, 0,
            hw->wiphy->perm_addr, ETH_ALEN, NULL);
}/*}}}*/

static int wtap_ops_add_interface(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct wtap_vif_priv *vif_priv = (void*)vif->drv_priv;
    u32 new_id = 0;

    /* Set the identifier of new vif */
    get_random_bytes(&new_id, sizeof(new_id));
    vif_priv->id = new_id;

    info_msg("new vif added (addr = %pM, id = %#x, iftype: %s).",
            vif->addr, vif_priv->id,
            iftype_modes[ieee80211_vif_type_p2p(vif)]);

    vif->cab_queue = 0;
    vif->hw_queue[IEEE80211_AC_VO] = 0;
    vif->hw_queue[IEEE80211_AC_VI] = 1;
    vif->hw_queue[IEEE80211_AC_BE] = 2;
    vif->hw_queue[IEEE80211_AC_BK] = 3;

    spin_lock_bh(&shared->spinlock);

    if (vif->type == NL80211_IFTYPE_AP ||
            vif->type == NL80211_IFTYPE_AP_VLAN) {
        priv->master = true;
    } else {
        priv->master = false;
    }

    if ((vif->type == NL80211_IFTYPE_P2P_CLIENT) ||
            (vif->type == NL80211_IFTYPE_P2P_GO) ||
            (vif->type == NL80211_IFTYPE_P2P_DEVICE)) {
        priv->p2p = true;
    } else {
        priv->p2p = false;
    }

    list_add_tail(&vif_priv->list, &priv->vif_list);

    spin_unlock_bh(&shared->spinlock);

    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_VIF_ADD, 0, NULL, 0, NULL);

    return 0;
}/*}}}*/

static int wtap_ops_change_interface(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        enum nl80211_iftype newtype,
        bool newp2p)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct wtap_vif_priv *vif_priv = (void*)vif->drv_priv;

    newtype = ieee80211_iftype_p2p(newtype, newp2p);

    info_msg("vif iftype changed (%s -> %s) (HWaddr = %pM, id = %#x).",
            iftype_modes[vif->type], iftype_modes[newtype],
            vif->addr, vif_priv->id);

    vif->type = newtype;
    vif->cab_queue = 0;

    spin_lock_bh(&shared->spinlock);

    if (vif->type == NL80211_IFTYPE_AP ||
            vif->type == NL80211_IFTYPE_AP_VLAN) {
        priv->master = true;
    } else {
        priv->master = false;
    }

    priv->p2p = !!(newp2p);

    spin_unlock_bh(&shared->spinlock);

    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_VIF_ADD, 0,
            hw->wiphy->perm_addr, ETH_ALEN, NULL);

    return 0;
}/*}}}*/

static void wtap_ops_remove_interface(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_vif_priv *vif_priv = (void*)vif->drv_priv;

    spin_lock_bh(&shared->spinlock);
    list_del(&vif_priv->list);
    spin_unlock_bh(&shared->spinlock);

    info_msg("vif removed (addr = %pM, id = %#x).",
            vif->addr, vif_priv->id);

    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_VIF_REMOVE, 0, NULL, 0, NULL);
}/*}}}*/

static int wtap_ops_config(struct ieee80211_hw *hw,/*{{{*/
        u32 changed)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct ieee80211_conf *conf = &hw->conf;
    static const char *smps_modes[IEEE80211_SMPS_NUM_MODES] = {
        [IEEE80211_SMPS_AUTOMATIC] = "automatic",
        [IEEE80211_SMPS_OFF] = "off",
        [IEEE80211_SMPS_STATIC] = "static",
        [IEEE80211_SMPS_DYNAMIC] = "dynamic",
    };
    struct ieee80211_channel channel;

    info_msg("HWconfig changed (HWaddr = %pM) %s",
            hw->wiphy->perm_addr,
            ((changed & IEEE80211_CONF_CHANGE_CHANNEL)? "(channel changed)": ""));

    if (conf->chandef.chan) {
        info_msg("  freq = %d (%d - %d), idle = %d, ps = %d, smps = %s",
                conf->chandef.chan->center_freq,
                conf->chandef.center_freq1,
                conf->chandef.center_freq2,
                !!(conf->flags & IEEE80211_CONF_IDLE),
                !!(conf->flags & IEEE80211_CONF_PS),
                smps_modes[conf->smps_mode]);
    } else {
        info_msg("  freq = 0, idle = %d, ps = %d, smps = %s",
                /* conf->chandef.chan->center_freq, */
                !!(conf->flags & IEEE80211_CONF_IDLE),
                !!(conf->flags & IEEE80211_CONF_PS),
                smps_modes[conf->smps_mode]);
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    info_msg("  max_sleep_period = %d, ps_dtim_period = %d, ps_timeout = %d",
            conf->max_sleep_period, conf->ps_dtim_period, conf->dynamic_ps_timeout);
#else
    info_msg("  ps_dtim_period = %d, ps_timeout = %d",
            conf->ps_dtim_period, conf->dynamic_ps_timeout);
#endif
    info_msg("  radar detection %s", (conf->radar_enabled)? "enabled": "disabled");
    info_msg("  minimum TX power changed %d => %d [dBm]", priv->power_level, conf->power_level);

    spin_lock_bh(&shared->spinlock);

    if (changed & IEEE80211_CONF_CHANGE_IDLE) {
        priv->idle = !!(conf->flags & IEEE80211_CONF_IDLE);
    }

    if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
        priv->channel = conf->chandef.chan;
    }

    if (changed & IEEE80211_CONF_CHANGE_POWER) {
        priv->power_level = conf->power_level;
    }

    spin_unlock_bh(&shared->spinlock);

    if (!priv->started || !priv->beacon_interval) {
        // Turn beacon timer off
        tasklet_hrtimer_cancel(&priv->beacon_timer);
    } else if (!hrtimer_is_queued(&priv->beacon_timer.timer)) {
        wtap_set_beacon_timer(priv, HRTIMER_MODE_REL);
    }

    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_HW_CONF,
            changed, &hw->conf, sizeof(hw->conf), NULL);

    memcpy(&channel, hw->conf.chandef.chan, sizeof(channel));
    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_CHANNEL,
            changed, &channel, sizeof(channel), NULL);

    return 0;
}/*}}}*/

static void wtap_ops_configure_filter(struct ieee80211_hw *hw,/*{{{*/
        unsigned int changed_flags,
        unsigned int *total_flags,
        u64 multicast)
{
    struct wtap_priv *priv = hw->priv;

    priv->rx_filter = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    if (*total_flags & FIF_PROMISC_IN_BSS) {
        priv->rx_filter |= FIF_PROMISC_IN_BSS;
    }
    if (*total_flags & FIF_ALLMULTI) {
        priv->rx_filter |= FIF_ALLMULTI;
    }
#endif

    *total_flags = priv->rx_filter;
}/*}}}*/

static void wtap_ops_bss_info_changed(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_bss_conf *info,
        u32 changed)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct wtap_vif_priv *vp = (struct wtap_vif_priv*)vif->drv_priv;

    info_msg("BSS info changed (HWaddr: %pM):", vif->addr);

    spin_lock_bh(&shared->spinlock);

    if (changed & BSS_CHANGED_ASSOC) {
        info_msg("  ASSOC: assoc %d => %d, aid %d => %d",
                vp->bss_conf.assoc, info->assoc,
                vp->bss_conf.aid, info->aid);

        vif->bss_conf.assoc = info->assoc;
        vif->bss_conf.aid = info->aid;
        vp->bss_conf.assoc = info->assoc;
        vp->bss_conf.aid = info->aid;
    }

    if (changed & BSS_CHANGED_ERP_CTS_PROT) {
        info_msg("  ERP CTS Prot: %d => %d",
                vp->bss_conf.use_cts_prot, info->use_cts_prot);

        vif->bss_conf.use_cts_prot = info->use_cts_prot;
        vp->bss_conf.use_cts_prot = info->use_cts_prot;
    }

    if (changed & BSS_CHANGED_ERP_PREAMBLE) {
        info_msg("  ERP Preamble: %d => %d",
                vp->bss_conf.use_short_preamble, info->use_short_preamble);

        vif->bss_conf.use_short_preamble = info->use_short_preamble;
        vp->bss_conf.use_short_preamble = info->use_short_preamble;
    }

    if (changed & BSS_CHANGED_ERP_SLOT) {
        info_msg("  ERP Slot: %d => %d",
                vp->bss_conf.use_short_slot, info->use_short_slot);

        vif->bss_conf.use_short_slot = info->use_short_slot;
        vp->bss_conf.use_short_slot = info->use_short_slot;
    }

    if (changed & BSS_CHANGED_HT) {
        info_msg("  HT info: %#x => %#x",
                vp->bss_conf.ht_operation_mode, info->ht_operation_mode);

        vif->bss_conf.ht_operation_mode = info->ht_operation_mode;
        vp->bss_conf.ht_operation_mode = info->ht_operation_mode;
    }

    if (changed & BSS_CHANGED_BASIC_RATES) {
        info_msg("  Basic rate: %u => %u",
                vp->basic_rates, info->basic_rates);

        vif->bss_conf.basic_rates = info->basic_rates;
        vp->bss_conf.basic_rates = info->basic_rates;
    }

    if (changed & BSS_CHANGED_BEACON_INT) {
        info_msg("  Beacon interval: %u -> %u",
                vp->beacon_int, info->beacon_int * 1024);

        priv->beacon_interval = info->beacon_int * 1024;
        vif->bss_conf.beacon_int = info->beacon_int;
        vp->bss_conf.beacon_int = info->beacon_int;
    }

    if (changed & BSS_CHANGED_BSSID) {
        info_msg("  BSSID: %pM => %pM)", vp->bssid, info->bssid);

        memcpy(vp->bssid, info->bssid, ETH_ALEN);
    }

    if (changed & BSS_CHANGED_BEACON) {
        info_msg("  Beacon info:");
    }

    if (changed & BSS_CHANGED_BEACON_ENABLED) {
        info_msg("  Beaconing: %s => %s",
                ((vp->enable_beacon)? "enabled": "disabled"),
                ((info->enable_beacon)? "enabled": "disabled"));

        vp->enable_beacon = info->enable_beacon;

        if (info->enable_beacon) {
            if (priv->started && !hrtimer_is_queued(&priv->beacon_timer.timer)) {
                wtap_set_beacon_timer(priv, HRTIMER_MODE_REL);
            }
        } else {
            unsigned int count = 0;
            ieee80211_iterate_active_interfaces_atomic(hw, IEEE80211_IFACE_ITER_NORMAL,
                    wtap_enable_beacon_iterator, &count);
            if (count == 0) {
                tasklet_hrtimer_cancel(&priv->beacon_timer);
            }
        }
    }

    if (changed & BSS_CHANGED_CQM) {
        info_msg("  CQM: RSSI thold %d => %d",
                vp->bss_conf.cqm_rssi_thold, info->cqm_rssi_thold);
        info_msg("       RSSI hysteresis %d => %d",
                vp->bss_conf.cqm_rssi_hyst, info->cqm_rssi_hyst);

        vif->bss_conf.cqm_rssi_thold = info->cqm_rssi_thold;
        vif->bss_conf.cqm_rssi_hyst = info->cqm_rssi_hyst;
        vp->bss_conf.cqm_rssi_thold = info->cqm_rssi_thold;
        vp->bss_conf.cqm_rssi_hyst = info->cqm_rssi_hyst;
    }

    if ((changed & BSS_CHANGED_IBSS) ||
            (changed & BSS_CHANGED_OCB)) {
        info_msg("  IBSS: %s, %s",
                ((info->ibss_joined)? "joind": "left"),
                ((info->ibss_creator)? "(new IBSS created)": ""));

        vif->bss_conf.ibss_joined = info->ibss_joined;
        vif->bss_conf.ibss_creator = info->ibss_creator;
        vp->bss_conf.ibss_joined = info->ibss_joined;
        vp->bss_conf.ibss_creator = info->ibss_creator;
    }

    if (changed & BSS_CHANGED_ARP_FILTER) {
        info_msg("  ARP Filter:");
    }

    if (changed & BSS_CHANGED_QOS) {
        info_msg("  QoS: %s => %s",
                ((vp->bss_conf.qos)? "enabled": "disabled"),
                ((info->qos)? "enabled": "disabled"));

        vif->bss_conf.qos = info->qos;
        vp->bss_conf.qos = info->qos;
    }

    if (changed & BSS_CHANGED_IDLE) {
        info_msg("  NIC status: %s -> %s",
                ((vp->idle)? "idle": "active"),
                ((info->idle)? "idle": "active"));

        priv->idle = info->idle;
        vif->bss_conf.idle = info->idle;
        vp->bss_conf.idle = info->idle;
    }

    if (changed & BSS_CHANGED_SSID) {
        info_msg("  SSID: %pM => %pM (%s)",
                vp->ssid, info->ssid,
                (info->hidden_ssid)? "visible": "unvisible");
        memcpy(vp->ssid, info->ssid, IEEE80211_MAX_SSID_LEN);

        vif->bss_conf.ssid_len = info->ssid_len;
        vif->bss_conf.hidden_ssid = info->hidden_ssid;
        vp->bss_conf.ssid_len = info->ssid_len;
        vp->bss_conf.hidden_ssid = info->hidden_ssid;
    }

    if (changed & BSS_CHANGED_AP_PROBE_RESP) {
        info_msg("  AP probe response: ");
    }

    if (changed & BSS_CHANGED_PS) {
        info_msg("  Power saving status changed: %d => %d",
                vp->bss_conf.ps, info->ps);

        vif->bss_conf.ps = info->ps;
        vp->bss_conf.ps = info->ps;
    }

    if (changed & BSS_CHANGED_TXPOWER) {
        info_msg("  TX power changed: %d => %d [dBm]",
                vif->bss_conf.txpower, info->txpower);

        vif->bss_conf.txpower = info->txpower;
        vp->bss_conf.txpower = info->txpower;
    }

    if (changed & BSS_CHANGED_P2P_PS) {
        info_msg("  P2P power savings changed:");
    }

    if (changed & BSS_CHANGED_BEACON_INFO) {
        info_msg("  Beacon info: dtim period %d => %d",
                vif->bss_conf.dtim_period, info->dtim_period);

        vif->bss_conf.dtim_period = info->dtim_period;
        vp->bss_conf.dtim_period = info->dtim_period;
    }

    if (changed & BSS_CHANGED_BANDWIDTH) {
    }

    // Integrated with BSS_CHANGED_IBSS
    //if (changed & BSS_CHANGED_OCB) {
    //}

    // BSS_CHANGED_MU_GROUPS is not available on Linux 3.19.
    /*
     * if (changed & BSS_CHANGED_MU_GROUPS) {
     *   debug_msg("  VHT MU-MIMO id or user position changed:");
     * }
     */

    spin_unlock_bh(&shared->spinlock);

    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_BSS_INFO,
            changed, info, sizeof(*info), NULL);

}/*}}}*/

static int wtap_ops_sta_add(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_sta *sta)
{
    struct wtap_vif_priv *vp = (void*)vif->drv_priv;
    struct wtap_sta_priv *sp =
        (void*)rcu_dereference(sta)->drv_priv;

    rcu_read_lock();

    get_random_bytes(&sp->sta_id, sizeof(sp->sta_id));
    vp->bss_joined = true;

    info_msg("sta added (sta_id = %#x) (HWaddr = %pM)",
            sp->sta_id, vif->addr);

    rcu_read_unlock();

    return 0;
}/*}}}*/

static int wtap_ops_sta_remove(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_sta *sta)
{
    struct wtap_vif_priv *vp = (void*)vif->drv_priv;
    struct wtap_sta_priv *sp =
        (void*)rcu_dereference(sta)->drv_priv;

    rcu_read_lock();

    vp->bss_joined = false;

    info_msg("sta removed (sta_id = %#x) (HWaddr = %pM)",
            sp->sta_id, vif->addr);

    rcu_read_unlock();

    return 0;
}/*}}}*/

static void wtap_ops_sta_notify(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        enum sta_notify_cmd cmd,
        struct ieee80211_sta *sta)
{
    info_msg("sta notify:");
}/*}}}*/

static int wtap_ops_set_tim(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_sta *sta,
        bool set)
{
    return 0;
}/*}}}*/

static int wtap_ops_conf_tx(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        u16 queue,
        const struct ieee80211_tx_queue_params *params)
{
    info_msg("TX queue parameters changed:");
    info_msg("  queue = %d, txop = %d, cw_min = %d, cw_max = %d, aifs = %d)",
            queue, params->txop, params->cw_min, params->cw_max, params->aifs);
    wtap_send_mgmt_msg(hw, WTAP_MGMT_MSG_TYPE_TX_QUEUE, queue,
            params, sizeof(*params), NULL);

    return 0;
}/*}}}*/

static int wtap_ops_get_survey(struct ieee80211_hw *hw,/*{{{*/
        int idx,
        struct survey_info *survey)
{
    struct ieee80211_conf *conf = &hw->conf;

    info_msg("survey idx = %d", idx);

    survey->channel = conf->chandef.chan;

    if (idx >= num_of_channels) {
        return -ENOENT;
    }

    return 0;
}/*}}}*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
static int wtap_ops_ampdu_action(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        enum ieee80211_ampdu_mlme_action action,
        struct ieee80211_sta *sta,
        u16 tid, u16 *ssn,
        u8 buf_size)
{
    switch (action) {
        case IEEE80211_AMPDU_TX_START:
            ieee80211_start_tx_ba_cb_irqsafe(vif, sta->addr, tid);
            break;
        case IEEE80211_AMPDU_TX_STOP_CONT:
        case IEEE80211_AMPDU_TX_STOP_FLUSH:
        case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
            ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
            break;
        case IEEE80211_AMPDU_TX_OPERATIONAL:
            break;
        case IEEE80211_AMPDU_RX_START:
        case IEEE80211_AMPDU_RX_STOP:
            break;
        default:
            return -EOPNOTSUPP;
    }
    return 0;
}/*}}}*/
#else
static int wtap_ops_ampdu_action(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_ampdu_params *params)
{
    switch (params->action) {
        case IEEE80211_AMPDU_TX_START:
            ieee80211_start_tx_ba_cb_irqsafe(vif, params->sta->addr, params->tid);
            break;
        case IEEE80211_AMPDU_TX_STOP_CONT:
        case IEEE80211_AMPDU_TX_STOP_FLUSH:
        case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
            ieee80211_stop_tx_ba_cb_irqsafe(vif, params->sta->addr, params->tid);
            break;
        case IEEE80211_AMPDU_TX_OPERATIONAL:
            break;
        case IEEE80211_AMPDU_RX_START:
        case IEEE80211_AMPDU_RX_STOP:
            break;
        default:
            return -EOPNOTSUPP;
    }
    return 0;
}/*}}}*/
#endif

static void wtap_ops_sw_scan_start(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        const u8 *mac_addr)
{
    struct wtap_priv *priv = hw->priv;

    info_msg("software scanning started.");

    mutex_lock(&priv->mutex);

    if (priv->scanning) {
        error_msg("vif is already scanning.");
        mutex_unlock(&priv->mutex);
        return ;
    }

    memcpy(priv->scan_addr, mac_addr, ETH_ALEN);
    priv->scanning = true;

    mutex_unlock(&priv->mutex);
}/*}}}*/

static void wtap_ops_sw_scan_complete(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif)
{
    struct wtap_priv *priv = hw->priv;

    mutex_lock(&priv->mutex);

    priv->scanning = false;
    memset(priv->scan_addr, 0, ETH_ALEN);

    mutex_unlock(&priv->mutex);

    info_msg("software scanning completed.");
}/*}}}*/

static void wtap_ops_flush(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        u32 queues,
        bool drop)
{
    // Nothing
}/*}}}*/

static u64 wtap_ops_get_tsf(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif)
{
    struct wtap_priv *priv = hw->priv;
    return le64_to_cpu(wtap_get_tsf(priv));
}/*}}}*/

static void wtap_ops_set_tsf(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        u64 tsf)
{
    struct wtap_priv *priv = hw->priv;
    u64 now = wtap_get_tsf(priv);
    u32 beacon_int = priv->beacon_interval;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    u64 delta = abs64(tsf - now);
#else
    /* u64 delta = ((tsf - now) < 0) ? -(tsf - now) : (tsf - now); */
    u64 delta = tsf - now;
#endif

    if (tsf > now) {
        priv->tsf_offset += delta;
        priv->beacon_delta = do_div(delta, beacon_int);
    } else {
        priv->tsf_offset -= delta;
        priv->beacon_delta = -do_div(delta, beacon_int);
    }
}/*}}}*/

static void wtap_ops_get_et_strings(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        u32 sset,
        u8 *data)
{

}/*}}}*/

static int wtap_ops_get_et_sset_count(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        int sset)
{
    return 0;
}/*}}}*/

static void wtap_ops_get_et_stats(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ethtool_stats *stats,
        u64 *data)
{

}/*}}}*/

static int wtap_ops_hw_scan(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_scan_request *hw_req)
{
    struct wtap_priv *priv = hw->priv;
    struct cfg80211_scan_request *request = &hw_req->req;

    mutex_lock(&priv->mutex);

    /* if (WARN_ON(priv->tmp_channel || priv->scan_request)) { */
    if (priv->channel_status & HW_SCAN_SCHEDULED) {
        mutex_unlock(&priv->mutex);
        error_msg("a channel (%u[MHz]) is busy.",
                priv->tmp_channel->center_freq);
        return -EBUSY;
    }

    /*
     * The flag HW_SCAN_SCHEDULED bans the kernel from scanning radio
     * while another scanning process is active.
     */
    priv->channel_status |= HW_SCAN_SCHEDULED;

    priv->scan_request = request;
    priv->scan_vif = vif;
    priv->scan_chan_idx = 0;

    if (request->flags & NL80211_SCAN_FLAG_RANDOM_ADDR) {
        get_random_mask_addr(priv->scan_addr,
                hw_req->req.mac_addr, hw_req->req.mac_addr_mask);
    } else {
        memcpy(priv->scan_addr, vif->addr, ETH_ALEN);
    }

    mutex_unlock(&priv->mutex);

    ieee80211_queue_delayed_work(hw, &priv->hw_scan, 0);

    return 0;
}/*}}}*/

static void wtap_ops_cancel_hw_scan(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif)
{
    struct wtap_priv *priv = hw->priv;

    info_msg("scanning aborted.");

    // Wait for an active scanning.
    cancel_delayed_work_sync(&priv->hw_scan);

    mutex_lock(&priv->mutex);
    ieee80211_scan_completed(hw, true);
    priv->scan_request = NULL;
    priv->scan_vif = NULL;
    priv->tmp_channel = NULL;
    priv->channel_status &= ~HW_SCAN_SCHEDULED;
    mutex_unlock(&priv->mutex);
}/*}}}*/

static int wtap_ops_get_txpower(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        int *dbm)
{
    struct wtap_priv *priv = hw->priv;
    struct wtap_vif_priv *vp = (struct wtap_vif_priv*)vif->drv_priv;

    mutex_lock(&priv->mutex);

    if (priv->use_chanctx && vp->chanctx) {
        *dbm = vp->chanctx->power_level;
    } else {
        *dbm = priv->power_level;
    }

    mutex_unlock(&priv->mutex);

    return 0;
}/*}}}*/

// Operations for multi channels -------------------------------------------------

static int wtap_ops_remain_on_channel(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_channel *chan,
        int duration,
        enum ieee80211_roc_type type)
{
    struct wtap_priv *priv = hw->priv;

    mutex_lock(&priv->mutex);

    if (WARN_ON(priv->tmp_channel || priv->scan_request)) {
        mutex_unlock(&priv->mutex);
        return -EBUSY;
    }
    priv->tmp_channel = chan;
    mutex_unlock(&priv->mutex);

    // Notify the kernel that remain on channel start.
    info_msg("remaining on channel on HWaddr = %pM (%d[MHz] while %d[ms])",
            hw->wiphy->perm_addr, chan->center_freq, duration);
    ieee80211_ready_on_channel(hw);

    ieee80211_queue_delayed_work(hw, &priv->roc_done,
            msecs_to_jiffies(duration));

    return 0;
}/*}}}*/

static int wtap_ops_cancel_remain_on_channel(struct ieee80211_hw *hw) {/*{{{*/
    struct wtap_priv *priv = hw->priv;

    cancel_delayed_work_sync(&priv->roc_done);

    mutex_lock(&priv->mutex);
    priv->tmp_channel = NULL;
    mutex_unlock(&priv->mutex);

    info_msg("remain on channel canceled on HWaddr = %pM",
            hw->wiphy->perm_addr);
    return 0;
}/*}}}*/

static int wtap_ops_add_chanctx(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_chanctx_conf *ctx)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct wtap_chanctx_priv *ctx_priv = (void*)ctx->drv_priv;
    u32 new_ctx_id = 0;

    get_random_bytes(&new_ctx_id, sizeof(new_ctx_id));

    mutex_lock(&priv->mutex);
    memcpy(&ctx_priv->ctx_id, &new_ctx_id, sizeof(new_ctx_id));
    mutex_unlock(&priv->mutex);

    info_msg("channel context added (HWaddr = %pM, ctx_id = %#x): "
            "%d[MHz/width], freq1: %d[MHz], freq2: %d[MHz] max_power = %d[dBm]",
            hw->wiphy->perm_addr, new_ctx_id,
            ctx->def.chan->center_freq,
            ctx->def.center_freq1, ctx->def.center_freq2,
            ctx->def.chan->max_power);

    ctx_priv->power_level = ctx->def.chan->max_power;
    /*
     * spin_lock_bh(&shared->spinlock);
     * [> priv->channel = ctx->def.chan; <]
     * spin_unlock_bh(&shared->spinlock);
     */
    return 0;
}/*}}}*/

static void wtap_ops_change_chanctx(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_chanctx_conf *ctx,
        u32 changed)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct wtap_chanctx_priv *ctx_priv = (void*)ctx->drv_priv;

    info_msg("channel context changed (HWaddr = %pM, ctx_id = %#x): "
            "%d[MHz/width], freq1: %d[MHz], freq2: %d[MHz], max_power = %d[dBm]",
            hw->wiphy->perm_addr, ctx_priv->ctx_id,
            ctx->def.chan->center_freq,
            ctx->def.center_freq1, ctx->def.center_freq2,
            ctx->def.chan->max_power);

    ctx_priv->power_level = ctx->def.chan->max_power;
    /*
     * spin_lock_bh(&shared->spinlock);
     * [> priv->channel = ctx->def.chan; <]
     * spin_unlock_bh(&shared->spinlock);
     */
}/*}}}*/

static void wtap_ops_remove_chanctx(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_chanctx_conf *ctx)
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = hw->priv;
    struct wtap_chanctx_priv *ctx_priv = (void*)ctx->drv_priv;

    info_msg("channel context removed (HWaddr = %pM, ctx_id = %#x): "
            "%d[MHz/width], freq1: %d[MHz], freq2: %d[MHz], max_power = %d[dBm]",
            hw->wiphy->perm_addr, ctx_priv->ctx_id,
            ctx->def.chan->center_freq,
            ctx->def.center_freq1, ctx->def.center_freq2,
            ctx->def.chan->max_power);

    /*
     * spin_lock_bh(&shared->spinlock);
     * [> priv->channel = ctx->def.chan; <]
     * spin_unlock_bh(&shared->spinlock);
     */
}/*}}}*/

static int wtap_ops_assign_vif_chanctx(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_chanctx_conf *ctx)
{
    struct wtap_priv *priv = hw->priv;
    struct wtap_vif_priv *vif_priv = (void*)vif->drv_priv;
    struct wtap_chanctx_priv *ctx_priv = (void*)ctx->drv_priv;
    int i = 0;

    mutex_lock(&priv->mutex);

    info_msg("assigned vif (addr = %pM, id = %#x) to channel context "
            "(freq = %d[MHz], max_power = %d[dBm] ctx_id = %#x)",
            vif->addr, vif_priv->id,
            ctx->def.chan->center_freq, ctx->def.chan->max_power, ctx_priv->ctx_id);

    if (!vif->chanctx_conf) {
        info_msg("vif->chanctx_conf is null");
    }

    vif_priv->chanctx_conf = ctx;
    vif_priv->chanctx = ctx_priv;
    vif_priv->ctx_assigned = true;
    ctx_priv->power_level = ctx->def.chan->max_power;
    priv->assigned_vifs++;

    mutex_unlock(&priv->mutex);

    return 0;
}/*}}}*/

static void wtap_ops_unassign_vif_chanctx(struct ieee80211_hw *hw,/*{{{*/
        struct ieee80211_vif *vif,
        struct ieee80211_chanctx_conf *ctx)
{
    struct wtap_priv *priv = hw->priv;
    struct wtap_vif_priv *vif_priv = (void*)vif->drv_priv;
    struct wtap_chanctx_priv *ctx_priv = (void*)ctx->drv_priv;
    int i = 0;

    mutex_lock(&priv->mutex);

    info_msg("unassigned vif (addr = %pM, id = %#x) to channel context "
            "(freq = %d[MHz], ctx_id = %#x)",
            vif->addr, vif_priv->id,
            ctx->def.chan->center_freq,
            ctx_priv->ctx_id);

    if (!vif->chanctx_conf) {
        info_msg("vif->chanctx_conf is null");
    } else {
        info_msg("vif->ctx_conf: %d[MHz]",
                rcu_dereference(vif->chanctx_conf)->def.chan->center_freq);
    }

    vif_priv->chanctx_conf = NULL;
    vif_priv->chanctx = NULL;
    vif_priv->ctx_assigned = false;
    ctx_priv->power_level = 0;
    priv->assigned_vifs--;

    mutex_unlock(&priv->mutex);

}/*}}}*/

// ieee80211_ops structures ------------------------------------------------------

static struct ieee80211_ops wtap_ops = {/*{{{*/
    // Must be set
    .tx = wtap_ops_tx,
    .start = wtap_ops_start,
    .stop = wtap_ops_stop,
    .add_interface = wtap_ops_add_interface,
    .change_interface = wtap_ops_change_interface,
    .remove_interface = wtap_ops_remove_interface,
    .config = wtap_ops_config,
    .configure_filter = wtap_ops_configure_filter,
    .bss_info_changed = wtap_ops_bss_info_changed,
    .sta_add = wtap_ops_sta_add,
    .sta_remove = wtap_ops_sta_remove,
    .sta_notify = wtap_ops_sta_notify,
    .set_tim = wtap_ops_set_tim,
    .conf_tx = wtap_ops_conf_tx,
    .hw_scan = wtap_ops_hw_scan,
    .cancel_hw_scan = wtap_ops_cancel_hw_scan,

    // Should be set
    .get_survey = wtap_ops_get_survey,
    .ampdu_action = wtap_ops_ampdu_action,
    .sw_scan_start = wtap_ops_sw_scan_start,
    .sw_scan_complete = wtap_ops_sw_scan_complete,
    .flush = wtap_ops_flush,
    .get_tsf = wtap_ops_get_tsf,
    .set_tsf = wtap_ops_set_tsf,
    .get_et_sset_count = wtap_ops_get_et_sset_count,
    .get_et_stats = wtap_ops_get_et_stats,
    .get_et_strings = wtap_ops_get_et_strings,
    .get_txpower = wtap_ops_get_txpower,
};/*}}}*/

static struct ieee80211_ops wtap_mch_ops = {/*{{{*/
    // Must be set
    .tx = wtap_ops_tx,
    .start = wtap_ops_start,
    .stop = wtap_ops_stop,
    .add_interface = wtap_ops_add_interface,
    .change_interface = wtap_ops_change_interface,
    .remove_interface = wtap_ops_remove_interface,
    .config = wtap_ops_config,
    .configure_filter = wtap_ops_configure_filter,
    .bss_info_changed = wtap_ops_bss_info_changed,
    .sta_add = wtap_ops_sta_add,
    .sta_remove = wtap_ops_sta_remove,
    .sta_notify = wtap_ops_sta_notify,
    .set_tim = wtap_ops_set_tim,
    .conf_tx = wtap_ops_conf_tx,
    .hw_scan = wtap_ops_hw_scan,
    .cancel_hw_scan = wtap_ops_cancel_hw_scan,

    // Should be set
    .get_survey = wtap_ops_get_survey,
    .ampdu_action = wtap_ops_ampdu_action,
    .sw_scan_start = NULL,
    .sw_scan_complete = NULL,
    .flush = wtap_ops_flush,
    .get_tsf = wtap_ops_get_tsf,
    .set_tsf = wtap_ops_set_tsf,
    .get_et_sset_count = wtap_ops_get_et_sset_count,
    .get_et_stats = wtap_ops_get_et_stats,
    .get_et_strings = wtap_ops_get_et_strings,
    .get_txpower = wtap_ops_get_txpower,

    // Multi channel use only
    .remain_on_channel = wtap_ops_remain_on_channel,
    .cancel_remain_on_channel = wtap_ops_cancel_remain_on_channel,
    .add_chanctx = wtap_ops_add_chanctx,
    .change_chanctx = wtap_ops_change_chanctx,
    .remove_chanctx = wtap_ops_remove_chanctx,
    .assign_vif_chanctx = wtap_ops_assign_vif_chanctx,
    .unassign_vif_chanctx = wtap_ops_unassign_vif_chanctx,
};/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Virtual WLAN device registration process                                        */
/* ------------------------------------------------------------------------------- */
static void wtap_get_addrlist_all(char *buf)/*{{{*/
{
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = NULL;
    char *head = buf;
    unsigned int offset = 0;

    spin_lock(&shared->spinlock);
    list_for_each_entry(priv, &wtap_shared.dev_list, list) {
        memcpy(head + offset, priv->addresses[0].addr, ETH_ALEN);
        offset += ETH_ALEN;
    }
    spin_unlock(&shared->spinlock);
}/*}}}*/

static void wtap_set_rnd_mac_addr(struct wtap_priv *priv,/*{{{*/
        unsigned int index)
{
    u8 addr[ETH_ALEN] = {0};
    u8 rnds[2] = {0};

    // Generate random bits
    get_random_bytes(rnds, sizeof(rnds));

    // Set virtual mac address

    // if (is_hwaddr_fixed && (num_of_fixed_hwaddr == 1 || num_of_fixed_hwaddr == num_of_devices)) {
    //     int fixed_hwaddr_index = (num_of_fixed_hwaddr == 1) ? 0 : index;
    //     int i;
    //     // Ignore the last octet
    //     for (i = 5; i > 0; --i)
    //         addr[i] = (char)(fixed_hwaddr[fixed_hwaddr_index] >> (8 * i));
    if (is_hwaddr_fixed) {
        addr[0] = 0x0c;
        addr[1] = 0xff;
        addr[2] = 0xfa;
        addr[3] = 0x00;
        addr[4] = 0x00;
    } else {
        addr[0] = 0x0c;
        addr[1] = 0xff;
        addr[2] = 0xfa;
        addr[3] = rnds[0];
        addr[4] = rnds[1];
    }
    addr[5] = index;

    // Register the addresses
    memcpy(priv->addresses[0].addr, addr, ETH_ALEN);
    memcpy(priv->addresses[1].addr, addr, ETH_ALEN);
    priv->addresses[1].addr[2] |= 0xfb;
    priv->hw->wiphy->n_addresses = 2;
    priv->hw->wiphy->addresses = priv->addresses;
    SET_IEEE80211_PERM_ADDR(priv->hw, addr);
}/*}}}*/

#define WMI_MAX_SPETIAL_STREAM 8
#define NUM_OF_RF_CHAINS WMI_MAX_SPETIAL_STREAM
static struct ieee80211_sta_vht_cap wtap_create_vht_cap(void) {/*{{{*/
    struct ieee80211_sta_vht_cap vht_cap = {0};
    u16 mcs_map = 0;
    int i = 0;

    vht_cap.vht_supported = true;
    vht_cap.cap = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454           |
        IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK |
        IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ |
        IEEE80211_VHT_CAP_RXLDPC                          |
        IEEE80211_VHT_CAP_SHORT_GI_80                     |
        IEEE80211_VHT_CAP_SHORT_GI_160                    |
        IEEE80211_VHT_CAP_TXSTBC                          |
        IEEE80211_VHT_CAP_RXSTBC_1                        |
        IEEE80211_VHT_CAP_RXSTBC_2                        |
        IEEE80211_VHT_CAP_RXSTBC_3                        |
        IEEE80211_VHT_CAP_RXSTBC_4                        |
        IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE           |
        IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE;

    for (i = 0; i < 8; ++i) {
        if (i < NUM_OF_RF_CHAINS) {
            mcs_map |= IEEE80211_VHT_MCS_SUPPORT_0_9 << (i * 2);
        } else {
            mcs_map |= IEEE80211_VHT_MCS_NOT_SUPPORTED << (i * 2);
        }
    }

    vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(mcs_map);
    vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(mcs_map);

    return vht_cap;
}/*}}}*/

#define WMI_PEER_SMPS_DYNAMIC 2
#define WMI_HT_CAP_RX_STBC 0x0030 /* B4 - B5 STBC */
#define WMI_HT_CAP_RX_STBC_MASK_SHIFT 4
static struct ieee80211_sta_ht_cap wtap_create_ht_cap(void) {/*{{{*/
    struct ieee80211_sta_ht_cap ht_cap = {0};
    u32 smps = 0;
    u32 stbc = 0;
    int i = 0;

    ht_cap.ht_supported = 1;
    ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
    ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_8;
    ht_cap.cap = IEEE80211_HT_CAP_MAX_AMSDU       |
        IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
        IEEE80211_HT_CAP_SGI_20          |
        IEEE80211_HT_CAP_SGI_40          |
        IEEE80211_HT_CAP_DSSSCCK40       |
        IEEE80211_HT_CAP_RX_STBC         |
        IEEE80211_HT_CAP_SM_PS           |
        IEEE80211_HT_CAP_LDPC_CODING     |
        IEEE80211_HT_CAP_LSIG_TXOP_PROT;

    ht_cap.cap = WLAN_HT_CAP_SM_PS_STATIC << IEEE80211_HT_CAP_SM_PS_SHIFT;
    smps = WLAN_HT_CAP_SM_PS_DYNAMIC;
    smps <<= IEEE80211_HT_CAP_SM_PS_SHIFT;
    ht_cap.cap |= smps;

    stbc   = WMI_HT_CAP_RX_STBC;
    stbc >>= WMI_HT_CAP_RX_STBC_MASK_SHIFT;
    stbc <<= IEEE80211_HT_CAP_RX_STBC_SHIFT;
    stbc  &= IEEE80211_HT_CAP_RX_STBC;
    ht_cap.cap |= stbc;

    for (i = 0; i < NUM_OF_RF_CHAINS; ++i) {
        ht_cap.mcs.rx_mask[i] = 0xff;
    }
    ht_cap.mcs.rx_highest = cpu_to_le16(300);
    ht_cap.mcs.tx_params |= IEEE80211_HT_MCS_TX_DEFINED;

    return ht_cap;
}/*}}}*/

static void wtap_set_all_channels(struct wtap_priv *priv) {/*{{{*/
    struct ieee80211_hw *hw = priv->hw;
    enum ieee80211_band band = 0;
    struct ieee80211_sta_ht_cap ht_cap = wtap_create_ht_cap();
    struct ieee80211_sta_vht_cap vht_cap = wtap_create_vht_cap();

    priv->channels = num_of_channels;
    priv->use_chanctx = !!(num_of_channels > 1);
    priv->p2p_device = !!(use_p2p);

    if (priv->use_chanctx) {
        hw->wiphy->max_scan_ssids = 255;
        hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;
        hw->wiphy->max_remain_on_channel_duration = 1000; // micro second

        hw->wiphy->iface_combinations = &priv->iface_combination;
        hw->wiphy->n_iface_combinations = 1;

        if (priv->p2p_device) {
            priv->iface_combination = wtap_iface_comb_p2p[0];
        } else {
            priv->iface_combination = wtap_iface_comb[0];
        }
        priv->iface_combination.num_different_channels = priv->channels;
    } else if (priv->p2p_device) {
        hw->wiphy->iface_combinations = wtap_iface_comb_p2p;
        hw->wiphy->n_iface_combinations = ARRAY_SIZE(wtap_iface_comb_p2p);
    } else {
        hw->wiphy->iface_combinations = wtap_iface_comb;
        hw->wiphy->n_iface_combinations = ARRAY_SIZE(wtap_iface_comb);
    }

    memcpy(priv->channels_2ghz, wtap_supported_channels_2ghz,
            sizeof(priv->channels_2ghz));
    memcpy(priv->channels_5ghz, wtap_supported_channels_5ghz,
            sizeof(priv->channels_5ghz));
    memcpy(priv->channels_60ghz, wtap_supported_channels_60ghz,
            sizeof(priv->channels_60ghz));
    memcpy(priv->rates, __wtap_supported_rates, sizeof(priv->rates));

    for (band = IEEE80211_BAND_2GHZ; band < IEEE80211_NUM_BANDS; ++band) {
        struct ieee80211_supported_band *sband = &priv->bands[band];

        if (band == IEEE80211_BAND_2GHZ) {
            sband = &wtap_supported_band_2ghz;
            sband->ht_cap = ht_cap;
            hw->wiphy->bands[band] = sband;
        }

        if (band == IEEE80211_BAND_5GHZ) {
            sband = &wtap_supported_band_5ghz;
            sband->ht_cap = ht_cap;
            sband->vht_cap = vht_cap;
            hw->wiphy->bands[band] = sband;
        }

        if (band == IEEE80211_BAND_60GHZ) {
            sband = &wtap_supported_band_60ghz;
            sband->ht_cap = ht_cap; /* Todo: redefine ht_cap for 60GHz band */
            hw->wiphy->bands[band] = sband;
        }
    }
}/*}}}*/

#define SUPPORT_RX_CHAINMASK ((1 << NUM_OF_RF_CHAINS) - 1)
#define SUPPORT_TX_CHAINMASK ((1 << NUM_OF_RF_CHAINS) - 1)
static void wtap_set_hw_flags_and_property(struct wtap_priv *priv) {/*{{{*/
    const char *fw_version = "No firmware";
    struct ieee80211_hw *hw = priv->hw;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    hw->flags |= IEEE80211_HW_SIGNAL_DBM |
        IEEE80211_HW_SUPPORTS_PS |
        IEEE80211_HW_SUPPORTS_UAPSD |
        IEEE80211_HW_SUPPORTS_HT_CCK_RATES |
        IEEE80211_HW_SPECTRUM_MGMT |
        IEEE80211_HW_MFP_CAPABLE |
        IEEE80211_HW_AP_LINK_PS |
        IEEE80211_HW_WANT_MONITOR_VIF |
        IEEE80211_HW_QUEUE_CONTROL |
        /* IEEE80211_HW_RX_INCLUDES_FCS | */
        IEEE80211_HW_CHANCTX_STA_CSA |
        IEEE80211_HW_AMPDU_AGGREGATION;
#else
    ieee80211_hw_set(hw, SIGNAL_DBM);
    ieee80211_hw_set(hw, SUPPORTS_PS);
    /* ieee80211_hw_set(hw, SUPPORTS_UAPSD); */
    ieee80211_hw_set(hw, SUPPORTS_HT_CCK_RATES);
    ieee80211_hw_set(hw, SPECTRUM_MGMT);
    ieee80211_hw_set(hw, MFP_CAPABLE);
    ieee80211_hw_set(hw, AP_LINK_PS);
    ieee80211_hw_set(hw, WANT_MONITOR_VIF);
    ieee80211_hw_set(hw, QUEUE_CONTROL);
    ieee80211_hw_set(hw, RX_INCLUDES_FCS);
    ieee80211_hw_set(hw, CHANCTX_STA_CSA);
    ieee80211_hw_set(hw, AMPDU_AGGREGATION);
#endif

    hw->vif_data_size = sizeof(struct wtap_vif_priv);
    hw->sta_data_size = sizeof(struct wtap_sta_priv);
    hw->chanctx_data_size = sizeof(struct wtap_chanctx_priv);

    hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD |
        WIPHY_FLAG_SUPPORTS_5_10_MHZ |
        WIPHY_FLAG_SUPPORTS_TDLS |
        /* WIPHY_FLAG_OFFCHAN_TX | */
        WIPHY_FLAG_HAS_CHANNEL_SWITCH |
        WIPHY_FLAG_REPORTS_OBSS |
        WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;

    hw->wiphy->features |= NL80211_FEATURE_ACTIVE_MONITOR |
        NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR |
        NL80211_FEATURE_STATIC_SMPS |
        NL80211_FEATURE_DYNAMIC_SMPS |
        NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE;

    hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_STATION) |
        BIT(NL80211_IFTYPE_AP) |
        BIT(NL80211_IFTYPE_ADHOC) |
        BIT(NL80211_IFTYPE_MESH_POINT) |
        BIT(NL80211_IFTYPE_OCB) |
        BIT(NL80211_IFTYPE_P2P_CLIENT) |
        BIT(NL80211_IFTYPE_P2P_GO);

    if (priv->p2p_device) {
        hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_P2P_DEVICE);
    }

    if (num_of_channels > 1) {
        hw->wiphy->available_antennas_rx = SUPPORT_RX_CHAINMASK;
        hw->wiphy->available_antennas_tx = SUPPORT_TX_CHAINMASK;
    } else {
        hw->wiphy->available_antennas_rx = 1;
        hw->wiphy->available_antennas_tx = 1;
    }

    /*
     * The number of tx queue.
     * QoS/WMM requires at least four.
     */
    hw->queues = 5;
    hw->offchannel_tx_hw_queue = 4;

    // Enable to retrasmit frames for lossy channels
    hw->max_rates = 4;
    hw->max_rate_tries = 11;

    // Set the hardware version
    hw->wiphy->hw_version = 1705;
    strncpy(hw->wiphy->fw_version, fw_version, strlen(fw_version) + 1);
}/*}}}*/

static void wtap_priv_init(struct wtap_priv *priv)/*{{{*/
{
    spin_lock_init(&priv->stat.spinlock);
}/*}}}*/

static int wtap_register_new_device(const char *hwname) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    struct ieee80211_ops *ops = NULL;
    struct wtap_priv *priv = NULL;
    struct ieee80211_hw *hw = NULL;
    unsigned int index = 0;
    int err = 0;

    spin_lock_bh(&shared->spinlock);
    index = shared->dev_index++;
    spin_unlock_bh(&shared->spinlock);

    ops = (num_of_channels > 1)? &wtap_mch_ops: &wtap_ops;
    hw = ieee80211_alloc_hw_nm(sizeof(*priv), ops, hwname);
    if (!hw) {
        error_msg("could not allocate memory for a new hardware");
        err = -ENOMEM;
        goto out_alloc_hw_failed;
    }

    priv = hw->priv;
    priv->hw = hw;
    priv->index = index;

    wtap_priv_init(priv);

    priv->dev = device_create(shared->class, NULL, 0, hw, "wtap80211-%d", index);
    if (IS_ERR(priv->dev)) {
        error_msg("could not create a device file.");
        err = -ENOMEM;
        goto out_free_hw;
    }
    priv->dev->driver = &wtap_platform_driver.driver;
    err = device_bind_driver(priv->dev);
    if (err != 0) {
        error_msg("could not bind the driver (err = %d).", err);
        goto out_device_unregister;
    }
    SET_IEEE80211_DEV(hw, priv->dev);

    mutex_init(&priv->mutex);
    INIT_LIST_HEAD(&priv->vif_list);
    skb_queue_head_init(&priv->pending);
    skb_queue_head_init(&priv->last_tx_frames);
    skb_queue_head_init(&priv->last_rx_frames);
    INIT_DELAYED_WORK(&priv->roc_done, wtap_roc_done);
    INIT_DELAYED_WORK(&priv->hw_scan, wtap_hw_scan_work);

    wtap_set_rnd_mac_addr(priv, index);
    wtap_set_all_channels(priv);
    wtap_set_hw_flags_and_property(priv);

    // Register the hardware
    err = ieee80211_register_hw(hw);
    if (err < 0) {
        error_msg("could not register a hardware (err = %d).", err);
        goto out_release_driver;
    }

    info_msg("new hardware (requested_hwname: %s, mac addr: %pM) registered.", hwname, hw->wiphy->perm_addr);

    priv->debugfs = debugfs_create_dir("wtap80211", priv->hw->wiphy->debugfsdir);
    debugfs_create_file("simple_test", 0667, priv->debugfs, priv, &wtap_fops_simple_test);
    debugfs_create_file("test", 0667, priv->debugfs, priv, &wtap_fops_test);
    debug_msg("priv address = %p", priv);

    spin_lock_bh(&shared->spinlock);
    list_add_tail(&priv->list, &shared->dev_list);
    spin_unlock_bh(&shared->spinlock);

    // Initialize the beacon timer
    tasklet_hrtimer_init(&priv->beacon_timer,
            wtap_beacon,
            CLOCK_MONOTONIC_RAW, HRTIMER_MODE_ABS);

    return 0;

out_release_driver:
    device_release_driver(priv->dev);
out_device_unregister:
    device_unregister(priv->dev);
out_free_hw:
    ieee80211_free_hw(hw);
out_alloc_hw_failed:
    return err;
}/*}}}*/

static void wtap_remove_device(struct wtap_priv *priv) {/*{{{*/
    debugfs_remove_recursive(priv->debugfs);
    ieee80211_unregister_hw(priv->hw);
    device_release_driver(priv->dev);
    device_unregister(priv->dev);
    ieee80211_free_hw(priv->hw);
}/*}}}*/

static void wtap_unregister_devices(void) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    struct wtap_priv *priv = NULL;

    spin_lock_bh(&shared->spinlock);

    while ((priv = list_first_entry_or_null(&shared->dev_list,
                    struct wtap_priv, list))) {
        list_del(&priv->list);
        spin_unlock_bh(&shared->spinlock);
        wtap_remove_device(priv);
        spin_lock_bh(&shared->spinlock);
    }
    spin_unlock_bh(&shared->spinlock);
}/*}}}*/

/* ------------------------------------------------------------------------------- */
/* Module Hooks                                                                    */
/* ------------------------------------------------------------------------------- */
static int __init wtap_init(void) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    int i, err = 0;

    // Check module parameters
    if (num_of_devices < 0 || num_of_devices > 1024 || num_of_channels < 1) {
        return -EINVAL;
    }

    // Initialize shared resources
    memset(shared, 0, sizeof(*shared));
    spin_lock_init(&shared->spinlock);
    mutex_init(&shared->mutex);
    INIT_LIST_HEAD(&shared->dev_list);

    shared->workqueue = create_workqueue("wtap80211wq");
    if (!shared->workqueue) {
        return -ENOMEM;
    }

    // Register the driver
    err = platform_driver_register(&wtap_platform_driver);
    if (err) {
        return err;
    }

    // Create a class file
    shared->class = class_create(THIS_MODULE, "wtap80211");
    if (IS_ERR(shared->class)) {
        err = PTR_ERR(shared->class);
        goto out_unregister_driver;
    }

    // Register hardware information
    for (i = 0; i < num_of_devices; ++i) {
        err = wtap_register_new_device(NULL);
        if (err) {
            goto out_unregister_devices;
        }
    }

    // Connect to the netlink
    err = wtap_genl_init();
    if (err < 0) {
        goto out_unregister_devices;
    }

    return 0;

out_unregister_devices:
    flush_workqueue(shared->workqueue);
    destroy_workqueue(shared->workqueue);
    wtap_unregister_devices();
    class_destroy(shared->class);
out_unregister_driver:
    platform_driver_unregister(&wtap_platform_driver);
    return err;
}/*}}}*/
module_init(wtap_init);

static void __exit wtap_exit(void) {/*{{{*/
    struct wtap_shared *shared = &wtap_shared;
    info_msg("unregistering driver ...");
    flush_workqueue(shared->workqueue);
    destroy_workqueue(shared->workqueue);
    wtap_genl_exit();
    wtap_unregister_devices();
    class_destroy(shared->class);
    platform_driver_unregister(&wtap_platform_driver);
}/*}}}*/
module_exit(wtap_exit);
