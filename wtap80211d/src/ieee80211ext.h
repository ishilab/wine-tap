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

/* Note that utils.h must be included earlier than ieee80211.h */
#include "utils.h"
#include "nl80211.h"
#include "ieee80211.h"

#define IEEE80211_MAX_CHAINS 4

/*
 * Forked from linux/cfg80211.h
 */

/**
 * enum ieee80211_band - supported frequency bands
 *
 * The bands are assigned this way because the supported
 * bitrates differ in these bands.
 *
 * @IEEE80211_BAND_2GHZ: 2.4GHz ISM band
 * @IEEE80211_BAND_5GHZ: around 5GHz band (4.9-5.7)
 * @IEEE80211_BAND_60GHZ: around 60 GHz band (58.32 - 64.80 GHz)
 * @IEEE80211_NUM_BANDS: number of defined bands
 */
enum ieee80211_band {
    IEEE80211_BAND_2GHZ  = NL80211_BAND_2GHZ,
    IEEE80211_BAND_5GHZ  = NL80211_BAND_5GHZ,
    IEEE80211_BAND_60GHZ = NL80211_BAND_60GHZ,

    /* keep last */
    IEEE80211_NUM_BANDS
};

/**
 * enum ieee80211_channel_flags - channel flags
 *
 * Channel flags set by the regulatory control code.
 *
 * @IEEE80211_CHAN_DISABLED: This channel is disabled.
 * @IEEE80211_CHAN_NO_IR: do not initiate radiation, this includes
 *   sending probe requests or beaconing.
 * @IEEE80211_CHAN_RADAR: Radar detection is required on this channel.
 * @IEEE80211_CHAN_NO_HT40PLUS: extension channel above this channel
 *   is not permitted.
 * @IEEE80211_CHAN_NO_HT40MINUS: extension channel below this channel
 *   is not permitted.
 * @IEEE80211_CHAN_NO_OFDM: OFDM is not allowed on this channel.
 * @IEEE80211_CHAN_NO_80MHZ: If the driver supports 80 MHz on the band,
 *  this flag indicates that an 80 MHz channel cannot use this
 *  channel as the control or any of the secondary channels.
 *  This may be due to the driver or due to regulatory bandwidth
 *  restrictions.
 * @IEEE80211_CHAN_NO_160MHZ: If the driver supports 160 MHz on the band,
 *  this flag indicates that an 160 MHz channel cannot use this
 *  channel as the control or any of the secondary channels.
 *  This may be due to the driver or due to regulatory bandwidth
 *  restrictions.
 * @IEEE80211_CHAN_INDOOR_ONLY: see %NL80211_FREQUENCY_ATTR_INDOOR_ONLY
 * @IEEE80211_CHAN_GO_CONCURRENT: see %NL80211_FREQUENCY_ATTR_GO_CONCURRENT
 * @IEEE80211_CHAN_NO_20MHZ: 20 MHz bandwidth is not permitted
 *  on this channel.
 * @IEEE80211_CHAN_NO_10MHZ: 10 MHz bandwidth is not permitted
 *  on this channel.
 *
 */
enum ieee80211_channel_flags {
    IEEE80211_CHAN_DISABLED      = 1<<0,
    IEEE80211_CHAN_NO_IR         = 1<<1,
    /* hole at 1<<2 */
    IEEE80211_CHAN_RADAR         = 1<<3,
    IEEE80211_CHAN_NO_HT40PLUS   = 1<<4,
    IEEE80211_CHAN_NO_HT40MINUS  = 1<<5,
    IEEE80211_CHAN_NO_OFDM       = 1<<6,
    IEEE80211_CHAN_NO_80MHZ      = 1<<7,
    IEEE80211_CHAN_NO_160MHZ     = 1<<8,
    IEEE80211_CHAN_INDOOR_ONLY   = 1<<9,
    IEEE80211_CHAN_GO_CONCURRENT = 1<<10,
    IEEE80211_CHAN_NO_20MHZ      = 1<<11,
    IEEE80211_CHAN_NO_10MHZ      = 1<<12,
};

#define IEEE80211_CHAN_NO_HT40 \
    (IEEE80211_CHAN_NO_HT40PLUS | IEEE80211_CHAN_NO_HT40MINUS)

#define IEEE80211_DFS_MIN_CAC_TIME_MS    60000
#define IEEE80211_DFS_MIN_NOP_TIME_MS    (30 * 60 * 1000)

/**
 * struct ieee80211_channel - channel definition
 *
 * This structure describes a single channel for use
 * with cfg80211.
 *
 * @center_freq: center frequency in MHz
 * @hw_value: hardware-specific value for the channel
 * @flags: channel flags from &enum ieee80211_channel_flags.
 * @orig_flags: channel flags at registration time, used by regulatory
 *  code to support devices with additional restrictions
 * @band: band this channel belongs to.
 * @max_antenna_gain: maximum antenna gain in dBi
 * @max_power: maximum transmission power (in dBm)
 * @max_reg_power: maximum regulatory transmission power (in dBm)
 * @beacon_found: helper to regulatory code to indicate when a beacon
 *  has been found on this channel. Use regulatory_hint_found_beacon()
 *  to enable this, this is useful only on 5 GHz band.
 * @orig_mag: internal use
 * @orig_mpwr: internal use
 * @dfs_state: current state of this channel. Only relevant if radar is required
 *  on this channel.
 * @dfs_state_entered: timestamp (jiffies) when the dfs state was entered.
 * @dfs_cac_ms: DFS CAC time in milliseconds, this is valid for DFS channels.
 */
struct ieee80211_channel {
    enum ieee80211_band band;
    u16 center_freq;
    u16 hw_value;
    u32 flags;
    int max_antenna_gain;
    int max_power;
    int max_reg_power;
    bool beacon_found;
    u32 orig_flags;
    int orig_mag, orig_mpwr;
    enum nl80211_dfs_state dfs_state;
    unsigned long dfs_state_entered;
    unsigned int dfs_cac_ms;
};

/**
 * enum ieee80211_rate_flags - rate flags
 *
 * Hardware/specification flags for rates. These are structured
 * in a way that allows using the same bitrate structure for
 * different bands/PHY modes.
 *
 * @IEEE80211_RATE_SHORT_PREAMBLE: Hardware can send with short
 *  preamble on this bitrate; only relevant in 2.4GHz band and
 *  with CCK rates.
 * @IEEE80211_RATE_MANDATORY_A: This bitrate is a mandatory rate
 *  when used with 802.11a (on the 5 GHz band); filled by the
 *  core code when registering the wiphy.
 * @IEEE80211_RATE_MANDATORY_B: This bitrate is a mandatory rate
 *  when used with 802.11b (on the 2.4 GHz band); filled by the
 *  core code when registering the wiphy.
 * @IEEE80211_RATE_MANDATORY_G: This bitrate is a mandatory rate
 *  when used with 802.11g (on the 2.4 GHz band); filled by the
 *  core code when registering the wiphy.
 * @IEEE80211_RATE_ERP_G: This is an ERP rate in 802.11g mode.
 * @IEEE80211_RATE_SUPPORTS_5MHZ: Rate can be used in 5 MHz mode
 * @IEEE80211_RATE_SUPPORTS_10MHZ: Rate can be used in 10 MHz mode
 */
enum ieee80211_rate_flags {
    IEEE80211_RATE_SHORT_PREAMBLE = 1<<0,
    IEEE80211_RATE_MANDATORY_A    = 1<<1,
    IEEE80211_RATE_MANDATORY_B    = 1<<2,
    IEEE80211_RATE_MANDATORY_G    = 1<<3,
    IEEE80211_RATE_ERP_G          = 1<<4,
    IEEE80211_RATE_SUPPORTS_5MHZ  = 1<<5,
    IEEE80211_RATE_SUPPORTS_10MHZ = 1<<6,
};

/**
 * struct ieee80211_rate - bitrate definition
 *
 * This structure describes a bitrate that an 802.11 PHY can
 * operate with. The two values @hw_value and @hw_value_short
 * are only for driver use when pointers to this structure are
 * passed around.
 *
 * @flags: rate-specific flags
 * @bitrate: bitrate in units of 100 Kbps
 * @hw_value: driver/hardware value for this rate
 * @hw_value_short: driver/hardware value for this rate when
 *  short preamble is used
 */
struct ieee80211_rate {
    u32 flags;
    u16 bitrate;
    u16 hw_value, hw_value_short;
};

/**
 * struct ieee80211_sta_ht_cap - STA's HT capabilities
 *
 * This structure describes most essential parameters needed
 * to describe 802.11n HT capabilities for an STA.
 *
 * @ht_supported: is HT supported by the STA
 * @cap: HT capabilities map as described in 802.11n spec
 * @ampdu_factor: Maximum A-MPDU length factor
 * @ampdu_density: Minimum A-MPDU spacing
 * @mcs: Supported MCS rates
 */
struct ieee80211_sta_ht_cap {
    u16 cap; /* use IEEE80211_HT_CAP_ */
    bool ht_supported;
    u8 ampdu_factor;
    u8 ampdu_density;
    struct ieee80211_mcs_info mcs;
};

/**
 * struct ieee80211_sta_vht_cap - STA's VHT capabilities
 *
 * This structure describes most essential parameters needed
 * to describe 802.11ac VHT capabilities for an STA.
 *
 * @vht_supported: is VHT supported by the STA
 * @cap: VHT capabilities map as described in 802.11ac spec
 * @vht_mcs: Supported VHT MCS rates
 */
struct ieee80211_sta_vht_cap {
    bool vht_supported;
    u32 cap; /* use IEEE80211_VHT_CAP_ */
    struct ieee80211_vht_mcs_info vht_mcs;
};

/**
 * struct cfg80211_chan_def - channel definition
 * @chan: the (control) channel
 * @width: channel width
 * @center_freq1: center frequency of first segment
 * @center_freq2: center frequency of second segment
 *  (only with 80+80 MHz)
 */
struct cfg80211_chan_def {
    struct ieee80211_channel *chan;
    enum nl80211_chan_width width;
    u32 center_freq1;
    u32 center_freq2;
};

/**
 * cfg80211_get_chandef_type - return old channel type from chandef
 * @chandef: the channel definition
 *
 * Return: The old channel type (NOHT, HT20, HT40+/-) from a given
 * chandef, which must have a bandwidth allowing this conversion.
 */
static inline enum nl80211_channel_type
cfg80211_get_chandef_type(const struct cfg80211_chan_def *chandef)
{
    switch (chandef->width) {
        case NL80211_CHAN_WIDTH_20_NOHT:
            return NL80211_CHAN_NO_HT;
        case NL80211_CHAN_WIDTH_20:
            return NL80211_CHAN_HT20;
        case NL80211_CHAN_WIDTH_40:
            if (chandef->center_freq1 > chandef->chan->center_freq)
                return NL80211_CHAN_HT40PLUS;
            return NL80211_CHAN_HT40MINUS;
        default:
            WARN_ON(1);
            return NL80211_CHAN_NO_HT;
    }
}

/**
 * ieee80211_chandef_rate_flags - returns rate flags for a channel
 *
 * In some channel types, not all rates may be used - for example CCK
 * rates may not be used in 5/10 MHz channels.
 *
 * @chandef: channel definition for the channel
 *
 * Returns: rate flags which apply for this channel
 */
static inline enum ieee80211_rate_flags
ieee80211_chandef_rate_flags(struct cfg80211_chan_def *chandef)
{
    switch (chandef->width) {
        case NL80211_CHAN_WIDTH_5:
            return IEEE80211_RATE_SUPPORTS_5MHZ;
        case NL80211_CHAN_WIDTH_10:
            return IEEE80211_RATE_SUPPORTS_10MHZ;
        default:
            break;
    }
    return 0;
}

/*
 * mac80211 structures
 */

/**
 * enum ieee80211_max_queues - maximum number of queues
 *
 * @IEEE80211_MAX_QUEUES: Maximum number of regular device queues.
 * @IEEE80211_MAX_QUEUE_MAP: bitmap with maximum queues set
 */
enum ieee80211_max_queues {
    IEEE80211_MAX_QUEUES    = 16,
    IEEE80211_MAX_QUEUE_MAP = BIT(IEEE80211_MAX_QUEUES) - 1,
};

#define IEEE80211_INVAL_HW_QUEUE  0xff

/**
 * enum ieee80211_ac_numbers - AC numbers as used in mac80211
 * @IEEE80211_AC_VO: voice
 * @IEEE80211_AC_VI: video
 * @IEEE80211_AC_BE: best effort
 * @IEEE80211_AC_BK: background
 */
enum ieee80211_ac_numbers {
    IEEE80211_AC_VO = 0,
    IEEE80211_AC_VI = 1,
    IEEE80211_AC_BE = 2,
    IEEE80211_AC_BK = 3,
};
#define IEEE80211_NUM_ACS  4

/**
 * struct ieee80211_tx_queue_params - transmit queue configuration
 *
 * The information provided in this structure is required for QoS
 * transmit queue configuration. Cf. IEEE 802.11 7.3.2.29.
 *
 * @aifs: arbitration interframe space [0..255]
 * @cw_min: minimum contention window [a value of the form
 *  2^n-1 in the range 1..32767]
 * @cw_max: maximum contention window [like @cw_min]
 * @txop: maximum burst time in units of 32 usecs, 0 meaning disabled
 * @acm: is mandatory admission control required for the access category
 * @uapsd: is U-APSD mode enabled for the queue
 */
struct ieee80211_tx_queue_params {
    u16 txop;
    u16 cw_min;
    u16 cw_max;
    u8 aifs;
    bool acm;
    bool uapsd;
};

/**
 * enum ieee80211_bss_change - BSS change notification flags
 *
 * These flags are used with the bss_info_changed() callback
 * to indicate which BSS parameter changed.
 *
 * @BSS_CHANGED_ASSOC: association status changed (associated/disassociated),
 *  also implies a change in the AID.
 * @BSS_CHANGED_ERP_CTS_PROT: CTS protection changed
 * @BSS_CHANGED_ERP_PREAMBLE: preamble changed
 * @BSS_CHANGED_ERP_SLOT: slot timing changed
 * @BSS_CHANGED_HT: 802.11n parameters changed
 * @BSS_CHANGED_BASIC_RATES: Basic rateset changed
 * @BSS_CHANGED_BEACON_INT: Beacon interval changed
 * @BSS_CHANGED_BSSID: BSSID changed, for whatever
 *  reason (IBSS and managed mode)
 * @BSS_CHANGED_BEACON: Beacon data changed, retrieve
 *  new beacon (beaconing modes)
 * @BSS_CHANGED_BEACON_ENABLED: Beaconing should be
 *  enabled/disabled (beaconing modes)
 * @BSS_CHANGED_CQM: Connection quality monitor config changed
 * @BSS_CHANGED_IBSS: IBSS join status changed
 * @BSS_CHANGED_ARP_FILTER: Hardware ARP filter address list or state changed.
 * @BSS_CHANGED_QOS: QoS for this association was enabled/disabled. Note
 *  that it is only ever disabled for station mode.
 * @BSS_CHANGED_IDLE: Idle changed for this BSS/interface.
 * @BSS_CHANGED_SSID: SSID changed for this BSS (AP and IBSS mode)
 * @BSS_CHANGED_AP_PROBE_RESP: Probe Response changed for this BSS (AP mode)
 * @BSS_CHANGED_PS: PS changed for this BSS (STA mode)
 * @BSS_CHANGED_TXPOWER: TX power setting changed for this interface
 * @BSS_CHANGED_P2P_PS: P2P powersave settings (CTWindow, opportunistic PS)
 *  changed (currently only in P2P client mode, GO mode will be later)
 * @BSS_CHANGED_BEACON_INFO: Data from the AP's beacon became available:
 *  currently dtim_period only is under consideration.
 * @BSS_CHANGED_BANDWIDTH: The bandwidth used by this interface changed,
 *  note that this is only called when it changes after the channel
 *  context had been assigned.
 * @BSS_CHANGED_OCB: OCB join status changed
 */
enum ieee80211_bss_change {
    BSS_CHANGED_ASSOC          = 1<<0,
    BSS_CHANGED_ERP_CTS_PROT   = 1<<1,
    BSS_CHANGED_ERP_PREAMBLE   = 1<<2,
    BSS_CHANGED_ERP_SLOT       = 1<<3,
    BSS_CHANGED_HT             = 1<<4,
    BSS_CHANGED_BASIC_RATES    = 1<<5,
    BSS_CHANGED_BEACON_INT     = 1<<6,
    BSS_CHANGED_BSSID          = 1<<7,
    BSS_CHANGED_BEACON         = 1<<8,
    BSS_CHANGED_BEACON_ENABLED = 1<<9,
    BSS_CHANGED_CQM            = 1<<10,
    BSS_CHANGED_IBSS           = 1<<11,
    BSS_CHANGED_ARP_FILTER     = 1<<12,
    BSS_CHANGED_QOS            = 1<<13,
    BSS_CHANGED_IDLE           = 1<<14,
    BSS_CHANGED_SSID           = 1<<15,
    BSS_CHANGED_AP_PROBE_RESP  = 1<<16,
    BSS_CHANGED_PS             = 1<<17,
    BSS_CHANGED_TXPOWER        = 1<<18,
    BSS_CHANGED_P2P_PS         = 1<<19,
    BSS_CHANGED_BEACON_INFO    = 1<<20,
    BSS_CHANGED_BANDWIDTH      = 1<<21,
    BSS_CHANGED_OCB            = 1<<22,

    /* when adding here, make sure to change ieee80211_reconfig */
};

/*
 * The maximum number of IPv4 addresses listed for ARP filtering. If the number
 * of addresses for an interface increase beyond this value, hardware ARP
 * filtering will be disabled.
 */
#define IEEE80211_BSS_ARP_ADDR_LIST_LEN 4

/**
 * enum ieee80211_rssi_event - RSSI threshold event
 * An indicator for when RSSI goes below/above a certain threshold.
 * @RSSI_EVENT_HIGH: AP's rssi crossed the high threshold set by the driver.
 * @RSSI_EVENT_LOW: AP's rssi crossed the low threshold set by the driver.
 */
enum ieee80211_rssi_event {
    RSSI_EVENT_HIGH,
    RSSI_EVENT_LOW,
};

/**
 * struct ieee80211_bss_conf - holds the BSS's changing parameters
 *
 * This structure keeps information about a BSS (and an association
 * to that BSS) that can change during the lifetime of the BSS.
 *
 * @assoc: association status
 * @ibss_joined: indicates whether this station is part of an IBSS
 *  or not
 * @ibss_creator: indicates if a new IBSS network is being created
 * @aid: association ID number, valid only when @assoc is true
 * @use_cts_prot: use CTS protection
 * @use_short_preamble: use 802.11b short preamble;
 *  if the hardware cannot handle this it must set the
 *  IEEE80211_HW_2GHZ_SHORT_PREAMBLE_INCAPABLE hardware flag
 * @use_short_slot: use short slot time (only relevant for ERP);
 *  if the hardware cannot handle this it must set the
 *  IEEE80211_HW_2GHZ_SHORT_SLOT_INCAPABLE hardware flag
 * @dtim_period: num of beacons before the next DTIM, for beaconing,
 *  valid in station mode only if after the driver was notified
 *  with the %BSS_CHANGED_BEACON_INFO flag, will be non-zero then.
 * @sync_tsf: last beacon's/probe response's TSF timestamp (could be old
 *  as it may have been received during scanning long ago). If the
 *  HW flag %IEEE80211_HW_TIMING_BEACON_ONLY is set, then this can
 *  only come from a beacon, but might not become valid until after
 *  association when a beacon is received (which is notified with the
 *  %BSS_CHANGED_DTIM flag.)
 * @sync_device_ts: the device timestamp corresponding to the sync_tsf,
 *  the driver/device can use this to calculate synchronisation
 *  (see @sync_tsf)
 * @sync_dtim_count: Only valid when %IEEE80211_HW_TIMING_BEACON_ONLY
 *  is requested, see @sync_tsf/@sync_device_ts.
 * @beacon_int: beacon interval
 * @assoc_capability: capabilities taken from assoc resp
 * @basic_rates: bitmap of basic rates, each bit stands for an
 *  index into the rate table configured by the driver in
 *  the current band.
 * @beacon_rate: associated AP's beacon TX rate
 * @mcast_rate: per-band multicast rate index + 1 (0: disabled)
 * @bssid: The BSSID for this BSS
 * @enable_beacon: whether beaconing should be enabled or not
 * @chandef: Channel definition for this BSS -- the hardware might be
 *  configured a higher bandwidth than this BSS uses, for example.
 * @ht_operation_mode: HT operation mode like in &struct ieee80211_ht_operation.
 *  This field is only valid when the channel type is one of the HT types.
 * @cqm_rssi_thold: Connection quality monitor RSSI threshold, a zero value
 *  implies disabled
 * @cqm_rssi_hyst: Connection quality monitor RSSI hysteresis
 * @arp_addr_list: List of IPv4 addresses for hardware ARP filtering. The
 *  may filter ARP queries targeted for other addresses than listed here.
 *  The driver must allow ARP queries targeted for all address listed here
 *  to pass through. An empty list implies no ARP queries need to pass.
 * @arp_addr_cnt: Number of addresses currently on the list. Note that this
 *  may be larger than %IEEE80211_BSS_ARP_ADDR_LIST_LEN (the arp_addr_list
 *  array size), it's up to the driver what to do in that case.
 * @qos: This is a QoS-enabled BSS.
 * @idle: This interface is idle. There's also a global idle flag in the
 *  hardware config which may be more appropriate depending on what
 *  your driver/device needs to do.
 * @ps: power-save mode (STA only). This flag is NOT affected by
 *  offchannel/dynamic_ps operations.
 * @ssid: The SSID of the current vif. Valid in AP and IBSS mode.
 * @ssid_len: Length of SSID given in @ssid.
 * @hidden_ssid: The SSID of the current vif is hidden. Only valid in AP-mode.
 * @txpower: TX power in dBm
 * @p2p_noa_attr: P2P NoA attribute for P2P powersave
 */
struct ieee80211_bss_conf {
    const u8 *bssid;
    /* association related data */
    bool assoc, ibss_joined;
    bool ibss_creator;
    u16 aid;
    /* erp related data */
    bool use_cts_prot;
    bool use_short_preamble;
    bool use_short_slot;
    bool enable_beacon;
    u8 dtim_period;
    u16 beacon_int;
    u16 assoc_capability;
    u64 sync_tsf;
    u32 sync_device_ts;
    u8 sync_dtim_count;
    u32 basic_rates;
    struct ieee80211_rate *beacon_rate;
    int mcast_rate[IEEE80211_NUM_BANDS];
    u16 ht_operation_mode;
    s32 cqm_rssi_thold;
    u32 cqm_rssi_hyst;
    struct cfg80211_chan_def chandef;
    __be32 arp_addr_list[IEEE80211_BSS_ARP_ADDR_LIST_LEN];
    int arp_addr_cnt;
    bool qos;
    bool idle;
    bool ps;
    u8 ssid[IEEE80211_MAX_SSID_LEN];
    size_t ssid_len;
    bool hidden_ssid;
    int txpower;
    struct ieee80211_p2p_noa_attr p2p_noa_attr;
};

/**
 * enum mac80211_tx_info_flags - flags to describe transmission information/status
 *
 * These flags are used with the @flags member of &ieee80211_tx_info.
 *
 * @IEEE80211_TX_CTL_REQ_TX_STATUS: require TX status callback for this frame.
 * @IEEE80211_TX_CTL_ASSIGN_SEQ: The driver has to assign a sequence
 *  number to this frame, taking care of not overwriting the fragment
 *  number and increasing the sequence number only when the
 *  IEEE80211_TX_CTL_FIRST_FRAGMENT flag is set. mac80211 will properly
 *  assign sequence numbers to QoS-data frames but cannot do so correctly
 *  for non-QoS-data and management frames because beacons need them from
 *  that counter as well and mac80211 cannot guarantee proper sequencing.
 *  If this flag is set, the driver should instruct the hardware to
 *  assign a sequence number to the frame or assign one itself. Cf. IEEE
 *  802.11-2007 7.1.3.4.1 paragraph 3. This flag will always be set for
 *  beacons and always be clear for frames without a sequence number field.
 * @IEEE80211_TX_CTL_NO_ACK: tell the low level not to wait for an ack
 * @IEEE80211_TX_CTL_CLEAR_PS_FILT: clear powersave filter for destination
 *  station
 * @IEEE80211_TX_CTL_FIRST_FRAGMENT: this is a first fragment of the frame
 * @IEEE80211_TX_CTL_SEND_AFTER_DTIM: send this frame after DTIM beacon
 * @IEEE80211_TX_CTL_AMPDU: this frame should be sent as part of an A-MPDU
 * @IEEE80211_TX_CTL_INJECTED: Frame was injected, internal to mac80211.
 * @IEEE80211_TX_STAT_TX_FILTERED: The frame was not transmitted
 *  because the destination STA was in powersave mode. Note that to
 *  avoid race conditions, the filter must be set by the hardware or
 *  firmware upon receiving a frame that indicates that the station
 *  went to sleep (must be done on device to filter frames already on
 *  the queue) and may only be unset after mac80211 gives the OK for
 *  that by setting the IEEE80211_TX_CTL_CLEAR_PS_FILT (see above),
 *  since only then is it guaranteed that no more frames are in the
 *  hardware queue.
 * @IEEE80211_TX_STAT_ACK: Frame was acknowledged
 * @IEEE80211_TX_STAT_AMPDU: The frame was aggregated, so status
 *   is for the whole aggregation.
 * @IEEE80211_TX_STAT_AMPDU_NO_BACK: no block ack was returned,
 *   so consider using block ack request (BAR).
 * @IEEE80211_TX_CTL_RATE_CTRL_PROBE: internal to mac80211, can be
 *  set by rate control algorithms to indicate probe rate, will
 *  be cleared for fragmented frames (except on the last fragment)
 * @IEEE80211_TX_INTFL_OFFCHAN_TX_OK: Internal to mac80211. Used to indicate
 *  that a frame can be transmitted while the queues are stopped for
 *  off-channel operation.
 * @IEEE80211_TX_INTFL_NEED_TXPROCESSING: completely internal to mac80211,
 *  used to indicate that a pending frame requires TX processing before
 *  it can be sent out.
 * @IEEE80211_TX_INTFL_RETRIED: completely internal to mac80211,
 *  used to indicate that a frame was already retried due to PS
 * @IEEE80211_TX_INTFL_DONT_ENCRYPT: completely internal to mac80211,
 *  used to indicate frame should not be encrypted
 * @IEEE80211_TX_CTL_NO_PS_BUFFER: This frame is a response to a poll
 *  frame (PS-Poll or uAPSD) or a non-bufferable MMPDU and must
 *  be sent although the station is in powersave mode.
 * @IEEE80211_TX_CTL_MORE_FRAMES: More frames will be passed to the
 *  transmit function after the current frame, this can be used
 *  by drivers to kick the DMA queue only if unset or when the
 *  queue gets full.
 * @IEEE80211_TX_INTFL_RETRANSMISSION: This frame is being retransmitted
 *  after TX status because the destination was asleep, it must not
 *  be modified again (no seqno assignment, crypto, etc.)
 * @IEEE80211_TX_INTFL_MLME_CONN_TX: This frame was transmitted by the MLME
 *  code for connection establishment, this indicates that its status
 *  should kick the MLME state machine.
 * @IEEE80211_TX_INTFL_NL80211_FRAME_TX: Frame was requested through nl80211
 *  MLME command (internal to mac80211 to figure out whether to send TX
 *  status to user space)
 * @IEEE80211_TX_CTL_LDPC: tells the driver to use LDPC for this frame
 * @IEEE80211_TX_CTL_STBC: Enables Space-Time Block Coding (STBC) for this
 *  frame and selects the maximum number of streams that it can use.
 * @IEEE80211_TX_CTL_TX_OFFCHAN: Marks this packet to be transmitted on
*  the off-channel channel when a remain-on-channel offload is done
*  in hardware -- normal packets still flow and are expected to be
*  handled properly by the device.
* @IEEE80211_TX_INTFL_TKIP_MIC_FAILURE: Marks this packet to be used for TKIP
*  testing. It will be sent out with incorrect Michael MIC key to allow
*  TKIP countermeasures to be tested.
* @IEEE80211_TX_CTL_NO_CCK_RATE: This frame will be sent at non CCK rate.
*  This flag is actually used for management frame especially for P2P
*  frames not being sent at CCK rate in 2GHz band.
* @IEEE80211_TX_STATUS_EOSP: This packet marks the end of service period,
*  when its status is reported the service period ends. For frames in
*  an SP that mac80211 transmits, it is already set; for driver frames
*  the driver may set this flag. It is also used to do the same for
*  PS-Poll responses.
* @IEEE80211_TX_CTL_USE_MINRATE: This frame will be sent at lowest rate.
*  This flag is used to send nullfunc frame at minimum rate when
*  the nullfunc is used for connection monitoring purpose.
* @IEEE80211_TX_CTL_DONTFRAG: Don't fragment this packet even if it
*  would be fragmented by size (this is optional, only used for
*  monitor injection).
* @IEEE80211_TX_CTL_PS_RESPONSE: This frame is a response to a poll
*  frame (PS-Poll or uAPSD).
*
* Note: If you have to add new flags to the enumeration, then don't
*   forget to update %IEEE80211_TX_TEMPORARY_FLAGS when necessary.
*/
enum mac80211_tx_info_flags {
    IEEE80211_TX_CTL_REQ_TX_STATUS       = BIT(0),
    IEEE80211_TX_CTL_ASSIGN_SEQ          = BIT(1),
    IEEE80211_TX_CTL_NO_ACK              = BIT(2),
    IEEE80211_TX_CTL_CLEAR_PS_FILT       = BIT(3),
    IEEE80211_TX_CTL_FIRST_FRAGMENT      = BIT(4),
    IEEE80211_TX_CTL_SEND_AFTER_DTIM     = BIT(5),
    IEEE80211_TX_CTL_AMPDU               = BIT(6),
    IEEE80211_TX_CTL_INJECTED            = BIT(7),
    IEEE80211_TX_STAT_TX_FILTERED        = BIT(8),
    IEEE80211_TX_STAT_ACK                = BIT(9),
    IEEE80211_TX_STAT_AMPDU              = BIT(10),
    IEEE80211_TX_STAT_AMPDU_NO_BACK      = BIT(11),
    IEEE80211_TX_CTL_RATE_CTRL_PROBE     = BIT(12),
    IEEE80211_TX_INTFL_OFFCHAN_TX_OK     = BIT(13),
    IEEE80211_TX_INTFL_NEED_TXPROCESSING = BIT(14),
    IEEE80211_TX_INTFL_RETRIED           = BIT(15),
    IEEE80211_TX_INTFL_DONT_ENCRYPT      = BIT(16),
    IEEE80211_TX_CTL_NO_PS_BUFFER        = BIT(17),
    IEEE80211_TX_CTL_MORE_FRAMES         = BIT(18),
    IEEE80211_TX_INTFL_RETRANSMISSION    = BIT(19),
    IEEE80211_TX_INTFL_MLME_CONN_TX      = BIT(20),
    IEEE80211_TX_INTFL_NL80211_FRAME_TX  = BIT(21),
    IEEE80211_TX_CTL_LDPC                = BIT(22),
    IEEE80211_TX_CTL_STBC                = BIT(23) | BIT(24),
    IEEE80211_TX_CTL_TX_OFFCHAN          = BIT(25),
    IEEE80211_TX_INTFL_TKIP_MIC_FAILURE  = BIT(26),
    IEEE80211_TX_CTL_NO_CCK_RATE         = BIT(27),
    IEEE80211_TX_STATUS_EOSP             = BIT(28),
    IEEE80211_TX_CTL_USE_MINRATE         = BIT(29),
    IEEE80211_TX_CTL_DONTFRAG            = BIT(30),
    IEEE80211_TX_CTL_PS_RESPONSE         = BIT(31),
};

#define IEEE80211_TX_CTL_STBC_SHIFT    23

/**
 * enum mac80211_tx_control_flags - flags to describe transmit control
 *
 * @IEEE80211_TX_CTRL_PORT_CTRL_PROTO: this frame is a port control
 *  protocol frame (e.g. EAP)
 *
 * These flags are used in tx_info->control.flags.
 */
enum mac80211_tx_control_flags {
    IEEE80211_TX_CTRL_PORT_CTRL_PROTO  = BIT(0),
};

/*
 * This definition is used as a mask to clear all temporary flags, which are
 * set by the tx handlers for each transmission attempt by the mac80211 stack.
 */
#define IEEE80211_TX_TEMPORARY_FLAGS (IEEE80211_TX_CTL_NO_ACK |          \
        IEEE80211_TX_CTL_CLEAR_PS_FILT | IEEE80211_TX_CTL_FIRST_FRAGMENT |    \
        IEEE80211_TX_CTL_SEND_AFTER_DTIM | IEEE80211_TX_CTL_AMPDU |        \
        IEEE80211_TX_STAT_TX_FILTERED |  IEEE80211_TX_STAT_ACK |          \
        IEEE80211_TX_STAT_AMPDU | IEEE80211_TX_STAT_AMPDU_NO_BACK |        \
        IEEE80211_TX_CTL_RATE_CTRL_PROBE | IEEE80211_TX_CTL_NO_PS_BUFFER |    \
        IEEE80211_TX_CTL_MORE_FRAMES | IEEE80211_TX_CTL_LDPC |          \
        IEEE80211_TX_CTL_STBC | IEEE80211_TX_STATUS_EOSP)

/**
 * enum mac80211_rate_control_flags - per-rate flags set by the
 *  Rate Control algorithm.
 *
 * These flags are set by the Rate control algorithm for each rate during tx,
 * in the @flags member of struct ieee80211_tx_rate.
 *
 * @IEEE80211_TX_RC_USE_RTS_CTS: Use RTS/CTS exchange for this rate.
 * @IEEE80211_TX_RC_USE_CTS_PROTECT: CTS-to-self protection is required.
 *  This is set if the current BSS requires ERP protection.
 * @IEEE80211_TX_RC_USE_SHORT_PREAMBLE: Use short preamble.
 * @IEEE80211_TX_RC_MCS: HT rate.
 * @IEEE80211_TX_RC_VHT_MCS: VHT MCS rate, in this case the idx field is split
 *  into a higher 4 bits (Nss) and lower 4 bits (MCS number)
 * @IEEE80211_TX_RC_GREEN_FIELD: Indicates whether this rate should be used in
 *  Greenfield mode.
 * @IEEE80211_TX_RC_40_MHZ_WIDTH: Indicates if the Channel Width should be 40 MHz.
 * @IEEE80211_TX_RC_80_MHZ_WIDTH: Indicates 80 MHz transmission
 * @IEEE80211_TX_RC_160_MHZ_WIDTH: Indicates 160 MHz transmission
 *  (80+80 isn't supported yet)
 * @IEEE80211_TX_RC_DUP_DATA: The frame should be transmitted on both of the
 *  adjacent 20 MHz channels, if the current channel type is
 *  NL80211_CHAN_HT40MINUS or NL80211_CHAN_HT40PLUS.
 * @IEEE80211_TX_RC_SHORT_GI: Short Guard interval should be used for this rate.
 */
enum mac80211_rate_control_flags {
    IEEE80211_TX_RC_USE_RTS_CTS        = BIT(0),
    IEEE80211_TX_RC_USE_CTS_PROTECT    = BIT(1),
    IEEE80211_TX_RC_USE_SHORT_PREAMBLE = BIT(2),

    /* rate index is an HT/VHT MCS instead of an index */
    IEEE80211_TX_RC_MCS                = BIT(3),
    IEEE80211_TX_RC_GREEN_FIELD        = BIT(4),
    IEEE80211_TX_RC_40_MHZ_WIDTH       = BIT(5),
    IEEE80211_TX_RC_DUP_DATA           = BIT(6),
    IEEE80211_TX_RC_SHORT_GI           = BIT(7),
    IEEE80211_TX_RC_VHT_MCS            = BIT(8),
    IEEE80211_TX_RC_80_MHZ_WIDTH       = BIT(9),
    IEEE80211_TX_RC_160_MHZ_WIDTH      = BIT(10),
};


/* there are 40 bytes if you don't need the rateset to be kept */
#define IEEE80211_TX_INFO_DRIVER_DATA_SIZE 40

/* if you do need the rateset, then you have less space */
#define IEEE80211_TX_INFO_RATE_DRIVER_DATA_SIZE 24

/* maximum number of rate stages */
#define IEEE80211_TX_MAX_RATES  4

/* maximum number of rate table entries */
#define IEEE80211_TX_RATE_TABLE_SIZE  4

/**
 * struct ieee80211_tx_rate - rate selection/status
 *
 * @idx: rate index to attempt to send with
 * @flags: rate control flags (&enum mac80211_rate_control_flags)
 * @count: number of tries in this rate before going to the next rate
 *
 * A value of -1 for @idx indicates an invalid rate and, if used
 * in an array of retry rates, that no more rates should be tried.
 *
 * When used for transmit status reporting, the driver should
 * always report the rate along with the flags it used.
 *
 * &struct ieee80211_tx_info contains an array of these structs
 * in the control information, and it will be filled by the rate
 * control algorithm according to what should be sent. For example,
 * if this array contains, in the format { <idx>, <count> } the
 * information
 *    { 3, 2 }, { 2, 2 }, { 1, 4 }, { -1, 0 }, { -1, 0 }
 * then this means that the frame should be transmitted
 * up to twice at rate 3, up to twice at rate 2, and up to four
 * times at rate 1 if it doesn't get acknowledged. Say it gets
 * acknowledged by the peer after the fifth attempt, the status
 * information should then contain
 *   { 3, 2 }, { 2, 2 }, { 1, 1 }, { -1, 0 } ...
 * since it was transmitted twice at rate 3, twice at rate 2
 * and once at rate 1 after which we received an acknowledgement.
 */
struct ieee80211_tx_rate {
    s8 idx;
    u16 count:5,
        flags:11;
} __packed;

#define IEEE80211_MAX_TX_RETRY    31

static inline void ieee80211_rate_set_vht(struct ieee80211_tx_rate *rate,
        u8 mcs, u8 nss)
{
    WARN_ON(mcs & ~0xF);
    WARN_ON((nss - 1) & ~0x7);
    rate->idx = ((nss - 1) << 4) | mcs;
}

    static inline u8
ieee80211_rate_get_vht_mcs(const struct ieee80211_tx_rate *rate)
{
    return rate->idx & 0xF;
}

    static inline u8
ieee80211_rate_get_vht_nss(const struct ieee80211_tx_rate *rate)
{
    return (rate->idx >> 4) + 1;
}

/**
 * struct ieee80211_tx_info - skb transmit information
 *
 * This structure is placed in skb->cb for three uses:
 *  (1) mac80211 TX control - mac80211 tells the driver what to do
 *  (2) driver internal use (if applicable)
 *  (3) TX status information - driver tells mac80211 what happened
 *
 * @flags: transmit info flags, defined above
 * @band: the band to transmit on (use for checking for races)
 * @hw_queue: HW queue to put the frame on, skb_get_queue_mapping() gives the AC
 * @ack_frame_id: internal frame ID for TX status, used internally
 * @control: union for control data
 * @status: union for status data
 * @driver_data: array of driver_data pointers
 * @ampdu_ack_len: number of acked aggregated frames.
 *   relevant only if IEEE80211_TX_STAT_AMPDU was set.
 * @ampdu_len: number of aggregated frames.
 *   relevant only if IEEE80211_TX_STAT_AMPDU was set.
 * @ack_signal: signal strength of the ACK frame
 */
struct ieee80211_tx_info {
    /* common information */
    u32 flags;
    u8 band;

    u8 hw_queue;

    u16 ack_frame_id;

    union {
        struct {
            union {
                /* rate control */
                struct {
                    struct ieee80211_tx_rate rates[
                        IEEE80211_TX_MAX_RATES];
                    s8 rts_cts_rate_idx;
                    u8 use_rts:1;
                    u8 use_cts_prot:1;
                    u8 short_preamble:1;
                    u8 skip_table:1;
                    /* 2 bytes free */
                };
                /* only needed before rate control */
                unsigned long jiffies;
            };
            /* NB: vif can be NULL for injected frames */
            struct ieee80211_vif *vif;
            struct ieee80211_key_conf *hw_key;
            u32 flags;
            /* 4 bytes free */
        } control;
        struct {
            struct ieee80211_tx_rate rates[IEEE80211_TX_MAX_RATES];
            s32 ack_signal;
            u8 ampdu_ack_len;
            u8 ampdu_len;
            u8 antenna;
            u16 tx_time;
            void *status_driver_data[19 / sizeof(void *)];
        } status;
        struct {
            struct ieee80211_tx_rate driver_rates[
                IEEE80211_TX_MAX_RATES];
            u8 pad[4];

            void *rate_driver_data[
                IEEE80211_TX_INFO_RATE_DRIVER_DATA_SIZE / sizeof(void *)];
        };
        void *driver_data[
            IEEE80211_TX_INFO_DRIVER_DATA_SIZE / sizeof(void *)];
    };
};

/**
 * enum mac80211_rx_flags - receive flags
 *
 * These flags are used with the @flag member of &struct ieee80211_rx_status.
 * @RX_FLAG_MMIC_ERROR: Michael MIC error was reported on this frame.
 *  Use together with %RX_FLAG_MMIC_STRIPPED.
 * @RX_FLAG_DECRYPTED: This frame was decrypted in hardware.
 * @RX_FLAG_MMIC_STRIPPED: the Michael MIC is stripped off this frame,
 *  verification has been done by the hardware.
 * @RX_FLAG_IV_STRIPPED: The IV/ICV are stripped from this frame.
 *  If this flag is set, the stack cannot do any replay detection
 *  hence the driver or hardware will have to do that.
 * @RX_FLAG_FAILED_FCS_CRC: Set this flag if the FCS check failed on
 *  the frame.
 * @RX_FLAG_FAILED_PLCP_CRC: Set this flag if the PCLP check failed on
 *  the frame.
 * @RX_FLAG_MACTIME_START: The timestamp passed in the RX status (@mactime
 *  field) is valid and contains the time the first symbol of the MPDU
 *  was received. This is useful in monitor mode and for proper IBSS
 *  merging.
 * @RX_FLAG_MACTIME_END: The timestamp passed in the RX status (@mactime
 *  field) is valid and contains the time the last symbol of the MPDU
 *  (including FCS) was received.
 * @RX_FLAG_SHORTPRE: Short preamble was used for this frame
 * @RX_FLAG_HT: HT MCS was used and rate_idx is MCS index
 * @RX_FLAG_VHT: VHT MCS was used and rate_index is MCS index
 * @RX_FLAG_40MHZ: HT40 (40 MHz) was used
 * @RX_FLAG_SHORT_GI: Short guard interval was used
 * @RX_FLAG_NO_SIGNAL_VAL: The signal strength value is not present.
 *  Valid only for data frames (mainly A-MPDU)
 * @RX_FLAG_HT_GF: This frame was received in a HT-greenfield transmission, if
 *  the driver fills this value it should add %IEEE80211_RADIOTAP_MCS_HAVE_FMT
 *  to hw.radiotap_mcs_details to advertise that fact
 * @RX_FLAG_AMPDU_DETAILS: A-MPDU details are known, in particular the reference
 *  number (@ampdu_reference) must be populated and be a distinct number for
 *  each A-MPDU
 * @RX_FLAG_AMPDU_REPORT_ZEROLEN: driver reports 0-length subframes
 * @RX_FLAG_AMPDU_IS_ZEROLEN: This is a zero-length subframe, for
 *  monitoring purposes only
 * @RX_FLAG_AMPDU_LAST_KNOWN: last subframe is known, should be set on all
 *  subframes of a single A-MPDU
 * @RX_FLAG_AMPDU_IS_LAST: this subframe is the last subframe of the A-MPDU
 * @RX_FLAG_AMPDU_DELIM_CRC_ERROR: A delimiter CRC error has been detected
 *  on this subframe
 * @RX_FLAG_AMPDU_DELIM_CRC_KNOWN: The delimiter CRC field is known (the CRC
 *  is stored in the @ampdu_delimiter_crc field)
 * @RX_FLAG_LDPC: LDPC was used
 * @RX_FLAG_STBC_MASK: STBC 2 bit bitmask. 1 - Nss=1, 2 - Nss=2, 3 - Nss=3
 * @RX_FLAG_10MHZ: 10 MHz (half channel) was used
 * @RX_FLAG_5MHZ: 5 MHz (quarter channel) was used
 * @RX_FLAG_AMSDU_MORE: Some drivers may prefer to report separate A-MSDU
 *  subframes instead of a one huge frame for performance reasons.
 *  All, but the last MSDU from an A-MSDU should have this flag set. E.g.
 *  if an A-MSDU has 3 frames, the first 2 must have the flag set, while
 *  the 3rd (last) one must not have this flag set. The flag is used to
 *  deal with retransmission/duplication recovery properly since A-MSDU
 *  subframes share the same sequence number. Reported subframes can be
 *  either regular MSDU or singly A-MSDUs. Subframes must not be
 *  interleaved with other frames.
 * @RX_FLAG_RADIOTAP_VENDOR_DATA: This frame contains vendor-specific
 *  radiotap data in the skb->data (before the frame) as described by
 *  the &struct ieee80211_vendor_radiotap.
 */
enum mac80211_rx_flags {
    RX_FLAG_MMIC_ERROR            = BIT(0),
    RX_FLAG_DECRYPTED             = BIT(1),
    RX_FLAG_MMIC_STRIPPED         = BIT(3),
    RX_FLAG_IV_STRIPPED           = BIT(4),
    RX_FLAG_FAILED_FCS_CRC        = BIT(5),
    RX_FLAG_FAILED_PLCP_CRC       = BIT(6),
    RX_FLAG_MACTIME_START         = BIT(7),
    RX_FLAG_SHORTPRE              = BIT(8),
    RX_FLAG_HT                    = BIT(9),
    RX_FLAG_40MHZ                 = BIT(10),
    RX_FLAG_SHORT_GI              = BIT(11),
    RX_FLAG_NO_SIGNAL_VAL         = BIT(12),
    RX_FLAG_HT_GF                 = BIT(13),
    RX_FLAG_AMPDU_DETAILS         = BIT(14),
    RX_FLAG_AMPDU_REPORT_ZEROLEN  = BIT(15),
    RX_FLAG_AMPDU_IS_ZEROLEN      = BIT(16),
    RX_FLAG_AMPDU_LAST_KNOWN      = BIT(17),
    RX_FLAG_AMPDU_IS_LAST         = BIT(18),
    RX_FLAG_AMPDU_DELIM_CRC_ERROR = BIT(19),
    RX_FLAG_AMPDU_DELIM_CRC_KNOWN = BIT(20),
    RX_FLAG_MACTIME_END           = BIT(21),
    RX_FLAG_VHT                   = BIT(22),
    RX_FLAG_LDPC                  = BIT(23),
    RX_FLAG_STBC_MASK             = BIT(26) | BIT(27),
    RX_FLAG_10MHZ                 = BIT(28),
    RX_FLAG_5MHZ                  = BIT(29),
    RX_FLAG_AMSDU_MORE            = BIT(30),
    RX_FLAG_RADIOTAP_VENDOR_DATA  = BIT(31),
};

#define RX_FLAG_STBC_SHIFT    26

/**
 * enum mac80211_rx_vht_flags - receive VHT flags
 *
 * These flags are used with the @vht_flag member of
 *  &struct ieee80211_rx_status.
 * @RX_VHT_FLAG_80MHZ: 80 MHz was used
 * @RX_VHT_FLAG_80P80MHZ: 80+80 MHz was used
 * @RX_VHT_FLAG_160MHZ: 160 MHz was used
 * @RX_VHT_FLAG_BF: packet was beamformed
 */
enum mac80211_rx_vht_flags {
    RX_VHT_FLAG_80MHZ    = BIT(0),
    RX_VHT_FLAG_80P80MHZ = BIT(1),
    RX_VHT_FLAG_160MHZ   = BIT(2),
    RX_VHT_FLAG_BF       = BIT(3),
};

/**
 * struct ieee80211_rx_status - receive status
 *
 * The low-level driver should provide this information (the subset
 * supported by hardware) to the 802.11 code with each received
 * frame, in the skb's control buffer (cb).
 *
 * @mactime: value in microseconds of the 64-bit Time Synchronization Function
 *   (TSF) timer when the first data symbol (MPDU) arrived at the hardware.
 * @device_timestamp: arbitrary timestamp for the device, mac80211 doesn't use
 *  it but can store it and pass it back to the driver for synchronisation
 * @band: the active band when this frame was received
 * @freq: frequency the radio was tuned to when receiving this frame, in MHz
 * @signal: signal strength when receiving this frame, either in dBm, in dB or
 *  unspecified depending on the hardware capabilities flags
 *  @IEEE80211_HW_SIGNAL_*
 * @chains: bitmask of receive chains for which separate signal strength
 *  values were filled.
 * @chain_signal: per-chain signal strength, in dBm (unlike @signal, doesn't
 *  support dB or unspecified units)
 * @antenna: antenna used
 * @rate_idx: index of data rate into band's supported rates or MCS index if
 *  HT or VHT is used (%RX_FLAG_HT/%RX_FLAG_VHT)
 * @vht_nss: number of streams (VHT only)
 * @flag: %RX_FLAG_*
 * @vht_flag: %RX_VHT_FLAG_*
 * @rx_flags: internal RX flags for mac80211
 * @ampdu_reference: A-MPDU reference number, must be a different value for
 *  each A-MPDU but the same for each subframe within one A-MPDU
 * @ampdu_delimiter_crc: A-MPDU delimiter CRC
 */
struct ieee80211_rx_status {
    u64 mactime;
    u32 device_timestamp;
    u32 ampdu_reference;
    u32 flag;
    u16 freq;
    u8 vht_flag;
    u8 rate_idx;
    u8 vht_nss;
    u8 rx_flags;
    u8 band;
    u8 antenna;
    s8 signal;
    u8 chains;
    s8 chain_signal[IEEE80211_MAX_CHAINS];
    u8 ampdu_delimiter_crc;
};

/*
 * Extension part begins here
 */

/*
 * struct ieee80211_mgmt_ie -
 *      IEEE 802.11 management frame information element
 */
struct ieee80211_mgmt_ie {
    u8 eid;
    u8 len;
    union {
        u8 ssid[32];
        struct {
            u8 rates[8];
        } __attribute__((packed)) supp_rates;
        struct {
            u16 dwell;
            u8 hset;
            u8 hpattern;
            u8 hidx;
        } __attribute__((packed)) fh;
        struct {
            u8 chan;
        } __attribute__((packed)) ds;
        struct {
            u8 count;
            u8 interval;
            u16 max_duration;
            u16 remainder;
        } __attribute__((packed)) cf;
        struct {
            u16 atim_win;
        } __attribute__((packed)) ibss;
        struct {
            u8 dtim_count;
            u8 dtim_int;
            u8 bmp_mgmt;
            u8 pvbmp[251];
        } __attribute__((packed)) tim;
        struct {
            u8 country_code[3];
            u8 chan_idx;
            u8 chan;
            u8 max_power;
        } __attribute__((packed)) country;
        struct {
            u8 text[253];
        } __attribute__((packed)) challenge;
        struct {
            u8 local_limit;
        } __attribute__((packed)) pw_limit;
        struct {
            u8 mode;
            u8 new_chan_idx;
            u8 count;
        } __attribute__((packed)) chan_sw;
        struct {
            u8 count;
            u8 term;
            u16 duration;
            u16 offset;
        } __attribute__((packed)) quiet;
        struct {
            u8 flag;
        } __attribute__((packed)) erp_info;
        struct {
            u8 rates[255];
        } __attribute__((packed)) ext_supp_rates;
        struct {
            u8 cap[48];
            // Reserved fields follow the basic capability field.
        } __attribute__((packed)) ext_cap;
        struct {
            u8 interval;
        } __attribute__((packed)) tim_bcast_req;
        struct {
            u8 content[255];
        } __attribute__((packed)) vendor_spec;
    } u;
} __attribute__((packed, aligned(2)));


/*
 * ieee80211_is_broadcast - check if @da is the broadcast address
 * @da: Destination address included in IEEE 802.11 frame header.
 */
static inline int ieee80211_is_broadcast(const u8 *da) {
    const char bcaddr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return !memcmp(da, bcaddr, ETH_ALEN);
}


/*
 * ieee80211_is_qos - check if IEEE80211_STYPE_QOS_DATA
 * @fc: frame control bytes in little-endian byteoder
 */
static int ieee80211_is_qos(__le16 fc) {
    return ((fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
            cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA));
}


/*
 * ieee80211_is_qos_no_data - check if IEEE80211_STYPE_QOS_DATA && 0x0040
 * @fc: frame control bytes in little-endian byteoder
 *
 * This function returns true when @fc is a qos frame without data fields.
 */
static int ieee80211_is_qos_no_data(__le16 fc) {
    return ((fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
            cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | 0x0040));
}

#endif /* IEEE80211_EXTENSION_H */
