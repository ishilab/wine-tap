/*
 * genl.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>

#include <stddef.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <event.h>
#include <libconfig.h>
#include "checksum.h"

#include "utils.h"
#include "version.h"
#include "libworkqueue.h"
#include "ieee80211.h"
#include "ieee8022.h"
#include "common/ip.h"
#include "common/message.h"
#include "libtcpserv.h"
#include "libunserv.h"
#include "libwinetap.h"
#include "event_manager.h"
#include "config_manager.h"
#include "genetlink_connector.h"
#include "system_logger.h"
#include "netdevice_manager.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "genetlink"

#define DEFAULT_LISTEN_PORT 57209

#ifndef NL_ACT_MAX

enum {
    NL_ACT_UNSPEC,
    NL_ACT_NEW,
    NL_ACT_DEL,
    NL_ACT_GET,
    NL_ACT_SET,
    NL_ACT_CHANGE,
    __NL_ACT_MAX,
};

#define NL_ACT_MAX (__NL_ACT_MAX - 1)

#endif /* NL_ACT_MAX */

enum wtap_genl_cmds {
    WTAP_GENL_CMD_UNSPEC = 0,
    WTAP_GENL_CMD_CONFIG,
    WTAP_GENL_CMD_AUTH,
    WTAP_GENL_CMD_AUTH_ACK,
    WTAP_GENL_CMD_TX_FRAME,
    WTAP_GENL_CMD_RX_FRAME,
    WTAP_GENL_CMD_LOOPBACK,
    WTAP_GENL_CMD_SYNC_REQ,
    WTAP_GENL_CMD_SYNC_RESP,
    WTAP_GENL_CMD_GET_PROPERTY,
    WTAP_GENL_CMD_SET_PROPERTY,
    WTAP_GENL_CMD_UNSPEC_CONFIG,

    __WTAP_GENL_CMD_MAX,
};

#define WTAP_GENL_CMD_MAX (__WTAP_GENL_CMD_MAX - 1)

enum wtap_genl_attrs {
    WTAP_GENL_ATTR_UNSPEC = 0,
    WTAP_GENL_ATTR_AUTH_CHECKSUM,
    WTAP_GENL_ATTR_DOT_ELEVEN_FRAME,
    WTAP_GENL_ATTR_FCS,
    WTAP_GENL_ATTR_TX_INFO,
    WTAP_GENL_ATTR_RX_STATUS,
    WTAP_GENL_ATTR_FREQUENCY,
    WTAP_GENL_ATTR_CHANNEL,
    WTAP_GENL_ATTR_FLAGS,

    // WTAP_GENL_ATTR_BSS_INFO_CHANGED,
    // WTAP_GENL_ATTR_BSS_INFO_CONF,
    // WTAP_GENL_ATTR_CONFIG_FLAGS,
    // WTAP_GENL_ATTR_CONFIG,

    WTAP_GENL_ATTR_CONF_ADDR,
    WTAP_GENL_ATTR_CONF_TYPE,
    WTAP_GENL_ATTR_CONF_CHANGED,
    WTAP_GENL_ATTR_CONF_PARAM,

    WTAP_GENL_ATTR_ADDRLIST,

    __WTAP_GENL_ATTR_MAX
};

#define WTAP_GENL_ATTR_MAX (__WTAP_GENL_ATTR_MAX - 1)

enum {
    WTAP_MGMT_MSG_TYPE_BSS_INFO   = BIT(0),
    WTAP_MGMT_MSG_TYPE_RX_FILTER  = BIT(1),
    WTAP_MGMT_MSG_TYPE_TX_QUEUE   = BIT(2),
    WTAP_MGMT_MSG_TYPE_HW_CONF    = BIT(3),
    WTAP_MGMT_MSG_TYPE_TX_CONF    = BIT(4),
    WTAP_MGMT_MSG_TYPE_HW_START   = BIT(5),
    WTAP_MGMT_MSG_TYPE_HW_STOP    = BIT(6),
    WTAP_MGMT_MSG_TYPE_VIF_ADD    = BIT(7),
    WTAP_MGMT_MSG_TYPE_VIF_REMOVE = BIT(8),
};

enum {
    WTAP_FRAME_MSG_TYPE_FCS = BIT(0),
};

// In version 0.1, this container's format must be compatible with struct message
struct genetlink_connector_container {
    enum wtap_genl_cmds cmd;
    enum wtap_genl_attrs attr;
    uint32_t message_id;
    uint32_t len;

    union {
        struct {
            size_t length;
            uint32_t flags;
            uint32_t fcs;
            struct genl_info info;
            struct ieee80211_tx_info tx_info;
            struct ieee80211_channel channel;
        } tx_frame __attribute__((aligned(2),packed));

        struct {
            uint32_t type;
            uint32_t changed;
            size_t param_len;
            char hwaddr[ETH_ALEN];
        } config __attribute__((aligned(2),packed));

        struct {
            size_t length;
        } rx_frame __attribute__((aligned(2),packed));

        struct {
            size_t length;
        } auth_ack __attribute__((aligned(2),packed));
    } metadata;

    char data[0];
};

static struct genetlink_connector_struct {
    struct genl_family *family;
    struct nl_cache_mngr *mngr;
    struct nl_cache *cache;
    struct nl_sock *sock;
    struct nl_cb *cb;
    int fd;
    int family_id;
    int flags;
    int version;

    struct {
        char *addrs;
        size_t ndev;
    } info;

    struct {
        struct message_statistics_struct genl;
        struct message_statistics_struct ud;
        struct message_statistics_struct tcp;
    } stat;

    struct timeval timeout;

    struct nl_dump_params dump;

    // Old opmodes (deprecated)
    //bool enable_loopback;
    //bool enable_forwarding;
    //bool enable_simulation;
    //bool enable_force_genl_to_connect;
    bool enable_loopback;
    bool enable_tcp_forwarding;
    bool enable_local_forwarding;
    bool enable_force_to_connect;
    bool enable_netlink;

    bool enable_limit_log_output;

    // TCP connection information
    struct libtcpserv_struct *tcpserver;
    struct libtcpserv_client_struct *tcpclient;
    char tcp_dest_addr[IPADDR_LEN];
    int tcp_dest_port;
    bool is_another_host_connected;
    int listen_port;

    // Unix domain connection
    struct libwinetap_struct *unclient;
    bool is_simulator_connected;
    char dest_path[SUNPATH_LEN + 1];
    char src_path[SUNPATH_LEN + 1];
    struct message prev_msg;

    pthread_mutex_t mutex;

    struct libworkqueue_struct *workqueue;
} genl;

static pthread_t genl_pthreads;

static char* get_config_type_str(uint32_t type)
{
    switch (type) {
        case WTAP_MGMT_MSG_TYPE_BSS_INFO:
            return "BSS Information";
        case WTAP_MGMT_MSG_TYPE_RX_FILTER:
            return "RX Filter rules";
        case WTAP_MGMT_MSG_TYPE_TX_QUEUE:
            return "TX Queue";
        case WTAP_MGMT_MSG_TYPE_HW_CONF:
            return "HW Configuration";
        case WTAP_MGMT_MSG_TYPE_TX_CONF:
            return "TX Configuration";
        case WTAP_MGMT_MSG_TYPE_HW_START:
            return "HW Up";
        case WTAP_MGMT_MSG_TYPE_HW_STOP:
            return "HW Down";
        case WTAP_MGMT_MSG_TYPE_VIF_ADD:
            return "VIF Add";
        case WTAP_MGMT_MSG_TYPE_VIF_REMOVE:
            return "VIF Remove";
        default:
            return NULL;
    };
}

static char* get_frame_type_str(u16 fc)
{

    if (ieee80211_is_data(fc))
        return "Data";
    else if (ieee80211_is_data_qos(fc))
        return "Data QoS";
    else if (ieee80211_is_data_present(fc))
        return "Data present";
    else if (ieee80211_is_assoc_req(fc))
        return "Association request";
    else if (ieee80211_is_assoc_resp(fc))
        return "Association response";
    else if (ieee80211_is_reassoc_req(fc))
        return "Re-association request";
    else if (ieee80211_is_reassoc_resp(fc))
        return "Re-association response";
    else if (ieee80211_is_probe_req(fc))
        return "Probe request";
    else if (ieee80211_is_probe_resp(fc))
        return "Probe response";
    else if (ieee80211_is_beacon(fc))
        return "Beacon";
    else if (ieee80211_is_atim(fc))
        return "Announcement traffic indication message (ATIM)";
    else if (ieee80211_is_disassoc(fc))
        return "Disassociation";
    else if (ieee80211_is_auth(fc))
        return "Authentication";
    else if (ieee80211_is_deauth(fc))
        return "Deauthentication";
    else if (ieee80211_is_action(fc))
        return "Action";
    else if (ieee80211_is_action(fc))
        return "Action";
    else if (ieee80211_is_back_req(fc))
        return "Block ack request";
    else if (ieee80211_is_back(fc))
        return "Block ack";
    else if (ieee80211_is_pspoll(fc))
        return "PS-Poll";
    else if (ieee80211_is_rts(fc))
        return "RTS";
    else if (ieee80211_is_cts(fc))
        return "CTS";
    else if (ieee80211_is_ack(fc))
        return "ACK";
    else if (ieee80211_is_cfend(fc))
        return "CF-End";
    else if (ieee80211_is_cfendack(fc))
        return "CF-End and CF-Ack";
    else if (ieee80211_is_nullfunc(fc))
        return "Null func";
    else if (ieee80211_is_qos_nullfunc(fc))
        return "QoS null func";
    else
        return "Unknown";
}

static inline void genl_lock(void)
{
    pthread_mutex_lock(&genl.mutex);
}

static inline void genl_unlock(void)
{
    pthread_mutex_unlock(&genl.mutex);
}

static inline size_t container_len(size_t data_size)
{
    return ((sizeof(struct genetlink_connector_container) + data_size));
}

int genl_send_easy(int cmd, int flags)
{
    return genl_send_simple(genl.sock,
                genl.fd, cmd,genl.version, flags | NLM_F_REQUEST);
}

int wr_nl_send_sync(struct nl_msg *msg)
{
    return nl_send_sync(genl.sock, msg);
}

void print_nlmsg_header(const struct nlmsghdr *nlhdr)
{
#ifdef ENABLE_DEBUG

    print_log(MSG_DBG, "nlhdr: len: %u: type: %u: seq: %u: pid: %u\n",
            nlhdr->nlmsg_len, nlhdr->nlmsg_type, nlhdr->nlmsg_seq, nlhdr->nlmsg_pid);

#endif /* ENABLE_DEBUG */
}

void print_genlmsg_header(const struct nlmsghdr *nlhdr)
{
#ifdef ENABLE_DEBUG

    struct genlmsghdr *genlhdr = nlmsg_data(nlhdr);

    print_nlmsg_header(nlhdr);
    print_log(MSG_DBG, "glhdr: cmd: %u: version: %u\n",
            genlhdr->cmd, genlhdr->version);

#endif /* ENABLE_DEBUG */
}

void print_nlattr_entry(const struct nlattr **attrs)
{
#ifdef ENABLE_DEBUG

    int i;

    print_log(MSG_DBG, "nlattr entry: ");
    for (i = 0; i < WTAP_GENL_ATTR_MAX; ++i)
        fprintf(stderr, "%u ", ((attrs[i])? 1: 0));
    fprintf(stderr, "\n");

#endif /* ENABLE_DEBUG */
}

void print_frame_message(const struct nlmsghdr *nlhdr, const struct nlattr **attrs)
{
#ifdef ENABLE_DEBUG
    /*
     * print_mac_header_human(nla_data(attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]),
     *         nla_len(attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]));
     * print_mac_header_binary(nla_data(attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]),
     *         nla_len(attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]));
     * print_tx_info(nla_data(attrs[WTAP_GENL_ATTR_TX_INFO]), nla_data(attrs[WTAP_GENL_ATTR_CHANNEL]));
     */
#endif /* ENABLE_DEBUG */
}

static void log_ip_packet(const struct ieee80211_hdr *frame_hdr)
{
    char timestr[64] = {0};
    get_timestr_unix(timestr, ARRAY_SIZE(timestr));

    // Todo: Support IPv6
    if (ieee80211_is_data(frame_hdr->frame_control)) {
        struct ieee8022_hdr *llc_hdr = NULL;
        struct ipv4_hdr *ip_hdr = NULL;

        if (ieee80211_is_data_qos(frame_hdr->frame_control))
            llc_hdr = (struct ieee8022_hdr *) (
                    (char *) frame_hdr + sizeof(struct ieee80211_qos_hdr));
        else
            llc_hdr = (struct ieee8022_hdr *) (
                    (char *) frame_hdr + sizeof(struct ieee80211_hdr));

        ip_hdr = (struct ipv4_hdr *) ((char *) llc_hdr + sizeof(struct ieee8022_hdr));

        system_logger_printf(
                "[RecvDataPacket] "
                "llc: {dsap: 0x%02x, ssap: 0x%02x, ctrl: 0x%02x, oui: 0x%02x-%02x-%02x}, "
                "ip: {version: 0x%02x, ihl: 0x%02x, tos: 0x%02x, tot_len: 0x%04x, id: 0x%04x, flag: 0x%04x, ttl: 0x%02x, proto: 0x%02x, chksum: 0x%04x, saddr: 0x%08x, daddr: 0x%08x}\n",
                llc_hdr->dsap, llc_hdr->ssap, llc_hdr->ctrl,
                llc_hdr->oui[0], llc_hdr->oui[1], llc_hdr->oui[2],
                ip_hdr->version, ip_hdr->ihl, ip_hdr->tos, ip_hdr->tot_len,
                ip_hdr->id, ip_hdr->flag_off, ip_hdr->ttl, ip_hdr->proto, ip_hdr->checksum,
                ip_hdr->saddr, ip_hdr->daddr);
    }
}

static void log_message(const struct message *msg)
{
    // Todo: Support the other message types
    if (msg->message_type == MESSAGE_TYPE_ID_TX_FRAME) {
        const struct ieee80211_hdr *frame_hdr = (const struct ieee80211_hdr*)&msg->data;
        const struct ieee80211_tx_info *tx_info = &msg->header.tx_frame.tx_info;
        const struct ieee80211_channel *channel = &msg->header.tx_frame.channel;
        const size_t frame_len = msg->len;

        // Ignore beacon frames and data frames to reduce the output in log_limit mode.
        if (genl.enable_limit_log_output &&
                (ieee80211_is_beacon(frame_hdr->frame_control) ||
                 ieee80211_is_data(frame_hdr->frame_control))) {
            return ;
        }

        system_logger_printf(
                "[RecvFrameMessage] "
                "msgheader: {msg_len: %zu, frame_len: %zu bytes, flags: 0x%x, frame_fcs: 0x%08x}, "
                "tx_info: {band: %d, hw_queue: %d}, "
                "channel: {band: %d, center_freq: %d, max_power: %d}, "
                "frame: {fc: 0x%x (%s), duration_id: 0x%x, seq: 0x%x, "
                "addr1: " HWADDR_FMT ", addr2: " HWADDR_FMT ", addr3: " HWADDR_FMT ", "
                "fcs: 0x%08x}\n",
                message_len(msg), frame_len, msg->header.tx_frame.flags, msg->header.tx_frame.fcs,
                (int) tx_info->band, (int) tx_info->hw_queue,
                channel->band, (int) channel->center_freq, (int) channel->max_power,
                frame_hdr->frame_control, get_frame_type_str(frame_hdr->frame_control),
                frame_hdr->duration_id, frame_hdr->seq_ctrl,
                HWADDR_ARG(frame_hdr->addr1), HWADDR_ARG(frame_hdr->addr2), HWADDR_ARG(frame_hdr->addr3),
                *((uint32_t * )((char *) frame_hdr + (frame_len - sizeof(u32)))));

        log_ip_packet(frame_hdr);
    }
}

static int nlattr_put_auth_frame(struct nl_msg *msg, struct nlattr **attrs)
{
    declare_unused_variable(attrs);

    const char *keyword = "wtap80211";
    uint32_t checksum_crc32 = crc_32((const unsigned char*)keyword, strlen(keyword));
    uint32_t checksum_crc32_jamcrc = ~checksum_crc32;
    int err = 0;


    if ((err = nla_put(msg, WTAP_GENL_ATTR_AUTH_CHECKSUM,
                    sizeof(uint32_t), &checksum_crc32)) < 0)
        return err;

    print_log(MSG_DBG,
            "checksum: {crc32: 0x%X, crc32_jamcrc: 0x%X}\n",
            checksum_crc32, checksum_crc32_jamcrc);

    return 0;
}

static int nlattr_put_rx_frame(struct nl_msg *msg, struct nlattr **attrs)
{
    int err = 0;

    if (!attrs ||
            !attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME] ||
            !attrs[WTAP_GENL_ATTR_TX_INFO] ||
            !attrs[WTAP_GENL_ATTR_CHANNEL]) {
        return -NLE_IMMUTABLE;
    }

    if ((err = nla_put(msg, WTAP_GENL_ATTR_DOT_ELEVEN_FRAME,
            nla_len(attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]),
            nla_data(attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]))) < 0)
        return err;

    if ((err = nla_put(msg, WTAP_GENL_ATTR_TX_INFO,
            nla_len(attrs[WTAP_GENL_ATTR_TX_INFO]),
            nla_data(attrs[WTAP_GENL_ATTR_TX_INFO]))) < 0)
        return err;

    if ((err = nla_put(msg, WTAP_GENL_ATTR_CHANNEL,
            nla_len(attrs[WTAP_GENL_ATTR_CHANNEL]),
            nla_data(attrs[WTAP_GENL_ATTR_CHANNEL]))) < 0)
        return err;

    return 0;
}

static struct nl_msg* get_genlmsg_header(uint8_t cmd)
{
    struct nl_msg *msg = NULL;
    void *usr_hdr = NULL;

    if (!(msg = nlmsg_alloc()))
        return NULL;

    if (!(usr_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                        genl.family_id, 0, 0, cmd, genl.version))) {
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

static int genlmsg_unicast_custom(uint8_t cmd,
        int (*nlattr_func)(struct nl_msg *, struct nlattr **),
        struct nlattr **attrs)
{
    struct nl_msg *msg = NULL;
    void *usr_hdr = NULL;
    int err = 0, i;

    if (!(msg = nlmsg_alloc()))
        return -NLE_NOMEM;

    if (!(usr_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                        genl.family_id, 0, 0, cmd, genl.version))) {
        err = -NLE_NOMEM;
        goto out;
    }

    if (nlattr_func) {
        if ((err = nlattr_func(msg, attrs)) < 0)
            goto out;
    }

    /* print_genlmsg_header(nlmsg_hdr(msg)); */
    /* print_log(MSG_DBG, "genl: %p: genl.sock: %p: msg: %p\n", genl, genl.sock, msg); */

    if (!genl.sock) {
        print_log(MSG_CRIT, "genl.sock is null.\n");
        err = -NLE_BAD_SOCK;
        goto out;
    }

    err = nl_send_auto_complete(genl.sock, msg);

out:
    nlmsg_free(msg);
    return err;
}

static void cache_mngr_change_cb(struct nl_cache *cache,
                                 struct nl_object *obj,
                                 int action, void *data)
{
    struct nl_dump_params dump = {
        .dp_type = NL_DUMP_LINE,
    };

    switch (action) {
        case NL_ACT_NEW:
            break;
        case NL_ACT_DEL:
            break;
        case NL_ACT_CHANGE:
            break;
        default:
            break;
    }

    nl_object_dump(obj, &dump);
}

#define NLA_POLICY(_attr, _type, _minlen, _maxlen)  \
      [_attr] = { .type = (_type), .minlen = (_minlen), .maxlen = (_maxlen), }

#define NLA_POLICY_U32(_attr)  \
      [_attr] = { .type = NLA_U32, .minlen = sizeof(u32), .maxlen = sizeof(u32), }

static struct nla_policy nlattr_policy[WTAP_GENL_ATTR_MAX + 1] = {
    /* Reserved */
    NLA_POLICY(WTAP_GENL_ATTR_UNSPEC, NLA_UNSPEC, 0, 0),

    /* 802.11 frame */
    NLA_POLICY(WTAP_GENL_ATTR_DOT_ELEVEN_FRAME, NLA_UNSPEC, 0, IEEE80211_MAX_FRAME_LEN + 1),
    NLA_POLICY(WTAP_GENL_ATTR_TX_INFO,          NLA_UNSPEC, 0, sizeof(struct ieee80211_tx_info)),
    NLA_POLICY(WTAP_GENL_ATTR_RX_STATUS,        NLA_UNSPEC, 0, sizeof(struct ieee80211_rx_status)),

    /* Channel */
    NLA_POLICY(WTAP_GENL_ATTR_CHANNEL, NLA_NESTED, 0, sizeof(struct ieee80211_channel)),

    /* HW configuration */
    NLA_POLICY(WTAP_GENL_ATTR_CONF_ADDR, NLA_UNSPEC, 0, ETH_ALEN),
    NLA_POLICY_U32(WTAP_GENL_ATTR_CONF_TYPE),
    NLA_POLICY_U32(WTAP_GENL_ATTR_CONF_CHANGED),
    NLA_POLICY(WTAP_GENL_ATTR_CONF_PARAM, NLA_UNSPEC, 0, 128),

    /* Miscellaneous */
    NLA_POLICY(WTAP_GENL_ATTR_ADDRLIST, NLA_UNSPEC, 0, (ETH_ALEN << 10)),
};

static int nl_err_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg)
{
    struct genlmsghdr *genlhdr = nlmsg_data(&nlerr->msg);

    print_log(MSG_DBG, "cmd = %d, seq = %d, %s\n",
            genlhdr->cmd, nlerr->msg.nlmsg_seq, nl_geterror(abs(nlerr->error)));

    return NL_SKIP;
}

/*
 * nl_msg_err_chk(): Check if an incoming message is an error message
 *
 * Returns: 1 on valid message, 0 on an ack, or a nagative error code
 */
static int nl_msg_err_chk(struct nlmsghdr *nlhdr)
{
    struct nlmsgerr *nlerr = nlmsg_data(nlhdr);
    return (nlhdr->nlmsg_type == NLMSG_ERROR)? ((nlerr->error < 0)? nlerr->error: 0): 1;
}

static int nl_msg_recv_cb(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlhdr = nlmsg_hdr(msg);
    struct genlmsghdr *genlhdr = nlmsg_data(nlhdr);
    int err = 0;

    err = nl_msg_err_chk(nlhdr);
    if (err < 1) {
        genl_lock();
        genl.stat.genl.rx_error++;
        genl_unlock();
        return err;
    }

    switch (genlhdr->cmd) {
        case WTAP_GENL_CMD_TX_FRAME:
        case WTAP_GENL_CMD_CONFIG:
        case WTAP_GENL_CMD_AUTH_ACK:
            err = genl_handle_msg(msg, &genl);
            break;
        default:
            /* print_log(MSG_DBG, "[genetlink] unknown message (genlcmd = %d)\n", genlhdr->cmd); */
            nl_msg_dump(msg, stdout);
            genl_lock();
            genl.stat.genl.rx_error++;
            genl.stat.genl.unknown++;
            genl_unlock();
            err = 0;
            break;
    }

    /*
     * Do not call nlmsg_free() here because nlmsg_free() is called
     * when nl_msg_recv_cb() returned.
     */
    return err;
}

static void notify_bss_info(struct genetlink_connector_container *container)
{
    struct ieee80211_bss_conf *info = (struct ieee80211_bss_conf*)container->data;
    uint32_t changed = container->metadata.config.changed;

    system_logger_printf("BSS info changed (HWaddr: " HWADDR_FMT "):\n",
                         HWADDR_ARG(container->metadata.config.hwaddr));

    if (changed & BSS_CHANGED_ASSOC) {
        system_logger_printf("  ASSOC: assoc = %d, aid = %d\n", info->assoc, info->aid);
    }

    if (changed & BSS_CHANGED_ERP_CTS_PROT) {
        system_logger_printf("  ERP CTS Prot: %d\n", info->use_cts_prot);
    }

    if (changed & BSS_CHANGED_ERP_PREAMBLE) {
        system_logger_printf("  ERP Preamble: %d\n", info->use_short_preamble);
    }

    if (changed & BSS_CHANGED_ERP_SLOT) {
        system_logger_printf("  ERP Slot: %d\n", info->use_short_slot);
    }

    if (changed & BSS_CHANGED_HT) {
        system_logger_printf("  HT info: %#x => %#x\n", info->ht_operation_mode);
    }

    if (changed & BSS_CHANGED_BASIC_RATES) {
        system_logger_printf("  Basic rate: %u\n", info->basic_rates);
    }

    if (changed & BSS_CHANGED_BEACON_INT) {
        system_logger_printf("  Beacon interval: %u\n", info->beacon_int * 1024);
    }

    if (changed & BSS_CHANGED_BSSID) {
        system_logger_printf("  BSSID: " HWADDR_FMT "\n", info->bssid);
    }

    if (changed & BSS_CHANGED_BEACON) {
        system_logger_printf("  Beacon info:\n");
    }

    if (changed & BSS_CHANGED_BEACON_ENABLED) {
        system_logger_printf("  Beaconing: %s\n", ((info->enable_beacon)? "enabled": "disabled"));
    }

    if (changed & BSS_CHANGED_CQM) {
        system_logger_printf("  CQM: RSSI thold %d\n", info->cqm_rssi_thold);
        system_logger_printf("       RSSI hysteresis %d\n", info->cqm_rssi_hyst);
    }

    if ((changed & BSS_CHANGED_IBSS) || (changed & BSS_CHANGED_OCB)) {
        system_logger_printf("  IBSS: %s, %s\n",
                 ((info->ibss_joined)? "joind": "left"),
                 ((info->ibss_creator)? "(new IBSS created)": ""));
    }

    if (changed & BSS_CHANGED_ARP_FILTER) {
        system_logger_printf("  ARP Filter:\n");
    }

    if (changed & BSS_CHANGED_QOS) {
        system_logger_printf("  QoS: %s\n", ((info->qos)? "enabled": "disabled"));
    }

    if (changed & BSS_CHANGED_IDLE) {
        system_logger_printf("  NIC status: %s\n", ((info->idle)? "idle": "active"));
    }

    if (changed & BSS_CHANGED_SSID) {
        system_logger_printf("  SSID: " HWADDR_FMT "(%s)\n",
                 info->ssid, (info->hidden_ssid)? "visible": "unvisible");
    }

    if (changed & BSS_CHANGED_AP_PROBE_RESP) {
        system_logger_printf("  AP probe response:\n");
    }

    if (changed & BSS_CHANGED_PS) {
        system_logger_printf("  Power saving status changed: %d\n", info->ps);
    }

    if (changed & BSS_CHANGED_TXPOWER) {
        system_logger_printf("  TX power changed: %d [dBm]\n", info->txpower);
    }

    if (changed & BSS_CHANGED_P2P_PS) {
        system_logger_printf("  P2P power savings changed:\n");
    }

    if (changed & BSS_CHANGED_BEACON_INFO) {
        system_logger_printf("  Beacon info: dtim period %d\n", info->dtim_period);
    }
}

static void notify_tx_queue_change(struct genetlink_connector_container *container)
{
    struct ieee80211_tx_queue_params *params = (struct ieee80211_tx_queue_params*)container->data;
    system_logger_printf("TX queue parameters changed:\n");
    system_logger_printf("  queue = %d, txop = %d, cw_min = %d, cw_max = %d, aifs = %d\n",
                         container->metadata.config.changed,
                         params->txop, params->cw_min, params->cw_max, params->aifs);
}

static void notify_hw_config(struct genetlink_connector_container* container)
{
    struct ieee80211_conf *conf = (struct ieee80211_conf*)container->data;
    uint32_t changed = container->metadata.config.changed;

    system_logger_printf("HWconfig changed (HWaddr = " HWADDR_FMT ") %s\n",
             HWADDR_ARG(container->metadata.config.hwaddr),
             ((changed & IEEE80211_CONF_CHANGE_CHANNEL)? "(channel changed)": ""));
    system_logger_printf("  idle = %d, ps = %d, smps = %d\n",
                         !!(conf->flags & IEEE80211_CONF_IDLE),
                         !!(conf->flags & IEEE80211_CONF_PS),
                         conf->smps_mode);
    system_logger_printf("  TX power %d [dBm]", conf->power_level);
}

static void notify_hw_start(struct genetlink_connector_container* container)
{
    system_logger_printf("HWaddr = " HWADDR_FMT " started\n",
                         HWADDR_ARG(container->metadata.config.hwaddr));
}

static void notify_hw_stop(struct genetlink_connector_container* container)
{
    system_logger_printf("HWaddr = " HWADDR_FMT " stopped\n",
                         HWADDR_ARG(container->metadata.config.hwaddr));
}

static void notify_add_interface(struct genetlink_connector_container* container)
{
    system_logger_printf("new vif added (addr = " HWADDR_FMT ")\n",
                         HWADDR_ARG(container->metadata.config.hwaddr));
}

static void notify_remove_interface(struct genetlink_connector_container* container)
{
    system_logger_printf("vif removed (addr = " HWADDR_FMT ")\n",
                         HWADDR_ARG(container->metadata.config.hwaddr));
}

static void* do_notify_changed_config(void *arg)
{
    struct genetlink_connector_container *container =
        (struct genetlink_connector_container*)arg;

    system_logger_printf(
            "msg: config, "
            "hwaddr: " HWADDR_FMT ", type: 0x%x (%s), changed: 0x%x, param_len: %zu\n",
            HWADDR_ARG(container->metadata.config.hwaddr),
            container->metadata.config.type,
            get_config_type_str(container->metadata.config.type),
            container->metadata.config.changed,
            container->metadata.config.param_len);

    switch(container->metadata.config.type) {
        case WTAP_MGMT_MSG_TYPE_TX_QUEUE:
            notify_tx_queue_change(container);
            break;
        case WTAP_MGMT_MSG_TYPE_BSS_INFO:
            notify_bss_info(container);
            break;
        case WTAP_MGMT_MSG_TYPE_HW_CONF:
            notify_hw_config(container);
            break;
        case WTAP_MGMT_MSG_TYPE_HW_START:
            notify_hw_start(container);
            break;
        case WTAP_MGMT_MSG_TYPE_HW_STOP:
            notify_hw_stop(container);
            break;
        case WTAP_MGMT_MSG_TYPE_VIF_ADD:
            notify_add_interface(container);
            break;
        case WTAP_MGMT_MSG_TYPE_VIF_REMOVE:
            notify_remove_interface(container);
            break;
        case WTAP_MGMT_MSG_TYPE_RX_FILTER:
        case WTAP_MGMT_MSG_TYPE_TX_CONF:
            break;
    }

    gc_free(arg);

    return NULL;
}

static int parse_cmd_config(struct nl_cache_ops *ops, struct genl_cmd *cmd,
                            struct genl_info *info, void *arg)
{
    struct nlattr *attrs[WTAP_GENL_ATTR_MAX + 1] = {0};
    int err = 0;

    declare_unused_variable(ops);

    system_logger_printf(
            "genlmsg_id: %d: name: %s: maxattr: %d: parser: %p (%p): policy: %p (%p)\n",
            cmd->c_id, cmd->c_name, cmd->c_maxattr, cmd->c_msg_parser,
            parse_cmd_config, cmd->c_attr_policy, nlattr_policy);

    if (info->attrs[WTAP_GENL_ATTR_CONF_ADDR]
            && info->attrs[WTAP_GENL_ATTR_CONF_TYPE]
            && info->attrs[WTAP_GENL_ATTR_CONF_CHANGED]
            && info->attrs[WTAP_GENL_ATTR_CONF_PARAM]) {
        struct genetlink_connector_container *container = NULL;
        size_t len = nla_len(info->attrs[WTAP_GENL_ATTR_CONF_PARAM]);

        container = (struct genetlink_connector_container*)gc_calloc(1,
                            sizeof(struct genetlink_connector_container) + len);

        if (container) {
            memcpy(&container->metadata.config.hwaddr,
                    nla_data(info->attrs[WTAP_GENL_ATTR_CONF_ADDR]),
                    sizeof(container->metadata.config.hwaddr));
            memcpy(&container->metadata.config.type,
                    nla_data(info->attrs[WTAP_GENL_ATTR_CONF_TYPE]),
                    sizeof(container->metadata.config.type));
            memcpy(&container->metadata.config.changed,
                    nla_data(info->attrs[WTAP_GENL_ATTR_CONF_CHANGED]),
                    sizeof(container->metadata.config.changed));
            memcpy(&container->data,
                    nla_data(info->attrs[WTAP_GENL_ATTR_CONF_PARAM]),
                    nla_len(info->attrs[WTAP_GENL_ATTR_CONF_PARAM]));

            libworkqueue_enqueue_task(genl.workqueue,
                    NULL, do_notify_changed_config, container);
        }
    } else {
        system_logger_printf("[genetlink] [InvalidMessage] Invalid config message received.\n");
    }

    if (info->attrs[WTAP_GENL_ATTR_FLAGS]) {
        /* This message is currently unavailable because of old attribute rule. */
    }

    if (info->attrs[WTAP_GENL_ATTR_FREQUENCY]) {
        /* This message is currently unavailable because of old attribute rule. */
    }

    if (info->attrs[WTAP_GENL_ATTR_CHANNEL]) {
        /* This message is currently unavailable because of old attribute rule. */
    }

    return 0;
}

static void ev_cb_recv_genlmsg(int fd, short flags, void *arg)
{
    nl_recvmsgs_default(genl.sock);
}

static int parse_cmd_auth_ack(struct nl_cache_ops *ops, struct genl_cmd *cmd,
                              struct genl_info *info, void *arg)
{
    struct nlattr *attrs[WTAP_GENL_ATTR_MAX + 1] = {0};
    int err = 0;

    declare_unused_variable(ops);

    if (info->attrs[WTAP_GENL_ATTR_ADDRLIST]) {
        char *addrlist = (char*)nla_data(info->attrs[WTAP_GENL_ATTR_ADDRLIST]);
        int n = nla_len(info->attrs[WTAP_GENL_ATTR_ADDRLIST]) / ETH_ALEN;
        char *__addrlist = (char*)gc_calloc(n, ETH_ALEN);

        print_log(MSG_DBG, "%u virtual device(s) available.\n", n);

        memcpy(__addrlist, addrlist, n * ETH_ALEN);

        genl.info.addrs = __addrlist;
        genl.info.ndev = n;
    }

    // Network device manager will be deprecated.
    // if (genl.flags & (GENL_STATE_STANDBY | GENL_STATE_AUTH_REQUIRED)) {
    //     genl.flags &= !(GENL_STATE_STANDBY | GENL_STATE_AUTH_REQUIRED);
    //     genl.flags |= GENL_STATE_READY;

    //     /* workq_enqueue(do_netdev_add_multiple_devices, NULL); */
    //     /* workq_enqueue(do_netdev_add_multiple_external_interfaces, NULL); */
    //     libworkqueue_enqueue_task(genl.workqueue,
    //             NULL, do_netdev_add_multiple_external_interfaces, NULL);

    //     print_log(MSG_DBG, "setting up tap interfaces.\n");
    // }

    return 0;
}

/* Todo: support multiple container types */
__attribute__((unused))
static void* do_forward_genlmsg(void *arg)
{
    struct genetlink_connector_container *container =
        (struct genetlink_connector_container*)arg;
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr*)container->data;

    libtcpserv_send_with_header(genl.tcpclient, container,
            container_len(container->metadata.tx_frame.length), 0);

    gc_free(arg);

    return NULL;
}

static void* do_connect_another_daemon(void *arg)
{
    struct libtcpserv_config_struct config = {
        .port = genl.tcp_dest_port,
        .family = AF_INET,
    };

    genl_lock();
    genl.is_another_host_connected = false;
    genl_unlock();

    memcpy(config.dest_addr, genl.tcp_dest_addr, strlen(genl.tcp_dest_addr));

    if (!(genl.tcpclient = libtcpserv_connect(&config))) {
        sleep_pthread(3, 0, NULL, NULL);
        libworkqueue_enqueue_task(genl.workqueue,
                NULL, do_connect_another_daemon, NULL);

        print_log(MSG_DBG, "%s:%d is unreachable. Retrying to connect...\n",
                genl.tcp_dest_addr, genl.tcp_dest_port);
    } else {
        genl_lock();
        genl.is_another_host_connected = true;
        genl_unlock();

        print_log(MSG_DBG,
                  "connected to another daemon (addr:%s, port: %d)\n",
                  config.dest_addr, config.port);
    }

    return NULL;
}

// __attribute__((unused))
// static void* do_connect_local_server(void *arg)
// {
//     struct libwinetap_config_struct config = {
//         .do_recv_handler = NULL,
//         .arg = NULL,
//         .src_path = "/var/tmp/libwinetap.sock",
//         .dest_path = "/var/tmp/scenargie.sock"
//     };
//
//     if (!(genl.unclient = libwinetap_new(&config))) {
//         genl.is_simulator_connected = false;
//         sleep(1);
//         libworkqueue_enqueue_task(genl.workqueue,
//                 NULL, do_connect_local_server, NULL);
//     } else {
//         genl.is_simulator_connected = true;
//         print_log(MSG_DBG, "[genetlink] Connected to the destination server (sunpath: %s)\n",
//                   genl.dest_path);
//     }
//
//     return NULL;
// }

static void* do_notify_frame_message(void *arg)
{
    //struct genetlink_connector_container *container = (struct genetlink_connector_container*)arg;
    struct message *msg = (struct message*)arg;
    int err;

    if (genl.enable_tcp_forwarding && genl.is_another_host_connected) {
        if ((err = libtcpserv_send_with_header(genl.tcpclient, msg, message_len(msg), 0)) < 0) {
            print_log(MSG_ERR, "Cannot send a message (reson: %s, code: %d)\n", strerror(errno), errno);

            genl_lock();
            genl.stat.tcp.tx_error++;
            genl_unlock();
        } else {
            log_message(msg);

            genl_lock();
            genl.stat.tcp.transmitted++;
            genl_unlock();
        }
    }

    gc_free(arg);

    return NULL;
}

static int parse_cmd_tx_frame(struct nl_cache_ops *ops, struct genl_cmd *cmd,
                              struct genl_info *info, void *arg)
{
    struct nlattr *attrs[WTAP_GENL_ATTR_MAX + 1];
    int err, i;

    declare_unused_variable(ops);

    // char timestr[64] = {0};
    // get_timestr_unix(timestr, ARRAY_SIZE(timestr));
    // system_logger_printf(
    //         "[%s]: [genetlink] [RecvMessage] {id: %d, name: %s, maxattr: %d, parser: %p (original: %p), policy: %p (original: %p)}\n",
    //         timestr,
    //         cmd->c_id, cmd->c_name, cmd->c_maxattr, cmd->c_msg_parser,
    //         parse_cmd_tx_frame, cmd->c_attr_policy, nlattr_policy);

    genl_lock();
    genl.stat.genl.received++;
    genl_unlock();


    if (info->nlh->nlmsg_len <= GENL_HDRLEN) {
        print_log(MSG_DBG, "Message is too short (%u <= %zu).\n", info->nlh->nlmsg_len, GENL_HDRLEN);
        print_genlmsg_header(info->nlh);

        genl_lock();
        genl.stat.genl.rx_error++;
        genl_unlock();

        return -NLE_MSGSIZE;
    }

    if (info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]
            && info->attrs[WTAP_GENL_ATTR_TX_INFO]
            && info->attrs[WTAP_GENL_ATTR_CHANNEL]
            && info->attrs[WTAP_GENL_ATTR_FLAGS]
            && info->attrs[WTAP_GENL_ATTR_FCS]) {

        /* Queue a genl message for transmission to netlink */
        /* if (genl.enable_loopback || (genl.enable_forwarding && genl.is_another_host_connected)) { */
        if (genl.enable_loopback) {
            if ((err = genlmsg_unicast_custom(WTAP_GENL_CMD_RX_FRAME, nlattr_put_rx_frame, info->attrs)) < 0) {
                print_log(MSG_ERR, "%s\n", nl_geterror(err));
                genl_lock();
                genl.stat.genl.tx_error++;
                genl_unlock();
                return err;
            } else {
                genl_lock();
                genl.stat.genl.transmitted++;
                genl_unlock();
            }
        } else {
            struct message *msg = get_frame_message(info,
                    nla_data(info->attrs[WTAP_GENL_ATTR_TX_INFO]),
                    nla_data(info->attrs[WTAP_GENL_ATTR_CHANNEL]),
                    *((uint32_t*)nla_data(info->attrs[WTAP_GENL_ATTR_FLAGS])),
                    nla_data(info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]),
                    nla_len(info->attrs[WTAP_GENL_ATTR_DOT_ELEVEN_FRAME]),
                    *((uint32_t*)nla_data(info->attrs[WTAP_GENL_ATTR_FCS])));

            if (!msg) {
                // Error
                genl_lock();
                genl.stat.ud.tx_error++;
                genl_unlock();
                return -ENOMEM;
            }

            if (genl.enable_tcp_forwarding && genl.is_another_host_connected) {
                libworkqueue_enqueue_task(genl.workqueue, NULL, do_notify_frame_message, msg);
            }
            else if (genl.enable_local_forwarding && genl.is_simulator_connected) {
                int rc = libwinetap_send(genl.unclient, msg, message_len(msg));

                if (rc < 0) {
                    print_log(MSG_DBG, "Could not send a message via local domain socket (rc: %d)\n", rc);

                    genl_lock();
                    genl.stat.ud.tx_error++;
                    genl_unlock();
                } else {
                    // print_message(msg, "forwarding: daemon -- netlink --> wtap80211");
                    genl_lock();
                    genl.stat.ud.transmitted++;
                    genl_unlock();
                }
            }
        }
    } else {
        // Attributes are invalid.
        genl_lock();
        genl.stat.genl.rx_error++;
        genl_unlock();
    }

    return 0;
}

static int parse_cmd_rx_frame(struct nl_cache_ops *ops, struct genl_cmd *cmd,
                              struct genl_info *info, void *arg)
{
    struct nlattr *attrs[WTAP_GENL_ATTR_MAX + 1] = {0};
    int err = 0;

    print_log(MSG_DBG, "Received a rx frame message.\n");

    return 0;
}

static int parse_cmd_get_property(struct nl_cache_ops *ops, struct genl_cmd *cmd,
                                  struct genl_info *info, void *arg)
{
    struct nlattr *attrs[WTAP_GENL_ATTR_MAX + 1] = {0};
    int err = 0;

    print_log(MSG_DBG, "Received a property message.\n");

    return 0;
}

static int parse_cmd_set_property(struct nl_cache_ops *ops, struct genl_cmd *cmd,
                                  struct genl_info *info, void *arg)
{
    struct nlattr *attrs[WTAP_GENL_ATTR_MAX + 1] = {0};
    int err = 0;

    return 0;
}

static void* tcp_server_handler(int sock, void *arg)
{
    static uuid_t prevmsg_id = {0};
    struct libtcpserv_msghdr *hdr = NULL;
    uint32_t len = 0;
    int err = 0;

    print_log(MSG_DBG, "tcp server handler launched.\n");

    if (!(hdr = (struct libtcpserv_msghdr*)gc_malloc(LIBTCPSERV_PAYLOAD_LENGTH_DEFAULT)))
        goto error;

    while (1) {
        if (libtcpserv_recv_all(sock, hdr, sizeof(struct libtcpserv_msghdr)) < 1)
            goto error;

        if (hdr->len > len) {
            struct libtcpserv_msghdr *realloc_hdr;
            if (!(realloc_hdr = (struct libtcpserv_msghdr *) gc_realloc(hdr,
                    sizeof(struct libtcpserv_msghdr) + hdr->len)))
                goto error;

            if (realloc_hdr != hdr)
                hdr = realloc_hdr;

            len = hdr->len;
        }

        if (libtcpserv_recv_all(sock, libtcpserv_data(hdr), hdr->len) < 1)
            goto error;

        // struct genetlink_connector_container *container = (struct genetlink_connector_container *) hdr->data;
        const struct message *msg = (const struct message*)hdr->data;

        // if (!uuid_compare(prevmsg_id, msg->message_id)) {
        //     uuid_copy(prevmsg_id, msg->message_id);
        //
        //     memset(hdr, 0, sizeof(struct libtcpserv_msghdr) + len);
        //     continue;
        // }

        genl_lock();
        genl.stat.tcp.received++;
        genl_unlock();

        if (genl.enable_local_forwarding && genl.is_another_host_connected) {
            int err = libwinetap_send(genl.unclient, msg, message_len(msg));
            genl_lock();
            if (err < 0)
                genl.stat.ud.tx_error++;
            else
                genl.stat.ud.transmitted++;
            genl_unlock();
        }
        else {
            // Forward the incoming message to wtap80211 via genl.

            struct nl_msg *nlmsg = NULL;

            if (!(nlmsg = get_genlmsg_header(WTAP_GENL_CMD_RX_FRAME))) {
                print_log(MSG_DBG, "Cannot allocate genlmsg buffer.\n");
                genl_lock();
                genl.stat.genl.tx_error++;
                genl_unlock();
                continue;
            }

            if ((nla_put(nlmsg, WTAP_GENL_ATTR_DOT_ELEVEN_FRAME, msg->len, msg->data) < 0)
                || (nla_put(nlmsg, WTAP_GENL_ATTR_FCS, sizeof(uint32_t), &msg->header.tx_frame.fcs) < 0)
                || (nla_put(nlmsg, WTAP_GENL_ATTR_FLAGS, sizeof(uint32_t), &msg->header.tx_frame.flags) < 0)
                || (nla_put(nlmsg, WTAP_GENL_ATTR_TX_INFO, sizeof(struct ieee80211_tx_info), &msg->header.tx_frame.tx_info) < 0)
                || (nla_put(nlmsg, WTAP_GENL_ATTR_CHANNEL, sizeof(struct ieee80211_channel), &msg->header.tx_frame.channel) < 0))
            {
                genl_lock();
                genl.stat.genl.tx_error++;
                genl_unlock();

                nlmsg_free(nlmsg);
                continue;
            }

            if (!genl.sock) {
                // print_log(MSG_CRIT, "genl.sock is null.\n");
                err = -NLE_BAD_SOCK;

                genl_lock();
                genl.stat.genl.tx_error++;
                genl_unlock();
            } else {
                if ((err = nl_send_auto_complete(genl.sock, nlmsg)) < 0) {
                    print_log(MSG_DBG, "Cannot send a genlmsg (reason: %s, code: %d)\n", nl_geterror(err), err);
                    genl_lock();
                    genl.stat.genl.tx_error++;
                    genl_unlock();
                } else {
                    genl_lock();
                    genl.stat.genl.transmitted++;
                    genl_unlock();
                }

                /* nl_msg_dump(msg, stderr); */
            }

            nlmsg_free(nlmsg);
        }

        // uuid_copy(prevmsg_id, msg->message_id);
        memset(hdr, 0, sizeof(struct libtcpserv_msghdr) + len);
    }

error:
    print_log(MSG_DBG, "Socket is closed (reason: %s, code: %d)\n", strerror(errno), errno);
    gc_free(hdr);
    return NULL;
}

#define GENL_CMD(__id, __name, __maxattr, __attr_policy, __msg_parser)  \
    {                                                                   \
        .c_id = __id,                                                   \
        .c_name = __name,                                               \
        .c_maxattr = __maxattr,                                         \
        .c_attr_policy = __attr_policy,                                 \
        .c_msg_parser = __msg_parser,                                   \
    }

static struct genl_cmd cmds[] = {
    GENL_CMD(WTAP_GENL_CMD_CONFIG,       "config",       WTAP_GENL_ATTR_MAX, nlattr_policy, &parse_cmd_config),
    GENL_CMD(WTAP_GENL_CMD_AUTH_ACK,     "auth_ack",     WTAP_GENL_ATTR_MAX, nlattr_policy, &parse_cmd_auth_ack),
    GENL_CMD(WTAP_GENL_CMD_TX_FRAME,     "tx_frame",     WTAP_GENL_ATTR_MAX, nlattr_policy, &parse_cmd_tx_frame),
    GENL_CMD(WTAP_GENL_CMD_RX_FRAME,     "rx_frame",     WTAP_GENL_ATTR_MAX, nlattr_policy, &parse_cmd_rx_frame),
    GENL_CMD(WTAP_GENL_CMD_GET_PROPERTY, "get_property", WTAP_GENL_ATTR_MAX, nlattr_policy, &parse_cmd_get_property),
    GENL_CMD(WTAP_GENL_CMD_SET_PROPERTY, "set_property", WTAP_GENL_ATTR_MAX, nlattr_policy, &parse_cmd_set_property),
};

static struct genl_ops ops = {
    .o_name = WTAP80211_GENL_NAME,
    .o_cmds = cmds,
    .o_ncmds = ARRAY_SIZE(cmds),
};

static struct nl_sock* genl_c_sock_init(void)
{
    struct nl_sock *c_sock = NULL;
    int err = 0;

    if ((c_sock = nl_socket_alloc()) == NULL)
        return NULL;

    if ((err = genl_connect(c_sock)) < 0)
        return NULL;

    return c_sock;
}

static int genl_cache_init(void)
{
    int err = 0;

    /*
     * Allocate cache and bind it to the Netlink socket
     *
     * This cache will contain a list of all currently registered kernel side Generic Netlink families.
     * The cache will be used to resolve family names locally.
     */
    if ((err = genl_ctrl_alloc_cache(genl.sock, &genl.cache)) < 0)
        goto error;

    /* Enable the cache system */
    /*
     * err = nl_cache_mngr_alloc(NULL, NETLINK_GENERIC, NL_AUTO_PROVIDE, &genl.mngr);
     * if (err < 0 || genl.mngr == NULL)
     *     return err;
     */

    /*
     * err = nl_cache_mngr_add(genl.mngr, "genl/family", &cache_mngr_change_cb, NULL, &genl.cache);
     * if (err < 0)
     *     return err;
     */

error:
    return err;
}

int genl_send_auth_request(void)
{
    return genlmsg_unicast_custom(WTAP_GENL_CMD_AUTH, NULL, NULL);
}

size_t genl_get_ndev(void)
{
    size_t ret;

    pthread_mutex_lock(&genl.mutex);
    ret = genl.info.ndev;
    pthread_mutex_unlock(&genl.mutex);

    return ret;
}

__attribute__((malloc))
char* genl_get_addrs(void)
{
    size_t len = genl.info.ndev * ETH_ALEN;
    char *ret = gc_calloc(1, len);

    if (!ret)
        return NULL;

    pthread_mutex_lock(&genl.mutex);
    memmove(ret, genl.info.addrs, len);
    pthread_mutex_unlock(&genl.mutex);

    return ret;
}

int genl_is_ready(void)
{
    genl_lock();
    int flags = genl.flags;
    genl_unlock();
    return !!(flags & GENL_STATE_READY);
}

// Receive handler of the local socket
static void* do_recv_handler(void *arg)
{
    struct libwinetap_recv_handler_container *container =
            (struct libwinetap_recv_handler_container*)arg;

    genl_lock();
    genl.stat.ud.received++;
    genl_unlock();

    if (genl.enable_tcp_forwarding && genl.is_another_host_connected) {
        // Debug
        // print_message(container->msg, "forwarding: daemon -- tcp --> daemon");

        // If the current and previous message are different, transmit the current one.
        // const struct message *recv_msg = container->msg;
        // if (!compare_message(recv_msg, &genl.prev_msg)) {
        //     libtcpserv_send_with_header(genl.tcpclient,
        //         container->msg, message_len(container->msg), 0);

        //     genl_lock();
        //     memcpy(&genl.prev_msg, recv_msg, sizeof(genl.prev_msg));
        //     genl_unlock();
        // } else {
        //     genl.stat.duplicated++;
        // }
        if (libtcpserv_send_with_header(genl.tcpclient, container->msg,
                message_len(container->msg), 0) < 0) {
            genl_lock();
            genl.stat.tcp.tx_error++;
            genl_unlock();
        } else {
            genl_lock();
            genl.stat.tcp.transmitted++;
            genl_unlock();
        }
    }

    libwinetap_free_recv_handler_container(container);

    return NULL;
}

static void parse_config(void)
{
    // Memo: Operation modes were updated from .
    // There is no compatibility between old and new ones except for loopback mode.

    // Old name is enable_loopback
    if (config_search_entry_int("enable_loopback",
            (int*)(&genl.enable_loopback)) == CONFIG_FALSE)
        genl.enable_loopback = true;

    // Old name is enable_forwarding
    if (config_search_entry_int("enable_tcp_forwarding",
            (int*)(&genl.enable_tcp_forwarding)) == CONFIG_FALSE)
        genl.enable_tcp_forwarding = false;

    // Old name is enable_simulation
    if (config_search_entry_int("enable_local_forwarding",
            (int*)(&genl.enable_local_forwarding)) == CONFIG_FALSE)
        genl.enable_local_forwarding = false;

    // Old name is enable_force_genl_to_connect
    if (config_search_entry_int("enable_force_to_connect",
            (int*)(&genl.enable_force_to_connect)) == CONFIG_FALSE)
        genl.enable_force_to_connect = false;

    if (genl.enable_loopback) {
        genl.enable_tcp_forwarding = false;
        genl.enable_local_forwarding = false;
    }

    if (genl.enable_tcp_forwarding) {
        const char *dest_addr;
        if (config_search_entry_string("another_daemon_address", &dest_addr) == CONFIG_FALSE)
            memcpy(genl.tcp_dest_addr, "127.0.0.1", strlen("127.0.0.1"));
        else
            memcpy(genl.tcp_dest_addr, dest_addr, strlen(dest_addr));

        if (config_search_entry_int("another_daemon_port", &genl.tcp_dest_port) == CONFIG_FALSE)
            genl.tcp_dest_port = DEFAULT_LISTEN_PORT;

        if (config_search_entry_int("listen_port", &genl.listen_port) == CONFIG_FALSE)
            genl.listen_port = DEFAULT_LISTEN_PORT;

        print_log(MSG_DBG, "tcp server listen port: %d, tcp client destination: %s:%d\n",
                genl.listen_port, genl.tcp_dest_addr, genl.tcp_dest_port);
    }

    if (genl.enable_local_forwarding) {
        const char *dest_path;
        const char *src_path;
        memset(genl.dest_path, 0, ARRAY_SIZE(genl.dest_path));
        memset(genl.src_path, 0, ARRAY_SIZE(genl.src_path));

        if (config_search_entry_string("destination_sunpath", &dest_path) == CONFIG_FALSE)
            memcpy(genl.dest_path, "/var/tmp/libwinetap_in.sock", strlen("/var/tmp/libwinetap_in.sock"));
        else
            memcpy(genl.dest_path, dest_path, min(SUNPATH_LEN, strlen(dest_path) + 1));

        if (config_search_entry_string("source_sunpath", &src_path) == CONFIG_FALSE)
            memcpy(genl.src_path, "/var/tmp/libwinetap_out.sock", strlen("/var/tmp/libwinetap_out.sock"));
        else
            memcpy(genl.src_path, src_path, min(SUNPATH_LEN, strlen(src_path) + 1));

        print_log(MSG_DBG, "Local server dest_sunpath: %s, src_sunpath: %s\n", genl.dest_path, genl.src_path);
    }

    genl.enable_netlink =
            (genl.enable_force_to_connect || !(genl.enable_tcp_forwarding && genl.enable_local_forwarding));

    print_log(MSG_DBG,
            "netlink: %s, loopback: %s, tcp forwarding: %s, local forwarding: %s, force_to_connect: %s\n",
            (genl.enable_netlink) ? "active" : "inactive",
            (genl.enable_loopback) ? "enable" : "disable",
            (genl.enable_tcp_forwarding) ? "enable" : "disable",
            (genl.enable_local_forwarding) ? "enable" : "disable",
            (genl.enable_force_to_connect) ? "enable" : "disable");
}

int genetlink_connector_init(const char *gf_name)
{
    struct nl_sock *c_sock = NULL;
    int err = 0;

    memset(&genl, 0, sizeof(struct genetlink_connector_struct));

    parse_config();

    pthread_mutex_init(&genl.mutex, NULL);

    if (!(genl.workqueue = libworkqueue_new()))
        return -ENOMEM;

    if (genl.enable_netlink) {
        print_log(MSG_NOTICE, "Connecting to the netlink ...\n");
        if ((c_sock = genl_c_sock_init()) == NULL) {
            err = -NLE_NOMEM;
            goto error;
        }

        /* Allocate a new callback handle */
        if (!(genl.cb = nl_cb_alloc(NL_CB_CUSTOM)))
            return -NLE_NOMEM;

        print_log(MSG_DBG, "Initializing a Netlink socket ... \n");
        if ((genl.sock = nl_socket_alloc_cb(genl.cb)) == NULL) {
            err = -NLE_NOMEM;
            goto error;
        }

        print_log(MSG_DBG, "Connecting to the Netlink core module ...\n");
        if ((err = genl_connect(genl.sock)) < 0)
            goto error_socket;

        print_log(MSG_DBG, "Initializing the cache system ...\n");
        if ((err = genl_cache_init()) < 0)
            goto error_socket;

        print_log(MSG_NOTICE, "Searching %s ...\n", WTAP80211_GENL_NAME);

        /* Find the target module and bind it to the cache */
        if (!(genl.family = genl_ctrl_search_by_name(genl.cache, gf_name))) {
            err = -NLE_NODEV;
            goto error;
        }

        genl.family_id = genl_family_get_id(genl.family);
        genl.fd = nl_socket_get_fd(genl.sock);

        print_log(MSG_NOTICE, "%s found (family id = %d, fd = %d)\n",
                  gf_name, genl.family_id, genl.fd);

        print_log(MSG_DBG, "Setting customized Neltink callbacks ...\n");

        /* Bind a custom callback to the Netlink socket for incoming messages */
        err = nl_cb_set(genl.cb, NL_CB_MSG_IN, NL_CB_CUSTOM, nl_msg_recv_cb, &genl);
        if (err < 0)
            return err;

        err = nl_cb_err(genl.cb, NL_CB_CUSTOM, nl_err_cb, &genl);
        if (err < 0)
            return err;

        /*
         * Register custom callbacks that will be called a Generic Netlink message is received.
         *
         * Note: The word, "family" in genl_register_family(), means a set of callbacks, not Generic Netlink family.
         *       genl_register_family() does not internally allocate genl_family structure.
         *       This function just checks all members of @ops and adds @ops to a list shared in libnl.
         */
        if ((err = genl_register_family(&ops)) < 0)
            goto error_socket;

        print_log(MSG_DBG, "Resolving the group name ...\n");

        /* Resolve the family name to its numeric identifier */
        if ((err = genl_ops_resolve(c_sock, &ops)) < 0)
            goto error_socket;

        /* print_log(MSG_NOTICE, "[genetlink] Resolving the Generic Netlink family name to its numeric family identifier ...\n"); */

        /* Resolve the Generic Netlink family name to the corresponding numeric family identifier. */
        /*
         * if ((err = genl_ctrl_resolve(genl.sock, gf_name)) < 0)
         *     goto error_socket;
         */

        if (register_event(genl.fd, EV_READ | EV_PERSIST, ev_cb_recv_genlmsg, NULL) < 0)
            goto error_socket;

        print_log(MSG_NOTICE, "Initialization completed.\n");

        print_log(MSG_NOTICE, "Requesting the device list to %s...\n", gf_name);

        /* Send an auth request to the target module. */
        /* if ((err = genl_send_simple(genl.sock, genl.family_id, WTAP_GENL_CMD_AUTH, genl.version, 0)) < 0) { */
        if ((err = genlmsg_unicast_custom(WTAP_GENL_CMD_AUTH, nlattr_put_auth_frame, NULL)) < 0) {
            print_log(MSG_NOTICE, "Could not send a request to %s.\n", gf_name);
            genl.flags = GENL_STATE_AUTH_REQUIRED;
        } else {
            genl.flags = GENL_STATE_STANDBY;
        }

        nl_socket_free(c_sock);

    } else {
        print_log(MSG_NOTICE,
                "Netlink connection is disabled. The daemon will work in forwarding/simulation mode.\n");
    }

    if (genl.enable_tcp_forwarding) {
        // Start the TCP server
        struct libtcpserv_config_struct tcp_config = {
                .port = genl.listen_port,
                .listen_backlog = 5,
                .func = tcp_server_handler,
                .arg = NULL,
        };

        genl.tcpserver = libtcpserv_new(&tcp_config);

        libworkqueue_enqueue_task(genl.workqueue,
                NULL, do_connect_another_daemon, NULL);

        print_log(MSG_DBG, "TCP server launched, listen_port: %d\n", genl.listen_port);
    }

    if (genl.enable_local_forwarding) {

        libwinetap_init();

        // Todo: Define the recv event callback
        struct libwinetap_config_struct config;
        config.do_recv_handler = do_recv_handler;
        config.user_arg = NULL;
        strncpy(config.dest_path, genl.dest_path, min(SUNPATH_LEN, strlen(genl.dest_path) + 1));
        strncpy(config.src_path, genl.src_path, min(SUNPATH_LEN, strlen(genl.src_path) + 1));

        if ((genl.unclient = libwinetap_new(&config))) {
            print_log(MSG_INFO, "Local domain server launched\n");
            genl.is_simulator_connected = true;
        } else {
            print_log(MSG_WARN, "Local domain server NOT launched\n");
            genl.is_simulator_connected = false;
        }
    }

    print_log(MSG_DBG, "Genetlink connector initialized\n");

    return 0;

error_socket:
    nl_socket_free(genl.sock);
error:
    nl_socket_free(c_sock);
    print_log(MSG_ERR, "%s.\n", nl_geterror(err));
    return err;
}

void genetlink_connector_exit(void)
{
    if (genl.tcpclient)
        libtcpserv_disconnect(genl.tcpclient);

    if (genl.tcpserver)
        libtcpserv_exit(genl.tcpserver);

    if (genl.unclient)
        libwinetap_release(genl.unclient);

    if (genl.sock)
        nl_socket_free(genl.sock);

    libworkqueue_remove(genl.workqueue);

    print_log(MSG_DBG, "msg: Genetlink connector terminated successfully.\n");
    print_message_stats(&genl.stat.genl, "class: genl, ");
    print_message_stats(&genl.stat.ud,   "class:   ud, ");
    print_message_stats(&genl.stat.tcp,  "class:  tcp, ");
}

#undef DEBUG_IDENTIFIER
