//
// Created by Arata Kato on 2019-07-29.
//

#ifndef WINE_TAP_MESSAGE_H
#define WINE_TAP_MESSAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <uuid/uuid.h>
#include <netlink/cli/utils.h>
#include "../utils.h"
#include "ieee80211.h"
#include "ieee8022.h"

#define DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY 0
#define DEFAULT_PAYLOAD_LENGTH             4096

// enum message_type_id, enum message_attribute_id, and enum conf_type_id
//     must be as the same as genetlink commands, attributes, and configuration id.
typedef enum message_type_id {
    MESSAGE_TYPE_ID_UNSPEC = 0,
    MESSAGE_TYPE_ID_CONFIG,
    MESSAGE_TYPE_ID_AUTH,
    MESSAGE_TYPE_ID_AUTH_ACK,
    MESSAGE_TYPE_ID_TX_FRAME,
    MESSAGE_TYPE_ID_RX_FRAME,
    MESSAGE_TYPE_ID_LOOPBACK,
    MESSAGE_TYPE_ID_SYNC_REQUEST,
    MESSAGE_TYPE_ID_SYNC_RESPONSE,
    MESSAGE_TYPE_ID_GET_PROPERTY,
    MESSAGE_TYPE_ID_SET_PROPERTY,
    MESSAGE_TYPE_ID_UNSPEC_CONFIG,

    MESSAGE_TYPE_ID_IMTIMESYNC_BROADCAST,
    MESSAGE_TYPE_ID_IMTIMESYNC_REQUEST,
    MESSAGE_TYPE_ID_IMTIMESYNC_RESPONSE,

    MESSAGE_TYPE_ID_ACK,

    MESSAGE_TYPE_ID_TEST,

    MESSAGE_TYPE_ID_MAX,
} message_type_id_t;

typedef enum message_attribute_id {

    MESSAGE_ATTRIBUTE_ID_UNSPECIFIED = 0,

    MESSAGE_ATTRIBUTE_ID_CHECKSUM,

    MESSAGE_ATTRIBUTE_ID_DOT11FRAME,
    MESSAGE_ATTRIBUTE_ID_FCS,
    MESSAGE_ATTRIBUTE_ID_TX_INFO,
    MESSAGE_ATTRIBUTE_ID_RX_STATUS,
    MESSAGE_ATTRIBUTE_ID_FREQUENCY,
    MESSAGE_ATTRIBUTE_ID_CHANNEL,
    MESSAGE_ATTRIBUTE_ID_FLAGS,

    MESSAGE_ATTRIBUTE_ID_CONF_ADDRESS,
    MESSAGE_ATTRIBUTE_ID_CONF_TYPE,
    MESSAGE_ATTRIBUTE_ID_CONF_CHANGED,
    MESSAGE_ATTRIBUTE_ID_CONF_PARAM,

    MESSAGE_ATTRIBUTE_ID_ADDRESS_LIST,

    MESSAGE_ATTRIBUTE_ATTRIBUTE_MAX_NUM,
} message_attirbute_id_t;

typedef enum conf_type_id {
    CONF_TYPE_ID_BSS_INFO = BIT(0),
    CONF_TYPE_ID_RX_FILTER = BIT(1),
    CONF_TYPE_ID_TX_QUEUE = BIT(2),
    CONF_TYPE_ID_HW_CONF = BIT(3),
    CONF_TYPE_ID_TX_CONF = BIT(4),
    CONF_TYPE_ID_HW_START = BIT(5),
    CONF_TYPE_ID_HW_STOP = BIT(6),
    CONF_TYPE_ID_VIF_ADD = BIT(7),
    CONF_TYPE_ID_VIF_REMOVE = BIT(8),
} conf_type_id_t;

struct message_statistics_struct {
    // Total number of messages transmitted
    unsigned long long int transmitted;

    // Total number of messages received (= @dropped + @unknown + @tx_success)
    unsigned long long int received;

    // Number of duplicated messages
    unsigned long long int duplicated;

    // Number of dropped messages
    unsigned long long int dropped;

    unsigned long long int tx_error;
    unsigned long long int rx_error;

    // Counter for messages with unknown message type
    unsigned long long int unknown;
};

struct visualizer_message {
    unsigned int port;
    unsigned int len;
    unsigned int nodeid;
    char data[0];
} __attribute__((packed));

// Todo:
// - Support little and big endianness
//   Scaler fields of this structure is ordered by Little Endian
//   and wine-tap only supports little-endian machine.
//   Support to big-endian machines is in progress.
struct message {
    uuid_t message_id; // uuid_t = unsigned char[16];
    uint32_t len; // Bytes in payload.

    enum message_type_id message_type;
    enum message_attribute_id attribute_type;

    union {
        struct {
            uint32_t flags;
            uint32_t fcs;
            struct genl_info info;
            struct ieee80211_tx_info tx_info;
            struct ieee80211_channel channel;
        } __attribute__((aligned(2), packed)) tx_frame;

        struct {
            uint32_t type;
            uint32_t changed;
            size_t param_len;
            char hwaddr[ETH_ALEN];
        } __attribute__((aligned(2), packed)) config;

        struct {
            size_t dummy;
        } __attribute__((aligned(2), packed)) rx_frame;

        struct {
            size_t dummy;
        } __attribute__((aligned(2), packed)) auth;

        struct {
            uuid_t message_id; // request message's id
            bool is_ok;
        } __attribute__((aligned(2), packed)) auth_ack;

        struct {
            uuid_t message_id; // request message's id
            bool is_ok;
        } __attribute__((aligned(2), packed)) ack;

        struct {
            uint64_t current_time;
        } __attribute__((aligned(2), packed)) imtimesync;

    } header;

    char data[0];
} __attribute__((aligned(2), packed));

#define message_payload_of(msg) ((void*)((char*)msg + sizeof(struct message)))

// #define message_len(len) (sizeof(struct message) + (len))
extern size_t message_len(const struct message *msg);

extern int validate_message_id(const struct message *msg);

extern void flush_message(struct message *msg);

extern bool compare_message(const struct message *msg1, const struct message *msg2);

extern void print_message_stats(const struct message_statistics_struct *ss, const char *str);

extern void print_message(const struct message *msg, const char *str);

extern struct message *allocate_message_buffer(size_t len);

//! @param[in] len payload length
extern struct message *get_new_message(size_t len);

extern struct message *resize_message(struct message *msg);

extern struct message *get_auth_message(void);

extern struct message *get_ack_message(uuid_t message_id, bool is_ok);

extern struct message *get_auth_ack_message(uuid_t message_id, bool is_ok);

extern struct message *get_frame_message(struct genl_info *info,
        struct ieee80211_tx_info *tx_info, struct ieee80211_channel *channel, uint32_t flags,
        void *frame, size_t len, uint32_t fcs);

extern struct message *get_test_message(void);

// recv_message receives the entire message.
extern struct message *recv_message(int sock);

// recv_message_header_only stores the header and discards the payload
extern struct message *recv_message_header_only(int sock);

// recv_message_auto receives the entire message and sends back an ack to the sender.
extern struct message *recv_message_auto(int sock);

#ifdef __cplusplus
};
#endif

#endif //WINE_TAP_MESSAGE_H
