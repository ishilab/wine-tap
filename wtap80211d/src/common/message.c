//
// Created by Arata Kato on 2019-08-02.
//

#include <stdio.h>
#include <sys/un.h>
#include <uuid/uuid.h>
#include "../utils.h"
#include "message.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "message"

static const char typestr[][20] = {
    [MESSAGE_TYPE_ID_UNSPEC] = "UNSPEC",
    [MESSAGE_TYPE_ID_CONFIG] = "CONFIG",
    [MESSAGE_TYPE_ID_AUTH] = "AUTH",
    [MESSAGE_TYPE_ID_AUTH_ACK] = "AUTH ACK",
    [MESSAGE_TYPE_ID_TX_FRAME] = "TX FRAME",
    [MESSAGE_TYPE_ID_RX_FRAME] = "RX FRAME",
    [MESSAGE_TYPE_ID_LOOPBACK] = "LOOPBACK",
    [MESSAGE_TYPE_ID_SYNC_REQUEST] = "SYNC REQ",
    [MESSAGE_TYPE_ID_SYNC_RESPONSE] = "SYNC RESP",
    [MESSAGE_TYPE_ID_GET_PROPERTY] = "GET PROP",
    [MESSAGE_TYPE_ID_SET_PROPERTY] = "SET PROP",
    [MESSAGE_TYPE_ID_UNSPEC_CONFIG] = "UNSPEC CONFIG",
    [MESSAGE_TYPE_ID_IMTIMESYNC_BROADCAST] = "IMTIME BROADCAST",
    [MESSAGE_TYPE_ID_IMTIMESYNC_REQUEST] = "IMTIME REQUEST",
    [MESSAGE_TYPE_ID_IMTIMESYNC_RESPONSE] = "IMTIME RESPONSE",
    [MESSAGE_TYPE_ID_ACK] = "ACK",
    [MESSAGE_TYPE_ID_TEST] = "TEST"
};

int validate_message_id(const struct message *msg)
{
    return (!msg || msg->message_type < 0 || msg->message_type > ARRAY_SIZE(typestr)) ? 0 : msg->message_type;
}

void message_free(struct message **message)
{
    gc_free(*(message));
}

inline void flush_message(struct message *msg)
{
    if (msg)
        memset(msg, 0, message_len(msg));
}

// If it returns zero, they are different. If true, they are the same one.
bool compare_message(const struct message *msg1, const struct message *msg2)
{
    // Memo: uuid_compare returns zero when both are the same one.
    return !(uuid_compare(msg1->message_id, msg2->message_id));
}

void print_message_stats(const struct message_statistics_struct *ss, const char *str)
{
    if (ss) {
        print_log(MSG_DBG,
                  "msg: message stat, %s"
                  "transmitted: %llu, tx_error: %llu, "
                  "received: %llu, rx_error: %llu, duplicated: %llu, dropped: %llu, unknown: %llu\n",
                  (str) ? : "",
                  ss->transmitted, ss->tx_error,
                  ss->received, ss->rx_error, ss->duplicated, ss->dropped, ss->unknown);
    }
}

void print_message(const struct message *msg, const char *str)
{
    if (!msg)
        return;

    print_log(MSG_DBG, "Message Type: %s %s\n",
            typestr[validate_message_id(msg)], (str) ? : "");

    char uuid_str[37] = {0};

    uuid_unparse_lower(msg->message_id, uuid_str);
    print_log(MSG_DBG, "\tattr_id: %d, message_id: %s, length: %d\n",
            msg->attribute_type, uuid_str, msg->len);

    if (msg->message_type == MESSAGE_TYPE_ID_ACK) {
        uuid_unparse_lower(msg->header.ack.message_id, uuid_str);
        print_log(MSG_DBG, "\tstate: %s, relative message_id: %s\n",
                  (msg->header.ack.is_ok) ? "true" : "false", uuid_str);
    } else if (msg->message_type == MESSAGE_TYPE_ID_AUTH_ACK) {
        uuid_unparse_lower(msg->header.auth_ack.message_id, uuid_str);
        print_log(MSG_DBG, "\tstate: %s, relative message_id: %s\n",
                  (msg->header.auth_ack.is_ok) ? "true" : "false", uuid_str);
    }
}

inline size_t message_len(const struct message* msg)
{
    return sizeof(struct message) + msg->len;
}

__attribute__((malloc))
inline struct message* allocate_message_buffer(size_t len)
{
    struct message* buf = (struct message*)gc_malloc(sizeof(struct message) + len);
    if (buf)
        buf->len = len;
    return buf;
}

__attribute__((malloc))
struct message* get_new_message(size_t len)
{
    struct message *msg = (struct message*)gc_malloc(sizeof(struct message) + len);

    if (msg) {
        uuid_generate(msg->message_id);
        msg->len = len;
    }

    return msg;
}

__attribute__((malloc))
struct message* resize_message(struct message *msg)
{
    struct message *resize_msg = NULL;
    if (!(resize_msg = (struct message*)gc_realloc(msg, sizeof(struct message) + msg->len)))
        return msg;

    return resize_msg;
}

struct message* get_auth_message(void)
{
    struct message *msg = get_new_message(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);

    if (msg) {
        msg->message_type = MESSAGE_TYPE_ID_AUTH;
        msg->attribute_type = MESSAGE_ATTRIBUTE_ID_UNSPECIFIED;
    }

    return msg;
}

struct message* get_ack_message(uuid_t message_id, bool is_ok)
{
    struct message *msg = get_new_message(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);

    if (msg) {
        msg->message_type = MESSAGE_TYPE_ID_ACK;
        msg->attribute_type = MESSAGE_ATTRIBUTE_ID_UNSPECIFIED;

        uuid_copy(msg->header.ack.message_id, message_id);
        msg->header.ack.is_ok = is_ok;
    }

    return msg;
}

struct message* get_auth_ack_message(uuid_t message_id, bool is_ok)
{
    struct message *msg = get_new_message(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);

    if (msg) {
        msg->message_type = MESSAGE_TYPE_ID_AUTH_ACK;
        msg->attribute_type = MESSAGE_ATTRIBUTE_ID_UNSPECIFIED;

        uuid_copy(msg->header.auth_ack.message_id, message_id);
        msg->header.auth_ack.is_ok = is_ok;
    }

    return msg;
}

struct message* get_frame_message(struct genl_info *info,
        struct ieee80211_tx_info *tx_info, struct ieee80211_channel *channel, uint32_t flags,
        void* frame, size_t len, uint32_t fcs)
{
    struct message *msg = get_new_message(len);

    if (msg) {
        msg->message_type = MESSAGE_TYPE_ID_TX_FRAME;
        msg->attribute_type = MESSAGE_ATTRIBUTE_ID_DOT11FRAME;

        memcpy(&msg->header.tx_frame.info, info, sizeof(struct genl_info));
        memcpy(&msg->header.tx_frame.tx_info, tx_info, sizeof(struct ieee80211_tx_info));
        memcpy(&msg->header.tx_frame.channel, channel, sizeof(struct ieee80211_channel));
        msg->header.tx_frame.flags = flags;
        msg->header.tx_frame.fcs = fcs;

        memcpy(message_payload_of(msg), frame, len);
    }

    return msg;
}

struct message* get_test_message(void)
{
    struct message *msg = get_new_message(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);

    if (msg) {
        msg->message_type = MESSAGE_TYPE_ID_TEST;
        msg->attribute_type = MESSAGE_ATTRIBUTE_ID_UNSPECIFIED;
    }

    return msg;
}

struct message* recv_message(int sock)
{
    int rc = 0;

    // Receive the message header
    struct message *recv_msg = allocate_message_buffer(DEFAULT_PAYLOAD_LENGTH);
    if (!recv_msg || (rc = recv_all_stream(sock, recv_msg, sizeof(struct message))) < 1)
        goto error;

    // Receive the message payload
    if (recv_msg->len > 0) {
        if (recv_msg->len > DEFAULT_PAYLOAD_LENGTH)
            recv_msg = resize_message(recv_msg);

        if ((rc = recv_all_stream(sock, message_payload_of(recv_msg), recv_msg->len)) < 1)
            goto error;
    }

    return recv_msg;

error:
    print_log(MSG_DBG, "Invalid message or socket closed\n");
    gc_free(recv_msg);
    return NULL;
}

struct message* recv_message_header_only(int sock)
{
    int rc = 0;

    struct message *recv_msg = allocate_message_buffer(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);
    if (!recv_msg || (rc = recv_all_stream(sock, recv_msg, sizeof(struct message))) < 0)
        goto error;

    //__attribute__((cleanup(release_memory))) char *buf = (char*)malloc(recv_msg->len);
    char *buf = (char*)gc_malloc(recv_msg->len);
    if (!buf || (rc = recv_all_stream(sock, buf, recv_msg->len)) < 0)
        goto error;

    return recv_msg;

error:
    print_log(MSG_DBG, "Invalid message or unknown error\n");
    gc_free(recv_msg);
    return NULL;
}

// recv_message_auto() receives a message and sends back an ack message to the destination.
struct message* recv_message_auto(int sock)
{
    struct message *recv_msg = allocate_message_buffer(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);
    //__attribute__((cleanup(message_free))) struct message *ack = NULL;
    //struct message *ack = NULL;

    int rc = 0;

    // Receive the message header
    if (!recv_msg || (rc = recv_all_stream(sock, recv_msg, sizeof(struct message))) < 0) {
        //ack = get_ack_message((uuid_t){0}, false);
        goto error;
    }

    // Receive the message payload
    if (recv_msg->len > 0) {
        resize_message(recv_msg);

        if ((rc = recv_all_stream(sock, message_payload_of(recv_msg), recv_msg->len)) < 0) {
            //ack = get_ack_message(recv_msg->message_id, false);
            goto error;
        }
    }

    // Send an ack
    if (recv_msg->message_type != MESSAGE_TYPE_ID_ACK ||
            recv_msg->message_type != MESSAGE_TYPE_ID_AUTH_ACK) {
        //ack = get_ack_message(recv_msg->message_id, true);
        //send_all_stream(sock, ack, message_len(ack));
    }

    return recv_msg;

error:
    // send_all_stream(sock, ack, message_len(ack));
    print_log(MSG_DBG, "Invalid message or unknown error\n");
    gc_free(recv_msg);
    return NULL;
}

#undef DEBUG_IDENTIFIER
