//
// Created by Arata Kato on 2019-08-05.
//

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <sys/epoll.h>
#include <event.h>
#include "utils.h"
#include "common/message.h"
#include "libworkqueue.h"
#include "libunserv.h"
#include "libwinetap.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libwinetap"

#define libwinetap_priv_of(s) ((struct libwinetap_priv*)&((s)->priv))

static struct {
    pthread_mutex_t mutex;
    bool is_initialized;
} libwinetap = {
    .is_initialized = false,
};

struct libwinetap_priv {
    struct libunserv_struct *server;

    bool is_client;
    bool is_authenticated;
    bool is_running;

    void* (*do_recv_handler)(void*);
    void *user_arg;

    struct libworkqueue_struct *workqueue;
};

bool libwinetap_is_connected(struct libwinetap_struct *s)
{
    struct libwinetap_priv *priv = libwinetap_priv_of(s);
    return libunserv_is_connected(priv->server);
}

bool libwinetap_is_authenticated(struct libwinetap_struct *s)
{
    struct libwinetap_priv *priv = libwinetap_priv_of(s);
    return priv->is_authenticated;
}

bool libwinetap_is_running(struct libwinetap_struct *s)
{
    struct libwinetap_priv *priv = libwinetap_priv_of(s);
    return priv->is_running;
}

inline void libwinetap_free_recv_handler_container(struct libwinetap_recv_handler_container *container)
{
    if (container) {
        gc_free(container->msg);
        gc_free(container);
    }
}

inline void libwinetap_config_init(struct libwinetap_config_struct *config,
        const char * dest_path, const char * src_path,
        void* (*do_recv_handler)(void*), void* user_arg)
{
    strncpy(config->dest_path, dest_path, min(SUNPATH_LEN, strlen(dest_path) + 1));
    strncpy(config->src_path, src_path, min(SUNPATH_LEN, strlen(src_path) + 1));
    config->do_recv_handler = do_recv_handler;
    config->user_arg = user_arg;
}

int libwinetap_send(struct libwinetap_struct *s, const void *data, size_t len)
{
    int rc = -1;

    if (s) {
        struct libwinetap_priv *priv = libwinetap_priv_of(s);
        rc = libunserv_send_all(priv->server, data, len);
    }

    return rc;
}

void libwinetap_wait(struct libwinetap_struct *s)
{
    if (s) {
        struct libwinetap_priv *priv = libwinetap_priv_of(s);
        libunserv_wait(priv->server);
    }
}

// __attribute__((unused))
// static struct message* recv_message(struct libwinetap_priv *priv, int *__rc)
// {
//     struct message *msg = allocate_message_buffer(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);
//     int rc = 0;
//
//     rc = libunclient_recv_all(priv->client, msg, sizeof(struct message));
//     if (rc > 0)
//         rc = libunclient_recv_all(priv->client, message_payload_of(msg), msg->len);
//
//     __attribute__((cleanup(message_free))) struct message *ack =
//             (rc < 0) ? get_ack_message((uuid_t){0}, false)
//                      : get_ack_message(msg->message_id, true);
//
//     libunclient_send_all(priv->client, ack, message_len(ack));
//
//     if (rc < 0)
//         gc_free(msg);
//
//     *__rc = rc;
//
//     return (rc < 0) ? NULL : msg;
// }

// The receive process that needs to access the private field MUST be executed in this handler.
// __attribute__((unused))
// static void client_handler(int sock, short int flags, void *arg)
// {
//     struct libwinetap_priv *priv = (struct libwinetap_priv*)arg;
//
//     print_log(MSG_DBG, "[libwinetap client] Sending a authentication request...\n");
//
//     __attribute__((cleanup(message_free))) struct message *msg =
//             get_new_message(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);
//     if (!msg)
//         goto error;
//
//     msg->message_type = MESSAGE_TYPE_ID_AUTH;
//     msg->header.auth.length = 0;
//
//     if (libunclient_send_all(priv->client, msg, message_len(msg)) < 0)
//         goto error;
//
//     print_message(msg, "(client) (send)");
//
//     int rc = 0;
//     do {
//         struct message *recv_msg = NULL;
//         struct message *ack = NULL;
//
//         // Allocate buffer
//         if (!(recv_msg = allocate_message_buffer(DEFAULT_PAYLOAD_LENGTH))) {
//             ack = get_ack_message((uuid_t){0}, false);
//             libunclient_send_all(priv->client, ack, message_len(ack));
//             continue;
//         }
//
//         size_t bufsize = recv_msg->len;
//
//         // Receive the message header
//         rc = libunclient_recv_all(priv->client, recv_msg, sizeof(struct message));
//
//         // Receive the payload
//         if (rc > 0) {
//             if (recv_msg->len > bufsize)
//                 resize_message(recv_msg);
//
//             rc = libunclient_recv_all(priv->client, message_payload_of(recv_msg), recv_msg->len);
//         }
//         else {
//             ack = get_ack_message(recv_msg->message_id, false);
//             libunclient_send_all(priv->client, ack, message_len(ack));
//             continue;
//         }
//
//         if (recv_msg->message_type == MESSAGE_TYPE_ID_AUTH_ACK) {
//             ack = get_auth_ack_message(msg->message_id, true);
//
//             priv->is_authenticated = true;
//             print_log(MSG_DBG, "[libwinetap client] Client handler authenticated successfully.\n");
//         }
//         else {
//             ack = get_ack_message(recv_msg->message_id, true);
//         }
//
//         if (priv->do_recv_handler)
//             pthread_create(&priv->recv_thread, NULL, priv->do_recv_handler, recv_msg);
//
//     } while (rc >= 0);
//
// error:
//     print_log(MSG_ERR, "[libwinetap client] client handler terminated (reason: %s, code: %d)\n", strerror(errno), errno);
//     return ;
// }

// __attribute__((unused))
// static void *socket_handler(void *arg) {
//     struct libwinetap_priv *priv = (struct libwinetap_priv *) arg;
//     struct pollfd fds = {
//         .fd = priv->client->sock,
//         .events = POLLIN | POLLERR,
//     };
//     int rc = 0;
//
//     while ((rc = poll(&fds, 1, -1)) < 0) {
//         if (fds.revents & POLLIN) {
//             // Forward an incoming packet to a network simulator that owns this instance.
//             struct message *msg = get_new_message(DEFAULT_PAYLOAD_LENGTH);
//
//             if (!msg) {
//                 struct message *ack = get_ack_message(0, false);
//                 libunclient_send_all(priv->client, ack, sizeof(struct message));
//                 print_log(MSG_DBG, "Could not allocate a buffer memory field");
//                 continue;
//             }
//
//             libunclient_recv_all(priv->client, msg, sizeof(struct message));
//
//             if (msg->len - sizeof(struct message) > DEFAULT_PAYLOAD_LENGTH)
//                 msg = resize_message(msg);
//
//             libunclient_recv_all(priv->client, message_payload_of(msg), msg->len);
//
//             print_message(msg, "(sock handler)");
//
//         } else if (fds.revents & POLLERR) {
//             print_log(MSG_ERR, "Irregular error happened (reason: %s, code: %d)\n",
//                       strerror(errno), errno);
//         }
//     }
//
//     return NULL;
// }

// __attribute__((unused))
// static void* do_recv_message(void *arg)
// {
//     struct libwinetap_priv *priv = (struct libwinetap_priv*)arg;
//
//     print_log(MSG_DBG, "[libwinetap client] Sending a authentication request...\n");
//
//     __attribute__((cleanup(message_free))) struct message *msg =
//             get_new_message(DEFAULT_PAYLOAD_LENGTH_HEADER_ONLY);
//     if (!msg)
//         goto error;
//
//     int rc = 0;
//
//     do {
//         struct message *recv_msg = NULL;
//         struct message *ack = NULL;
//
//         // Allocate buffer
//         if (!(recv_msg = allocate_message_buffer(DEFAULT_PAYLOAD_LENGTH))) {
//             ack = get_ack_message((uuid_t){0}, false);
//             libunclient_send_all(priv->client, ack, message_len(ack));
//             continue;
//         }
//
//         size_t bufsize = recv_msg->len;
//
//         // Receive the message header
//         if ((rc = libunclient_recv_all(priv->client, recv_msg, sizeof(struct message))) <= 0) {
//             ack = get_ack_message(recv_msg->message_id, false);
//             libunclient_send_all(priv->client, ack, message_len(ack));
//             gc_free(msg);
//             continue;
//         }
//
//         // Resize the message buffer length
//         if (recv_msg->len > bufsize)
//             resize_message(recv_msg);
//
//         // Receive the payload
//         if ((rc = libunclient_recv_all(priv->client, message_payload_of(recv_msg), recv_msg->len)) <= 0) {
//             ack = get_ack_message(recv_msg->message_id, false);
//             libunclient_send_all(priv->client, ack, message_len(ack));
//             gc_free(msg);
//             continue;
//         }
//
//         print_message(msg, "(client) (send)");
//
//         // Send a successful ack
//         if (recv_msg->message_type == MESSAGE_TYPE_ID_AUTH_ACK) {
//             ack = get_auth_ack_message(msg->message_id, true);
//
//             priv->is_authenticated = true;
//             print_log(MSG_DBG, "[libwinetap client] Client handler authenticated successfully.\n");
//         }
//         else {
//             ack = get_ack_message(recv_msg->message_id, true);
//         }
//
//         // Move the receiving process to the user handler
//         // Select a callback function
//         if (priv->recv_handler)
//             pthread_create(&priv->recv_thread, NULL, priv->recv_handler, recv_msg);
//
//     } while (rc >= 0);
//
// error:
//     print_log(MSG_ERR, "[libwinetap client] client handler terminated (reason: %s, code: %d)\n", strerror(errno), errno);
//     return NULL;
// }

static void* do_send_auth_message(void *arg)
{
    struct libwinetap_struct *s = (struct libwinetap_struct*)arg;
    struct libwinetap_priv *priv = libwinetap_priv_of(s);
    struct message *msg = get_auth_message();

    // if (msg) {
    //     libwinetap_send(s, msg, message_len(msg));
    //     sleep_pthread(3, NULL, NULL);
    // }

    // if (!priv->is_authenticated) {
    //     libworkqueue_enqueue_task(priv->workqueue, NULL, do_send_auth_message, s);
    //     print_log(MSG_DBG,
    //             "No auth response received. Retransmitting an auth request... (priv: %p)\n", priv);
    // }

    gc_free(msg);

    return NULL;
}

static void ev_recv_message(int sock, short int flag, void *arg)
{
    struct libwinetap_priv *priv = (struct libwinetap_priv*)arg;

    // Decode the message
    struct message *msg = recv_message(sock);
    if (msg) {
        // Authentication process is skipped.
        if (msg->message_type == MESSAGE_TYPE_ID_AUTH) {
            priv->is_authenticated = true;
            print_log(MSG_DBG, "Authenticated (priv: %p)\n", priv);
        }

        if (priv->do_recv_handler) {

            struct libwinetap_recv_handler_container *container =
                    (struct libwinetap_recv_handler_container*)gc_calloc(1,
                            sizeof(struct libwinetap_recv_handler_container));

            container->user_arg = priv->user_arg;
            container->msg = msg;

            // Memo: discard the thread id because it will never be referred from any objects except itself.
            // pthread_create(&(pthread_t){0}, NULL, priv->do_recv_handler, container);
            libworkqueue_enqueue_task(priv->workqueue, NULL, priv->do_recv_handler, container);
        }
    }
    else {
        close(sock);
        libunserv_reconnect(priv->server);
        print_log(MSG_DBG, "Transmit socket has been closed. Trying to reconnect to the same destination...\n");
    }
}

static void print_config(struct libwinetap_config_struct *config)
{
    print_log(MSG_DBG,
            "config: %p, handler: %p, user_arg: %p, dest_path: %s, src_path: %s\n",
            config, config->do_recv_handler, config->user_arg, config->dest_path, config->src_path);
}

struct libwinetap_struct* libwinetap_new(struct libwinetap_config_struct *config) {
    struct libwinetap_priv *priv;
    struct libwinetap_struct *s;
    int rc = 0;

    if (!libwinetap.is_initialized || !config) {
        print_log(MSG_ERR, "libwinetap module not initialized or no configuration\n");
        return NULL;
    }

    print_config(config);

    if (!(s = (struct libwinetap_struct *)gc_calloc(1,
            sizeof(struct libwinetap_struct) + sizeof(struct libwinetap_priv))))
        return NULL;

    priv = libwinetap_priv_of(s);

    priv->workqueue = libworkqueue_new();

    priv->do_recv_handler = config->do_recv_handler;
    priv->user_arg = config->user_arg;

    struct libunserv_config_struct server_config;
    server_config.listen_backlog = 5;
    strncpy(server_config.dest_path, config->dest_path, min(SUNPATH_LEN, strlen(config->dest_path) + 1));
    strncpy(server_config.src_path, config->src_path, min(SUNPATH_LEN, strlen(config->src_path) + 1));
    server_config.ev_recv_handler = ev_recv_message;
    server_config.arg = priv;
    server_config.is_persist = true;

    if (!(priv->server = libunserv_new(&server_config)))
        goto error;

    libworkqueue_enqueue_task(priv->workqueue, NULL, do_send_auth_message, s);

    priv->is_running = true;

    print_log(MSG_ERR, "New instance instantiated.\n");

    return s;

error:
    gc_free(s);
    print_log(MSG_ERR, "Instantiation aborted.\n");
    return NULL;
}

void libwinetap_release(struct libwinetap_struct *s)
{
    struct libwinetap_priv *priv = libwinetap_priv_of(s);

    libunserv_release(priv->server);

    libworkqueue_remove(priv->workqueue);

    gc_free(s);
}

void libwinetap_init(void) {
    libworkqueue_init();

    pthread_mutex_init(&libwinetap.mutex, NULL);

    libunserv_init();

    libwinetap.is_initialized = true;

    print_log(MSG_INFO, "libwinetap module initialized successfully\n");
    print_log(MSG_DBG,  "\tev_recv_message: %p\n", ev_recv_message);
}

void libwinewtap_exit(void) {
    libwinetap.is_initialized = false;
}

#undef DEBUG_IDENTIFIER
