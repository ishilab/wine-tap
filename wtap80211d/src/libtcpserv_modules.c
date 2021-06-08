/*
 * libtcpserv_modules.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "utils.h"
#include "libtcpserv.h"

#define LIBTCPSERV_DEFAULT_LEN 4096

static int recv_all(int sock, void *data, int len)
{
    /* @reminder is bytes already received. */
    int total = 0;

    while (total < len) {
        int recv_bytes = 0;
        if ((recv_bytes = recv(sock, (void*)((char*)data + total),
                                len - total, 0)) < 1) {
            if (recv_bytes == 0)
                return 0;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            else
                goto error;
        }
        total += recv_bytes;
    }

    /* print_log(MSG_DBG, "[libtcpserv] %d bytes received.\n", total); */

    return total;

error:
    print_log(MSG_DBG, "[libtcpserv] %s (code: %d)\n", strerror(errno), errno);
    return -1;
}

int libtcpserv_recv_all(int sock, void *data, int len)
{
    return recv_all(sock, data, len);
}

int libtcpclient_recv_all(struct libtcpserv_client_struct *cs, void *data, int len)
{
    return recv_all(cs->sock, data, len);
}

static int send_all(int sock, void *data, size_t len)
{
    /* @reminder is bytes not sent yet. */
    size_t reminder = len;

    while (reminder > 0) {
        int sent_bytes = 0;
        if ((sent_bytes = send(sock, (void*)((char*)data + len - reminder),
                            reminder, 0)) < 0)
            goto error;
        reminder -= sent_bytes;
    }

    /* print_log(MSG_DBG, "[libtcpserv] %zu bytes sent.\n", len - reminder); */

    return 0;

error:
    print_log(MSG_DBG, "[libtcpserv] %s (code: %d)\n", strerror(errno), errno);
    return reminder;
}

int libtcpserv_send_all(int sock, void *data, int len)
{
    return send_all(sock, data, len);
}

int libtcpclient_send_all(struct libtcpserv_client_struct *cs, void *data, int len)
{
    return send_all(cs->sock, data, len);
}

void* libtcpserv_forward_module(int sock, void *arg)
{
    struct libtcpserv_config_struct *config = (struct libtcpserv_config_struct*)arg;
    struct libtcpserv_client_struct *cs;
    struct libtcpserv_msghdr *hdr = NULL;
    uint32_t len = LIBTCPSERV_DEFAULT_LEN;

    if (!config || !(cs = libtcpserv_connect(config)))
        goto error;

    if (!(hdr = (struct libtcpserv_msghdr*)gc_malloc(sizeof(struct libtcpserv_msghdr) + len)))
        goto error;

    print_log(MSG_DBG, "[%s] Connection established\n", __func__);

    while (1) {
        int ret = recv_all(sock, hdr, sizeof(struct libtcpserv_msghdr));
        if (ret == 0)
            break;
        else if (ret < 1)
            goto error;

        if (hdr->len > len) {
            struct libtcpserv_msghdr *realloc_hdr;
            if (!(realloc_hdr = (struct libtcpserv_msghdr*)gc_realloc(hdr,
                            sizeof(struct libtcpserv_msghdr) + hdr->len))) {
                gc_free(hdr);
                break;
            }

            if (realloc_hdr != hdr)
                hdr = realloc_hdr;

            len = hdr->len;
        }

        if (recv_all(sock, libtcpserv_data(hdr), hdr->len) < 1) {
            gc_free(hdr);
            break;
        }

        if (send_all(cs->sock, hdr, libtcpserv_len(hdr)) < 0) {
            gc_free(hdr);
            break;
        }
    }

    print_log(MSG_DBG,
            "[%s] Socket is closed (reason: %s, code: %d)\n",
            __func__, strerror(errno), errno);

    return NULL;

error:
    print_log(MSG_ERR, "[%s] Invalid message or destination.\n", __func__);
    return NULL;
}

void* libtcpserv_echo_module(int sock, void *arg)
{
    char buf[LIBTCPSERV_DEFAULT_LEN];
    int recv_bytes;

    print_log(MSG_DBG, "[%s] Connection established\n", __func__);

    while ((recv_bytes = recv(sock, buf, ARRAY_SIZE(buf), 0)) != 0) {
        if (recv_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            else
                break;
        }

        send_all(sock, buf, recv_bytes);
    }

    print_log(MSG_DBG,
            "[%s] Socket is closed (reason: %s, code: %d)\n",
            __func__, strerror(errno), errno);

    return NULL;
}

static void print_message(void *msg, const char *module_name)
{
    struct libtcpserv_msghdr *hdr = msg;
    char buf[11] = {0};

    if (hdr->len < 10)
        memcpy(buf, hdr->data, hdr->len);
    else
        memcpy(buf, hdr->data, 10);

    print_log(MSG_DBG,
            "[libtcpserv_""%s""_module] "
            "type = %0x, len = %d bytes, payload (first 10 bytes only) = %s\n",
            module_name, hdr->type, hdr->len, buf);
}

void* libtcpserv_debug_module(int sock, void *arg)
{
    struct libtcpserv_msghdr *hdr = NULL;
    uint32_t len = 0;

    print_log(MSG_DBG, "[%s] Connection established\n", __func__);

    if (!(hdr = (struct libtcpserv_msghdr*)gc_malloc(sizeof(struct libtcpserv_msghdr) + len)))
        goto error;

    while (1) {
        if (recv_all(sock, hdr, sizeof(struct libtcpserv_msghdr)) < 1)
            goto error;

        if (hdr->len > len) {
            struct libtcpserv_msghdr *realloc_hdr;
            if (!(realloc_hdr = (struct libtcpserv_msghdr*)gc_realloc(hdr,
                            sizeof(struct libtcpserv_msghdr) + hdr->len))) {
                gc_free(hdr);
                break;
            }

            if (realloc_hdr != hdr)
                hdr = realloc_hdr;

            len = hdr->len;
        }

        if (recv_all(sock, libtcpserv_data(hdr), hdr->len) < 1) {
            gc_free(hdr);
            break;
        }

        print_message(hdr, "debug");
    }

    print_log(MSG_DBG,
            "[%s] Socket is closed (reason: %s, code: %d)\n",
            __func__, strerror(errno), errno);

    return NULL;

error:
    print_log(MSG_ERR,
            "[%s] Disconnect (reason: %s, code: %d).\n",
            __func__, strerror(errno), errno);
    return NULL;
}
