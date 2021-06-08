/*
 * libunserv_modules.c
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
#include "libunserv.h"

#define libunserv_DEFAULT_LEN 4096

void libunserv_forward_module(int sock, short int flags, void *arg)
{
    struct libunserv_config_struct *config = (struct libunserv_config_struct*)arg;
    struct libunserv_client_struct *cs;
    struct libunserv_msghdr *hdr = NULL;
    uint32_t len = libunserv_DEFAULT_LEN;

    if (!config || !(cs = libunserv_connect(config, 5)))
        goto error;

    if (!(hdr = (struct libunserv_msghdr*)gc_malloc(sizeof(struct libunserv_msghdr) + len)))
        goto error;

    print_log(MSG_DBG, "[%s] Connection established\n", __func__);

    while (1) {
        int ret = recv_all_stream(sock, hdr, sizeof(struct libunserv_msghdr));
        if (ret == 0)
            break;
        else if (ret < 1)
            goto error;

        if (hdr->len > len) {
            struct libunserv_msghdr *realloc_hdr;
            if (!(realloc_hdr = (struct libunserv_msghdr*)gc_realloc(hdr,
                            sizeof(struct libunserv_msghdr) + hdr->len))) {
                gc_free(hdr);
                break;
            }

            if (realloc_hdr != hdr)
                hdr = realloc_hdr;

            len = hdr->len;
        }

        if (recv_all_stream(sock, libunserv_data(hdr), hdr->len) < 1) {
            gc_free(hdr);
            break;
        }

        if (send_all_stream(cs->sock, hdr, libunserv_len(hdr)) < 0) {
            gc_free(hdr);
            break;
        }
    }

    print_log(MSG_DBG,
            "[%s] Socket is closed (reason: %s, code: %d)\n",
            __func__, strerror(errno), errno);

    return ;

error:
    print_log(MSG_ERR, "[%s] Invalid message or destination.\n", __func__);
    return ;
}

void libunserv_echo_module(int sock, short int flags, void *arg)
{
    char buf[libunserv_DEFAULT_LEN];
    int recv_bytes;

    print_log(MSG_DBG, "[%s] Connection established\n", __func__);

    while ((recv_bytes = recv(sock, buf, ARRAY_SIZE(buf), 0)) != 0) {
        if (recv_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            else
                break;
        }

        send_all_stream(sock, buf, recv_bytes);
    }

    print_log(MSG_DBG,
            "[%s] Socket is closed (reason: %s, code: %d)\n",
            __func__, strerror(errno), errno);

    return ;
}

static void print_message(void *msg, const char *module_name)
{
    struct libunserv_msghdr *hdr = msg;
    char buf[11] = {0};

    if (hdr->len < 10)
        memcpy(buf, hdr->data, hdr->len);
    else
        memcpy(buf, hdr->data, 10);

    print_log(MSG_DBG,
            "[libunserv_""%s""_module] "
            "type = %0x, len = %d bytes, payload (first 10 bytes only) = %s\n",
            module_name, hdr->type, hdr->len, buf);
}

void libunserv_debug_module(int sock, short int flags, void *arg)
{
    struct libunserv_msghdr *hdr = NULL;
    uint32_t len = 0;

    print_log(MSG_DBG, "[%s] Connection established\n", __func__);

    if (!(hdr = (struct libunserv_msghdr*)gc_malloc(sizeof(struct libunserv_msghdr) + len)))
        goto error;

    while (1) {
        if (recv_all_stream(sock, hdr, sizeof(struct libunserv_msghdr)) < 1)
            goto error;

        if (hdr->len > len) {
            struct libunserv_msghdr *realloc_hdr;
            if (!(realloc_hdr = (struct libunserv_msghdr*)gc_realloc(hdr,
                            sizeof(struct libunserv_msghdr) + hdr->len))) {
                gc_free(hdr);
                break;
            }

            if (realloc_hdr != hdr)
                hdr = realloc_hdr;

            len = hdr->len;
        }

        if (recv_all_stream(sock, libunserv_data(hdr), hdr->len) < 1) {
            gc_free(hdr);
            break;
        }

        print_message(hdr, "debug");
    }

    print_log(MSG_DBG,
            "[%s] Socket is closed (reason: %s, code: %d)\n",
            __func__, strerror(errno), errno);

    return ;

error:
    print_log(MSG_ERR,
            "[%s] Disconnect (reason: %s, code: %d).\n",
            __func__, strerror(errno), errno);
    return ;
}
