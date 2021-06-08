/*
 * test_libtcpserv.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "utils.h"
#include "libtcpserv.h"

static void* server_handler(int sock, void *arg)
{
    print_log(MSG_DBG, "[%s] Connection established\n", __func__);
    return NULL;
}

static struct libtcpserv_config_struct* forward_setup(void)
{
    struct libtcpserv_config_struct *config = NULL;

    if (!(config = (struct libtcpserv_config_struct*)gc_malloc(
                    sizeof(struct libtcpserv_config_struct))))
        return NULL;

    config->port = 57210;
    config->family = AF_INET;
    strcpy(config->dest_addr, "127.0.0.1");

    return config;
}

int main(int argc, char **argv)
{
    struct libtcpserv_struct *tcpserv = NULL;
    struct libtcpserv_config_struct config = {
        .port = 57209,
        .listen_backlog = 5,
        /* .func = server_handler, */
        .arg = NULL,
    };

    if (argc < 3) {
        print_log(MSG_ERR, "Usage: ./test_libtcpserv <simple|echo|debug|forward> <port>\n");
        return -1;
    }

    config.port = atoi(argv[2]);

    if (!strcmp(argv[1], "simple")) {
        config.func = server_handler;
    } else if (!strcmp(argv[1], "echo")) {
        config.func = libtcpserv_echo_module;
    } else if (!strcmp(argv[1], "debug")) {
        config.func = libtcpserv_debug_module;
    } else if (!strcmp(argv[1], "forward")) {
        config.func = libtcpserv_forward_module;
        if (!(config.arg = (void*)forward_setup()))
            return -1;
    } else {
        print_log(MSG_DBG, "[%s] No module found.\n", __func__);
        return -1;
    }

    if (!(tcpserv = libtcpserv_new(&config)))
        return -1;

    print_log(MSG_DBG, "[%s] %s server launched.\n", __func__, argv[1]);

    libtcpserv_wait(tcpserv);

    return 0;
}
