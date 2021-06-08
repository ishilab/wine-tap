/*
 * test_libtcpserv_client.c
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

int main(int argc, char **argv)
{
    struct libtcpserv_client_struct *tcpclient = NULL;
    struct libtcpserv_config_struct config = {
        .port = 57209,
        .family = AF_INET,
        .dest_addr = "127.0.0.1",
    };

    char *str = "If today were the last day of my life, would I want to do what I am about to do today?";
    char buf[128];

    if (argc < 2)
        goto error;

    if (!(tcpclient = libtcpserv_connect(&config)))
        return -1;

    if (!strcmp(argv[1], "simple")) {
        libtcpserv_send(tcpclient, str, strlen(str) + 1);
    } else if (!strcmp(argv[1], "echo")) {
        libtcpserv_send(tcpclient, str, strlen(str) + 1);
        libtcpserv_recv(tcpclient, buf, ARRAY_SIZE(buf));
        print_log(MSG_INFO, "[libtcpserv] %s\n", buf);
    } else if (!strcmp(argv[1], "debug")) {
        libtcpserv_send_with_header(tcpclient, str, strlen(str) + 1, 0);
    } else if (!strcmp(argv[1], "forward")) {
        libtcpserv_send_with_header(tcpclient, str, strlen(str) + 1, 0);
    } else {
        goto error;
    }

    return 0;

error:
    print_log(MSG_ERR, "Usage: ./test_libtcpclient <simple|echo|debug|forward>\n");
    return -1;
}
