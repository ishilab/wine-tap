/*
 * test_libtuntap
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"
#include "libtuntap.h"
#include "libtcpserv.h"

#define BUFSIZE 1024

static void recv_handler(int fd, short flag, void *arg)
{
    char buf[BUFSIZE] = {0};

    print_log(MSG_ERR, "recv_handler launched.\n");

    while (read(fd, buf, (BUFSIZE - 1)) > 0) {
        memset(buf, 0, BUFSIZE);
        print_log(MSG_INFO, "[ReadMessage]: %s\n", buf);
    }
}

int main(int argc, char **argv)
{
    struct libtuntap_struct *s;
    bool mode;
    int err;

    if (argc < 4)
        goto error;

    if (strcmp(argv[2], "tun") == 0)
        mode = false;
    else if (strcmp(argv[2], "tap") == 0)
        mode = true;
    else
        goto error;

    libtuntap_init();

    if (!(s = libtuntap_new(argv[1], mode))) {
        print_log(MSG_ERR, "Could not create an interface.\n");
        return -1;
    }

    if (strcmp(argv[3], "send") == 0) {
        char *str = "It always seems impossible until it's done.";
        int size = libtuntap_send(s, str, strlen(str) + 1);
        print_log(MSG_DBG, "Sending a string, %s (%d bytes transmitted)\n", str, size);
        sleep(30);
    } else if (strcmp(argv[3], "recv") == 0) {
        char buf[1024] = {0};

        if ((err = libtuntap_register_recv_handler(s, recv_handler, NULL)) < 0)
            print_log(MSG_ERR, "Could not register a recv handler (reason: %s, code: %d).\n",
                    strerror(-err), err);
        else
            print_log(MSG_DBG, "Waiting for an incoming message.\n");

        sleep(300);

    } else if (strcmp(argv[3], "self") == 0) {
        char *str = "It always seems impossible until it's done.";

        if ((err = libtuntap_register_recv_handler(s, recv_handler, NULL)) < 0)
            print_log(MSG_ERR, "Could not register a recv handler (reason: %s, code: %d).\n",
                    strerror(-err), err);

        int size = libtuntap_send(s, str, strlen(str) + 1);
        print_log(MSG_DBG, "%d bytes sent.\n", size);
    }

    libtuntap_release(s);

    libtuntap_exit();

    return 0;

error:
    print_log(MSG_ERR, "Usage: ./test_libtuntap <ifname> <tap|tun> <send|recv|self>\n");
    return -1;
}
