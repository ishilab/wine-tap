/*
 * test_libunserv_client.c
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
#include "libunserv.h"
#include "common/message.h"

static char *test_message = "If today were the last day of your life, would you want to do what you are about to do today?";
static char* dest_sunpath = NULL;
static char* src_sunpath = NULL;
static char* mode = NULL;

static void ev_recv_handler(int sock, short int flag, void *arg)
{
    char buf[128] = {0};
    recvfrom(sock, buf, ARRAY_SIZE(buf), 0, NULL, 0);
    print_log(MSG_DBG, "%s\n", buf);
}

static void send_test_message(struct libunserv_struct *s,
                              void *data, size_t len)
{
    struct message *msg = get_new_message(len);

    if (msg) {
        msg->message_type = MESSAGE_TYPE_ID_TEST;
        msg->attribute_type = MESSAGE_ATTRIBUTE_ID_UNSPECIFIED;

        if (data)
            memcpy(message_payload_of(msg), data, len);

        while (!libunserv_is_connected(s))
            sleep(3);

        int sent_bytes = libunserv_send_all(s, msg, message_len(msg));

        print_message(msg, "(sender)");
    }
}

static void ev_recv_message(int sock, short int flag, void *arg)
{
    print_log(MSG_DBG, "Detect receive event (test_libunclient)\n");

    // Decode the message
    struct message *msg = recv_message_auto(sock);
    if (msg)
        print_message(msg, "(client)");

    return ;
}

static void test_message_function(const char *dest_path, const char *src_path)
{
    struct libunserv_config_struct config;
    strncpy(config.dest_path, dest_path, min(SUNPATH_LEN, strlen(dest_path) + 1));
    strncpy(config.src_path, src_path, min(SUNPATH_LEN, strlen(src_path) + 1));
    config.ev_recv_handler = ev_recv_message;
    config.listen_backlog = 5;

    struct libunserv_struct *server;
    if ((server = libunserv_new(&config))) {
        send_test_message(server, NULL, 0);
        libunserv_wait(server);
    }
}

static int launch_client(void)
{
    if (!strcmp(mode, "message"))
        test_message_function(dest_sunpath, src_sunpath);

    return 0;
}

static int parse_arg(int argc, char **argv, struct libunserv_config_struct *config)
{
    const struct option long_options[] = {
            {"destination", required_argument, 0, 'd'},
            {"module",      required_argument, 0, 'm'},
            {"source",      required_argument, 0, 's'},
            {0, 0, 0, 0}
    };
    const char *optstr = "d:m:s:";
    int c, index;

    while ((c = getopt_long(argc, argv, optstr, long_options, &index)) != -1) {
        switch (c) {
            case 'd':
                strcpy(config->dest_path, optarg);
                break;
            case 'm':
                mode = optarg;
                break;
            case 's':
                strcpy(config->src_path, optarg);
                break;
            case '?':
            default:
                print_log(MSG_INFO,
                          "Usage: ./test_libunserv --mode <echo|debug|simple> --source <path> --destination <path>\n");
                exit(EXIT_SUCCESS);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct libunserv_client_struct *tcpclient = NULL;
    struct libunserv_config_struct config = {
            .listen_backlog = 0,
            .do_recv_handler = NULL,
            .ev_recv_handler = ev_recv_message,
            .arg = NULL,
            .src_path = "/var/tmp/test_libwinetap.sock",
            .dest_path = "/var/tmp/wtap80211d.sock",
    };

    parse_arg(argc, argv, &config);
    if (!dest_sunpath || !src_sunpath || !mode) {
        print_log(MSG_ERR,
                  "Terminated because of invalid arguments (You gave mode=%s, destination=%s, source=%s).\n",
                  mode, dest_sunpath, src_sunpath);
        return -1;
    }

    libunserv_init();

    if (!(tcpclient = libunserv_connect(&config, 5)))
        goto error;

    if (!strcmp(argv[1], "simple")) {
        libunserv_send(tcpclient, test_message, strlen(test_message) + 1);
    } else if (!strcmp(argv[1], "echo")) {
        char buf[128];
        libunserv_send(tcpclient, test_message, strlen(test_message) + 1);
        libunserv_recv(tcpclient, buf, ARRAY_SIZE(buf));
        print_log(MSG_INFO, "[libunserv] %s\n", buf);
    } else if (!strcmp(argv[1], "debug") || !strcmp(argv[1], "forward")) {
        libunserv_send_with_header(tcpclient, test_message, strlen(test_message) + 1, 0);
    } else {
        goto error;
    }

    libunserv_exit();

    return 0;

error:
    print_log(MSG_ERR, "Usage: ./test_libunserv <simple|echo|debug> <dest_sunpath> <src_sunpath>\n");
    return -1;
}
