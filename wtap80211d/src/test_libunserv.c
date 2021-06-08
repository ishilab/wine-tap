/*
 * test_libunserv.c
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
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "utils.h"
#include "libunserv.h"
#include "common/message.h"

static char* dest_sunpath = NULL;
static char* src_sunpath = NULL;
static char* mode = NULL;
static pthread_t thread;
static struct libunserv_struct *server;

static void ev_sigint_handler(int sock, short int flags, void *arg)
{
    print_log(MSG_DBG, "[test_libunserv] SIGINT signal detected. Shutting down the program...\n");
    pthread_cancel(thread);
    libunserv_release(server);
    libutils_event_loopbreak((struct libutils_event_struct*)arg);

    exit(EXIT_SUCCESS);
}

static void ev_recv_message(int sock, short int flag, void *arg)
{
    int readable_bytes = 0;

    print_log(MSG_DBG,
            "receive event detected (%d bytes ready to read)\n", get_bytes_ready2read(sock));

    struct message *msg = recv_message_header_only(sock);
    if (msg)
        print_message(msg, "(recv)");

    return ;
}

static void* launch_send_message(void *arg)
{
    struct libunserv_config_struct config;
    strncpy(config.dest_path, dest_sunpath, min(SUNPATH_LEN, strlen(dest_sunpath) + 1));
    strncpy(config.src_path, src_sunpath, min(SUNPATH_LEN, strlen(src_sunpath) + 1));
    config.ev_recv_handler = ev_recv_message;

    if (!(server = libunserv_new(&config)))
        return NULL;

    print_log(MSG_DBG, "Sending a test message via %s\n", dest_sunpath);

    for (int i = 0; i < 3; ++i) {
        struct message *msg = get_test_message();

        while (libunserv_send_all(server, msg, message_len(msg)) < 0) {
            print_log(MSG_DBG, "Client seems not to be connected yet. Waiting for it to connect...\n");
            sleep_pthread(3, 0, NULL, NULL);
        }

        print_message(msg, "(sender)");

        sleep_pthread(1, 0, NULL, NULL);

        gc_free(msg);
    }

    libunserv_wait(server);

    libunserv_release(server);

    return NULL;
}

static void set_recv_handler(struct libunserv_config_struct *config, const char *mode)
{
    if (!strcmp(mode, "echo"))
        config->ev_recv_handler = libunserv_echo_module;
    else if (!strcmp(mode, "debug"))
        config->ev_recv_handler = libunserv_debug_module;
    else if (!strcmp(mode, "message"))
        config->ev_recv_handler = ev_recv_message;
    else if (!strcmp(mode, "send_test_message")) {
        pthread_create(&thread, NULL, launch_send_message, NULL);
        pthread_join(thread, NULL);
        exit(EXIT_SUCCESS);
    }
    else
        config->ev_recv_handler = NULL;
}

static int parse_arg(int argc, char **argv)
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
                dest_sunpath = optarg;
                break;
            case 'm':
                mode = optarg;
                break;
            case 's':
                src_sunpath = optarg;
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
    parse_arg(argc, argv);
    if (!dest_sunpath || !src_sunpath || !mode) {
        print_log(MSG_ERR,
                "Terminated because of invalid arguments (You gave mode=%s, destination=%s, source=%s).\n",
                mode, dest_sunpath, src_sunpath);
        return -1;
    }

    struct libutils_event_struct *event_base = libutils_event_new();
    if (event_base) {
        libutils_event_register_sigev(event_base, SIGINT, ev_sigint_handler, event_base);
        libutils_event_dispatch(event_base);
    }

    libunserv_init();

    struct libunserv_config_struct config;
    strncpy(config.dest_path, dest_sunpath, min(SUNPATH_LEN, strlen(dest_sunpath) + 1));
    strncpy(config.src_path, src_sunpath, min(SUNPATH_LEN, strlen(src_sunpath) + 1));
    config.listen_backlog = 5;
    set_recv_handler(&config, mode);

    if ((server = libunserv_new(&config))) {
        print_log(MSG_DBG, "%s server launched.\n", mode);

        // Wait for the listener instance
        libunserv_wait(server);
    }

    libunserv_release(server);

    libutils_event_release(event_base);

    libunserv_exit();

    libutils_event_exit();

    return 0;
}

__attribute__((destructor)) void destructor(void)
{
    print_log(MSG_DBG, "Shutdown process completed. Goodbye!\n");
}
