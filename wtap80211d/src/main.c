
/*
 * wtap80211d
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/types.h>

#include <event.h>

#include "utils.h"
#include "libworkqueue.h"
#include "event_manager.h"
#include "system_logger.h"
#include "config_manager.h"
#include "rtnetlink_connector.h"
#include "udev_watchdog.h"
#include "genetlink_connector.h"
#include "netdevice_manager.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "main"

static bool is_dryrun = false;

static struct argument_struct {
    char *config_file;
    char *log_file;
} arg_st = {0};

static void print_usage(void)
{
    print_log(MSG_ERR, "Usage: ./wtap80211d -c <config file> [-l <logfile>]\n");
}

static void evsignal_cb_sigint(evutil_socket_t fd, short flags, void *arg)
{
    declare_unused_variable(fd);
    declare_unused_variable(flags);
    declare_unused_variable(arg);

    print_log(MSG_WARN, "Caught SIGINT, Shutting down the program...\n");

    exit(EXIT_FAILURE);
}

static void evsignal_cb_sigio(evutil_socket_t fd, short flags, void *arg)
{
    print_log(MSG_DBG, "Caught SIGIO (fd = %d).\n", (int)fd);
}

static void parse_args(int argc, char **argv)
{
    int opt = 0;

    while ((opt = getopt(argc, argv, "c:dl:")) != -1) {
        switch (opt) {
            case 'c':
                arg_st.config_file = optarg;
                break;
            case 'd':
                is_dryrun = true;
                break;
            case 'l':
                arg_st.log_file = optarg;
                break;
            case '?':
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char **argv)
{
    pid_t pid = 0;
    int err = 0;

    parse_args(argc, argv);

    if ((err = libworkqueue_init()) < 0)
        goto error;

    if ((err = config_manager_init(arg_st.config_file)) < 0)
        goto error;

    if ((err = system_logger_init(arg_st.log_file)) < 0)
        goto error;

    if ((err = event_manager_init()) < 0)
        goto error;

    if ((err = register_signal_event(SIGINT, evsignal_cb_sigint, NULL)) < 0)
        goto error;

    if ((err = register_signal_event(SIGIO, evsignal_cb_sigint, NULL)) < 0)
        goto error;

#ifdef ENABLE_UDEV_WATCHDOG
    if ((err = udev_watchdog_init()))
        goto error;
#endif

    if ((err = rtnetlink_connector_init()) < 0)
        goto error;

    if ((err = genetlink_connector_init("wtap80211")) < 0)
        goto error;

#ifdef ENABLE_NETDEVICE_MANAGER
    if ((err = netdevice_manager_init()) < 0)
        goto error;
#endif

    event_manager_dispatch();

    return 0;

error:
    print_log(MSG_ERR, "stopping the process with an error, reason: %s, code: %d\n",
            strerror(-err), err);
    return -1;
}

__attribute__((destructor)) void destructor(void)
{
    netdevice_manager_exit();
    genetlink_connector_exit();
    event_manager_exit();
    config_manager_exit();
    system_logger_exit();

    print_log(MSG_DBG, "Shutdown process completed. See ya!\n");
}

#undef DEBUG_IDENTIFIER
