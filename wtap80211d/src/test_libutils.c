//
// Created by Arata Kato on 2019-09-11.
//

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <event.h>
#include <sys/un.h>
#include "utils.h"
#include "common/message.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "test_libutils"

#define SUNPATH_LEN ((size_t)103)

static char* dest_sunpath = NULL;
static char* src_sunpath = NULL;
static char* mode = NULL;
static int sec = 1;
static bool enable_debug_test = false;

static int un_connect(const char * sunpath)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sunpath, min(SUNPATH_LEN, strlen(sunpath) + 1));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        goto error;

    return sock;

error:
    print_log(MSG_ERR, "Could not connect to %s \n", dest_sunpath);
    return -1;
}

static void event_handler(int sock, short int flag, void *arg)
{
    print_log(MSG_DBG, "Receive event detected\n");

    struct message *msg = recv_message_header_only(sock);
    if (msg)
        print_message(msg, "");
}

static void test_event_function(void)
{
    struct libutils_event_struct* es = libutils_event_new();
    if (!es)
        goto error;

    int sock = un_connect(dest_sunpath);
    libutils_event_register(es, sock, EV_READ | EV_PERSIST, event_handler, NULL);

    struct message *msg = get_test_message();
    send_all_stream(sock, msg, message_len(msg));

    libutils_event_dispatch(es);

    return ;

error:

    return ;
}

static void launch_test(void)
{
    if (!strcmp(mode, "btrace")) {
        libutils_debug_print_backtrace();
    }
    else if (!strcmp(mode, "unevent")) {
        if (!dest_sunpath || !src_sunpath)
            goto error;
        test_event_function();
    }
    else if (!strcmp(mode, "sleep_pthread")) {
        print_log(MSG_ERR, "Set the timer for %d seconds\n", sec);
        sleep_pthread(sec, 0, NULL, NULL);
        print_log(MSG_ERR, "Timer stopped\n");
    }
    else if (!strcmp(mode, "rdtsc")) {
        const unsigned int repeat_times = 1000 * 1000 * 50;
        struct timespec ts_start, ts_end;

        clockid_t cid;
        if (clock_getcpuclockid(0, &cid)) {
            print_log(MSG_ERR, "Failed to get the clock id.\n");
            return ;
        }

        clock_gettime(cid, &ts_start);
        for (unsigned int i = 0; i < repeat_times; ++i) {
            unsigned long long int rdtsc = gettime_rdtsc();
        }
        clock_gettime(cid, &ts_end);

        const unsigned long long int diff = diff_timespec(ts_start, ts_end);
        print_log(MSG_INFO, "%u rdtsc calls in %llu ns (%llu ns/call)\n",
                repeat_times, diff, diff / repeat_times);
    }
    else {
        print_log(MSG_ERR, "Unknown mode specified\n");
    }

    return ;

error:
    print_log(MSG_ERR, "Program terminted because of invalid or missing arguments\n");
}

static int parse_arg(int argc, char **argv)
{
    const struct option long_options[] = {
            {"debug",       required_argument, 0, 'g'},
            {"destination", required_argument, 0, 'd'},
            {"module",      required_argument, 0, 'm'},
            {"source",      required_argument, 0, 's'},
            {"second",      required_argument, 0, 't'},
            {0, 0, 0, 0}
    };
    const char *optstr = "d:m:s:t:";
    int c, index;

    while ((c = getopt_long(argc, argv, optstr, long_options, &index)) != -1) {
        switch (c) {
            case 'd':
                dest_sunpath = optarg;
                break;
            case 'g':
                enable_debug_test = true;
                mode = optarg;
                break;
            case 'm':
                mode = optarg;
                break;
            case 's':
                src_sunpath = optarg;
                break;
            case 't':
                sec = atoi(optarg);
                break;
            case '?':
            default:
                exit(EXIT_SUCCESS);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    parse_arg(argc, argv);

    launch_test();

    return 0;
}

#undef DEBUG_IDENTIFIER
