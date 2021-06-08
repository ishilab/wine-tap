//
// Created by Arata Kato on 2019-08-05.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "utils.h"
#include "common/message.h"
#include "libunserv.h"
#include "libwinetap.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "test_libwinetap"

static char* dest_sunpath = NULL;
static char* src_sunpath = NULL;
static char* mode = NULL;

static struct libwinetap_struct *server = NULL;
static struct libwinetap_struct *client = NULL;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

// Message handler
static void* do_recv_handler(void *arg)
{
    if (arg) {
        struct libwinetap_recv_handler_container *container =
                (struct libwinetap_recv_handler_container*)arg;
        struct message *msg = container->msg;
        long int id = (long int)container->user_arg;

        print_log(MSG_DBG, "thread id = %ld received a message\n", id);
        print_message(msg, "(test_libwientap recv)");

        libwinetap_free_recv_handler_container(container);
    }

    return NULL;
}

static void send_test_message(struct libwinetap_struct *s)
{
    struct message *msg = get_test_message();

    // while (!libwinetap_is_authenticated(s)) {
    //     print_log(MSG_DBG, "Waiting for the %s to be authenticated\n",
    //               (s == server) ? "server" : "client");
    //     sleep_pthread(3, 0, NULL, NULL);
    // }

    if (msg && !libwinetap_send(s, msg, message_len(msg))) {
        print_message(msg, "(sender)");
    } else {
        print_log(MSG_DBG, "Failed to transmit a test message\n");
    }
}

static void launch_instance(void)
{
    struct libwinetap_config_struct server_config;
    libwinetap_config_init(&server_config, dest_sunpath, src_sunpath, do_recv_handler, (void*)(0));

    struct libwinetap_config_struct client_config;
    libwinetap_config_init(&client_config, src_sunpath, dest_sunpath, do_recv_handler, (void*)(1));

    if (!strcmp(mode, "self")) {
        server = libwinetap_new(&server_config);
        sleep_pthread(5, 0, NULL, NULL);

        client = libwinetap_new(&client_config);
        sleep_pthread(5, 0, NULL, NULL);

        // Wait for the server and client to connect each other
        while (!libwinetap_is_connected(server) || !libwinetap_is_connected(client)) {
            print_log(MSG_DBG, "Retrying to connect to the local server...\n");
            sleep_pthread(1, 0, NULL, NULL);
        }

        send_test_message(server);
        send_test_message(client);

        libwinetap_wait(server);
        libwinetap_wait(client);
    }
    else if (!strcmp(mode, "normal")) {
        server = libwinetap_new(&server_config);
        libwinetap_wait(server);
    }
    else {
        print_log(MSG_ERR, "Unknown option\n");
    }
}

static int parse_arg(int argc, char **argv)
{
    const struct option long_options[] = {
            {"destination", required_argument, 0, 'd'},
            {"mode",      required_argument, 0, 'm'},
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
                          "Usage: ./test_libunserv --mode <self|normal> --source <path> --destination <path>\n");
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

    libwinetap_init();

    launch_instance();

    libwinewtap_exit();

    return 0;
}

#undef DEBUG_IDENTIFIER
