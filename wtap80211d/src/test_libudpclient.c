//
// Created by Arata Kato on 2019-07-30.
//

#include <assert.h>
#include <string.h>
#include "utils.h"
#include "libudpserv.h"

int main(int argc, char **argv)
{
    struct libudpserv_client_struct *cs = NULL;
    struct libudpserv_config_struct config = {
        .family = AF_INET,
        .port = 57210,
        .dest_addr = "127.0.0.1",
    };
    char *str = "Innovation distinguishes between a leader and a follower.";
    char buf[1024] = {0};

    if (!(cs = libudpclient_setup(&config))) {
        print_log(MSG_ERR, "[test_libudpclient] an error occurred while setting up\n");
        return -1;
    }

    int sent_size = libudpclient_send_all(cs, str, strlen(str) + 1);
    print_log(MSG_DBG, "[test_libudpclient] %d bytes sent.\n", sent_size);

    int recv_size = libudpclient_recv_all(cs, buf, sent_size);
    print_log(MSG_DBG, "[test_libudpclient] %d bytes received.\n", recv_size);

    print_log(MSG_INFO, "%s\n", buf);

    return 0;
}

