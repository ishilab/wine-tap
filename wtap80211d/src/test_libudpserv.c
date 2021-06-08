//
// Created by Arata Kato on 2019-07-30.
//

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include "utils.h"
#include "libudpserv.h"

// Sample echo server
static void* server_handler(int sock, void *arg)
{
    struct sockaddr_in addr = {0};
    socklen_t addrlen = sizeof(addr);
    size_t bufsize = 1024;
    char *buf = NULL;

    if (!(buf = (char*)gc_malloc(sizeof(char) * bufsize)))
        return NULL;

    print_log(MSG_DBG, "[libudpserv] test server launched.\n");

    while (1) {
        ssize_t recv_bytes = recvfrom(sock, buf, bufsize, 0, (struct sockaddr*)&addr, &addrlen);
        if (recv_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            else
                break;
        }

        print_log(MSG_DBG, "Received: %zd bytes\n", recv_bytes);

        ssize_t sent_bytes = sendto(sock, buf, recv_bytes, 0, (struct sockaddr*)&addr, addrlen);
        if (sent_bytes < 0)
            break;
    }

    print_log(MSG_DBG, "[libudpserv] test server terminated.\n");

    gc_free(buf);

    return NULL;
}

int main(int argc, char **argv)
{
    struct libudpserv_struct *udpserv = NULL;
    struct libudpserv_config_struct config = {
        .port = 57210,
        .func = server_handler,
        .arg = NULL,
    };

    if (!(udpserv = libudpserv_new(&config)))
        return -1;

    libudpserv_wait(udpserv);

    libudpserv_release(udpserv);

    return 0;
}
