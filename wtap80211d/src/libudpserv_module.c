//
// Created by Arata Kato on 2019-07-30.
//

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "utils.h"
#include "libudpserv.h"

static int recv_all(int sock, void *data, int len, struct sockaddr *src_addr)
{
    socklen_t addrlen = sizeof(*src_addr);
    int total = 0;

    while (total < len) {
        int recv_bytes = recvfrom(sock, (void*)((char*)data + total),
                                  len - total, 0, src_addr, &addrlen);

        if (recv_bytes < 1) {
            if (recv_bytes == 0)
                return 0;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            else
                goto error;
        }

        total += recv_bytes;
    }

    return total;

error:
    print_log(MSG_DBG, "[libudpserv] %s (code: %d)\n", strerror(errno), errno);
    return -1;
}

static int recv_all_restrict(int sock, void *data, size_t len,
                             struct sockaddr *src_addr, struct timespec *timeout)
{
    socklen_t addrlen = sizeof(*src_addr);
    size_t total = 0;
    fd_set rfds;
    int fd_status = 0;

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    do {
        fd_status = pselect(sock + 1, &rfds, NULL, NULL, timeout, NULL);

        if (FD_ISSET(sock, &rfds)) {
            int recv_bytes = recvfrom(sock, (void*)((char*)data + total),
                                      len - total, 0, src_addr, &addrlen);
            if (recv_bytes < 1) {
                if (recv_bytes == 0)
                    return 0;
                else if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                else
                    goto error;
            }

            total += recv_bytes;
        } else if (fd_status == 0){
            print_log(MSG_DBG, "[libudpserv] Receiving a datagram is interrupted by timeout");
            break;
        } else if (fd_status < 0){
            goto error;
        }
    } while (total < len);

    return total;

error:
    print_log(MSG_DBG, "[libudpserv] %s (code: %d)\n", strerror(errno), errno);
    return -1;
}

static int send_all(int sock, void *data, size_t len, const struct sockaddr *dest_addr)
{
    size_t reminder = len;

    while (reminder > 0) {
        print_log(MSG_DBG, "[libudpserv] len = %zu.\n", len);

        int sent_bytes = sendto(sock, (void*)((char*)data + len - reminder), reminder, MSG_DONTWAIT,
                                dest_addr, sizeof(*dest_addr));
        if (sent_bytes < 0)
            goto error;

        reminder -= sent_bytes;

        print_log(MSG_DBG, "[libudpserv] %d/%zu bytes sent.\n", sent_bytes, len);
    }

    print_log(MSG_DBG, "[libudpserv] total %zu bytes sent.\n", len);

    return len - reminder;

error:
    print_log(MSG_DBG, "[libudpserv] %s (code: %d)\n", strerror(errno), errno);
    return reminder;
}

static int send_all_restrict(int sock, void *data, size_t len,
                             const struct sockaddr *dest_addr, struct timespec *timeout)
{
    int reminder = len;
    fd_set sfds;

    FD_ZERO(&sfds);
    FD_SET(sock, &sfds);

    do {
        int rc = pselect(sock + 1, NULL, &sfds, NULL, timeout, NULL);

        if (FD_ISSET(sock, &sfds)) {
            int sent_bytes = sendto(sock, (void*)((char*)data + len - reminder), reminder, MSG_DONTWAIT,
                                    dest_addr, sizeof(*dest_addr));
            if (sent_bytes < 0)
                goto error;

            reminder -= sent_bytes;
        } else if (rc == 0){
            print_log(MSG_DBG, "[libudpserv] Sending a datagram is interrupted by timeout");
            break;
        } else if (rc < 0){
            goto error;
        }
    } while (reminder > 0);

    return len - reminder;

error:
    print_log(MSG_DBG, "[libudpserv] %s (code: %d)\n", strerror(errno), errno);
    return -1;
}

int libudpclient_recv_all(struct libudpserv_client_struct *cs, void *data, size_t len)
{
    return recv_all(cs->sock, data, len, (struct sockaddr*)&cs->addr);
}

int libudpclient_recv_all_restrict(struct libudpserv_client_struct *cs, void *data, size_t len,
                                   struct timespec *timeout)
{
    return recv_all_restrict(cs->sock, data, len, (struct sockaddr*)&cs->addr, timeout);
}

int libudpclient_send_all(struct libudpserv_client_struct *cs, void *data, size_t len)
{
    return send_all(cs->sock, data, len, (const struct sockaddr*)&cs->addr);
}

int libudpclient_send_all_restrict(struct libudpserv_client_struct *cs, void *data, size_t len,
                                   struct timespec *timeout)
{
    return send_all_restrict(cs->sock, data, len, (const struct sockaddr*)&cs->addr, timeout);
}

int libudpserv_recv_all(int sock, void *data, size_t len, struct sockaddr *addr)
{
    return recv_all(sock, data, len, addr);
}

int libudpserv_recv_all_restrict(int sock, void *data, size_t len, struct sockaddr *addr, struct timespec *timeout)
{
    return recv_all_restrict(sock, data, len, addr, timeout);
}

int libudpserv_send_all(int sock, void *data, size_t len, struct sockaddr *addr)
{
    return send_all(sock, data, len, addr);
}

int libudpserv_send_all_restrict(int sock, void *data, size_t len, struct sockaddr *addr, struct timespec *timeout)
{
    return send_all_restrict(sock, data, len, addr, timeout);
}
