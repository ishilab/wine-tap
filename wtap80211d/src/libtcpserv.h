/*
 * libtcpserv.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef LIBTCPSERV_H
#define LIBTCPSERV_H

#include <sys/socket.h>
#include <arpa/inet.h>

#define libtcpserv_len(hdr) (sizeof(struct libtcpserv_msghdr) + (hdr)->len)

#define libtcpserv_data(hdr) ((char*)(hdr) + sizeof(struct libtcpserv_msghdr))

#define LIBTCPSERV_PAYLOAD_LENGTH_DEFAULT  (size_t)(4096)

struct libtcpserv_config_struct {
    uint32_t port;
    int listen_backlog;

    void* (*func)(int, void*);
    void* arg;

    // Client mode use only
    short int family;
    char dest_addr[IPADDR_LEN];
};

struct libtcpserv_client_struct {
    pthread_t self_thread;
    struct sockaddr_in addr;
    int sock;

    pthread_mutex_t mutex;

    void* (*user_handler)(int, void*);
    void* user_arg;

    bool is_connected;
};

struct libtcpserv_msghdr {
    uint32_t type;
    uint32_t len;
    char data[0];
} __attribute__((aligned(2), packed));

struct libtcpserv_struct {
    unsigned int status;
    char priv[0];
};

extern void* libtcpserv_forward_module(int sock, void *arg);

extern void* libtcpserv_echo_module(int sock, void *arg);

/*
 * Debug module for checking incoming messages
 * formatted with libtcpserv_msghdr
 */
extern void* libtcpserv_debug_module(int sock, void *arg);

extern int libtcpserv_recv(struct libtcpserv_client_struct *cs, void *buf, size_t len);

extern int libtcpserv_recv_all(int sock, void *data, int len);

extern int libtcpclient_recv_all(struct libtcpserv_client_struct *cs, void *data, int len);

extern int libtcpserv_send(struct libtcpserv_client_struct *cs, void *data, size_t len);
extern int libtcpserv_send_all(int sock, void *data, int len);

extern int libtcpclient_send_all(struct libtcpserv_client_struct *cs, void *data, int len);

extern int libtcpserv_send_with_header(struct libtcpserv_client_struct *cs, void *data, size_t len, uint32_t type);

extern struct libtcpserv_client_struct* libtcpserv_connect(struct libtcpserv_config_struct *config);

extern void libtcpserv_disconnect(struct libtcpserv_client_struct *cs);

extern void libtcpserv_wait(struct libtcpserv_struct *s);

extern struct libtcpserv_struct* libtcpserv_new(struct libtcpserv_config_struct *config);

extern int libtcpserv_init(void);

extern void libtcpserv_exit(struct libtcpserv_struct *s);

#endif /* LIBTCPSERV_H */
