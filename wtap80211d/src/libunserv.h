/*
 * libunserv.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef LIBUNSERV_H
#define LIBUNSERV_H

#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SUNPATH_LEN ((size_t)108)

#define libunserv_len(hdr) (sizeof(struct libunserv_msghdr) + (hdr)->len)

#define libunserv_data(hdr) ((char*)(hdr) + sizeof(struct libunserv_msghdr))

struct libunserv_config_struct {
    int listen_backlog;

    void* (*do_recv_handler)(void*);
    void (*ev_recv_handler)(int, short, void*);
    void* arg;
    bool is_persist;

    char dest_path[SUNPATH_LEN + 1];
    char src_path[SUNPATH_LEN + 1];
};

struct libunserv_client_struct {
    pthread_t self_thread;
    struct sockaddr_un dest_addr;
    struct sockaddr_un src_addr;
    int sock;

    void (*ev_recv_handler)(int, short, void*);
    void* user_arg;

    struct event_base *event_base;
};

struct libunserv_msghdr {
    uint32_t type;
    uint32_t len;
    char data[0];
} __attribute__((aligned(2), packed));

struct libunserv_struct {
    unsigned int status;
    char priv[0];
};

extern void libunserv_forward_module(int sock, short int flags, void *arg);

extern void libunserv_echo_module(int sock, short int flags, void *arg);

/*
 * Debug module for checking incoming messages
 * formatted with libunserv_msghdr
 */
extern void libunserv_debug_module(int sock, short int flags, void *arg);

extern bool libunserv_is_connected(struct libunserv_struct *s);

extern int libunserv_get_sock(struct libunserv_struct *s);

extern int libunserv_recv(struct libunserv_client_struct *cs, void *buf, size_t len);

extern int libunserv_recv_all(struct libunserv_struct *s, void *data, int len);

extern int libunclient_recv_all(struct libunserv_client_struct *cs, void *data, int len);

extern int libunserv_send(struct libunserv_client_struct *cs, void *data, size_t len);

extern int libunserv_send_all(struct libunserv_struct *s, const void *data, int len);

extern int libunclient_send_all(struct libunserv_client_struct *cs, void *data, int len);

extern int libunserv_send_with_header(struct libunserv_client_struct *cs, void *data, size_t len, uint32_t type);

extern struct libunserv_client_struct* libunserv_connect(struct libunserv_config_struct *config, int retry_times);

extern void libunserv_disconnect(struct libunserv_client_struct *cs);

extern void libunserv_shutdown(struct libunserv_struct *s);

extern void libunserv_wait(struct libunserv_struct *s);

extern void libunserv_client_wait(struct libunserv_client_struct *cs);

extern struct libunserv_client_struct* libunserv_client_new(struct libunserv_config_struct *config);

extern void libunserv_reconnect(struct libunserv_struct *s);

extern struct libunserv_struct* libunserv_new(struct libunserv_config_struct *config);

extern void libunserv_release(struct libunserv_struct *s);

extern int libunserv_init(void);

extern void libunserv_exit(void);

#endif /* LIBUNSERV_H */
