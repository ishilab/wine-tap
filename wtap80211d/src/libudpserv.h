//
// Created by Arata Kato on 2019-07-30.
//

#ifndef WINE_TAP_LIBUDPSERV_H
#define WINE_TAP_LIBUDPSERV_H

#include <sys/types.h>
#include <arpa/inet.h>

struct libudpserv_config_struct {
    uint32_t port;

    void* (*func)(int, void*);
    void* arg;

    // Client mode use only
    short int family;
    char dest_addr[IPADDR_LEN];
};

struct libudpserv_client_struct {
    pthread_t self_thread;
    struct sockaddr_in addr;
    int sock;

    void* (*user_handler)(int, void*);
    void* user_arg;
};

struct libudpserv_struct {
    unsigned int type;
    char priv[0];
};

extern int libudpclient_recv_all(struct libudpserv_client_struct *cs, void *data, size_t len);

extern int libudpclient_recv_all_restrict(struct libudpserv_client_struct *cs, void *data, size_t len,
                                          struct timespec *timeout);

extern int libudpclient_send_all(struct libudpserv_client_struct *cs, void *data, size_t len);

extern int libudpclient_send_all_restrict(struct libudpserv_client_struct *cs, void *data, size_t len,
                                          struct timespec *timeout);

extern int libudpserv_recv_all(int sock, void *data, size_t len, struct sockaddr *addr);

extern int libudpserv_recv_all_restrict(int sock, void *data, size_t len,
                                        struct sockaddr *addr, struct timespec *timeout);

extern int libudpserv_send_all(int sock, void *data, size_t len, struct sockaddr *addr);

extern int libudpserv_send_all_restrict(int sock, void *data, size_t len,
                                        struct sockaddr *addr, struct timespec *timeout);

extern int libudpserv_broadcast_all(void *data, size_t len, int port);

extern struct libudpserv_client_struct*
        libudpclient_setup(struct libudpserv_config_struct *config);

extern struct libudpserv_struct*
        libudpserv_new(struct libudpserv_config_struct *config);

extern void libudpserv_release(struct libudpserv_struct *s);

extern void libudpserv_wait(struct libudpserv_struct *s);

extern void libudpserv_init(void);

extern void libudpserv_exit(void);

#endif //WINE_TAP_LIBUDPSERV_H
