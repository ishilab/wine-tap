//
// Created by Arata Kato on 2019-08-05.
//

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WINE_TAP_LIBWINETAP_H
#define WINE_TAP_LIBWINETAP_H

#include <stdbool.h>
#include "libunserv.h"

struct libwinetap_config_struct {
    void* (*do_recv_handler)(void*);
    void* user_arg;

    char dest_path[SUNPATH_LEN + 1];
    char src_path[SUNPATH_LEN + 1];
};

struct libwinetap_recv_handler_container {
    // A user must free user_arg in the user-specified handler if it is set
    // because libwinetap does not know its allocated size.
    void *user_arg;

    struct message *msg;
};

struct libwinetap_struct {
    unsigned int id;
    char priv[0];
};

extern bool libwinetap_is_connected(struct libwinetap_struct *s);

extern bool libwinetap_is_authenticated(struct libwinetap_struct *s);

extern bool libwinetap_is_running(struct libwinetap_struct *s);

extern void libwinetap_free_recv_handler_container(struct libwinetap_recv_handler_container *container);

extern void libwinetap_config_init(struct libwinetap_config_struct *config,
        const char * dest_path, const char * src_path,
        void* (*do_recv_handler)(void*), void* user_arg);

// libwinetap_send() can only be called by the client.
extern int libwinetap_send(struct libwinetap_struct *s, const void *data, size_t len);

extern void libwinetap_wait(struct libwinetap_struct *s);

extern struct libwinetap_struct *libwinetap_new(struct libwinetap_config_struct *config);

extern void libwinetap_release(struct libwinetap_struct *s);

extern void libwinetap_init(void);

extern void libwinewtap_exit(void);

#endif //WINE_TAP_LIBWINETAP_H

#ifdef __cplusplus
}
#endif
