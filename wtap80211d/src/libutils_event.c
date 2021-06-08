//
// Created by Arata Kato on 2019-09-10.
//

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "event2/event.h"
#include "event2/thread.h"
#include "utils.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libutils_event"

#define libutils_event_priv_of(s) ((struct libutils_event_priv*)&((s)->priv))

// Memo: EV_FEATURE_EARLY_CLOSE is not defined in xenial64's event2
#ifndef EV_FEATURE_EARLY_CLOSE
#define EV_FEATURE_EARLY_CLOSE 0x08
#endif

static struct {
    pthread_mutex_t mutex;
    bool is_initialized;
} libutils_event ;

struct libutils_event_priv {
    struct event_base *event_base;
    struct event *stack[MAX_EVENTS];
    size_t count;

    pthread_t dispatch_thread;
    // pthread_mutex_t dispatch_mutex;
    // pthread_cond_t dispatch_cond;
    bool is_dispatched;
    bool is_canceled;

    pthread_mutex_t mutex;

};

static void debug_priv_mapping_info(const struct libutils_event_struct *s)
{
    const struct libutils_event_priv *priv = libutils_event_priv_of(s);
    print_log(MSG_DBG,
            "s: %p, priv: %p, "
            STRUCTURE_MEMBER_MAP_FMT(event_base) ", "
            STRUCTURE_MEMBER_MAP_FMT(stack) ", "
            STRUCTURE_MEMBER_MAP_FMT(count) ", "
            STRUCTURE_MEMBER_MAP_FMT(dispatch_thread) ", "
            //"dispatch_mutex: %p+%lx (%p), dispatch_cond: %p+%lx (%p), "
            STRUCTURE_MEMBER_MAP_FMT(is_dispatched) ", "
            STRUCTURE_MEMBER_MAP_FMT(mutex) "\n",
            // ===== format string ends here. =====
            s, priv,
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libutils_event_priv, event_base),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libutils_event_priv, stack),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libutils_event_priv, count),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libutils_event_priv, dispatch_thread),
            //priv, offsetof(struct libutils_event_priv, dispatch_mutex), &priv->dispatch_mutex,
            //priv, offsetof(struct libutils_event_priv, dispatch_cond), &priv->dispatch_cond,
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libutils_event_priv, is_dispatched),
            STRUCTURE_MEMBER_MAP_ARG(priv, struct libutils_event_priv, mutex));
}

static void push_event(struct libutils_event_priv *priv, struct event *ev)
{
    if (priv && ev && priv->count < MAX_EVENTS) {
        priv->count++;
        priv->stack[priv->count - 1] = ev;
    }
}

// Memo: pop_event() must be called only in libutils_event_release()
static struct event* pop_event(struct libutils_event_priv *priv)
{
    struct event *ev = NULL;

    if (priv && priv->count > 0) {
        ev = priv->stack[priv->count - 1];
        priv->count--;
    }

    return ev;
}

static void inactivate_events(struct libutils_event_priv *priv, int sock)
{
    if (!priv)
        return ;

    for (size_t i = 0; i < priv->count; ++i) {
        struct event *e = priv->stack[i];
        int fd = event_get_fd(e);

        if (fd == sock)
            event_del(e);
    }
}

static inline void priv_lock(struct libutils_event_priv *priv)
{
    pthread_mutex_lock(&priv->mutex);
}

static inline void priv_unlock(struct libutils_event_priv *priv)
{
    pthread_mutex_unlock(&priv->mutex);
}

void libutils_event_shutdown(struct libutils_event_struct *s, int fd)
{
    struct libutils_event_priv *priv = libutils_event_priv_of(s);
    inactivate_events(priv, fd);
}

int libutils_event_register_sigev(struct libutils_event_struct *s,
        short int flags, void (*handler)(int, short, void*), void *arg)
{
    if (!s || !handler)
        goto error;

    struct libutils_event_priv *priv = libutils_event_priv_of(s);

    // Locked section starts here.
    priv_lock(priv);

    if (priv->is_canceled)
        goto error_in_lock;

    struct event *ev = evsignal_new(priv->event_base, flags, handler, arg);
    if (!ev || event_add(ev, NULL) < 0) {
        priv_unlock(priv);
        print_log(MSG_DBG, "Adding a new event failed\n");
        goto error_in_lock;
    }

    priv_unlock(priv);
    // Locked section ends here.

    print_log(MSG_DBG,
            "New signal event registered (event_base: %p, handler: %p, arg: %p)\n",
            priv->event_base, handler, arg);

    return 0;

error_in_lock:
    priv_unlock(priv);
error:
    print_log(MSG_DBG,
            "Registering a new event failed (struct: %p, handler: %p)\n", s, handler);
    return -1;
}

int libutils_event_register(struct libutils_event_struct *s,
        int sock, short int flags, void (*handler)(int, short, void*), void *arg)
{
    if (!s || !handler)
        goto error;

    struct libutils_event_priv *priv = libutils_event_priv_of(s);

    // Locked section starts here.
    priv_lock(priv);

    if (priv->is_canceled)
        goto error_in_lock;

    struct event *ev = event_new(priv->event_base, sock, flags, handler, arg);
    if (!ev || event_add(ev, NULL) < 0) {
        priv_unlock(priv);
        print_log(MSG_DBG, "Adding a new event failed\n");
        goto error_in_lock;
    }

    push_event(priv, ev);

    priv_unlock(priv);
    // Locked section ends here.

    print_log(MSG_DBG, "New event registered (event_base: %p, handler: %p, arg: %p)\n",
            priv->event_base, handler, arg);

    return 0;

error_in_lock:
    priv_unlock(priv);
error:
    print_log(MSG_DBG, "Registering a new event failed (structure: %p, handler: %p)\n", s, handler);
    return -1;
}

// libutils_event_wait stops the process of the caller thread until
// it receives the do_event_loop's termination notification.
void libutils_event_wait(struct libutils_event_struct *s)
{
    if (!s)
        return ;

    struct libutils_event_priv *priv = libutils_event_priv_of(s);

    // pthread_mutex_lock(&priv->dispatch_mutex);

    // // Wait for do_event_loop's termination notification
    // pthread_cond_wait(&priv->dispatch_cond, &priv->dispatch_mutex);

    // pthread_mutex_unlock(&priv->dispatch_mutex);

    pthread_join(priv->dispatch_thread, NULL);
}

static void do_event_loop_terminate_handler(void *arg)
{
    print_log(MSG_DBG, "event loop handler terminated. Cleaning up...\n");
}

static void* do_event_loop(void *arg)
{
    struct libutils_event_priv *priv = (struct libutils_event_priv*)arg;
    int rc = 0;

    print_log(MSG_DBG, "event_loop_handler launched (priv: %p, event_base's addr: %p)\n",
            priv, priv->event_base);

    // Let this thread to be released immediately when pthread_cancel() is called
    // pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &(int){0});
    // pthread_detach(pthread_self());

    if (priv) {
        //pthread_mutex_lock(&priv->dispatch_mutex);
        // rc = event_base_dispatch(priv->event_base);
        rc = event_base_loop(priv->event_base, EVLOOP_NO_EXIT_ON_EMPTY);
        //pthread_mutex_unlock(&priv->dispatch_mutex);

        //Inform the handler's termination to all threads that wait it.
        //pthread_cond_broadcast(&priv->dispatch_cond);
    }

    print_log(MSG_DBG,
            "event_loop_handler terminated (reason: %s, code: %d)\n",
            (rc < 0) ? "internal error" : ((rc > 0) ? "no active event registered" : "all events terminated"), rc);

    return NULL;
}

void libutils_event_dispatch(struct libutils_event_struct *s)
{
    if (s) {
        struct libutils_event_priv *priv = libutils_event_priv_of(s);

        priv_lock(priv);

        if (!priv->is_dispatched) {
            pthread_create(&priv->dispatch_thread, NULL, do_event_loop, priv);
            priv->is_dispatched = true;
        }

        priv_unlock(priv);
    }
}

void libutils_event_loopbreak(struct libutils_event_struct *s)
{
    if (s) {
        struct libutils_event_priv *priv = libutils_event_priv_of(s);

        priv_lock(priv);

        priv->is_canceled = true;

        if (priv->is_dispatched) {
            // event_base_loopbreak(priv->event_base);
            event_base_loopexit(priv->event_base, &(struct timeval){1L, 0L});
            // pthread_cancel(priv->dispatch_thread);
            priv->is_dispatched = false;
        }

        priv_unlock(priv);
    }
}

struct libutils_event_struct* libutils_event_new(void)
{
    struct libutils_event_struct *s = (struct libutils_event_struct*)gc_calloc(1,
            sizeof(struct libutils_event_struct) + sizeof(struct libutils_event_priv));
    if (!s)
        return NULL;

    struct libutils_event_priv *priv = libutils_event_priv_of(s);

    priv->is_canceled = false;
    priv->is_dispatched = false;

    pthread_mutex_init(&priv->mutex, NULL);
    // pthread_mutex_init(&priv->dispatch_mutex, NULL);
    // pthread_cond_init(&priv->dispatch_cond, NULL);

    // struct event_config *event_config = event_config_new();
    // event_config_require_features(event_config, EV_FEATURE_EARLY_CLOSE);
    // if (!(priv->event_base = event_base_new_with_config(event_config)))
    //     goto error;
    // if (!(priv->event_base = event_init()))
    if (!(priv->event_base = event_base_new()))
        goto error;

#ifdef ENABLE_DEBUG
    debug_priv_mapping_info(s);
#endif

    print_log(MSG_DBG,
            "New event basement created (priv: %p, priv->event_base: %p)\n",
            priv, priv->event_base);

    return s;

error:
    free(s);
    print_log(MSG_DBG, "Error occured while creating new event basement\n");
    return NULL;
}

void libutils_event_release(struct libutils_event_struct *s)
{
    if (!s)
        return ;

    struct libutils_event_priv *priv = libutils_event_priv_of(s);

    print_log(MSG_DBG, "Stopping event handler (event_base: %p)\n", priv->event_base);

    //event_base_loopbreak(priv->event_base);
    libutils_event_loopbreak(s);

    for (size_t i = 0; i < priv->count; ++i) {
        struct event *ev = pop_event(priv);
        if (ev)
            event_free(ev);
    }

    event_base_free(priv->event_base);

    free(s);
}

void libutils_event_init(void)
{
    if (!libutils_event.is_initialized) {
        pthread_mutex_init(&libutils_event.mutex, NULL);
        libutils_event.is_initialized = true;
        evthread_use_pthreads();
    }
}

void libutils_event_exit(void)
{
    // Nothing
}

#undef DEBUG_IDENTIFIER
