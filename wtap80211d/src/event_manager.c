/*
 * event.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <pthread.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "utils.h"
#include "event_manager.h"

static struct event_manager_struct {
    struct event_base *event_base;
    struct event *event_queue[MAX_EVENT];
    int length;

    pthread_mutex_t mutex;

    unsigned int status;
} ev_st;

static void event_manager_lock(void)
{
    pthread_mutex_lock(&ev_st.mutex);
}

static void event_manager_unlock(void)
{
    pthread_mutex_unlock(&ev_st.mutex);
}

static void push_event(struct event *ev)
{
    if (ev_st.length < MAX_EVENT && ev) {
        ev_st.length++;
        ev_st.event_queue[ev_st.length - 1] = ev;
    }
}

static struct event* pop_event(void)
{
    struct event *ev = NULL;

    if (ev_st.length > 0) {
        ev = ev_st.event_queue[ev_st.length - 1];
        ev_st.length--;
    }

    return ev;
}

int register_signal_event(int flag, void (*callback)(int, short, void*), void *arg)
{
    struct event *ev = NULL;
    int err = 0;

    if (!(ev = evsignal_new(ev_st.event_base, flag, callback, arg)))
        return -ENOMEM;

    event_manager_lock();

    event_add(ev, NULL);
    push_event(ev);

    event_manager_unlock();

    return 0;
}

int register_timer_event(void (*callback)(int, short, void*), void *arg,
                         long int sec, long int usec)
{
    struct event *ev = NULL;

    if (!(ev = evtimer_new(ev_st.event_base, callback, arg)))
        return -ENOMEM;

    event_manager_lock();
    struct timeval tv = { .tv_sec = sec, .tv_usec = usec };
    evtimer_add(ev, &tv);
    event_manager_unlock();

    return 0;
}

int register_event(int fd, int flags, void (*callback)(int, short, void*), void *arg)
{
    struct event *ev = NULL;

    if (!(ev = (struct event *)gc_malloc(sizeof(struct event))))
        return -ENOMEM;

    event_set(ev, fd, flags, callback, arg);
    event_base_set(ev_st.event_base, ev);

    event_manager_lock();

    event_add(ev, NULL);
    push_event(ev);

    event_manager_unlock();

    return 0;
}

void event_manager_dispatch(void)
{
    event_base_dispatch(ev_st.event_base);
}

int event_manager_init(void)
{
    struct event_base *event_base = NULL;

    pthread_mutex_init(&ev_st.mutex, NULL);

    if (!(event_base = event_init()))
        return -ENOMEM;

    ev_st.event_base = event_base;
    return 0;
}

void event_manager_exit(void)
{
    int i;

    event_base_loopbreak(ev_st.event_base);

    /*
     * for (i = 0; i < ev_st.length; ++i)
     *     free(ev_st.event_queue[i]);
     */

    event_base_free(ev_st.event_base);
}
