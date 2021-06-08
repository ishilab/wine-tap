/*
 * utils.c
 * wtap80211d - Netlink server to communicate with wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <net/if.h>

#include "utils.h"
#include "gc/gc.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libutils"

inline bool is_sys_little_endian(void)
{
#if defined(__LITTLE_ENDIAN__)
    return true;
#elif defined(__BIG_ENDIAN__)
    return false;
#else
    int i = 0x01;
    return !!(*((char*)&i));
#endif
}

inline bool is_sys_big_endian(void) {
#if defined(__LITTLE_ENDIAN__)
    return false;
#elif defined(__BIG_ENDIAN__)
    return true;
#else
    int i = 0x01;
    return !(*((char*)&i));
#endif
}

inline unsigned int change_bit_order_lsb2(unsigned int bits)
{
    return ((bits >> 1) ^ bits) & 0x01;
}

inline void swap(void* a, void* b, size_t size) {
    unsigned char *__a = (unsigned char*)a, *__b = (unsigned char*)b;
    do {
        unsigned char __tmp = *__a;
        *__a++ = *__b;
        *__b++ = __tmp;
    } while (--size > 0);
}

inline void release_memory(void *p) {
    free(*(void**)p);
}

inline char* copy_ifname(char *dst, const char *src)
{
    memset(dst, 0, IFNAMSIZ);
    return strncpy(dst, src, IFNAMSIZ - 1);
}

// Timer function helpers

//struct libutils_ratelimit_state {
//    struct timespec prev;
//    struct timespec next;
//    struct timespec interval;
//
//    pthread_mutex_t mutex;
//};

//inline void libutils_ratelimit_state_init(struct libutils_ratelimit_state *state,
//        struct timespec *interval)
//{
//    pthread_mutex_init(&state->mutex);
//
//    if (config) {
//        memcpy(&state->interval, interval, sizeof(struct timespec));
//    } else {
//        state->interval.tv_sec = 5;
//        state->interval.tv_nsec = 0;
//    }
//
//    clock_gettime(CLOCK_REALTIME, &state->prev_wakeup_time);
//    state->next.tv_sec = state->prev.tv_sec + state->interval.tv_sec;
//    state->next.tv_nsec = state->prev.tv_nsec + state->interval.tv_nsec;
//}

//bool ratelimit_trigger(struct libutils_ratelimit_state *state)
//{
//    // Todo: Implement it
//    return true;
//}

inline unsigned long long int diff_timespec(struct timespec start, struct timespec end)
{
    return (unsigned long long int)(
            ((end.tv_sec - start.tv_sec) * 1000 * 1000 * 1000) + (end.tv_nsec - start.tv_nsec));
}

void get_timestr_unix(char *str, size_t len)
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_REALTIME, &ts);
    snprintf(str, len, "%10ld.%09ld", ts.tv_sec, ts.tv_nsec);
    // snprintf(str, len, "+%019llu", gettime_rdtsc());
}

char* get_timestr(char *str, size_t len)
{
    struct timeval tv = {0};
    struct tm *tm = NULL;
    char buf[64] = {0};
    size_t buflen = 0;

    if (len < ARRAY_SIZE(buf))
        return NULL;

    /* buflen = strftime(buf, ARRAY_SIZE(buf), "%Y%m%d%H%M%S+%L", tm); */
    /* if (buflen == 0) */
        /* return NULL; */
    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    buflen = snprintf(buf, ARRAY_SIZE(buf), "%04d%02d%02d%02d%02d%02d.%03d",
                    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                    tm->tm_hour, tm->tm_min, tm->tm_sec,
                    (int)tv.tv_usec / 1000);

    memcpy(str, buf, buflen);

    return str;
}

int sleep_pthread(long sec, long nsec, pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    pthread_mutex_t __mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t __cond = PTHREAD_COND_INITIALIZER;
    struct timespec ts;
    int rc = 0;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += sec;
    ts.tv_nsec += nsec;

    pthread_mutex_lock((mutex) ? : &__mutex);
    do {
        rc = pthread_cond_timedwait((cond) ? : &__cond, (mutex) ? : &__mutex, &ts);
    } while (rc == 0);
    pthread_mutex_unlock((mutex) ? : &__mutex);

    return (rc == ETIMEDOUT) ? 0 : rc;
}

int nanosleep_restrict(long nsec)
{
    struct timespec req = { .tv_sec = 0, .tv_nsec = nsec };
    struct timespec rem = {0};
    int err = 0;

    while ((err = nanosleep(&req, &rem)) < 0 && errno == EINTR)
        memcpy(&req, &rem, sizeof(struct timespec));

    return err;
}

inline int microsleep_restrict(long usec)
{
    return nanosleep_restrict(usec * 1000);
}

inline int millisleep_restrict(long msec)
{
    return nanosleep_restrict(msec * 1000000);
}

inline int is_file_exist(const char *filename)
{
    //return stat(filename, (struct stat []){0}) == 0;
    return access(filename, F_OK) == 0;
}


// Pthread utilities
inline int pthread_mutex_init_errorcheck(pthread_mutex_t *mutex)
{
    int rc = 0;

#ifdef ENABLE_DEBUG
    pthread_mutexattr_t attr;

    if ((rc = pthread_mutexattr_init(&attr)) < 0)
        return rc;

    if ((rc = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)) < 0)
        return rc;

    pthread_mutex_init(mutex, &attr);

    pthread_mutexattr_destroy(&attr);
#else
    pthread_mutex_init(mutex, NULL);
#endif

    return rc;
}


// File descriptor utilities
int get_sockinfo(int sock, int optname)
{
    int type;
    socklen_t len = sizeof(type);

    if (getsockopt(sock, SOL_SOCKET, optname, &type, &len) < 0)
        goto error;

    return type;

error:
    print_log(MSG_ERR, "%s (code: %d)\n", strerror(errno), errno);
    return -1;
}

inline int get_socktype(int sock)
{
    return get_sockinfo(sock, SO_TYPE);
}

inline int get_sockproto(int sock)
{
    return get_sockinfo(sock, SO_PROTOCOL);
}

// Todo: Upgrade the timer resolution
int get_bytes_on_fdbuf(int fd, int flag)
{
    int bytes = 0;
    while (!bytes && ioctl(fd, flag, &bytes) >= 0)
        sleep_pthread(1, 0, NULL, NULL);
    return bytes;
}

inline int get_bytes_ready2read(int fd)
{
    return get_bytes_on_fdbuf(fd, FIONREAD);
}

struct sockaddr* allocate_sockaddr(int sock, socklen_t *len)
{
    struct sockaddr* addr = NULL;
    int proto = get_sockproto(sock);

    print_log(MSG_DBG, "proto = %d (AF_UNIX= %d)\n", proto, AF_INET);

    if (proto == AF_INET) {
        addr = (struct sockaddr*)gc_calloc(1, sizeof(struct sockaddr_in));
        *len = sizeof(struct sockaddr_in);
    }
    else if (proto == AF_UNIX) {
        addr = (struct sockaddr*)gc_calloc(1, sizeof(struct sockaddr_un));
        *len = sizeof(struct sockaddr_un);
    }
    else {
        *len = 0;
    }

    return addr;
}

int recv_all_stream(int sock, void *data, int len)
{
    /* @reminder is bytes already received. */
    int total = 0;

    while (total < len) {
        int recv_bytes = 0;
        if ((recv_bytes = recv(sock, (void*)((char*)data + total),
                               len - total, 0)) < 1) {
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
    print_log(MSG_DBG, "[libunserv] %s (code: %d)\n", strerror(errno), errno);
    return -1;
}

int recv_all_dgram(int sock, void *data, int len, struct sockaddr* addr, socklen_t *addrlen)
{
    /* @reminder is bytes already received. */
    int total = 0;

    while (total < len) {
        int recv_bytes = 0;
        if ((recv_bytes = recvfrom(sock, (void*)((char*)data + total), len - total, 0, addr, addrlen)) < 1) {
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
    print_log(MSG_DBG, "[libunserv] %s (code: %d)\n", strerror(errno), errno);
    return -1;
}

int send_all_stream(int sock, const void *data, size_t len)
{
    /* @reminder is bytes not sent yet. */
    size_t reminder = len;

    while (reminder > 0) {
        int sent_bytes = 0;
        if ((sent_bytes = send(sock, (void*)((char*)data + len - reminder), reminder, 0)) < 0)
            goto error;

        reminder -= sent_bytes;
    }

    return 0;

error:
    print_log(MSG_DBG, "[libunserv] %s (code: %d)\n", strerror(errno), errno);
    return reminder;
}

int send_all_dgram(int sock, void *data, size_t len, struct sockaddr *addr, socklen_t addrlen)
{
    /* @reminder is bytes not sent yet. */
    size_t reminder = len;

    while (reminder > 0) {
        int sent_bytes = 0;
        if ((sent_bytes = sendto(sock, (void*)((char*)data + len - reminder), reminder, 0, addr, addrlen)) < 0)
            goto error;

        reminder -= sent_bytes;
    }

    return 0;

error:
    print_log(MSG_DBG, "[libunserv] %s (code: %d)\n", strerror(errno), errno);
    return reminder;
}


// Garbage collection utilities

// Memo: Add BSD9TCP_INCLUDED guard due to conflicts with bsd9tcp symbols of Scenargie source
// #ifndef BSD9TCP_INCLUDED
// # ifndef ENABLE_DEBUG
// #  define malloc(size) GC_malloc((size))
// #  define realloc(p, size) GC_realloc((p), (size))
// #  define calloc(m, n) GC_malloc(((m)*(n)))
// # else
// #  define malloc(size) GC_debug_malloc((size), __FILE__, __LINE__)
// #  define realloc(p, size) GC_debug_realloc((p), (size), __FILE__, __LINE__)
// #  define calloc(m, n) GC_debug_malloc(((m)*(n)), __FILE__, __LINE__)
// # endif

__attribute__((malloc)) inline void* gc_malloc(size_t __size) {
#if defined(ENABLE_GARBAGE_COLLECTION) && !defined(ENABLE_SMART_POINTER)
    return GC_malloc(__size);
#else
    return malloc(__size);
#endif
}

__attribute__((malloc)) inline void* gc_calloc(size_t __nmemb, size_t __size) {
#if defined(ENABLE_GARBAGE_COLLECTION) && !defined(ENABLE_SMART_POINTER)
    void *ptr = GC_malloc(__nmemb * __size);
    memset(ptr, 0, __nmemb * __size);
    return ptr;
#else
    return calloc(__nmemb, __size);
#endif
}

__attribute__((malloc)) inline void* gc_realloc(void *__ptr, size_t __size) {
#if defined(ENABLE_GARBAGE_COLLECTION) && !defined(ENABLE_SMART_POINTER)
    return GC_realloc(__ptr, __size);
#else
    return realloc(__ptr, __size);
#endif
}

inline void gc_free(void *__ptr) {
#if defined(ENABLE_GARBAGE_COLLECTION) || defined(ENABLE_SMART_POINTER)
    // Nothing done because of libgc and libcsptr do not need a call to free() manualy.
#else
    free(__ptr);
#endif
}

#undef DEBUG_IDENTIFIER
