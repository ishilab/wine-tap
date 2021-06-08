/*
 * utils.h
 * wtap80211d - Netlink server to communicate with wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef UTILS_H
#define UTILS_H

// The macro symbols below must be defined before any standard library headers
#ifdef ENABLE_DEBUG

// __USE_GNU is necessary to use Dl_info and dladdr().
#ifndef __USE_GNU
#define __USE_GNU
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#endif /* ENABLE_DEBUG */

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <byteswap.h>

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifdef WARN_ON
# define WARN_ON(x)
#endif

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))

#if __BYTE_ORDER == __BIG_ENDIAN
# define cpu_to_le16 bswap_16
# define cpu_to_le32 bswap_32
# define cpu_to_le64 bswap_64
# define le16_to_cpu bswap_16
# define le32_to_cpu bswap_32
# define le64_to_cpu bswap_64
# define cpu_to_be16
# define cpu_to_be32
# define cpu_to_be64
# define be16_to_cpu
# define be32_to_cpu
# define be64_to_cpu
#else
# define cpu_to_le16
# define cpu_to_le32
# define cpu_to_le64
# define le16_to_cpu
# define le32_to_cpu
# define le64_to_cpu
# define cpu_to_be16 bswap_16
# define cpu_to_be32 bswap_32
# define cpu_to_be64 bswap_64
# define be16_to_cpu bswap_16
# define be32_to_cpu bswap_32
# define be64_to_cpu bswap_64
#endif

#ifndef BIT
# define BIT(nr) (1UL << (nr))
# define BIT_ULL(nr) (1ULL << (nr))
# define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
# define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
# define BIT_ULL_MASK(nr) (1ULL << ((nr) % BITS_PER_LONG_LONG))
# define BIT_ULL_WORD(nr) ((nr) / BITS_PER_LONG_LONG)
# define BITS_PER_BYTE 8
# define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#endif

bool is_sys_little_endian(void);

bool is_sys_big_endian(void);

extern unsigned int change_bit_order_lsb2(unsigned int bits);

#define declare_unused_variable(var) (void)(var)

#ifndef sizeof_bits
# define sizeof_bits(s) (sizeof(s) << 3)
#endif

#ifndef sizeof_field
# define sizeof_field(s, m) (sizeof((((s*)0)->m)))
#endif



// Address calculation utilities

#ifndef offsetof
#ifdef __cplusplus

// Todo: Redefine the section into another header file because it is so stupid.
// Disable C linkage temporarily
}

template<class P, class M>
size_t __cpp_offsetof(const M P::*member) {
    return (size_t)&(reinterpret_cast<P*>(0)->*member);
}

#define offsetof(type, name) __cpp_offsetof(&type::name)

// Enbale C linkage temporarily
extern "C" {

#else
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif /* __cplusplus */
#endif /* offsetof */

#ifndef container_of

#ifdef __cplusplus

// Todo: Redefine the section into another header file because it is so stupid.
// Disable C linkage temporarily
}

template<class P, class M>
P* __cpp_container_of(M* ptr, const M P::*member) {
    return (P*)((char*)ptr - __cpp_offsetof(member));
}

#define container_of(ptr, type, member) __cpp_container_of(ptr, &type::member)

// Enbale C linkage temporarily
extern "C" {

#else
/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:    the type of the container struct this is embedded in.
 * @member:    the name of the member within the struct.
 */
#define container_of(ptr, type, member) ({                     \
        const typeof(((type *)0)->member) * __mptr = (ptr);    \
        (type *)((char *)__mptr - offsetof(type, member)); })

#endif /* __cplusplus */

#endif /* container_of */

// General cleanup handler for pointers with the gcc cleanup attribute
extern void release_memory(void *p);

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(array) ((size_t)(sizeof(array) / sizeof(array[0])))
#endif



// Basic math tools

#ifndef max
#ifdef __cplusplus
#include <algorithm>
using std::max;
#else
#define max(x, y) ({                          \
            typeof(x) _max1 = (x);            \
            typeof(y) _max2 = (y);            \
            (void) (&_max1 == &_max2);        \
            _max1 > _max2 ? _max1 : _max2; })
#endif /* __cplusplus */
#endif

#ifndef min
#ifdef __cplusplus
#include <algorithm>
using std::min;
#else
#define min(x, y) ({                          \
            typeof(x) _min1 = (x);            \
            typeof(y) _min2 = (y);            \
            (void) (&_min1 == &_min2);        \
            _min1 < _min2 ? _min1 : _min2; })
#endif /* __cplusplus */
#endif

#ifndef roundup
#define roundup(x, y) ({                      \
            const typeof(y) __y = y;          \
            (((x) + (__y - 1)) / __y) * __y;  \
        })
#endif

#ifndef roundup_modulo2
#define roundup_modulo2(x, p) (((x) + ((p) - 1)) & ~((p) - 1))
#endif

void swap(void *, void *, size_t);



// IEEE 802 General Address utilities

// For keep compatibility with Scenargie
// #ifndef BSD9TCP_INCLUDED
// # include <netlink/cli/utils.h>
// #endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
//#include "system_logger.h"

#define STRING(str) #str

#ifndef CHAR2HEX
# define CHAR2HEX(c) ((c) & 0xff)
#endif /* CHAR2HEX */

#ifndef SET_HWADDR
# define SET_HWADDR(ptr, addr0, addr1, addr2, addr3, addr4, addr5)  \
     do {                                                           \
         *((ptr) + 0) = (u8)(addr0);                                \
         *((ptr) + 1) = (u8)(addr1);                                \
         *((ptr) + 2) = (u8)(addr2);                                \
         *((ptr) + 3) = (u8)(addr3);                                \
         *((ptr) + 4) = (u8)(addr4);                                \
         *((ptr) + 5) = (u8)(addr5);                                \
     } while (0)
#endif

#ifndef SET_HWADDR_HEX
# define SET_HWADDR_HEX(ptr, hex)                   \
    do {                                            \
        int i = ETH_ALEN - 1;                       \
        do {                                        \
            *(((ptr) + i)) = (((hex) << i) & 0xff)  \
        } while (--i >= 0);                         \
    } while (0)
#endif

#define HWADDR_MASK 0x000000ff
#define HWADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define HWADDR_ARG(addr)  \
    ((addr)[0] & HWADDR_MASK), ((addr)[1] & HWADDR_MASK), ((addr)[2] & HWADDR_MASK), \
    ((addr)[3] & HWADDR_MASK), ((addr)[4] & HWADDR_MASK), ((addr)[5] & HWADDR_MASK)
// *((addr) + 0), *((addr) + 1), *((addr) + 2), *((addr) + 3), *((addr) + 4), *((addr) + 5),

#define IPADDR_LEN 16

extern char *copy_ifname(char *, const char *);


// Pthread utilities
extern int pthread_mutex_init_errorcheck(pthread_mutex_t *mutex);

// Timer function utilities

#include <time.h>

extern unsigned long long int diff_timespec(struct timespec start, struct timespec end);

extern char *get_timestr(char *, size_t);

extern void get_timestr_unix(char *str, size_t len);

extern unsigned long long int gettime_rdtsc(void);

extern int sleep_pthread(long sec, long nsec, pthread_cond_t *cond, pthread_mutex_t *mutex);

extern int nanosleep_restrict(long nsec);

extern int microsleep_restrict(long usec);

extern int millisleep_restrict(long msec);


// Data structure utilities

struct libutils_queue_struct {
    unsigned int status;
    char priv[0];
};

extern int libutils_queue_is_empty(struct libutils_queue_struct *s);

extern int libutils_queue_enqueue(struct libutils_queue_struct *s, void* data);

extern void* libutils_queue_dequeue(struct libutils_queue_struct *s);

extern void libutils_queue_flush(struct libutils_queue_struct *s);

extern struct libutils_queue_struct* libutils_queue_new(void);

extern void libutils_queue_release(struct libutils_queue_struct *s);


// File descriptor utilities

extern int is_file_exist(const char *filename);

extern int get_sockinfo(int sock, int optname);

extern int get_socktype(int sock);

extern int get_sockproto(int sock);

extern int get_bytes_ready2read(int sock);

extern struct sockaddr *allocate_sockaddr(int sock, socklen_t *len);

/// @return: recv_all_stream returns
///          - received bytes if succeeded,
///          - zero if connection closed,
///          - negative value if error happened.
extern int recv_all_stream(int sock, void *data, int len);

extern int recv_all_dgram(int sock, void *data, int len, struct sockaddr *addr, socklen_t *addrlen);

extern int send_all_stream(int sock, const void *data, size_t len);

extern int send_all_dgram(int sock, void *data, size_t len, struct sockaddr *addr, socklen_t addrlen);



// Libevent helpers

// Todo: Get the limit of number of descriptor automatically
#define DESCRIPTOR_LIMIT 65536

#define MAX_EVENTS (DESCRIPTOR_LIMIT * 3)

struct libutils_event_struct {
    unsigned int status;
    char priv[0];
};

extern void libutils_event_shutdown(struct libutils_event_struct *s, int sock);

extern int libutils_event_register_sigev(struct libutils_event_struct *s,
                                         short int flags, void (*handler)(int, short, void *), void *arg);

extern int libutils_event_register(struct libutils_event_struct *s,
                                   int sock, short int flags, void (*handler)(int, short, void *), void *arg);

extern void libutils_event_wait(struct libutils_event_struct *s);

extern void libutils_event_dispatch(struct libutils_event_struct *s);

extern void libutils_event_loopbreak(struct libutils_event_struct *s);

extern struct libutils_event_struct *libutils_event_new(void);

extern void libutils_event_release(struct libutils_event_struct *s);

extern void libutils_event_init(void);

extern void libutils_event_exit(void);


// Garbage collection utilities (it will be deprecated)
// The following wrapper functions are to avoid symbol conflicts between the daemon/libwinetap and the other programs.
extern void* gc_malloc(size_t __size);

extern void* gc_calloc(size_t __nmemb, size_t __size);

extern void* gc_realloc(void *__ptr, size_t __size);

extern void gc_free(void *__ptr);



// Debug utilities

#define MSG_EMERG  0x00  /* problem that makes the program crashed */
#define MSG_ALERT  0x01  /* action that must be taken immediately */
#define MSG_CRIT   0x02  /* critical conditions */
#define MSG_ERR    0x03  /* error conditions */
#define MSG_WARN   0x04  /* warning conditions */
#define MSG_NOTICE 0x05  /* significant conditions */
#define MSG_INFO   0x06  /* generic information */
#define MSG_DBG    0x07  /* debug information (debug) */

// int debug_level = MSG_DBG;
#define DEBUG_LEVEL MSG_DBG

#ifndef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "Unspecified"
#endif

#define STRUCTURE_MEMBER_MAP_FMT(member) \
    #member ": %p+%zu (%p)"

#define STRUCTURE_MEMBER_MAP_ARG(priv, type, member) \
    (priv), offsetof(type, member), &((priv)->member)

extern void libutils_debug_print_backtrace(void);

#ifdef ENABLE_DEBUG

#include <dlfcn.h>

#if !defined(_DLFCN_H)
#error "dlfcn.h is not included even though debug mode is on."
#elif !defined(RTLD_DEFAULT)
#error "dlfcn.h is included but no symbol is loaded (Check __USE_GNU/_GNU_SOURCE macro symbols are defined before any standard header files."
#endif

#define print_log(level, format, ...)                                                                                            \
    do {                                                                                                                         \
        char unixtime[20] = {0};                                                                                                 \
        get_timestr_unix(unixtime, 20);                                                                                          \
        Dl_info __dynamic_linker_info;                                                                                           \
        dladdr(__builtin_return_address(0), &__dynamic_linker_info);                                                             \
        if (level <= DEBUG_LEVEL) {                                                                                              \
            fprintf(stderr,                                                                                                      \
                    "[%s] mod: " DEBUG_IDENTIFIER ", level: " STRING(level) ", file: %s, line: %d, func: %s(), caller: %s() (%p), " format,  \
                    unixtime, __FILE__, __LINE__, __func__, __dynamic_linker_info.dli_sname, __builtin_return_address(0),        \
                    ##__VA_ARGS__);                                                                                              \
        }                                                                                                                        \
    } while (0)

#else

#define print_log(level, format, ...)                                   \
    do {                                                                \
        char unixtime[20];                                              \
        get_timestr_unix(unixtime, 20);                                 \
        if (level <= DEBUG_LEVEL) {                                     \
            fprintf(stdout, "[%s] mod: " DEBUG_IDENTIFIER ", " format,       \
                    unixtime, ##__VA_ARGS__);                           \
        }                                                               \
    } while (0)
#endif /* ENABLE_DEBUG */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UTILS_H */
