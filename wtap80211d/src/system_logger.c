/*
 * system_logger.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <libconfig.h>
#include "utils.h"
#include "config_manager.h"
#include "system_logger.h"
#include "libshm.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "logger"

#define BUF_SIZE 4096
#define MMAP_SIZE (system_logger.pagesize * 16)
#define DEFAULT_LOCATION "/var/tmp/wtap80211d.log"

static struct system_logger {
    int fd;
    long int pagesize;
    char *mmap;
    unsigned int mmap_size;
    unsigned int bytes_on_mmap;
    pthread_mutex_t mutex;

    int (*writer)(void*, size_t);

    bool is_logging_enabled;
    bool is_fast_logging_enabled;
    struct libshm_config_struct shm_config;
    struct libshm_struct *shm;
} system_logger ;

static inline void debug_priv_mapping_info(void)
{
    print_log(MSG_DBG,
            "priv: %p"
            STRUCTURE_MEMBER_MAP_FMT(fd) ", "
            STRUCTURE_MEMBER_MAP_FMT(pagesize) ", "
            STRUCTURE_MEMBER_MAP_FMT(mmap) ", "
            STRUCTURE_MEMBER_MAP_FMT(mmap_size) ", "
            STRUCTURE_MEMBER_MAP_FMT(bytes_on_mmap) ", "
            STRUCTURE_MEMBER_MAP_FMT(mutex) ", "
            STRUCTURE_MEMBER_MAP_FMT(writer) ", "
            STRUCTURE_MEMBER_MAP_FMT(is_logging_enabled) ", "
            STRUCTURE_MEMBER_MAP_FMT(is_fast_logging_enabled) ", "
            STRUCTURE_MEMBER_MAP_FMT(shm_config) ", "
            STRUCTURE_MEMBER_MAP_FMT(shm) ", "
            "\n",
            &system_logger,
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, fd),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, pagesize),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, mmap),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, mmap_size),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, bytes_on_mmap),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, mutex),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, writer),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, is_logging_enabled),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, is_fast_logging_enabled),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, shm_config),
            STRUCTURE_MEMBER_MAP_ARG(&system_logger, struct system_logger, shm));
}

/* static pthread_mutex_t system_logger_mutex = PTHREAD_MUTEX_INITIALIZER; */

static inline void system_logger_lock(void)
{
    pthread_mutex_lock(&system_logger.mutex);
}

static inline void system_logger_unlock(void)
{
    pthread_mutex_unlock(&system_logger.mutex);
}

static inline bool get_is_logging_enabled(void)
{
    system_logger_lock();
    bool is_logging_enabled = system_logger.is_logging_enabled;
    system_logger_unlock();

    return is_logging_enabled;
}

static int system_logger_print(void* data, size_t len)
{
    return fwrite(data, 1, len, stdout);
}

static int system_logger_write(void* data, size_t len)
{
    int err;

    /* if ((MMAP_SIZE - system_logger.bytes_on_mmap) < len) { */
    if (len - (system_logger.mmap_size - system_logger.bytes_on_mmap) > 0) {
        if ((err = msync(system_logger.mmap, system_logger.bytes_on_mmap, MS_SYNC)) < 0)
            return err;
        system_logger.bytes_on_mmap = 0;
    }

    if ((err = write(system_logger.fd, data, len) < 0))
        return err;

    system_logger.bytes_on_mmap += len;

    return len;
}

__attribute__((format(printf,1,2)))
void system_logger_printf(char *format, ...)
{
    char buf[BUF_SIZE] = {0};
    char tmp[BUF_SIZE] = {0};
    char time_str[64] = {0};
    va_list arg;
    int ret;

    if (!get_is_logging_enabled())
        return;

    va_start(arg, format);

    vsnprintf(tmp, ARRAY_SIZE(buf), format, arg);

    get_timestr_unix(time_str, ARRAY_SIZE(time_str));
    snprintf(buf, ARRAY_SIZE(buf), "[%s] %s", time_str, tmp);

    system_logger_lock();
    int len = strlen(buf);
    if (system_logger.writer && len > 0) {
        if ((ret = (*system_logger.writer)(buf, len)) < 0)
            print_log(MSG_DBG, "writing logs failed (%s).\n", strerror(ret));
    }
    system_logger_unlock();

    va_end(arg);
}

static int system_logger_shm_write(void *data, size_t len)
{
    return libshm_write(system_logger.shm, data, len);
}

static int check_shm_config(void)
{
    memset(&system_logger.shm_config, 0, sizeof(system_logger.shm_config));

    if (config_search_entry_int("fast_logging", (int*)&system_logger.is_fast_logging_enabled) == CONFIG_FALSE
            || !system_logger.is_fast_logging_enabled) {
        print_log(MSG_INFO, "fast logging disabled\n");
        return -1;
    } else {
        const char *shm_objfile;

        print_log(MSG_INFO, "fast logging enabled\n");

        if (config_search_entry_string("shm_object_file", &shm_objfile) == CONFIG_FALSE)
            return -EINVAL;

        memcpy(system_logger.shm_config.shm_objfile, shm_objfile, strlen(shm_objfile));

        if (config_search_entry_int("memory_block_size",
                    (int*)(&system_logger.shm_config.block_size)) == CONFIG_FALSE)
            return -EINVAL;

        if (config_search_entry_int("number_of_memory_blocks",
                    (int*)(&system_logger.shm_config.block_num)) == CONFIG_FALSE)
            return -EINVAL;

        if (config_search_entry_int("overwrite_blocks",
                    (int*)&system_logger.shm_config.is_overwrite_enabled) == CONFIG_FALSE)
            return -EINVAL;
    }

    return 0;
}

int system_logger_init(const char *logfile)
{
    memset(&system_logger, 0, sizeof(system_logger));

    if (config_search_entry_int("system_logging",
                                (int*)(&system_logger.is_logging_enabled)) == CONFIG_FALSE)
        system_logger.is_logging_enabled = true;

    if (system_logger.is_logging_enabled) {
        if (config_search_entry_int("mmap_size",
                                    (int*)(&system_logger.mmap_size)) == CONFIG_FALSE)
            system_logger.mmap_size = MMAP_SIZE;

        system_logger.pagesize = getpagesize();

        if (pthread_mutex_init(&system_logger.mutex, NULL))
            goto error;

        system_logger.mmap_size *= system_logger.pagesize;
        print_log(MSG_DBG, "mmap size is %d.\n", system_logger.mmap_size);

        if ((system_logger.fd = open(((logfile)? logfile: DEFAULT_LOCATION), O_CREAT | O_APPEND | O_RDWR, 0666)) < 0)
            goto error;

        // if ((system_logger.mmap = mmap(NULL, system_logger.mmap_size,
        //                                PROT_WRITE, MAP_PRIVATE, system_logger.fd, 0)) == MAP_FAILED)
        //     goto mmap_error;
        if ((system_logger.mmap = mmap(NULL, 1,
                                       PROT_WRITE, MAP_PRIVATE, system_logger.fd, 0)) == MAP_FAILED)
            goto mmap_error;

        if (!check_shm_config()) {
            libshm_init();
            if (!(system_logger.shm = libshm_new(&system_logger.shm_config)))
                goto mmap_error;
            system_logger.writer = system_logger_shm_write;
        } else {
            system_logger.writer = system_logger_write;
            /* system_logger.writer = system_logger_print; */
            print_log(MSG_DBG, "system_logger.writer's address is %p (system_logger_printf() = %p).\n",
                      system_logger.writer, system_logger_write);
        }

        print_log(MSG_DBG, "logfile is located at %s.\n", logfile);

#ifdef ENABLE_DEBUG
        debug_priv_mapping_info();
#endif
    }

    print_log(MSG_DBG, "system_logger is %s.\n",
            (system_logger.is_logging_enabled) ? "ready" : "disabled");

    return 0;

mmap_error:
    close(system_logger.fd);

error:
    print_log(MSG_WARN, "system logger is unavailable (reason: %s).\n", strerror(errno));
    return -1;
}

void system_logger_exit(void)
{
    if (get_is_logging_enabled()) {
        munmap(system_logger.mmap, system_logger.mmap_size);
        close(system_logger.fd);
    }
}

#undef DEBUG_IDENTIFIER
