/*
 * libshm.h
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef LIBSHM_H
#define LIBSHM_H

#include <stdlib.h>
#include <stdbool.h>
#include "utils.h"
#include "libshm.h"

#define LIBSHM_CONFIG_DEFAULT_OBJFILE "/shm_objfile"
#define LIBSHM_CONFIG_DEFAULT_BLOCK_SIZE 4096
#define LIBSHM_CONFIG_DEFAULT_BLOCK_NUM 256
#define LIBSHM_CONFIG_DEFAULT_OVERWRITE false

#define LIBSHM_STATUS_INITIALIZED (1 << 0)

struct libshm_config_struct {
    char shm_objfile[NAME_MAX];
    size_t block_size;
    size_t block_num;
    bool is_overwrite_enabled;
};

struct libshm_struct {
    unsigned int status;
    char priv[0];
};

extern int libshm_write(struct libshm_struct *s, void *data, size_t bytes);

extern int libshm_read(struct libshm_struct *s, void *data, size_t bytes);

extern size_t libshm_get_data_field_size(struct libshm_struct *s);

extern struct libshm_struct* libshm_new(struct libshm_config_struct *config);

extern void libshm_init(void);

extern void libshm_release(struct libshm_struct *s);

#endif /* LIBSHM_H */
