/*
 * logwatcher.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "libshm.h"

#define BUFSIZE 32

int main(int argc, char **argv)
{
    struct libshm_config_struct config = {
        .shm_objfile = "/shm_objfile",
        .block_size = 64,
        .block_num = 3,
        .is_overwrite_enabled = false,
    };
    struct libshm_struct *s = NULL;
    const char char_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char buf[BUFSIZE];
    int i, j, err;

    print_log(MSG_INFO, "Logwatcher for wtap80211 daemon\n");

    libshm_init();

    if (!(s = libshm_new(&config))) {
        fprintf(stderr, "Could not initialize libshm.\n");
        return -1;
    }

    print_log(MSG_DBG, "Data field size: %zu bytes\n", libshm_get_data_field_size(s));

    print_log(MSG_INFO, "Testing writing functions...\n");

    for (j = 0; j < 4; ++j) {
        memset(buf, 0, BUFSIZE);

        for (i = 0; i < BUFSIZE; ++i)
            buf[i] = char_set[rand() % (sizeof(char_set) - 1)];

        printf("[%d] ", j);
        for (i = 0; i < BUFSIZE; ++i)
            printf("%c", buf[i]);
        printf(" (size: %d bytes)\n", BUFSIZE);

        if (libshm_write(s, buf, sizeof(buf)) < 0) {
            print_log(MSG_WARN, "[libshm] No space to write logs\n");
            break;
        }
    }

    print_log(MSG_INFO, "Testing reading functions...\n");

    for (j = 0; j < 6; ++j) {
        memset(buf, 0, BUFSIZE);

        if ((err = libshm_read(s, buf, sizeof(buf))) < 0) {
            print_log(MSG_ERR, "Could not read data from memory blocks (reason: %s, code: %d)\n", strerror(err), err);
            libshm_release(s);
            return -1;
        }

        printf("[%d] ", j);
        for (i = 0; i < BUFSIZE; ++i)
            printf("%c", buf[i]);
        printf("\n");

    }

    libshm_release(s);

    return 0;
}
