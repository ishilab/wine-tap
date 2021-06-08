/*
 * wtap80211d
 * misc.c
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <fcntl.h>

bool set_nonblock(int fd)
{
    return (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)? false: true;
}

bool set_cloexec(int fd)
{
    return (fcntl(fd, F_SETFL, FD_CLOEXEC) < 0)? false: true;
}
