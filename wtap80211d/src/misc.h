/*
 * wtap80211d
 * misc.h
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef MISC_H
#define MISC_H

extern bool set_nonblock(int fd);

extern bool set_cloexec(int fd);

#endif /* MISC_H */
