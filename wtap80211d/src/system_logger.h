/*
 * system_logger.h
 * wtap80211d
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef SYSTEM_LOGGER_H
#define SYSTEM_LOGGER_H

void system_logger_printf(char *format, ...);

int system_logger_init(const char *logfile);

void system_logger_exit(void);

#endif /* SYSTEM_LOGGER_H */
