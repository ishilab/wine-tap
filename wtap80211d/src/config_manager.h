/*
 * cfgmgmr.h
 * wtap80211d - Netlink server to communicate with wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

extern int config_search_entry_string(char *key, const char **buf);

extern int config_search_entry_int(char *key, int *val);

extern int config_search_entry_bool(char *key, bool *val);

extern int config_manager_init(const char *cfgfile);

extern void config_manager_exit(void);

#endif /* CONFIG_MANAGER_H */
