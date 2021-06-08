/*
 * cfgmgmr.c
 * wtap80211d - Netlink server to communicate with wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <libconfig.h>
#include <stdlib.h>
#include "utils.h"

static struct config_manager_struct {
    config_t cfg;
    config_setting_t cfgset;
} st ;

static int load_config_file(const char *cfgfile)
{
    config_init(&st.cfg);

    if (!config_read_file(&st.cfg, cfgfile)) {
        print_log(MSG_ERR, "[config] %s:%d - %s\n",
                config_error_file(&st.cfg), config_error_line(&st.cfg), config_error_text(&st.cfg));
        config_destroy(&st.cfg);
        return -1;
    }

    return 0;
}

int config_search_entry_string(char *key, const char **buf)
{
    return config_lookup_string(&st.cfg, key, buf);
}

int config_search_entry_int(char *key, int *val)
{
    return config_lookup_int(&st.cfg, key, val);
}

int config_search_entry_bool(char *key, bool *val)
{
    int tmp, ret;
    if ((ret = config_lookup_int(&st.cfg, key, &tmp)) == CONFIG_FALSE)
        *val = tmp;
    return ret;
}

int config_manager_init(const char *cfgfile)
{
    memset(&st, 0, sizeof(struct config_manager_struct));
    return load_config_file(cfgfile);
}

void config_manager_exit(void)
{
    config_destroy(&st.cfg);
}
