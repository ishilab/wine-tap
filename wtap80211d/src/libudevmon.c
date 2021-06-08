/*
 * libudevmon.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libudev.h>
#include "utils.h"
#include "libudevmon.h"

#define libudevmon_priv_of(s) ((struct libudevmon_priv*)&((s)->data))

struct libudevmon_priv {
    struct udev *udev;
    struct udev_enumerate *udev_enum;
    struct udev_monitor *udev_mon;
    char subtype[16];
    int udev_fd;
};

bool libudevmon_has_multiple_devices(struct libudevmon_struct *s,
                                     const char **ifnames,
                                     int n)
{
    struct libudevmon_priv *priv;
    struct udev_list_entry *devices;
    struct udev_list_entry *entry;
    int hitcount = 0;

    priv = libudevmon_priv_of(s);

    udev_enumerate_scan_devices(priv->udev_enum);
    devices = udev_enumerate_get_list_entry(priv->udev_enum);

    udev_list_entry_foreach(entry, devices) {
        const char *syspath, *dev_name;
        struct udev_device *dev;

        syspath = udev_list_entry_get_name(entry);
        dev = udev_device_new_from_syspath(priv->udev, syspath);

        if (dev) {
            dev_name = udev_device_get_sysname(dev);

            for (int i = 0; i < n; ++i) {
                if (strcmp(dev_name, ifnames[i]) == 0
                        && udev_device_get_is_initialized(dev))
                    hitcount++;
            }
        }

        udev_device_unref(dev);
    }

    return (hitcount == n);
}

inline bool libudevmon_has_device(struct libudevmon_struct *s, const char* ifname)
{
    const char** ifnames = &ifname;
    return libudevmon_has_multiple_devices(s, ifnames, 1);
}

__attribute__((malloc))
struct libudevmon_struct* libudevmon_new(const char *subtype)
{
    struct libudevmon_struct *s;
    struct libudevmon_priv *priv;

    if (!subtype)
        return NULL;

    s = (struct libudevmon_struct*)gc_calloc(1,
            sizeof(struct libudevmon_struct) + sizeof(struct libudevmon_priv));
    if (!s)
        return NULL;

    priv = libudevmon_priv_of(s);

    strncpy(priv->subtype, subtype, min(strlen(subtype), ARRAY_SIZE(priv->subtype) - 1));

    if (!(priv->udev = udev_new()))
        goto error;

    if (!(priv->udev_mon = udev_monitor_new_from_netlink(priv->udev, "udev")))
        goto error_mon;

    udev_monitor_filter_add_match_subsystem_devtype(priv->udev_mon, subtype, NULL);
    udev_monitor_enable_receiving(priv->udev_mon);

    if ((priv->udev_fd = udev_monitor_get_fd(priv->udev_mon)) < 0)
        goto error_mon;

    if (!(priv->udev_enum = udev_enumerate_new(priv->udev)))
        goto error_mon;

    udev_enumerate_add_match_subsystem(priv->udev_enum, subtype);

    return s;

error_mon:
    udev_unref(priv->udev);
error:
    gc_free(s);
    return NULL;
}

void libudevmon_release(struct libudevmon_struct *s)
{
    struct libudevmon_priv *priv;

    if (!s)
        return;

    priv = libudevmon_priv_of(s);

    udev_unref(priv->udev);
    gc_free(s);
}

int libudevmon_init(void)
{
    return 0;
}

void libudevmon_exit(void)
{
    /* Nothing */
}
