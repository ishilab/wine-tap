/*
 * wtap80211d
 * udev_watcher.c
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <unistd.h>
#include <event.h>
#include <libudev.h>
#include "utils.h"
#include "netdevice_manager.h"
#include "event_manager.h"

#ifdef ENABLE_UDEV_WATCHDOG

static struct udev_watchdog_struct {
    struct udev *udev;
    struct udev_enumerate *enumerate;
    struct udev_monitor *mon;
    struct udev_list_entry *devices;
    int udev_fd;
} uw_st ;

static void print_udev_info_net(struct udev_device *dev)
{
    print_log(MSG_DBG, "[udev_watchdog] device action  = %s\n",
            udev_device_get_action(dev));
    print_log(MSG_DBG, "[udev_watchdog] device path    = %s\n",
            udev_device_get_devpath(dev));
    print_log(MSG_DBG, "[udev_watchdog] device macaddr = %s\n",
            udev_device_get_sysattr_value(dev, "address"));
}

static void ev_cb_recv_udev_net(int fd, short flags, void *arg)
{
    struct udev_device *dev = NULL;
    const char *ifname, *action;

    declare_unused_variable(arg);

    if (!(dev = udev_monitor_receive_device(uw_st.mon))) {
        print_log(MSG_ERR, "[udev_watchdog] No active device found.\n");
        return ;
    }

    print_udev_info_net(dev);

    ifname = udev_device_get_sysname(dev);
    action = udev_device_get_action(dev);
    netdev_notify_udev_action(ifname, action);

    udev_device_unref(dev);
}

static int udev_enumerate_init(const char *subtype)
{
    if (!(uw_st.enumerate = udev_enumerate_new(uw_st.udev)))
        return -ENOMEM;

    udev_enumerate_add_match_subsystem(uw_st.enumerate, subtype);

    return 0;
}

bool udev_has_device(const char *ifname, const char *subtype)
{
    struct udev_list_entry *devices;
    struct udev_list_entry *entry;
    bool has_device = false;

    udev_enumerate_scan_devices(uw_st.enumerate);
    devices = udev_enumerate_get_list_entry(uw_st.enumerate);

    udev_list_entry_foreach(entry, devices) {
        const char *syspath, *dev_name;
        struct udev_device *dev;

        syspath = udev_list_entry_get_name(entry);
        dev = udev_device_new_from_syspath(uw_st.udev, syspath);

        if (dev) {
            dev_name = udev_device_get_sysname(dev);

            if (strcmp(dev_name, ifname) == 0
                    && udev_device_get_is_initialized(dev))
                has_device = true;
        }

        udev_device_unref(dev);
    }

    return has_device;
}

bool udev_has_multiple_devices(const char (*ifnames)[IFNAMSIZ], int n, const char *subtype)
{

    struct udev_list_entry *devices;
    struct udev_list_entry *entry;
    int hitcount = 0;

    udev_enumerate_scan_devices(uw_st.enumerate);
    devices = udev_enumerate_get_list_entry(uw_st.enumerate);

    print_log(MSG_DBG,
            "[udev_watchdog] searching %d device(s) in the udev entries (subtype: %s).\n",
            n, subtype);

    udev_list_entry_foreach(entry, devices) {
        const char *syspath, *dev_name;
        struct udev_device *dev;

        syspath = udev_list_entry_get_name(entry);
        dev = udev_device_new_from_syspath(uw_st.udev, syspath);

        if (dev) {
            int i;

            dev_name = udev_device_get_sysname(dev);

            for (i = 0; i < n; ++i) {
                if (strcmp(dev_name, ifnames[i]) == 0
                        && udev_device_get_is_initialized(dev))
                    hitcount++;
            }
        }

        udev_device_unref(dev);
    }

    print_log(MSG_DBG, "[udev_watchdog] %d device(s) found.\n", hitcount);

    return (hitcount == n);
}

static int udev_net_monitor_init(const char *subtype)
{
    if (!(uw_st.mon = udev_monitor_new_from_netlink(uw_st.udev, "udev")))
        return -ENOMEM;

    udev_monitor_filter_add_match_subsystem_devtype(uw_st.mon, subtype, NULL);
    udev_monitor_enable_receiving(uw_st.mon);

    if ((uw_st.udev_fd = udev_monitor_get_fd(uw_st.mon)) < 0)
        return -EBUSY;

    register_event(uw_st.udev_fd, EV_READ | EV_PERSIST,
            ev_cb_recv_udev_net, NULL);

    print_log(MSG_DBG, "[udev_watchdog] udev monitor started (subtype: %s).\n", subtype);

    return 0;
}

int udev_watchdog_init(void)
{
    memset(&uw_st, 0, sizeof(uw_st));

    if (!(uw_st.udev = udev_new()))
        return -ENOMEM;

    udev_net_monitor_init("net");

    udev_enumerate_init("net");

    print_log(MSG_INFO, "[udev_watchdog] udev_watchdog started.\n");

    return 0;
}

void udev_watchdog_exit(void)
{

}

#endif /* ENABLE_UDEV_WATCHDOG */

