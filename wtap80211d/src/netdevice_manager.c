/*
 * dev_mgmr.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <ctype.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <event.h>
#include <libconfig.h>

#include "uthash/uthash.h"
#include "tap.h"
#include "utils.h"
#include "libworkqueue.h"
#include "libnetlink.h"
#include "ieee80211.h"
#include "event_manager.h"
#include "config_manager.h"
#include "rtnetlink_connector.h"
#include "genetlink_connector.h"
#include "netdevice_manager.h"
#include "udev_watchdog.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "netdeivce"

#define TAP_BASENAME "emu"
#define NETDEV_DEFAULT_SLEEP_INTERVAL 500

#define CHECK_DEVICE_FLAG(info,roleid,flag) \
    (((info)->ifnames[(roleid)]) ? true : false)

enum {
    SYSTEM_SIDE_DATA = 0,
    SYSTEM_SIDE_CONFIG,
    SIMULATOR_SIDE_DATA,
    SIMULATOR_SIDE_CONFIG,

    TAPFDS_MAX,
};

struct devinfo {
    /* The MAC address of a virtual wireless device (used as an ID). */
    char addr[ETH_ALEN];
    int hwid;
    int roleid;

    /* Tap interface information */
    char ifaddrs[TAPFDS_MAX][ETH_ALEN];
    char ifnames[TAPFDS_MAX][IFNAMSIZ];
    int fds[TAPFDS_MAX];
    unsigned int flags[TAPFDS_MAX];

    pthread_mutex_t mutex;

    UT_hash_handle hh;
};

struct netdevice_manager_container {
    struct devinfo *info;
    char hwaddr[ETH_ALEN];
    char ifname[IFNAMSIZ];
    int roleid;

    char priv[0];
};

static struct netdevice_manager_struct {

    struct devinfo *dev_list;

    struct rtnl_handle rtnl;
    int is_rtnl_available;

    pthread_mutex_t mutex;

    int num_of_external_interfaces;

    unsigned int sleep_interval;

    struct libworkqueue_struct *workqueue;

} netdev_st = {0};

static struct devinfo* __netdev_find_device(char *hwaddr)
{
    struct devinfo *info = NULL;
    /* HASH_FIND_STR(netdev_st.dev_list, addr, info); */
    HASH_FIND(hh, netdev_st.dev_list, hwaddr, ETH_ALEN, info);
    return info;
}

static void print_all_entries(void);
static void tap_close(struct devinfo *info);

static bool is_network_interface_active(const char *ifname)
{
    struct ifreq ifr = {{{0}},{{0}}};
    int skfd = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return false;

    strncpy(ifr.ifr_name, ifname, ETH_ALEN);

    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
        return false;

    close(skfd);

    return !!(ifr.ifr_flags & IFF_UP);
}

static int netdev_write_binary(char *addr, const char *buf, size_t n)
{
    struct devinfo *info = NULL;
    int written_size = 0;

    pthread_mutex_lock(&netdev_st.mutex);
    info = __netdev_find_device(addr);
    pthread_mutex_unlock(&netdev_st.mutex);

    if (!info)
        return -EINVAL;

    if ((written_size = write(info->fds[SYSTEM_SIDE_DATA], buf, n)) < 0) {
        int err = written_size;
        print_log(MSG_DBG,
                "could not write binary to %s (reason: %s (code: %d))\n",
                info->ifnames[SYSTEM_SIDE_DATA], strerror(-err), err);
        return err;
    }

    return written_size;
}

static void ev_cb_recv_data(int fd, short flags, void *arg)
{
    print_log(MSG_DBG, "Frame message received.\n");
}

static void ev_cb_recv_config(int fd, short flags, void *arg)
{
    print_log(MSG_DBG, "Config message received.\n");
}

static int get_hwids(const char *ifname, int *__hwid, int *__roleid)
{
    int hwid = 0, roleid = 0;

    print_log(MSG_DBG, "ifname: %s\n", ifname);

    if (sscanf(ifname, TAP_BASENAME "%d-%d", &hwid, &roleid) == EOF)
        return -EINVAL;

    print_log(MSG_DBG, "hwid: %d, roleid: %d\n", hwid, roleid);

    *__hwid = hwid;
    *__roleid = roleid;

    return 0;
}

static inline bool verify_tap_interface(const char *ifname)
{
    return !(strncmp(TAP_BASENAME, ifname, sizeof(TAP_BASENAME) - 1));
}

static struct devinfo* search_devinfo_with_hwid(char hwid)
{
    struct devinfo *info, *tmp;

    HASH_ITER(hh, netdev_st.dev_list, info, tmp) {
        if ((info->addr[5] & HWADDR_MASK) == hwid) {
            return info;
        }
    }

    return NULL;
}

void netdev_notify_udev_action(const char *ifname, const char *action)
{
    struct devinfo *info = NULL;
    int hwid = 0, roleid = 0, err = 0;

    print_log(MSG_DBG,
            "Action notification (ifname: %s, action: %s)\n",
            ifname, action);

    if (!verify_tap_interface(ifname)) {
        print_log(MSG_DBG, "%s ignored.\n", ifname);
        return ;
    }

    if ((err = get_hwids(ifname, &hwid, &roleid)) < 0) {
        print_log(MSG_DBG, "Extracting hwid from %s failed.\n", ifname);
        return ;
    }

    if (!(info = search_devinfo_with_hwid((char)hwid))) {
        print_log(MSG_DBG, "%s not found.\n", ifname);
        return ;
    }

    /* pthread_mutex_lock(&netdev_st.mutex); */

    if (strcmp(action, "add") == 0) {
        print_log(MSG_DBG,
                "%s is registered (bound hwaddr: " HWADDR_FMT ", hwid: %d, roleid: %d)\n",
                ifname, HWADDR_ARG(info->addr), hwid, roleid);
        info->flags[roleid] |= NETDEV_UDEV_STATE_REG;
    }

    /* pthread_mutex_unlock(&netdev_st.mutex); */

    return ;
}

static bool is_network_interface_registered(struct devinfo *info, int roleid)
{
#ifdef ENABLE_UDEV_WATCHDOG
    bool flags[2] = {false};

    flags[0] = udev_has_device(info->ifnames[roleid], "net");
    /* flags[1] = (info->flags[roleid] & NETDEV_UDEV_STATE_REG) ? true : false; */
    flags[1] = CHECK_DEVICE_FLAG(info,roleid,NETDEV_UDEV_STATE_REG);

    print_log(MSG_DBG,
            "%s status [udev: %s, udev_action: %s]\n",
            info->ifnames[roleid],
            ((flags[0]) ? "ready" : "standby"),
            ((flags[1]) ? "ready" : "standby"));

    return (flags[0] && flags[1]);
#else
    return 1;
#endif
}

static bool is_network_interface_activated(struct devinfo *info, int roleid)
{
#ifdef ENABLE_UDEV_WATCHDOG
    bool flags[4] = {false};

    flags[0] = is_network_interface_active(info->ifnames[roleid]);
    flags[1] = rtnl_is_interface_active(info->ifnames[roleid]);
    flags[2] = udev_has_device(info->ifnames[roleid], "net");
    flags[3] = info->flags[roleid] & NETDEV_UDEV_STATE_REG;

    print_log(MSG_DBG,
            "%s status [io: %s, rtnl: %s, udev: %s, udev_action: %s]\n",
            info->ifnames[roleid],
            ((flags[0]) ? "ready" : "standby"),
            ((flags[1]) ? "ready" : "standby"),
            ((flags[2]) ? "ready" : "standby"),
            ((flags[3]) ? "ready" : "standby"));

    return (flags[0] && flags[1] && flags[2] && flags[3]);
#else
    bool flags[2] = {false};

    flags[0] = is_network_interface_active(info->ifnames[roleid]);
    flags[1] = rtnl_is_interface_active(info->ifnames[roleid]);

    print_log(MSG_DBG,
            "%s status [io: %s, rtnl: %s]\n",
            info->ifnames[roleid],
            ((flags[0]) ? "ready" : "standby"),
            ((flags[1]) ? "ready" : "standby"));

    return (flags[0] && flags[1]);
#endif
}

static void* do_netdev_assign_ip_address(void *arg)
{
    /* union task_container *container = (union task_container*)arg; */
    struct netdevice_manager_container *container = arg;
    struct devinfo *info = container->info;
    char *ifname = container->ifname;
    int roleid = container->roleid;
    int err = 0;

    if ((err = tap_set_ipaddr(ifname, 0)) < 0)
        print_log(MSG_ERR,
                "could assign ip address to %s (reason: %s (code: %d))\n",
                ifname, strerror(-err), err);

    if ((err = tap_ifup_name(ifname) < 0))
        print_log(MSG_ERR,
                "could make %s be up (reason: %s (code: %d))\n",
                ifname, strerror(-err), err);

    while (!is_network_interface_activated(info, roleid))
        sleep(1);

    print_log(MSG_DBG, "%s is ready.\n", ifname);

    gc_free(arg);

    return NULL;
}

static void ev_cb_check_network_interface_status(int fd, short int flags, void *arg)
{
    struct netdevice_manager_container *container =
        (struct netdevice_manager_container*)arg;
    struct devinfo *info = container->info;
    int roleid = container->roleid;

    if (is_network_interface_registered(info, roleid)) {
        print_log(MSG_DBG, "%s is ready.\n", container->ifname);
        gc_free(arg);
    } else {
        register_timer_event(ev_cb_check_network_interface_status, arg, 1L, 0);
    }
}

static int check_network_interface_status(struct devinfo *info,
                                          const char *hwaddr, const char *ifname,
                                          const int roleid)
{
    struct netdevice_manager_container *container = NULL;
    int err = 0;

    if (!(container = (struct netdevice_manager_container*)gc_calloc(1,
                            sizeof(struct netdevice_manager_container)))) {
        return -ENOMEM;
    }

    container->info = info;
    memcpy(container->hwaddr, hwaddr, ETH_ALEN);
    memcpy(container->ifname, ifname, IFNAMSIZ);
    container->roleid = roleid;

    if ((err = register_timer_event(ev_cb_check_network_interface_status,
                    container, 1L, 0)) < 0) {
        return err;
    }

    return 0;
}

static int netdev_add_tap_interface(struct devinfo *info,
                                    const char *hwaddr, const int roleid)
{
    /* union task_container *container = NULL; */
    struct netdevice_manager_container *container = NULL;

    char ifname[IFNAMSIZ + 1] = {0};
    int fd = 0, err;

    snprintf(ifname, ARRAY_SIZE(ifname), "%s%d-%d",
            TAP_BASENAME,
            (int)(hwaddr[5] & HWADDR_MASK),
            roleid);

    print_log(MSG_DBG,
            "adding a new tap interface (ifname: %s, bound hwaddr: " HWADDR_FMT ", roleid: %d)\n",
            ifname, HWADDR_ARG(hwaddr), roleid);

    pthread_mutex_lock(&netdev_st.mutex);

#ifdef ENABLE_UDEV_WATCHDOG
    if (udev_has_device((const char*)ifname, "net")) {
        print_log(MSG_NOTICE, "[netdevice] %s already exists\n", ifname);
        pthread_mutex_lock(&info->mutex);
        info->flags[roleid] |= NETDEV_UDEV_STATE_REG;
        pthread_mutex_unlock(&info->mutex);
    }
#endif

    if ((fd = tap_alloc(ifname)) < 0) {
        err = fd;
        print_log(MSG_ERR,
                "could not open %s (reason: %s (code: %d))\n",
                ifname, strerror(-err), err);
        goto error_in_lock;
    }

    tap_set_persist(fd, 1);
    tap_set_owner(fd, getuid());

    /*
     * if ((err = fcntl(fd, F_SETFL, O_NONBLOCK | O_ASYNC)) < 0)
     *     goto error_in_lock;
     */

    /*
     * while (!is_network_interface_registered(info, roleid))
     *     sleep(1);
     */

    pthread_mutex_unlock(&netdev_st.mutex);

    memcpy(info->ifnames[roleid], ifname, IFNAMSIZ);
    tap_get_hwaddr(ifname, info->ifaddrs[roleid]);
    info->fds[roleid] = fd;

    check_network_interface_status(info, hwaddr, ifname, roleid);

    print_log(MSG_INFO,
            "%s (hwaddr: " HWADDR_FMT ") is activated (fd = %d).\n",
            ifname, HWADDR_ARG(info->ifaddrs[roleid]), info->fds[roleid]);

    return 0;

error_in_lock:
    pthread_mutex_unlock(&netdev_st.mutex);
    return err;
}

static void* do_netdev_add_tap_interface(void *arg)
{
    /* union task_container *container = (union task_container*)arg; */
    struct netdevice_manager_container *container = arg;
    struct devinfo *info = container->info;
    const char *hwaddr = container->hwaddr;
    const int roleid = container->roleid;
    int err = 0;

    if ((err = netdev_add_tap_interface(info, hwaddr, roleid)) < 0) {
        print_log(MSG_ERR,
                "[netdevice] could not open a tap interface (bound hwaddr %s, roleid: %d)\n",
                hwaddr, roleid);
    }

    gc_free(arg);

    return NULL;
}

static void* do_netdev_add_multiple_tap_interfaces(void *arg)
{
    struct devinfo *info = (struct devinfo*)arg;
    int i;

    for (i = 0; i < netdev_st.num_of_external_interfaces; ++i) {
        /* union task_container *container = */
                /* (union task_container*)gc_calloc(1, sizeof(union task_container)); */
        struct netdevice_manager_container *container =
            (struct netdevice_manager_container*)gc_calloc(1,
                    sizeof(struct netdevice_manager_container));

        if (container) {
            memcpy(container->hwaddr, info->addr, ETH_ALEN);
            container->roleid = i;
            container->info = info;
            /* workq_enqueue(do_netdev_add_tap_interface, (void*)container); */
            libworkqueue_enqueue_task(netdev_st.workqueue,
                    NULL, do_netdev_add_tap_interface, (void*)container);
        }
    }

    return NULL;
}

int netdev_add_multiple_external_interfaces(char *hwaddr)
{
    struct devinfo *info = NULL;

    pthread_mutex_lock(&netdev_st.mutex);
    info = __netdev_find_device(hwaddr);
    pthread_mutex_unlock(&netdev_st.mutex);

    if (!info) {
        if (!(info = (struct devinfo *)gc_calloc(1, sizeof(struct devinfo)))) {
            pthread_mutex_unlock(&netdev_st.mutex);
            return -ENOMEM;
        }

        pthread_mutex_lock(&netdev_st.mutex);

        memcpy(info->addr, hwaddr, ETH_ALEN);
        info->hwid = (int)(hwaddr[5] & HWADDR_MASK);
        HASH_ADD_STR(netdev_st.dev_list, addr, info);

        pthread_mutex_unlock(&netdev_st.mutex);

        print_log(MSG_DBG,
                "New entry added (bound hwaddr: " HWADDR_FMT ")\n",
                HWADDR_ARG(info->addr));

        /* workq_enqueue(do_netdev_add_multiple_tap_interfaces, (void*)info); */
        libworkqueue_enqueue_task(netdev_st.workqueue,
                NULL, do_netdev_add_multiple_tap_interfaces, (void*)info);
    }

    return 0;
}

void* do_netdev_add_multiple_external_interfaces(void *arg)
{
    char *addrlist = genl_get_addrs();
    size_t n = genl_get_ndev();
    size_t i = 0;

    if (netdev_st.num_of_external_interfaces > 0) {
        print_log(MSG_DBG, "Setting up %zu tap interfaces\n",
                netdev_st.num_of_external_interfaces * n);

        for (i = 0; i < n; ++i) {
            char *addr = addrlist + i * ETH_ALEN;
            netdev_add_multiple_external_interfaces(addr);
        }
    } else {
        print_log(MSG_DBG, "No external interface set up\n");
    }

    gc_free(addrlist);

    return NULL;
}

int netdev_add_device(char *addr)
{
    struct devinfo *info = NULL;
    int i, err = 0;
    char ifnames[TAPFDS_MAX][IFNAMSIZ] = {{0}};

    pthread_mutex_lock(&netdev_st.mutex);

    info = __netdev_find_device(addr);
    if (!info) {

        if (!(info = (struct devinfo *)gc_calloc(1, sizeof(struct devinfo)))) {
            pthread_mutex_unlock(&netdev_st.mutex);
            return -ENOMEM;
        }

        for (i = 0; i < netdev_st.num_of_external_interfaces; ++i) {
            char dev_name[IFNAMSIZ + 1] = {0};

            snprintf(info->ifnames[i], ARRAY_SIZE(info->ifnames[i]), "%s%d-%d",
                    TAP_BASENAME, (int)(addr[5] & HWADDR_MASK), i);
            strncpy(dev_name, (const char*)info->ifnames[i], IFNAMSIZ);

#ifdef ENABLE_UDEV_WATCHDOG
            if (udev_has_device((const char*)info->ifnames[i], "net")) {
                print_log(MSG_NOTICE, "%s already exists\n", info->ifnames[i]);
                info->flags[i] |= NETDEV_UDEV_STATE_REG;
            }
#endif

            /* if ((info->fds[i] = tap_alloc(info->ifnames[i])) < 0) { */
            if ((info->fds[i] = tap_iplink_setup(info->ifnames[i])) < 0) {
                err = info->fds[i];
                print_log(MSG_ERR,
                        "[netdevice] Could not open %s (reason: %s (code: %d))\n",
                        info->ifnames[i], strerror(-err), err);
                goto error_in_lock;
            }

            if ((err = fcntl(info->fds[i], F_SETFL, O_NONBLOCK | O_ASYNC)) < 0)
                goto error_in_lock;;

            HASH_ADD_STR(netdev_st.dev_list, addr, info);

            while (!is_network_interface_active(info->ifnames[i])
                    || !rtnl_is_interface_active(info->ifnames[i])
#ifdef ENABLE_UDEV_WATCHDOG
                    || !udev_has_device(info->ifnames[i], "net")
#endif
                    || !(info->flags[i] & NETDEV_UDEV_STATE_REG))
                sleep_pthread(1L, 0L, NULL, NULL);
                /* millisleep_continue(netdev_st.sleep_interval); */
                /* sleep(netdev_st.sleep_interval); */

            tap_get_hwaddr((const char *)info->ifnames[i], info->ifaddrs[i]);

            strncpy(ifnames[i], info->ifnames[i], IFNAMSIZ);

            print_log(MSG_INFO, "%s (bound hwaddr: " HWADDR_FMT ") is registered (fd = %d).\n",
                    info->ifnames[i], HWADDR_ARG(info->ifaddrs[i]), info->fds[i]);
        }

        strncpy(info->addr, addr, ETH_ALEN);
        info->hwid = (int)(addr[5] & HWADDR_MASK);

        /* HASH_ADD_STR(netdev_st.dev_list, addr, info); */
    }

    pthread_mutex_unlock(&netdev_st.mutex);

/*
 *     if (info) {
 *         if ((err = register_event(info->fds[SYSTEM_SIDE_DATA], EV_READ | EV_PERSIST,
 *                         ev_cb_recv_data, NULL)) < 0)
 *             print_log(MSG_ERR, "[netdevice] could not register the reception event for %s\n",
 *                     info->ifnames[SYSTEM_SIDE_DATA]);
 * 
 *         if ((err = register_event(info->fds[SYSTEM_SIDE_CONFIG], EV_READ | EV_PERSIST,
 *                         ev_cb_recv_config, NULL)) < 0)
 *             print_log(MSG_ERR, "[netdevice] could not register the reception event for %s\n",
 *                     info->ifnames[SYSTEM_SIDE_CONFIG]);
 *     }
 */

    if (info) {
        int index;

        for (index = 0; index < (netdev_st.num_of_external_interfaces >> 1); ++index) {
            if ((err = register_event(info->fds[index],
                            EV_READ | EV_PERSIST, ev_cb_recv_data, NULL)) < 0) {
                print_log(MSG_ERR,
                        "could not register the reception event for %s\n",
                        info->ifnames[SYSTEM_SIDE_DATA]);
            }
        }
    }

#ifdef ENABLE_UDEV_WATCHDOG
    while (!udev_has_multiple_devices((const char (*)[])ifnames, netdev_st.num_of_external_interfaces, "net"))
        millisleep_continue(netdev_st.sleep_interval);
        /* sleep(netdev_st.sleep_interval); */
#endif

    print_all_entries();

    return 0;

error_in_lock:
    pthread_mutex_unlock(&netdev_st.mutex);
    tap_close(info);
    gc_free(info);
    print_log(MSG_ERR, "%s\n", strerror(-err));
    return err;
}

int netdev_add_multiple_devices(char *addrlist, size_t n)
{
    size_t i = 0;

    print_log(MSG_DBG, "Setting up %zu tap interfaces\n", n);

    for (i = 0; i < n; ++i) {
        char *addr = addrlist + i * ETH_ALEN;
        netdev_add_device(addr);
    }

    return 0;
}

void* do_netdev_add_device(void *arg)
{
    /* union task_container *container = arg; */
    struct netdevice_manager_container *container = arg;

    char *addr = container->hwaddr;

    if (addr)
        netdev_add_device(addr);

    gc_free(arg);

    return NULL;
}

void* do_netdev_add_multiple_devices(void *arg)
{
    char *addrlist = genl_get_addrs();
    size_t n = genl_get_ndev();
    size_t i = 0;

    /* netdev_add_multiple_devices(addrlist, n); */

    print_log(MSG_DBG, "Starting jobs to register tap interfaces\n");

    for (i = 0; i < n; ++i) {
        /* union task_container *container = */
            /* (union task_container*)gc_calloc(1, sizeof(union task_container)); */
        struct netdevice_manager_container *container =
                (struct netdevice_manager_container*)gc_calloc(1,
                        sizeof(struct netdevice_manager_container));

        if (container) {
            strncpy(container->hwaddr, addrlist + i * ETH_ALEN, ETH_ALEN);
            /* workq_enqueue(do_netdev_add_device, container); */
            libworkqueue_enqueue_task(netdev_st.workqueue,
                    NULL, do_netdev_add_device, container);
        }
        /* netdev_add_tap_device(addrlist + i * ETH_ALEN); */
    }

    return NULL;
}

void netdev_set_flag(const char *addr, unsigned int flag)
{
/*
 *     struct devinfo *info = NULL;
 * 
 *     pthread_mutex_lock(&netdev_st.mutex);
 *     info = __netdev_find_device(addr);
 *     pthread_mutex_unlock(&netdev_st.mutex);
 */
}

static void tap_close(struct devinfo *info)
{
    int i, err = 0;

    /* for (i = 0; i < TAPFDS_MAX; ++i) { */
    for (i = 0; i < netdev_st.num_of_external_interfaces; ++i) {
        if ((err = tap_release(info->fds[i])) < 0)
            print_log(MSG_ERR,
                    "could not make %s be non-persistent.\n",
                    info->ifnames[i]);
    }
}

static void print_all_entries(void)
{
    struct devinfo *info, *tmp;

    print_log(MSG_INFO, "Tap interfaces currently available: ");

    HASH_ITER(hh, netdev_st.dev_list, info, tmp) {
        fprintf(stdout, "{%s, %s, %s, %s}, ",
                info->ifnames[SYSTEM_SIDE_DATA], info->ifnames[SYSTEM_SIDE_CONFIG],
                info->ifnames[SIMULATOR_SIDE_DATA], info->ifnames[SIMULATOR_SIDE_CONFIG]);
    }

    fprintf(stdout, "\n");
}

static void delete_entry(struct devinfo *info)
{
    tap_close(info);
    HASH_DEL(netdev_st.dev_list, info);
    gc_free(info);
}

static void delete_all_entries(void)
{
    struct devinfo *target, *tmp;

    pthread_mutex_lock(&netdev_st.mutex);

    HASH_ITER(hh, netdev_st.dev_list, target, tmp) {
        delete_entry(target);
    }

    pthread_mutex_unlock(&netdev_st.mutex);
}

int netdev_remove_device(char *hwaddr)
{
    struct devinfo *info = NULL;

    pthread_mutex_lock(&netdev_st.mutex);

    /* HASH_FIND_STR(netdev_st.dev_list, addr, info); */
    HASH_FIND(hh, netdev_st.dev_list, hwaddr, strlen(hwaddr) - 1, info);
    if (info)
        delete_entry(info);

    pthread_mutex_unlock(&netdev_st.mutex);

    return 0;
}

void netdev_remove_all_devices(void)
{
    delete_all_entries();
}

int netdevice_manager_init(void)
{
    int err = 0;

    memset(&netdev_st, 0, sizeof(struct netdevice_manager_struct));

    if (!(netdev_st.workqueue = libworkqueue_new()))
        return -ENOMEM;

    if (config_search_entry_int("netdevice_manager_sleep_interval",
                (int*)(&netdev_st.sleep_interval)) == CONFIG_FALSE) {
        netdev_st.sleep_interval = NETDEV_DEFAULT_SLEEP_INTERVAL;
    }

    print_log(MSG_WARN, "sleep interval = %u ms\n",
            netdev_st.sleep_interval);

    if (config_search_entry_int("external_interfaces",
                (int*)(&netdev_st.num_of_external_interfaces)) == CONFIG_FALSE) {
        netdev_st.num_of_external_interfaces = TAPFDS_MAX;
    } else if (netdev_st.num_of_external_interfaces > TAPFDS_MAX) {
        netdev_st.num_of_external_interfaces = TAPFDS_MAX;
    } else if (netdev_st.num_of_external_interfaces < 0) {
        netdev_st.num_of_external_interfaces = 0;
    }

    print_log(MSG_WARN, "%d external interface(s) will be set up.\n",
            netdev_st.num_of_external_interfaces);

    if ((err = pthread_mutex_init(&netdev_st.mutex, NULL)) < 0)
        return err;

    return 0;
}

void netdevice_manager_exit(void)
{
    delete_all_entries();
    libworkqueue_remove(netdev_st.workqueue);
    print_log(MSG_INFO, "Waiting for network interfaces to close...\n");
}

#undef DEBUG_IDENTIFIER
