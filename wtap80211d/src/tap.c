/*
 * tap.c
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
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_link.h>
/* #include <linux/rtnetlink.h> */
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libconfig.h>
#include "utils.h"
#include "misc.h"
#include "config_manager.h"

/* Pre 2.4.6 compatibility */
#ifndef OTUNSETNOCSUM
# define OTUNSETNOCSUM  (('T' << 8) | 200)
# define OTUNSETDEBUG   (('T' << 8) | 201)
# define OTUNSETIFF     (('T' << 8) | 202)
# define OTUNSETPERSIST (('T' << 8) | 203)
# define OTUNSETOWNER   (('T' << 8) | 204)
#endif

#ifdef ENABLE_DEBUG

#define TUN_FEATURES (IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR | IFF_MULTI_QUEUE)

static void print_fdstat(int fd)
{
    struct stat s = {0};
    int err = 0;

    if ((err = fstat(fd, &s)) < 0) {
        print_log(MSG_ERR,
                "[libtap] Getting the fd status failed (reason: %s (code: %d))\n",
                strerror(-err), err);
        return ;
    }

    print_log(MSG_DBG,
            "\n\t[tap] File descriptor information:\n"
            "\t\t fd     : %d\n"
            "\t\t devid  : %u\n"
            "\t\t inode  : %ld\n"
            "\t\t mode   : 0x%0lx\n"
            "\t\t link   : %ld\n"
            "\t\t uid    : %ld (0x%0lx)\n"
            "\t\t gid    : %ld (0x%0lx)\n"
            "\t\t rdevid : %u (0x%0x)\n"
            "\t\t size   : %lld\n"
            "\t\t blksize: %ld (0x%0lx)\n"
            "\t\t blkcnt : %lld (0x%0llx)\n",
            fd,
            (unsigned int)s.st_dev, (long)s.st_ino,
            (unsigned long)s.st_mode, (long)s.st_nlink,
            (long)s.st_uid, (long)s.st_uid,
            (long)s.st_gid, (long)s.st_gid,
            (unsigned int)s.st_rdev, (unsigned int)s.st_rdev,
            (long long)s.st_size,
            (long)s.st_blksize, (long)s.st_blksize,
            (long long)s.st_blocks, (long long)s.st_blocks);
}

static void print_tapinfo(int fd)
{
    struct ifreq ifr = {{{0}},{{0}}};
    int err = 0;

    /* rtnl_lock(); */
    err = ioctl(fd, TUNGETIFF, &ifr);
    /* rtnl_unlock(); */

    if (err < 0)
        return ;

    print_log(MSG_DBG,
            "\n\t[tap] Tap device information:\n"
            "\t\t fd     : %d\n"
            "\t\t devname: %s\n"
            "\t\t flags  : 0x%x\n"
            "\t\t   feature: %s%s%s%s(0x%04x)\n"
            "\t\t   persist: %s (0x%04x)\n"
            "\t\t   type   : %s (0x%04x)\n",
            fd,
            ifr.ifr_name,
            ifr.ifr_flags,
            (ifr.ifr_flags & IFF_NO_PI) ? "IFF_NO_PI " : "",
            (ifr.ifr_flags & IFF_ONE_QUEUE) ? "IFF_ONE_QUEUE " : "",
            (ifr.ifr_flags & IFF_VNET_HDR) ? "IFF_VNET_HDR " : "",
            (ifr.ifr_flags & IFF_MULTI_QUEUE) ? "IFF_MULTI_QUEUE " : "",
            ifr.ifr_flags & TUN_FEATURES,
            (ifr.ifr_flags & IFF_PERSIST) ? "yes": "no",
            ifr.ifr_flags & IFF_PERSIST,
            ((ifr.ifr_flags & IFF_TUN) ? "tun"
                : (ifr.ifr_flags & IFF_TAP) ? "tap" : "unknown"),
            ifr.ifr_flags & (IFF_TUN | IFF_TAP));
}

#else

#define print_tapinfo(arg, ...) (void)(0)
#define print_fdstat(arg, ...) (void)(0)

#endif /* ENABLE_DEBUG */

static int tap_setflags_sk(char *ifname, unsigned int flags)
{
    struct ifreq ifr = {{{0}},{{0}}};
    int skfd = 0;
    int ret = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -EINVAL;

    copy_ifname(ifr.ifr_name, ifname);
    ifr.ifr_flags |= flags;

    /* rtnl_lock(); */
    ret = ioctl(skfd, SIOCSIFFLAGS, (void*)&ifr);
    /* rtnl_unlock(); */

    close(skfd);

    return ret;
}

int tap_ifup_name(char *ifname)
{
    return tap_setflags_sk(ifname, IFF_UP);
}

int tap_ifdown_name(char *ifname)
{
    return tap_setflags_sk(ifname, ~IFF_UP);
}

int tap_get_hwaddr(const char *ifname, char *hwaddr)
{
    struct ifreq ifr = {{{0}},{{0}}};
    int err = 0;
    int fd = 0;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -EINVAL;

    ifr.ifr_addr.sa_family = AF_INET;
    copy_ifname(ifr.ifr_name, ifname);

    /* rtnl_lock(); */
    err = ioctl(fd, SIOCGIFHWADDR, &ifr);
    /* rtnl_unlock(); */

    close(fd);

    if (!(err < 0))
        memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return err;
}

#define DEFAULT_NETWORK_ADDRESS "10.0.0.0"

static void generate_unique_addr(char *ipaddr, int index)
{
    const char *buf;
    char new_addr[IPADDR_LEN] = {0};
    int bitsets[4] = {0};
    static int count = 1;

    if (config_search_entry_string("network_address", &buf) == CONFIG_FALSE)
        sscanf(DEFAULT_NETWORK_ADDRESS,
                "%d.%d.%d.%d", &bitsets[0], &bitsets[1], &bitsets[2], &bitsets[3]);
    else
        sscanf(buf, "%d.%d.%d.%d", &bitsets[0], &bitsets[1], &bitsets[2], &bitsets[3]);

    /* bitsets[3] = index; */
    bitsets[3] = count++;
    snprintf(new_addr, IPADDR_LEN, "%d.%d.%d.%d",
            bitsets[0], bitsets[1], bitsets[2], bitsets[3]);

    memcpy(ipaddr, new_addr, IPADDR_LEN);
}

int tap_set_ipaddr(char *ifname, int index)
{
    struct ifreq ifr = {{{0}},{{0}}};
    struct sockaddr_in *addr = NULL;
    char new_addr[IPADDR_LEN + 1] = {0};
    int skfd = 0;
    int ret = 0;
    static int count = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -EINVAL;

    generate_unique_addr(new_addr, ((index < 0) ? ++count : index));

    print_log(MSG_DBG, "[tap] ip address (%s) assigned to %s\n", new_addr, ifname);

    copy_ifname(ifr.ifr_name, ifname);
    addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(new_addr);
    /* inet_pton(AF_INET, new_addr, &addr->sin_addr); */

    /* rtnl_lock(); */
    ret = ioctl(skfd, SIOCSIFADDR, (void*)&ifr);
    /* rtnl_unlock(); */

    close(skfd);

    return ret;
}

static int tap_setflags(int fd, unsigned int flags, int enabled)
{
    struct ifreq ifr = {{{0}},{{0}}};

    /* rtnl_lock(); */

    if (ioctl(fd, SIOCGIFFLAGS, (void*)&ifr) < 0) {
        /* rtnl_unlock(); */
        return -EBUSY;
    }

    if (enabled)
        ifr.ifr_flags |= flags;
    else
        ifr.ifr_flags &= ~flags & 0xffff;

    if (ioctl(fd, SIOCGIFFLAGS, (void*)&ifr) < 0) {
        /* rtnl_unlock(); */
        return -EINVAL;
    }

    return 0;
}

int tap_ifup(int fd)
{
    return tap_setflags(fd, IFF_UP | IFF_RUNNING, 1);
}

int tap_ifdown(int fd)
{
    return tap_setflags(fd, IFF_UP | IFF_RUNNING, 0);
}

int tap_alloc(char *dev)
{
    struct ifreq ifr = {{{0}},{{0}}};
    int fd = 0;
    int err = 0;

    /* if ((fd = open("/dev/net/tun", O_RDWR | O_CREAT)) < 0) */
    if ((fd = open("/dev/net/tun", O_RDWR, S_IRWXU)) < 0)
        return fd;

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (*dev)
        copy_ifname(ifr.ifr_name, dev);

    /* rtnl_lock(); */

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        if (err == EBADFD) {
            /* Try old ioctl command */
            if ((err = ioctl(fd, OTUNSETIFF, (void*)&ifr)) < 0)
                goto error;
        } else {
            goto error;
        }
    }

    /* rtnl_unlock(); */

    strcpy(dev, ifr.ifr_name);
    return fd;

error:
    /* rtnl_unlock(); */
    close(fd);
    return err;
}

bool tap_set_persist(int fd, int flag)
{
    int err = 0;

    /* rtnl_lock(); */
    err = (ioctl(fd, TUNSETPERSIST, flag) < 0);
    /* rtnl_unlock(); */

    return !(err < 0);
}

bool tap_set_owner(int fd, uid_t uid)
{
    int err = 0;

    /* rtnl_lock(); */
    err = ioctl(fd, TUNSETOWNER, uid);
    /* rtnl_unlock(); */

    return !(err < 0);
}

int tap_iplink_setup(char *ifname)
{
    int fd, err = 0;

    if ((fd = tap_alloc(ifname)) < 0) {
        err = fd;
        print_log(MSG_ERR, "[tap] Could not create a tap interface (reason: %s (code: %d))\n",
                strerror(-err), err);
        return -EBUSY;
    }

    tap_set_persist(fd, 1);
    tap_set_owner(fd, getuid());

    if ((err = tap_set_ipaddr(ifname, 0)) < 0)
        print_log(MSG_ERR, "[tap] Could assign ip address to %s (reason: %s (code: %d))\n",
                ifname, strerror(-err), err);

    if ((err = tap_ifup_name(ifname) < 0))
        print_log(MSG_ERR, "[tap] Could make %s be up (reason: %s (code: %d))\n",
                ifname, strerror(-err), err);

    return fd;
}

int tap_release(int fd)
{
    int err = 0;

    /* rtnl_lock(); */

    if ((err = ioctl(fd, TUNSETPERSIST, 0)) < 0) {
        /* rtnl_unlock(); */
        return err;
    }

    /* rtnl_unlock(); */

    close(fd);

    return 0;
}
