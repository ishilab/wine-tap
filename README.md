# WiNE-Tap: Wireless Network Emulator using Wireless Network Tap Device

## Overview

WiNE-Tap (Wireless Network Emulator using wireless network Tap device) is an IEEE 802.11 network emulator using a wireless network tap device (wtap80211), a virtual SoftMAC driver.

## Requirements

WiNE-Tap is designed to work between Linux 3.19 and 4.4. The Linux kernel headers are required to compile wtap80211. wtap80211 works with the Linux IEEE 802.11 implementation and depends on kernel modules, cfg80211 and mac80211.

## Build instructions

### Building wtap80211

Move to the source directory named with wtap80211 and execute the following commands.

```bash
# Install the linux kernel headers and build wtap80211
$ apt -y install linux-headers-`uname -r`
$ make

# Install wtap80211 into the system
$ sudo modprobe mac80211
$ sudo insmod wtap80211
```

### Building wtap80211 daemon (wtap80211d)

The executable binary of wtap80211 daemon is generated under the directory, `wtap80211d`.

```bash
# Make directories to put some built binaries
$ make {lib,test}

# Install some requirements from apt repositories
$ apt -y install libudev-dev libconfig-dev uuid-dev liblzma-dev

# Extract other pre-compiled requirements.
$ cd extlib/
$ bash extract_lib.sh
$ cd -

# Build the daemon
$ make all
```
