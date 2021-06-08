#!/bin/bash

# Set a hook
set -e -u

ARCH=$(dpkg --print-architecture)

# Set the working directory to a directory which this script is in.
SCRIPT_ROOT="$(cd $(dirname $0); pwd)"
PROJECT_ROOT=${SCRIPT_ROOT}/../../

# path to iw command
IW=${SCRIPT_ROOT}/../extbin/${ARCH}/iw

# Install wtap80211
modprobe mac80211
insmod ${PROJECT_ROOT}/wtap80211/wtap80211.ko devices=2 hwaddr_fixed=1

# Change the operation mode of each interface to OCB mode.
phys='wlan0 wlan1'
for phy in $phys; do
    ip link set $phy down
    $IW dev $phy set type ibss
    ip link set $phy up
done

