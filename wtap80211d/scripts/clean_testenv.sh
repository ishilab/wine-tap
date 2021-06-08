#!/usr/bin/env bash

ip link set wlan0 down
ip link set wlan1 down

rmmod wtap80211
modprobe -r mac80211