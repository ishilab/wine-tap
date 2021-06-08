#!/bin/bash

modprobe mac80211
insmod ../wtap80211/wtap80211.ko devices=$1
