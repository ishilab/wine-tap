#!/bin/bash

ip link set $1 down
iw dev $1 set type $2
ip link set $1 up
