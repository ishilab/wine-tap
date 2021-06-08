#
# setup_netns.sh
#

#!/bin/bash

# Network configuration parameters
# declare -r global_ipaddr="10.10.10"
# declare -r brd_ipaddr=""$global_ipaddr".255"
# declare -r mask=24

# Enable error check.
set -e -u

ARCH="$(dpkg --print-architecture)"
SCRIPT_DIR="$(cd $(dirname $0); pwd)"
EXTBIN_DIR="${SCRIPT_DIR}/../extbin/${ARCH}/"
IW="${EXTBIN_DIR}/iw"

NETWORK_ADDR="10.0.0"
BROADCAST_ADDR="${NETWORK_ADDR}.255"
NETWORK_MASK=24

# Check arguments

echo -e "\033[1;37mChecking a relation between wiphy and its network interface...\033[0;39m"

IFS=$'\n'
declare -A interfaces=()
declare -A netspaces=()
declare -A ipaddrs=()
for line in `iw dev | grep -E "phy|wlan" | sed -e 's/#//g' -e 's/Interface//g' | sed -E '/(phy.*)/N;s/\n/ /g'`; do
    IFS=" "; set -- $line; interfaces[$1]=$3;
done

if [ ${#interfaces[@]} -lt 1 ]; then
    exit 1;
fi

echo -e "\033[1;37m${#interfaces[@]} wiphys found.\033[0;39m"

# declare -A ipaddrs=()
for wiphy in ${!interfaces[@]}; do
   ipaddrs[$wiphy]=""${NETWORK_ADDR}".$((`echo ${interfaces[$wiphy]} | sed -e 's/wlan//g'` + 1))";
   netspaces[$wiphy]="netspace-"$wiphy"";
   echo ${netspaces[$wiphy]};
done

echo -e "\033[1;37m==> Allocating namespaces...\033[0;39m"

# Make network namespaces
for wiphy in ${!interfaces[@]}; do

    # if [ $wiphy = 'phy0' ]; then
    #     continue
    # fi

    # echo -ne "\r\033[1;37mSetting a network namespace (${netspaces[$wiphy]}) to $wiphy (${interfaces[$wiphy]})...\033[0;39m"

    echo -e "\033[1;37mSetting a network namespace (${netspaces[$wiphy]}) to $wiphy (${interfaces[$wiphy]})...\033[0;39m"

    # Make the interface be down.
    echo -e "\033[0;37mMaking $wiphy (${interfaces[$wiphy]}) down...\033[0;39m"
    ip link set "${interfaces[$wiphy]}" down || exit $?

    sleepenh 10.0 > /dev/null

    # Create a network namespace.
    echo -e "\033[0;37mAdd new network namespace ${netspaces[$wiphy]}...\033[0;39m"
    ip netns add "${netspaces[$wiphy]}" || exit $?

    sleepenh 10.0 > /dev/null

    # Bind the @wiphy to the namespace.
    echo -e "\033[0;37mBinding $wiphy (${interfaces[$wiphy]}) to ${netspaces[$wiphy]}...\033[0;39m"
    ${IW} phy $wiphy set netns "`ip netns exec ${netspaces[$wiphy]} sh -c 'sleep 9999 >&- & echo "$!"'`" || exit $?

    sleepenh 10.0 > /dev/null

    # Initialize configurations of the network interface.
    echo -e "\033[0;37m==> ${interfaces[$wiphy]}'s addr: "${ipaddrs[$wiphy]}"/"${NETWORK_MASK}": bcast: "${BROADCAST_ADDR}"\033[0;39m"
    ip netns exec "${netspaces[$wiphy]}" ip addr add ${ipaddrs[$wiphy]}/${NETWORK_MASK} brd "${BROADCAST_ADDR}" dev "${interfaces[$wiphy]}"
    # echo -e "\033[1;37m==> ${interfaces[$wiphy]}'s ip address: "${ipaddrs[$wiphy]}"/"$mask": brd: "$brd_ipaddr"\033[0;39m"
    # ip netns exec "${netspaces[$wiphy]}" ip addr add ${ipaddrs[$wiphy]}/$mask brd "$brd_ipaddr" dev "${interfaces[$wiphy]}"

    sleepenh 10.0 > /dev/null

    # Set the operation mode of the interface to IBSS.
    ip netns exec "${netspaces[$wiphy]}" ${IW} dev ${interfaces[$wiphy]} set type ocb

    # Wake the interface up.
    # ip netns exec "${netspaces[$wiphy]}" ip link set lo up
    # ip netns exec "${netspaces[$wiphy]}" ip link set ${interfaces[$wiphy]} up
    # ip netns exec "${netspaces[$wiphy]}" iw dev ${interfaces[$wiphy]} ibss join test 2412

    # Check the current state of the interface
    # ip netns exec "${netspaces[$wiphy]}" iwconfig

    # Waiting till the interface has waken up completely to avoid resource conflicts.
    sleepenh 10.0 > /dev/null
done

echo -e "\r\033[1;37mAll network namespaces were configured successfully.\033[0;39m"
echo -e "\r\033[1;37mWARNING: Do not manipulate the network namespaces for a few seconds because initialization process may be not finished yet.\033[0;39m"
