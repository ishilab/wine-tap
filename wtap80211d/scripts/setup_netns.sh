#!/bin/bash
#
# setup_netns.sh
# Author: Arata Kato <arata.kato@outlook.com>
#

# Enable error check.
set -e -u

ARCH="$(dpkg --print-architecture)"
SCRIPT_DIR="$(cd $(dirname $0); pwd)"
EXTBIN_DIR="${SCRIPT_DIR}/../extbin/${ARCH}/"
IW="${EXTBIN_DIR}/iw"

SLEEP_INTERVAL=10

declare -r NETWORK_ADDR="10.0.0"
declare -r BROADCAST_ADDR="10.255.255.255"
declare -r NETWORK_MASK=8

# Check arguments
opmode=""
if [[ $# -eq 0 ]]; then
    echo -e "\033[1;37mNOTE: Opmode is automatically set to ibss.\033[0;39m"
    opmode="ibss";
else
    echo -e "\033[1;37mNOTE: Opmode is set to ${1}.\033[0;39m";
    opmode="${1}";
fi

echo -e "\033[1;37m==> Checking relations between wiphys and network interfaces...\033[0;39m"

IFS=$'\n'
declare -A interfaces=()
declare -A netspaces=()
declare -A ipaddrs=()

for line in `iw dev | grep -E "phy|wlan" | sed -e 's/#//g' -e 's/Interface//g' | sed -E '/(phy.*)/N;s/\n/ /g'`; do
    IFS=" "; set -- $line; interfaces[$1]=$3;
done

# Check if there are wiphys.
[[ ${#interfaces[@]} -gt 0 ]] && echo -e "\033[1;37m${#interfaces[@]} wiphys found.\033[0;39m" || exit 1

# declare -A ipaddrs=()
echo "New network namespaces below will be created."
for wiphy in ${!interfaces[@]}; do
    ipaddrs[$wiphy]=""${NETWORK_ADDR}".$((`echo ${interfaces[$wiphy]} | sed -e 's/wlan//g'` + 1))";
    netspaces[$wiphy]="netspace-"$wiphy"";
    echo -e "\t${netspaces[$wiphy]}: $wiphy <-> ${interfaces[$wiphy]}";
done

echo -e "\033[1;37m==> Creating new namespaces...\033[0;39m"

# Make network namespaces
for wiphy in ${!interfaces[@]}; do

    # if [ $wiphy = 'phy0' ]; then
    #     continue
    # fi

    interface="${interfaces[$wiphy]}"
    netspace="${netspaces[$wiphy]}"
    ipaddr=${ipaddrs[$wiphy]}

    echo -e "\033[1;37m\r\e[2KSetting up a network namespace (${netspace}) to $wiphy (${interface})...\033[0;39m"

    # Make the target interface be down.
    echo -ne "\033[0;37m\r\e[2KTurning $wiphy (${interface}) down...\033[0;39m"
    (ip link set ${interface} down) && sleepenh ${SLEEP_INTERVAL} > /dev/null || exit $?

    # Create a new network namespace.
    echo -ne "\033[0;37m\r\e[2KCreating new network namespace ${netspace}...\033[0;39m"
    (ip netns add ${netspace}) && sleepenh ${SLEEP_INTERVAL} > /dev/null || exit $?

    # Bind the @wiphy to the namespace.
    echo -ne "\033[0;37m\r\e[2KBinding $wiphy (${interface}) to ${netspace}...\033[0;39m"
    (${IW} phy $wiphy set netns name ${netspace}) && sleepenh ${SLEEP_INTERVAL} > /dev/null || exit $?
    # (${IW} phy $wiphy set netns "`ip netns exec ${netspace} sh -c 'sleep 9999 >&- & echo "$!"'`") \
        #     && sleepenh ${SLEEP_INTERVAL} > /dev/null
    #     || exit $?

    # Initialize configurations of the network interface.
    echo -ne "\033[0;37m\r\e[2KAssigning ${interface}'s ipaddr: "${ipaddr}"/"${NETWORK_MASK}": bcast: "${BROADCAST_ADDR}"\033[0;39m"
    (ip netns exec ${netspace} ip addr add ${ipaddr}/${NETWORK_MASK} brd "${BROADCAST_ADDR}" dev ${interface}) \
        && sleepenh ${SLEEP_INTERVAL} > /dev/null \
        | exit $?

    # Set the operation mode of the interface to IBSS.
    echo -ne "\033[0;37m\r\e[2KChanging ${wiphy}'s opmode to ibss...\033[0;39m"
    (ip netns exec ${netspace} ${IW} dev ${interface} set type ${opmode}) \
        && sleepenh ${SLEEP_INTERVAL} > /dev/null \
        | exit $?

done

echo -e "\r\033[1;37mAll network namespaces were configured successfully.\033[0;39m"
echo -e "\r\033[1;37mWARNING: Do not manipulate the namespaces immediately because the initialization process might be in progress.\033[0;39m"
