#!/bin/bash

# Todo: support multiple distribuions

# Set a hook
set -e

# Set the working directory to the current one
SCRIPT_ROOT="$(cd $(dirname $0); pwd)"
PROJECT_ROOT=${SCRIPT_ROOT}/../../

ARCH=$(uname -m)

if [ ${ARCH} = 'x86_64' ]; then
    tar -zxf ${SCRIPT_ROOT}/glibc-2.23.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libcrc-2.0.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/iproute2-4.3.0.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libgc-7.4.18.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libnl-3.2.29.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/uthash_v2.1.0.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libevent-2.1.11.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libunwind-1.3.1.tar.gz -C ${SCRIPT_ROOT}
elif [ ${ARCH} = 'armhf' ]; then
    tar -zxf ${SCRIPT_ROOT}/libcrc-2.0-${ARCH}.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/iproute2-4.3.0-${ARCH}.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libgc-7.4.18-${ARCH}.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libnl-3.2.29-${ARCH}.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/uthash_v2.1.0.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libevent-2.1.11-${ARCH}.tar.gz -C ${SCRIPT_ROOT}
    tar -zxf ${SCRIPT_ROOT}/libunwind-1.3.1-${ARCH}.tar.gz -C ${SCRIPT_ROOT}
fi
