#!/usr/bin/env bash

# Set a hook
set -e

# Set the working directory to the directory that this script is in.
SCRIPT_ROOT="$(cd $(dirname $0); pwd)"
SCRIPT_NAME=$0

if [ $# -lt 3 ]; then
    echo "Usage: ./${SCRIPT_NAME} <target library> <dependencies ...>"
    exit 0
fi

PREFIX=$1
TARGET_LIBRARY=$2
LINKED_LIBRARIES=("${@:3}")

TARGET_MRI_SCRIPT_FILE=${PREFIX}/${TARGET_LIBRARY%.*}.mri

echo "create ${TARGET_LIBRARY}" > ${TARGET_MRI_SCRIPT_FILE}
for lib in ${LINKED_LIBRARIES[@]}; do
    extension=${lib##*.}
    if [ "${extension}" = "a" ]; then
        echo "addlib ${lib}" >> ${TARGET_MRI_SCRIPT_FILE}
    elif [ "${extension}" = "o" ]; then
        echo "addmod ${lib}" >> ${TARGET_MRI_SCRIPT_FILE}
    fi
done
echo -e "save\nend\n" >> ${TARGET_MRI_SCRIPT_FILE}

#Debug
#echo "===== ${TARGET_MRI_SCRIPT_FILE} ====="
#cat ${TARGET_MRI_SCRIPT_FILE}
#echo "===== ${TARGET_MRI_SCRIPT_FILE} ====="
