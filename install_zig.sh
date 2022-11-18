#!/bin/bash

set -eux

# Thanks to https://stackoverflow.com/questions/3466166/how-to-check-if-running-in-cygwin-mac-or-linux
unames=$(uname -s)
case "$unames" in
    Linux*)     HOST_ARCH="x86_64-linux";;
    Darwin*)    HOST_ARCH="x86_64-macos";;
    *)          echo "Unknown HOST_ARCH=$(uname -s)"; exit 1;;
esac

ZIG_VERSIONS=$(curl https://ziglang.org/download/index.json)

ZIG_MASTER_TAR=$(echo $ZIG_VERSIONS | jq -r ".master.\"$HOST_ARCH\".tarball")
ZIG_MASTER_SHA256=$(echo $ZIG_VERSIONS | jq -r ".master.\"$HOST_ARCH\".shasum")

ZIG_TAR_NAME="zig-master.tar.xz"

if [ -e $ZIG_TAR_NAME ]; then
    rm $ZIG_TAR_NAME
fi

curl $ZIG_MASTER_TAR -o zig-master.tar.xz
TAR_SHA256=$(shasum -a 256 $ZIG_TAR_NAME | awk '{print $1}')
if [ "$TAR_SHA256" != "$ZIG_MASTER_SHA256" ]; then
    echo "Invalid SHASUM!"
    exit 1
fi

INSTALL_DIR="$HOME/.local/zig-master"
if [ -e $INSTALL_DIR ]; then
    rm -rf $INSTALL_DIR
fi
mkdir -p $INSTALL_DIR

tar -xvf $ZIG_TAR_NAME -C $INSTALL_DIR --strip-components 1
rm $ZIG_TAR_NAME
set +e
cat ~/.bashrc | grep "PATH=\$PATH:$HOME/.local/zig-master"
if [ $? -ne 0 ]; then
    echo "PATH=\$PATH:$HOME/.local/zig-master" >> ~/.bashrc
fi
set -e