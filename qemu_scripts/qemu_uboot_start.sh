#!/bin/sh

echo "currently, we don't know any ways to start our uboot with qemu-system-arm"

# sudo qemu-system-x86_64 \
# -nographic \
# -bios ./build/bin/u-boot.rom \
# -netdev tap,id=t0,ifname=vnet0,script=qemu_scripts/qemu-ifup.sh,downscript=no -device e1000,netdev=t0

