#!/bin/sh

sudo qemu-system-x86_64 \
-nographic \
-bios u-boot_v2018.05-rc1/u-boot.rom \
-netdev tap,id=t0,ifname=vnet0,script=qemu_scripts/qemu-ifup.sh,downscript=no -device e1000,netdev=t0

