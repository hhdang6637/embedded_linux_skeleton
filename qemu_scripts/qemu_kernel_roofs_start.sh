#!/bin/sh

sudo qemu-system-i386 \
-nographic \
-kernel \
./build/bin/bzImage \
-initrd \
./build/bin/rootfs.cpio \
-append console=ttyS0 \
-serial telnet:127.0.0.1:4444,server \
-netdev tap,id=t0,ifname=vnet0,script=qemu_scripts/qemu-ifup.sh,downscript=no -device e1000,netdev=t0
