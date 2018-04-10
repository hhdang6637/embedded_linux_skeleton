#!/bin/sh

sudo qemu-system-i386 \
-nographic \
-kernel \
./linux-4.14.22/arch/i386/boot/bzImage \
-initrd \
./buildroot-2017.02.10/output/images/rootfs.cpio \
-append console=ttyS0 \
-serial telnet:127.0.0.1:4444,server \
-netdev tap,id=t0,ifname=vnet0,script=qemu_scripts/qemu-ifup.sh,downscript=no -device e1000,netdev=t0
