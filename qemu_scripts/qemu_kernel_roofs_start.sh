#!/bin/sh

qemu-system-arm \
-nographic \
-kernel kernel-qemu-4.4.34-jessie \
-cpu arm1176 \
-m 256 \
-M versatilepb \
-append "console=ttyAMA0,115200  root=/dev/root ro loglevel=8" \
-initrd ../build/sdcard_boot/rootfs.cpio \
-net nic \
-net user,hostfwd=tcp::2022-:22,hostfwd=tcp::2080-:80
