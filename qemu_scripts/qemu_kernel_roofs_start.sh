#!/bin/sh

qemu-system-arm \
-M vexpress-a9 \
-m 512 \
-nographic \
-kernel ./build/arm_vexpress_a9/bin/u-boot \
-sd ./build/arm_vexpress_a9/sdcard_boot/sd_p1.img \
-net nic \
-net user,hostfwd=tcp::2022-:22,hostfwd=tcp::2080-:80
