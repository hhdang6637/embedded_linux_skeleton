#!/bin/bash

SD_P1="sd_p1.img"

dd if=/dev/zero of=$SD_P1 bs=1M count=220

mkfs.vfat $SD_P1

UBOOT_SCRIPT_NAME=boot.scr
UBOOT_NAME=kernel.img
FW_NAME=firmware

mcopy -i $SD_P1 $UBOOT_SCRIPT_NAME ::/
mcopy -i $SD_P1 $UBOOT_NAME ::/

echo "0" > firmware_selected
mcopy -i $SD_P1 firmware_selected               ::/
mcopy -i $SD_P1 $FW_NAME ::/firmware_0
mcopy -i $SD_P1 $FW_NAME ::/firmware_1

dd if=/dev/zero of=sd_test.img bs=1M count=512

parted -s sd_test.img \
mklabel msdos \
mkpart primary fat16 1M 221M \
mkpart primary ext4 221M 100%

dd if=$SD_P1 of=sd_test.img seek=1 bs=1M count=220 conv=notrunc

# run this command in qemu to workarounf "mke2fs /dev/mmcblk0p2 && reboot"