#!/bin/bash

SD_P1="sd_p1.img"

UBOOT_SCRIPT_NAME=boot.scr
UBOOT_NAME=kernel.img

dd if=/dev/zero of=$SD_P1 bs=1M count=220
mkfs.vfat $SD_P1
mcopy -i $SD_P1 $PI_BOOT_DIR/start.elf          ::/
mcopy -i $SD_P1 $PI_BOOT_DIR/fixup.dat          ::/
mcopy -i $SD_P1 $PI_BOOT_DIR/bootcode.bin       ::/
mcopy -i $SD_P1 $PI_BOOT_DIR/LICENCE.broadcom   ::/
mcopy -i $SD_P1 $PI_BOOT_DIR/LICENSE.oracle     ::/
mcopy -i $SD_P1 $UBOOT_SCRIPT_NAME              ::/
mcopy -i $SD_P1 $UBOOT_NAME                     ::/

echo "0" > firmware_selected
mcopy -i $SD_P1 firmware_selected               ::/
mcopy -i $SD_P1 firmware                        ::/firmware_0
mcopy -i $SD_P1 firmware                        ::/firmware_1
