#!/bin/bash

SD_P1="sd_p1.img"

dd if=/dev/zero of=$SD_P1 bs=1M count=30

mkfs.vfat $SD_P1

UBOOT_SCRIPT_NAME=boot.scr
UBOOT_NAME=kernel.img
FW_NAME=fw_0

mcopy -i $SD_P1 $UBOOT_SCRIPT_NAME ::/$UBOOT_SCRIPT_NAME
mcopy -i $SD_P1 $UBOOT_NAME ::/$UBOOT_NAME
mcopy -i $SD_P1 $FW_NAME ::/$FW_NAME
