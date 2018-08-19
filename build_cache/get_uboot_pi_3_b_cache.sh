#!/bin/sh

UBOOT_CACHE=$(git ls-tree HEAD u-boot_v2018.05-rc1 | awk '{print "build_cache/"$3"_build_pi_3_b_uboot.tar.xz"}')
if [ -e $UBOOT_CACHE ]; then
	echo "found $UBOOT_CACHE , reuse it"
	tar -xvf $UBOOT_CACHE
	exit 0;
else
	echo "not found $UBOOT_CACHE"
	exit 1;
fi
