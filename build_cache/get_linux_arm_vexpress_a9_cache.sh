#!/bin/sh

LINUX_CACHE=$(git ls-tree HEAD linux-4.14.22 | awk '{print "build_cache/"$3"_build_arm_vexpress_a9_linux.tar.gz"}')
if [ -e $LINUX_CACHE ]; then
	echo "found $LINUX_CACHE , reuse it"
	tar -xvf $LINUX_CACHE
	exit 0;
else
	echo "not found $LINUX_CACHE"
	exit 1;
fi