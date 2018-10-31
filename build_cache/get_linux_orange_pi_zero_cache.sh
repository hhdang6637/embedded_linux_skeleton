#!/bin/sh

LINUX_CACHE=$(git ls-tree HEAD linux | awk '{print "build_cache/"$3"_build_orange_pi_zero_linux.tar.xz"}')
if [ -e $LINUX_CACHE ]; then
	echo "found $LINUX_CACHE , reuse it"
	tar -xvf $LINUX_CACHE
	exit 0;
else
	echo "not found $LINUX_CACHE"
	exit 1;
fi
