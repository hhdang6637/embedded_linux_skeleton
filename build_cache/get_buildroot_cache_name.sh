#!/bin/sh

BUILDROOT_CACHE=$(git ls-tree HEAD | grep buildroot | awk '{print "build_cache/"$3"_build_pi_b_plus_buildroot.tar.gz"}')
if [ -e $BUILDROOT_CACHE ]; then
	echo "found $BUILDROOT_CACHE , reuse it"
	tar -xvf $BUILDROOT_CACHE
	sed -i 's?/home/builder/code/embedded_linux_skeleton?'$PWD'?' build/pi_b_plus/buildroot/host/usr/bin/fakeroot
	exit 0;
else
	echo "not found $BUILDROOT_CACHE"
	exit 1;
fi
