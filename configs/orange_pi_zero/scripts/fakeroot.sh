#!/bin/sh

cd $BUILD_DIR
mkdir -p rootfs_tmp
cd rootfs_tmp
cpio -i < $BIN_BUILD_DIR/rootfs.cpio
mkdir -p lib/modules/4.14.67/kernel
cp -r $LINUX_MOD_BUILD_DIR/lib .
cp -r $SKELETON_ROOTFS_DIR/* .
cp -r $ROOTFS_DIR/* .
mkdir -p lib/firmware
cp -r $FIRMWARE_NONFREE/xr819 lib/firmware

# remove /var/run
if [ -e var/run ]; then
    rm -rf var/run
fi
# add new symbol link /var/run -> /tmp
cd var && ln -sf ../tmp run && cd ..

# remove /root
if [ -e root ]; then
    rm -rf root
fi
# add new symbol link /root -> /tmp/root
ln -sf tmp/root root
rm -rf run; ln -sf tmp run
ln -sf tmp home

rm etc/passwd
cd etc && ln -sf ../tmp/passwd passwd && cd ..

# mkdir /boot
mkdir boot

find . -print | cpio -o -H newc > ../sdcard_boot/rootfs.cpio
cd ..
rm -rf rootfs_tmp