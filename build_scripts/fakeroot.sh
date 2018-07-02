cd $BUILD_DIR
mkdir -p rootfs_tmp
cd rootfs_tmp
cpio -i < $BIN_BUILD_DIR/rootfs.cpio
mkdir -p lib/modules/4.14.22/kernel
cp -r $LINUX_MOD_BUILD_DIR/lib .
cp -r $SKELETON_ROOTFS_DIR/* .
cp -r $ROOTFS_DIR/* .
find . -print | cpio -o -H newc > ../sdcard_boot/rootfs.cpio
cd ..
rm -rf rootfs_tmp
