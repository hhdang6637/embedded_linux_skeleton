cd $BUILD_DIR
mkdir -p rootfs
cd rootfs
cpio -i < $BIN_BUILD_DIR/rootfs.cpio
mkdir -p lib/modules/4.14.22/kernel
cp -r $LINUX_MOD_BUILD_DIR/lib .
find . -print | cpio -o > ../sdcard_boot/rootfs.cpio
cd ..
rm -rf rootfs
