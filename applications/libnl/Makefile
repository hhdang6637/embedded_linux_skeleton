LIBNL_FLAGS := --target=arm-none-linux-gnueabi --host=armv7-none-linux-gnueabi \
--prefix=$(CROSS_COMPILE_PATH)/arm-buildroot-linux-uclibcgnueabi/sysroot/usr
export CFLAGS =-Wall

all:
	tar -xvf libnl-3.2.25.tar.gz
	cd libnl-3.2.25 && ./configure $(LIBNL_FLAGS) && make && make install

	# cp $(BIN) $(ROOTFS_DIR)/usr/bin
	cp -av libnl-3.2.25/lib/.libs/libnl-3.so* $(ROOTFS_DIR)/usr/lib
	cp -av libnl-3.2.25/lib/.libs/libnl-genl-3.so* $(ROOTFS_DIR)/usr/lib

clean:
	@echo "do nothing"
