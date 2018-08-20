OPENSSL_FLAGS :=--prefix=$(CROSS_COMPILE_PATH) os/compiler:arm-linux-gnueabihf shared 
export CFLAGS =-Wall

all:
	tar -xvf openssl-1.0.2p.tar.gz
	cd openssl-1.0.2p && ./config $(OPENSSL_FLAGS) && make CC="$(CROSS_COMPILE)gcc" && make install

	# cp $(BIN) $(ROOTFS_DIR)/usr/bin
	#cp -av libnl-3.2.25/lib/.libs/libnl-3.so* $(ROOTFS_DIR)/usr/lib
	#cp -av libnl-3.2.25/lib/.libs/libnl-genl-3.so* $(ROOTFS_DIR)/usr/lib

clean:
	@echo "do nothing"
