OPENSSL_FLAGS :=--prefix=/usr --openssldir=/etc/ssl --libdir=/lib os/compiler:arm-linux-gnueabihf shared
export CFLAGS =-Wall

all:
ifneq ("$(wildcard openssl-1.0.2p_$(MODEL).tar.xz)","")
	tar -xvf openssl-1.0.2p_$(MODEL).tar.xz
	cp -r usr/* $(CROSS_COMPILE_PATH)
	rm -rf usr
else
	tar -xvf openssl-1.0.2p.tar.gz
	cd openssl-1.0.2p && ./config $(OPENSSL_FLAGS) && make CC="$(CROSS_COMPILE)gcc" && make INSTALL_PREFIX=$(BUILDROOT_BUILD_DIR)/host install_sw
endif
	cp $(BUILDROOT_BUILD_DIR)/host/usr/bin/openssl $(ROOTFS_DIR)/usr/bin
	cp -r $(BUILDROOT_BUILD_DIR)/host/etc/ssl $(ROOTFS_DIR)/etc

clean:
	@echo "do nothing"
