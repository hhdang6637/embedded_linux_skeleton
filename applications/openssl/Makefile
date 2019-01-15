OPENSSL_FLAGS :=linux-armv4 shared --prefix=/usr --openssldir=/etc/ssl --libdir=/lib zlib-dynamic
export CFLAGS =

all:
ifneq ("$(wildcard openssl-1.0.2p_$(MODEL).tar.xz)","")
	tar -xvf openssl-1.0.2p_$(MODEL).tar.xz
	cp -r usr/* $(CROSS_COMPILE_PATH)
	rm -rf usr
else
	tar -xvf openssl-1.0.2p.tar.gz
	cd openssl-1.0.2p && \
	./Configure $(OPENSSL_FLAGS) && \
	make CC="$(CROSS_COMPILE)gcc" && \
	make INSTALL_PREFIX=$(BUILDROOT_BUILD_DIR)/host install_sw
endif
	cp $(BUILDROOT_BUILD_DIR)/host/usr/bin/openssl $(ROOTFS_DIR)/usr/bin
	cp openssl-1.0.2p/libssl.so* $(ROOTFS_DIR)/usr/lib
	cp openssl-1.0.2p/libcrypto.so* $(ROOTFS_DIR)/usr/lib
	cp -r $(BUILDROOT_BUILD_DIR)/host/etc/ssl $(ROOTFS_DIR)/etc

clean:
	@echo "do nothing"
