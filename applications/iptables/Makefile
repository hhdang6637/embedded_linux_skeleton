BIN := iptables-1.6.2/iptables/.libs/xtables-multi
IPTABLES_FLAGS := --target=arm-none-linux-gnueabi --host=armv7-none-linux-gnueabi \
--prefix=$(CROSS_COMPILE_PATH) \
--disable-nftables
export CFLAGS =-Wall

$(BIN):
	tar -xvf iptables-1.6.2.tar.bz2
	cd iptables-1.6.2 && ./configure $(IPTABLES_FLAGS) && make

install:
	cp $(BIN) $(ROOTFS_DIR)/sbin
	cp -av iptables-1.6.2/libiptc/.libs/lib*.so* $(ROOTFS_DIR)/usr/lib
	cp -av iptables-1.6.2/libxtables/.libs/lib*.so* $(ROOTFS_DIR)/usr/lib
	cp -av iptables-1.6.2/extensions/libxt_conntrack.so $(ROOTFS_DIR)/usr/lib
	cp -av iptables-1.6.2/extensions/libxt_standard.so $(ROOTFS_DIR)/usr/lib
	cp -av iptables-1.6.2/extensions/libipt_MASQUERADE.so $(ROOTFS_DIR)/usr/lib
	cd $(ROOTFS_DIR)/sbin && ln -fs xtables-multi iptables
	cd $(ROOTFS_DIR)/sbin && ln -fs xtables-multi iptables-restore
	cd $(ROOTFS_DIR)/sbin && ln -fs xtables-multi iptables-save
	cd $(ROOTFS_DIR)/usr/bin && ln -fs ../../sbin/xtables-multi iptables-xml

all: $(BIN) install

clean:
	@echo "do nothing"
