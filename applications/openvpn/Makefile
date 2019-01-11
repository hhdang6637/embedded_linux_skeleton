BIN := openvpn-2.4.6/src/openvpn/openvpn
OPENVPN_FLAGS := --target=arm-none-linux-gnueabi --host=armv7-none-linux-gnueabi \
--prefix=$(CROSS_COMPILE_PATH) \
--includedir=$(CROSS_COMPILE_PATH)/usr/include \
--libdir=$(CROSS_COMPILE_PATH)/usr/lib \
--disable-lz4 \
--disable-lzo \
--disable-plugin-auth-pam

export CFLAGS =-I$(CROSS_COMPILE_PATH)/include -L$(CROSS_COMPILE_PATH)/lib -Wl,-rpath=$(CROSS_COMPILE_PATH)/lib
export CXXFLAGS =-I$(CROSS_COMPILE_PATH)/include -L$(CROSS_COMPILE_PATH)/lib -Wl,-rpath=$(CROSS_COMPILE_PATH)/lib

$(BIN):
ifneq ("$(wildcard openvpn-2.4.6_$(MODEL).tar.xz)","")
	tar -xvf openvpn-2.4.6_$(MODEL).tar.xz
else
	tar -xvf openvpn-2.4.6.tar.gz
	cd openvpn-2.4.6 &&  autoreconf -vi && ./configure $(OPENVPN_FLAGS) && make
endif
install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install

clean:
	@echo "do nothing"
