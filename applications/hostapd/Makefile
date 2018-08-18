BIN := hostapd-2.6/hostapd/hostapd
export CFLAGS =-Wall -I$(CROSS_COMPILE_PATH)/include -L$(CROSS_COMPILE_PATH)/lib -I $(CROSS_COMPILE_PATH)/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/include/libnl3
export LDFLAGS=-L$(CROSS_COMPILE_PATH)/lib -L$(CROSS_COMPILE_PATH)/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/lib

$(BIN):
	tar -xvf hostapd-2.6.tar.gz
	cp defconfig hostapd-2.6/hostapd/.config
	cd hostapd-2.6/hostapd && make

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install

clean:
	@echo "do nothing"
