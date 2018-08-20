BIN := ntp-4.2.8p8/ntpd/ntpd
NTPD_FLAGS := --target=arm-none-linux-gnueabi --host=armv7-none-linux-gnueabi \
--prefix=$(CROSS_COMPILE_PATH)  CFLAGS=-static --with-yielding-select=yes

export CFLAGS =-I$(CROSS_COMPILE_PATH)/include -L$(CROSS_COMPILE_PATH)/lib
export CXXFLAGS =-I$(CROSS_COMPILE_PATH)/include -L$(CROSS_COMPILE_PATH)/lib

$(BIN):
ifneq ("$(wildcard ntp-4.2.8p8_$(MODEL).tar.xz)","")
	tar -xvf ntp-4.2.8p8_$(MODEL).tar.xz
else
	tar -xvf ntp-4.2.8p8.tar.gz
	cd ntp-4.2.8p8 && ./configure $(NTPD_FLAGS) && make
endif
install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install

clean:
	@echo "do nothing"
