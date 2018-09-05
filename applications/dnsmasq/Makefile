BIN := dnsmasq-2.79/src/dnsmasq

# export CFLAGS =-Wall

$(BIN):
ifneq ("$(wildcard dnsmasq-2.79_$(MODEL).tar.xz)","")
	tar -xvf dnsmasq-2.79_$(MODEL).tar.xz
else
	tar -xvf dnsmasq-2.79.tar.xz
	cd dnsmasq-2.79 && make
endif
install:
	cp $(BIN) $(ROOTFS_DIR)/usr/sbin

all: $(BIN) install

clean:
	@echo "do nothing"
