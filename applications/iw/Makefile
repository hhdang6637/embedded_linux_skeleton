BIN := iw-4.9/iw

# export CFLAGS =-Wall

$(BIN):
ifneq ("$(wildcard iw-4.9_$(MODEL).tar.xz)","")
	tar -xvf iw-4.9_$(MODEL).tar.xz
else
	tar -xvf iw-4.9.tar.xz
	cd iw-4.9 && make
endif
install:
	cp $(BIN) $(ROOTFS_DIR)/usr/bin

all: $(BIN) install

clean:
	@echo "do nothing"
