BIN := busybox-1.29.2/busybox

export CFLAGS =-Wall

$(BIN):
	tar -xvf busybox-1.29.2.tar.bz2
	cd busybox-1.29.2 && make defconfig && make

install:
	cp $(BIN) $(ROOTFS_DIR)/bin/busybox

all: $(BIN) install

clean:
	@echo "do nothing"
