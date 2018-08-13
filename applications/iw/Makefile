BIN := iw-4.9/iw

# export CFLAGS =-Wall

$(BIN):
	tar -xvf iw-4.9.tar.xz
	cd iw-4.9 && make

install:
	cp $(BIN) $(ROOTFS_DIR)/usr/bin

all: $(BIN) install

clean:
	@echo "do nothing"
