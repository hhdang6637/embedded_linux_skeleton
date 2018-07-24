DROPBEAR_FLAGS := --host=arm --prefix=$(ROOTFS_DIR)/usr --disable-zlib --disable-harden

export CFLAGS =-Wall

all:
	@./configure $(DROPBEAR_FLAGS)
	@make && make install

clean:
	@echo "do nothing"
