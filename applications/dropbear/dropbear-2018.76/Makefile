DROPBEAR_FLAGS := --host=arm --prefix=$(ROOTFS_DIR)/usr --disable-zlib --disable-harden

export CFLAGS =-Wall
export PROGRAMS =dropbear dbclient dropbearkey dropbearconvert scp

all:
	@./configure $(DROPBEAR_FLAGS)
	@make && make install

clean:
	@echo "do nothing"
