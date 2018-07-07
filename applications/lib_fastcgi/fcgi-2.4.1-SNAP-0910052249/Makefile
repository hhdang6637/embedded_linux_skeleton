FCGI_FLAGS := --host=arm --prefix=$(ROOTFS_DIR)/usr/local/lib

export CFLAGS =-Wall

all:
	@rm -rf build
	@mkdir build
	@cd build && ../configure $(FCGI_FLAGS)
	@cd build && make && make install

clean:
	@rm -rf build
