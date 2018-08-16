FCGI_FLAGS := --host=arm --prefix=$(ROOTFS_DIR)/usr

export CFLAGS =-Wall

all:
	@rm -rf build
	@mkdir build
	@cd build && ../configure $(FCGI_FLAGS)
	@cd build && make -j1 && make install

clean:
	@rm -rf build
