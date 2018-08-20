LIB_FCGI_FLAGS :=--prefix=$(ROOTFS_DIR)/usr --target=arm-none-linux-gnueabi --host=armv7-none-linux-gnueabi
export CFLAGS =-Wall

all:
	tar -xvf fcgi2-2.4.0.tar.gz
	touch fcgi2-2.4.0/NEWS
	touch fcgi2-2.4.0/AUTHORS
	touch fcgi2-2.4.0/ChangeLog
	cp -f configure.in fcgi2-2.4.0
	cp -f Makefile.am  fcgi2-2.4.0
	cd fcgi2-2.4.0 && autoreconf -vi && ./configure $(LIB_FCGI_FLAGS) && make && make install

clean:
	@echo "do nothing"
