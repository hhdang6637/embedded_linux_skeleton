BIN := nmap

export CFLAGS =-Wall
export CXXFLAGS =-Wall -DHAVE_SOCKADDR_STORAGE=1

$(BIN):
	tar -xvf nmap-7.70.tar.bz2
	cd nmap-7.70 && ./configure \
	--host=arm-linux-gnueabi --without-subversion --without-liblua --without-zenmap --with-pcre=/usr \
	&& make

install:
	mkdir -p $(ROOTFS_DIR)/usr/share/nmap
	mkdir -p $(ROOTFS_DIR)/usr/bin
	cp nmap-7.70/nmap $(ROOTFS_DIR)/usr/bin
	cp nmap-7.70/nmap-services $(ROOTFS_DIR)/usr/share/nmap/nmap-services

all: $(BIN) install

clean:
	@echo "do nothing"
