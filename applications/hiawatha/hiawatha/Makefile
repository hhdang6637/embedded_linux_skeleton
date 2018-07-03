# CC       = gcc
# CFLAGS += -Wall -g
BIN           := build/hiawatha
MBEDTLS_LIB   := build/mbedtls/library
CONFIG_FILE   := config/hiawatha.conf.in
MIMETYPE_FILE := config/mimetype.conf
INDEX_FILE    := config/index.xslt

export LOG_DIR     = /tmp/log/hiawatha
export WEBROOT_DIR = /var/www/hiawatha

$(BIN):
	@rm -rf build
	@mkdir build
	@cd build && cmake ..
	@cd build && make

install:
	cp     $(BIN)                   $(ROOTFS_DIR)/usr/bin
	cp -av $(MBEDTLS_LIB)/lib*.so*  $(ROOTFS_DIR)/usr/lib # copy with simbolic links
	cp     $(CONFIG_FILE)           $(ROOTFS_DIR)/etc/hiawatha/hiawatha.conf
	cp     $(MIMETYPE_FILE)         $(ROOTFS_DIR)/etc/hiawatha
	cp     $(INDEX_FILE)            $(ROOTFS_DIR)/var/www/hiawatha/index.html # example page

all: $(BIN) install
