BIN           := build/hiawatha
MBEDTLS_LIB   := build/mbedtls/library
CONFIG_FILE   := config/hiawatha.conf.in
MIMETYPE_FILE := config/mimetype.conf
INDEX_FILE    := config/index.xslt
SERVER_PEM    := config/server.pem


export CFLAGS  = -Wall

ifeq ($(MODEL),orange_pi_zero)
export INCLUDE = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabihf/sysroot/usr/include
export LIB     = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabihf/sysroot/usr/lib
else
export INCLUDE = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/include
export LIB     = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/lib
endif

$(BIN):
	@rm -rf build
	@mkdir build
	@cd build && cmake ..
	@cd build && make

install:
	@cp     $(BIN)                   $(ROOTFS_DIR)/usr/bin
	@cp -av $(MBEDTLS_LIB)/lib*.so*  $(ROOTFS_DIR)/usr/lib # copy with simbolic links
	@cp     $(CONFIG_FILE)           $(ROOTFS_DIR)/etc/hiawatha/hiawatha.conf
	@cp     $(MIMETYPE_FILE)         $(ROOTFS_DIR)/etc/hiawatha
	@cp     $(INDEX_FILE)            $(ROOTFS_DIR)/var/www/hiawatha/ # example page
	@cp     $(SERVER_PEM)            $(ROOTFS_DIR)/etc/hiawatha/ # example page


all: $(BIN) install

clean:
	@rm -rf build
