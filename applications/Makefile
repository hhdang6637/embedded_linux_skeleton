# export CROSS_COMPILE=arm-linux-
# export ARCH=arm

export CC      = $(CROSS_COMPILE)gcc
export CXX     = $(CROSS_COMPILE)g++
export INCLUDE = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/include
export LIB     = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/lib

$(ROOTFS_DIR):
	mkdir    $(ROOTFS_DIR)
	mkdir    $(ROOTFS_DIR)/usr
	mkdir -p $(ROOTFS_DIR)/var/www/hiawatha
	mkdir -p $(ROOTFS_DIR)/etc/hiawatha
	mkdir    $(ROOTFS_DIR)/usr/bin
	mkdir    $(ROOTFS_DIR)/usr/lib

all: $(ROOTFS_DIR)
	$(MAKE) -C hello_world_app all
	$(MAKE) -C hiawatha/hiawatha all