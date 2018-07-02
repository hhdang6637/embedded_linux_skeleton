# export CROSS_COMPILE=arm-linux-
# export ARCH=arm

export CC=$(CROSS_COMPILE)gcc
export CXX=$(CROSS_COMPILE)g++

$(ROOTFS_DIR):
	mkdir $(ROOTFS_DIR)
	mkdir $(ROOTFS_DIR)/usr
	mkdir $(ROOTFS_DIR)/usr/bin

all: $(ROOTFS_DIR)
	$(MAKE) -C hello_world_app all