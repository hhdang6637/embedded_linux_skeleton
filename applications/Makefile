# export CROSS_COMPILE=arm-linux-
# export ARCH=arm

export CC      = $(CROSS_COMPILE)gcc
export CXX     = $(CROSS_COMPILE)g++
export CFLAGS  = -Wall -Werror
export INCLUDE = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/include
export LIB     = $(BUILD_DIR)/buildroot/host/usr/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/lib

$(ROOTFS_DIR):
	# remove app dir before we build it
	@rm -rf   $(ROOTFS_DIR)
	
	@mkdir    $(ROOTFS_DIR)
	@mkdir    $(ROOTFS_DIR)/data
	@mkdir    $(ROOTFS_DIR)/usr
	@mkdir -p $(ROOTFS_DIR)/var/www/hiawatha
	@mkdir -p $(ROOTFS_DIR)/etc/hiawatha
	@mkdir    $(ROOTFS_DIR)/usr/bin
	@mkdir    $(ROOTFS_DIR)/usr/sbin
	@mkdir    $(ROOTFS_DIR)/usr/lib

all: $(ROOTFS_DIR)
	@$(MAKE) -C hello_world_app all
	@$(MAKE) -C hiawatha/hiawatha-10.8.1 all
	@$(MAKE) -C web_server all
	@$(MAKE) -C network_manager clean all
	@$(MAKE) -C system_manager clean all

clean:
	@$(MAKE) -C hiawatha/hiawatha-10.8.1 clean
