# export CROSS_COMPILE=arm-linux-
# export ARCH=arm

export CC      = ccache $(CROSS_COMPILE)gcc
export CXX     = ccache $(CROSS_COMPILE)g++
export LD      = $(CROSS_COMPILE)ld
export INCLUDE = $(ROOTFS_DIR)/usr/include
export LIB     = $(ROOTFS_DIR)/usr/lib
export CFLAGS  = -Wall -Werror -D$(MODEL) -I$(INCLUDE) -L$(LIB)
export CXXFLAGS= -Wall -Werror -D$(MODEL) -I$(INCLUDE) -L$(LIB)

$(ROOTFS_DIR):
	@mkdir    $(ROOTFS_DIR)
	@mkdir    $(ROOTFS_DIR)/data
	@mkdir    $(ROOTFS_DIR)/usr
	@mkdir -p $(ROOTFS_DIR)/var/www/hiawatha
	@mkdir -p $(ROOTFS_DIR)/etc/hiawatha
	@mkdir    $(ROOTFS_DIR)/usr/bin
	@mkdir    $(ROOTFS_DIR)/usr/sbin
	@mkdir    $(ROOTFS_DIR)/usr/lib

all: $(ROOTFS_DIR)
	@$(MAKE) -C hiawatha/hiawatha-10.8.1 clean all
	@$(MAKE) -C lib_fastcgi/fcgi-2.4.0 clean all
	@$(MAKE) -C lib_app clean all
	@$(MAKE) -C web_server clean all
	@$(MAKE) -C network_manager clean all
	@$(MAKE) -C system_manager clean all
	@$(MAKE) -C hello_world_app clean all
	@$(MAKE) -C dropbear/dropbear-2018.76 clean all

clean:
	@$(MAKE) -C hiawatha/hiawatha-10.8.1 clean
	@$(MAKE) -C lib_fastcgi/fcgi-2.4.0 clean
	@$(MAKE) -C lib_rpc clean
	@$(MAKE) -C hello_world_app clean
	@$(MAKE) -C network_manager clean
	@$(MAKE) -C system_manager clean
	@$(MAKE) -C web_server clean
	@$(MAKE) -C dropbear/dropbear-2018.76 clean
	@rm -rf   $(ROOTFS_DIR)
