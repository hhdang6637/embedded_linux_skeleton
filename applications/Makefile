# export CROSS_COMPILE=arm-linux-
# export ARCH=arm

export CC      = $(CROSS_COMPILE)gcc
export CXX     = $(CROSS_COMPILE)g++
export AR      = $(CROSS_COMPILE)ar
export LD      = $(CROSS_COMPILE)ld
export INCLUDE +=$(ROOTFS_DIR)/usr/include -I$(CROSS_COMPILE_PATH)/usr/include
export LIB     +=$(ROOTFS_DIR)/usr/lib -L$(CROSS_COMPILE_PATH)/usr/lib
export CFLAGS  = -Wall -Werror -D$(MODEL) -I$(INCLUDE) -L$(LIB)
export CXXFLAGS= -Wall -Werror -D$(MODEL) -I$(INCLUDE) -L$(LIB)

ifeq ($(BUILD_TYPE),NORMAL)
# CFLAGS += -Os
else ifeq ($(BUILD_TYPE),DEBUG)
CFLAGS += -g -rdynamic
endif

$(ROOTFS_DIR):
	@mkdir    $(ROOTFS_DIR)
	@mkdir    $(ROOTFS_DIR)/data
	@mkdir    $(ROOTFS_DIR)/usr
	@mkdir    $(ROOTFS_DIR)/bin
	@mkdir    $(ROOTFS_DIR)/sbin
	@mkdir -p $(ROOTFS_DIR)/var/www/hiawatha
	@mkdir -p $(ROOTFS_DIR)/etc/hiawatha
	@mkdir    $(ROOTFS_DIR)/usr/bin
	@mkdir    $(ROOTFS_DIR)/usr/sbin
	@mkdir    $(ROOTFS_DIR)/usr/lib

all: $(ROOTFS_DIR)
	@$(MAKE) -C noip-2.1.9-1
	@cp noip-2.1.9-1/noip2 $(ROOTFS_DIR)/bin
	@$(MAKE) -C iptables clean all
	@$(MAKE) -C ntp clean all
	@$(MAKE) -C openssl clean all
	@$(MAKE) -C openvpn clean all
ifeq ($(MODEL),$(filter $(MODEL),pi_3_b orange_pi_zero))
	@$(MAKE) -C libnl clean all
	@$(MAKE) -C iw clean all
	@$(MAKE) -C hostapd clean all
	@$(MAKE) -C dnsmasq clean all
endif
	@$(MAKE) -C hiawatha/hiawatha-10.8.1 clean all
	@$(MAKE) -C lib_fastcgi clean all
	@$(MAKE) -C lib_app clean all
	@$(MAKE) -C event_manager clean all
	@$(MAKE) -C web_server clean all
	@$(MAKE) -C network_manager clean all
	@$(MAKE) -C system_manager clean all
	@$(MAKE) -C resource_manager clean all
	@$(MAKE) -C hello_world_app clean all
	@$(MAKE) -C dropbear/dropbear-2018.76 clean all
	@$(MAKE) -C busybox clean all
	@$(MAKE) -C nmap all
ifeq ($(BUILD_TYPE),DEBUG)
	@$(MAKE) -C valgrind/valgrind-3.13.0 clean all
endif

clean:
	@$(MAKE) -C event_manager clean
	@$(MAKE) -C hiawatha/hiawatha-10.8.1 clean
	@$(MAKE) -C lib_fastcgi/fcgi-2.4.0 clean
	@$(MAKE) -C lib_rpc clean
	@$(MAKE) -C hello_world_app clean
	@$(MAKE) -C network_manager clean
	@$(MAKE) -C system_manager clean
	@$(MAKE) -C resource_manager clean
	@$(MAKE) -C web_server clean
	@$(MAKE) -C dropbear/dropbear-2018.76 clean
ifeq ($(BUILD_TYPE),DEBUG)
	@$(MAKE) -C valgrind/valgrind-3.13.0 clean
endif
	@rm -rf   $(ROOTFS_DIR)
