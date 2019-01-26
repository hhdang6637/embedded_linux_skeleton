export MODEL ?= pi_b_plus
export BUILD_TYPE ?= NORMAL
export PI_BOOT_DIR          := $(PWD)/pi-boot
export FIRMWARE_NONFREE     := $(PWD)/firmware-nonfree
export BUILD_DIR            := $(PWD)/build/$(MODEL)
export CONFIGS_DIR          := $(PWD)/configs/$(MODEL)
export CACHE_DIR            := $(PWD)/build_cache
export BUILDROOT_BUILD_DIR  := $(BUILD_DIR)/buildroot
export LINUX_BUILD_DIR      := $(BUILD_DIR)/linux
export LINUX_MOD_BUILD_DIR  := $(BUILD_DIR)/linux_mod
export UBOOT_BUILD_DIR      := $(BUILD_DIR)/uboot
export BIN_BUILD_DIR        := $(BUILD_DIR)/bin
export SCRIPT_BUILD_DIR     := $(CONFIGS_DIR)/scripts
export SKELETON_ROOTFS_DIR  := $(CONFIGS_DIR)/skeleton_rootfs
export ROOTFS_DIR           := $(BUILD_DIR)/rootfs

export CURRENT_LOG          := $(BUILD_DIR)/current.log
export ALL_LOG              := $(BUILD_DIR)/all.log

include $(CONFIGS_DIR)/Makefile.variable

# follow https://elinux.org/RPi_U-Boot
export PATH := $(BUILDROOT_BUILD_DIR)/host/usr/bin:$(PATH)
#export LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(BUILDROOT_BUILD_DIR)/host/usr/lib
export CROSS_COMPILE=ccache arm-linux-
export CROSS_COMPILE_STRIP=arm-linux-strip
export CROSS_COMPILE_PATH=$(BUILDROOT_BUILD_DIR)/host/usr
export BISON_PKGDATADIR=$(BUILDROOT_BUILD_DIR)/host/usr/share/bison
export M4=$(BUILDROOT_BUILD_DIR)/host/usr/bin/m4
export ARCH=arm
#export USE_PRIVATE_LIBGCC=yes

NUM_OF_CPU := $(nproc)

all: compile_buildroot compile_linux_kernel make_firmware

clean: clean_buildroot clean_linux_kernel clean_uboot clean_apps
	rm -rf $(BUILD_DIR)
	rm -rf $(TFTP_DIR)

$(BIN_BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILDROOT_BUILD_DIR)
	@mkdir -p $(LINUX_BUILD_DIR)
	@mkdir -p $(UBOOT_BUILD_DIR)
	@mkdir -p $(BIN_BUILD_DIR)

compile_buildroot: $(BIN_BUILD_DIR)
	@echo "**********compile_buildroot**********"
	@cp $(CONFIGS_DIR)/buildroot/config $(BUILDROOT_BUILD_DIR)/.config
	@if  ! $(CACHE_DIR)/get_buildroot_$(MODEL)_cache.sh > $(CURRENT_LOG) 2>&1 ; then \
		$(MAKE) -C buildroot-2017.02.10 O=$(BUILDROOT_BUILD_DIR) 2>&1 && cat $(CURRENT_LOG) >> $(ALL_LOG); \
	fi
	@cp $(BUILDROOT_BUILD_DIR)/images/rootfs.cpio $(BIN_BUILD_DIR)
	@echo "**********done**********"

clean_buildroot:
	@rm -rf $(BUILDROOT_BUILD_DIR)

compile_linux_kernel: $(BIN_BUILD_DIR)
	@echo "**********compile_linux_kernel**********"
	@cp $(CONFIGS_DIR)/linux/config $(LINUX_BUILD_DIR)/.config
	@if  ! $(CACHE_DIR)/get_linux_$(MODEL)_cache.sh > $(CURRENT_LOG) 2>&1 ; then \
		if [ $(MODEL) = "orange_pi_zero" ] ; then \
			$(MAKE) -j3 -C linux/linux-4.14.67 O=$(LINUX_BUILD_DIR) > $(CURRENT_LOG) 2>&1 && cat $(CURRENT_LOG) >> $(ALL_LOG) ; \
			$(MAKE) -j3 -C linux/linux-4.14.67 O=$(LINUX_BUILD_DIR) INSTALL_MOD_PATH=$(LINUX_MOD_BUILD_DIR) modules_install >> $(BUILD_DIR)/linux_kernel.log 2>&1 ; \
		else \
			$(MAKE) -j3 -C linux/linux-4.14.22 O=$(LINUX_BUILD_DIR) > $(CURRENT_LOG) 2>&1 && cat $(CURRENT_LOG) >> $(ALL_LOG) ; \
			$(MAKE) -j3 -C linux/linux-4.14.22 O=$(LINUX_BUILD_DIR) INSTALL_MOD_PATH=$(LINUX_MOD_BUILD_DIR) modules_install >> $(BUILD_DIR)/linux_kernel.log 2>&1 ; \
		fi \
	fi
	@cp $(LINUX_BUILD_DIR)/arch/arm/boot/zImage                      $(BIN_BUILD_DIR)
	@cp $(LINUX_BUILD_DIR)/arch/arm/boot/dts/*.dtb  $(BIN_BUILD_DIR)
	@echo "**********done**********"

clean_linux_kernel:
	@rm -rf $(LINUX_BUILD_DIR)

compile_uboot: $(BIN_BUILD_DIR)
	@echo "**********compile_uboot**********"
	@if  ! $(CACHE_DIR)/get_uboot_$(MODEL)_cache.sh > $(CURRENT_LOG) 2>&1 ; then \
		cp $(CONFIGS_DIR)/uboot/config $(UBOOT_BUILD_DIR)/.config ; \
		$(MAKE) -C u-boot_v2018.05-rc1 O=$(UBOOT_BUILD_DIR) > $(CURRENT_LOG) 2>&1 && cat $(CURRENT_LOG) >> $(ALL_LOG) ; \
	fi
	@cp $(UBOOT_BUILD_DIR)/u-boot $(UBOOT_BUILD_DIR)/u-boot.bin $(BIN_BUILD_DIR)
	@echo "**********done**********"

compile_apps: $(BIN_BUILD_DIR)
	@echo "**********compile_apps**********"
	@cp -asf $(PWD)/applications $(BUILD_DIR)
	@if ! $(MAKE) -C $(BUILD_DIR)/applications all > $(CURRENT_LOG) 2>&1 ; then \
		cat $(CURRENT_LOG); exit 1; \
	fi
	@cat $(CURRENT_LOG) >> $(ALL_LOG)
	@echo "**********done**********"

clean_apps:
	@rm -rf $(BUILD_DIR)/applications

clean_uboot:
	@rm -rf $(UBOOT_BUILD_DIR)

make_firmware: compile_apps
	@echo "**********make_firmware**********"
	# @rm -rf $(BUILD_DIR)/sdcard_boot
	# @mkdir $(BUILD_DIR)/sdcard_boot


	# @mkimage -C none -A arm -T script -d $(SCRIPT_BUILD_DIR)/boot.cmd  $(BUILD_DIR)/sdcard_boot/boot.scr
	# @cp $(UBOOT_BUILD_DIR)/u-boot.bin    $(BUILD_DIR)/sdcard_boot/kernel.img
	@cp $(BIN_BUILD_DIR)/$(DTB_FILE)       $(BUILD_DIR)
	@cp $(BIN_BUILD_DIR)/zImage            $(BUILD_DIR)
	@cp $(SCRIPT_BUILD_DIR)/image.its      $(BUILD_DIR)
	@mkimage -A arm -T ramdisk -C none -n uInitrd -d $(BIN_BUILD_DIR)/rootfs.cpio $(BUILD_DIR)/uInitrd
	@fakeroot $(SCRIPT_BUILD_DIR)/fakeroot.sh

	@mkimage -f $(BUILD_DIR)/image.its $(BUILD_DIR)/firmware
	@echo "**********done**********"
