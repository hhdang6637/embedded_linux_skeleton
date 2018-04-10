
TFTP_DIR := tftp_boot
BUILD_DIR := $(PWD)/build
BUILDROOT_BUILD_DIR := $(BUILD_DIR)/buildroot
LINUX_BUILD_DIR := $(BUILD_DIR)/linux
UBOOT_BUILD_DIR := $(BUILD_DIR)/uboot

NUM_OF_CPU := $(nproc)

all: tftp_boot compile_buildroot compile_linux_kernel compile_uboot

clean: clean_buildroot clean_linux_kernel clean_uboot
	rm -rf $(BUILD_DIR)
	rm -rf $(TFTP_DIR)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)
	mkdir $(BUILDROOT_BUILD_DIR)
	mkdir $(LINUX_BUILD_DIR)
	mkdir $(UBOOT_BUILD_DIR)

tftp_boot: compile_buildroot compile_linux_kernel compile_uboot
	rm -rf $(TFTP_DIR)
	mkdir $(TFTP_DIR)
	cp $(LINUX_BUILD_DIR)/arch/x86/boot/bzImage $(TFTP_DIR)
	cp $(BUILDROOT_BUILD_DIR)/images/rootfs.cpio $(TFTP_DIR)

compile_buildroot: $(BUILD_DIR)
	cp configs/buildroot/config $(BUILDROOT_BUILD_DIR)/.config
	$(MAKE) -C buildroot-2017.02.10 O=$(BUILDROOT_BUILD_DIR)

clean_buildroot:
	rm -rf $(BUILDROOT_BUILD_DIR)

compile_linux_kernel: $(BUILD_DIR)
	cp configs/linux/config $(LINUX_BUILD_DIR)/.config
	$(MAKE) -j$(NUM_OF_CPU) -C linux-4.14.22 O=$(LINUX_BUILD_DIR)

clean_linux_kernel:
	rm -rf $(LINUX_BUILD_DIR)

compile_uboot: $(BUILD_DIR)
	cp configs/uboot/config $(UBOOT_BUILD_DIR)/.config
	$(MAKE) -j$(NUM_OF_CPU) -C u-boot_v2018.05-rc1 O=$(UBOOT_BUILD_DIR)

clean_uboot:
	rm -rf $(UBOOT_BUILD_DIR)
