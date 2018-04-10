all: tftp_boot compile_buildroot compile_linux_kernel compile_uboot
clean: clean_buildroot clean compile_linux_kernel clean uboot

fftp_boot: compile_buildroot compile_linux_kernel compile_uboot
	rm -rf tftp_boot
	mkdir tftp_boot
	cp linux-4.14.22/arch/x86/boot/bzImage tftp_boot
	cp buildroot-2017.02.10/output/images/rootfs.cpio tftp_boot

compile_buildroot:
	cp configs/buildroot/config buildroot-2017.02.10/.config
	$(MAKE) -C buildroot-2017.02.10

clean_buildroot:
	$(MAKE) -C buildroot-2017.02.10 clean

compile_linux_kernel:
	cp configs/linux/config linux-4.14.22/.config
	$(MAKE) -j4 -C linux-4.14.22

clean_linux_kernel:
	$(MAKE) -C linux-4.14.22 clean

compile_uboot:
	cp configs/uboot/config u-boot_v2018.05-rc1/.config
	$(MAKE) -j4 -C u-boot_v2018.05-rc1

clean_uboot:
	$(MAKE) -C u-boot_v2018.05-rc1 clean
