fatload mmc 0:2 ${kernel_addr_r}    fw.active/zImage
fatload mmc 0:2 ${fdt_addr_r}       fw.active/bcm2835-rpi-b-plus.dtb
fatload mmc 0:2 ${ramdisk_addr_r}   fw.active/uInitrd
setenv bootargs console=ttyAMA0,115200 earlyprintk root=/dev/root rootwait panic=10 loglevel=8
bootz ${kernel_addr_r} ${ramdisk_addr_r} ${fdt_addr_r}
