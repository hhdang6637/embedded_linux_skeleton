fatload mmc 0:2 0x10000000 fw_0
setenv bootargs console=ttyAMA0,115200 earlyprintk root=/dev/root rootwait panic=10 loglevel=8
bootm 0x10000000
