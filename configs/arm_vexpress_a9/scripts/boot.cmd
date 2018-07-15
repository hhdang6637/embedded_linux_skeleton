fatload mmc 0:0 0x61000000 fw_0
setenv bootargs console=ttyAMA0,115200 earlyprintk root=/dev/root rootwait panic=10 loglevel=4
bootm 0x61000000
