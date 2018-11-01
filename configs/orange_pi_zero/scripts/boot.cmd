fatload mmc 0 0x45000000 firmware
setenv bootargs console=ttyS0,115200 earlyprintk root=/dev/root rootwait panic=10 loglevel=4
bootm 0x45000000
