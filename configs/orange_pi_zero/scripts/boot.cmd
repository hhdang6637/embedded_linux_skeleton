firmwareload 0x4a000000
setenv bootargs console=ttyS0,115200 earlyprintk root=/dev/root rootwait panic=10 loglevel=4
bootm 0x4a000000
