firmwareload 0x71000000
setenv bootargs console=ttyAMA0,115200 earlyprintk root=/dev/root rootwait panic=10 loglevel=4
bootm 0x71000000
