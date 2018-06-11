# Building U-Boot, Linux kernel, and Rootfs from scratch for the embedded system

## Purpose
This repository is a "simple" guide on how to build U-Boot, Linux kernel, and Rootfs from scratch for the linux embedded system.

## Dependencies
You'll need the following programs installed on your machine
- [GNU Make](https://www.gnu.org/software/make/) for running the Makefile
- [python and python-dev](https://www.python.org/)
- [swig](http://www.swig.org/index.php): Generate scripting interfaces to C/C++ code
- [ccache](https://ccache.samba.org/): caches the output of C/C++ compilation so that the next time

In ubuntu, run the following command to install all of them:
```
sudo apt-get install -y build-essential python python-dev swig ccache
```

## Get the source code
```
git clone https://github.com/hhdang6637/embedded_linux_skeleton.git
```
## Build
To compile and run the example project, run the following commands:

```
cd embedded_linux_skeleton
make
```

After that, we have the `uboot`, `kernel`, and `rootfs` image files at `build/bin/`

## Test with QEMU
- Install QEMU:
```
sudo apt install qemu-system-i386
```

- Run QEMU with uboot image:
```
./qemu_scripts/qemu_uboot_start.sh
```

- Run QEMU with Kernel and Rootfs:

First, run the following command:
```
./qemu_scripts/qemu_kernel_roofs_start.sh
```

And then, telnet to QEMU machine:
```
telnet 127.0.0.1 4444
```
Login with `root` and no password.

To be continued...
