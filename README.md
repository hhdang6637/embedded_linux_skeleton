# Building U-Boot, Linux kernel, and Rootfs from scratch for the embedded system

![](https://travis-ci.org/hhdang6637/embedded_linux_skeleton.svg?branch=master)

## Purpose
This repository is a "simple" guide on how to build U-Boot, Linux kernel, and Rootfs from scratch for the linux embedded system.

## Dependencies
You'll need the following programs installed on your machine
- [GNU Make](https://www.gnu.org/software/make/) for running the Makefile
- [python and python-dev](https://www.python.org/)
- [swig](http://www.swig.org/index.php): Generate scripting interfaces to C/C++ code
- [ccache](https://ccache.samba.org/): caches the output of C/C++ compilation so that the next time
- [dh-autoreconf](https://packages.ubuntu.com/trusty/dh-autoreconf): debhelper add-on to call autoreconf and clean up after the build
- [net-tools](https://packages.ubuntu.com/xenial/net-tools): NET-3 networking toolkit, required for building OpenVPN
- [cmake](https://cmake.org/overview/): for building some opensoucre apps

In ubuntu, run the following command to install all of them:
```
sudo apt-get install -y build-essential python python-dev swig ccache net-tools dh-autoreconf
```

## Get the source code
```
git clone https://github.com/hhdang6637/embedded_linux_skeleton.git
```
## Build
To compile and run the example project, run the following commands:

```
export MODEL=arm_vexpress_a9
cd embedded_linux_skeleton
make
```

After that, we have the `uboot`, `kernel`, and `rootfs` image files at `build/bin/`

## Test with QEMU
- Install QEMU:
```
sudo apt install qemu-system-arm
```

- Run QEMU with Kernel and Rootfs:

First, run the following command:
```
./qemu_scripts/qemu_kernel_roofs_start.sh
```

Login with `root` and no password.

Access Web Gui: http://127.0.0.1:2080

To be continued...

![](https://raw.githubusercontent.com/wiki/hhdang6637/embedded_linux_skeleton/resource_history_page.png)

![](https://raw.githubusercontent.com/wiki/hhdang6637/embedded_linux_skeleton/firmware_upgrade.png)
