# We don't want to copy valgrind to our firmware
# We just copy when wen to debug some apps

# How to run valgrind

# scp -P 2022 build/arm_vexpress_a9/applications/valgrind/valgrind-3.13.0/coregrind/valgrind root@127.0.0.1:/tmp
# scp -P 2022 build/arm_vexpress_a9/applications/valgrind/valgrind-3.13.0/memcheck/memcheck-arm-linux  root@127.0.0.1:/tmp
# export PATH=$PATH:/tmp
# export VALGRIND_LIB=/tmp
# touch /tmp/default.supp
# valgrind /usr/bin/hello_world

VALGRIND_FLAGS := --target=arm-none-linux-gnueabi --host=armv7-none-linux-gnueabi --prefix=$(ROOTFS_DIR)/usr

export CFLAGS = -static

all:
	@./configure $(VALGRIND_FLAGS)
	@make

clean:
	@echo "do nothing"
