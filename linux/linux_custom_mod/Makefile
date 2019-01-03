obj-m	:= ethernetflow.o
ethernetflow-m	:= ethernet_flow.o ethernet_flow_core.o

KERNELDIR ?= $(LINUX_BUILD_DIR)
PWD       := $(shell pwd)

all: default

default:
	$(MAKE) -C $(KERNELDIR) O=$(LINUX_BUILD_DIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
