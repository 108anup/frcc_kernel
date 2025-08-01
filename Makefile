ifneq ($(KERNELRELEASE),)

# For showing compiler flags
# ccflags-y := $(ccflags-y) -xc -E -v

# kbuild part of makefile
obj-m  := tcp_frcc.o

else
# normal makefile

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif
