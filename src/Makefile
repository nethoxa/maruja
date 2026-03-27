obj-m += maruja.o

KDIR := /lib/modules/$(shell uname -r)/build
THIS_DIR := $(shell cd $(dir $(lastword $(MAKEFILE_LIST))) && pwd)

all:
	make -C $(KDIR) M=$(THIS_DIR) modules

clean:
	make -C $(KDIR) M=$(THIS_DIR) clean