obj-m += hide-file.o

PWD := $(CURDIR)

-include /etc/os-release
ifeq ($(ID), ubuntu)
	CC := x86_64-linux-gnu-gcc-13
else
	CC := gcc
endif

all:
	make -C /lib/modules/$(shell uname -r)/build CC=$(CC) M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build CC=$(CC) M=$(PWD) clean
