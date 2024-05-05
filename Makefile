obj-m += hide-file.o

PWD := $(CURDIR)
CC := x86_64-linux-gnu-gcc-13

all:
	make -C /lib/modules/$(shell uname -r)/build CC=$(CC) M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build CC=$(CC) M=$(PWD) clean
