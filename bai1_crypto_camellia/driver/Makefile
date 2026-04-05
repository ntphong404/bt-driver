obj-m += camellia_drv.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

# Load/unload helpers
load:
	sudo insmod camellia_drv.ko
	@echo "Driver loaded. Device: /dev/camellia_drv"

unload:
	sudo rmmod camellia_drv
	@echo "Driver unloaded."

status:
	@lsmod | grep camellia || echo "Driver not loaded"
	@ls -la /dev/camellia_drv 2>/dev/null || echo "Device not present"
