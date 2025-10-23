obj-m := rootfs_verifier.o

# path to the parent kernel source
KDIR := ..
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
