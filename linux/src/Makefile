obj-m := rootfs_verifier.o

# Use the real kernel tree path (adjust if needed)
KDIR := /home/hazbiu/Team-Project-2025/linux
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

