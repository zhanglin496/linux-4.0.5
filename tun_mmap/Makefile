include $(MAKEFILE_TOP_INCLUDE)

ifeq ($(ARCH),rlx)
EXTRA_CFLAGS += -mlong-calls
endif

KDIR = $(KERNEL_DIR)

obj-m += tun.o
tun-objs := tun_mmap.o

all:
	make -C $(KDIR) M=$(shell pwd) ARCH=$(ARCH) modules
clean:
	make -C $(KDIR) M=$(shell pwd) ARCH=$(ARCH) clean
