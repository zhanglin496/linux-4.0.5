include $(MAKEFILE_TOP_INCLUDE)
KDIR = $(KERNEL_DIR)

ifeq ($(ARCH),rlx)
EXTRA_CFLAGS += -mlong-calls
endif

obj-m += ntfs.o

ntfs-objs := aops.o attrib.o collate.o compress.o debug.o dir.o file.o \
	  index.o inode.o mft.o mst.o namei.o runlist.o super.o sysctl.o \
	  unistr.o upcase.o bitmap.o lcnalloc.o logfile.o quota.o usnjrnl.o

ccflags-y := -DNTFS_VERSION=\"2.1.30\"
ccflags-y += -DDEBUG
ccflags-y += -DNTFS_RW

all:
	make -C $(KDIR) ARCH=$(ARCH) M=$(shell pwd) modules
clean:
	make -C $(KDIR) M=$(shell pwd) clean

