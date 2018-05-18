obj-m += rsa_kernel.o
rsa_kernel-objs := rsa.o bignum.o md.o md5.o oid.o sha1.o sha256.o sha512.o asn1parse.o md_wrap.o ripemd160.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

