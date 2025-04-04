obj-m += escape_mod.o
# Must have used dockerfile to build kernel skeleton
# KERNELDIR?=../refs/linux/linux-skel-6.13.4

# Set KBUILD_MODPOST_WARN to skip warnings from missing symvers, since we are 
# building against an uncompiled kernel
VARS += KBUILD_MODPOST_WARN=1

all:
	make -C $(KERNELDIR) M=$(CURDIR) modules $(VARS)
clean:
	rm -f *.o *.ko *.mod *.mod.c *.order *.symvers \
	    .*.cmd .*.o
# clean:
# 	make -C $(KERNELDIR) M=$(PWD) clean
