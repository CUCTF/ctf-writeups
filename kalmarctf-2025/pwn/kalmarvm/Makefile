.PHONY: all clean cleanall

all: module

linux-ref:
	$(MAKE) -C linux-skel/

module: linux-ref
	$(MAKE) -C payload_module KERNELDIR=$(PWD)/linux-skel/linux-skel-6.13.4

clean:
	$(MAKE) -C payload_module clean

cleanall: clean
	$(MAKE) -C linux-skel/ clean

.DEFAULT_GOAL := all