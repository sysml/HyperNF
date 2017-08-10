PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build
NETMAP_SRC ?= $(PWD)/../netmap
NETMAP_KSYM := $(NETMAP_SRC)/LINUX/Module.symvers

obj-m := xen-netmapback.o
xen-netmapback-y := netmapback.o xenbus.o interface.o xennet.o hwth.o

EXTRA_CFLAGS := -I$(PWD) -I$(NETMAP_SRC) -I$(NETMAP_SRC)/sys -I$(NETMAP_SRC)/LINUX
EXTRA_CFLAGS += -DCONFIG_NETMAP -DCONFIG_NETMAP_VALE -DCONFIG_NETMAP_MONITOR
MOD_LIST = 
EXTRA_SYMBOLS += $(NETMAP_KSYM)

SUBDIRS = $(PWD)

COMMON_OPS = -C $(KDIR) $(MOD_LIST) M='$(SUBDIRS)' EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS='$(EXTRA_SYMBOLS)'

deafult:
	$(MAKE) $(COMMON_OPS) modules

CLEAN_TARGET := .tmp_*.gcno *.gcno *.o *.ko *.cmd *.mod.c .*.cmd .tmp_versions modules.order Module.symvers *~

clean:
	rm -rf $(CLEAN_TARGET)
