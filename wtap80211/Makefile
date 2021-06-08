BUILDDIR = /lib/modules/$(shell uname -r)/build
SRCDIR = $(shell pwd)
PARENTDIR = $(shell dirname $(SRCDIR))
TARGET = wtap80211

CONFIG_MODULE_SIG=n

# Memo: Wno-sign-compare is required to avoid warnings in arm machines.
EXTRA_CFLAGS := -I$(SRCDIR)/include \
				-Wall -Wextra \
				-Wno-unused-parameter \
				-Wno-unused-variable \
				-Wno-unused-function \
				-Wno-missing-field-initializers \
				-Wno-sign-compare \
				-Xlinker --warn-common

obj-m += $(TARGET).o

$(TARGET)-objs := main.o \
				  utils.o

clean-files := *.o *.ko *.mod.[co] *~

all:
	make -C $(BUILDDIR) SUBDIRS=$(SRCDIR) M=$(SRCDIR) modules

clean:
	make -C $(BUILDDIR) SUBDIRS=$(SRCDIR) M=$(SRCDIR) clean

install:
	modprobe mac80211
	insmod wtap80211.ko devices=2
