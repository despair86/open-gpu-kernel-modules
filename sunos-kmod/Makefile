#
# This Makefile was automatically generated; do not edit.
#

#
# Makefile for building the NVIDIA Solaris driver kernel interface layer
# and linking the NVIDIA Solaris kernel module; requires GNU make.
#

OSOBJ = nv-sunos.o
KMOD = nvidia
RMOBJ ?= nv-kernel.o
KMODDIR = /kernel/drv
DEPEND_ON = misc/gfx_private

ifndef DO_NOT_OVERRIDE_CC_AND_LD
 CC = gcc
 LD = ld
endif

SPECTRE_V2_RETPOLINE ?= 1

#
# If the caller has defined NV_SOLARIS_ADD_DT_NEEDED, use that to specify
# the DT_NEEDED for the module. Otherwise, use the linker's '-dy' option.
#
ifeq ($(origin NV_SOLARIS_ADD_DT_NEEDED), undefined)
 LD_DT_NEEDED_ARGS = -dy -N$(DEPEND_ON)
 ADD_DT_NEEDED_CMD =
else
 LD_DT_NEEDED_ARGS =
 ADD_DT_NEEDED_CMD = $(NV_SOLARIS_ADD_DT_NEEDED) $(KMOD) $(DEPEND_ON)
endif

all: $(OSOBJ)

override CFLAGS += -I. -I$(NVIDIA_ROOT)/src
override CFLAGS += -D_KERNEL -D__KERNEL__
override CFLAGS += -DNVRM -DNV_VERSION_STRING=\"515.48.07\"  -Wno-unused-function -Wuninitialized -O2 -fno-strict-aliasing -fno-asynchronous-unwind-tables -m64  -ffreestanding -mno-red-zone -mcmodel=kernel     -UDEBUG -U_DEBUG -DNDEBUG
override CFLAGS += -DNV_SPECTRE_V2=$(SPECTRE_V2_RETPOLINE)
override CFLAGS += -DNV_KERNEL_INTERFACE_LAYER

include optional-cflags.mk

CPPFLAGS = -DNV_UNIX -DSYSV -DSYSACCT -DC2_AUDIT -DQUOTA -D_SYSCALL32

include nvidia-sources.mk
GLUEOBJS = $(patsubst %.c,%.o,$(NVIDIA_SOURCES))

OBJS += $(RMOBJ) $(GLUEOBJS)

NOOBJ = true

beforeinstall: $(KMOD)

clean:
	rm -f $(GLUEOBJS) $(OSOBJ) $(KMOD)

$(KMOD): $(OBJS)
	$(LD) -r -o $@ $^ $(LD_DT_NEEDED_ARGS)
	$(ADD_DT_NEEDED_CMD)

$(OSOBJ): $(KMOD)
	$(LD) -r -o $@ $(GLUEOBJS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@
