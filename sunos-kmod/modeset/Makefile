KMOD     = nvidia_modeset
RMOBJ    = nv-modeset-kernel.o
KMODDIR  = /kernel/drv
TARGET_ARCH = amd64
DEPEND_ON = nvidia
# NV_SOLARIS_ADD_DT_NEEDED = $(NV_TOOLS)/unix/hosts/Linux-x86/unix-build/bin/add-DT_NEEDED

ifndef DO_NOT_OVERRIDE_CC_AND_LD
  CC = gcc
  LD = ld
endif

all: $(KMOD)

override CFLAGS += -D_KERNEL -D__KERNEL__
override CFLAGS += -DNV_VERSION_STRING=\"515.48.07\"
override CFLAGS += -I.. -Wall

SPECTRE_V2_RETPOLINE ?= 1
override CFLAGS += -DNV_SPECTRE_V2=$(SPECTRE_V2_RETPOLINE)

ifeq ($(TARGET_ARCH),x86)
  override CFLAGS += -m32
endif
ifeq ($(TARGET_ARCH),amd64)
  override CFLAGS += -m64 -mno-red-zone -mcmodel=kernel
endif

# if the caller has defined NV_SOLARIS_ADD_DT_NEEDED, use that to specify
# DT_NEEDED for the module. Otherwise, use linkers' -dy option
#
ifeq ($(origin NV_SOLARIS_ADD_DT_NEEDED), undefined)
  LD_DT_NEEDED_ARGS = -dy N$(DEPEND_ON)
  ADD_DT_NEEDED_CMD = 
else
  LD_DT_NEEDED_ARGS =
  ADD_DT_NEEDED_CMD = $(NV_SOLARIS_ADD_DT_NEEDED) $(KMOD) $(DEPEND_ON)
endif

include ../optional-cflags.mk

CPPFLAGS = -DNV_UNIX -DSYSV -DSYSACCT -DC2_AUDIT -DQUOTA -D_SYSCALL32

NVIDIA_SOURCES = nvidia-modeset-sunos.c

GLUEOBJS = $(patsubst %.c,%.o,$(NVIDIA_SOURCES))

OBJS += $(RMOBJ) $(GLUEOBJS)

clean:
	rm -f $(GLUEOBJS) $(KMOD)

$(KMOD): $(OBJS)
	$(LD) -r -o $@ $^ $(LD_DT_NEEDED_ARGS)
	$(ADD_DT_NEEDED_CMD)

%.o: %.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@
