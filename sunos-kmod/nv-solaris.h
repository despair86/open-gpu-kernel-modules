/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2010 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#ifndef _NV_SOLARIS_H
#define _NV_SOLARIS_H

#include <stddef.h>

#include <note.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/signal.h>

#include <sys/file.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/map.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>

#include <vm/page.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/seg.h>

#include <sys/ddi.h>
#include <sys/ddi_obsolete.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/fs/snode.h>
#include <sys/pci.h>

#include <sys/modctl.h>
#include <sys/uio.h>

#include <sys/visual_io.h>
#include <sys/fbio.h>

#ifndef FBIOLOADHNDL
#define FBIOLOADHNDL    (FIOC|45)
#endif

#include <sys/ddidmareq.h>

#include <sys/kstat.h>
#include <sys/callb.h>

#include <sys/promif.h>
#include <sys/sysconfig.h>
#include <sys/atomic.h>

#include <sys/cpuvar.h>

#ifndef VIS_CONSCLEAR
#define VIS_CONSCLEAR   (VIOC|8)
#endif

/* PSARC/2007/695 */
#ifndef VIS_READ_DDCCI
#define VIS_READ_DDCCI  (('V' << 8) | 20)
#define VIS_WRITE_DDCCI (('V' << 8) | 21)
#define VIS_INIT_DDCCI  (('V' << 8) | 22)

struct vis_ddcci {
    uint_t      port;
    int         length;
    caddr_t     buffer;
};

#if defined(_SYSCALL32)
struct vis_ddcci32 {
    uint_t      port;
    int         length;
    caddr32_t   buffer;
};
#endif /* _SYSCALL32 */
#endif /* VIS_READ_DDCI -- PSARC/2007/695 */

/* PSARC/2009/xxx */
#ifndef VIS_I2C_CAPS
#define VIS_I2C_CAPS    (('V' << 8) | 23)
#define VIS_I2C_CMDS    (('V' << 8) | 24)

#define VIS_I2C_TENBIT_ADDR             0x00000001
#define VIS_I2C_READ                    0x00000002
#define VIS_I2C_WRITE                   0x00000004
#define VIS_I2C_SMBUS_TENBIT_ADDR       0x00000010
#define VIS_I2C_SMBUS_QUICK_READ        0x00000020
#define VIS_I2C_SMBUS_QUICK_WRITE       0x00000040
#define VIS_I2C_SMBUS_BYTE_READ         0x00000080
#define VIS_I2C_SMBUS_BYTE_WRITE        0x00000100
#define VIS_I2C_SMBUS_BYTE_BLOCK_READ   0x00000200
#define VIS_I2C_SMBUS_BYTE_BLOCK_WRITE  0x00000400
#define VIS_I2C_SMBUS_SHORT_BLOCK_READ  0x00000800
#define VIS_I2C_SMBUS_SHORT_BLOCK_WRITE 0x00001000

struct vis_i2c_caps {
    uint32_t    bus_count;
    uint32_t    flags;
};

struct vis_i2c_cmd {
    uint32_t    bus;        /* 0 .. (vis_i2c_caps.bus_count)-1 */
    uint32_t    addr;       /* I2C bus address */
    uint32_t    command;    /* SMBus command */
    uint32_t    flags;      /* vis_i2c_caps.flags */
    int32_t     length;
    int32_t     pad;        /* mbz */
    caddr_t     buffer;
};

struct vis_i2c_cmd_list {
    uint32_t    count;
    struct vis_i2c_cmd *cmd_list;
};

#if defined(_SYSCALL32)
struct vis_i2c_cmd32 {
    uint32_t    bus;
    uint32_t    addr;
    uint32_t    command;
    uint32_t    flags;
    int32_t     length;
    int32_t     pad;
    caddr32_t   buffer;
};

struct vis_i2c_cmd_list32 {
    uint32_t    count;
    caddr32_t   cmd_list;
};
#endif /* _SYSCALL32 */
#endif /* VIS_I2C_CAPS -- PSARC/2009/xxx */

#include "gfx_private.h"

#if NVCPU_IS_X86
#define pci_config_get8  pci_config_getb
#define pci_config_get16 pci_config_getw
#define pci_config_get32 pci_config_getl
#define pci_config_put8  pci_config_putb
#define pci_config_put16 pci_config_putw
#define pci_config_put32 pci_config_putl
#endif

/*
 * Bus dma burst sizes
 */
#define BURSTSIZE
#define BURST1                  0x01
#define BURST2                  0x02
#define BURST4                  0x04
#define BURST8                  0x08
#define BURST16                 0x10
#define BURST32                 0x20
#define BURST64                 0x40
#define BURST128                0x80
#define BURSTSIZE_MASK          0xff
#define DEFAULT_BURSTSIZE       BURST16|BURST8|BURST4|BURST2|BURST1

/* autopm */
#define NV_PM_COMPONENTS        2
#define NV_PM_BOARD             0       /* component 0:  NVDA board     */
#define NV_PM_MONITOR           1       /* component 1:  monitor        */
#define NV_BOARD_OFF            0       /* Board is off, not suspended  */
#define NV_BOARD_NO_PCI_CLK     1       /* Same as PM_LEVEL_D2 */
#define NV_BOARD_ON             3       /* Same as PM_LEVEL_D0 */
#define NV_BOARD_SUSPENDED      4       /* Same as PM_LEVEL_D3 */
#define NV_DPMS_OFF             0
#define NV_DPMS_SUSPEND 1
#define NV_DPMS_STANDBY 2
#define NV_DPMS_NORMAL          3
#define NV_PWR_UNKNOWN          (-1)    /* must be less than NV_BOARD_OFF */

/* cannot exceed NV_MAX_DEVICES (currently 8) defined in nv.h */
#define NV_CLONEDEV             0x00000100
#define NV_CLONEMASK            0xffffff00
#define CDEV_CTL_MINOR          255

/* Assigned register set numbers */
#define REGNUM_CONF             0
#define REGNUM_REGS             1       /* PCI BAR 0 */
#define REGNUM_FB               2       /* PCI BAR 1 */

        /* DATA STRUCTURES */

typedef struct nvidia_alloc {
        struct nvidia_alloc *forw;
        struct nvidia_alloc *back;
        uint32_t size;
        int alloc_type_contiguous;
        NvU64 *pte_array;
        ddi_dma_handle_t dma_handle;
        ddi_acc_handle_t dma_data_handle;
        uint_t cookie_count;
        ddi_dma_cookie_t cookie;
        struct ddi_umem_cookie *umem_cookie;
        size_t real_length;
        caddr_t kva;
        struct ddi_device_acc_attr *attr;
} nvidia_alloc_t;

typedef struct nv_os_event {
        struct nv_os_event *next;
        nv_event_t event;
} nv_os_event_t;

#define NV_CLONE_FLAG_IGNORE                  1

typedef struct nv_sunos_file_private nv_sunos_file_private_t;

/* per-open data */
struct nv_sunos_file_private {
        nv_file_private_t nvfp;

        nvidia_stack_t     *sp;
        nv_sunos_file_private_t *next;
        minor_t         cloneminor;
        uint32_t        flags;
        pid_t           pid;        /* pid of the process with this minor dev */
        struct nv_softc *softc;
        kmutex_t        event_lock;
        nv_os_event_t   *event_queue;
        struct pollhead event_pollhead;
        NvBool          event_pending;
        nv_alloc_mapping_context_t mmap_context;
        NvU32 *attached_gpus;
        size_t num_attached_gpus;
};

static inline nv_sunos_file_private_t *nv_get_nvsfp_from_nvfp(nv_file_private_t *nvfp)
{
    return (nv_sunos_file_private_t *)
        ((uintptr_t)nvfp - offsetof(nv_sunos_file_private_t, nvfp));
}

#define NV_I2C_MAX_BUSSES       32

struct nv_i2c_bus {
        uint32_t        port;
};

enum nv_softc_dev_stack_t
{
    NV_DEV_STACK_ATTACH,        /* nv_attach() */
    NV_DEV_STACK_ISR,           /* nv_intr() */
    NV_DEV_STACK_TIMER,         /* nvidia_rc_timer() */
    NV_DEV_STACK_COUNT
};

/* per-unit data */
struct nv_softc {
        uint32_t        pidr;           /* pci id register */
        uint32_t        sidr;           /* pci sid register */
        uint32_t        pcsr;           /* pci csr register */
        int             nregs;          /* number of base registers */
        uint64_t        dma_mask;
        ddi_acc_handle_t        conf;   /* configuration registers */
        ddi_acc_handle_t        regmap; /* register mapping */
        ddi_acc_handle_t        fbmap;  /* fb mapping */
        volatile caddr_t pcicfg;        /* kernel pci configuration mapping */
        volatile caddr_t registers ;    /* kernel control registers mapping */
        caddr_t         fb ;            /* kernel fb mapping */
        pfn_t           regpfnum;       /* pfn of reg for mmap() */
        pfn_t           fbpfnum;        /* pfn of fb for mmap() */
        dev_info_t      *devi;          /* back pointer */
        ddi_iblock_cookie_t iblock_cookie;      /* block interrupts */
        kmutex_t        mutex;          /* mutex locking */
        nv_sunos_file_private_t *minordevs;
        unsigned int    flags;
        kstat_t         *intrstats;
        nv_state_t      *nv_state;
        int             refcnt;
        nvidia_stack_t  *sp[NV_DEV_STACK_COUNT];
        nvidia_alloc_t  *alloc_list;
        kmutex_t        alloc_list_lock;
        kmutex_t        mtx_rm;
        kmutex_t        api_lock;
        timeout_id_t    timer_ch;
        struct nv_i2c_bus *i2c_busses[NV_I2C_MAX_BUSSES];
        int             power_level[NV_PM_COMPONENTS];
        void            *vgatext_softc;
};

/* softc.flags */
#define NV_PM_SUSPENDED         0x00000010      /* board is off, system still on */
#define NV_PM_RESUMING          0x00000020      /* board is on, but not fully restored */

#define NV_BOARD_IS_ON(softc) (!((softc)->flags & NV_PM_SUSPENDED))

/*
 *      NV_PM_SUSPENDED NV_PM_RESUMING
 *              0               0       BOARD IS ON
 *              0               1       should not occur
 *              1               0       BOARD IS OFF
 *              1               1       BOARD IS RESUMING but not fully ON
 */
#define NV_BOARD_IS_ON_OR_RESUMING(softc) \
    (((softc)->flags & (NV_PM_SUSPENDED|NV_PM_RESUMING)) != NV_PM_SUSPENDED)


#define KIOIP   KSTAT_INTR_PTR(softc->intrstats)

/* global constants */
extern void     *nv_softc_head;

/* control device */
extern struct nv_softc  nvidia_ctl_sc;
extern nv_state_t       nvidia_ctl_state;

#define getsoftc(instance)      \
        ((instance) == CDEV_CTL_MINOR)  ? &nvidia_ctl_sc : \
                ((struct nv_softc *)ddi_get_soft_state(nv_softc_head, (instance) & ~NV_CLONEMASK))

#define NV_ISCTL(instance)      \
        (((instance) & ~NV_CLONEMASK) == CDEV_CTL_MINOR)

/*
 * These macros extract the encoded ioctl type and number from the
 * command; we inspect the type to verify that device/control ioctls
 * originate from NVIDIA RM clients and use the number to allow the
 * core resource manager's ioctl handler to be ignorant of operating
 * specific ioctl encodings.
 */

#define __NV_IOC_TYPE(_cmd) (((_cmd) >>  8) & 0xff)
#define __NV_IOC_SIZE(_cmd) (((_cmd) >> 16) & 0xff)
#define __NV_IOC_NR(_cmd)   (((_cmd) >>  0) & 0xff)

#define NV_KMEM_ALLOC_STACK(ptr)                            \
    {                                                       \
        (ptr) = kmem_alloc(sizeof(nvidia_stack_t), KM_SLEEP);   \
        if ((ptr) != NULL)                                  \
        {                                                   \
            (ptr)->size = sizeof((ptr)->stack);             \
            (ptr)->top = (ptr)->stack + (ptr)->size;        \
        }                                                   \
    }

#define NV_KMEM_FREE_STACK(ptr)                             \
    {                                                       \
        kmem_free((ptr), sizeof(nvidia_stack_t));               \
        (ptr) = NULL;                                       \
    }

/* nv.c */
extern ddi_taskq_t *nvidia_taskq;
extern int ddi_quiesce_not_supported (dev_info_t *) __attribute__((weak));

/* nv-i2c.c */
extern int nv_i2c_ioctl(nvidia_stack_t *, nv_state_t *, int, void *, int, cred_t *);

/* nvidia_subr.c */
extern int    nv_try_lock_api       (nv_state_t *);
extern void   nv_lock_api           (nv_state_t *);
extern void   nv_unlock_api         (nv_state_t *);
extern int    nvidia_get_card_info  (void *, int);

/* nvidia_pci.c */
#if !defined(PCI_COMM_SERR_ENABLE)
#define PCI_COMM_SERR_ENABLE    0x100
#endif
#if !defined(PCI_COMM_INTX_DISABLE)
#define PCI_COMM_INTX_DISABLE   0x400
#endif

extern NvU8  nvidia_pci_find_capability     (struct nv_softc *, NvU8);

extern int nvidia_pci_probe(nvidia_stack_t *, struct nv_softc *softc);
extern int nvidia_pci_get_addresses(struct nv_softc *);
extern int nvidia_pci_probe_legacy(dev_info_t *dip);

/* nvidia_reg.c */
extern void nvidia_update_registry(nvidia_stack_t *, char *);

extern void nv_cache_flush(void);

#define DEBUGF(level, args)
#define DEBUGP(args)

extern void nv_kstat_init(struct nv_softc *);
extern void nv_kstat_destroy(struct nv_softc *);

/* structure filled in by nv_get_system_release() */
struct nv_release {
        int     major;
        int     minor;
        int     micro;
};

extern major_t nv_major_device_number;
nv_sunos_file_private_t *nv_file_private_from_minor(struct nv_softc *, minor_t);
NvBool find_vnode_offset_within_file_t(void);

#endif  /* _NV_SOLARIS_H */
