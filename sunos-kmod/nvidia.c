/*
 * Copyright 2004-2021 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2014 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-solaris.h"
#include "nv-modeset-interface.h"

#define NV_DISABLE_INTR(ptr) (((NvU32 *)(ptr))[0x140/4] = 0);

static  int     nv_open(dev_t *, int, int, cred_t *);
static  int     nv_close(dev_t, int, int, cred_t *);
static  int     nv_ioctl(dev_t, int, intptr_t arg, int mode, cred_t *, int *);
static  int     nv_devmap(dev_t, devmap_cookie_t, offset_t, size_t, size_t *, uint_t);
static  int     nv_segmap(dev_t, off_t, struct as *, caddr_t *, off_t, u_int,
                          u_int, u_int, cred_t *);

static  int     nv_info(dev_info_t * dip, ddi_info_cmd_t infocmd,
                         void *arg, void **result);
static  int     nv_attach(dev_info_t *, ddi_attach_cmd_t);
static  int     nv_detach(dev_info_t *, ddi_detach_cmd_t);
static  int     nv_probe(dev_info_t *);
static  int     nv_power(dev_info_t *, int, int);
static  int     nv_poll(dev_t dev, short events, int anyyet, short *reventsp,
                        struct pollhead **phpp);
static  int     nv_reset(dev_info_t *devi, ddi_reset_cmd_t cmd);
static  void    nvidia_modeset_suspend(NvU32 gpuId);
static  void    nvidia_modeset_resume(NvU32 gpuId);
static  int     nv_open_kernel(NvU32 gpu_id, nvidia_stack_t *);
static  void    nv_close_kernel(NvU32 gpu_id, nvidia_stack_t *);

        /* DATA STRUCTURES */

        /*
         * Control device state (/dev/nvidiactl) which is opened
         * by each client but has no hardware attached to it.
        */
struct nv_softc nvidia_ctl_sc;
nv_state_t      nvidia_ctl_state;
        /* user operations: */

static struct cb_ops nv_cb_ops = {
        nv_open,                /* open */
        nv_close,               /* close */
        nodev,                  /* strategy */
        nodev,                  /* print */
        nodev,                  /* dump */
        nulldev,                /* read */
        nulldev,                /* write */
        nv_ioctl,               /* ioctl */
        nv_devmap,              /* devmap */
        nodev,                  /* mmap */
        nv_segmap,              /* segmap */
        nv_poll,                /* poll */
        ddi_prop_op,            /* cb_prop_op */
        0x0,                    /* streamtab  */
        D_NEW|D_MP|D_DEVMAP     /* Driver compatibility flag */
};

        /* system operations: */

struct dev_ops nv_ops = {
        DEVO_REV,               /* devo_rev, */
        0,                      /* refcnt  */
        nv_info,                /* info */
        nulldev,                /* identify */
        nv_probe,               /* probe */
        nv_attach,              /* attach */
        nv_detach,              /* detach */
        nv_reset,               /* reset */
        &nv_cb_ops,             /* driver operations */
        (struct bus_ops *)0,    /* bus operations */
        nv_power,               /* power management */
        ddi_quiesce_not_supported /* fast reboot */
};

        /* loadable driver stuff */

static struct modldrv modldrv = {
        &mod_driverops,         /* Type of module.  This one is a driver */
        "nvidia " NV_VERSION_STRING " " __DATE__" "__TIME__, /* Name of the module. */
        &nv_ops,                /* driver ops */
};

static struct modlinkage modlinkage = {
        MODREV_1, { (void *) &modldrv, NULL }
};

nvidia_stack_t *__nvidia_init_sp = NULL;

ddi_taskq_t *nvidia_taskq;

/*
 * So that nv_get_file_private() can validate that a vnode
 * corresponds to nvidia driver, we cache the device major number.
 */
major_t nv_major_device_number = 0;

/*
 * we cannot create these in the nvidia.conf file
 * since that is for the pseudo device. That will result in
 * devi being the devi for the pseudo device instead
 * of the nvidia device. This will result in erroneous
 * operation.
 *
 * Additionally, though we export an off state, a
 * request through our nv_power() entry to go to
 * off state will fail. We export simply to get
 * around the PM framework's complaint of mal-
 * -formed pm-components property if we do not supply
 * an off state in the property for each device.
 */
static char * pmcomps[] = {
    "NAME=GPU",
    "0=Off",
    "3=On",
    "NAME=Monitor",
    "0=Off",
    "3=On"
};

void            *nv_softc_head;

static struct ddi_device_acc_attr WC_attr = {
        DDI_DEVICE_ATTR_V0,
        DDI_NEVERSWAP_ACC,
        DDI_MERGING_OK_ACC
};

static struct ddi_device_acc_attr UC_attr = {
        DDI_DEVICE_ATTR_V0,
        DDI_NEVERSWAP_ACC,
        DDI_STRICTORDER_ACC
};

struct nv_release nv_sys_rel;   /* current system release level */

/* prototypes for functions local to this file */

static  u_int   nv_intr(caddr_t);
static int nv_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *cred, int *rval);

static inline NvBool nv_lock_init_locks(nvidia_stack_t *sp, nv_state_t *nv)
{
    return rm_init_event_locks(sp, nv);
}

static inline void nv_lock_destroy_locks(nvidia_stack_t *sp, nv_state_t *nv)
{
    rm_destroy_event_locks(sp, nv);
}

/*
 * Convert string to a integer - ends at first non-digit.
 * Returns pointer to place where conversion stopped.
 */
static char *
cvt_num_dot_to_int(register char *cp, int *result)
{
        register char   ch;
        register int    num;
        int             neg = 0;

        if (!cp) {
            if (*result) *result = 0;
            return (NULL);
        }

        if (*cp != 0) {
                while ((ch = *cp) &&
                    (ch == ' ' || ch == '\t' || ch == '\n')) cp++;
                ch = *cp;
                if (ch == '-') {
                        neg = 1;
                        cp++;
                }
                if (ch == '+') {
                        neg = 0;
                        cp++;
                }
        }

        for (num = 0; (ch = *cp) && (ch >= '0' && ch <= '9'); cp++) {
                num *= 10;
                num += '0' - ch;        /* accum neg to handle MAX neg int */
        }

        *result = neg ? num : -num;

        return (cp);
}


/* get current system release level */
static void
nv_get_system_release(struct nv_release *result)
{
        char    *cp;

        result->major = result->minor = result->micro = 0;

        cp = cvt_num_dot_to_int(utsname.release, &result->major);
        if (cp && *cp)
                cp = cvt_num_dot_to_int(cp + 1, &result->minor);
        if (cp && *cp)
                cp = cvt_num_dot_to_int(cp + 1, &result->micro);
}

        /* MODULE FUNCTIONS */

        /* Init function.  Called when driver is loaded */
int
_init(void)
{
        int e, debug_level;
        struct nv_softc *ctl_softc = &nvidia_ctl_sc;
        nv_state_t *ctl_nv = &nvidia_ctl_state;
        nvidia_stack_t *sp = NULL;

        os_page_size  = PAGESIZE;
        os_page_mask  = PAGEMASK;
        os_page_shift = PAGESHIFT;

#ifndef DEBUG
        /*
         * Don't print the NVIDIA kernel module load notification
         * by default with retail drivers to avoid violation of
         * Sun's boot policy. Do print it by default if this is a
         * DEBUG build.
         */
        debug_level = NV_DBG_INFO;
#else
        debug_level = NV_DBG_ERRORS;
#endif

        nv_printf(debug_level, "NVRM: loading %s\n", pNVRM_ID);

        NV_KMEM_ALLOC_STACK(sp);
        if (sp == NULL)
            return (ENOMEM);

        if (!find_vnode_offset_within_file_t()) {
            nv_printf(NV_DBG_WARNINGS, "NVRM: Failed to assess run-time environment.\n");
            return EIO;
        }

        /*
         * initialize some global constants
         */

        // When the RM is loaded on current solaris kernels, the first attach
        // and first open are for device 0, due to hard coded logic in the kernel
        // concerning text consoles. Since ctl_softc and ctl_nv contain refcnt
        // and mutex required to access the refcount, and because they are global
        // structures, it was decided that we would move init of those structures
        // here when the module loaded, so the contents of those structures could
        // be used properly before the attach for the control device. These structures
        // are used to determine if RM should initialize the hardware or not during
        // open.
        bzero(ctl_softc, sizeof(struct nv_softc));

        mutex_init(&ctl_softc->mutex, "softc_mtx", MUTEX_DRIVER, NULL);
        mutex_init(&ctl_softc->mtx_rm, "mtx_rm", MUTEX_DRIVER, NULL);
        mutex_init(&ctl_softc->api_lock, "api_lock", MUTEX_DRIVER, NULL);

        ctl_nv->os_state = (void *)ctl_softc;
        ctl_softc->nv_state = ctl_nv;

        /* get current system release level from utsname kernel global */
        nv_get_system_release(&nv_sys_rel);

        if ((e = ddi_soft_state_init(&nv_softc_head,
                    sizeof (struct nv_softc), 1)) != 0) {
                nv_printf(NV_DBG_ERRORS,
                    "NVRM: _init: ddi_soft_state_init() failed (%d)\n", e);
                NV_KMEM_FREE_STACK(sp);
                return (e);
        }

        nvidia_taskq = ddi_taskq_create(NULL, "nvidia_taskq", 1,
                TASKQ_DEFAULTPRI, 0);
        if (nvidia_taskq == NULL) {
                nv_printf(NV_DBG_ERRORS,
                        "NVRM: _init: ddi_taskq_create() failed (%d)\n", e);
                ddi_soft_state_fini(&nv_softc_head);
                NV_KMEM_FREE_STACK(sp);
                return (ENOMEM);
        }

        /*
         * The module load event. Our KLD has just been loaded and is
         * ready to initialize. We setup the core resource manager in
         * this routine, further initialization takes place at attach
         * time.
         */
        if (!rm_init_rm(sp)) {
                nv_printf(NV_DBG_ERRORS, "NVRM: _init: rm_init_rm failed\n");
                ddi_soft_state_fini(&nv_softc_head);
                NV_KMEM_FREE_STACK(sp);
                return (EIO);
        }

        if (!nv_lock_init_locks(sp, ctl_nv)) {
                rm_shutdown_rm(sp);
                ddi_soft_state_fini(&nv_softc_head);
                NV_KMEM_FREE_STACK(sp);
                return (ENOMEM);
        }

        e = mod_install(&modlinkage);

        if (e) {
                nv_lock_destroy_locks(sp, ctl_nv);
                rm_shutdown_rm(sp);
                ddi_soft_state_fini(&nv_softc_head);
                NV_KMEM_FREE_STACK(sp);
                nv_printf(NV_DBG_ERRORS, "NVRM: _init: mod_install failed\n") ;
                return (e);
        }

        __nvidia_init_sp = sp;

        return (e);
}


        /* Fini function.  Called when driver is unloaded */

int
_fini(void)
{
        struct nv_softc *ctl_softc = &nvidia_ctl_sc;
        nv_state_t *ctl_nv = &nvidia_ctl_state;
        nvidia_stack_t *sp = __nvidia_init_sp;
        int e;

        nv_printf(NV_DBG_INFO, "NVRM: _fini\n");

        if (nv_ops.devo_refcnt != 0)
            return EBUSY;

        if ((e = mod_remove(&modlinkage)) != 0)
            return (e);

        nv_lock_destroy_locks(sp, ctl_nv);

        rm_shutdown_rm(sp);

        ddi_taskq_destroy(nvidia_taskq);

        ddi_soft_state_fini(&nv_softc_head);

        // destroy the mutices of the global nvidia_ctl_sc structure
        mutex_destroy(&ctl_softc->api_lock);
        mutex_destroy(&ctl_softc->mtx_rm);
        mutex_destroy(&ctl_softc->mutex);

        NV_KMEM_FREE_STACK(sp);

        return (0);
}


        /* Info function.  Called to return driver info */

int
_info(struct modinfo * modinfop)
{
        return (mod_info(&modlinkage, modinfop));
}

nv_sunos_file_private_t *
nv_file_private_from_minor(struct nv_softc *softc, minor_t unit)
{
        nv_sunos_file_private_t *nvsfp;
        nv_sunos_file_private_t *result = (nv_sunos_file_private_t *) 0;

        mutex_enter(&softc->mutex);

        /* locate minordev structure */
        for (nvsfp = softc->minordevs; nvsfp != NULL; nvsfp = nvsfp->next) {
                if (nvsfp->cloneminor == unit) {
                        result = nvsfp;
                        break;
                }
        }

        mutex_exit(&softc->mutex);

        return (result);
}

        /* DRIVER INIT FUNCTIONS */

/* ARGSUSED */
static int
nv_probe(dev_info_t *devi)
{
    nvidia_stack_t *sp;
    int e;

    nv_printf(NV_DBG_INFO,
              "NVRM: nv_probe: (%s) unit = %d\n",
              ddi_get_name(devi), ddi_get_instance(devi));

    e = nvidia_pci_probe_legacy(devi);

    return e;
}

static int
nv_attach_ctl(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
        struct nv_softc *softc;
        int unit = ddi_get_instance(devi);
        nvidia_stack_t *sp = NULL;
        char *option_string;

        nv_printf(NV_DBG_INFO,
                  "NVRM: nv_attach_ctl: devi = %p unit = %d cmd = %d\n",
                  devi, unit, (int) cmd);

        switch (cmd) {

          case DDI_ATTACH:

                softc = &nvidia_ctl_sc;

                 /* link it in */
                softc->devi = devi;
                ddi_set_driver_private(devi, (caddr_t) softc);

                if (ddi_create_minor_node(devi, "nvidiactl", S_IFCHR,
                    unit, DDI_PSEUDO, 0) == DDI_FAILURE) {
                    nv_printf(NV_DBG_ERRORS,
                              "NVRM: nv_attach_ctl: ddi_create_minor_node failed");
                    ddi_remove_minor_node(devi, NULL);
                    return (DDI_FAILURE);
                }

                NV_KMEM_ALLOC_STACK(sp);
                if (sp == NULL) {
                    ddi_remove_minor_node(devi, NULL);
                    return (DDI_FAILURE);
                }

                ddi_report_dev(devi);

                if (ddi_prop_lookup_string(DDI_DEV_T_ANY,
                            devi, DDI_PROP_DONTPASS,
                            "registry", &option_string) == DDI_PROP_SUCCESS) {
                    nvidia_update_registry(sp, option_string);
                    ddi_prop_free(option_string);
                }

                NV_KMEM_FREE_STACK(sp);

            return (DDI_SUCCESS);

          case DDI_RESUME:
          case DDI_PM_RESUME:
            return (DDI_FAILURE);

          default:
            nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach_ctl: unknown cmd %d\n", cmd);
            return (DDI_FAILURE);
        }
}

static void
nv_dev_free_stacks(struct nv_softc *softc)
{
    NvU32 i;
    for (i = 0; i < NV_DEV_STACK_COUNT; i++)
    {
        if (softc->sp[i])
            NV_KMEM_FREE_STACK(softc->sp[i]);
    }
}

static int
nv_dev_alloc_stacks(struct nv_softc *softc)
{
    NvU32 i;
    for (i = 0; i < NV_DEV_STACK_COUNT; i++)
    {
        NV_KMEM_ALLOC_STACK(softc->sp[i]);
        if (softc->sp[i] == NULL)
        {
            nv_dev_free_stacks(softc);
            return 1;
        }
    }
    return 0;
}

static int
nv_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
        struct nv_softc *softc;
        nv_state_t      *nv;
        char            name[16];
        int             unit = ddi_get_instance(devi);
        int             rc;
        int             nregs;
        ddi_idevice_cookie_t    idev_cookie;
        pci_regspec_t   *pci_rp;
        uint_t          length;
        uint64_t        pa;
        NV_STATUS       status = NV_ERR_GENERIC;
        nvidia_stack_t     *sp = NULL;

        if (NV_ISCTL(unit))
                return (nv_attach_ctl(devi, cmd));

        nv_printf(NV_DBG_INFO,
                  "NVRM: nv_attach: devi = %p, unit = %d cmd = %d\n", devi, unit, (int) cmd);

        switch (cmd) {

          case DDI_ATTACH:

            if ((ddi_dev_nregs(devi, &nregs) == DDI_FAILURE)) {
                nv_printf(NV_DBG_ERRORS, "NVRM: attach: ddi_dev_nregs failed\n");
                return (DDI_FAILURE);
            }

            /* Allocate softc struct */
            if (ddi_soft_state_zalloc(nv_softc_head, unit) != 0 )
                    return (DDI_FAILURE);

            softc = ddi_get_soft_state(nv_softc_head, unit);

            softc->nv_state = kmem_zalloc(sizeof(nv_state_t), KM_SLEEP);
            if (softc->nv_state == NULL) {
                (void) ddi_soft_state_free(nv_softc_head, unit);
                return (DDI_FAILURE);
            }
            nv = softc->nv_state;

            if (nv_dev_alloc_stacks(softc)) {
                kmem_free(softc->nv_state, sizeof(nv_state_t));
                ddi_soft_state_free(nv_softc_head, unit);
                return (DDI_FAILURE);
            }

            sp = softc->sp[NV_DEV_STACK_ATTACH];

            /* link it in */
            softc->devi = devi;
            ddi_set_driver_private(devi, (caddr_t) softc);

            /* map in the configuration registers */
            /* instead of using pci_config_setup(), do the mapping */
            /* ourselves so we have the KVA for a ddi_peek() later */

            if (ddi_regs_map_setup(devi, REGNUM_CONF, (caddr_t *)&softc->pcicfg,
                                 0, 0, &UC_attr, &softc->conf) )
            {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_attach: CONF ddi_regs_map_setup failed\n");
                goto failed1;
            }

            if (nvidia_pci_probe(sp, softc)) {
                nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach: nvidia_pci_probe failed\n");
                ddi_regs_map_free(&softc->conf);
                goto failed1;
            }

            /*
             * Only attach the gfx_private vgatext code if this is
             * is a VGA device; nv_attach() is called for devices with
             * a subclass of PCI_DISPLAY_VGA and PCI_DISPLAY_3D.
             */
            if (pci_config_get8(softc->conf,
                                PCI_CONF_SUBCLASS) == PCI_DISPLAY_VGA) {
                softc->vgatext_softc = gfxp_vgatext_softc_alloc();
                if (softc->vgatext_softc == NULL) {
                    nv_printf(NV_DBG_ERRORS,
                              "NVRM: nv_attach: gfxp_vgatext_softc_alloc failed\n");
                    ddi_regs_map_free(&softc->conf);
                    goto failed1;
                }
                if (gfxp_vgatext_attach(devi, cmd, softc->vgatext_softc) == DDI_FAILURE) {
                    nv_printf(NV_DBG_ERRORS,
                              "NVRM: nv_attach: gfxp_vgatext_attach failed\n");
                    ddi_regs_map_free(&softc->conf);
                    goto failed1;
                }
            }

            /* default to 32-bit PCI bus address space */
            softc->dma_mask = 0xffffffffULL;

            pci_config_put16(softc->conf, PCI_CONF_COMM,
                (pci_config_get16(softc->conf, PCI_CONF_COMM) | PCI_COMM_MAE));

            softc->sidr = pci_config_get32(softc->conf, PCI_CONF_SUBVENID);
            softc->pidr = pci_config_get32(softc->conf, PCI_CONF_VENID);
            softc->pcsr = pci_config_get32(softc->conf, PCI_CONF_COMM);

            // ddi_dev_nregs() done on entry
            softc->nregs = nregs;

            /* map in the registers */

/*
 * Workaround for 6195346:  Only map the first page of the register
 * and framebuffer apertures to prevent exhausting the device arena.
 * The starting pfnum is all we need for segmap/mmap since the PA
 * is linear.
*/
/* NVDA says the entire register 16MB must be mapped */
            if (ddi_regs_map_setup(devi, REGNUM_REGS,
                (caddr_t *)&softc->registers, 0, PAGESIZE,
                &UC_attr, &softc->regmap) ) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_attach: REGS ddi_regs_map_setup failed\n");
                goto failed2;
            }

            gfxp_va2pa(&kas, softc->registers, &pa);
            if (pa == 0) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_attach: REGS gfxp_va2pa failed\n");
                goto failed2;
            }
            softc->regpfnum = (pa >> PAGESHIFT);

/* NVDA, do we need the entire frame buffer mapped? */
            /* map in the entire frame buffer */
            if (ddi_regs_map_setup(devi, REGNUM_FB, &softc->fb, 0,
                PAGESIZE, &UC_attr, &softc->fbmap) ) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_attach: FB ddi_regs_map_setup failed\n");
                ddi_regs_map_free(&softc->regmap);
                goto failed2;
            }

            gfxp_va2pa(&kas, softc->fb, &pa);
            if (pa == 0) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_attach: FB gfxp_va2pa failed\n");
                goto failed2;
            }
            softc->fbpfnum = (pa >> PAGESHIFT);

            if (ddi_intr_hilevel(devi, 0)) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_attach: ddi_intr_hilevel failed\n");
                goto failed3;
            }

            if (ddi_get_iblock_cookie(devi, 0, &softc->iblock_cookie)
                                        != DDI_SUCCESS) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_attach: ddi_get_iblock_cookie failed\n");
                goto failed3;
            }

            mutex_init(&softc->mutex, "softc_mtx", MUTEX_DRIVER, softc->iblock_cookie);
            mutex_init(&softc->alloc_list_lock, "alloc_list_lock", MUTEX_DRIVER, NULL);
            mutex_init(&softc->mtx_rm, "mtx_rm", MUTEX_DRIVER, NULL);
            mutex_init(&softc->api_lock, "api_lock", MUTEX_DRIVER, NULL);

            /* hold off interrupt routine during rest of initialization */
            NV_DISABLE_INTR(softc->registers);

            nv->os_state = softc;
            nv->flags = 0;

            if (ddi_add_intr(devi, 0, NULL, &idev_cookie,
                nv_intr, (caddr_t) softc) != DDI_SUCCESS) {
                nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach: ddi_add_intr failed\n");
                goto failed3;
            }

            // TODO: are nv_detach calls needed on failure?
            sprintf(name, "nvidia%d", unit);

            if (ddi_create_minor_node(devi, name, S_IFCHR,
                unit, DDI_NT_DISPLAY, 0) == DDI_FAILURE) {
                nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach: ddi_create_minor_node failed\n");
                goto failed4;
            }

            /* get "reg" property */
            rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, devi,
                        DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
                        (uint_t *)&length);
            if (rc == DDI_SUCCESS) {
                nv->pci_info.domain = 0;
                nv->pci_info.bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
                nv->pci_info.slot = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
                ddi_prop_free(pci_rp);
            } else {
                nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach: \"reg\" lookup failed\n");
                goto failed4;
            }

            /* XXX fix me! (interupt_line) */
            nv->interrupt_line = pci_config_get8(softc->conf, PCI_CONF_ILINE);

            nv->fb   = &nv->bars[NV_GPU_BAR_INDEX_FB];
            nv->regs = &nv->bars[NV_GPU_BAR_INDEX_REGS];

            /* enable kstat reporting */
            /* nv_kstat_init(softc); */  /* XXX Fix me? (kstat) */

            /*
             * advertise power management
            */

            softc->power_level[NV_PM_BOARD] = NV_BOARD_OFF;
            softc->power_level[NV_PM_MONITOR] = NV_DPMS_NORMAL;

            if (ddi_prop_update_string_array(DDI_DEV_T_NONE, devi,
                                            "pm-components", &pmcomps[0],
                                            sizeof(pmcomps)/sizeof(char *)) != DDI_PROP_SUCCESS) {
                /* failure to create pm components is not critical */
                nv_printf(NV_DBG_WARNINGS, "NVRM: nv_attach: Unable to create \"pm-components\" property.\n");
            }

            /*
             * advertise that we are in standby mode. This will allow an open to the RM.
             */
            if (pm_power_has_changed(devi, NV_PM_BOARD, NV_BOARD_ON) != (DDI_SUCCESS))
                nv_printf(NV_DBG_WARNINGS, "NVRM: nv_attach: Request pm_power_has_changed for GPU device has failed.\n");
            else if (pm_power_has_changed(devi, NV_PM_MONITOR, NV_DPMS_NORMAL) != (DDI_SUCCESS))
                nv_printf(NV_DBG_WARNINGS, "NVRM: nv_attach: Reqeust pm_power_has_changed for Monitor device has failed.\n");

/* NVDA: any restriction on bus clock? */
#if 0
            pci_report_pmcap(devi, PCI_PM_IDLESPEED, PCI_PM_IDLESPEED_ANY);
#else
            pci_report_pmcap(devi, PCI_PM_IDLESPEED, PCI_PM_IDLESPEED_NONE);
#endif

            if (!rm_init_private_state(sp, softc->nv_state)) {
                nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach: rm_init_private_state failed\n");
                goto failed4;
            }

            if (!nv_lock_init_locks(sp, softc->nv_state))
            {
                rm_free_private_state(sp, softc->nv_state);
                goto failed4;
            }

            ddi_report_dev(devi);
            nv_major_device_number = ddi_driver_major(devi);

            return (DDI_SUCCESS);


failed4:    ddi_remove_minor_node(devi, NULL);
            ddi_remove_intr(devi, 0, softc->iblock_cookie);
failed3:    ddi_regs_map_free(&softc->fbmap);
            ddi_regs_map_free(&softc->regmap);
failed2:    ddi_regs_map_free(&softc->conf);
            if (softc->vgatext_softc != NULL)
                gfxp_vgatext_softc_free(softc->vgatext_softc);
failed1:    nv_dev_free_stacks(softc);
            kmem_free(softc->nv_state, sizeof(nv_state_t));
            ddi_soft_state_free(nv_softc_head, unit);

            return (DDI_FAILURE);

          case DDI_RESUME:
          case DDI_PM_RESUME:

              softc = (struct nv_softc *)ddi_get_driver_private(devi);
              nv = softc->nv_state;

              sp = softc->sp[NV_DEV_STACK_ATTACH];

              nv_lock_api(nv);
              mutex_enter(&softc->mutex);

              // if we are resuming a board that is not suspended, bail
              if (softc->power_level[NV_PM_BOARD] != NV_BOARD_SUSPENDED) {
                  mutex_exit(&softc->mutex);
                  nv_unlock_api(nv);
                  return (DDI_FAILURE);
              }

              // restore config space for card.
              rc = pci_restore_config_regs(softc->devi);

              if (rc == (DDI_SUCCESS)) {
                  softc->flags |= NV_PM_RESUMING;

                  status = rm_power_management(sp, nv, NV_PM_ACTION_RESUME);

                  if (status == NV_OK) {
                      softc->power_level[NV_PM_BOARD] = NV_BOARD_ON;

                      //  if we woke successfully, we can decrement our reference for suspend
                      softc->refcnt--;
                  } else {
                      // (do not modify rc to DDI_FAILURE)
                      nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach: rm_power_management(%d) failed\n", unit);
                  }

                  // check refcnt before disabling and shutting down the adapter
                  if (softc->refcnt == 0) {
                      rm_disable_adapter(sp, nv);
                      rm_shutdown_adapter(sp, nv);

                      // we can erase the open flag (open will need to init)
                      nv->flags &= ~NV_FLAG_OPEN;

                      // mark board as off
                      softc->power_level[NV_PM_BOARD] = NV_BOARD_OFF;
                  }

                  softc->flags &= ~(NV_PM_RESUMING | NV_PM_SUSPENDED);
              }

              mutex_exit(&softc->mutex);
              nv_unlock_api(nv);

              if (rc == DDI_SUCCESS)
              {
                  nvidia_modeset_resume(nv->gpu_id);
              }
              return rc;

          default:
            nv_printf(NV_DBG_ERRORS, "NVRM: nv_attach: unknown cmd %d\n", cmd);
            return (DDI_FAILURE);
        }
}

static int
nv_detach_ctl(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
        struct nv_softc *softc = (struct nv_softc *)ddi_get_driver_private(devi);
        nv_state_t *ctl_nv = &nvidia_ctl_state;

        nv_printf(NV_DBG_INFO,
                  "NVRM: nv_detach_ctl: softc = %x, devi = 0x%x, cmd = %d\n",
                  softc, devi, cmd);

        switch (cmd) {

          case DDI_DETACH:

                if (!nv_try_lock_api(ctl_nv))
                    return (DDI_FAILURE);

                /*
                 * Do not allow the control device to detach if
                 * it's still open.
                 */
                if ((ctl_nv->flags & NV_FLAG_OPEN) == NV_FLAG_OPEN) {
                    nv_unlock_api(ctl_nv);
                    return (DDI_FAILURE);
                }

                nv_unlock_api(ctl_nv);

                /*
                 * destroy nvidiactlN
                 */
                ddi_remove_minor_node(devi, NULL);
                return (DDI_SUCCESS);

          case DDI_SUSPEND:
          case DDI_PM_SUSPEND:
            return (DDI_FAILURE);

          default:
              return (DDI_FAILURE);
        }
}

static int
nv_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
        int instance = ddi_get_instance(devi);
        nvidia_stack_t *sp = NULL;
        struct nv_softc *softc = (struct nv_softc *)ddi_get_driver_private(devi);
        nv_state_t *nv = softc->nv_state;
        nv_state_t *ctl_nv = &nvidia_ctl_state;
        NV_STATUS status = NV_ERR_GENERIC;
        int ddi_status = (DDI_FAILURE);
        int unit = ddi_get_instance(devi);

        nv_printf(NV_DBG_INFO,
                  "NVRM: nv_detach: softc = %x, devi = 0x%x, cmd = %d\n",
                  softc, devi, cmd);

        if (NV_ISCTL(instance))
                return (nv_detach_ctl(devi, cmd));

        nv = softc->nv_state;

        switch (cmd) {

          case DDI_DETACH:

                if (!nv_try_lock_api(ctl_nv))
                    return (DDI_FAILURE);
                if (!nv_try_lock_api(nv)) {
                    nv_unlock_api(ctl_nv);
                    return (DDI_FAILURE);
                }

                /*
                 * Do not allow this device to detach if it's still
                 * open or if the control device is open.
                 */
                if (((ctl_nv->flags & NV_FLAG_OPEN) == NV_FLAG_OPEN) ||
                    ((nv->flags & NV_FLAG_OPEN) == NV_FLAG_OPEN)) {
                    nv_unlock_api(nv);
                    nv_unlock_api(ctl_nv);
                    return (DDI_FAILURE);
                }

                nv_unlock_api(nv);
                nv_unlock_api(ctl_nv);

                mutex_enter(&softc->mutex);

                /*
                 * If board is powered off, don't allow the detach.
                 * On attach we cannot know the board power state,
                 * plus we will leak all the memory allocated for
                 * the saved state.
                */
                if (!NV_BOARD_IS_ON(softc)) {
                        mutex_exit(&softc->mutex);
                        return (DDI_FAILURE);
                }

                mutex_exit(&softc->mutex);

                rm_i2c_remove_adapters(softc->sp[NV_DEV_STACK_ATTACH], nv);

                ddi_remove_intr(devi, 0, softc->iblock_cookie);

                if (softc->vgatext_softc != NULL) {
                    gfxp_vgatext_detach(devi, cmd, softc->vgatext_softc);
                    gfxp_vgatext_softc_free(softc->vgatext_softc);
                }

                if (softc->timer_ch)
                        untimeout(softc->timer_ch);

                ddi_regs_map_free(&softc->fbmap);
                ddi_regs_map_free(&softc->regmap);
                ddi_regs_map_free(&softc->conf);

                mutex_destroy(&softc->api_lock);
                mutex_destroy(&softc->mtx_rm);
                mutex_destroy(&softc->alloc_list_lock);

                mutex_destroy(&softc->mutex);

                ddi_prop_remove(DDI_DEV_T_NONE, devi, "pm-components");

                ddi_remove_minor_node(devi, NULL);

                rm_free_private_state(softc->sp[NV_DEV_STACK_ATTACH],
                                      softc->nv_state);

                nv_lock_destroy_locks(softc->sp[NV_DEV_STACK_ATTACH],
                                      softc->nv_state);

                nv_dev_free_stacks(softc);

                kmem_free(softc->nv_state, sizeof(nv_state_t));

                (void) ddi_soft_state_free(nv_softc_head, instance);

                return (DDI_SUCCESS);

          case DDI_SUSPEND:
          case DDI_PM_SUSPEND:
              ddi_status = (DDI_FAILURE);

              nvidia_modeset_suspend(nv->gpu_id);

              nv_lock_api(nv);
              mutex_enter(&softc->mutex);

              sp = softc->sp[NV_DEV_STACK_ATTACH];

              if (softc->refcnt == 0) {
                  mutex_exit(&softc->mutex);

                  // we should only be here if the board has not been posted.
                  // Let's attempt to post.
                  if (!rm_init_adapter(sp, nv)) {
                      nv_printf(NV_DBG_ERRORS, "NVRM: rm_init_adapter(%d) failed\n", unit);
                      nv_unlock_api(nv);
                      return (DDI_FAILURE);
                  }

                  // if open comes through after we are suspended, we need to
                  // avoid re-initializing the board
                  nv->flags |= NV_FLAG_OPEN;

                  mutex_enter(&softc->mutex);

                  // note that the board is now on (proper book-keeping)
                  softc->power_level[NV_PM_BOARD] = NV_BOARD_ON;

                  // save the current low resolution mode information
                  rm_save_low_res_mode(sp, nv);
              }

              status = rm_power_management(sp, nv, NV_PM_ACTION_STANDBY);

              if (status == NV_OK) {
                  ddi_status = pci_save_config_regs(softc->devi);

                  // bump refcnt now that sleep is depending on the device to be present.
                  softc->refcnt++;
              } else {
                  nv_printf(NV_DBG_ERRORS, "NVRM: nv_detach: rm_power_management(%d) failed\n", unit);
              }

              if (ddi_status == (DDI_SUCCESS)) {
                  softc->power_level[NV_PM_BOARD] = NV_BOARD_SUSPENDED;
                  softc->flags |= NV_PM_SUSPENDED;
              }

              mutex_exit(&softc->mutex);
              nv_unlock_api(nv);

              return ddi_status;

          default:
              return (DDI_FAILURE);
        }
}


/* ARGSUSED */
static int
nv_info(dev_info_t * dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
        int error = DDI_SUCCESS;
        minor_t unit;
        struct nv_softc *softc;

        unit = getminor((dev_t)arg);

        switch (infocmd) {
        case DDI_INFO_DEVT2DEVINFO:
                if (NV_ISCTL(unit)) {
                        *result = nvidia_ctl_sc.devi;
                        error = DDI_SUCCESS;
                } else if ((softc = getsoftc(unit)) == NULL) {
                        error = DDI_FAILURE;
                } else {
                        *result = (void *) softc->devi;
                        error = DDI_SUCCESS;
                }
        break;
        case DDI_INFO_DEVT2INSTANCE:
                *result = (void *) (uintptr_t)(unit & ~NV_CLONEMASK);
                error = DDI_SUCCESS;
                break;
        default:
                error = DDI_FAILURE;
        }
        return (error);
}



        /* USER FUNCTIONS */

/*ARGSUSED*/
static int
nv_open_ctl(dev_t *devp, int flag, int otyp, cred_t *cred)
{
        int unit = getminor(*devp);
        struct  nv_softc *softc = &nvidia_ctl_sc;
        nv_state_t *nv = &nvidia_ctl_state;
        nv_sunos_file_private_t *nvsfp, *new_nvsfp;
        minor_t cloneminor; int cleanpass;
        nvidia_stack_t *sp = NULL;

        nv_printf(NV_DBG_INFO, "NVRM: nv_open_ctl: unit = %d\n", unit);

        mutex_enter(&softc->mutex);
        /*
         * Find an unused minor device number: for each value in the
         * clone minor device space, see if that value is used.  When we
         * find an unused one, use it for this open and hang the
         * nv_sunos_file_private_t struct on the nv_softc's minor device list.
         */
        for (cloneminor = unit + NV_CLONEDEV; ; cloneminor += NV_CLONEDEV) {
                cleanpass = 1;

                for (nvsfp = softc->minordevs; nvsfp != NULL; nvsfp = nvsfp->next) {
                        if (nvsfp->cloneminor == cloneminor) {
                                cleanpass = 0;
                                break;
                        }
                }

                if (cleanpass)
                        goto gotminor;
        }

        nv_printf(NV_DBG_ERRORS,
            "NVRM: failed to allocate minor device number\n");
        mutex_exit(&softc->mutex);
        return (ENXIO);

gotminor:
        NV_KMEM_ALLOC_STACK(sp);
        if (sp == NULL) {
            mutex_exit(&softc->mutex);
            return (ENOMEM);
        }

        new_nvsfp = kmem_zalloc(sizeof(nv_sunos_file_private_t), KM_SLEEP);
        if (new_nvsfp == NULL) {
            NV_KMEM_FREE_STACK(sp);
            mutex_exit(&softc->mutex);
            return (ENOMEM);
        }

        new_nvsfp->sp = sp;
        new_nvsfp->pid = ddi_get_pid();
        new_nvsfp->next = softc->minordevs;
        new_nvsfp->cloneminor = cloneminor;
        new_nvsfp->softc = softc;
        mutex_init(&new_nvsfp->event_lock, "event_lock", MUTEX_DRIVER, NULL);
        softc->minordevs = new_nvsfp;

        *devp = makedevice(getmajor(*devp), cloneminor);

        softc->refcnt++;

        mutex_exit(&softc->mutex);

        nv_lock_api(nv);

        nv->flags |= NV_FLAG_OPEN;
        nv->flags |= NV_FLAG_CONTROL;

        nv_unlock_api(nv);

        return (0);
}

static nv_state_t* nv_find_state(NvU32 gpu_id)
{
    unsigned int i;

    for (i = 0; i < NV_MAX_DEVICES; i++) {
        nv_state_t *nv;
        struct nv_softc *sc = ddi_get_soft_state(nv_softc_head, i);
        if (sc == NULL) {
            continue;
        }

        nv = sc->nv_state;

        if (nv->gpu_id == gpu_id) {
            return nv;
        }
    }

    return NULL;
}

static int
nv_open_increment(nv_state_t *nv, nvidia_stack_t *sp)
{
        nv_state_t *ctl_nv = &nvidia_ctl_state;
        struct nv_softc *softc = nv->os_state;

        softc->refcnt++;
        if ((nv->flags & NV_FLAG_OPEN) == 0) {
            if (!rm_init_adapter(sp, nv)) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: nv_open: rm_init_adapter(0x%08x) failed\n",
                          nv->gpu_id);
                softc->refcnt--;
                return EIO;
            }
            nv->flags |= NV_FLAG_OPEN;

            mutex_enter(&softc->mutex);

            //success, mark that power is now on.
            softc->power_level[NV_PM_BOARD] = NV_BOARD_ON;
            mutex_exit(&softc->mutex);
        }

        return 0;
}



/*ARGSUSED*/
static  int
nv_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
        int e = ENOMEM;
        int unit = getminor(*devp);
        struct  nv_softc *softc;
        nv_state_t *ctl_nv = &nvidia_ctl_state;
        nv_state_t *nv;
        nv_sunos_file_private_t *nvsfp, *new_nvsfp = NULL;
        minor_t cloneminor; int cleanpass;
        nvidia_stack_t *sp = NULL;

        if (otyp != OTYP_CHR)
                return (EINVAL);

        nv_printf(NV_DBG_INFO, "NVRM: nv_open: unit = %d\n", unit);

        if (NV_ISCTL(unit))
                return (nv_open_ctl(devp, flag, otyp, cred));

        softc = getsoftc(unit);

        if (softc == NULL)
                return (ENXIO);

        nv = softc->nv_state;

        if (nv->handle == NULL) {
            nv->handle = os_pci_init_handle(nv->pci_info.domain, nv->pci_info.bus,
                                            nv->pci_info.slot, 0,
                                            &nv->pci_info.vendor_id,
                                            &nv->pci_info.device_id);
        }

        if (softc->vgatext_softc != NULL) {
            if (gfxp_vgatext_open(devp, flag, otyp, cred, softc->vgatext_softc)) {
                nv_printf(NV_DBG_ERRORS,
                          "NVRM: gfxp_vgatext_open failed\n");
                return (ENXIO);
            }
        }

        mutex_enter(&softc->mutex);
        /*
         * Find an unused minor device number: for each value in the
         * clone minor device space, see if that value is used.  When we
         * find an unused one, use it for this open and hang the
         * nv_sunos_file_private_t struct on the nv_softc's minor device list.
         */
        for (cloneminor = unit + NV_CLONEDEV; ; cloneminor += NV_CLONEDEV) {
                cleanpass = 1;

                for (nvsfp = softc->minordevs; nvsfp != NULL; nvsfp = nvsfp->next) {
                        if (nvsfp->cloneminor == cloneminor) {
                                cleanpass = 0;
                                break;
                        }
                }

                if (cleanpass)
                        goto gotminor;
        }

        nv_printf(NV_DBG_ERRORS,
            "NVRM: failed to allocate minor device number\n");
        mutex_exit(&softc->mutex);
        if (softc->vgatext_softc != NULL)
            gfxp_vgatext_close(*devp, flag, otyp, cred, softc->vgatext_softc);
        return (ENXIO);

gotminor:
        NV_KMEM_ALLOC_STACK(sp);
        if (sp == NULL)
            goto failed1;

        new_nvsfp = kmem_zalloc(sizeof(nv_sunos_file_private_t), KM_SLEEP);
        if (new_nvsfp == NULL)
            goto failed1;

        new_nvsfp->sp = sp;
        new_nvsfp->pid = ddi_get_pid();
        new_nvsfp->next = softc->minordevs;
        new_nvsfp->cloneminor = cloneminor;
        new_nvsfp->softc = softc;
        mutex_init(&new_nvsfp->event_lock, "event_lock", MUTEX_DRIVER, softc->iblock_cookie);
        softc->minordevs = new_nvsfp;

        *devp = makedevice(getmajor(*devp), cloneminor);

        mutex_exit(&softc->mutex);

        nv_lock_api(ctl_nv);
        nv_lock_api(nv);

        /*
         * XXX In addition to checking if the device's reference
         * count is zero, check if the control device is open.
         * This is needed to defer device initialization until the
         * X server opens the device, such that RM registry keys
         * can still be written in time.
         */
        if ((ctl_nv->flags & NV_FLAG_OPEN) == NV_FLAG_OPEN) {
            e = nv_open_increment(nv, sp);
            if (e != 0) {
                goto failed2;
            }
        } else {
            new_nvsfp->flags |= NV_CLONE_FLAG_IGNORE;
        }

        nv_unlock_api(nv);
        nv_unlock_api(ctl_nv);

        return (0);

failed2:
    nv_unlock_api(nv);
    nv_unlock_api(ctl_nv);

    mutex_enter(&softc->mutex);

    softc->minordevs = new_nvsfp->next;
    mutex_destroy(&new_nvsfp->event_lock);

failed1:
    mutex_exit(&softc->mutex);

    if (new_nvsfp != NULL) {
        memset((void *)new_nvsfp, 0xff, sizeof(nv_sunos_file_private_t));
        kmem_free(new_nvsfp, sizeof(nv_sunos_file_private_t));
    }

    if (sp != NULL)
        NV_KMEM_FREE_STACK(sp);

    if (softc->vgatext_softc != NULL)
        gfxp_vgatext_close(*devp, flag, otyp, cred, softc->vgatext_softc);

    return (e);
}

static int
nv_open_kernel(NvU32 gpu_id, nvidia_stack_t *sp)
{
        nv_state_t *nv = nv_find_state(gpu_id);
        struct nv_softc *softc;
        int status;

        if (nv == NULL) {
            return EINVAL;
        }

        nv_lock_api(nv);
        status = nv_open_increment(nv, sp);
        nv_unlock_api(nv);

        return status;
}

/*ARGSUSED*/
static  int
nv_close_ctl(dev_t dev, int flag, int otyp, cred_t *cred)
{
        minor_t unit = getminor(dev);
        nvidia_stack_t *sp = NULL;
        struct nv_softc *softc = &nvidia_ctl_sc;
        nv_state_t *nv = &nvidia_ctl_state;
        nv_sunos_file_private_t *nvsfp, *prev_nvsfp;
        nv_os_event_t *et = NULL;

        nv_printf(NV_DBG_INFO,
                  "NVRM: nv_close_ctl: unit = %d, flag = 0x%x, otyp = %d\n",
                  unit, flag, otyp);

        mutex_enter(&softc->mutex);

        for (nvsfp = softc->minordevs; nvsfp != NULL; nvsfp = nvsfp->next) {
                if (nvsfp->cloneminor == unit) {
                        break;
                }
        }

        mutex_exit(&softc->mutex);

        if (nvsfp == NULL) {
            nv_printf(NV_DBG_ERRORS,
                "NVRM: couldn't find minor device for unit %d\n", unit);
            return (ENXIO);
        }

        sp = nvsfp->sp;
        rm_cleanup_file_private(sp, nv, &nvsfp->nvfp);

        if (nvsfp->num_attached_gpus != 0)
        {
            size_t i;

            for (i = 0; i < nvsfp->num_attached_gpus; i++)
            {
                if (nvsfp->attached_gpus[i] != 0)
                    nv_close_kernel(nvsfp->attached_gpus[i], sp);
            }

            kmem_free(nvsfp->attached_gpus,
                      sizeof(NvU32) * nvsfp->num_attached_gpus);
            nvsfp->num_attached_gpus = 0;
        }

        nv_lock_api(nv);
        mutex_enter(&softc->mutex);

        /* since we dropped the lock, prev_nvsfp may have changed for this nvsfp */
        prev_nvsfp = NULL;
        for (nvsfp = softc->minordevs; nvsfp != NULL; nvsfp = nvsfp->next) {
                if (nvsfp->cloneminor == unit) {
                        break;
                } else {
                        prev_nvsfp = nvsfp;
                }
        }

        softc->refcnt--;

        if (softc->refcnt == 0) {
                /*
                 * The control device has been released; without physical devices
                * backing it, we only need to reset the flags.
                */
                nv->flags &= ~NV_FLAG_OPEN;
        }

        /* remove this minordev from the list of minordevs */
        if (prev_nvsfp == NULL) {
            softc->minordevs = nvsfp->next;
        } else {
            prev_nvsfp->next = nvsfp->next;
        }

        mutex_exit(&softc->mutex);
        nv_unlock_api(nv);

        while((et = nvsfp->event_queue) != NULL) {
            nvsfp->event_queue = et->next;
            kmem_free(et, sizeof(nv_os_event_t));
        }

        mutex_destroy(&nvsfp->event_lock);
        NV_KMEM_FREE_STACK(sp);

        memset((void *)nvsfp, 0xff, sizeof(nv_sunos_file_private_t));
        kmem_free(nvsfp, sizeof(nv_sunos_file_private_t));

        return (0);
}

void
nv_close_decrement(nv_state_t *nv, nvidia_stack_t *sp)
{
        struct nv_softc *softc = nv->os_state;

        softc->refcnt--;

        if (softc->refcnt == 0) {
            /*
             * The usage count for this device has dropped to zero, it can
             * be safely shut down. We don't need to wait for any pending
             * bottom-halfes like we do on Linux, they're run synchronously
             * on Solaris. We do need to reset the open flag, though.
             */
            rm_disable_adapter(sp, nv);
            rm_shutdown_adapter(sp, nv);

            nv->flags &= ~NV_FLAG_OPEN;

            //success, mark that power is now off
            softc->power_level[NV_PM_BOARD] = NV_BOARD_OFF;
        }
}

/*ARGSUSED*/
static  int
nv_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
        minor_t unit = getminor(dev);
        nvidia_stack_t *sp = NULL;
        struct nv_softc *softc;
        nv_state_t *nv;
        nv_sunos_file_private_t *nvsfp, *prev_nvsfp;
        nv_os_event_t *et = NULL;

        if (otyp != OTYP_CHR)
                return (EINVAL);

        if (NV_ISCTL(unit))
                return (nv_close_ctl(dev, flag, otyp, cred));

        nv_printf(NV_DBG_INFO,
                  "NVRM: nv_close: unit = %d, flag = 0%x, otyp = %d\n",
                  unit, flag, otyp);

        softc = getsoftc(unit);

        if (softc == NULL)
                return (ENXIO);

        nv = softc->nv_state;

        if (softc->vgatext_softc != NULL)
            gfxp_vgatext_close(dev, flag, otyp, cred, softc->vgatext_softc);

        mutex_enter(&softc->mutex);

        for (nvsfp = softc->minordevs; nvsfp != NULL; nvsfp = nvsfp->next) {
                if (nvsfp->cloneminor == unit) {
                        break;
                }
        }

        mutex_exit(&softc->mutex);

        if (nvsfp == NULL) {
            nv_printf(NV_DBG_ERRORS,
                "NVRM: couldn't find minor device for unit %d\n", unit);
            return (ENXIO);
        }

        sp = nvsfp->sp;

        rm_cleanup_file_private(sp, nv, &nvsfp->nvfp);

        nv_lock_api(nv);
        mutex_enter(&softc->mutex);

        /* since we dropped the lock, prev_nvsfp may have changed for this nvsfp */
        prev_nvsfp = NULL;
        for (nvsfp = softc->minordevs; nvsfp != NULL; nvsfp = nvsfp->next) {
                if (nvsfp->cloneminor == unit) {
                        break;
                } else {
                        prev_nvsfp = nvsfp;
                }
        }

        /*
         * XXX Don't update the reference count if this minor device
         * was allocated when the control device was still closed,
         * it didn't contribute to the current reference count. This
         * complements logic in nv_open().
         */
        if ((nvsfp->flags & NV_CLONE_FLAG_IGNORE) == 0) {
            nv_close_decrement(nv, sp);
        }

        /* remove this minordev from the list of minordevs */
        if (prev_nvsfp == NULL) {
            softc->minordevs = nvsfp->next;
        } else {
            prev_nvsfp->next = nvsfp->next;
        }

        mutex_exit(&softc->mutex);
        nv_unlock_api(nv);

        while((et = nvsfp->event_queue) != NULL) {
            nvsfp->event_queue = et->next;
            kmem_free(et, sizeof(nv_os_event_t));
        }

        mutex_destroy(&nvsfp->event_lock);
        NV_KMEM_FREE_STACK(sp);

        memset((void *)nvsfp, 0xff, sizeof(nv_sunos_file_private_t));
        kmem_free(nvsfp, sizeof(nv_sunos_file_private_t));

        return (0);
}

static void
nv_close_kernel(NvU32 gpu_id, nvidia_stack_t *sp)
{
        nv_state_t *nv = nv_find_state(gpu_id);
        struct nv_softc *softc;

        if (nv == NULL) {
            return;
        }

        nv_lock_api(nv);
        softc = nv->os_state;
        mutex_enter(&softc->mutex);

        nv_close_decrement(nv, sp);

        mutex_exit(&softc->mutex);
        nv_unlock_api(nv);
}


static  u_int
nv_intr(caddr_t arg)
{
        struct nv_softc *softc = (struct nv_softc *) arg;
        nvidia_stack_t *sp = softc->sp[NV_DEV_STACK_ISR];
        nv_state_t *nv;
        NvU32 run_bottom_half = 0;
        NvBool handled;
        NvU32 faultsCopied = 0;

        mutex_enter(&softc->mutex);

        /* if board is currently powered off, it cannot be our interrupt */
        if (!NV_BOARD_IS_ON_OR_RESUMING(softc)) {
            mutex_exit(&softc->mutex);
            return (DDI_INTR_UNCLAIMED);
        }

        mutex_exit(&softc->mutex);

        nv = softc->nv_state;

        handled = rm_isr(sp, nv, &run_bottom_half);

        if (run_bottom_half) {
                /*
                 * As UVM with faulting is currently not supported in this plateform, we can copy
                 * MMU faults after grabbing RM lock. With UVM, this routine should be called
                 * before calling rm_isr and bottom_half should be scheduled unconditionally
                 * with low priority thread as bottom_half can wait for lock
                 */
                rm_gpu_copy_mmu_faults(sp, nv, &faultsCopied);

                /* We're not executing in an HW ISR context */
                rm_isr_bh(sp, nv);
        }

        /*
         * keep kernel statistics on our interrupts
         */
        if (softc->intrstats && handled)
                KIOIP->intrs[KSTAT_INTR_HARD]++;

        return (handled ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

static  int
nv_ioctl_ctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred, int *rval)
{
        minor_t unit = getminor(dev);
        struct nv_softc *softc;
        void *data;
        void *arg_ptr = (void *)arg;
        int arg_cmd;
        nvidia_stack_t *sp = NULL;
        size_t arg_size;
        nv_state_t *nv;
        nv_sunos_file_private_t *nvsfp;
        int status = 0;
        nv_ioctl_xfer_t ioc_xfer;

        nv_printf(NV_DBG_INFO,
                "NVRM: nv_ioctl_ctl: unit = %d, cmd = 0x%x, arg = %p\n", unit, cmd, arg_ptr);

        nv = &nvidia_ctl_state;
        softc = nv->os_state;

        nvsfp = nv_file_private_from_minor(softc, unit);

        if (nvsfp == NULL)
                return (ESRCH);

        if (__NV_IOC_TYPE(cmd) != NV_IOCTL_MAGIC)
                return (ENOTTY);

        arg_cmd  = __NV_IOC_NR(cmd);
        arg_size = __NV_IOC_SIZE(cmd);

        if (arg_cmd == NV_ESC_IOCTL_XFER_CMD) {
            if (arg_size != sizeof(nv_ioctl_xfer_t))
                return (EINVAL);

            if (ddi_copyin(arg_ptr, (void *)&ioc_xfer,
                        sizeof(ioc_xfer), mode)) {
                nv_printf(NV_DBG_ERRORS,
                        "NVRM: nv_ioctl_ctl: failed to copyin ioctl XFER data\n");
                return (EFAULT);
            }

            arg_cmd  = ioc_xfer.cmd;
            arg_size = ioc_xfer.size;
            arg_ptr  = NvP64_VALUE(ioc_xfer.ptr);

            if (arg_size > NV_ABSOLUTE_MAX_IOCTL_SIZE) {
                nv_printf(NV_DBG_ERRORS,
                        "NVRM: nv_ioctl_ctl: invalid ioctl XFER size\n");
                return (EINVAL);
            }
        }

        if ((data = kmem_zalloc(arg_size, KM_SLEEP)) == NULL)
            return (ENOMEM);

        if (ddi_copyin(arg_ptr, data, arg_size, mode)) {
            kmem_free(data, arg_size);
            return (EFAULT);
        }

        nv_lock_api(nv);
        sp = nvsfp->sp;

        switch (arg_cmd) {
            case NV_ESC_CARD_INFO:
                status = nvidia_get_card_info(data, arg_size);
                break;

            case NV_ESC_CHECK_VERSION_STR:
                status = ((rm_perform_version_check(sp, data,
                                arg_size) == NV_OK) ? 0 : EINVAL);
                break;

            case NV_ESC_ATTACH_GPUS_TO_FD:
            {
                size_t num_arg_gpus = arg_size / sizeof(NvU32);
                size_t i;

                if ((nv->flags & NV_FLAG_CONTROL) == 0)
                {
                    status = EINVAL;
                    break;
                }


                if (num_arg_gpus == 0 || nvsfp->num_attached_gpus != 0 ||
                    arg_size % sizeof(NvU32) != 0)
                {
                    status = EINVAL;
                    break;
                }

                nvsfp->attached_gpus = kmem_zalloc(arg_size, KM_SLEEP);
                if (nvsfp->attached_gpus == NULL)
                {
                    status = ENOMEM;
                    break;
                }
                memcpy(nvsfp->attached_gpus, data, arg_size);
                nvsfp->num_attached_gpus = num_arg_gpus;

                status = 0;

                for (i = 0; i < nvsfp->num_attached_gpus; i++)
                {
                    if (nvsfp->attached_gpus[i] == 0)
                    {
                        continue;
                    }

                    if (nv_open_kernel(nvsfp->attached_gpus[i], sp))
                    {
                        while (i--)
                        {
                            if (nvsfp->attached_gpus[i] != 0)
                                nv_close_kernel(nvsfp->attached_gpus[i], sp);
                        }
                        kmem_free(nvsfp->attached_gpus, arg_size);
                        nvsfp->num_attached_gpus = 0;

                        status = EINVAL;
                        break;
                    }
                }

                break;
            }

            default:
                status = ((rm_ioctl(sp, nv, &nvsfp->nvfp, arg_cmd, data,
                                arg_size) == NV_OK) ? 0 : EINVAL);
                break;
        }

        nv_unlock_api(nv);

        if (ddi_copyout(data, arg_ptr, arg_size, mode))
            status = EFAULT;

        kmem_free(data, arg_size);

        return status;
}

#include <sys/kd.h>

static struct vis_identifier nv_text_ident = { "NVDAnvda" };

/*ARGSUSED*/
static  int
nv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred, int *rval)
{
        minor_t unit = getminor(dev);
        struct nv_softc *softc;
        void *data = NULL;
        void *arg_ptr = (void *)arg;
        int arg_cmd;
        nvidia_stack_t *sp = NULL;
        size_t arg_size;
        nv_state_t *nv;
        nv_sunos_file_private_t *nvsfp;
        int status = ENOTTY;
        nv_ioctl_xfer_t ioc_xfer;

        if (NV_ISCTL(unit))
            return (nv_ioctl_ctl(dev, cmd, arg, mode, cred, rval));

        nv_printf(NV_DBG_INFO,
                  "NVRM: nv_ioctl: unit = %d, cmd = 0x%x, arg = %p\n", unit, cmd, arg_ptr);

        softc = getsoftc(unit);

        if (softc == NULL)
                return (ENXIO);

        nvsfp = nv_file_private_from_minor(softc, unit);

        if (nvsfp == NULL)
                return (ESRCH);

        nv = softc->nv_state;

        arg_cmd  = __NV_IOC_NR(cmd);
        arg_size = (cmd == VIS_GETIDENTIFIER)
            ? sizeof(struct vis_identifier) : __NV_IOC_SIZE(cmd);

        if ((cmd == VIS_GETIDENTIFIER) ||
                ((__NV_IOC_TYPE(cmd) == NV_IOCTL_MAGIC) &&
                 (__NV_IOC_SIZE(cmd) != 0))) {
            if ((arg_cmd == NV_ESC_IOCTL_XFER_CMD) &&
                    (__NV_IOC_TYPE(cmd) == NV_IOCTL_MAGIC)) {
                if (arg_size != sizeof(nv_ioctl_xfer_t))
                    return (EINVAL);

                if (ddi_copyin(arg_ptr, (void *)&ioc_xfer,
                            sizeof(ioc_xfer), mode)) {
                    nv_printf(NV_DBG_ERRORS,
                            "NVRM: nv_ioctl: failed to copyin ioctl XFER data\n");
                    return (EFAULT);
                }

                arg_cmd  = ioc_xfer.cmd;
                arg_size = ioc_xfer.size;
                arg_ptr  = NvP64_VALUE(ioc_xfer.ptr);

                if (arg_size > NV_ABSOLUTE_MAX_IOCTL_SIZE) {
                    nv_printf(NV_DBG_ERRORS,
                            "NVRM: nv_ioctl: invalid ioctl XFER size\n");
                    return (EINVAL);
                }
            }

            // both calls need scratch space
            if ((data = kmem_zalloc(arg_size, KM_SLEEP)) == NULL)
                return (ENOMEM);

            // only RM needs to know what was passed to it
            if (cmd != VIS_GETIDENTIFIER) {
                if (ddi_copyin(arg_ptr, data, arg_size, mode)) {
                    kmem_free(data, arg_size);
                    return (EFAULT);
                }
             }
        }

        nv_lock_api(nv);
        sp = nvsfp->sp;

        if ((__NV_IOC_TYPE(cmd) == NV_IOCTL_MAGIC) &&
                (__NV_IOC_SIZE(cmd) != 0)) {
            status = ((rm_ioctl(sp, nv, &nvsfp->nvfp, arg_cmd,
                            data, arg_size) == NV_OK) ? 0 : EINVAL);
        } else {
            switch (cmd) {
                case VIS_INIT_DDCCI:
                case VIS_I2C_CAPS:
                case VIS_READ_DDCCI:
                case VIS_WRITE_DDCCI:
                case VIS_I2C_CMDS:
                    status = nv_i2c_ioctl(sp, nv, cmd, arg_ptr, mode, cred);
                    break;

                case KDSETMODE:
                case KDGETMODE:
                case VIS_DEVINIT:
                case VIS_CONSCOPY:
                case VIS_CONSDISPLAY:
                case VIS_CONSCLEAR:
                case VIS_CONSCURSOR:
                case VIS_GETCMAP:
                case VIS_PUTCMAP:
                case FBIOPUTCMAP:
                case FBIOGETCMAP:
                case FBIOGATTR:
                case FBIOGTYPE:
                case FBIOLOADHNDL:
                    if (softc->vgatext_softc != NULL) {
                        status = gfxp_vgatext_ioctl(dev, cmd, arg, mode, cred,
                                        rval, softc->vgatext_softc);
                    }
                    break;

                case VIS_GETIDENTIFIER:
                    memcpy(data, &nv_text_ident, arg_size);
                    status = 0;
                    break;
            }
        }

        if (data) {
            if (ddi_copyout(data, arg_ptr, arg_size, mode))
                status = EFAULT;
            kmem_free(data, arg_size);
        }

        nv_unlock_api(nv);

        return status;
}

static int nv_devmap(
    dev_t dev,
    devmap_cookie_t handle,
    offset_t off,
    size_t len,
    size_t *maplen,
    uint_t model
)
{
    minor_t unit = getminor(dev);
    nvidia_stack_t *sp;
    nvidia_alloc_t *at;
    struct nv_softc *softc;
    nv_state_t *nv;
    nv_sunos_file_private_t *nvsfp;
    NV_STATUS rmStatus;
    uint64_t uoff = (ulong_t)off;
    int error = EINVAL;
    uint_t maxprot = (PROT_ALL & ~PROT_EXEC);
    NvU64 pageIndex;
    NvU32 prot;
    nv_alloc_mapping_context_t *mmap_context;

    if (NV_ISCTL(unit)) {
        nv = &nvidia_ctl_state;
        softc = nv->os_state;
    } else {
        softc = getsoftc(unit);
        nv = softc->nv_state;
    }

    nvsfp = nv_file_private_from_minor(softc, unit);
    if (!nvsfp)
        return (ESRCH);

    //
    // Do not allow mmap operation if this is an fd on
    // which rm objects have been exported.
    //
    if (nvsfp->nvfp.handles != NULL)
    {
        return EINVAL;
    }

    sp = nvsfp->sp;

    nv_lock_api(nv);

    mmap_context = &nvsfp->mmap_context;

    /*
     * If mmap context is not valid on this file descriptor, this mapping wasn't
     * previously validated with the RM so it must be rejected.
     */
    if (!mmap_context->valid)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: VM: invalid mmap\n");
        return (EINVAL);
    }

    prot = mmap_context->prot;

    if (!NV_ISCTL(unit)) {
        if ((prot & NV_PROTECT_WRITEABLE) == 0)
            maxprot &= ~PROT_WRITE;

        if (IS_UD_OFFSET(nv, uoff, len)) {
            error = devmap_devmem_setup(handle, softc->devi, NULL, REGNUM_FB,
                    (uoff - nv->fb->cpu_address), len, maxprot,
                    DEVMAP_DEFAULTS, &UC_attr);
        } else if (IS_FB_OFFSET(nv, uoff, len)) {
            error = devmap_devmem_setup(handle, softc->devi, NULL, REGNUM_FB,
                    (uoff - nv->fb->cpu_address), len, maxprot,
                    DEVMAP_DEFAULTS, &WC_attr);
        } else if (IS_REG_OFFSET(nv, uoff, len)) {
            error = devmap_devmem_setup(handle, softc->devi, NULL, REGNUM_REGS,
                    (uoff - nv->regs->cpu_address), len, maxprot,
                    DEVMAP_DEFAULTS, &UC_attr);
        } else
            goto done;

        if (error != 0) {
            nv_printf(NV_DBG_ERRORS,
                "NVRM: nv_devmap: devmap_devmem_setup() failed (%d)\n", error);
        }
    } else {
        rmStatus = rm_acquire_api_lock(sp);
        if (rmStatus != NV_OK)
            goto done;

        at = (nvidia_alloc_t*)mmap_context->alloc;
        pageIndex = mmap_context->page_index;

        if ((prot & NV_PROTECT_WRITEABLE) == 0)
            maxprot &= ~PROT_WRITE;

        error = gfxp_devmap_umem_setup(handle, softc->devi, NULL,
                (ddi_umem_cookie_t)at->umem_cookie, (pageIndex * PAGESIZE),
                len, maxprot, DEVMAP_DEFAULTS, at->attr);

        rm_release_api_lock(sp);
    }

    /* acknowledge the entire range */
    *maplen = len;

done:
    nv_unlock_api(nv);

    return (error);
}

static int
nv_segmap(dev_t dev,
          off_t off,
          struct as *as,
          caddr_t *addrp,
          off_t len,
          u_int prot,
          u_int maxprot,
          u_int flags,
          cred_t *cred
)
{
    int error;
    minor_t unit = getminor(dev);
    struct nv_softc *softc;
    nv_sunos_file_private_t *nvsfp;

    nv_alloc_mapping_context_t *mmap_context;

    if (NV_ISCTL(unit)) {
        softc = nvidia_ctl_state.os_state;
    } else {
        softc = getsoftc(unit);
    }

    nvsfp = nv_file_private_from_minor(softc, unit);
    if (!nvsfp)
        return (ESRCH);

    //
    // Do not allow mmap operation if this is an fd on
    // which rm objects have been exported.
    //
    if (nvsfp->nvfp.handles != NULL)
    {
        return EINVAL;
    }

    mmap_context = &nvsfp->mmap_context;
    if (!mmap_context)
        return (EINVAL);

    /*
     * If mmap context is not valid on this file descriptor, this mapping wasn't
     * previously validated with the RM so it must be rejected.
     */
    if (!mmap_context->valid)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: VM: invalid mmap\n");
        return (EINVAL);
    }

    off = mmap_context->mmap_start;
    len = mmap_context->mmap_size;

    error = ddi_devmap_segmap(dev, off, as, addrp, len, prot, maxprot,
                              flags, cred);
    if (error != 0) {
        nv_printf(NV_DBG_ERRORS,
            "NVRM: nv_segmap: ddi_devmap_segmap() failed (%d)\n", error);
    }

    return (error);
}

static int
nv_power(dev_info_t *devi, int component, int level)
{
    int ddi_status = (DDI_FAILURE);
    int unit = ddi_get_instance(devi);

    nv_printf(NV_DBG_INFO, "NVRM: nv_power: devi = %p, unit = %d, component = %d, level = %d\n", devi, unit, component, level);

    switch(component)
    {
        case NV_PM_BOARD:
            /*
             * Mapping is as follows:
             * 0 - Device is off. Not supported by board device.
             * 1 - Device is suspended. Supported by board device, but not selectable via nv_power()
             *     See nv_attach()/nv_detach() for suspend and resume.
             * 2 - Device is in standby. Can be posted to VGA mode, or can be unposted. As long as
             *     we have attached, we should be in standby at minimum. nv_power() cannot move
             *     device to standby mode.
             * 3 - Device is on. Device has been opened and initialized by the RM.
             *
             * Only states 0 and 3 are exported to the pm-components framework.
             */

            if (level == NV_BOARD_ON) {
                /*
                 * system can only request that board go on. Never off.
                 * If the OS thinks we are off, the PM framework will block
                 * open calls to the RM, insuring RM will never do anything
                 * to get the power on.
                 */
                ddi_status = (DDI_SUCCESS);
            } else {
                /* Never off. */
                ddi_status = (DDI_FAILURE);
            }

            break;

        case NV_PM_MONITOR:

            if (level == NV_DPMS_NORMAL)
            {
                ddi_status = (DDI_SUCCESS);
            } else {
                ddi_status = (DDI_FAILURE);
            }

            break;

        default:
            /* unrecognized component */
            nv_printf(NV_DBG_WARNINGS, "NVRM: nv_power: Unrecognized component %d requested for nv_power() transition control\n", component);
    };

    return ddi_status;
}

void NV_API_CALL nv_set_dma_address_size(
    nv_state_t  *nv,
    NvU32       phys_addr_bits
)
{
    struct nv_softc *softc = nv->os_state;
#if NVCPU_IS_X86_64
    softc->dma_mask = (((uint64_t)1) << phys_addr_bits) - 1;
#else
    softc->dma_mask = 0xffffffffULL;
#endif
}

static int nv_poll(
    dev_t  dev,
    short  events,
    int    anyyet,
    short *reventsp,
    struct pollhead **phpp
)
{
    int unit = getminor(dev);
    struct nv_softc *softc;
    nv_sunos_file_private_t *nvsfp;
    short revent = 0;

    if (NV_ISCTL(unit))
        softc = nvidia_ctl_state.os_state;
    else
        softc = getsoftc(unit);
    if (softc == NULL)
        return (ENXIO);

    nvsfp = nv_file_private_from_minor(softc, unit);
    if (nvsfp == NULL)
        return (ESRCH);

    mutex_enter(&nvsfp->event_lock);

    if ((nvsfp->event_queue != NULL) || nvsfp->event_pending) {
        revent = (events & (POLLIN | POLLPRI | POLLRDNORM));
        nvsfp->event_pending = NV_FALSE;
    }

    if ((revent == 0) && !anyyet)
        *phpp = &nvsfp->event_pollhead;

    *reventsp = revent;

    mutex_exit(&nvsfp->event_lock);

    return (0);
}

/*
 * Undocumented DDI hook for resetting the board.
 * In this case just mask the interrupt.
 */
/*ARGSUSED*/
static int
nv_reset(dev_info_t *devi, ddi_reset_cmd_t cmd)
{
    int unit = ddi_get_instance(devi);
    struct nv_softc *softc = ddi_get_soft_state(nv_softc_head, unit);

    if (softc == NULL)
        return (DDI_FAILURE);

    /* cmd is always DDI_RESET_FORCE (0) */
    NV_DISABLE_INTR(softc->registers);

    return (DDI_SUCCESS);
}

NV_STATUS NV_API_CALL nv_acpi_method(
    NvU32 acpi_method,
    NvU32 function,
    NvU32 subFunction,
    void  *inParams,
    NvU16 inParamSize,
    NvU32 *outStatus,
    void  *outData,
    NvU16 *outDataSize
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_dsm_method(
    nv_state_t *nv,
    NvU8  *pAcpiDsmGuid,
    NvU32 acpiDsmRev,
    NvBool acpiNvpcfDsmFunction,
    NvU32 acpiDsmSubFunction,
    void  *inParams,
    NvU16 inParamSize,
    NvU32 *outStatus,
    void  *outData,
    NvU16 *outDataSize
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_ddc_method(
    nv_state_t *nv,
    void *pEdidBuffer,
    NvU32 *pSize,
    NvBool bReadMultiBlock
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_dod_method(
    nv_state_t *nv,
    NvU32      *pOutData,
    NvU32      *pSize
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_rom_method(
    nv_state_t *nv,
    NvU32 *pInData,
    NvU32 *pOutData
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_get_powersource(NvU32 *ac_plugged)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_acpi_methods_init(NvU32 *handlesPresent)
{
    *handlesPresent = 0;
}

void NV_API_CALL nv_acpi_methods_uninit(void)
{
    return;
}

NvBool NV_API_CALL nv_acpi_is_battery_present(void)
{
    return NV_FALSE;
}

static const nvidia_modeset_callbacks_t *nv_modeset_callbacks;

static int nvidia_modeset_rm_ops_alloc_stack(nvidia_stack_t **sp)
{
    NV_KMEM_ALLOC_STACK(*sp);
    return (*sp == NULL) ? ENOMEM : 0;
}

static void nvidia_modeset_rm_ops_free_stack(nvidia_stack_t *sp)
{
    NV_KMEM_FREE_STACK(sp);
}

static int nvidia_modeset_set_callbacks(const nvidia_modeset_callbacks_t *cb)
{
    if ((nv_modeset_callbacks != NULL && cb != NULL) ||
        (nv_modeset_callbacks == NULL && cb == NULL))
    {
        return -EINVAL;
    }

    nv_modeset_callbacks = cb;
    return 0;
}

static void nvidia_modeset_suspend(NvU32 gpuId)
{
    if (nv_modeset_callbacks)
    {
        nv_modeset_callbacks->suspend(gpuId);
    }
}

static void nvidia_modeset_resume(NvU32 gpuId)
{
    if (nv_modeset_callbacks)
    {
        nv_modeset_callbacks->resume(gpuId);
    }
}

NV_STATUS nvidia_get_rm_ops(nvidia_modeset_rm_ops_t *rm_ops)
{
    const nvidia_modeset_rm_ops_t local_rm_ops = {
        .version_string = NV_VERSION_STRING,
        .system_info    = {
            .allow_write_combining = NV_FALSE,
        },
        .alloc_stack    = nvidia_modeset_rm_ops_alloc_stack,
        .free_stack     = nvidia_modeset_rm_ops_free_stack,
        .enumerate_gpus = NULL,
        .open_gpu       = nv_open_kernel,
        .close_gpu      = nv_close_kernel,
        .op             = rm_kernel_rmapi_op, /* provided by nv-kernel.o */
        .set_callbacks  = nvidia_modeset_set_callbacks,
    };

    if (strcmp(rm_ops->version_string, NV_VERSION_STRING) != 0)
    {
        rm_ops->version_string = NV_VERSION_STRING;
        return NV_ERR_GENERIC;
    }

    *rm_ops = local_rm_ops;

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_get_device_memory_config(
    nv_state_t *nv,
    NvU64 *pAddrSysPhys,
    NvU64 *pAddrGuestPhys,
    NvU32 *pAddrWidth,
    NvU32 *pGranularity,
    NvS32 *pNodeId
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_acpi_mux_method(
    nv_state_t *nv,
    NvU32 *pInOut,
    NvU32 muxAcpiId,
    const char *pMethodName
)
{
    return NV_ERR_NOT_SUPPORTED;
}
