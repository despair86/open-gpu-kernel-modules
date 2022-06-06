/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2022 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-solaris.h"
#include "nv-caps.h"

nv_cap_t *nvidia_caps_root = NULL;

const NvBool nv_is_rm_firmware_supported_os = NV_FALSE;

int nvidia_get_card_info(void *args, int size)
{
    struct nv_ioctl_card_info *ci;
    unsigned int i;
    struct nv_softc *sc;
    nv_state_t *nv;

    if (size < (sizeof(*ci) * NV_MAX_DEVICES))
        return EINVAL;

    ci = args;
    memset(ci, 0, sizeof(ci));

    for (i = 0; i < NV_MAX_DEVICES; i++) {
        sc = ddi_get_soft_state(nv_softc_head, i);
        if (!sc)
            continue;
        nv = sc->nv_state;

        ci[i].valid              = NV_TRUE;
        ci[i].pci_info.domain    = nv->pci_info.domain;
        ci[i].pci_info.bus       = nv->pci_info.bus;
        ci[i].pci_info.slot      = nv->pci_info.slot;
        ci[i].pci_info.vendor_id = nv->pci_info.vendor_id;
        ci[i].pci_info.device_id = nv->pci_info.device_id;
        ci[i].gpu_id             = nv->gpu_id;
        ci[i].interrupt_line     = nv->interrupt_line;
        ci[i].fb_address         = nv->fb->cpu_address;
        ci[i].fb_size            = nv->fb->size;
        ci[i].reg_address        = nv->regs->cpu_address;
        ci[i].reg_size           = nv->regs->size;
        ci[i].minor_number       = i;
    }

    return 0;
}


int nv_try_lock_api(nv_state_t *nv)
{
    struct nv_softc *sc = nv->os_state;
    return mutex_tryenter(&sc->api_lock);
}

void nv_lock_api(nv_state_t *nv)
{
    struct nv_softc *sc = nv->os_state;
    mutex_enter(&sc->api_lock);
}

void nv_unlock_api(nv_state_t *nv)
{
    struct nv_softc *sc = nv->os_state;
    mutex_exit(&sc->api_lock);
}

void NV_API_CALL nv_post_event(
    nv_event_t *event,
    NvHandle    hObject,
    NvU32       index,
    NvU32       info32,
    NvU16       info16,
    NvBool      data_valid
)
{
    nv_sunos_file_private_t *nvsfp = nv_get_nvsfp_from_nvfp(event->nvfp);
    nv_os_event_t *et;

    mutex_enter(&nvsfp->event_lock);

    if (data_valid) {
        et = kmem_zalloc(sizeof(nv_os_event_t), KM_NOSLEEP);
        if (et == NULL) {
            mutex_exit(&nvsfp->event_lock);
            return;
        }

        et->event = *event;
        et->event.hObject = hObject;
        et->event.index = index;
        et->event.info32 = info32;
        et->event.info16 = info16;

        if (nvsfp->event_queue == NULL)
            nvsfp->event_queue = et;
        else {
            nv_os_event_t *p = nvsfp->event_queue;
            while ((p->next) != NULL)
                p = p->next;
            p->next = et;
        }
        et->next = NULL;
    }

    nvsfp->event_pending = NV_TRUE;
    mutex_exit(&nvsfp->event_lock);

    pollwakeup(&nvsfp->event_pollhead, (POLLIN | POLLPRI | POLLRDNORM));
}

NvS32 NV_API_CALL nv_get_event(
    nv_file_private_t *nvfp,
    nv_event_t *event,
    NvU32      *pending
)
{
    nv_sunos_file_private_t *nvsfp = nv_get_nvsfp_from_nvfp(nvfp);
    nv_os_event_t *et;

    mutex_enter(&nvsfp->event_lock);

    et = nvsfp->event_queue;
    if (et == NULL) {
        mutex_exit(&nvsfp->event_lock);
        return -1;
     }

    *event = et->event;

    nvsfp->event_queue = et->next;

    *pending = (nvsfp->event_queue != NULL);

    mutex_exit(&nvsfp->event_lock);

    kmem_free(et, sizeof(nv_os_event_t));

    return NV_OK;
}

void
nv_insert_alloc(nv_state_t *nv, nvidia_alloc_t *at)
{
        struct nv_softc *softc;

        if (nv)
            softc = nv->os_state;
        else
            softc = &nvidia_ctl_sc;

        mutex_enter(&softc->alloc_list_lock);
        /* add to head of list */
        if (softc->alloc_list)
                softc->alloc_list->back = at;
        at->forw = softc->alloc_list;
        at->back = NULL;
        softc->alloc_list = at;
        mutex_exit(&softc->alloc_list_lock);
}

void
nv_remove_alloc(nv_state_t *nv, nvidia_alloc_t *at)
{
        struct nv_softc *softc;

        if (nv)
            softc = nv->os_state;
        else
            softc = &nvidia_ctl_sc;

        mutex_enter(&softc->alloc_list_lock);
        if (at->forw)
                at->forw->back = at->back;
        if (at->back)
                at->back->forw = at->forw;
        /* TODO: should we panic if list ptr is NULL? */
        if (softc->alloc_list == at)
                softc->alloc_list = at->forw;
        mutex_exit(&softc->alloc_list_lock);
}

void* NV_API_CALL nv_alloc_kernel_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    NvU64       pageIndex,
    NvU32       pageOffset,
    NvU64       size,
    void      **ppPrivate
)
{
    nvidia_alloc_t *at = pAllocPrivate;
    uintptr_t linear;

    linear = (uintptr_t)at->kva;
    return (void *)(uintptr_t)(linear + (pageIndex * PAGESIZE) + pageOffset);
}

NV_STATUS NV_API_CALL nv_free_kernel_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    void       *address,
    void       *pPrivate
)
{
    return NV_OK;
}

/*************************************************************************
 *
 * Find offsetof(file_t, f_vnode) for the running kernel.
 *
 * The offset of the f_vnode field within file_t differs by kernel
 * version.  This code is compiled once and used across different
 * Solaris kernel versions, so we cannot rely on a single compile-time
 * definition of file_t.
 *
 * Instead, compute the offset at run-time through the following
 * atrocity:
 *
 * - Allocate a temporary dummy vnode_t.
 * - Call falloc() to allocate a temporary new file_t for the dummy vnode_t.
 * - falloc() assigns the file_t::f_vnode field with the provided
 *   vnode_t pointer.
 * - Scan through the falloc()-returned file_t memory for the provided
 *   vnode_t pointer.
 * - Free both the temporary file_t and vnode_t.
 *
 *************************************************************************/

static size_t nv_vnode_offset_within_file_t = 0;

NvBool find_vnode_offset_within_file_t(void)
{
    unsigned char *ptr;
    uintptr_t vnodeaddr;
    file_t *file = NULL;
    int status;
    size_t offset;
    vnode_t *vnode;
    NvBool ret = NV_FALSE;

    vnode = vn_alloc(KM_SLEEP);
    if (vnode == NULL) {
        return NV_FALSE;
    }

    vnodeaddr = (uintptr_t) vnode;
    status = falloc(vnode, 0 /* flag */, &file, NULL /* &fd */);
    if (status != 0) {
        goto done;
    }

    ptr = (unsigned char *) file;

    /*
     * On all known kernels, offsetof(file_t, f_vnode) is within the
     * first 64 bytes.
     */
    for (offset = 0; offset < 64; offset++) {
        if (memcmp(ptr + offset, &vnodeaddr, sizeof(vnodeaddr)) == 0) {
            nv_vnode_offset_within_file_t = offset;
            ret = NV_TRUE;
            break;
        }
    }

    unfalloc(file);

done:
    vn_free(vnode);

    return ret;
}

nv_file_private_t* NV_API_CALL nv_get_file_private(
    NvS32     fd,
    NvBool    ctl,
    void    **os_private
)
{
    nv_sunos_file_private_t* nvsfp = NULL;
    unsigned char *ptr = (unsigned char *) getf(fd);
    struct vnode *vnode;
    minor_t minor;
    struct nv_softc *softc;

    if (ptr == NULL)
        return NULL;

    vnode = *(struct vnode **) (ptr + nv_vnode_offset_within_file_t);
    if (getmajor(vnode->v_rdev) != nv_major_device_number)
        goto fail;

    minor = getminor(vnode->v_rdev);
    if (!!NV_ISCTL(minor) != !!ctl)
        goto fail;

    if (ctl)
        softc = &nvidia_ctl_sc;
    else
        softc = getsoftc(minor);

    if (!softc)
        goto fail;

    nvsfp = nv_file_private_from_minor(softc, minor);
    if (nvsfp == NULL)
        goto fail;

    *os_private = (void *)(intptr_t)fd;

    return &nvsfp->nvfp;

fail:
    releasef(fd);
    *os_private = (void *)(intptr_t)-1;
    return NULL;
}

void NV_API_CALL nv_put_file_private(
    void *os_private
)
{
    int fd = (int)(intptr_t)os_private;
    if (fd >= 0)
        releasef(fd);
}

NV_STATUS NV_API_CALL nv_add_mapping_context_to_file(
    nv_state_t *nv,
    nv_usermap_access_params_t *nvuap,
    NvU32       prot,
    void       *pAllocPriv,
    NvU64       pageIndex,
    NvU32       fd
)
{
    nv_alloc_mapping_context_t *nvamc = NULL;
    nv_file_private_t *nvfp = NULL;
    nv_sunos_file_private_t *nvsfp = NULL;
    NV_STATUS status = NV_OK;
    void *priv;

    /* Get the nvidia private file data from file descriptor */
    nvfp = nv_get_file_private(fd, NV_IS_CTL_DEVICE(nv), &priv);
    if (!nvfp)
        return NV_ERR_INVALID_ARGUMENT;

    nvsfp = nv_get_nvsfp_from_nvfp(nvfp);

    nvamc = &nvsfp->mmap_context;

    if (nvamc->valid)
    {
        status = NV_ERR_STATE_IN_USE;
        goto done;
    }

    nvamc->alloc = pAllocPriv;
    nvamc->page_index = pageIndex;

    nvamc->mmap_start = nvuap->mmap_start;
    nvamc->mmap_size = nvuap->mmap_size;
    nvamc->access_start = nvuap->access_start;
    nvamc->access_size = nvuap->access_size;
    nvamc->remap_prot_extra = nvuap->remap_prot_extra;

    nvamc->prot = prot;
    nvamc->valid = NV_TRUE;

done:
    nv_put_file_private(priv);

    return status;
}

NV_STATUS NV_API_CALL nv_alloc_user_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    NvU64       pageIndex,
    NvU32       pageOffset,
    NvU64       size,
    NvU32       protect,
    NvU64      *pUserAddress,
    void      **ppPrivate
)
{
    nvidia_alloc_t *at = pAllocPrivate;
    ulong_t linear;
    uint64_t pa;

    linear = ((uintptr_t)at->kva + (pageIndex * PAGESIZE));
    gfxp_va2pa(&kas, (caddr_t)linear, &pa);

    *pUserAddress = (pa + pageOffset);

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_free_user_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    NvU64       userAddress,
    void       *pPrivate
)
{
    return NV_OK;
}

static struct ddi_device_acc_attr WB_attr = {
        DDI_DEVICE_ATTR_V0,
        DDI_NEVERSWAP_ACC,
        DDI_UNORDERED_OK_ACC
};

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

/*
 * Really ugly hack for S10.  The KVA returned from ddi_dma_mem_alloc()
 * always has WB/cached PTEs.  This causes severe coherency problems
 * when the pages are exported to user space with uncached/UC/WC PTEs.
 * Use hat_devload to change the cache attributes for each page.
 */
void
nv_fix_ddi_dma_mem_cache_attrs(nvidia_alloc_t *at)
{
    caddr_t kva = (caddr_t)at->kva;
    int cache_attr;

    if (at->attr == &UC_attr) {
        cache_attr = GFXP_MEMORY_UNCACHED;
    } else if (at->attr == &WC_attr) {
        cache_attr = GFXP_MEMORY_WRITECOMBINED;
    } else
        return;

    gfxp_fix_mem_cache_attrs(kva, at->real_length, cache_attr);
}

NvS32
nv_alloc_contig_pages(
    nv_state_t *nv,
    NvU32       count,
    NvU32       cache_type,
    NvBool      zero,
    NvU64      *pte_array,
    void      **private
)
{
        int num_bytes = ptob(count);
        nvidia_alloc_t *at;
        struct nv_softc *softc;
        ddi_dma_attr_t dma_attr;
        int rc;

        if (nv)
            softc = nv->os_state;
        else
            softc = &nvidia_ctl_sc;

        if ((at = kmem_zalloc(sizeof(nvidia_alloc_t), KM_SLEEP)) == NULL)
                return -ENOMEM;

        switch (cache_type) {
            case NV_MEMORY_CACHED:
                at->attr = &WB_attr; /* WB (Write Back) */
                break;
            case NV_MEMORY_UNCACHED:
                at->attr = &UC_attr; /* UC (Uncacheable) */
                break;
            case NV_MEMORY_WRITECOMBINED:
                at->attr = &WC_attr; /* WC (Write Combined) */
                break;
            default:
                kmem_free(at, sizeof(nvidia_alloc_t));
                return -ENOMEM;
        }

        if (nv) {
            dma_attr.dma_attr_version = DMA_ATTR_V0;
            dma_attr.dma_attr_addr_lo = 0;
            dma_attr.dma_attr_addr_hi = (unsigned long long)softc->dma_mask;
            dma_attr.dma_attr_count_max = 0xffffffffULL;
            dma_attr.dma_attr_align = PAGESIZE;
            dma_attr.dma_attr_burstsizes = (DEFAULT_BURSTSIZE | BURST32 | BURST64 | BURST128);
            dma_attr.dma_attr_minxfer = 1;
            dma_attr.dma_attr_maxxfer = 0xffffffffULL;
            dma_attr.dma_attr_seg = 0xffffffffULL;
            dma_attr.dma_attr_sgllen = 1;
            dma_attr.dma_attr_granular = 512;
            dma_attr.dma_attr_flags = 0;

            if (ddi_dma_alloc_handle(softc->devi, &dma_attr, DDI_DMA_SLEEP,
                NULL, &at->dma_handle) != DDI_SUCCESS) {
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

            if (gfxp_ddi_dma_mem_alloc(at->dma_handle, num_bytes, at->attr,
                DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &at->kva,
                &at->real_length, &at->dma_data_handle) != DDI_SUCCESS) {
                    ddi_dma_free_handle(&at->dma_handle);
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

            if (zero)
                memset(at->kva, 0, at->real_length);

            nv_fix_ddi_dma_mem_cache_attrs(at);

            if ((rc = ddi_dma_addr_bind_handle(at->dma_handle, NULL, at->kva,
                at->real_length, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
                NULL, &at->cookie, &at->cookie_count)) != DDI_DMA_MAPPED) {
                    ddi_dma_mem_free(&at->dma_data_handle);
                    ddi_dma_free_handle(&at->dma_handle);
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

            at->umem_cookie = gfxp_umem_cookie_init(at->kva, num_bytes);
            if (at->umem_cookie == NULL) {
                    ddi_dma_unbind_handle(at->dma_handle);
                    ddi_dma_mem_free(&at->dma_data_handle);
                    ddi_dma_free_handle(&at->dma_handle);
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

        } else {
            at->kva = ddi_umem_alloc(num_bytes,
                                     DDI_UMEM_SLEEP,
                                     (void**)&at->umem_cookie);
            if (at->kva == NULL) {
                kmem_free(at, sizeof(nvidia_alloc_t));
                return (-ENOMEM);
            }

            if (zero)
                memset(at->kva, 0, at->real_length);
        }

        at->alloc_type_contiguous = 1;

        at->size = num_bytes;
        pte_array[0] = nv_get_kern_phys_address((NvUPtr)at->kva);
        at->pte_array = pte_array;

        *private = at;
        nv_insert_alloc(nv, at);

        return (0);
}


NvS32
nv_alloc_system_pages(
    nv_state_t *nv,
    NvU32       count,
    NvU32       cache_type,
    NvBool      zero,
    NvU64      *pte_array,
    void      **private
)
{
        unsigned int i;
        int num_bytes = ptob(count);
        nvidia_alloc_t *at;
        struct nv_softc *softc;
        ddi_dma_attr_t dma_attr;
        int rc;

        if (nv)
            softc = nv->os_state;
        else
            softc = &nvidia_ctl_sc;

        if ((at = kmem_zalloc(sizeof(nvidia_alloc_t), KM_SLEEP)) == NULL)
                return -ENOMEM;

        switch (cache_type) {
            case NV_MEMORY_CACHED:
                at->attr = &WB_attr; /* WB (Write Back) */
                break;
            case NV_MEMORY_UNCACHED:
                at->attr = &UC_attr; /* UC (Uncacheable) */
                break;
            case NV_MEMORY_WRITECOMBINED:
                at->attr = &WC_attr; /* WC (Write Combined) */
                break;
            default:
                kmem_free(at, sizeof(nvidia_alloc_t));
                return -ENOMEM;
        }

        if (nv) {
            dma_attr.dma_attr_version = DMA_ATTR_V0;
            dma_attr.dma_attr_addr_lo = 0;
            dma_attr.dma_attr_addr_hi = (unsigned long long)softc->dma_mask;
            dma_attr.dma_attr_count_max = 0xffffffffULL;
            dma_attr.dma_attr_align = PAGESIZE;
            dma_attr.dma_attr_burstsizes = (DEFAULT_BURSTSIZE | BURST32 | BURST64 | BURST128);
            dma_attr.dma_attr_minxfer = 1;
            dma_attr.dma_attr_maxxfer = 0xffffffffULL;
            dma_attr.dma_attr_seg = 0xffffffffULL;
            dma_attr.dma_attr_sgllen = count;
            dma_attr.dma_attr_granular = 512;
            dma_attr.dma_attr_flags = 0;

            if (ddi_dma_alloc_handle(softc->devi, &dma_attr, DDI_DMA_SLEEP,
                NULL, &at->dma_handle) != DDI_SUCCESS) {
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

            if (gfxp_ddi_dma_mem_alloc(at->dma_handle, num_bytes, at->attr,
                DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &at->kva,
                &at->real_length, &at->dma_data_handle) != DDI_SUCCESS) {
                    ddi_dma_free_handle(&at->dma_handle);
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

            if (zero)
                memset(at->kva, 0, at->real_length);

            nv_fix_ddi_dma_mem_cache_attrs(at);

            if ((rc = ddi_dma_addr_bind_handle(at->dma_handle, NULL, at->kva,
                at->real_length, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
                NULL, &at->cookie, &at->cookie_count)) != DDI_DMA_MAPPED) {
                    ddi_dma_mem_free(&at->dma_data_handle);
                    ddi_dma_free_handle(&at->dma_handle);
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

            at->umem_cookie = gfxp_umem_cookie_init(at->kva, num_bytes);
            if (at->umem_cookie == NULL) {
                    ddi_dma_unbind_handle(at->dma_handle);
                    ddi_dma_mem_free(&at->dma_data_handle);
                    ddi_dma_free_handle(&at->dma_handle);
                    kmem_free(at, sizeof(nvidia_alloc_t));
                    return (-ENOMEM);
            }

        } else {
            at->kva = ddi_umem_alloc(num_bytes,
                                     DDI_UMEM_SLEEP | DDI_UMEM_PAGEABLE,
                                     (void**)&at->umem_cookie);
            if (at->kva == NULL) {
                kmem_free(at, sizeof(nvidia_alloc_t));
                return (-ENOMEM);
            }

            if (zero)
                memset(at->kva, 0, at->real_length);
        }

        at->alloc_type_contiguous = 0;

        at->size = num_bytes;
        for (i = 0; i < count; i++)
            pte_array[i] = nv_get_kern_phys_address((NvUPtr)at->kva + (i * PAGESIZE));
        at->pte_array = pte_array;

        *private = at;
        nv_insert_alloc(nv, at);

        return (0);
}

NvS32 nv_free_system_pages(
    nv_state_t *nv,
    void *private
)
{
    nvidia_alloc_t *at = private;

    nv_remove_alloc(nv, at);

    if (nv) {
        gfxp_umem_cookie_destroy(at->umem_cookie);
        ddi_dma_unbind_handle(at->dma_handle);
        ddi_dma_mem_free(&at->dma_data_handle);
        ddi_dma_free_handle(&at->dma_handle);
    } else {
        ddi_umem_free(at->umem_cookie);
    }

    kmem_free(at, sizeof(nvidia_alloc_t));

    return 0;
}

NvS32 nv_free_contig_pages(
    nv_state_t *nv,
    void *private
)
{
    return(nv_free_system_pages(nv, private));
}

NV_STATUS NV_API_CALL nv_alias_pages(
    nv_state_t *nv,
    NvU32       count,
    NvU32       alloc_type_contiguous,
    NvU32       cache_type,
    NvU64       guest_id,
    NvU64      *pte_array,
    void      **priv_data
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_alloc_pages(
    nv_state_t *nv,
    NvU32       count,
    NvBool      alloc_type_contiguous,
    NvU32       cache_type,
    NvBool      alloc_type_zeroed,
    NvBool      unencrypted,
    NvU64      *pte_array,
    void      **private
)
{
    NV_STATUS status = NV_OK;
    NvBool zero = alloc_type_zeroed;

    if (!alloc_type_contiguous) {
        if (nv_alloc_system_pages(nv, count, cache_type, zero,
                    pte_array, private)) {
            status = NV_ERR_NO_MEMORY;
        }
    } else  {
        if (nv_alloc_contig_pages(nv, count, cache_type, zero,
                    pte_array, private)) {
            status = NV_ERR_NO_MEMORY;
        }
    }

    return status;
}

NV_STATUS NV_API_CALL nv_free_pages(
    nv_state_t *nv,
    NvU32 count,
    NvBool alloc_type_contiguous,
    NvU32 cache_type,
    void *private
)
{
    NV_STATUS status = NV_OK;

    if (!alloc_type_contiguous) {
        if (nv_free_system_pages(nv, private))
            status = NV_ERR_GENERIC;
    } else {
        if (nv_free_contig_pages(nv, private))
            status = NV_ERR_GENERIC;
    }

    return status;
}

NvU64 NV_API_CALL nv_get_kern_phys_address(NvU64 address)
{
    uint64_t pa;
    gfxp_va2pa(&kas, (caddr_t)(NvUPtr)address, &pa);
    if (pa == 0) {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: nv_get_kern_phys_address: gfxp_va2pa failed!\n");
        return 0;
    }
    return (pa | (address & PAGEOFFSET));
}

NvU64 NV_API_CALL nv_get_user_phys_address(NvU64 address)
{
    struct proc *p;
    uint64_t pa;

    if (drv_getparm(UPROCP, (void *)&p) != 0)
        return 0;

    gfxp_va2pa(p->p_as, (caddr_t)(NvUPtr)address, &pa);
    if (pa == 0) {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: nv_get_user_phys_address: gfxp_va2pa failed!\n");
        return 0;
    }
    return (pa | (address & PAGEOFFSET));
}

void nvidia_rc_timer(void *data)
{
        nv_state_t *nv = data;
        struct nv_softc *sc = nv->os_state;
        nvidia_stack_t *sp = sc->sp[NV_DEV_STACK_TIMER];

        /*
         * We need this timer to trigger again one second from
         * now, reset the timeout.
        */
        if (rm_run_rc_callback(sp, nv) == NV_OK)
            sc->timer_ch = timeout(nvidia_rc_timer, nv, drv_usectohz(1000000));
}

int NV_API_CALL nv_start_rc_timer(
    nv_state_t *nv
)
{
        struct nv_softc *sc = nv->os_state;

        if (nv->rc_timer_enabled != 0)
                return (-EIO);

        sc->timer_ch = timeout(nvidia_rc_timer,
                                (void *) nv, drv_usectohz(1000000));
        nv->rc_timer_enabled = 1;

        return (0);
}

int NV_API_CALL nv_stop_rc_timer(
    nv_state_t *nv
)
{
        struct nv_softc *sc = nv->os_state;

        if (nv->rc_timer_enabled == 0)
                return (-EIO);

        (void)untimeout(sc->timer_ch);
        sc->timer_ch = 0;
        nv->rc_timer_enabled = 0;

        return (0);
}

nv_state_t* NV_API_CALL nv_get_adapter_state(
    NvU32 domain,
    NvU8  bus,
    NvU8  slot
)
{
    unsigned int i;
    struct nv_softc *sc;
    nv_state_t *nv;

    for (i = 0; i < NV_MAX_DEVICES; i++) {
        sc = ddi_get_soft_state(nv_softc_head, i);
        if (!sc)
            continue;
        nv = sc->nv_state;

        if (nv->pci_info.bus == bus && nv->pci_info.slot == slot)
            return nv;
    }

    return NULL;
}

nv_state_t* NV_API_CALL nv_get_ctl_state(void)
{
    return &nvidia_ctl_state;
}

NV_STATUS NV_API_CALL nv_dma_map_pages(
    nv_dma_device_t *dma_dev,
    NvU64            page_count,
    NvU64           *pte_array,
    NvBool           contig,
    NvU32            cache_type,
    void           **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_unmap_pages(
    nv_dma_device_t *dma_dev,
    NvU64            page_count,
    NvU64           *pte_array,
    void           **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_map_alloc(
    nv_dma_device_t *dma_dev,
    NvU64            page_count,
    NvU64           *va_array,
    NvBool           contig,
    void           **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_unmap_alloc(
    nv_dma_device_t *dma_dev,
    NvU64            page_count,
    NvU64           *va_array,
    void           **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_map_peer(
    nv_dma_device_t *dma_dev,
    nv_dma_device_t *peer_dma_dev,
    NvU8             bar_index,
    NvU64            page_count,
    NvU64           *va
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_dma_unmap_peer(
    nv_dma_device_t *dma_dev,
    NvU64            page_count,
    NvU64            va
)
{
}

NV_STATUS NV_API_CALL nv_dma_map_mmio(
    nv_dma_device_t *dma_dev,
    NvU64            page_count,
    NvU64           *va
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_dma_unmap_mmio(
    nv_dma_device_t *dma_dev,
    NvU64            page_count,
    NvU64            va
)
{
}

void NV_API_CALL nv_dma_cache_invalidate(
    nv_dma_device_t *dma_dev,
    void            *priv
)
{
}

void NV_API_CALL nv_dma_enable_nvlink(
    nv_dma_device_t *dma_dev
)
{
}

NV_STATUS NV_API_CALL nv_log_error(
    nv_state_t *nv,
    NvU32       error_number,
    const char *format,
    va_list    ap
)
{
    return NV_OK;
}

NvU64 NV_API_CALL nv_get_dma_start_address(
    nv_state_t *nv
)
{
    return 0;
}

NV_STATUS NV_API_CALL nv_set_primary_vga_status(
    nv_state_t *nv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_pci_trigger_recovery(
    nv_state_t *nv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL nv_requires_dma_remap(
    nv_state_t *nv
)
{
    return NV_FALSE;
}

NV_STATUS NV_API_CALL nv_register_user_pages(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64      *phys_addr,
    void       *import_priv,
    void      **priv_data
)
{
    return NV_OK;
}

void NV_API_CALL nv_unregister_user_pages(
    nv_state_t *nv,
    NvU64       page_count,
    void      **import_priv,
    void      **priv_data
)
{
}

NV_STATUS NV_API_CALL nv_get_usermap_access_params(
    nv_state_t *nv,
    nv_usermap_access_params_t *nvuap
)
{
    return NV_OK;
}

NV_STATUS NV_API_CALL nv_register_peer_io_mem(
    nv_state_t *nv,
    NvU64      *phys_addr,
    NvU64       page_count,
    void      **priv_data
)
{
    return NV_OK;
}

void NV_API_CALL nv_unregister_peer_io_mem(
    nv_state_t *nv,
    void       *priv_data
)
{
}

NV_STATUS NV_API_CALL nv_register_sgt(
    nv_state_t *nv,
    NvU64      *phys_addr,
    NvU64       page_count,
    NvU32       cache_type,
    void      **priv_data,
    struct sg_table *import_sgt,
    void       *import_priv
)
{
    return NV_OK;
}

void NV_API_CALL nv_unregister_sgt(
    nv_state_t *nv,
    struct sg_table **import_sgt,
    void **import_priv,
    void  *priv_data
)
{
}

NV_STATUS NV_API_CALL nv_register_phys_pages(
    nv_state_t *nv,
    NvU64      *phys_addr,
    NvU64       page_count,
    NvU32       cache_type,
    void      **priv_data
)
{
    return NV_OK;
}

void NV_API_CALL nv_unregister_phys_pages(
    nv_state_t *nv,
    void       *priv_data
)
{
}

NV_STATUS NV_API_CALL nv_get_num_phys_pages(
    void    *pAllocPrivate,
    NvU32   *pNumPages
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_get_phys_pages(
    void    *pAllocPrivate,
    void    *pPages,
    NvU32   *pNumPages
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_get_ibmnpu_genreg_info(
    nv_state_t *nv,
    NvU64      *addr,
    NvU64      *size,
    void      **device
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_get_ibmnpu_relaxed_ordering_mode(
    nv_state_t *nv,
    NvBool *mode
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_wait_for_ibmnpu_rsync(
    nv_state_t *nv
)
{
}

void NV_API_CALL nv_p2p_free_platform_data(
    void *data
)
{
}

NV_STATUS NV_API_CALL nv_revoke_gpu_mappings(
    nv_state_t *nv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_acquire_mmap_lock(
    nv_state_t *nv
)
{
}

void NV_API_CALL nv_release_mmap_lock(
    nv_state_t *nv
)
{
}

NvBool NV_API_CALL nv_get_all_mappings_revoked_locked(
    nv_state_t *nv
)
{
    return NV_FALSE;
}

void NV_API_CALL nv_set_safe_to_mmap_locked(
    nv_state_t *nv,
    NvBool safe_to_mmap
)
{
}

NV_STATUS NV_API_CALL nv_indicate_idle(
    nv_state_t *nv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_indicate_not_idle(
    nv_state_t *nv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_idle_holdoff(
    nv_state_t *nv
)
{
}

NvBool NV_API_CALL nv_dynamic_power_available(
    nv_state_t *nv
)
{
    return NV_FALSE;
}

void NV_API_CALL nv_control_soc_irqs(nv_state_t *nv, NvBool bEnable)
{
}

nv_soc_irq_type_t NV_API_CALL nv_get_current_irq_type(nv_state_t *nv)
{
    return NV_SOC_IRQ_INVALID_TYPE;
}

NvU32 NV_API_CALL nv_get_dev_minor(
    nv_state_t *nv
)
{
    return -1;
}

NV_STATUS NV_API_CALL nv_acquire_fabric_mgmt_cap(int fd, int *duped_fd)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_audio_dynamic_power(
    nv_state_t *nv
)
{
}

NvBool NV_API_CALL nv_is_gpu_accessible(
    nv_state_t *nv
)
{
    return NV_TRUE;
}

NV_STATUS NV_API_CALL nv_dma_import_sgt
(
    nv_dma_device_t *dma_dev,
    struct sg_table *sgt,
    struct drm_gem_object *gem
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_import_dma_buf
(
    nv_dma_device_t *dma_dev,
    struct dma_buf *dma_buf,
    NvU32 *size,
    void **user_pages,
    struct sg_table **sgt,
    nv_dma_buf_t **import_priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_import_from_fd
(
    nv_dma_device_t *dma_dev,
    NvS32 fd,
    NvU32 *size,
    void **user_pages,
    struct sg_table **sgt,
    nv_dma_buf_t **import_priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_dma_release_sgt
(
    struct sg_table *sgt,
    struct drm_gem_object *gem
)
{
}

void NV_API_CALL nv_dma_release_dma_buf
(
    void *user_pages,
    nv_dma_buf_t *import_priv
)
{
}


NvBool NV_API_CALL nv_platform_supports_s0ix(void)
{
    return NV_FALSE;
}

NvBool NV_API_CALL nv_s2idle_pm_configured(void)
{
    return NV_FALSE;
}


void NV_API_CALL
nv_schedule_uvm_isr(nv_state_t *nv)
{
}

NvBool NV_API_CALL nv_is_rm_firmware_active(
    nv_state_t *nv
)
{
    return NV_FALSE;
}

const void* NV_API_CALL nv_get_firmware(
    nv_state_t *nv,
    nv_firmware_t fw_type,
    const void **fw_buf,
    NvU32 *fw_size
)
{
    return NULL;
}

void NV_API_CALL nv_put_firmware(
    const void *fw_handle
)
{
}

NvBool NV_API_CALL nv_is_chassis_notebook(void)
{
    return NV_FALSE;
}

void NV_API_CALL nv_allow_runtime_suspend(
    nv_state_t *nv
)
{
}

void NV_API_CALL nv_disallow_runtime_suspend(
    nv_state_t *nv
)
{
}

NvU32 NV_API_CALL nv_get_os_type(void)
{
    return OS_TYPE_SUNOS;
}

void NV_API_CALL nv_flush_coherent_cpu_cache_range
(
    nv_state_t *nv,
    NvU64 cpu_virtual,
    NvU64 size
)
{
}

void NV_API_CALL nv_get_updated_emu_seg(
    NvU32 *start,
    NvU32 *end
)
{
}
