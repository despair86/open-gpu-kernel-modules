/*
 * Copyright 2004-2021 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2021 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-solaris.h"
#include "nv-retpoline.h"

#define MAX_ERROR_STRING    512

/* Initialized in nvidia.c:_init() */
NvU32 os_page_size;
NvU64 os_page_mask;
NvU8  os_page_shift;

NvU32  os_sev_status  = 0;
NvBool os_sev_enabled = 0;

NvBool os_dma_buf_enabled = NV_FALSE;

NvU64 NV_API_CALL os_get_num_phys_pages(void)
{
    return (NvU64)sysconfig(_CONFIG_PHYS_PAGES);
}

/*
 * The core resource manager's favorite source of memory, this routine is
 * called from different contexts, including ISRs. This means that it can
 * not be allowed to sleep when memory is low.
 *
 * It is assumed this memory is only for driver use and not
 * for DMA and/or exporting to user space.
 */

/*
 * The NVDA core does not normally track the allocation size, which
 * must be given to kmem_free().  For Solaris, the allocation
 * will include an extra double word aligned chunk "hidden" at the
 * start which track the allocation.
*/
typedef struct nvidia_mem_info {
        void *ptr;      /* sanity check, word in ILP32, double-word in LP64 */
        size_t size;    /* word in ILP32, double-word in LP64 */
                        /* structure size is double word aligned */
} nvidia_mem_info_t;

NV_STATUS NV_API_CALL os_alloc_mem(
    void **address,
    NvU64 size
)
{
        size_t alloc_size = size;

        void *ptr = NULL;

        /*
         * kmem_zalloc takes an input of unsigned long (8 bytes in x64,
         * 4 bytes in x86). To avoid truncation and wrong allocation,
         * below check is required.
         */
        if ((alloc_size + sizeof(nvidia_mem_info_t)) !=
            (size + sizeof(nvidia_mem_info_t)))
            return (NV_ERR_INVALID_PARAMETER);

        ptr = kmem_zalloc(alloc_size + sizeof(nvidia_mem_info_t), KM_NOSLEEP);
        if (ptr) {
                nvidia_mem_info_t *p = (nvidia_mem_info_t *)ptr;
                *address = p->ptr = ptr + sizeof(nvidia_mem_info_t);
                p->size = alloc_size;
                return (NV_OK);
        } else {
            return (NV_ERR_NO_MEMORY);
        }
}

void NV_API_CALL os_free_mem(void *address)
{
        if (address) {
                nvidia_mem_info_t *ptr = (nvidia_mem_info_t *)
                    ((caddr_t)address - sizeof(nvidia_mem_info_t));
                ptr->size += sizeof(nvidia_mem_info_t);
                kmem_free(ptr, ptr->size);
        }
}

NV_STATUS NV_API_CALL os_get_current_time(
    NvU32 *sec,
    NvU32 *usec
)
{
        timestruc_t ts;

        gethrestime(&ts);
        *sec  = ts.tv_sec;
        *usec = ts.tv_nsec / 1000;
        return NV_OK;
}

#define NANOSEC_PER_USEC    1000

NvU64 NV_API_CALL os_get_current_tick_hr(void)
{
    return gethrtime();
}

NvU64 NV_API_CALL os_get_current_tick(void)
{
        NvU32 sec, usec;

        /* TODO: can we use gethrtime() or ddi_get_lbolt() for this? */
        (void) os_get_current_time(&sec, &usec);
        return ((NvU64)sec * NANOSEC + (NvU64)usec * NANOSEC_PER_USEC);
}

NvU64 NV_API_CALL os_get_tick_resolution(void)
{
        /*
         * Currently using os_get_current_time() which has microsecond
         * resolution.
         */
        return NANOSEC_PER_USEC;
}

/*
 * delay functions are assumed no to allow sleeping.
 * If sleeping is allowed, change to delay().
*/
NV_STATUS NV_API_CALL os_delay(NvU32 MilliSeconds)
{
        drv_usecwait(MilliSeconds * 1000);
        return NV_OK;
}

NV_STATUS NV_API_CALL os_delay_us(NvU32 MicroSeconds)
{
        drv_usecwait(MicroSeconds);
        return NV_OK;
}

NvU64 NV_API_CALL os_get_cpu_frequency(void)
{
        /*
         * This will only work for x86.
         */
        NvU64 start, end;

        start = nv_rdtsc();
        drv_usecwait(100);
        /* Hopefully, we are still on the same CPU */
        end = nv_rdtsc();

        /* convert from 100 microseconds to 1 second */
        return ((end - start) * 10000);
}

NvU32 NV_API_CALL os_get_current_process(void)
{
        return ddi_get_pid();
}

void NV_API_CALL os_get_current_process_name(char *buf, NvU32 len)
{
    /* Unsupported */
    buf[0] = '\0';
}

NV_STATUS NV_API_CALL os_get_current_thread(NvU64 *threadId)
{
        *threadId = (NvU64) ddi_get_kt_did();
        return NV_OK;
}

NvBool NV_API_CALL os_is_administrator(void)
{
        /* can be called from user context only */
        /* TODO: add RBAC support */
        return (drv_priv(ddi_get_cred()) == 0);
}

NvBool NV_API_CALL os_allow_priority_override(void)
{
    return os_is_administrator();
}

NvU8 NV_API_CALL os_io_read_byte(
    NvU32 address
)
{
    /* XXX Fix me? (bus_space access) */
    return inb(address);
}

void NV_API_CALL os_io_write_byte(
    NvU32 address,
    NvU8  value
)
{
    /* XXX Fix me? (bus_space access) */
    outb(address, value);
}

NvU16 NV_API_CALL os_io_read_word(
    NvU32 address
)
{
    /* XXX Fix me? (bus_space access) */
    return inw(address);
}

void NV_API_CALL os_io_write_word(
    NvU32 address,
    NvU16 value
)
{
    /* XXX Fix me? (bus_space access) */
    outw(address, value);
}

NvU32 NV_API_CALL os_io_read_dword(
    NvU32 address
)
{
    /* XXX Fix me? (bus_space access) */
    return inl(address);
}

void NV_API_CALL os_io_write_dword(
    NvU32 address,
    NvU32 value
)
{
    /* XXX Fix me? (bus_space access) */
    outl(address, value);
}

/*
 * This routine maps a range of physical pages into kernel virtual memory
 * to make it accessible by the kernel module. Normally, we wouldn't need
 * this, the kernel provides drivers with linear mappings for each of the
 * memory resources of the device the driver registered itself for.
 */

void* NV_API_CALL os_map_kernel_space(
    NvU64 start,
    NvU64 size,
    NvU32 mode
)
{
    size_t   map_size;
    uint64_t map_start;
    uint32_t map_mode;
    gfxp_kva_t kva;

    if (size == 0)
        return NULL;

    switch (mode) {
        case NV_MEMORY_CACHED:
            map_mode = GFXP_MEMORY_CACHED;
            break;
        case NV_MEMORY_WRITECOMBINED:
            map_mode = GFXP_MEMORY_WRITECOMBINED;
            break;
        case NV_MEMORY_UNCACHED:
        case NV_MEMORY_DEFAULT:
            map_mode = GFXP_MEMORY_UNCACHED;
            break;
        default:
            nv_printf(NV_DBG_ERRORS,
                      "NVRM: unknown mode in os_map_kernel_space()\n");
            return NULL;
    }

    map_start = start;
    map_size = size;

    kva = gfxp_map_kernel_space(map_start, map_size, map_mode);

    return (void *)kva;
}

void NV_API_CALL os_unmap_kernel_space(
    void *address,
    NvU64 size
)
{
    size_t map_size;
    gfxp_kva_t kva;

    if (size == 0 || address == NULL)
        return;

    kva = (gfxp_kva_t)address;
    map_size = size;

    gfxp_unmap_kernel_space(kva, map_size);
}

void* NV_API_CALL os_map_user_space(
    NvU64   start,
    NvU64   size_bytes,
    NvU32   mode,
    NvU32   protect,
    void  **priv_data
)
{
    return (void *)(NvUPtr)start;
}

void NV_API_CALL os_unmap_user_space(
    void  *address,
    NvU64  size,
    void  *priv_data
)
{
}

/*
 * The current debug level is used to determine if certain debug messages
 * are printed to the system console/log files or not. It defaults to the
 * highest debug level, i.e. the lowest debug output.
 */

NvU32 cur_debuglevel = 0xffffffff;

void NV_API_CALL os_dbg_init(void)
{
    nvidia_stack_t *sp = NULL;
    NvU32 new_debuglevel;

    NV_KMEM_ALLOC_STACK(sp);
    if (sp == NULL)
        return;

    if (rm_read_registry_dword(sp, NULL,
                "ResmanDebugLevel", &new_debuglevel) == NV_OK) {
        if (new_debuglevel != 0xffffffff)
            cur_debuglevel = new_debuglevel;
    }

    NV_KMEM_FREE_STACK(sp);
}

NV_STATUS NV_API_CALL os_schedule(void)
{
    delay(1 /* clock ticks */);

    return NV_OK;
}

static void os_execute_work_item(void *data)
{
    nvidia_stack_t *sp = NULL;

    NV_KMEM_ALLOC_STACK(sp);
    if (sp == NULL) {
        nv_printf(NV_DBG_ERRORS, "NVRM: failed to allocate stack!\n");
        return;
    }

    rm_execute_work_item(sp, data);

    NV_KMEM_FREE_STACK(sp);
}

NV_STATUS NV_API_CALL os_queue_work_item(struct os_work_queue *queue, void *data)
{
    int status;

    status = ddi_taskq_dispatch(nvidia_taskq, os_execute_work_item,
                data, DDI_NOSLEEP);

    if (status != DDI_SUCCESS)
        return NV_ERR_GENERIC;

    return NV_OK;
}

NV_STATUS NV_API_CALL os_flush_work_queue(struct os_work_queue *queue)
{
    ddi_taskq_wait(nvidia_taskq);
    return NV_OK;
}

void NV_API_CALL os_dbg_set_level(NvU32 new_debuglevel)
{
    cur_debuglevel = new_debuglevel;
}

extern NvU32 NVreg_EnableDbgBreakpoint;

void NV_API_CALL os_dbg_breakpoint(void)
{
    if (NVreg_EnableDbgBreakpoint == 0)
    {
        return;
    }

    debug_enter("NVRM: Breakpoint Hit!\n");
}

/*
 * The binary core of RM (nv-kernel.o) calls this:
 */
void NV_API_CALL out_string(const char *message)
{
    prom_printf("%s", message);
}

static char nv_error_string[MAX_ERROR_STRING];

int NV_API_CALL nv_printf(NvU32 debuglevel, const char *format, ...)
{
    char *message = nv_error_string;
    va_list arglist;
    int chars_written = 0;

    if (debuglevel >= ((cur_debuglevel >> 4) & 3)) {
        va_start(arglist, format);
        chars_written = vsnprintf(message, sizeof(nv_error_string), format, arglist);
        va_end(arglist);
        cmn_err(CE_NOTE, "%s", message);
    }

    return chars_written;
}

NvS32 NV_API_CALL os_snprintf(char *buf, NvU32 size, const char *fmt, ...)
{
    va_list arglist;
    int chars_written;

    va_start(arglist, fmt);
    chars_written = vsnprintf(buf, size, fmt, arglist);
    va_end(arglist);

    return chars_written;
}

NvS32 NV_API_CALL os_vsnprintf(char *buf, NvU32 size, const char *fmt, va_list arglist)
{
    return vsnprintf(buf, size, fmt, arglist);
}

void NV_API_CALL os_log_error(const char *fmt, va_list ap)
{
    vsnprintf(nv_error_string, MAX_ERROR_STRING, fmt, ap);
    printf("%s", nv_error_string);
}

NvS32 NV_API_CALL os_mem_cmp(
    const NvU8 *buf0,
    const NvU8 *buf1,
    NvU32 length
)
{
    return memcmp(buf0, buf1, length);
}

void *NV_API_CALL os_mem_copy(
    void       *dstPtr,
    const void *srcPtr,
    NvU32       length
)
{
    void *ret = dstPtr;
    NvU32 dwords, bytes = length;
    NvU8 *dst = dstPtr;
    const NvU8 *src = srcPtr;

    if ((length >= 128) &&
        (((NvUPtr)dst & 3) == 0) & (((NvUPtr)src & 3) == 0))
    {
        dwords = (length / sizeof(NvU32));
        bytes = (length % sizeof(NvU32));

        while (dwords != 0)
        {
            *(NvU32 *)dst = *(const NvU32 *)src;
            dst += sizeof(NvU32);
            src += sizeof(NvU32);
            dwords--;
        }
    }

    while (bytes != 0)
    {
        *dst = *src;
        dst++;
        src++;
        bytes--;
    }

    return ret;
}

NV_STATUS NV_API_CALL os_memcpy_from_user(
    void *dst,
    const void *src,
    NvU32 length
)
{
        return copyin(src, dst, length)  ? NV_ERR_INVALID_POINTER : NV_OK;
}

NV_STATUS NV_API_CALL os_memcpy_to_user(
    void *dst,
    const void *src,
    NvU32 length
)
{
        return copyout(src, dst, length) ? NV_ERR_INVALID_POINTER : NV_OK;
}

void* NV_API_CALL os_mem_set(
    void  *dst,
    NvU8   c,
    NvU32  length
)
{
    NvU8 *ret = dst;
    NvU32 bytes = length;

    while (bytes != 0)
    {
        *(NvU8 *)dst = c;
        dst = ((NvU8 *)dst + 1);
        bytes--;
    }

    return ret;
}

char* NV_API_CALL os_string_copy(
    char *dst,
    const char *src
)
{
        return strcpy(dst, src);
}

NvU32 NV_API_CALL os_string_length(const char* s)
{
    return strlen(s);
}

NvU32 NV_API_CALL os_strtoul(const char *str, char **endp, NvU32 base)
{
    NvU32 result = 0;
    NvU32 rc;

    rc = ddi_strtoul(str, endp, base, &result);
    return (NvU32)((rc != 0) ? 0 : result);
}

NvS32 NV_API_CALL os_string_compare(const char *str1, const char *str2)
{
    return strcmp(str1, str2);
}

/*
 * TODO: This returns the maximum number of CPUs on the system.
 * It does not count the CPUs correctly for the current zone
 * or CPUs offlined.
*/
NvU32 NV_API_CALL os_get_cpu_count(void)
{
        /* TODO: very non-DDI compliant, expect this to break */
        extern int max_ncpus;
        return (max_ncpus);
}

NvU32 NV_API_CALL os_get_cpu_number(void)
{
    return CPU->cpu_id;
}

NV_STATUS NV_API_CALL os_flush_cpu_cache(void)
{
    /*
     * XXX This will do for now, but this may need to be extended
     * to make IPI calls (flushing all caches).
     */
    __asm__ __volatile__("wbinvd": : :"memory");
    return NV_OK;
}

NV_STATUS NV_API_CALL os_flush_user_cache(void)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_flush_cpu_cache_all(void)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_flush_cpu_write_combine_buffer(void)
{
    __asm__ __volatile__("sfence": : :"memory");
}

typedef kmutex_t os_mutex_t;

NV_STATUS NV_API_CALL os_alloc_mutex(void **mutex)
{
    os_mutex_t *os_mutex;

    os_mutex = (os_mutex_t *)kmem_zalloc(sizeof(os_mutex_t), KM_SLEEP);
    if (os_mutex == NULL) {
        nv_printf(NV_DBG_ERRORS, "NVRM: failed to allocate mutex!\n");
        return NV_ERR_NO_MEMORY;
    }
    mutex_init(os_mutex, "nv os lock mutex", MUTEX_DRIVER, NULL);
    *mutex = (void *) os_mutex;

    return NV_OK;
}

void NV_API_CALL os_free_mutex(void *mutex)
{
    os_mutex_t *os_mutex = (os_mutex_t *)mutex;

    if (os_mutex != NULL) {
        ASSERT(mutex_owned(os_mutex) == 0);
        mutex_destroy(os_mutex);
        kmem_free(os_mutex, sizeof(os_mutex_t));
    }
}

NV_STATUS NV_API_CALL os_acquire_mutex(void *mutex)
{
    os_mutex_t *os_mutex = (os_mutex_t *)mutex;
    mutex_enter(os_mutex);

    return NV_OK;
}

NV_STATUS NV_API_CALL os_cond_acquire_mutex(void *mutex)
{
    os_mutex_t *os_mutex = (os_mutex_t *)mutex;

    if (mutex_tryenter(os_mutex) == 0) {
        return NV_ERR_TIMEOUT_RETRY;
    }

    return NV_OK;
}

void NV_API_CALL os_release_mutex(void *mutex)
{
    os_mutex_t *os_mutex = (os_mutex_t *)mutex;
    mutex_exit(os_mutex);
}

typedef struct os_semaphore {
    kmutex_t lock;
    kcondvar_t cv;
    NvS32 count;
} os_semaphore_t;


void* NV_API_CALL os_alloc_semaphore(NvU32 initialValue)
{
    os_semaphore_t *os_sema;

    os_sema = (os_semaphore_t *)kmem_zalloc(sizeof(os_semaphore_t), KM_SLEEP);
    if (os_sema == NULL) {
        nv_printf(NV_DBG_ERRORS, "NVRM: failed to allocate semaphore!\n");
        return NULL;
    }
    mutex_init(&os_sema->lock, "nv os semaphore mutex", MUTEX_DRIVER, NULL);
    cv_init(&os_sema->cv, "nv os semaphore cv", CV_DRIVER, NULL);
    os_sema->count = initialValue;

    return (void *)os_sema;
}

void NV_API_CALL os_free_semaphore(void *semaphore)
{
    os_semaphore_t *os_sema = (os_semaphore_t *)semaphore;

    cv_destroy(&os_sema->cv);
    mutex_destroy(&os_sema->lock);
    kmem_free(os_sema, sizeof(os_semaphore_t));
}

NV_STATUS NV_API_CALL os_acquire_semaphore(void *semaphore)
{
    os_semaphore_t *os_sema = (os_semaphore_t *)semaphore;

    mutex_enter(&os_sema->lock);
    os_sema->count--;
    if (os_sema->count < 0) {
        cv_wait(&os_sema->cv, &os_sema->lock);
    }
    mutex_exit(&os_sema->lock);

    return NV_OK;
}

NV_STATUS NV_API_CALL os_cond_acquire_semaphore(void *semaphore)
{
    NV_STATUS status = NV_ERR_TIMEOUT_RETRY;
    os_semaphore_t *os_sema = (os_semaphore_t *)semaphore;

    if (mutex_tryenter(&os_sema->lock) != 0) {
        if (os_sema->count > 0) {
            os_sema->count--;
            status = NV_OK;
        }
        mutex_exit(&os_sema->lock);
    }

    return status;
}

NV_STATUS NV_API_CALL os_release_semaphore(void *semaphore)
{
    os_semaphore_t *os_sema = (os_semaphore_t *)semaphore;
    NvBool wakeup = NV_FALSE;

    mutex_enter(&os_sema->lock);
    if (os_sema->count < 0) {
        wakeup = NV_TRUE;
    }
    os_sema->count++;
    mutex_exit(&os_sema->lock);

    if (wakeup)
        cv_signal(&os_sema->cv);

    return NV_OK;
}

NvBool NV_API_CALL os_semaphore_may_sleep(void)
{
#ifdef DEBUG
    ASSERT(0);
#endif
    return NV_TRUE;
}

NvBool NV_API_CALL os_is_isr(void)
{
#ifdef DEBUG
    ASSERT(0);
#endif
    return NV_FALSE;
}

NvBool NV_API_CALL os_pat_supported(void)
{
    return NV_TRUE;
}

NvBool NV_API_CALL os_is_efi_enabled(void)
{
    return NV_FALSE;
}

void NV_API_CALL os_get_screen_info(
    NvU64 *pPhysicalAddress,
    NvU16 *pFbWidth,
    NvU16 *pFbHeight,
    NvU16 *pFbDepth,
    NvU16 *pFbPitch,
    NvU64 consoleBar1Address,
    NvU64 consoleBar2Address
)
{
    *pPhysicalAddress = 0;
    *pFbWidth = *pFbHeight = *pFbDepth = *pFbPitch = 0;
}

void NV_API_CALL os_disable_console_access(void)
{
}

void NV_API_CALL os_enable_console_access(void)
{
}

typedef kmutex_t os_spinlock_t;

NV_STATUS NV_API_CALL os_alloc_spinlock(void **spinlock)
{
    os_spinlock_t *os_spinlock;

    os_spinlock = (os_spinlock_t *)kmem_zalloc(sizeof(os_spinlock_t), KM_SLEEP);
    if (os_spinlock == NULL) {
        nv_printf(NV_DBG_ERRORS, "NVRM: failed to allocate spinlock!\n");
        return NV_ERR_NO_MEMORY;
    }
    mutex_init(os_spinlock, "nv os spinlock mutex ", MUTEX_DRIVER, NULL);
    *spinlock = (void *) os_spinlock;

    return NV_OK;

}

void NV_API_CALL os_free_spinlock(void *spinlock)
{
    os_spinlock_t *os_spinlock = (os_spinlock_t *)spinlock;

    if (os_spinlock != NULL) {
        ASSERT(mutex_owned(os_spinlock) == 0);
        mutex_destroy(os_spinlock);
        kmem_free(os_spinlock, sizeof(os_spinlock_t));
    }
}

NvU64 NV_API_CALL os_acquire_spinlock(void *spinlock)
{
    os_spinlock_t *os_spinlock = (os_spinlock_t *)spinlock;

    mutex_enter(os_spinlock);

    return 0;
}

void NV_API_CALL os_release_spinlock(void *spinlock, NvU64 oldIrql)
{
    os_spinlock_t *os_spinlock = (os_spinlock_t *)spinlock;

    mutex_exit(os_spinlock);
}

NV_STATUS NV_API_CALL os_get_version_info(os_version_info * pOsVersionInfo)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL os_is_xen_dom0(void)
{
    return NV_FALSE;
}

NvBool NV_API_CALL os_is_vgx_hyper(void)
{
    return NV_FALSE;
}

NV_STATUS NV_API_CALL os_inject_vgx_msi(NvU16 guestID, NvU64 msiAddr, NvU32 msiData)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL os_is_grid_supported(void)
{
    return NV_FALSE;
}

NvU32 NV_API_CALL os_get_grid_csp_support(void)
{
    return 0;
}

void NV_API_CALL os_bug_check(NvU32 bugCode, const char *bugCodeStr)
{
}

NV_STATUS NV_API_CALL os_lock_user_pages(
    void   *address,
    NvU64   page_count,
    void  **page_array,
    NvU32   flags
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_unlock_user_pages(
    NvU64  page_count,
    void  *page_array
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_lookup_user_io_memory(
    void   *address,
    NvU64   page_count,
    NvU64 **pte_array,
    void  **page_array
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_match_mmap_offset(
    void  *pAllocPrivate,
    NvU64  offset,
    NvU64 *pPageIndex
)
{
    nvidia_alloc_t *at = pAllocPrivate;
    ulong_t linear;
    uint64_t pa;

    linear = (uintptr_t)at->kva;
    *pPageIndex = 0;
    do {
        gfxp_va2pa(&kas, (caddr_t)linear, &pa);
        if (pa == offset)
            return NV_OK;
        linear += PAGESIZE;
        (*pPageIndex)++;
    } while (linear < ((uintptr_t)at->kva + at->size));

    return NV_ERR_OBJECT_NOT_FOUND;
}

NV_STATUS NV_API_CALL os_get_euid(NvU32 *pSecToken)
{
    *pSecToken = (NvU32)crgetuid(ddi_get_cred());
    return NV_OK;
}

NV_STATUS NV_API_CALL os_get_smbios_header(NvU64 *pSmbsAddr)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_get_acpi_rsdp_from_uefi
(
    NvU32  *pRsdpAddr
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_add_record_for_crashLog(void *pbuffer, NvU32 size)
{

}

void NV_API_CALL os_delete_record_for_crashLog(void *pbuffer)
{
}

NV_STATUS NV_API_CALL os_call_vgpu_vfio(void *pvgpu_vfio_info, NvU32 cmd_type)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_numa_memblock_size(NvU64 *memblock_size)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_alloc_pages_node
(
    NvS32  nid,
    NvU32  size,
    NvU32  flag,
    NvU64 *pAddress
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_get_page
(
    NvU64 address
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL  os_put_page
(
    NvU64 address
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvU32 NV_API_CALL os_get_page_refcount
(
    NvU64 address
)
{
    return 0;
}

NvU32 NV_API_CALL os_count_tail_pages
(
    NvU64 address
)
{
    return 0;
}

void NV_API_CALL os_free_pages_phys
(
    NvU64 address,
    NvU32 size
)
{
}

NV_STATUS NV_API_CALL os_call_nv_vmbus(NvU32 vmbus_cmd, void *input)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_open_temporary_file
(
    void **ppFile
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_close_file
(
    void *pFile
)
{
}

NV_STATUS NV_API_CALL os_write_file
(
    void *pFile,
    NvU8 *pBuffer,
    NvU64 size,
    NvU64 offset
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_read_file
(
    void *pFile,
    NvU8 *pBuffer,
    NvU64 size,
    NvU64 offset
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_open_readonly_file
(
    const char  *filename,
    void       **ppFile
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_open_and_read_file
(
    const char *filename,
    NvU8       *buf,
    NvU64       count
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL os_is_nvswitch_present(void)
{
    return NV_FALSE;
}

void NV_API_CALL os_dump_stack(void)
{

}

void NV_API_CALL os_get_random_bytes
(
    NvU8 *bytes,
    NvU16 numBytes
)
{
    random_get_pseudo_bytes(bytes, numBytes);
}

NV_STATUS NV_API_CALL os_alloc_wait_queue
(
    os_wait_queue **wq
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_free_wait_queue
(
    os_wait_queue *wq
)
{
}

void NV_API_CALL os_wait_uninterruptible
(
    os_wait_queue *wq
)
{
}

void NV_API_CALL os_wait_interruptible
(
    os_wait_queue *wq
)
{
}

void NV_API_CALL os_wake_up
(
    os_wait_queue *wq
)
{
}

int NV_API_CALL os_nv_cap_validate_and_dup_fd
(
    const nv_cap_t *cap,
    int fd
)
{
    return 0;
}

void NV_API_CALL os_nv_cap_close_fd
(
    int fd
)
{
}

nv_cap_t* NV_API_CALL os_nv_cap_create_file_entry
(
    nv_cap_t *parent_cap,
    const char *name,
    int mode
)
{
    return NULL;
}

nv_cap_t* NV_API_CALL os_nv_cap_create_dir_entry
(
    nv_cap_t *parent_cap,
    const char *name,
    int mode
)
{
    return NULL;
}

void NV_API_CALL os_nv_cap_destroy_entry
(
    nv_cap_t *cap
)
{
}

nv_cap_t* NV_API_CALL os_nv_cap_init
(
    const char *path
)
{
    return NULL;
}
























