/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2015 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/file.h>

#include "nvidia-modeset-os-interface.h"
#include "nvkms-ioctl.h"
#include "nvkms.h"
#include "nv-modeset-interface.h"

#include "nv-retpoline.h"

#define NVKMS_LOG_PREFIX "nvidia_modeset: "

#define NVKMS_POLL_MASK (POLLIN | POLLPRI | POLLRDNORM)


/*************************************************************************
 * NVKMS uses a global lock, nvkms_lock.  The lock is taken in the
 * file operation callback functions when calling into core NVKMS.
 *************************************************************************/

static kmutex_t nvkms_lock;

/*************************************************************************
 * The nvkms_per_open structure tracks data that is specific to a
 * single file open./
 *************************************************************************/

struct nvkms_per_open {
    void *data;
    struct {
        NvBool available;
        struct pollhead pollhead;
    } events;
};


/*
 * For use with ddi_get_soft_state() and friends, to track per-open
 * data associated with each dev_t.
 */
static void *nvkms_per_open_softc;


/*
 * So that nvkms_get_per_open_data() can validate that a vnode
 * corresponds to nvidia-modeset, we cache the device major number.
 */
static major_t nvkms_major = 0;

/*************************************************************************
 * Per-open tracking.
 *
 * SunOS does not provide a convenient way to associate per-open
 * data with a per-open instance.  Instead, assign each per-open
 * instance a unique minor number, and then use ddi_get_soft_state(),
 * et al, to associate per-open data with that unique minor number.
 *
 * See:
 * https://docs.oracle.com/cd/E23824_01/html/819-3196/character-6.html#scrolltoc
 *
 * Use a bitmask to track what minor numbers are available.
 * Manipulation of this bitmask must be protected by
 * nvkms_per_open_minor_lock.
 *
 *************************************************************************/

#define NVKMS_PER_OPEN_MINOR_MAX 512
static uint32_t nvkms_per_open_minor_bitmask[NVKMS_PER_OPEN_MINOR_MAX/32] = { 0 };
static kmutex_t nvkms_per_open_minor_lock;

/*
 * Allocate an available per-open minor number.  If allocation fails,
 * return 0.
 *
 * Note that nvkms_per_open_minor_bitmask[] is used to track bits [0..511].
 * However, nvkms_{alloc,free}_per_open_minor() deal with minor numbers
 * [1..512] so that 0 can be used to indicate failure.
 */
static minor_t nvkms_alloc_per_open_minor(void)
{
    minor_t minor;

    mutex_enter(&nvkms_per_open_minor_lock);

    for (minor = 0; minor < NVKMS_PER_OPEN_MINOR_MAX; minor++) {
        if ((nvkms_per_open_minor_bitmask[minor/32] & (1 << (minor%32))) == 0) {
            nvkms_per_open_minor_bitmask[minor/32] |= (1 << (minor%32));
            mutex_exit(&nvkms_per_open_minor_lock);
            return minor+1;
        }
    }

    mutex_exit(&nvkms_per_open_minor_lock);
    return 0;
}

/*
 * Record that the per-open minor number is now available, again.
 */
static void nvkms_free_per_open_minor(minor_t minor)
{
    if (minor < 1) {
        return;
    }

    minor -= 1;

    mutex_enter(&nvkms_per_open_minor_lock);
    nvkms_per_open_minor_bitmask[minor/32] &= ~(1 << (minor%32));
    mutex_exit(&nvkms_per_open_minor_lock);
}


/*************************************************************************
 * nvidia-modeset-os-interface.h functions.  It is assumed that these
 * are called while nvkms_lock is held.
 *************************************************************************/

void* nvkms_alloc(size_t size, NvBool zero)
{
    /*
     * KM_SLEEP: allow sleeping until memory is available.
     * kmem_zalloc() returns zero-initialized memory.
     */
    return zero ? kmem_zalloc(size, KM_SLEEP) : kmem_alloc(size, KM_SLEEP);
}

void nvkms_free(void *ptr, size_t size)
{
    kmem_free(ptr, size);
}

void* nvkms_memset(void *ptr, NvU8 c, size_t size)
{
    return memset(ptr, c, size);
}

void* nvkms_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}

void* nvkms_memmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}

int nvkms_memcmp(const void *s1, const void *s2, size_t n)
{
    return memcmp(s1, s2, n);
}

size_t nvkms_strlen(const char *s)
{
    return strlen(s);
}

int nvkms_strcmp(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}

char* nvkms_strncpy(char *dest, const char *src, size_t n)
{
    return strncpy(dest, src, n);
}

void nvkms_usleep(NvU64 usec)
{
    /* Note that drv_usecwait(9F) busy waits. */
    drv_usecwait(usec);
}

NvU64 nvkms_get_usec(void)
{
    timestruc_t ts;

    gethrestime(&ts);

    return (((NvU64)ts.tv_sec) * 1000000) + ts.tv_nsec / 1000;
}

int nvkms_copyin(void *kptr, NvU64 uaddr, size_t n)
{
    int ret;

    if (!nvKmsNvU64AddressIsSafe(uaddr)) {
        return EINVAL;
    }

    ret = copyin(nvKmsNvU64ToPointer(uaddr), kptr, n);

    /*
     * According to the copyin(9F) man page, it returns 0 or -1.  If
     * it returns -1, the driver should return EFAULT to user-space.
     */
    return (ret == 0) ? 0 : EFAULT;
}

int nvkms_copyout(NvU64 uaddr, const void *kptr, size_t n)
{
    int ret;

    if (!nvKmsNvU64AddressIsSafe(uaddr)) {
        return EINVAL;
    }

    ret = copyout(kptr, nvKmsNvU64ToPointer(uaddr), n);

    /*
     * According to the copyout(9F) man page, it returns 0 or -1.  If
     * it returns -1, the driver should return EFAULT to user-space.
     */
    return (ret == 0) ? 0 : EFAULT;
}

void nvkms_yield(void)
{
    delay(1 /* clock ticks */);
}

void nvkms_dump_stack(void)
{
    /* Implement me */
}

/* Unsupported STUB for nvkms_syncpt_op APIs */
NvBool nvkms_syncpt_op(
    enum NvKmsSyncPtOp op,
    NvKmsSyncPtOpParams *params)
{
    return NV_FALSE;
}

int nvkms_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = vsnprintf(str, size, format, ap);
    va_end(ap);

    return ret;
}

int nvkms_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    return vsnprintf(str, size, format, ap);
}

void nvkms_log(const int level, const char *gpuPrefix, const char *msg)
{
    int log_level;

    switch (level) {
    default:
    case NVKMS_LOG_LEVEL_INFO:  log_level = CE_CONT; break;
    case NVKMS_LOG_LEVEL_WARN:  log_level = CE_NOTE; break;
    case NVKMS_LOG_LEVEL_ERROR: log_level = CE_WARN; break;
    }

    /* Don't send INFO messages to the console */
    if (log_level == CE_NOTE) {
        cmn_err(log_level, "!%s%s\n", gpuPrefix, msg);
    } else {
        cmn_err(log_level, "%s%s\n", gpuPrefix, msg);
    }
}

void
nvkms_event_queue_changed(nvkms_per_open_handle_t *pOpenKernel,
                          NvBool eventsAvailable)
{
    struct nvkms_per_open *popen = pOpenKernel;

    popen->events.available = eventsAvailable;

    pollwakeup(&popen->events.pollhead, NVKMS_POLL_MASK);
}

/*************************************************************************
 * ref_ptr implementation.
 *************************************************************************/

struct nvkms_ref_ptr {
    kmutex_t lock;
    int refcnt;
    // Access to ptr is guarded by the nvkms_lock.
    void *ptr;
};

struct nvkms_ref_ptr* nvkms_alloc_ref_ptr(void *ptr)
{
    struct nvkms_ref_ptr *ref_ptr = nvkms_alloc(sizeof(*ref_ptr), NV_FALSE);
    if (ref_ptr) {
        mutex_init(&ref_ptr->lock, "nvkms-ref-ptr-lock", MUTEX_DRIVER, NULL);
        // The ref_ptr owner counts as a reference on the ref_ptr itself.
        ref_ptr->refcnt = 1;
        ref_ptr->ptr = ptr;
    }
    return ref_ptr;
}

void nvkms_free_ref_ptr(struct nvkms_ref_ptr *ref_ptr)
{
    if (ref_ptr) {
        ref_ptr->ptr = NULL;
        // Release the owner's reference of the ref_ptr.
        nvkms_dec_ref(ref_ptr);
    }
}

void nvkms_inc_ref(struct nvkms_ref_ptr *ref_ptr)
{
    mutex_enter(&ref_ptr->lock);
    ref_ptr->refcnt++;
    mutex_exit(&ref_ptr->lock);
}

void* nvkms_dec_ref(struct nvkms_ref_ptr *ref_ptr)
{
    void *ptr = ref_ptr->ptr;

    mutex_enter(&ref_ptr->lock);
    if (--ref_ptr->refcnt == 0) {
        mutex_destroy(&ref_ptr->lock);
        nvkms_free(ref_ptr, sizeof(*ref_ptr));
    } else {
        mutex_exit(&ref_ptr->lock);
    }

    return ptr;
}

/*************************************************************************
 * Timer support
 *
 * Core NVKMS needs to be able to schedule work to execute in the
 * future, within a process context.
 *
 * To achieve this, use timeout(9F) to schedule a timeout callback,
 * nvkms_timeout_callback().  This will execute in softirq context, so
 * from there schedule a ddi_taskq_t item, nvkms_taskq_callback(),
 * which will execute in process context.  See ddi_taskq_dispatch(9F).
 *************************************************************************/

static ddi_taskq_t *nvkms_taskq = NULL;

struct nvkms_timer_t {
    timeout_id_t timeout_id;
    NvBool timeout_created;
    NvBool cancel;
    NvBool complete;
    NvBool work_schedule;
    NvBool isRefPtr;
    nvkms_timer_proc_t *proc;
    void *dataPtr;
    NvU32 dataU32;
    struct nvkms_timer_t *prev;
    struct nvkms_timer_t *next;
};

/*
 * Global list with pending timers, any change requires acquiring lock
 */
struct nvkms_timers_t {
    kmutex_t lock;
    struct nvkms_timer_t *list;
};

static struct nvkms_timers_t nvkms_timers;

/*
 * Simple list implementation
 */
static void _nvkms_list_add(struct nvkms_timer_t *timer, struct nvkms_timer_t **list)
{
    if (timer == NULL) {
        return;
    }

    if ((*list) == NULL) {
        (*list) = timer;
        (*list)->prev = (*list)->next = NULL;
        return;
    }

    (*list)->prev = timer;

    timer->prev = NULL;
    timer->next = (*list);

    (*list) = timer;
}

static void _nvkms_list_del(struct nvkms_timer_t *timer, struct nvkms_timer_t **list)
{
    if (timer == NULL) {
        return;
    }

    if (timer->prev != NULL) {
        timer->prev->next = timer->next;
    } else if (timer == *list) {
        (*list) = timer->next;
    }

    if (timer->next != NULL) {
        timer->next->prev = timer->prev;
    }

    timer->next = timer->prev = NULL;
}

static void nvkms_taskq_callback(void *arg)
{
    struct nvkms_timer_t *timer = arg;
    void *dataPtr;

    /*
     * We can delete this timer from pending timers list - it's being
     * processed now.
     */
    mutex_enter(&nvkms_timers.lock);
    _nvkms_list_del(timer, &nvkms_timers.list);
    mutex_exit(&nvkms_timers.lock);

    /*
     * After taskq_callback we want to be sure that timeout_callback
     * for this timer also have finished. It's important during module
     * unload - this way we can safely unload this module by first deleting
     * pending timers and than waiting for taskq callbacks.
     */
    if (timer->timeout_created) {
        untimeout(timer->timeout_id);
    }

    mutex_enter(&nvkms_lock);

    if (timer->isRefPtr) {
        // If the object this timer refers to was destroyed, treat the timer as
        // canceled.
        dataPtr = nvkms_dec_ref(timer->dataPtr);
        if (!dataPtr) {
            timer->cancel = NV_TRUE;
        }
    } else {
        dataPtr = timer->dataPtr;
    }

    if (!timer->cancel) {
        timer->proc(dataPtr, timer->dataU32);
        timer->complete = NV_TRUE;
    }

    if (timer->cancel || timer->isRefPtr) {
        nvkms_free(timer, sizeof(*timer));
    }

    mutex_exit(&nvkms_lock);
}

static void nvkms_timeout_callback(void *arg)
{
    struct nvkms_timer_t *timer = (struct nvkms_timer_t *) arg;
    /*
     * In softirq context, so schedule nvkms_taskq_callback().  Note
     * we must use the NOSLEEP allocation flag in softirq context, but
     * that makes allocation failure more likely...
     */
    ddi_taskq_dispatch(nvkms_taskq, nvkms_taskq_callback, arg, DDI_NOSLEEP);
    timer->work_schedule = NV_TRUE;
}

static void
nvkms_init_timer(struct nvkms_timer_t *timer, nvkms_timer_proc_t *proc,
                 void *dataPtr, NvU32 dataU32, NvBool isRefPtr, NvU64 usec)
{
    timer->cancel = NV_FALSE;
    timer->complete = NV_FALSE;
    timer->isRefPtr = isRefPtr;
    timer->work_schedule = NV_FALSE;
    timer->prev = NULL;
    timer->next = NULL;

    timer->proc = proc;
    timer->dataPtr = dataPtr;
    timer->dataU32 = dataU32;

    /*
     * After adding timer to timers_list we need to finish referencing it
     * (calling schedule_work() or mod_timer()) before releasing the lock.
     * Otherwise, if the code to free the timer were ever updated to
     * run in parallel with this, it could race against nvkms_init_timer()
     * and free the timer before its initialization is complete.
     */
    mutex_enter(&nvkms_timers.lock);
    _nvkms_list_add(timer, &nvkms_timers.list);

    if (usec == 0) {
        timer->timeout_created = NV_FALSE;
        ddi_taskq_dispatch(nvkms_taskq, nvkms_taskq_callback,
                           timer, DDI_SLEEP);
    } else {
        timer->timeout_created = NV_TRUE;
        timer->timeout_id = timeout(nvkms_timeout_callback, timer, drv_usectohz(usec));
    }
    mutex_exit(&nvkms_timers.lock);
}

nvkms_timer_handle_t*
nvkms_alloc_timer(nvkms_timer_proc_t *proc,
                  void *dataPtr, NvU32 dataU32,
                  NvU64 usec)
{
    // nvkms_alloc_timer cannot be called from an interrupt context.
    struct nvkms_timer_t *timer = nvkms_alloc(sizeof(*timer), NV_TRUE);
    if (timer) {
        nvkms_init_timer(timer, proc, dataPtr, dataU32, NV_FALSE, usec);
    }
    return timer;
}

NvBool
nvkms_alloc_timer_with_ref_ptr(nvkms_timer_proc_t *proc,
                               struct nvkms_ref_ptr *ref_ptr,
                               NvU32 dataU32, NvU64 usec)
{
    // nvkms_alloc_timer_with_ref_ptr is called from an interrupt bottom half
    // handler.
    // TODO: Determine whether we really need to use KM_NOSLEEP here.
    struct nvkms_timer_t *timer = kmem_zalloc(sizeof(*timer), KM_NOSLEEP);
    if (timer) {
        // Reference the ref_ptr to make sure that it doesn't get freed before
        // the timer fires.
        nvkms_inc_ref(ref_ptr);
        nvkms_init_timer(timer, proc, ref_ptr, dataU32, NV_TRUE, usec);
    }

    return timer != NULL;
}

void nvkms_free_timer(nvkms_timer_handle_t *handle)
{
    struct nvkms_timer_t *timer = handle;

    if (timer == NULL) {
        return;
    }

    if (timer->complete) {
        nvkms_free(timer, sizeof(*timer));
        return;
    }

    timer->cancel = NV_TRUE;
}

static void nvkms_suspend(NvU32 gpuId)
{
    mutex_enter(&nvkms_lock);
    nvKmsSuspend(gpuId);
    mutex_exit(&nvkms_lock);
}

static void nvkms_resume(NvU32 gpuId)
{
    mutex_enter(&nvkms_lock);
    nvKmsResume(gpuId);
    mutex_exit(&nvkms_lock);
}


/*************************************************************************
 * Interface with resman.
 *
 * Due to the global nvkms_lock, all NVKMS calls to RM are serialized,
 * so we can use a single nvidia_modeset_stack_ptr for calling RM.
 *************************************************************************/

static nvidia_modeset_rm_ops_t __rm_ops = { 0 };
static nvidia_modeset_stack_ptr nvkms_nvidia_stack = NULL;
static nvidia_modeset_callbacks_t nvkms_rm_callbacks = {
    nvkms_suspend,
    nvkms_resume
};

static int nvkms_alloc_rm(void)
{
    NV_STATUS nvstatus;
    int ret;

    __rm_ops.version_string = NV_VERSION_STRING;

    nvstatus = nvidia_get_rm_ops(&__rm_ops);

    if (nvstatus != NV_OK) {
        cmn_err(CE_WARN, NVKMS_LOG_PREFIX
                "Version mismatch: nvidia(%s) nvidia-modeset(%s)\n",
                __rm_ops.version_string, NV_VERSION_STRING);
        return EINVAL;
    }

    ret = __rm_ops.set_callbacks(&nvkms_rm_callbacks);
    if (ret < 0) {
        cmn_err(CE_WARN, NVKMS_LOG_PREFIX "Failed to register callbacks\n");
        return ret;
    }

    return __rm_ops.alloc_stack(&nvkms_nvidia_stack);
}

static void nvkms_free_rm(void)
{
    __rm_ops.set_callbacks(NULL);
    if (__rm_ops.free_stack != NULL) {
        __rm_ops.free_stack(nvkms_nvidia_stack);
    }
}

void nvkms_call_rm(void *ops)
{
    __rm_ops.op(nvkms_nvidia_stack, ops);
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

static size_t nvkms_vnode_offset_within_file_t = 0;

static NvBool find_vnode_offset_within_file_t(void)
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
            nvkms_vnode_offset_within_file_t = offset;
            ret = NV_TRUE;
            break;
        }
    }

    unfalloc(file);

done:
    vn_free(vnode);

    return ret;
}

void* nvkms_get_per_open_data(int fd)
{
    struct nvkms_per_open *popen = NULL;
    unsigned char *ptr = (unsigned char *) getf(fd);
    struct vnode *vnode;
    minor_t minor;
    void *data = NULL;

    if (ptr == NULL) {
        return NULL;
    }

    vnode = *(struct vnode **) (ptr + nvkms_vnode_offset_within_file_t);

    if (getmajor(vnode->v_rdev) != nvkms_major) {
        goto done;
    }

    minor = getminor(vnode->v_rdev);
    popen = ddi_get_soft_state(nvkms_per_open_softc, minor);

    if (popen == NULL) {
        goto done;
    }

    data = popen->data;

done:
    /*
     * getf() incremented the struct file's reference count, which
     * needs to be balanced with a call to releasef(9).  It is safe to
     * decrement the reference count before returning the per-open
     * value because core NVKMS is currently holding the nvkms_lock,
     * which prevents the nvkms_close() => nvKmsClose() call chain
     * from freeing the file out from under the caller of
     * nvkms_get_per_open_data().
     */
    releasef(fd);

    return data;
}

NvBool nvkms_fd_is_nvidia_chardev(int fd)
{
    /*
     * Currently, sunos doesn't have a case where we would expect
     * fd to be non RM fd.
     */
    return NV_TRUE;
}

NvBool nvkms_open_gpu(NvU32 gpuId)
{
    return __rm_ops.open_gpu(gpuId, nvkms_nvidia_stack) == 0;
}

void nvkms_close_gpu(NvU32 gpuId)
{
    __rm_ops.close_gpu(gpuId, nvkms_nvidia_stack);
}

NvU32 nvkms_enumerate_gpus(nv_gpu_info_t *gpu_info)
{
    return 0;
}

NvBool nvkms_allow_write_combining(void)
{
    return __rm_ops.system_info.allow_write_combining;
}

/*************************************************************************
 * Implementation of sysfs interface to control backlight
 *************************************************************************/

struct nvkms_backlight_device*
nvkms_register_backlight(NvU32 gpu_id, NvU32 display_id, void *drv_priv,
                         NvU32 current_brightness)
{
    return NULL;
}

void nvkms_unregister_backlight(struct nvkms_backlight_device *nvkms_bd)
{
}

/*************************************************************************
 * NVKMS interface for kernel space NVKMS clients like KAPI
 *************************************************************************/

struct nvkms_per_open* nvkms_open_from_kapi
(
    struct NvKmsKapiDevice *device
)
{
    return NULL;
}

void nvkms_close_from_kapi(struct nvkms_per_open *popen)
{
}

NvBool nvkms_ioctl_from_kapi
(
    struct nvkms_per_open *popen,
    NvU32 cmd, void *params_address, const size_t params_size
)
{
    return NV_FALSE;
}


/*************************************************************************
 * APIs for locking.
 *************************************************************************/

nvkms_sema_handle_t* nvkms_sema_alloc(void)
{
    return NULL;
}

void nvkms_sema_free(nvkms_sema_handle_t *sema)
{
}

void nvkms_sema_down(nvkms_sema_handle_t *seam)
{
}

void nvkms_sema_up(nvkms_sema_handle_t *sema)
{
}
/*************************************************************************
 * File operation callback functions.
 *************************************************************************/

/*
 * Process the open(2) system call on the NVKMS device file.  Allocate
 * the nvkms_per_open structure and associate it with this "minor".

 * The minor number is assigned back to 'dev', so that the per-open
 * structure can be looked up by minor when ioctl and close are
 * called.
 */
static int nvkms_open(dev_t *dev, int flag, int type, cred_t *cred)
{
    struct nvkms_per_open *popen;
    int status = 0;
    minor_t minor;

    if (type != OTYP_CHR) { /* Only support character devices. */
        return EINVAL;
    }

    minor = nvkms_alloc_per_open_minor();
    if (minor == 0) {
        return ENOMEM;
    }

    /* Allocate an nvkms_per_open for this minor number. */
    status = ddi_soft_state_zalloc(nvkms_per_open_softc, minor);
    if (status != 0) {
        goto fail;
    }

    /* Look up the nvkms_per_open for this minor number. */
    popen = ddi_get_soft_state(nvkms_per_open_softc, minor);
    if (popen == NULL) {
        status = ENOMEM;
        goto fail;
    }

    mutex_enter(&nvkms_lock);
    popen->data = nvKmsOpen(ddi_get_pid(), NVKMS_CLIENT_USER_SPACE, popen);
    mutex_exit(&nvkms_lock);

    if (popen->data == NULL) {
        status = ENOMEM;
        goto fail;
    }

    *dev = makedevice(getmajor(*dev), minor);

    return 0;

fail:

    ddi_soft_state_free(nvkms_per_open_softc, minor);
    nvkms_free_per_open_minor(minor);

    return status;
}

static int nvkms_close(dev_t dev, int flag, int type, cred_t *cred)
{
    struct nvkms_per_open *popen;
    minor_t minor = getminor(dev);

    popen = ddi_get_soft_state(nvkms_per_open_softc, minor);
    if (popen == NULL) {
        return EINVAL;
    }

    mutex_enter(&nvkms_lock);
    nvKmsClose(popen->data);
    mutex_exit(&nvkms_lock);

    ddi_soft_state_free(nvkms_per_open_softc, minor);
    nvkms_free_per_open_minor(minor);

    return 0;
}

static int nvkms_ioctl(dev_t dev, int cmd, intptr_t arg,
                       int mode, cred_t *cred, int *rval)
{
    struct nvkms_per_open *popen;
    int status;
    minor_t minor = getminor(dev);
    struct NvKmsIoctlParams params;
    NvBool ret;
    size_t size;
    unsigned int nr;

    popen = ddi_get_soft_state(nvkms_per_open_softc, minor);
    if ((popen == NULL) || (popen->data == NULL)) {
        return EINVAL;
    }

    size = (cmd >> 16) & IOCPARM_MASK;
    nr = cmd & IOCPARM_MASK;

    /* The only supported ioctl is NVKMS_IOCTL_CMD. */
    if ((nr != NVKMS_IOCTL_CMD) || (size != sizeof(struct NvKmsIoctlParams))) {
        return EINVAL;
    }

    status = ddi_copyin((void *)arg, &params, size, mode);
    if (status != 0) {
        return EFAULT;
    }

    mutex_enter(&nvkms_lock);
    ret = nvKmsIoctl(popen->data,
                     params.cmd,
                     params.address,
                     params.size);
    mutex_exit(&nvkms_lock);

    return ret ? 0 : EPERM;
}

/*
 * When the chpoll(9E) callback function is called, report the number
 * of pending events by assigning reventsp.
 *
 * If no events are pending, point 'phpp' at the per-open pollhead.
 * When events become available, nvkms_event_queue_changed() will call
 * pollwakeup(9F) to wake the fd waiting on the pollhead.
 *
 * https://docs.oracle.com/cd/E23824_01/html/821-1476/chpoll-9e.html#REFMAN9Echpoll-9e
 */
static int nvkms_poll(dev_t dev, short events, int anyyet, short *reventsp,
                      struct pollhead **phpp)
{
    struct nvkms_per_open *popen;
    minor_t minor = getminor(dev);
    short revents = 0;

    popen = ddi_get_soft_state(nvkms_per_open_softc, minor);
    if ((popen == NULL) || (popen->data == NULL)) {
        return EINVAL;
    }

    if (popen->events.available) {
        revents = events & NVKMS_POLL_MASK;
    } else if (!anyyet) {
        *phpp = &popen->events.pollhead;
    }

    *reventsp = revents;

    return 0;
}


/*************************************************************************
 * Module loading support code.
 *************************************************************************/

static int
nvkms_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
    return DDI_FAILURE;
}

static int
nvkms_attach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
    switch (cmd) {

    case DDI_ATTACH:
        {
            int status;
            int unit;

            unit = ddi_get_instance(dev);
            status = ddi_create_minor_node(dev, "ctl", S_IFCHR,
                                           unit, DDI_PSEUDO, 0);
            if (status != DDI_SUCCESS) {
                return status;
            }

            nvkms_major = ddi_driver_major(dev);

            return DDI_SUCCESS;
        }

    case DDI_RESUME:
        break;

    default:
        break;
    }

    return DDI_SUCCESS;
}

static int
nvkms_detach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
    switch (cmd) {

    case DDI_DETACH:
        ddi_remove_minor_node(dev, NULL);
        return DDI_SUCCESS;

    case DDI_SUSPEND:
        break;

    default:
        break;
    }

    return DDI_SUCCESS;
}

static struct cb_ops nvkms_cb_ops = {
    nvkms_open,             /* open */
    nvkms_close,            /* close */
    nodev,                  /* strategy */
    nodev,                  /* print */
    nodev,                  /* dump */
    nodev,                  /* read */
    nodev,                  /* write */
    nvkms_ioctl,            /* ioctl */
    nodev,                  /* devmap */
    nodev,                  /* mmap */
    nodev,                  /* segmap */
    nvkms_poll,             /* poll */
    ddi_prop_op,            /* prop_op */
    NULL,                   /* streamtab  */
    D_NEW | D_MP,           /* cb_flag */
    CB_REV,                 /* cb_rev */
    nodev,                  /* aread */
    nodev                   /* awrite */
};

static struct dev_ops nvkms_ops = {
    DEVO_REV,                  /* devo_rev, */
    0,                         /* refcnt  */
    nvkms_info,                /* getinfo */
    nulldev,                   /* identify */
    nulldev,                   /* probe */
    nvkms_attach,              /* attach */
    nvkms_detach,              /* detach */
    nodev,                     /* reset */
    &nvkms_cb_ops,             /* cb_ops */
    NULL,                      /* bus_ops */
    NULL,                      /* power */
    NULL,                      /* quiesce */
};

static struct modldrv modldrv = {
    &mod_driverops,                           /* Module type: driver. */
    "nvidia-modeset " NV_VERSION_STRING,      /* Name of the module. */
    &nvkms_ops,                               /* Driver operations. */
};

static struct modlinkage modlinkage = {
    MODREV_1,
    { &modldrv, NULL }
};

int _info(struct modinfo *modinfop)
{
    return (mod_info(&modlinkage, modinfop));
}

/*
 * The driver's attach function can be called once mod_install()
 * returns, so this needs to be the last step of _init().
 */
int _init(void)
{
    int status;

    if (!find_vnode_offset_within_file_t()) {
        cmn_err(CE_WARN, NVKMS_LOG_PREFIX
                "Failed to assess run-time environment.\n");
        return EIO;
    }

    /*
     * The "softc" is the infrastructure used to allocate per-open
     * structures.  nvkms_per_open_softc is the opaque handle to the
     * infrastructure, and ddi_soft_state_zalloc() will be called to
     * allocate nvkms_per_open structs.
     */
    status = ddi_soft_state_init(&nvkms_per_open_softc,
                                 sizeof(struct nvkms_per_open), 1);
    if (status != 0) {
        return status;
    }

    mutex_init(&nvkms_lock,
               "nvkms_lock",
               MUTEX_DRIVER, NULL);

    mutex_init(&nvkms_per_open_minor_lock,
               "nvkms_per_open_minor_lock",
               MUTEX_DRIVER, NULL);

    mutex_init(&nvkms_timers.lock,
               "nvkms_timers lock",
               MUTEX_DRIVER, NULL);

    nvkms_timers.list = NULL;

    nvkms_taskq = ddi_taskq_create(NULL, "nvkms_taskq", 1,
                                   TASKQ_DEFAULTPRI, 0);
    if (nvkms_taskq == NULL) {
        status = ENOMEM;
        goto fail;
    }

    status = nvkms_alloc_rm();

    if (status != 0) {
        goto fail;
    }

    status = mod_install(&modlinkage);

    if (status != 0) {
        goto fail;
    }

    mutex_enter(&nvkms_lock);
    if (!nvKmsModuleLoad()) {
        status = ENOMEM;
    }
    mutex_exit(&nvkms_lock);
    if (status != 0) {
        goto fail;
    }

    return 0;

fail:
    nvkms_free_rm();
    if (nvkms_taskq != NULL) {
        ddi_taskq_destroy(nvkms_taskq);
    }
    mutex_destroy(&nvkms_timers.lock);
    mutex_destroy(&nvkms_per_open_minor_lock);
    mutex_destroy(&nvkms_lock);
    ddi_soft_state_fini(&nvkms_per_open_softc);
    return status;
}

/*
 * There is no guarantee that other parts of the driver are not still
 * running until mod_remove() returns success, so this must be the
 * first step of _fini().  Note that mod_remove() can fail, in which
 * case _fini() should fail.  _fini() will be called again until it
 * succeeds.
 *
 * https://docs.oracle.com/cd/E23824_01/html/819-3196/autoconf-95548.html#scrolltoc
 */
int _fini(void)
{
    int status;
    struct nvkms_timer_t *timer, *tmp;

    status = mod_remove(&modlinkage);

    if (status != 0) {
        return status;
    }

    mutex_enter(&nvkms_lock);
    nvKmsModuleUnload();
    mutex_exit(&nvkms_lock);

    nvkms_free_rm();

    mutex_enter(&nvkms_timers.lock);

    for (timer = nvkms_timers.list; timer; ) {
        if (timer->timeout_created) {
            untimeout(timer->timeout_id);
            /*
             * We delete pending timers and check whether it was being executed
             * by checking work_schedule flag. If it began execution, the
             * taskq callback will wait for timeout completion, and we wait
             * for taskq completion with ddi_taskq_destroy below.
             */
            if (!timer->work_schedule) {
                /* We've deactivated timer so we need to clean after it */
                tmp = timer;
                timer = timer->next;
                _nvkms_list_del(tmp, &nvkms_timers.list);

                if (tmp->isRefPtr) {
                    nvkms_dec_ref(tmp->dataPtr);
                }
                nvkms_free(tmp, sizeof(*tmp));
                continue;
            }
        }
        timer = timer->next;
    }

    mutex_exit(&nvkms_timers.lock);

    if (nvkms_taskq != NULL) {
        /*
         * At this point, any pending tasks should be marked canceled,
         * but we still need to drain them, so that
         * nvkms_taskq_callback() doesn't get called after the module
         * is unloaded.  ddi_taskq_destroy(9) drains the taskq before
         * destroying it.
         */
        ddi_taskq_destroy(nvkms_taskq);
    }

    mutex_destroy(&nvkms_timers.lock);
    mutex_destroy(&nvkms_per_open_minor_lock);
    mutex_destroy(&nvkms_lock);

    ddi_soft_state_fini(&nvkms_per_open_softc);

    return 0;
}
