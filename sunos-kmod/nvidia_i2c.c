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

#include "os-interface.h"
#include "nv.h"
#include "nv-solaris.h"

#define NV_I2C_SUPPORTED_XFER \
    (VIS_I2C_READ | VIS_I2C_WRITE | \
     VIS_I2C_SMBUS_QUICK_READ | \
     VIS_I2C_SMBUS_QUICK_WRITE | \
     VIS_I2C_SMBUS_BYTE_READ | \
     VIS_I2C_SMBUS_BYTE_WRITE | \
     VIS_I2C_SMBUS_BYTE_BLOCK_READ | \
     VIS_I2C_SMBUS_BYTE_BLOCK_WRITE | \
     VIS_I2C_SMBUS_SHORT_BLOCK_READ | \
     VIS_I2C_SMBUS_SHORT_BLOCK_WRITE)

static int
nv_i2c_insert_bus(struct nv_softc *softc, struct nv_i2c_bus *bus)
{
    uint32_t i;
    for (i = 0; i < NV_I2C_MAX_BUSSES; i++) {
        if (!softc->i2c_busses[i]) {
            softc->i2c_busses[i] = bus;
            return 0;
        }
    }
    return ENOMEM;
}

static int
nv_i2c_remove_bus(struct nv_softc *softc, struct nv_i2c_bus *bus)
{
    uint32_t i;
    for (i = 0; i < NV_I2C_MAX_BUSSES; i++) {
        if (softc->i2c_busses[i] == bus) {
            softc->i2c_busses[i] = NULL;
            return 0;
        }
    }
    return ENODEV;
}

static uint32_t
nv_i2c_enumerate_busses(struct nv_softc *softc)
{
    uint32_t i;
    for (i = 0; i < NV_I2C_MAX_BUSSES; i++) {
        if (!softc->i2c_busses[i])
            break;
    }
    return i;
}

static int
nv_i2c_read(nvidia_stack_t *sp, nv_state_t *nv, struct nv_i2c_bus *bus,
        uint32_t addr, uint32_t cmd, uint32_t flags,
        uint8_t *data, uint32_t len)
{
    NV_STATUS rmStatus = NV_OK;
    uint8_t sbuf[2];

    switch (flags) {
        case VIS_I2C_SMBUS_QUICK_READ:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_QUICK_READ,
                                       (NvU8)(addr & 0x7f),
                                       0, 0, NULL);
            break;
        case VIS_I2C_SMBUS_BYTE_BLOCK_READ:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_READ,
                                       (NvU8)(addr & 0x7f),
                                       (NvU8)(cmd & 0xff), 1, (NvU8 *)data);
            break;
        case VIS_I2C_SMBUS_SHORT_BLOCK_READ:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_READ,
                                       (NvU8)(addr & 0x74),
                                       (NvU8)(cmd & 0xff), 2, sbuf);
            data[0] = sbuf[1];
            data[1] = sbuf[0];
            break;
        case VIS_I2C_SMBUS_BYTE_READ:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_READ,
                                       (NvU8)(addr & 0x7f),
                                       (NvU8)cmd, (NvU32)(len & 0xffffUL),
                                       (NvU8 *)data);
            break;
        case VIS_I2C_READ:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_READ,
                                       (NvU8)(addr & 0x7f),
                                       0, (NvU32)(len & 0xffffUL),
                                       (NvU8 *)data);
            break;
        default:
            rmStatus = NV_ERR_INVALID_ARGUMENT;
    }

    return ((rmStatus != NV_OK) ? EIO : 0);
}

static int
nv_i2c_write(nvidia_stack_t *sp, nv_state_t *nv, struct nv_i2c_bus *bus,
        uint32_t addr, uint32_t cmd, uint32_t flags,
        uint8_t *data, uint32_t len)
{
    NV_STATUS rmStatus = NV_OK;
    uint8_t sbuf[2];

    switch (flags) {
        case VIS_I2C_SMBUS_QUICK_WRITE:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_QUICK_WRITE,
                                       (NvU8)(addr & 0x7f), 0, 0, NULL);
            break;
        case VIS_I2C_SMBUS_BYTE_BLOCK_WRITE:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_WRITE,
                                       (NvU8)(addr & 0x7f),
                                       (NvU8)(cmd & 0xff), 1, (NvU8 *)data);
            break;
        case VIS_I2C_SMBUS_SHORT_BLOCK_WRITE:
            sbuf[1] = data[0];
            sbuf[0] = data[1];
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_WRITE,
                                       (NvU8)(addr & 0x74),
                                       (NvU8)(cmd & 0xff), 2, sbuf);
            break;
        case VIS_I2C_SMBUS_BYTE_WRITE:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_SMBUS_WRITE,
                                       (NvU8)(addr & 0x7f), (NvU8)cmd,
                                       (NvU32)(len & 0xffffUL), (NvU8 *)data);
            break;
        case VIS_I2C_WRITE:
            rmStatus = rm_i2c_transfer(sp, nv, (void *)bus,
                                       NV_I2C_CMD_WRITE,
                                       (NvU8)(addr & 0x7f), 0,
                                       (NvU32)(len & 0xffffUL), (NvU8 *)data);
            break;
        default:
            rmStatus = NV_ERR_INVALID_ARGUMENT;
    }

    return ((rmStatus != NV_OK) ? EIO : 0);
}

/*
 * PSARC/2009/xxx VIS_I2C_CMDS
 */
static int
nv_i2c_ioctl_i2c(struct nv_softc *softc, nvidia_stack_t *sp, nv_state_t *nv,
        int cmd, void *arg_ptr, int mode, cred_t *cred)
{
    int status = 0;
    uint8_t *buf;
    uint32_t len;
    struct nv_i2c_bus *bus;
    uint8_t busno;
    struct vis_i2c_cmd_list l;
    struct vis_i2c_cmd *v;
    size_t v_size;
    uint32_t flags;
    uint32_t addr;
    uint32_t command;
#if defined(_SYSCALL32)
    struct vis_i2c_cmd_list32 l32;
    size_t v32_size;
    struct vis_i2c_cmd32 *v32;
#endif
    uint32_t i;

    switch (ddi_model_convert_from(mode)) {
#if defined(_SYSCALL32)
        case DDI_MODEL_ILP32:
            if (ddi_copyin(arg_ptr, &l32, sizeof(l32), mode) != 0)
                return EFAULT;
            l.count = l32.count;
            l.cmd_list = (struct vis_i2c_cmd *)(uintptr_t)l32.cmd_list;
            break;
#endif
        case DDI_MODEL_NONE:
            if (ddi_copyin(arg_ptr, &l, sizeof(l), mode) != 0)
                return EFAULT;
            break;
    }

    /*
     * Sanity check the command list count against an
     * arbitrary, but reasonably large number.
     */
    if (l.count <= 0 || l.count > 64)
        return EINVAL;

    v_size = (sizeof(struct vis_i2c_cmd) * l.count);
    v = kmem_zalloc(v_size, KM_SLEEP);
    if (!v)
        return ENOMEM;

    switch (ddi_model_convert_from(mode)) {
#if defined(_SYSCALL32)
        case DDI_MODEL_ILP32:
            v32_size = (sizeof(struct vis_i2c_cmd32) * l.count);
            v32 = kmem_zalloc(v32_size, KM_SLEEP);
            if (!v32) {
                kmem_free((void *)v, v_size);
                return ENOMEM;
            }
            if (ddi_copyin(l.cmd_list, v32, v32_size, mode) != 0) {
                kmem_free((void *)v, v_size);
                kmem_free((void *)v32, v32_size);
                return EFAULT;
            }
            for (i = 0; i < l.count; i++) {
                v[i].bus = v32[i].bus;
                v[i].addr = v32[i].addr;
                v[i].command = v32[i].command;
                v[i].flags = v32[i].flags;
                v[i].length = v32[i].length;
                v[i].pad = v32[i].pad;
                v[i].buffer = (caddr_t)(uintptr_t)v32[i].buffer;
            }
            kmem_free((void *)v32, v32_size);
            break;
#endif
        case DDI_MODEL_NONE:
            if (ddi_copyin(l.cmd_list, v, v_size, mode) != 0) {
                kmem_free((void *)v, v_size);
                return EFAULT;
            }
            break;
    }

    for (i = 0; i < l.count; i++) {
        busno = v[i].bus;
        if (busno >= NV_I2C_MAX_BUSSES) {
            kmem_free((void *)v, v_size);
            return EINVAL;
        }

        bus = softc->i2c_busses[busno];
        if (!bus) {
            kmem_free((void *)v, v_size);
            return ENODEV;
        }

        flags = v[i].flags;
        if (flags & ~NV_I2C_SUPPORTED_XFER) {
            kmem_free((void *)v, v_size);
            return EIO;
        }

        /*
         * Sanity check the buffer length to prevent attempts
         * to allocate unreasonably large buffers.  We do
         * not support requests larger than 64KB.
         */
        len = v[i].length;
        if (len > (64 * 1024)) {
            kmem_free((void *)v, v_size);
            return EINVAL;
        }

        buf = kmem_alloc(len, KM_SLEEP);
        if (!buf) {
            kmem_free((void *)v, v_size);
            return ENOMEM;
        }

        addr = v[i].addr;
        command = v[i].command;

        if (flags & (VIS_I2C_READ | VIS_I2C_SMBUS_QUICK_READ |
                     VIS_I2C_SMBUS_BYTE_READ |
                     VIS_I2C_SMBUS_BYTE_BLOCK_READ |
                     VIS_I2C_SMBUS_SHORT_BLOCK_READ)) {
            status = nv_i2c_read(sp, nv, bus, addr, command, flags, buf, len);
            if (status == 0) {
                if (ddi_copyout(buf, v[i].buffer, len, mode) != 0) {
                    kmem_free((void *)buf, len);
                    kmem_free((void *)v, v_size);
                    return EFAULT;
                }
            }
        } else {
            if (ddi_copyin(v[i].buffer, buf, len, mode) != 0) {
                kmem_free((void *)buf, len);
                kmem_free((void *)v, v_size);
                return EFAULT;
            }
            status = nv_i2c_write(sp, nv, bus, addr, command, flags, buf, len);
        }

        kmem_free((void *)buf, len);
        if (status != 0)
            break;
    }

    kmem_free((void *)v, v_size);
    return status;
}

/*
 * PSARC/2007/695 VIS_READ_DDCCI or VIS_WRITE_DDCCI
 */
static int
nv_i2c_ioctl_ddcci(struct nv_softc *softc, nvidia_stack_t *sp, nv_state_t *nv,
        int cmd, void *arg_ptr, int mode, cred_t *cred)
{
    int status;
    uint8_t *buf;
    uint32_t len;
    struct nv_i2c_bus *bus;
    uint8_t busno;
    struct vis_ddcci v;
    uint8_t addr; /* I2C 8-bit bus address */
#if defined(_SYSCALL32)
    struct vis_ddcci32 v32;
#endif

    switch (ddi_model_convert_from(mode)) {
#if defined(_SYSCALL32)
        case DDI_MODEL_ILP32:
            if (ddi_copyin(arg_ptr, &v32, sizeof(v32), mode) != 0)
                return EFAULT;
            v.port = v32.port;
            v.length = v32.length;
            v.buffer = (caddr_t)(uintptr_t)v32.buffer;
            break;
#endif
        case DDI_MODEL_NONE:
            if (ddi_copyin(arg_ptr, &v, sizeof(v), mode) != 0)
                return EFAULT;
            break;
    }

    /*
     * Sanity check the port.  PSARC/2007/695 discussions
     * have the enumeration starting at 1.
     */
    busno = (v.port - 1);
    if (busno >= NV_I2C_MAX_BUSSES)
        return EINVAL;

    bus = softc->i2c_busses[busno];
    if (bus == NULL)
        return ENODEV;

    /*
     * Sanity check the buffer length to prevent attempts
     * to allocate unreasonably large buffers.  We do
     * not support requests larger than 64KB.
     */
    len = v.length;
    if (len > (64 * 1024))
        return EINVAL;

    buf = kmem_alloc(len, KM_SLEEP);
    if (!buf)
        return ENOMEM;

    /* PSARC/2007/695 only defines DDCCI, addr 0x37 */
    addr = 0x37;

    if (cmd == VIS_READ_DDCCI) {
        status = nv_i2c_read(sp, nv, bus, addr, 0, 0, buf, len);
        if (status == 0) {
            if (ddi_copyout(buf, v.buffer, len, mode) != 0)
                status = EFAULT;
        }
    } else {
        if (ddi_copyin(v.buffer, buf, len, mode) != 0)
            status = EFAULT;
        else
            status = nv_i2c_write(sp, nv, bus, addr, 0, 0, buf, len);
    }

    kmem_free((void *)buf, len);
    return status;
}

int
nv_i2c_ioctl(nvidia_stack_t *sp, nv_state_t *nv, int cmd, void *arg_ptr,
        int mode, cred_t *cred)
{
    int status;
    struct nv_softc *softc = nv->os_state;
    struct vis_i2c_caps v;

    switch (cmd) {
        case VIS_INIT_DDCCI:
            status = 0;
            break;

        case VIS_I2C_CAPS:
            v.bus_count = nv_i2c_enumerate_busses(softc);
            v.flags = NV_I2C_SUPPORTED_XFER;
            if (ddi_copyout(&v, arg_ptr, sizeof(v), mode) != 0)
                return EFAULT;
            status = 0;
            break;

        case VIS_READ_DDCCI:
        case VIS_WRITE_DDCCI:
            status = nv_i2c_ioctl_ddcci(softc, sp, nv, cmd, arg_ptr,
                    mode, cred);
            break;

        case VIS_I2C_CMDS:
            status = nv_i2c_ioctl_i2c(softc, sp, nv, cmd, arg_ptr,
                    mode, cred);
            break;

        default:
            status = EINVAL;
    }

    return status;
}

void* NV_API_CALL nv_i2c_add_adapter(nv_state_t *nv, NvU32 port)
{
    int status;
    struct nv_i2c_bus *bus;
    struct nv_softc *softc = nv->os_state;

    bus = kmem_zalloc(sizeof(struct nv_i2c_bus), KM_SLEEP);
    if (!bus)
        return NULL;
    bus->port = port;

    status = nv_i2c_insert_bus(softc, bus);
    if (status != 0) {
        kmem_free((void *)bus, sizeof(struct nv_i2c_bus));
        bus = NULL;
    }

    return bus;
}

void NV_API_CALL nv_i2c_del_adapter(nv_state_t *nv, void *data)
{
    struct nv_i2c_bus *bus = data;
    struct nv_softc *softc = nv->os_state;

    nv_i2c_remove_bus(softc, bus);
    kmem_free((void *)bus, sizeof(struct nv_i2c_bus));
}
