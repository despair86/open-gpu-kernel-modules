/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2020 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-solaris.h"

void* NV_API_CALL os_pci_init_handle(
    NvU32  domain,
    NvU8   bus,
    NvU8   slot,
    NvU8   function,
    NvU16 *vendor,
    NvU16 *device
)
{
    return gfxp_pci_init_handle(bus, slot, function, vendor, device);
}

NV_STATUS NV_API_CALL os_pci_read_byte(
    void *handle,
    NvU32 offset,
    NvU8 *value
)
{
    if (offset >= 0x100) {
        *value = 0xff;
        return NV_ERR_NOT_SUPPORTED;
    }
    *value = gfxp_pci_read_byte(handle, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_word(
    void *handle,
    NvU32  offset,
    NvU16 *value
)
{
    if (offset >= 0x100) {
        *value = 0xffff;
        return NV_ERR_NOT_SUPPORTED;
    }
    *value = gfxp_pci_read_word(handle, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_dword(
    void *handle,
    NvU32  offset,
    NvU32 *value
)
{
    if (offset >= 0x100) {
        *value = 0xffffffff;
        return NV_ERR_NOT_SUPPORTED;
    }
    *value = gfxp_pci_read_dword(handle, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_byte(
    void *handle,
    NvU32  offset,
    NvU8   value
)
{
    if (offset >= 0x100)
        return NV_ERR_NOT_SUPPORTED;

    gfxp_pci_write_byte(handle, offset, value);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_word(
    void *handle,
    NvU32  offset,
    NvU16 value
)
{
    if (offset >= 0x100)
        return NV_ERR_NOT_SUPPORTED;

    gfxp_pci_write_word(handle, offset, value);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_dword(
    void *handle,
    NvU32  offset,
    NvU32 value
)
{
    if (offset >= 0x100)
        return NV_ERR_NOT_SUPPORTED;

    gfxp_pci_write_dword(handle, offset, value);
    return NV_OK;
}

void NV_API_CALL os_pci_remove(
    void *handle
)
{
    return;
}

NvBool NV_API_CALL os_pci_remove_supported(void)
{
    return NV_FALSE;
}










