/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2016 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#define NV_DEFINE_REGISTRY_KEY_TABLE

#include "os-interface.h"
#include "nv.h"
#include "nv-solaris.h"
#include "nv-reg.h"

void nvidia_update_registry(nvidia_stack_t *sp, char *option_string)
{
    char *mod, *ptr;
    char *token, *name, *value;
    unsigned long data;
    char *option_string_clean = NULL;
    if ((option_string_clean = rm_remove_spaces(option_string)) == NULL)
    {
        return;
    }

    ptr = option_string_clean;

    while ((token = rm_string_token(&ptr, ';')) != NULL) {
        if (!(name = rm_string_token(&token, '=')) || !strlen(name))
            continue;
        if (!(value = rm_string_token(&token, '=')) || !strlen(value))
            continue;
        if (rm_string_token(&token, '=') != NULL)
            continue;

        if (ddi_strtoul(value, NULL, 0, &data) == 0)
            rm_write_registry_dword(sp, NULL, name, (NvU32)data);
    }

    // Free the memory allocated by rm_remove_spaces()
    os_free_mem(option_string_clean);
}

NV_STATUS NV_API_CALL os_registry_init(void)
{
    nv_parm_t *entry;
    unsigned int i;
    nvidia_stack_t *sp = NULL;

    NV_KMEM_ALLOC_STACK(sp);
    if (sp == NULL)
        return NV_ERR_NO_MEMORY;

    for (i = 0; (entry = &nv_parms[i])->name != NULL; i++)
        rm_write_registry_dword(sp, NULL, entry->name, *entry->data);

    NV_KMEM_FREE_STACK(sp);

    return NV_OK;
}
