/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2018 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "os-interface.h"
#include "nv.h"
#include "nv-solaris.h"

int
nvidia_pci_probe_legacy(dev_info_t *dip)
{
    ddi_acc_handle_t conf;
    int rval = DDI_PROBE_SUCCESS, ret;

    if ((ret = pci_config_setup(dip, &conf)) != DDI_SUCCESS) {
        // Couldn't probe.  ignore for now.
        // (will still attempt to attach(9E) later.  See probe(9E))
        return DDI_PROBE_DONTCARE;
    }

    if (!rm_is_supported_pci_device(
            pci_config_get8(conf, PCI_CONF_BASCLASS),
            pci_config_get8(conf, PCI_CONF_SUBCLASS),
            pci_config_get16(conf, PCI_CONF_VENID),
            pci_config_get16(conf, PCI_CONF_DEVID),
            pci_config_get16(conf, PCI_CONF_SUBVENID),
            pci_config_get16(conf, PCI_CONF_SUBSYSID),
            NV_TRUE /* print_legacy_warning */))
    {
        rval = DDI_PROBE_FAILURE;
    }

    pci_config_teardown(&conf);

    return (rval);
}

int
nvidia_pci_probe(nvidia_stack_t *sp, struct nv_softc *softc)
{
    NvU16 command;
    nv_state_t *nv = softc->nv_state;

    if (!rm_is_supported_pci_device(
            pci_config_get8(softc->conf, PCI_CONF_BASCLASS),
            pci_config_get8(softc->conf, PCI_CONF_SUBCLASS),
            pci_config_get16(softc->conf, PCI_CONF_VENID),
            pci_config_get16(softc->conf, PCI_CONF_DEVID),
            pci_config_get16(softc->conf, PCI_CONF_SUBVENID),
            pci_config_get16(softc->conf, PCI_CONF_SUBSYSID),
            NV_TRUE /* print_legacy_warning */))
    {
        return ENXIO;
    }

    /*
     * Determine which BAR's are implemented, their locations and
     * respective sizes.
     */
    if (nvidia_pci_get_addresses(softc)) {
        return ENXIO;
    }

    command = pci_config_get16(softc->conf, PCI_CONF_COMM);
    pci_config_put16(softc->conf, PCI_CONF_COMM, (command | PCI_COMM_MAE));

    nv->regs = &nv->bars[NV_GPU_BAR_INDEX_REGS];

    if ((rm_is_supported_device(sp, nv)) != NV_OK)
        return ENXIO;

    return 0;
}

int
nvidia_pci_get_addresses(struct nv_softc *softc)
{
    NvU32 BAR_low, req, i, j;
    NvU64 BAR_high;
    ddi_acc_handle_t conf = softc->conf; /* PCI config handle */
    nv_state_t *nv = softc->nv_state;

    for (i = 0, j = 0; i < NVRM_PCICFG_NUM_BARS && j < NV_GPU_NUM_BARS; i++) {
        NvU8 offset = NVRM_PCICFG_BAR_OFFSET(i);
        nv->bars[j].offset = 0; /* mark not implemented */
        BAR_low = pci_config_get32(conf, offset);
        pci_config_put32(conf, offset, 0xffffffff);
        req = pci_config_get32(conf, offset);
        if ((req != 0) /* implemented */ && (req & NVRM_PCICFG_BAR_REQTYPE_MASK)
                == NVRM_PCICFG_BAR_REQTYPE_MEMORY) {
            if ((BAR_low & NVRM_PCICFG_BAR_ADDR_MASK) == 0) {
                pci_config_put32(conf, offset, BAR_low);
                nv_printf(NV_DBG_ERRORS,
                    "NVRM: BAR%d @ 0x%02x: BAR is 0 (invalid)\n", i, offset);
                return ENXIO;
            }
            nv->bars[j].cpu_address = BAR_low & NVRM_PCICFG_BAR_ADDR_MASK;
            nv->bars[j].size = req & ~((req & ~0x0f) - 1);
            nv->bars[j].offset = offset;
            if ((req & NVRM_PCICFG_BAR_MEMTYPE_MASK) == NVRM_PCICFG_BAR_MEMTYPE_64BIT)
            {
                BAR_high = pci_config_get32(conf, offset + 4);
                nv->bars[j].cpu_address |= (BAR_high << 32);
                i++;
            }
            j++;
        }
        pci_config_put32(conf, offset, BAR_low);
    }

    return 0;
}

NvU8 nvidia_pci_find_capability(struct nv_softc *softc, NvU8 capability)
{
    NvU16 status;
    NvU8  cap_ptr, cap_id;

    status = pci_config_get16(softc->conf, PCI_CONF_STAT);
    status &= PCI_STAT_CAP;
    if (!status)
        goto failed;

    switch (pci_config_get8(softc->conf, PCI_CONF_BASCLASS)) {
        case PCI_CLASS_DISPLAY:
        case PCI_CLASS_BRIDGE:
            cap_ptr = pci_config_get8(softc->conf, PCI_CONF_CAP_PTR);
            break;
        default:
            goto failed;
    }

    do {
        cap_ptr &= 0xfc;
        cap_id = pci_config_get8(softc->conf, cap_ptr + PCI_CAP_ID);
        if (cap_id == capability) {
            return cap_ptr;
        }
        cap_ptr = pci_config_get8(softc->conf, cap_ptr + PCI_CAP_NEXT_PTR);
    } while (cap_ptr && cap_id != 0xff);

failed:
    return 0;
}
