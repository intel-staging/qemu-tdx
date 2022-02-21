/*
 * SPDX-License-Identifier: GPL-2.0-or-later

 * Copyright (c) 2020 Intel Corporation
 * Author: Isaku Yamahata <isaku.yamahata at gmail.com>
 *                        <isaku.yamahata at intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "e820_memory_layout.h"
#include "hw/i386/pc.h"
#include "hw/i386/x86.h"
#include "hw/pci/pcie_host.h"
#include "sysemu/kvm.h"
#include "tdvf-hob.h"
#include "uefi.h"

typedef struct TdvfHob {
    hwaddr hob_addr;
    void *ptr;
    int size;

    /* working area */
    void *current;
    void *end;
} TdvfHob;

static uint64_t tdvf_current_guest_addr(const TdvfHob *hob)
{
    return hob->hob_addr + (hob->current - hob->ptr);
}

static void tdvf_align(TdvfHob *hob, size_t align)
{
    hob->current = QEMU_ALIGN_PTR_UP(hob->current, align);
}

static void *tdvf_get_area(TdvfHob *hob, uint64_t size)
{
    void *ret;

    if (hob->current + size > hob->end) {
        error_report("TD_HOB overrun, size = 0x%" PRIx64, size);
        exit(1);
    }

    ret = hob->current;
    hob->current += size;
    tdvf_align(hob, 8);
    return ret;
}

static void tdvf_hob_add_mmio_resource(TdvfHob *hob, uint64_t start,
                                       uint64_t end)
{
    EFI_HOB_RESOURCE_DESCRIPTOR *region;

    if (!start) {
        return;
    }

    region = tdvf_get_area(hob, sizeof(*region));
    *region = (EFI_HOB_RESOURCE_DESCRIPTOR) {
        .Header = {
            .HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
            .HobLength = cpu_to_le16(sizeof(*region)),
            .Reserved = cpu_to_le32(0),
        },
        .Owner = EFI_HOB_OWNER_ZERO,
        .ResourceType = cpu_to_le32(EFI_RESOURCE_MEMORY_MAPPED_IO),
        .ResourceAttribute = cpu_to_le32(EFI_RESOURCE_ATTRIBUTE_TDVF_MMIO),
        .PhysicalStart = cpu_to_le64(start),
        .ResourceLength = cpu_to_le64(end - start),
    };
}

static void tdvf_hob_add_mmio_resources(TdvfHob *hob)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86MachineState *x86ms = X86_MACHINE(ms);
    PCIHostState *pci_host;
    uint64_t start, end;
    uint64_t mcfg_base, mcfg_size;
    Object *host;

    /* Effectively PCI hole + other MMIO devices. */
    tdvf_hob_add_mmio_resource(hob, x86ms->below_4g_mem_size,
                               APIC_DEFAULT_ADDRESS);

    /* Stolen from acpi_get_i386_pci_host(), there's gotta be an easier way. */
    pci_host = OBJECT_CHECK(PCIHostState,
                            object_resolve_path("/machine/i440fx", NULL),
                            TYPE_PCI_HOST_BRIDGE);
    if (!pci_host) {
        pci_host = OBJECT_CHECK(PCIHostState,
                                object_resolve_path("/machine/q35", NULL),
                                TYPE_PCI_HOST_BRIDGE);
    }
    g_assert(pci_host);

    host = OBJECT(pci_host);

    /* PCI hole above 4gb. */
    start = object_property_get_uint(host, PCI_HOST_PROP_PCI_HOLE64_START,
                                     NULL);
    end = object_property_get_uint(host, PCI_HOST_PROP_PCI_HOLE64_END, NULL);
    tdvf_hob_add_mmio_resource(hob, start, end);

    /* MMCFG region */
    mcfg_base = object_property_get_uint(host, PCIE_HOST_MCFG_BASE, NULL);
    mcfg_size = object_property_get_uint(host, PCIE_HOST_MCFG_SIZE, NULL);
    if (mcfg_base && mcfg_base != PCIE_BASE_ADDR_UNMAPPED && mcfg_size) {
        tdvf_hob_add_mmio_resource(hob, mcfg_base, mcfg_base + mcfg_size);
    }
}

static void tdvf_hob_add_memory_resources(TdxGuest *tdx, TdvfHob *hob)
{
    EFI_HOB_RESOURCE_DESCRIPTOR *region;
    EFI_RESOURCE_ATTRIBUTE_TYPE attr;
    EFI_RESOURCE_TYPE resource_type;

    TdxRamEntry *e;
    int i;

    for (i = 0; i < tdx->nr_ram_entries; i++) {
        e = &tdx->ram_entries[i];

        if (e->type == TDX_RAM_UNACCEPTED) {
            resource_type = EFI_RESOURCE_MEMORY_UNACCEPTED;
            attr = EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED;
        } else if (e->type == TDX_RAM_ADDED){
            resource_type = EFI_RESOURCE_SYSTEM_MEMORY;
            attr = EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE;
        } else {
            error_report("unknown TDXRAMENTRY type %d", e->type);
            exit(1);
        }

        region = tdvf_get_area(hob, sizeof(*region));
        *region = (EFI_HOB_RESOURCE_DESCRIPTOR) {
            .Header = {
                .HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                .HobLength = cpu_to_le16(sizeof(*region)),
                .Reserved = cpu_to_le32(0),
            },
            .Owner = EFI_HOB_OWNER_ZERO,
            .ResourceType = cpu_to_le32(resource_type),
            .ResourceAttribute = cpu_to_le32(attr),
            .PhysicalStart = e->address,
            .ResourceLength = e->length,
        };
    }
}

void tdvf_hob_create(TdxGuest *tdx, TdxFirmwareEntry *td_hob)
{
    TdvfHob hob = {
        .hob_addr = td_hob->address,
        .size = td_hob->size,
        .ptr = td_hob->mem_ptr,

        .current = td_hob->mem_ptr,
        .end = td_hob->mem_ptr + td_hob->size,
    };

    EFI_HOB_GENERIC_HEADER *last_hob;
    EFI_HOB_HANDOFF_INFO_TABLE *hit;

    /* Note, Efi{Free}Memory{Bottom,Top} are ignored, leave 'em zeroed. */
    hit = tdvf_get_area(&hob, sizeof(*hit));
    *hit = (EFI_HOB_HANDOFF_INFO_TABLE) {
        .Header = {
            .HobType = EFI_HOB_TYPE_HANDOFF,
            .HobLength = cpu_to_le16(sizeof(*hit)),
            .Reserved = cpu_to_le32(0),
        },
        .Version = cpu_to_le32(EFI_HOB_HANDOFF_TABLE_VERSION),
        .BootMode = cpu_to_le32(0),
        .EfiMemoryTop = cpu_to_le64(0),
        .EfiMemoryBottom = cpu_to_le64(0),
        .EfiFreeMemoryTop = cpu_to_le64(0),
        .EfiFreeMemoryBottom = cpu_to_le64(0),
        .EfiEndOfHobList = cpu_to_le64(0), /* initialized later */
    };

    tdvf_hob_add_memory_resources(tdx, &hob);

    tdvf_hob_add_mmio_resources(&hob);

    last_hob = tdvf_get_area(&hob, sizeof(*last_hob));
    *last_hob =  (EFI_HOB_GENERIC_HEADER) {
        .HobType = EFI_HOB_TYPE_END_OF_HOB_LIST,
        .HobLength = cpu_to_le16(sizeof(*last_hob)),
        .Reserved = cpu_to_le32(0),
    };
    hit->EfiEndOfHobList = tdvf_current_guest_addr(&hob);
}
