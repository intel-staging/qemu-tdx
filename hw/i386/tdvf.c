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
#include "qemu/mmap-alloc.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "cpu.h"
#include "exec/hwaddr.h"
#include "hw/boards.h"
#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/tdvf.h"
#include "hw/i386/x86.h"
#include "hw/loader.h"
#include "sysemu/tdx.h"
#include "sysemu/tdvf.h"
#include "target/i386/kvm/tdx.h"

static void tdvf_init_ram_memory(MachineState *ms, TdxFirmwareEntry *entry)
{
    X86MachineState *x86ms = X86_MACHINE(ms);

    if (entry->type == TDVF_SECTION_TYPE_BFV ||
        entry->type == TDVF_SECTION_TYPE_CFV) {
            error_report("TDVF type %u addr 0x%" PRIx64 " in RAM (disallowed)",
                         entry->type, entry->address);
            exit(1);
    }

    if (entry->address >= 4 * GiB) {
        /*
         * If TDVF temp memory describe in TDVF metadata lays in RAM, reserve
         * the region property.
         */
        if (entry->address >= 4 * GiB + x86ms->above_4g_mem_size ||
            entry->address + entry->size >= 4 * GiB + x86ms->above_4g_mem_size) {
            error_report("TDVF type %u address 0x%" PRIx64 " size 0x%" PRIx64
                         " above high memory",
                         entry->type, entry->address, entry->size);
            exit(1);
        }
    }
    e820_change_type(entry->address, entry->size, E820_RESERVED);
}

static void tdvf_init_bios_memory(int fd, const char *filename,
                                  TdxFirmwareEntry *entry)
{
    static unsigned int nr_cfv;
    static unsigned int nr_tmp;

    MemoryRegion *system_memory = get_system_memory();
    Error *err = NULL;
    const char *name;

    /* Error out if the section might overlap other structures. */
    if (entry->address < 4 * GiB - 16 * MiB) {
        error_report("TDVF type %u address 0x%" PRIx64 " in PCI hole",
                        entry->type, entry->address);
        exit(1);
    }

    if (entry->type == TDVF_SECTION_TYPE_BFV) {
        name = g_strdup("tdvf.bfv");
    } else if (entry->type == TDVF_SECTION_TYPE_CFV) {
        name = g_strdup_printf("tdvf.cfv%u", nr_cfv++);
    } else if (entry->type == TDVF_SECTION_TYPE_TD_HOB) {
        name = g_strdup("tdvf.hob");
    } else if (entry->type == TDVF_SECTION_TYPE_TEMP_MEM) {
        name = g_strdup_printf("tdvf.tmp%u", nr_tmp++);
    } else {
        error_report("TDVF type %u unknown/unsupported", entry->type);
        exit(1);
    }
    entry->mr = g_malloc(sizeof(*entry->mr));

    memory_region_init_ram(entry->mr, NULL, name, entry->size, &err);
    if (err) {
        error_report_err(err);
        exit(1);
    }

    memory_region_add_subregion(system_memory, entry->address, entry->mr);

    if (entry->type == TDVF_SECTION_TYPE_TEMP_MEM) {
        e820_add_entry(entry->address, entry->size, E820_RESERVED);
    }

    if (entry->data_len) {
        if (lseek(fd, entry->data_offset, SEEK_SET) != entry->data_offset) {
            error_report("can't seek to 0x%x %s", entry->data_offset, filename);
            exit(1);
        }
        if (read(fd, entry->mem_ptr, entry->data_len) != entry->data_len) {
            error_report("can't read 0x%x %s", entry->data_len, filename);
            exit(1);
        }
    }

}

static void tdvf_parse_section_entry(TdxFirmwareEntry *entry,
                                     const TdvfSectionEntry *src,
                                     uint64_t file_size)
{
    entry->data_offset = le32_to_cpu(src->DataOffset);
    entry->data_len = le32_to_cpu(src->RawDataSize);
    entry->address = le64_to_cpu(src->MemoryAddress);
    entry->size = le64_to_cpu(src->MemoryDataSize);
    entry->type = le32_to_cpu(src->Type);
    entry->attributes = le32_to_cpu(src->Attributes);

    /* sanity check */
    if (entry->data_offset + entry->data_len > file_size) {
        error_report("too large section: DataOffset 0x%x RawDataSize 0x%x",
                     entry->data_offset, entry->data_len);
        exit(1);
    }
    if (entry->size < entry->data_len) {
        error_report("broken metadata RawDataSize 0x%x MemoryDataSize 0x%lx",
                     entry->data_len, entry->size);
        exit(1);
    }
    if (!QEMU_IS_ALIGNED(entry->address, TARGET_PAGE_SIZE)) {
        error_report("MemoryAddress 0x%lx not page aligned", entry->address);
        exit(1);
    }
    if (!QEMU_IS_ALIGNED(entry->size, TARGET_PAGE_SIZE)) {
        error_report("MemoryDataSize 0x%lx not page aligned", entry->size);
        exit(1);
    }
    if (entry->type == TDVF_SECTION_TYPE_TD_HOB ||
        entry->type == TDVF_SECTION_TYPE_TEMP_MEM) {
        if (entry->data_len > 0) {
            error_report("%d section with RawDataSize 0x%x > 0",
                         entry->type, entry->data_len);
            exit(1);
        }
    }
}

static void tdvf_parse_metadata_entries(int fd, TdxFirmware *fw,
                                        TdvfMetadata *metadata)
{

    TdvfSectionEntry *sections;
    ssize_t entries_size;
    uint32_t len, i;

    fw->nr_entries = le32_to_cpu(metadata->NumberOfSectionEntries);
    if (fw->nr_entries < 2) {
        error_report("Invalid number of entries (%u) in TDVF", fw->nr_entries);
        exit(1);
    }

    len = le32_to_cpu(metadata->Length);
    entries_size = fw->nr_entries * sizeof(TdvfSectionEntry);
    if (len != sizeof(*metadata) + entries_size) {
        error_report("TDVF metadata len (0x%x) mismatch, expected (0x%x)",
                     len, (uint32_t)(sizeof(*metadata) + entries_size));
        exit(1);
    }

    fw->entries = g_new(TdxFirmwareEntry, fw->nr_entries);
    sections = g_new(TdvfSectionEntry, fw->nr_entries);

    if (read(fd, sections, entries_size) != entries_size)  {
        error_report("Failed to read TDVF section entries");
        exit(1);
    }

    for (i = 0; i < fw->nr_entries; i++) {
        tdvf_parse_section_entry(&fw->entries[i], &sections[i], fw->file_size);
    }
    g_free(sections);
}

static int tdvf_parse_metadata_header(int fd, TdvfMetadata *metadata)
{
    uint32_t offset;
    int64_t size;

    size = lseek(fd, 0, SEEK_END);
    if (size < TDVF_METDATA_OFFSET_FROM_END || (uint32_t)size != size) {
        return -1;
    }

    /* Chase the metadata pointer to get to the actual metadata. */
    offset = size - TDVF_METDATA_OFFSET_FROM_END;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        return -1;
    }
    if (read(fd, &offset, sizeof(offset)) != sizeof(offset)) {
        return -1;
    }

    offset = le32_to_cpu(offset);
    if (offset > size - sizeof(*metadata)) {
        return -1;
    }

    /* Pointer to the metadata has been resolved, read the actual metadata. */
    if (lseek(fd, offset, SEEK_SET) != offset) {
        return -1;
    }
    if (read(fd, metadata, sizeof(*metadata)) != sizeof(*metadata)) {
        return -1;
    }

    /* Finally, verify the signature to determine if this is a TDVF image. */
    if (metadata->Signature[0] != 'T' || metadata->Signature[1] != 'D' ||
        metadata->Signature[2] != 'V' || metadata->Signature[3] != 'F') {
        return -1;
    }

    /* Sanity check that the TDVF doesn't overlap its own metadata. */
    metadata->Length = le32_to_cpu(metadata->Length);
    if (metadata->Length > size - offset) {
        return -1;
    }

    /* Only version 1 is supported/defined. */
    metadata->Version = le32_to_cpu(metadata->Version);
    if (metadata->Version != 1) {
        return -1;
    }

    return size;
}

int load_tdvf(const char *filename)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86MachineState *x86ms = X86_MACHINE(ms);
    TdxFirmwareEntry *entry;
    TdvfMetadata metadata;
    TdxGuest *tdx;
    TdxFirmware *fw;
    int64_t size;
    int fd;

    if (!kvm_enabled()) {
        return -1;
    }

    tdx = (void *)object_dynamic_cast(OBJECT(ms->cgs), TYPE_TDX_GUEST);
    if (!tdx) {
        return -1;
    }

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        return -1;
    }

    size = tdvf_parse_metadata_header(fd, &metadata);
    if (size < 0) {
        close(fd);
        return -1;
    }

    /* Error out if the user is attempting to load multiple TDVFs. */
    fw = &tdx->fw;
    if (fw->file_name) {
        error_report("tdvf can only be specified once.");
        exit(1);
    }

    fw->file_size = size;
    fw->file_name = g_strdup(filename);

    tdvf_parse_metadata_entries(fd, fw, &metadata);

    for_each_fw_entry(fw, entry) {
        entry->mem_ptr = qemu_ram_mmap(-1, size, qemu_real_host_page_size, 0, 0);
        if (entry->mem_ptr == MAP_FAILED) {
            error_report("failed to allocate memory for TDVF");
            exit(1);
        }
        if (entry->address < x86ms->below_4g_mem_size ||
            entry->address > 4 * GiB) {
            tdvf_init_ram_memory(ms, entry);
        } else {
            tdvf_init_bios_memory(fd, filename, entry);
        }
    }

    close(fd);
    return 0;
}
