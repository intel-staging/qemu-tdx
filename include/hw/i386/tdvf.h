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

#ifndef HW_I386_TDVF_H
#define HW_I386_TDVF_H

#include "qemu/osdep.h"

#define TDVF_SECTION_TYPE_BFV               0
#define TDVF_SECTION_TYPE_CFV               1
#define TDVF_SECTION_TYPE_TD_HOB            2
#define TDVF_SECTION_TYPE_TEMP_MEM          3

#define TDVF_SECTION_ATTRIBUTES_MR_EXTEND   (1U << 0)
#define TDVF_SECTION_ATTRIBUTES_PAGE_AUG    (1U << 1)

typedef struct TdxFirmwareEntry {
    uint32_t data_offset;
    uint32_t data_len;
    uint64_t address;
    uint64_t size;
    uint32_t type;
    uint32_t attributes;
} TdxFirmwareEntry;

typedef struct TdxFirmware {
    bool split_tdvf;
    void *code_ptr;
    void *vars_ptr;

    uint32_t nr_entries;
    TdxFirmwareEntry *entries;
} TdxFirmware;

int tdvf_parse_metadata(TdxFirmware *fw, void *flash_ptr, int size);

#endif /* HW_I386_TDVF_H */
