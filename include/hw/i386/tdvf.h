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

#define TDVF_METDATA_OFFSET_FROM_END    0x20

#define TDVF_SECTION_TYPE_BFV               0
#define TDVF_SECTION_TYPE_CFV               1
#define TDVF_SECTION_TYPE_TD_HOB            2
#define TDVF_SECTION_TYPE_TEMP_MEM          3

#define TDVF_SECTION_ATTRIBUTES_EXTENDMR    (1U << 0)

typedef struct {
    uint32_t DataOffset;
    uint32_t RawDataSize;
    uint64_t MemoryAddress;
    uint64_t MemoryDataSize;
    uint32_t Type;
    uint32_t Attributes;
} TdvfSectionEntry;

#define TDVF_SIGNATURE_LE32     0x46564454 /* TDVF as little endian */

typedef struct {
    uint8_t Signature[4];
    uint32_t Length;
    uint32_t Version;
    uint32_t NumberOfSectionEntries;
    TdvfSectionEntry SectionEntries[];
} TdvfMetadata;

#endif /* HW_I386_TDVF_H */
