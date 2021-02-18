/*
 * QEMU BIOS e820 routines
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * SPDX-License-Identifier: MIT
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "e820_memory_layout.h"

static size_t e820_entries;
struct e820_table e820_reserve;
struct e820_entry *e820_table;

static int e820_append_reserve(uint64_t address, uint64_t length, uint32_t type)
{
    int index = le32_to_cpu(e820_reserve.count);
    struct e820_entry *entry;

    /* old FW_CFG_E820_TABLE entry -- reservations only */
    if (index >= E820_NR_ENTRIES) {
        return -EBUSY;
    }
    entry = &e820_reserve.entry[index++];

    entry->address = cpu_to_le64(address);
    entry->length = cpu_to_le64(length);
    entry->type = cpu_to_le32(type);

    e820_reserve.count = cpu_to_le32(index);
    return 0;
}

static void e820_append_entry(uint64_t address, uint64_t length, uint32_t type)
{
    e820_table[e820_entries].address = cpu_to_le64(address);
    e820_table[e820_entries].length = cpu_to_le64(length);
    e820_table[e820_entries].type = cpu_to_le32(type);
    e820_entries++;
}

int e820_add_entry(uint64_t address, uint64_t length, uint32_t type)
{
    if (type != E820_RAM) {
        int ret = e820_append_reserve(address, length, type);
        if (ret) {
            return ret;
        }
    }

    /* new "etc/e820" file -- include ram too */
    e820_table = g_renew(struct e820_entry, e820_table, e820_entries + 1);
    e820_append_entry(address, length, type);

    return e820_entries;
}

int e820_change_type(uint64_t address, uint64_t length, uint32_t type)
{
    size_t i;

    if (type != E820_RAM) {
        int ret = e820_append_reserve(address, length, type);
        if (ret) {
            return ret;
        }
    }

    /* new "etc/e820" file -- include ram too */
    for (i = 0; i < e820_entries; i++) {
        struct e820_entry *e = &e820_table[i];
        struct e820_entry tmp = {
            .address = le64_to_cpu(e->address),
            .length = le64_to_cpu(e->length),
            .type = le32_to_cpu(e->type),
        };
        /* overlap? */
        if (address + length < tmp.address ||
            tmp.address + tmp.length < address) {
            continue;
        }
        /*
         * partial-overlap is not allowed.
         * It is assumed that the region is completely contained within
         * other region.
         */
        if (address < tmp.address ||
            tmp.address + tmp.length < address + length) {
            return -EINVAL;
        }
        /* only real type change is allowed. */
        if (tmp.type == type) {
            return -EINVAL;
        }

        if (tmp.address == address &&
            tmp.address + tmp.length == address + length) {
            e->type = cpu_to_le32(type);
            return e820_entries;
        } else if (tmp.address == address) {
            e820_table = g_renew(struct e820_entry,
                                 e820_table, e820_entries + 1);
            e = &e820_table[i];
            e->address = cpu_to_le64(tmp.address + length);
            e820_append_entry(address, length, type);
            return e820_entries;
        } else if (tmp.address + tmp.length == address + length) {
            e820_table = g_renew(struct e820_entry,
                                 e820_table, e820_entries + 1);
            e = &e820_table[i];
            e->length = cpu_to_le64(tmp.length - length);
            e820_append_entry(address, length, type);
            return e820_entries;
        } else {
            e820_table = g_renew(struct e820_entry,
                                 e820_table, e820_entries + 2);
            e = &e820_table[i];
            e->length = cpu_to_le64(address - tmp.address);
            e820_append_entry(address, length, type);
            e820_append_entry(address + length,
                              tmp.address + tmp.length - (address + length),
                              tmp.type);
            return e820_entries;
        }
    }

    return -EINVAL;
}

int e820_get_num_entries(void)
{
    return e820_entries;
}

bool e820_get_entry(int idx, uint32_t type, uint64_t *address, uint64_t *length)
{
    if (idx < e820_entries && e820_table[idx].type == cpu_to_le32(type)) {
        *address = le64_to_cpu(e820_table[idx].address);
        *length = le64_to_cpu(e820_table[idx].length);
        return true;
    }
    return false;
}
