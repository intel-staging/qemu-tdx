/*
 * QEMU memory attribute manager
 *
 * Copyright Intel
 *
 * Author:
 *      Chenyi Qiang <chenyi.qiang@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory
 *
 */

#ifndef SYSTEM_MEMORY_ATTRIBUTE_MANAGER_H
#define SYSTEM_MEMORY_ATTRIBUTE_MANAGER_H

#include "system/hostmem.h"

#define TYPE_MEMORY_ATTRIBUTE_MANAGER "memory-attribute-manager"

OBJECT_DECLARE_TYPE(MemoryAttributeManager, MemoryAttributeManagerClass, MEMORY_ATTRIBUTE_MANAGER)

struct MemoryAttributeManager {
    Object parent;

    MemoryRegion *mr;

    /* 1-setting of the bit represents the memory is populated (shared) */
    int32_t bitmap_size;
    unsigned long *shared_bitmap;

    QLIST_HEAD(, RamDiscardListener) rdl_list;
};

struct MemoryAttributeManagerClass {
    ObjectClass parent_class;
};

int memory_attribute_manager_realize(MemoryAttributeManager *mgr, MemoryRegion *mr);
void memory_attribute_manager_unrealize(MemoryAttributeManager *mgr);

#endif
