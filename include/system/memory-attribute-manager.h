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
    unsigned shared_bitmap_size;
    unsigned long *shared_bitmap;

    QLIST_HEAD(, RamDiscardListener) rdl_list;
};

struct MemoryAttributeManagerClass {
    ObjectClass parent_class;

    int (*state_change)(MemoryAttributeManager *mgr, uint64_t offset, uint64_t size,
                        bool to_private);
};

static inline int memory_attribute_manager_state_change(MemoryAttributeManager *mgr, uint64_t offset,
                                                        uint64_t size, bool to_private)
{
    MemoryAttributeManagerClass *klass;

    if (mgr == NULL) {
        return 0;
    }

    klass = MEMORY_ATTRIBUTE_MANAGER_GET_CLASS(mgr);

    g_assert(klass->state_change);
    return klass->state_change(mgr, offset, size, to_private);
}

int memory_attribute_manager_realize(MemoryAttributeManager *mgr, MemoryRegion *mr);
void memory_attribute_manager_unrealize(MemoryAttributeManager *mgr);

#endif
