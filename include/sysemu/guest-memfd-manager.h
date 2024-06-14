/*
 * QEMU guest memfd manager
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

#ifndef SYSEMU_GUEST_MEMFD_MANAGER_H
#define SYSEMU_GUEST_MEMFD_MANAGER_H

#include "sysemu/hostmem.h"

#define TYPE_GUEST_MEMFD_MANAGER "guest-memfd-manager"

OBJECT_DECLARE_TYPE(GuestMemfdManager, GuestMemfdManagerClass, GUEST_MEMFD_MANAGER)

struct GuestMemfdManager {
    Object parent;

    /* Managed memory region. */
    MemoryRegion *mr;

    /*
     * 1-setting of the bit represents the memory is populated (shared).
     */
    int32_t bitmap_size;
    unsigned long *bitmap;

    /* block size and alignment */
    uint64_t block_size;

    /* listeners to notify on populate/discard activity. */
    QLIST_HEAD(, RamDiscardListener) rdl_list;
};

struct GuestMemfdManagerClass {
    ObjectClass parent_class;

    int (*state_change)(GuestMemfdManager *gmm, uint64_t offset, uint64_t size,
                        bool shared_to_private);
};

static inline int guest_memfd_manager_state_change(GuestMemfdManager *gmm, uint64_t offset,
                                                   uint64_t size, bool shared_to_private)
{
    GuestMemfdManagerClass *klass;

    g_assert(gmm);
    klass = GUEST_MEMFD_MANAGER_GET_CLASS(gmm);

    if (klass->state_change) {
        return klass->state_change(gmm, offset, size, shared_to_private);
    }

    return 0;
}

#endif
