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

OBJECT_DECLARE_SIMPLE_TYPE(GuestMemfdManager, GUEST_MEMFD_MANAGER)

struct GuestMemfdManager {
    Object parent;

    /* Managed memory region. */
    MemoryRegion *mr;

    /* bitmap used to track discard/private memory */
    int32_t discard_bitmap_size;
    unsigned long *discard_bitmap;

    /* block size and alignment */
    uint64_t block_size;

    /* listeners to notify on plug/unplug activity. */
    QLIST_HEAD(, RamDiscardListener) rdl_list;
};

int guest_memfd_state_change(GuestMemfdManager *gmm, uint64_t offset, uint64_t size,
                             bool shared_to_private);

#endif
