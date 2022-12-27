/*
 * QEMU host private memfd memory backend
 *
 * Copyright (C) 2022 Intel Corporation
 *
 * Authors:
 *   Chenyi Qiang <chenyi.qiang@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HOSTMEM_MEMFD_PRIVATE_H
#define HOSTMEM_MEMFD_PRIVATE_H

#include "sysemu/hostmem.h"

#define TYPE_MEMORY_BACKEND_MEMFD_PRIVATE "memory-backend-memfd-private"

OBJECT_DECLARE_SIMPLE_TYPE(HostMemoryBackendPrivateMemfd,
                           MEMORY_BACKEND_MEMFD_PRIVATE)


/*
 * private memfd backend will only work as inital ram.
 * It is unpluggable currently
 */
struct HostMemoryBackendPrivateMemfd {
    HostMemoryBackend parent_obj;

    bool hugetlb;
    uint64_t hugetlbsize;

    /* block size and alignment */
    uint64_t block_size;

    /* listeners to notify on page attr change activity. */
    QLIST_HEAD(, RamDiscardListener) rdl_list;
};

int priv_memfd_backend_state_change(HostMemoryBackendPrivateMemfd *memfd,
                                    uint64_t offset, uint64_t size,
                                    bool private_to_shared);

#endif
