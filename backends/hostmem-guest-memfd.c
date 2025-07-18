/*
 * QEMU guest memfd as memory backend support
 *
 * Copyright (c) 2025 Intel Corporation
 *
 * Author:
 *      Xiaoyao Li <xiaoyao.li@intel.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "system/hostmem.h"
#include "system/kvm.h"
#include "qom/object_interfaces.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qom/object.h"

#include "linux/kvm.h"

#define TYPE_MEMORY_BACKEND_GUEST_MEMFD "memory-backend-guest-memfd"

OBJECT_DECLARE_SIMPLE_TYPE(HostMemoryBackendGuestMemfd,
                           MEMORY_BACKEND_GUEST_MEMFD)


struct HostMemoryBackendGuestMemfd {
    HostMemoryBackend parent_obj;
};

static bool guest_memfd_backend_memory_alloc(HostMemoryBackend *backend,
                                             Error **errp)
{
    g_autofree char *name = host_memory_backend_get_name(backend);
    uint64_t gmem_flags = GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED;
    uint32_t ram_flags;
    int fd;

    if (!backend->size) {
        error_setg(errp, "can't create guest backend with size 0");
        return false;
    }

    if (!backend->share) {
        error_setg(errp, "can't create guest_memfd backend with `share=off`");
        return false;
    }

    if (!kvm_enabled()) {
        error_setg(errp, "can't create guest_memfd backend: KVM required");
        return false;
    }

    if (backend->private_memory) {
        error_setg(errp, "can't create guest_memfd backend for machines which "
                         "require private memory");
        return false;
    }

    fd = kvm_create_guest_memfd(backend->size, gmem_flags, errp);
    if (fd < 0) {
        return false;
    }

    ram_flags = RAM_SHARED | RAM_FD_IS_GUEST_MEMFD;
    ram_flags |= backend->reserve ? 0 : RAM_NORESERVE;

    return memory_region_init_ram_from_fd(&backend->mr, OBJECT(backend), name,
                                          backend->size, ram_flags, fd, 0, errp);
}

static void guest_memfd_backend_class_init(ObjectClass *oc, const void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);

    bc->alloc = guest_memfd_backend_memory_alloc;
}

static void guest_memfd_backend_instance_init(Object *obj)
{
    HostMemoryBackend *backend = MEMORY_BACKEND(obj);

    backend->share = true;
}

static const TypeInfo guest_memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_GUEST_MEMFD,
    .parent = TYPE_MEMORY_BACKEND,
    .instance_init = guest_memfd_backend_instance_init,
    .class_init = guest_memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendGuestMemfd),
};

static void register_types(void)
{
    type_register_static(&guest_memfd_backend_info);
}

type_init(register_types);
