/*
 * QEMU host private memfd memory backend
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Authors:
 *   Chao Peng <chao.p.peng@linux.intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "sysemu/hostmem-memfd-private.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qom/object.h"

static void
priv_memfd_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(backend);
    uint32_t ram_flags;
    char *name;
    int fd, priv_fd;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return;
    }

    fd = qemu_memfd_create("memory-backend-memfd-shared", backend->size,
                           m->hugetlb, m->hugetlbsize, 0, errp);
    if (fd == -1) {
        return;
    }

    priv_fd = qemu_memfd_restricted(backend->size, 0, errp);
    if (priv_fd == -1) {
        return;
    }

    name = host_memory_backend_get_name(backend);
    ram_flags = backend->share ? RAM_SHARED : 0;
    ram_flags |= backend->reserve ? 0 : RAM_NORESERVE;
    memory_region_init_ram_from_fd(&backend->mr, OBJECT(backend), name,
                                   backend->size, ram_flags, fd, 0, errp);
    g_free(name);

    memory_region_set_restricted_fd(&backend->mr, priv_fd);
    memory_region_set_ram_discard_manager(&backend->mr,
                                          RAM_DISCARD_MANAGER(m));
}

static bool
priv_memfd_backend_get_hugetlb(Object *o, Error **errp)
{
    return MEMORY_BACKEND_MEMFD_PRIVATE(o)->hugetlb;
}

static void
priv_memfd_backend_set_hugetlb(Object *o, bool value, Error **errp)
{
    MEMORY_BACKEND_MEMFD_PRIVATE(o)->hugetlb = value;
}

static void
priv_memfd_backend_set_hugetlbsize(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);
    uint64_t value;

    if (host_memory_backend_mr_inited(MEMORY_BACKEND(obj))) {
        error_setg(errp, "cannot change property value");
        return;
    }

    if (!visit_type_size(v, name, &value, errp)) {
        return;
    }
    if (!value) {
        error_setg(errp, "Property '%s.%s' doesn't take value '%" PRIu64 "'",
                   object_get_typename(obj), name, value);
        return;
    }
    m->hugetlbsize = value;
}

static void
priv_memfd_backend_get_hugetlbsize(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);
    uint64_t value = m->hugetlbsize;

    visit_type_size(v, name, &value, errp);
}

static void
priv_memfd_backend_instance_init(Object *obj)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);

    m->block_size = qemu_real_host_page_size();
    QLIST_INIT(&m->rdl_list);

    MEMORY_BACKEND(obj)->reserve = false;
}

/*
 * Adjust the memory section to cover the intersection with the given range.
 *
 * Returns false if the intersection is empty, otherwise returns true.
 */
static bool
priv_memfd_backend_intersect_memory_section(MemoryRegionSection *s,
                                            uint64_t offset, uint64_t size)
{
    uint64_t start = MAX(s->offset_within_region, offset);
    uint64_t end = MIN(s->offset_within_region + int128_get64(s->size),
                       offset + size);

    if (end <= start) {
        return false;
    }

    s->offset_within_address_space += start - s->offset_within_region;
    s->offset_within_region = start;
    s->size = int128_make64(end - start);
    return true;
}

static uint64_t
priv_memfd_backend_rdm_get_min_granularity(const RamDiscardManager *rdm,
                                           const MemoryRegion *mr)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(rdm);
    HostMemoryBackend *backend = MEMORY_BACKEND(rdm);

    g_assert(mr == &backend->mr);
    return m->block_size;
}

static bool
priv_memfd_backend_valid_range(const HostMemoryBackendPrivateMemfd *memfd,
                               uint64_t offset, uint64_t size)
{
    MemoryRegion *mr = &(MEMORY_BACKEND(memfd)->mr);
    uint64_t region_size = memory_region_size(mr);
    if (!QEMU_IS_ALIGNED(offset, memfd->block_size)) {
        return false;
    }
    if (offset + size < offset || !size) {
        return false;
    }
    if (offset >= region_size || offset + size > region_size) {
        return false;
    }
    return true;
}

static void priv_memfd_backend_rdm_register_listener(RamDiscardManager *rdm,
                                                     RamDiscardListener *rdl,
                                                     MemoryRegionSection *s)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(rdm);
    HostMemoryBackend *backend = MEMORY_BACKEND(rdm);

    g_assert(s->mr == &backend->mr);
    rdl->section = memory_region_section_new_copy(s);

    QLIST_INSERT_HEAD(&m->rdl_list, rdl, next);
}

static void priv_memfd_backend_rdm_unregister_listener(RamDiscardManager *rdm,
                                                       RamDiscardListener *rdl)
{
    HostMemoryBackend *backend = MEMORY_BACKEND(rdm);

    g_assert(rdl->section->mr == &backend->mr);

    memory_region_section_free_copy(rdl->section);
    rdl->section = NULL;
    QLIST_REMOVE(rdl, next);
}

static void
priv_memfd_backend_notify_discard(HostMemoryBackendPrivateMemfd *memfd,
                                  uint64_t offset, uint64_t size)
{
    RamDiscardListener *rdl;

    QLIST_FOREACH(rdl, &memfd->rdl_list, next) {
        MemoryRegionSection tmp = *rdl->section;

        if (!priv_memfd_backend_intersect_memory_section(&tmp, offset, size)) {
            continue;
        }
        rdl->notify_discard(rdl, &tmp);
    }
}

static int
priv_memfd_backend_notify_populate(HostMemoryBackendPrivateMemfd *memfd,
                                   uint64_t offset, uint64_t size)
{
    RamDiscardListener *rdl, *rdl2;
    int ret = 0;

    QLIST_FOREACH(rdl, &memfd->rdl_list, next) {
        MemoryRegionSection tmp = *rdl->section;

        if (!priv_memfd_backend_intersect_memory_section(&tmp, offset, size)) {
            continue;
        }
        ret = rdl->notify_populate(rdl, &tmp);
        if (ret) {
            break;
        }
    }

    if (ret) {
        /* Notify all already-notified listeners. */
        QLIST_FOREACH(rdl2, &memfd->rdl_list, next) {
            MemoryRegionSection tmp = *rdl2->section;

            if (rdl2 == rdl) {
                break;
            }
            if (!priv_memfd_backend_intersect_memory_section(&tmp, offset, size)) {
                continue;
            }
            rdl2->notify_discard(rdl2, &tmp);
        }
    }
    return ret;
}

static int
priv_memfd_backend_state_change_notify(HostMemoryBackendPrivateMemfd *memfd,
                                       uint64_t offset, uint64_t size, bool shared)
{
    int ret = 0;

    if (!QEMU_IS_ALIGNED(offset, memfd->block_size) ||
        !QEMU_IS_ALIGNED(size, memfd->block_size)) {
        return -1;
    }

    if (!shared) {
        priv_memfd_backend_notify_discard(memfd, offset, size);
    } else {
        ret = priv_memfd_backend_notify_populate(memfd, offset, size);
    }

    return ret;
}

int priv_memfd_backend_state_change(HostMemoryBackendPrivateMemfd *memfd,
                                    uint64_t offset, uint64_t size,
                                    bool shared)
{
    if (!priv_memfd_backend_valid_range(memfd, offset, size)) {
        error_report("%s, invalid range: offset 0x%lx, size 0x%lx", __func__, offset, size);
        return -1;
    }

    return priv_memfd_backend_state_change_notify(memfd, offset, size, shared);
}

static bool priv_memfd_backend_rdm_is_populated(const RamDiscardManager *rdm,
                                                const MemoryRegionSection *s)
{
    return 0;
}

static int priv_memfd_backend_replay_populated(const RamDiscardManager *rdm,
                                               MemoryRegionSection *s,
                                               ReplayRamPopulate replay_fn,
                                               void *opaque)
{
    return 0;
}

static void priv_memfd_backend_replay_discarded(const RamDiscardManager *rdm,
                                                MemoryRegionSection *s,
                                                ReplayRamDiscard replay_fn,
                                                void *opaque)
{
    return;
}

static void
priv_memfd_backend_class_init(ObjectClass *oc, void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);
    RamDiscardManagerClass *rdmc = RAM_DISCARD_MANAGER_CLASS(oc);

    bc->alloc = priv_memfd_backend_memory_alloc;

    if (qemu_memfd_check(MFD_HUGETLB)) {
        object_class_property_add_bool(oc, "hugetlb",
                                       priv_memfd_backend_get_hugetlb,
                                       priv_memfd_backend_set_hugetlb);
        object_class_property_set_description(oc, "hugetlb",
                                              "Use huge pages");
        object_class_property_add(oc, "hugetlbsize", "int",
                                  priv_memfd_backend_get_hugetlbsize,
                                  priv_memfd_backend_set_hugetlbsize,
                                  NULL, NULL);
        object_class_property_set_description(oc, "hugetlbsize",
                                              "Huge pages size (ex: 2M, 1G)");
    }

    rdmc->get_min_granularity = priv_memfd_backend_rdm_get_min_granularity;
    rdmc->register_listener = priv_memfd_backend_rdm_register_listener;
    rdmc->unregister_listener = priv_memfd_backend_rdm_unregister_listener;
    rdmc->is_populated = priv_memfd_backend_rdm_is_populated;
    rdmc->replay_populated = priv_memfd_backend_replay_populated;
    rdmc->replay_discarded = priv_memfd_backend_replay_discarded;
}

static const TypeInfo priv_memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_MEMFD_PRIVATE,
    .parent = TYPE_MEMORY_BACKEND,
    .instance_init = priv_memfd_backend_instance_init,
    .class_init = priv_memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendPrivateMemfd),
    .interfaces = (InterfaceInfo[]) {
        { TYPE_RAM_DISCARD_MANAGER },
        { }
    },
};

static void register_types(void)
{
    if (qemu_memfd_check(MFD_ALLOW_SEALING)) {
        type_register_static(&priv_memfd_backend_info);
    }
}

type_init(register_types);
