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

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "sysemu/guest-memfd-manager.h"

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(GuestMemfdManager,
                                          guest_memfd_manager,
                                          GUEST_MEMFD_MANAGER,
                                          OBJECT,
                                          { TYPE_RAM_DISCARD_MANAGER },
                                          { })

static bool guest_memfd_rdm_is_populated(const RamDiscardManager *rdm,
                                         const MemoryRegionSection *section)
{
    const GuestMemfdManager *gmm = GUEST_MEMFD_MANAGER(rdm);
    uint64_t first_bit = section->offset_within_region / gmm->block_size;
    uint64_t last_bit = first_bit + int128_get64(section->size) / gmm->block_size - 1;
    unsigned long first_discard_bit;

    first_discard_bit = find_next_bit(gmm->discard_bitmap, last_bit + 1, first_bit);
    return first_discard_bit > last_bit;
}

static bool guest_memfd_rdm_intersect_memory_section(MemoryRegionSection *section,
                                                     uint64_t offset, uint64_t size)
{
    uint64_t start = MAX(section->offset_within_region, offset);
    uint64_t end = MIN(section->offset_within_region + int128_get64(section->size),
                       offset + size);
    if (end <= start) {
        return false;
    }

    section->offset_within_address_space += start - section->offset_within_region;
    section->offset_within_region = start;
    section->size = int128_make64(end - start);

    return true;
}

typedef int (*guest_memfd_section_cb)(MemoryRegionSection *s, void *arg);

static int guest_memfd_notify_populate_cb(MemoryRegionSection *section, void *arg)
{
    RamDiscardListener *rdl = arg;

    return rdl->notify_populate(rdl, section);
}

static int guest_memfd_notify_discard_cb(MemoryRegionSection *section, void *arg)
{
    RamDiscardListener *rdl = arg;

    rdl->notify_discard(rdl, section);

    return 0;
}

static int guest_memfd_for_each_populated_range(const GuestMemfdManager *gmm,
                                                MemoryRegionSection *section,
                                                void *arg,
                                                guest_memfd_section_cb cb)
{
    unsigned long first_zero_bit, last_zero_bit;
    uint64_t offset, size;
    int ret = 0;

    first_zero_bit = section->offset_within_region / gmm->block_size;
    first_zero_bit = find_next_zero_bit(gmm->discard_bitmap, gmm->discard_bitmap_size,
                                        first_zero_bit);

    while (first_zero_bit < gmm->discard_bitmap_size) {
        MemoryRegionSection tmp = *section;

        offset = first_zero_bit * gmm->block_size;
        last_zero_bit = find_next_bit(gmm->discard_bitmap, gmm->discard_bitmap_size,
                                      first_zero_bit + 1) - 1;
        size = (last_zero_bit - first_zero_bit + 1) * gmm->block_size;

        if (!guest_memfd_rdm_intersect_memory_section(&tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            break;
        }

        first_zero_bit = find_next_zero_bit(gmm->discard_bitmap, gmm->discard_bitmap_size,
                                            last_zero_bit + 2);
    }

    return ret;
}

static uint64_t guest_memfd_rdm_get_min_granularity(const RamDiscardManager *rdm,
                                                    const MemoryRegion *mr)
{
    GuestMemfdManager *gmm = GUEST_MEMFD_MANAGER(rdm);

    g_assert(mr == gmm->mr);
    return gmm->block_size;
}

static void guest_memfd_rdm_register_listener(RamDiscardManager *rdm,
                                              RamDiscardListener *rdl,
                                              MemoryRegionSection *section)
{
    GuestMemfdManager *gmm = GUEST_MEMFD_MANAGER(rdm);
    int ret;

    g_assert(section->mr == gmm->mr);
    rdl->section = memory_region_section_new_copy(section);

    QLIST_INSERT_HEAD(&gmm->rdl_list, rdl, next);

    ret = guest_memfd_for_each_populated_range(gmm, section, rdl,
                                               guest_memfd_notify_populate_cb);
    if (ret) {
        error_report("%s: Failed to register RAM discard listener: %s", __func__,
                     strerror(-ret));
    }
}

static void guest_memfd_rdm_unregister_listener(RamDiscardManager *rdm,
                                                RamDiscardListener *rdl)
{
    GuestMemfdManager *gmm = GUEST_MEMFD_MANAGER(rdm);
    int ret;

    g_assert(rdl->section);
    g_assert(rdl->section->mr == gmm->mr);

    ret = guest_memfd_for_each_populated_range(gmm, rdl->section, rdl,
                                               guest_memfd_notify_discard_cb);
    if (ret) {
        error_report("%s: Failed to unregister RAM discard listener: %s", __func__,
                     strerror(-ret));
    }

    memory_region_section_free_copy(rdl->section);
    rdl->section = NULL;
    QLIST_REMOVE(rdl, next);

}

static int guest_memfd_for_each_discarded_range(const GuestMemfdManager *gmm,
                                                MemoryRegionSection *section,
                                                void *arg,
                                                guest_memfd_section_cb cb)
{
    unsigned long first_one_bit, last_one_bit;
    uint64_t offset, size;
    int ret = 0;

    first_one_bit = section->offset_within_region / gmm->block_size;
    first_one_bit = find_next_bit(gmm->discard_bitmap, gmm->discard_bitmap_size,
                                  first_one_bit);

    while (first_one_bit < gmm->discard_bitmap_size) {
        MemoryRegionSection tmp = *section;

        offset = first_one_bit * gmm->block_size;
        last_one_bit = find_next_zero_bit(gmm->discard_bitmap, gmm->discard_bitmap_size,
                                          first_one_bit + 1) - 1;
        size = (last_one_bit - first_one_bit + 1) * gmm->block_size;

        if (!guest_memfd_rdm_intersect_memory_section(&tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            break;
        }

        first_one_bit = find_next_bit(gmm->discard_bitmap, gmm->discard_bitmap_size,
                                      last_one_bit + 2);
    }

    return ret;
}

typedef struct GuestMemfdReplayData {
    void *fn;
    void *opaque;
} GuestMemfdReplayData;

static int guest_memfd_rdm_replay_populated_cb(MemoryRegionSection *section, void *arg)
{
    struct GuestMemfdReplayData *data = arg;
    ReplayRamPopulate replay_fn = data->fn;

    return replay_fn(section, data->opaque);
}

static int guest_memfd_rdm_replay_populated(const RamDiscardManager *rdm,
                                            MemoryRegionSection *section,
                                            ReplayRamPopulate replay_fn,
                                            void *opaque)
{
    GuestMemfdManager *gmm = GUEST_MEMFD_MANAGER(rdm);
    struct GuestMemfdReplayData data = { .fn = replay_fn, .opaque = opaque };

    g_assert(section->mr == gmm->mr);
    return guest_memfd_for_each_populated_range(gmm, section, &data,
                                                guest_memfd_rdm_replay_populated_cb);
}

static int guest_memfd_rdm_replay_discarded_cb(MemoryRegionSection *section, void *arg)
{
    struct GuestMemfdReplayData *data = arg;
    ReplayRamDiscard replay_fn = data->fn;

    replay_fn(section, data->opaque);

    return 0;
}

static void guest_memfd_rdm_replay_discarded(const RamDiscardManager *rdm,
                                             MemoryRegionSection *section,
                                             ReplayRamDiscard replay_fn,
                                             void *opaque)
{
    GuestMemfdManager *gmm = GUEST_MEMFD_MANAGER(rdm);
    struct GuestMemfdReplayData data = { .fn = replay_fn, .opaque = opaque };

    g_assert(section->mr == gmm->mr);
    guest_memfd_for_each_discarded_range(gmm, section, &data,
                                         guest_memfd_rdm_replay_discarded_cb);
}

static void guest_memfd_manager_init(Object *obj)
{
    GuestMemfdManager *gmm = GUEST_MEMFD_MANAGER(obj);

    gmm->discard_bitmap_size = 0;
    gmm->discard_bitmap = NULL;
    gmm->block_size = qemu_real_host_page_size();
    QLIST_INIT(&gmm->rdl_list);
}

static void guest_memfd_manager_finalize(Object *obj)
{
}

static void guest_memfd_manager_class_init(ObjectClass *oc, void *data)
{
    RamDiscardManagerClass *rdmc = RAM_DISCARD_MANAGER_CLASS(oc);

    rdmc->get_min_granularity = guest_memfd_rdm_get_min_granularity;
    rdmc->register_listener = guest_memfd_rdm_register_listener;
    rdmc->unregister_listener = guest_memfd_rdm_unregister_listener;
    rdmc->is_populated = guest_memfd_rdm_is_populated;
    rdmc->replay_populated = guest_memfd_rdm_replay_populated;
    rdmc->replay_discarded = guest_memfd_rdm_replay_discarded;
}
