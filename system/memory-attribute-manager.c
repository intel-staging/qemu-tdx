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

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "exec/ramblock.h"
#include "system/memory-attribute-manager.h"

OBJECT_DEFINE_TYPE_WITH_INTERFACES(MemoryAttributeManager,
                                   memory_attribute_manager,
                                   MEMORY_ATTRIBUTE_MANAGER,
                                   OBJECT,
                                   { TYPE_RAM_DISCARD_MANAGER },
                                   { })

static size_t memory_attribute_manager_get_block_size(const MemoryAttributeManager *mgr)
{
    /*
     * Because page conversion could be manipulated in the size of at least 4K or 4K aligned,
     * Use the host page size as the granularity to track the memory attribute.
     */
    g_assert(mgr && mgr->mr && mgr->mr->ram_block);
    g_assert(mgr->mr->ram_block->page_size == qemu_real_host_page_size());
    return mgr->mr->ram_block->page_size;
}


static bool memory_attribute_rdm_is_populated(const RamDiscardManager *rdm,
                                              const MemoryRegionSection *section)
{
    const MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    const int block_size = memory_attribute_manager_get_block_size(mgr);
    uint64_t first_bit = section->offset_within_region / block_size;
    uint64_t last_bit = first_bit + int128_get64(section->size) / block_size - 1;
    unsigned long first_discard_bit;

    first_discard_bit = find_next_zero_bit(mgr->shared_bitmap, last_bit + 1, first_bit);
    return first_discard_bit > last_bit;
}

typedef int (*memory_attribute_section_cb)(MemoryRegionSection *s, void *arg);

static int memory_attribute_notify_populate_cb(MemoryRegionSection *section, void *arg)
{
    RamDiscardListener *rdl = arg;

    return rdl->notify_populate(rdl, section);
}

static int memory_attribute_notify_discard_cb(MemoryRegionSection *section, void *arg)
{
    RamDiscardListener *rdl = arg;

    rdl->notify_discard(rdl, section);

    return 0;
}

static int memory_attribute_for_each_populated_section(const MemoryAttributeManager *mgr,
                                                       MemoryRegionSection *section,
                                                       void *arg,
                                                       memory_attribute_section_cb cb)
{
    unsigned long first_bit, last_bit;
    uint64_t offset, size;
    const int block_size = memory_attribute_manager_get_block_size(mgr);
    int ret = 0;

    first_bit = section->offset_within_region / block_size;
    first_bit = find_next_bit(mgr->shared_bitmap, mgr->shared_bitmap_size, first_bit);

    while (first_bit < mgr->shared_bitmap_size) {
        MemoryRegionSection tmp = *section;

        offset = first_bit * block_size;
        last_bit = find_next_zero_bit(mgr->shared_bitmap, mgr->shared_bitmap_size,
                                      first_bit + 1) - 1;
        size = (last_bit - first_bit + 1) * block_size;

        if (!memory_region_section_intersect_range(&tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            error_report("%s: Failed to notify RAM discard listener: %s", __func__,
                         strerror(-ret));
            break;
        }

        first_bit = find_next_bit(mgr->shared_bitmap, mgr->shared_bitmap_size,
                                  last_bit + 2);
    }

    return ret;
}

static int memory_attribute_for_each_discarded_section(const MemoryAttributeManager *mgr,
                                                       MemoryRegionSection *section,
                                                       void *arg,
                                                       memory_attribute_section_cb cb)
{
    unsigned long first_bit, last_bit;
    uint64_t offset, size;
    const int block_size = memory_attribute_manager_get_block_size(mgr);
    int ret = 0;

    first_bit = section->offset_within_region / block_size;
    first_bit = find_next_zero_bit(mgr->shared_bitmap, mgr->shared_bitmap_size,
                                   first_bit);

    while (first_bit < mgr->shared_bitmap_size) {
        MemoryRegionSection tmp = *section;

        offset = first_bit * block_size;
        last_bit = find_next_bit(mgr->shared_bitmap, mgr->shared_bitmap_size,
                                      first_bit + 1) - 1;
        size = (last_bit - first_bit + 1) * block_size;

        if (!memory_region_section_intersect_range(&tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            error_report("%s: Failed to notify RAM discard listener: %s", __func__,
                         strerror(-ret));
            break;
        }

        first_bit = find_next_zero_bit(mgr->shared_bitmap, mgr->shared_bitmap_size,
                                       last_bit + 2);
    }

    return ret;
}

static uint64_t memory_attribute_rdm_get_min_granularity(const RamDiscardManager *rdm,
                                                         const MemoryRegion *mr)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);

    g_assert(mr == mgr->mr);
    return memory_attribute_manager_get_block_size(mgr);
}

static void memory_attribute_rdm_register_listener(RamDiscardManager *rdm,
                                                   RamDiscardListener *rdl,
                                                   MemoryRegionSection *section)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    int ret;

    g_assert(section->mr == mgr->mr);
    rdl->section = memory_region_section_new_copy(section);

    QLIST_INSERT_HEAD(&mgr->rdl_list, rdl, next);

    ret = memory_attribute_for_each_populated_section(mgr, section, rdl,
                                                      memory_attribute_notify_populate_cb);
    if (ret) {
        error_report("%s: Failed to register RAM discard listener: %s", __func__,
                     strerror(-ret));
    }
}

static void memory_attribute_rdm_unregister_listener(RamDiscardManager *rdm,
                                                     RamDiscardListener *rdl)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    int ret;

    g_assert(rdl->section);
    g_assert(rdl->section->mr == mgr->mr);

    ret = memory_attribute_for_each_populated_section(mgr, rdl->section, rdl,
                                                      memory_attribute_notify_discard_cb);
    if (ret) {
        error_report("%s: Failed to unregister RAM discard listener: %s", __func__,
                     strerror(-ret));
    }

    memory_region_section_free_copy(rdl->section);
    rdl->section = NULL;
    QLIST_REMOVE(rdl, next);

}

typedef struct MemoryAttributeReplayData {
    ReplayRamStateChange fn;
    void *opaque;
} MemoryAttributeReplayData;

static int memory_attribute_rdm_replay_cb(MemoryRegionSection *section, void *arg)
{
    MemoryAttributeReplayData *data = arg;

    return data->fn(section, data->opaque);
}

static int memory_attribute_rdm_replay_populated(const RamDiscardManager *rdm,
                                                 MemoryRegionSection *section,
                                                 ReplayRamStateChange replay_fn,
                                                 void *opaque)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    MemoryAttributeReplayData data = { .fn = replay_fn, .opaque = opaque };

    g_assert(section->mr == mgr->mr);
    return memory_attribute_for_each_populated_section(mgr, section, &data,
                                                       memory_attribute_rdm_replay_cb);
}

static int memory_attribute_rdm_replay_discarded(const RamDiscardManager *rdm,
                                                 MemoryRegionSection *section,
                                                 ReplayRamStateChange replay_fn,
                                                 void *opaque)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    MemoryAttributeReplayData data = { .fn = replay_fn, .opaque = opaque };

    g_assert(section->mr == mgr->mr);
    return memory_attribute_for_each_discarded_section(mgr, section, &data,
                                                       memory_attribute_rdm_replay_cb);
}

int memory_attribute_manager_realize(MemoryAttributeManager *mgr, MemoryRegion *mr)
{
    uint64_t shared_bitmap_size;
    const int block_size  = qemu_real_host_page_size();
    int ret;

    shared_bitmap_size = ROUND_UP(mr->size, block_size) / block_size;

    mgr->mr = mr;
    ret = memory_region_set_ram_discard_manager(mgr->mr, RAM_DISCARD_MANAGER(mgr));
    if (ret) {
        return ret;
    }
    mgr->shared_bitmap_size = shared_bitmap_size;
    mgr->shared_bitmap = bitmap_new(shared_bitmap_size);

    return ret;
}

void memory_attribute_manager_unrealize(MemoryAttributeManager *mgr)
{
    g_free(mgr->shared_bitmap);
    memory_region_set_ram_discard_manager(mgr->mr, NULL);
}

static void memory_attribute_manager_init(Object *obj)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(obj);

    QLIST_INIT(&mgr->rdl_list);
}

static void memory_attribute_manager_finalize(Object *obj)
{
}

static void memory_attribute_manager_class_init(ObjectClass *oc, void *data)
{
    RamDiscardManagerClass *rdmc = RAM_DISCARD_MANAGER_CLASS(oc);

    rdmc->get_min_granularity = memory_attribute_rdm_get_min_granularity;
    rdmc->register_listener = memory_attribute_rdm_register_listener;
    rdmc->unregister_listener = memory_attribute_rdm_unregister_listener;
    rdmc->is_populated = memory_attribute_rdm_is_populated;
    rdmc->replay_populated = memory_attribute_rdm_replay_populated;
    rdmc->replay_discarded = memory_attribute_rdm_replay_discarded;
}
