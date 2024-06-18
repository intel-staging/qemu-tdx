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
#include "system/memory-attribute-manager.h"

OBJECT_DEFINE_TYPE_WITH_INTERFACES(MemoryAttributeManager,
                                   memory_attribute_manager,
                                   MEMORY_ATTRIBUTE_MANAGER,
                                   OBJECT,
                                   { TYPE_RAM_DISCARD_MANAGER },
                                   { })

static int memory_attribute_manager_get_block_size(const MemoryAttributeManager *mgr)
{
    /*
     * Because page conversion could be manipulated in the size of at least 4K or 4K aligned,
     * Use the host page size as the granularity to track the memory attribute.
     * TODO: if necessary, switch to get the page_size from RAMBlock.
     * i.e. mgr->mr->ram_block->page_size.
     */
    return qemu_real_host_page_size();
}


static bool memory_attribute_rdm_is_populated(const RamDiscardManager *rdm,
                                              const MemoryRegionSection *section)
{
    const MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    int block_size = memory_attribute_manager_get_block_size(mgr);
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
    unsigned long first_one_bit, last_one_bit;
    uint64_t offset, size;
    int block_size = memory_attribute_manager_get_block_size(mgr);
    int ret = 0;

    first_one_bit = section->offset_within_region / block_size;
    first_one_bit = find_next_bit(mgr->shared_bitmap, mgr->bitmap_size, first_one_bit);

    while (first_one_bit < mgr->bitmap_size) {
        MemoryRegionSection tmp = *section;

        offset = first_one_bit * block_size;
        last_one_bit = find_next_zero_bit(mgr->shared_bitmap, mgr->bitmap_size,
                                          first_one_bit + 1) - 1;
        size = (last_one_bit - first_one_bit + 1) * block_size;

        if (!memory_region_section_intersect_range(&tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            error_report("%s: Failed to notify RAM discard listener: %s", __func__,
                         strerror(-ret));
            break;
        }

        first_one_bit = find_next_bit(mgr->shared_bitmap, mgr->bitmap_size,
                                      last_one_bit + 2);
    }

    return ret;
}

static int memory_attribute_for_each_discarded_section(const MemoryAttributeManager *mgr,
                                                       MemoryRegionSection *section,
                                                       void *arg,
                                                       memory_attribute_section_cb cb)
{
    unsigned long first_zero_bit, last_zero_bit;
    uint64_t offset, size;
    int block_size = memory_attribute_manager_get_block_size(mgr);
    int ret = 0;

    first_zero_bit = section->offset_within_region / block_size;
    first_zero_bit = find_next_zero_bit(mgr->shared_bitmap, mgr->bitmap_size,
                                        first_zero_bit);

    while (first_zero_bit < mgr->bitmap_size) {
        MemoryRegionSection tmp = *section;

        offset = first_zero_bit * block_size;
        last_zero_bit = find_next_bit(mgr->shared_bitmap, mgr->bitmap_size,
                                      first_zero_bit + 1) - 1;
        size = (last_zero_bit - first_zero_bit + 1) * block_size;

        if (!memory_region_section_intersect_range(&tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            error_report("%s: Failed to notify RAM discard listener: %s", __func__,
                         strerror(-ret));
            break;
        }

        first_zero_bit = find_next_zero_bit(mgr->shared_bitmap, mgr->bitmap_size,
                                            last_zero_bit + 2);
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
    void *fn;
    void *opaque;
} MemoryAttributeReplayData;

static int memory_attribute_rdm_replay_populated_cb(MemoryRegionSection *section, void *arg)
{
    MemoryAttributeReplayData *data = arg;

    return ((ReplayRamPopulate)data->fn)(section, data->opaque);
}

static int memory_attribute_rdm_replay_populated(const RamDiscardManager *rdm,
                                                 MemoryRegionSection *section,
                                                 ReplayRamPopulate replay_fn,
                                                 void *opaque)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    MemoryAttributeReplayData data = { .fn = replay_fn, .opaque = opaque };

    g_assert(section->mr == mgr->mr);
    return memory_attribute_for_each_populated_section(mgr, section, &data,
                                                       memory_attribute_rdm_replay_populated_cb);
}

static int memory_attribute_rdm_replay_discarded_cb(MemoryRegionSection *section, void *arg)
{
    MemoryAttributeReplayData *data = arg;

    ((ReplayRamDiscard)data->fn)(section, data->opaque);
    return 0;
}

static void memory_attribute_rdm_replay_discarded(const RamDiscardManager *rdm,
                                                  MemoryRegionSection *section,
                                                  ReplayRamDiscard replay_fn,
                                                  void *opaque)
{
    MemoryAttributeManager *mgr = MEMORY_ATTRIBUTE_MANAGER(rdm);
    MemoryAttributeReplayData data = { .fn = replay_fn, .opaque = opaque };

    g_assert(section->mr == mgr->mr);
    memory_attribute_for_each_discarded_section(mgr, section, &data,
                                                memory_attribute_rdm_replay_discarded_cb);
}

static bool memory_attribute_is_valid_range(MemoryAttributeManager *mgr,
                                            uint64_t offset, uint64_t size)
{
    MemoryRegion *mr = mgr->mr;

    g_assert(mr);

    uint64_t region_size = memory_region_size(mr);
    int block_size = memory_attribute_manager_get_block_size(mgr);

    if (!QEMU_IS_ALIGNED(offset, block_size)) {
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

static void memory_attribute_notify_discard(MemoryAttributeManager *mgr,
                                            uint64_t offset, uint64_t size)
{
    RamDiscardListener *rdl;

    QLIST_FOREACH(rdl, &mgr->rdl_list, next) {
        MemoryRegionSection tmp = *rdl->section;

        if (!memory_region_section_intersect_range(&tmp, offset, size)) {
            continue;
        }

        memory_attribute_for_each_populated_section(mgr, &tmp, rdl,
                                                    memory_attribute_notify_discard_cb);
    }
}

static int memory_attribute_notify_populate(MemoryAttributeManager *mgr,
                                            uint64_t offset, uint64_t size)
{
    RamDiscardListener *rdl, *rdl2;
    int ret = 0;

    QLIST_FOREACH(rdl, &mgr->rdl_list, next) {
        MemoryRegionSection tmp = *rdl->section;

        if (!memory_region_section_intersect_range(&tmp, offset, size)) {
            continue;
        }

        ret = memory_attribute_for_each_discarded_section(mgr, &tmp, rdl,
                                                          memory_attribute_notify_populate_cb);
        if (ret) {
            break;
        }
    }

    if (ret) {
        /* Notify all already-notified listeners. */
        QLIST_FOREACH(rdl2, &mgr->rdl_list, next) {
            MemoryRegionSection tmp = *rdl2->section;

            if (rdl2 == rdl) {
                break;
            }
            if (!memory_region_section_intersect_range(&tmp, offset, size)) {
                continue;
            }

            memory_attribute_for_each_discarded_section(mgr, &tmp, rdl2,
                                                        memory_attribute_notify_discard_cb);
        }
    }
    return ret;
}

static bool memory_attribute_is_range_populated(MemoryAttributeManager *mgr,
                                                uint64_t offset, uint64_t size)
{
    int block_size = memory_attribute_manager_get_block_size(mgr);
    const unsigned long first_bit = offset / block_size;
    const unsigned long last_bit = first_bit + (size / block_size) - 1;
    unsigned long found_bit;

    /* We fake a shorter bitmap to avoid searching too far. */
    found_bit = find_next_zero_bit(mgr->shared_bitmap, last_bit + 1, first_bit);
    return found_bit > last_bit;
}

static bool memory_attribute_is_range_discarded(MemoryAttributeManager *mgr,
                                                uint64_t offset, uint64_t size)
{
    int block_size = memory_attribute_manager_get_block_size(mgr);
    const unsigned long first_bit = offset / block_size;
    const unsigned long last_bit = first_bit + (size / block_size) - 1;
    unsigned long found_bit;

    /* We fake a shorter bitmap to avoid searching too far. */
    found_bit = find_next_bit(mgr->shared_bitmap, last_bit + 1, first_bit);
    return found_bit > last_bit;
}

static int memory_attribute_state_change(MemoryAttributeManager *mgr, uint64_t offset,
                                         uint64_t size, bool shared_to_private)
{
    int block_size = memory_attribute_manager_get_block_size(mgr);
    int ret = 0;

    if (!memory_attribute_is_valid_range(mgr, offset, size)) {
        error_report("%s, invalid range: offset 0x%lx, size 0x%lx",
                     __func__, offset, size);
        return -1;
    }

    if ((shared_to_private && memory_attribute_is_range_discarded(mgr, offset, size)) ||
        (!shared_to_private && memory_attribute_is_range_populated(mgr, offset, size))) {
        return 0;
    }

    if (shared_to_private) {
        memory_attribute_notify_discard(mgr, offset, size);
    } else {
        ret = memory_attribute_notify_populate(mgr, offset, size);
    }

    if (!ret) {
        unsigned long first_bit = offset / block_size;
        unsigned long nbits = size / block_size;

        g_assert((first_bit + nbits) <= mgr->bitmap_size);

        if (shared_to_private) {
            bitmap_clear(mgr->shared_bitmap, first_bit, nbits);
        } else {
            bitmap_set(mgr->shared_bitmap, first_bit, nbits);
        }

        return 0;
    }

    return ret;
}

int memory_attribute_manager_realize(MemoryAttributeManager *mgr, MemoryRegion *mr)
{
    uint64_t bitmap_size;
    int block_size = memory_attribute_manager_get_block_size(mgr);
    int ret;

    bitmap_size = ROUND_UP(mr->size, block_size) / block_size;

    mgr->mr = mr;
    mgr->bitmap_size = bitmap_size;
    mgr->shared_bitmap = bitmap_new(bitmap_size);

    ret = memory_region_set_ram_discard_manager(mgr->mr, RAM_DISCARD_MANAGER(mgr));
    if (ret) {
        g_free(mgr->shared_bitmap);
    }

    return ret;
}

void memory_attribute_manager_unrealize(MemoryAttributeManager *mgr)
{
    memory_region_set_ram_discard_manager(mgr->mr, NULL);

    g_free(mgr->shared_bitmap);
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
    MemoryAttributeManagerClass *mamc = MEMORY_ATTRIBUTE_MANAGER_CLASS(oc);
    RamDiscardManagerClass *rdmc = RAM_DISCARD_MANAGER_CLASS(oc);

    mamc->state_change = memory_attribute_state_change;

    rdmc->get_min_granularity = memory_attribute_rdm_get_min_granularity;
    rdmc->register_listener = memory_attribute_rdm_register_listener;
    rdmc->unregister_listener = memory_attribute_rdm_unregister_listener;
    rdmc->is_populated = memory_attribute_rdm_is_populated;
    rdmc->replay_populated = memory_attribute_rdm_replay_populated;
    rdmc->replay_discarded = memory_attribute_rdm_replay_discarded;
}
