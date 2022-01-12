/*
 * QEMU TDX support
 *
 * Copyright Intel
 *
 * Author:
 *      Xiaoyao Li <xiaoyao.li@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory
 *
 */

#include "qemu/osdep.h"
#include "qemu/mmap-alloc.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"

#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/x86.h"
#include "hw/i386/tdvf.h"
#include "hw/i386/tdvf-hob.h"
#include "kvm_i386.h"
#include "tdx.h"

#define TDX_SUPPORTED_KVM_FEATURES  ((1ULL << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1ULL << KVM_FEATURE_STEAL_TIME) | \
                                     (1ULL << KVM_FEATURE_PV_EOI) | \
                                     (1ULL << KVM_FEATURE_PV_UNHALT) | \
                                     (1ULL << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1ULL << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1ULL << KVM_FEATURE_POLL_CONTROL) | \
                                     (1ULL << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1ULL << KVM_FEATURE_MSI_EXT_DEST_ID))

#define TDX_TD_ATTRIBUTES_DEBUG             BIT_ULL(0)
#define TDX_TD_ATTRIBUTES_PKS               BIT_ULL(30)
#define TDX_TD_ATTRIBUTES_PERFMON           BIT_ULL(63)

#define TDX_MIN_TSC_FREQUENCY_KHZ   (100 * 1000)
#define TDX_MAX_TSC_FREQUENCY_KHZ   (10 * 1000 * 1000)

static TdxGuest *tdx_guest;

/* It's valid after kvm_confidential_guest_init()->kvm_tdx_init() */
bool is_tdx_vm(void)
{
    return !!tdx_guest;
}

enum tdx_ioctl_level{
    TDX_PLATFORM_IOCTL,
    TDX_VM_IOCTL,
    TDX_VCPU_IOCTL,
};

static int __tdx_ioctl(void *state, enum tdx_ioctl_level level, int cmd_id,
                        __u32 flags, void *data)
{
    struct kvm_tdx_cmd tdx_cmd;
    int r;

    memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));

    tdx_cmd.id = cmd_id;
    tdx_cmd.flags = flags;
    tdx_cmd.data = (__u64)(unsigned long)data;

    switch (level) {
    case TDX_PLATFORM_IOCTL:
        r = kvm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    case TDX_VM_IOCTL:
        r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    case TDX_VCPU_IOCTL:
        r = kvm_vcpu_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    default:
        error_report("Invalid tdx_ioctl_level %d", level);
        exit(1);
    }

    return r;
}

static inline int tdx_platform_ioctl(int cmd_id, __u32 metadata, void *data)
{
    return __tdx_ioctl(NULL, TDX_PLATFORM_IOCTL, cmd_id, metadata, data);
}

static inline int tdx_vm_ioctl(int cmd_id, __u32 metadata, void *data)
{
    return __tdx_ioctl(NULL, TDX_VM_IOCTL, cmd_id, metadata, data);
}

static inline int tdx_vcpu_ioctl(void *vcpu_fd, int cmd_id, __u32 metadata,
                                 void *data)
{
    return  __tdx_ioctl(vcpu_fd, TDX_VCPU_IOCTL, cmd_id, metadata, data);
}

static struct kvm_tdx_capabilities *tdx_caps;

static void get_tdx_capabilities(void)
{
    struct kvm_tdx_capabilities *caps;
    int max_ent = 1;
    int r, size;

    do {
        size = sizeof(struct kvm_tdx_capabilities) +
               max_ent * sizeof(struct kvm_tdx_cpuid_config);
        caps = g_malloc0(size);
        caps->nr_cpuid_configs = max_ent;

        r = tdx_platform_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
        if (r == -E2BIG) {
            g_free(caps);
            max_ent *= 2;
        } else if (r < 0) {
            error_report("KVM_TDX_CAPABILITIES failed: %s\n", strerror(-r));
            exit(1);
        }
    }
    while (r == -E2BIG);

    tdx_caps = caps;
}

static TdxFirmwareEntry *tdx_get_hob_entry(TdxGuest *tdx)
{
    TdxFirmwareEntry *entry;

    for_each_tdx_fw_entry(&tdx->tdvf, entry) {
        if (entry->type == TDVF_SECTION_TYPE_TD_HOB) {
            return entry;
        }
    }
    error_report("TDVF metadata doesn't specify TD_HOB location.");
    exit(1);
}

static void tdx_add_ram_entry(uint64_t address, uint64_t length, uint32_t type)
{
    uint32_t nr_entries = tdx_guest->nr_ram_entries;
    tdx_guest->ram_entries = g_renew(TdxRamEntry, tdx_guest->ram_entries,
                                     nr_entries + 1);

    tdx_guest->ram_entries[nr_entries].address = address;
    tdx_guest->ram_entries[nr_entries].length = length;
    tdx_guest->ram_entries[nr_entries].type = type;
    tdx_guest->nr_ram_entries++;
}

static int tdx_accept_ram_range(uint64_t address, uint64_t length)
{
    TdxRamEntry *e;
    int i;

    for (i = 0; i < tdx_guest->nr_ram_entries; i++) {
        e = &tdx_guest->ram_entries[i];

        if (address + length < e->address ||
            e->address + e->length < address) {
                continue;
        }

        if (e->address > address ||
            e->address + e->length < address + length) {
            return -EINVAL;
        }

        if (e->address == address && e->length == length) {
            e->type = TDX_RAM_ADDED;
        } else if (e->address == address) {
            e->address += length;
            e->length -= length;
            tdx_add_ram_entry(address, length, TDX_RAM_ADDED);
        } else if (e->address + e->length == address + length) {
            e->length -= length;
            tdx_add_ram_entry(address, length, TDX_RAM_ADDED);
        } else {
            TdxRamEntry tmp = {
                .address = e->address,
                .length = e->length,
            };
            e->length = address - tmp.address;

            tdx_add_ram_entry(address, length, TDX_RAM_ADDED);
            tdx_add_ram_entry(address + length,
                              tmp.address + tmp.length - (address + length),
                              TDX_RAM_UNACCEPTED);
        }

        return 0;
    }

    return -1;
}

static int tdx_ram_entry_compare(const void *lhs_, const void* rhs_)
{
    const TdxRamEntry *lhs = lhs_;
    const TdxRamEntry *rhs = rhs_;

    if (lhs->address == rhs->address) {
        return 0;
    }
    if (le64_to_cpu(lhs->address) > le64_to_cpu(rhs->address)) {
        return 1;
    }
    return -1;
}

static void tdx_init_ram_entries(void)
{
    unsigned i, j, nr_e820_entries;

    nr_e820_entries = e820_get_num_entries();
    tdx_guest->ram_entries = g_new(TdxRamEntry, nr_e820_entries);

    for (i = 0, j = 0; i < nr_e820_entries; i++) {
        uint64_t addr, len;

        if (e820_get_entry(i, E820_RAM, &addr, &len)) {
            tdx_guest->ram_entries[j].address = addr;
            tdx_guest->ram_entries[j].length = len;
            tdx_guest->ram_entries[j].type = TDX_RAM_UNACCEPTED;
            j++;
        }
    }
    tdx_guest->nr_ram_entries = j;
}

static void tdx_post_init_vcpus(void)
{
    TdxFirmwareEntry *hob;
    CPUState *cpu;
    int r;

    hob = tdx_get_hob_entry(tdx_guest);
    CPU_FOREACH(cpu) {
        r = tdx_vcpu_ioctl(cpu, KVM_TDX_INIT_VCPU, 0, (void *)hob->address);
        if (r < 0) {
            error_report("KVM_TDX_INIT_VCPU failed %s", strerror(-r));
            exit(1);
        }
    }
}

static void tdx_finalize_vm(Notifier *notifier, void *unused)
{
    TdxFirmware *tdvf = &tdx_guest->tdvf;
    TdxFirmwareEntry *entry;
    int r;

    tdx_init_ram_entries();

    for_each_tdx_fw_entry(tdvf, entry) {
        switch (entry->type) {
        case TDVF_SECTION_TYPE_BFV:
        case TDVF_SECTION_TYPE_CFV:
            entry->mem_ptr = tdvf->mem_ptr + entry->data_offset;
            break;
        case TDVF_SECTION_TYPE_TD_HOB:
        case TDVF_SECTION_TYPE_TEMP_MEM:
            entry->mem_ptr = qemu_ram_mmap(-1, entry->size,
                                           qemu_real_host_page_size(), 0, 0);
            tdx_accept_ram_range(entry->address, entry->size);
            break;
        default:
            error_report("Unsupported TDVF section %d", entry->type);
            exit(1);
        }
    }

    qsort(tdx_guest->ram_entries, tdx_guest->nr_ram_entries,
          sizeof(TdxRamEntry), &tdx_ram_entry_compare);

    tdvf_hob_create(tdx_guest, tdx_get_hob_entry(tdx_guest));

    tdx_post_init_vcpus();

    for_each_tdx_fw_entry(tdvf, entry) {
        struct kvm_tdx_init_mem_region mem_region = {
            .source_addr = (__u64)entry->mem_ptr,
            .gpa = entry->address,
            .nr_pages = entry->size / 4096,
        };

        __u32 metadata = entry->attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND ?
                         KVM_TDX_MEASURE_MEMORY_REGION : 0;

        r = tdx_vm_ioctl(KVM_TDX_INIT_MEM_REGION, metadata, &mem_region);
        if (r < 0) {
             error_report("KVM_TDX_INIT_MEM_REGION failed %s", strerror(-r));
             exit(1);
        }

        if (entry->type == TDVF_SECTION_TYPE_TD_HOB ||
            entry->type == TDVF_SECTION_TYPE_TEMP_MEM) {
            qemu_ram_munmap(-1, entry->mem_ptr, entry->size);
            entry->mem_ptr = NULL;
        }
    }

    r = tdx_vm_ioctl(KVM_TDX_FINALIZE_VM, 0, NULL);
    if (r < 0) {
        error_report("KVM_TDX_FINALIZE_VM failed %s", strerror(-r));
        exit(0);
    }
    tdx_guest->parent_obj.ready = true;
}

static Notifier tdx_machine_done_notify = {
    .notify = tdx_finalize_vm,
};

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    X86MachineState *x86ms = X86_MACHINE(ms);
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (x86ms->smm == ON_OFF_AUTO_AUTO) {
        x86ms->smm = ON_OFF_AUTO_OFF;
    } else if (x86ms->smm == ON_OFF_AUTO_ON) {
        error_setg(errp, "TDX VM doesn't support SMM");
        return -EINVAL;
    }

    if (x86ms->pic == ON_OFF_AUTO_AUTO) {
        x86ms->pic = ON_OFF_AUTO_OFF;
    } else if (x86ms->pic == ON_OFF_AUTO_ON) {
        error_setg(errp, "TDX VM doesn't support PIC");
        return -EINVAL;
    }

    if (!tdx_caps) {
        get_tdx_capabilities();
    }

    /*
     * Set kvm_readonly_mem_allowed to false, because TDX only supports readonly
     * memory for shared memory but not for private memory. Besides, whether a
     * memslot is private or shared is not determined by QEMU.
     *
     * Thus, just mark readonly memory not supported for simplicity.
     */
    kvm_readonly_mem_allowed = false;

    qemu_add_machine_init_done_notifier(&tdx_machine_done_notify);

    tdx_guest = tdx;

    return 0;
}

void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret)
{
    switch (function) {
    case 1:
        if (reg == R_ECX) {
            *ret &= ~CPUID_EXT_VMX;
        }
        break;
    case 0xd:
        if (index == 0) {
            if (reg == R_EAX) {
                *ret &= (uint32_t)tdx_caps->xfam_fixed0 & XCR0_MASK;
                *ret |= (uint32_t)tdx_caps->xfam_fixed1 & XCR0_MASK;
            } else if (reg == R_EDX) {
                *ret &= (tdx_caps->xfam_fixed0 & XCR0_MASK) >> 32;
                *ret |= (tdx_caps->xfam_fixed1 & XCR0_MASK) >> 32;
            }
        } else if (index == 1) {
            /* TODO: Adjust XSS when it's supported. */
        }
        break;
    case KVM_CPUID_FEATURES:
        if (reg == R_EAX) {
            *ret &= TDX_SUPPORTED_KVM_FEATURES;
        }
        break;
    default:
        /* TODO: Use tdx_caps to adjust CPUID leafs. */
        break;
    }
}

static int tdx_validate_attributes(TdxGuest *tdx)
{
    if (((tdx->attributes & tdx_caps->attrs_fixed0) | tdx_caps->attrs_fixed1) !=
        tdx->attributes) {
            error_report("Invalid attributes 0x%lx for TDX VM (fixed0 0x%llx, fixed1 0x%llx)",
                          tdx->attributes, tdx_caps->attrs_fixed0, tdx_caps->attrs_fixed1);
            return -EINVAL;
    }

    if (tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) {
        error_report("Current QEMU doesn't support attributes.debug[bit 0] for TDX VM");
        return -EINVAL;
    }

    return 0;
}

static int setup_td_guest_attributes(X86CPU *x86cpu)
{
    CPUX86State *env = &x86cpu->env;

    tdx_guest->attributes |= (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKS) ?
                             TDX_TD_ATTRIBUTES_PKS : 0;
    tdx_guest->attributes |= x86cpu->enable_pmu ? TDX_TD_ATTRIBUTES_PERFMON : 0;

    return tdx_validate_attributes(tdx_guest);
}

int tdx_pre_create_vcpu(CPUState *cpu)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    struct kvm_tdx_init_vm init_vm;
    int r = 0;

    qemu_mutex_lock(&tdx_guest->lock);
    if (tdx_guest->initialized) {
        goto out;
    }

    r = -EINVAL;
    if (env->tsc_khz && (env->tsc_khz < TDX_MIN_TSC_FREQUENCY_KHZ ||
                         env->tsc_khz > TDX_MAX_TSC_FREQUENCY_KHZ)) {
        error_report("Invalid TSC %ld KHz, must specify cpu_frequency between [%d, %d] kHz",
                      env->tsc_khz, TDX_MIN_TSC_FREQUENCY_KHZ,
                      TDX_MAX_TSC_FREQUENCY_KHZ);
        goto out;
    }

    if (env->tsc_khz % (25 * 1000)) {
        error_report("Invalid TSC %ld KHz, it must be multiple of 25MHz", env->tsc_khz);
        goto out;
    }

    r = setup_td_guest_attributes(x86cpu);
    if (r) {
        goto out;
    }

    memset(&init_vm, 0, sizeof(init_vm));
    init_vm.cpuid.nent = kvm_x86_arch_cpuid(env, init_vm.entries, 0);

    init_vm.attributes = tdx_guest->attributes;
    init_vm.max_vcpus = ms->smp.cpus;
    init_vm.tsc_khz = env->tsc_khz;

    r = tdx_vm_ioctl(KVM_TDX_INIT_VM, 0, &init_vm);
    if (r < 0) {
        error_report("KVM_TDX_INIT_VM failed %s", strerror(-r));
        goto out;
    }

    tdx_guest->initialized = true;

out:
    qemu_mutex_unlock(&tdx_guest->lock);
    return r;
}
int tdx_parse_tdvf(void *flash_ptr, int size)
{
    return tdvf_parse_metadata(&tdx_guest->tdvf, flash_ptr, size);
}

/* tdx guest */
OBJECT_DEFINE_TYPE_WITH_INTERFACES(TdxGuest,
                                   tdx_guest,
                                   TDX_GUEST,
                                   CONFIDENTIAL_GUEST_SUPPORT,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void tdx_guest_init(Object *obj)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    qemu_mutex_init(&tdx->lock);

    tdx->attributes = 0;
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}
