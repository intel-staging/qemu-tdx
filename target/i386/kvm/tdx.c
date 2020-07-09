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

#include <linux/kvm.h>
#include <sys/ioctl.h>

#include "cpu.h"
#include "kvm_i386.h"
#include "hw/boards.h"
#include "hw/i386/tdvf-hob.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "sysemu/tdx.h"
#include "tdx.h"

#define TDX1_TD_ATTRIBUTE_DEBUG BIT_ULL(0)
#define TDX1_TD_ATTRIBUTE_PERFMON BIT_ULL(63)
#define TDX1_MIN_TSC_FREQUENCY_KHZ (100 * 1000)
#define TDX1_MAX_TSC_FREQUENCY_KHZ (10 * 1000 * 1000)

bool kvm_has_tdx(KVMState *s)
{
    return !!(kvm_check_extension(s, KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}

static void __tdx_ioctl(void *state, int ioctl_no, const char *ioctl_name,
                        __u32 metadata, void *data)
{
    struct kvm_tdx_cmd tdx_cmd;
    int r;

    memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));

    tdx_cmd.id = ioctl_no;
    tdx_cmd.metadata = metadata;
    tdx_cmd.data = (__u64)(unsigned long)data;

    if (ioctl_no == KVM_TDX_CAPABILITIES) {
        r = kvm_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    } else if (ioctl_no == KVM_TDX_INIT_VCPU) {
        r = kvm_vcpu_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    } else {
        r = kvm_vm_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    }
    if (r) {
        error_report("%s failed: %s", ioctl_name, strerror(-r));
        exit(1);
    }
}
#define _tdx_ioctl(cpu, ioctl_no, metadata, data) \
        __tdx_ioctl(cpu, ioctl_no, stringify(ioctl_no), metadata, data)
#define tdx_ioctl(ioctl_no, metadata, data) \
        _tdx_ioctl(kvm_state, ioctl_no, metadata, data)

static TdxFirmwareEntry *tdx_get_hob_entry(TdxGuest *tdx)
{
    TdxFirmwareEntry *entry;

    for_each_fw_entry(&tdx->fw, entry) {
        if (entry->type == TDVF_SECTION_TYPE_TD_HOB) {
            return entry;
        }
    }
    error_report("TDVF metadata doesn't specify TD_HOB location.");
    exit(1);
}

static void tdx_finalize_vm(Notifier *notifier, void *unused)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = TDX_GUEST(ms->cgs);
    TdxFirmwareEntry *entry;

    tdvf_hob_create(tdx, tdx_get_hob_entry(tdx));

    for_each_fw_entry(&tdx->fw, entry) {
        struct kvm_tdx_init_mem_region mem_region = {
            .source_addr = (__u64)entry->mem_ptr,
            .gpa = entry->address,
            .nr_pages = entry->size / 4096,
        };

        __u32 metadata = entry->attributes & TDVF_SECTION_ATTRIBUTES_EXTENDMR ?
                         KVM_TDX_MEASURE_MEMORY_REGION : 0;

        tdx_ioctl(KVM_TDX_INIT_MEM_REGION, metadata, &mem_region);
    }

    tdx_ioctl(KVM_TDX_FINALIZE_VM, 0, NULL);

    tdx->parent_obj.ready = true;
}

static Notifier tdx_machine_done_late_notify = {
    .notify = tdx_finalize_vm,
};

#define TDX1_MAX_NR_CPUID_CONFIGS 6

static struct {
    struct kvm_tdx_capabilities __caps;
    struct kvm_tdx_cpuid_config __cpuid_configs[TDX1_MAX_NR_CPUID_CONFIGS];
} __tdx_caps;

static struct kvm_tdx_capabilities *tdx_caps = (void *)&__tdx_caps;

#define XCR0_MASK (MAKE_64BIT_MASK(0, 8) | BIT_ULL(9))
#define XSS_MASK (~XCR0_MASK)

int tdx_kvm_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(cgs),
                                                    TYPE_TDX_GUEST);
    if (!tdx) {
        return 0;
    }

    QEMU_BUILD_BUG_ON(sizeof(__tdx_caps) !=
                      sizeof(struct kvm_tdx_capabilities) +
                      sizeof(struct kvm_tdx_cpuid_config) *
                      TDX1_MAX_NR_CPUID_CONFIGS);

    tdx_caps->nr_cpuid_configs = TDX1_MAX_NR_CPUID_CONFIGS;
    tdx_ioctl(KVM_TDX_CAPABILITIES, 0, tdx_caps);

    qemu_add_machine_init_done_late_notifier(&tdx_machine_done_late_notify);

    return 0;
}

int tdx_system_firmware_init(PCMachineState *pcms, MemoryRegion *rom_memory)
{
    MachineState *ms = MACHINE(pcms);
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    int i;

    if (!tdx) {
        return -ENOSYS;
    }

    /*
     * Sanitiy check for tdx:
     * TDX uses generic loader to load bios instead of pflash.
     */
    for (i = 0; i < ARRAY_SIZE(pcms->flash); i++) {
        if (drive_get(IF_PFLASH, 0, i)) {
            error_report("pflash not supported by VM type, "
                         "use -device loader,file=<path>");
            exit(1);
        }
    }
    return 0;
}

void tdx_get_supported_cpuid(KVMState *s, uint32_t function,
                             uint32_t index, int reg, uint32_t *ret)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (!tdx) {
        return;
    }

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
            *ret &= ~((1ULL << KVM_FEATURE_CLOCKSOURCE) |
                      (1ULL << KVM_FEATURE_CLOCKSOURCE2) |
                      (1ULL << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT) |
                      (1ULL << KVM_FEATURE_ASYNC_PF) |
                      (1ULL << KVM_FEATURE_ASYNC_PF_VMEXIT) |
                      (1ULL << KVM_FEATURE_ASYNC_PF_INT));
        }
        break;
    default:
        /* TODO: Use tdx_caps to adjust CPUID leafs. */
        break;
    }
}

void tdx_pre_create_vcpu(CPUState *cpu)
{
    struct {
        struct kvm_cpuid2 cpuid;
        struct kvm_cpuid_entry2 entries[KVM_MAX_CPUID_ENTRIES];
    } cpuid_data;

    /*
     * The kernel defines these structs with padding fields so there
     * should be no extra padding in our cpuid_data struct.
     */
    QEMU_BUILD_BUG_ON(sizeof(cpuid_data) !=
                      sizeof(struct kvm_cpuid2) +
                      sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES);

    MachineState *ms = MACHINE(qdev_get_machine());
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    struct kvm_tdx_init_vm init_vm;

    if (!tdx) {
        return;
    }

    /* TODO: Use tdx_caps to validate the config. */
    if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
        error_report("TDX VM must support XSAVE features");
        exit(1);
    }

    if (env->tsc_khz && (env->tsc_khz < TDX1_MIN_TSC_FREQUENCY_KHZ ||
                         env->tsc_khz > TDX1_MAX_TSC_FREQUENCY_KHZ)) {
        error_report("Invalid TSC %ld KHz, must specify cpu_frequecy between [%d, %d] kHz\n",
                      env->tsc_khz, TDX1_MIN_TSC_FREQUENCY_KHZ,
                      TDX1_MAX_TSC_FREQUENCY_KHZ);
        exit(1);
    }

    if (env->tsc_khz % (25 * 1000)) {
        error_report("Invalid TSC %ld KHz, it must be multiple of 25MHz\n", env->tsc_khz);
        exit(1);
    }

    qemu_mutex_lock(&tdx->lock);
    if (tdx->initialized) {
        goto out;
    }
    tdx->initialized = true;

    memset(&cpuid_data, 0, sizeof(cpuid_data));

    cpuid_data.cpuid.nent = kvm_x86_arch_cpuid(env, cpuid_data.entries, 0);
    cpuid_data.cpuid.padding = 0;

    init_vm.max_vcpus = ms->smp.cpus;
    init_vm.tsc_khz = env->tsc_khz;
    init_vm.attributes = 0;
    init_vm.attributes |= tdx->debug ? TDX1_TD_ATTRIBUTE_DEBUG : 0;
    init_vm.attributes |= x86cpu->enable_pmu ? TDX1_TD_ATTRIBUTE_PERFMON : 0;

    init_vm.cpuid = (__u64)(&cpuid_data);
    tdx_ioctl(KVM_TDX_INIT_VM, 0, &init_vm);
out:
    qemu_mutex_unlock(&tdx->lock);
}

void tdx_post_init_vcpu(CPUState *cpu)
{
    CPUX86State *env = &X86_CPU(cpu)->env;

    _tdx_ioctl(cpu, KVM_TDX_INIT_VCPU, 0,
               (void *)(unsigned long)env->regs[R_ECX]);
}

static bool tdx_guest_get_debug(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return tdx->debug;
}

static void tdx_guest_set_debug(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    tdx->debug = value;
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

    tdx->debug = false;
    object_property_add_bool(obj, "debug", tdx_guest_get_debug,
                             tdx_guest_set_debug);
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}
