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
#include "qapi/qapi-types-misc-target.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/sysemu.h"
#include "sysemu/runstate-action.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "sysemu/tdx.h"
#include "tdx.h"

#include "hw/southbridge/piix.h"
#include "hw/i386/ich9.h"

#define TDX1_TD_ATTRIBUTE_DEBUG BIT_ULL(0)
#define TDX1_TD_ATTRIBUTE_PERFMON BIT_ULL(63)
#define TDX1_MIN_TSC_FREQUENCY_KHZ (100 * 1000)
#define TDX1_MAX_TSC_FREQUENCY_KHZ (10 * 1000 * 1000)

/*
 * The TODO feature bits below are those
 * that TDX requires to be fixed but they are not yet
 * supported by KVM.
 */
#define TDX_FIXED1_FEATURES (CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_APIC | \
            CPUID_MTRR | CPUID_MCA | CPUID_CLFLUSH | CPUID_DTS)
#define TDX_FIXED0_FEATURES (MAKE_64BIT_MASK(10, 1) | MAKE_64BIT_MASK(20, 1) | \
        MAKE_64BIT_MASK(30, 1))
#define TDX_FIXED0_EXT_FEATURES (CPUID_EXT_MONITOR | CPUID_EXT_VMX | CPUID_EXT_SMX | \
            MAKE_64BIT_MASK(16, 1))
#define TDX_FIXED1_EXT_FEATURES (CPUID_EXT_CX16 | CPUID_EXT_PDCM | CPUID_EXT_X2APIC | \
            CPUID_EXT_AES | CPUID_EXT_XSAVE | CPUID_EXT_RDRAND | CPUID_EXT_HYPERVISOR)
#define TDX_FIXED1_EXT2_FEATURES (CPUID_EXT2_NX | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP | \
            CPUID_EXT2_LM | MAKE_64BIT_MASK(0, 11) | MAKE_64BIT_MASK(12, 8) | \
            MAKE_64BIT_MASK(21, 5) | MAKE_64BIT_MASK(28, 1) | MAKE_64BIT_MASK(30, 2))
/* TODO: EBX_SGX(bit2) */
#define TDX_FIXED0_7_0_EBX_FEATURES (CPUID_7_0_EBX_TSC_ADJUST | CPUID_7_0_EBX_MPX | \
            CPUID_7_0_EBX_SGX)
#define TDX_FIXED1_7_0_EBX_FEATURES (CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_RTM | \
            CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_CLFLUSHOPT | \
            CPUID_7_0_EBX_CLWB | CPUID_7_0_EBX_SHA_NI)
/* TODO: ECX_FZM(bit15) ECX_ENQCMD(bit29) ECX_SGX_LC(bit30) */
#define TDX_FIXED0_7_0_ECX_FEATURES (CPUID_7_0_ECX_RESERVED_15 | CPUID_7_0_ECX_RESERVED_17_21 | \
            CPUID_7_0_ECX_ENQCMD | CPUID_7_0_ECX_SGX_LC)
#define TDX_FIXED1_7_0_ECX_FEATURES (CPUID_7_0_ECX_MOVDIR64B)
#define TDX_FIXED1_7_0_EDX_FEATURES (CPUID_7_0_EDX_SPEC_CTRL | CPUID_7_0_EDX_ARCH_CAPABILITIES | \
            CPUID_7_0_EDX_CORE_CAPABILITY | CPUID_7_0_EDX_SPEC_CTRL_SSBD)
#define TDX_FIXED0_7_0_EDX_FEATURES (MAKE_64BIT_MASK(0, 2) | MAKE_64BIT_MASK(6, 2) |\
            MAKE_64BIT_MASK(9, 1) | MAKE_64BIT_MASK(11, 3) | MAKE_64BIT_MASK(17, 1) |\
            MAKE_64BIT_MASK(21, 1))
#define TDX_FIXED1_8000_0008_EBX_FEATURES (CPUID_8000_0008_EBX_WBNOINVD)
#define TDX_FIXED1_XSAVE_EAX_FEATURES (CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC | \
            CPUID_XSAVE_XSAVES)
#define TDX_FIXED0_KVM_FEATURES ((1ULL << KVM_FEATURE_CLOCKSOURCE) | \
            (1ULL << KVM_FEATURE_CLOCKSOURCE2) | \
            (1ULL << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT) | \
            (1ULL << KVM_FEATURE_ASYNC_PF) | \
            (1ULL << KVM_FEATURE_ASYNC_PF_VMEXIT))

/* Some KVM PV features are treated as configurable */
#define TDX_CONFIG_KVM_FEATURES ((1ULL << KVM_FEATURE_NOP_IO_DELAY) | \
            (1ULL << KVM_FEATURE_PV_EOI) | (1ULL << KVM_FEATURE_PV_UNHALT) | \
            (1ULL << KVM_FEATURE_PV_TLB_FLUSH) | (1ULL << KVM_FEATURE_PV_SEND_IPI) | \
            (1ULL << KVM_FEATURE_POLL_CONTROL) | (1ULL << KVM_FEATURE_PV_SCHED_YIELD) | \
            (1ULL << KVM_FEATURE_ASYNC_PF_INT) | (1ULL << KVM_FEATURE_MSI_EXT_DEST_ID))

typedef struct kvm_tdx_cpuid_lookup {
  uint64_t tdx_fixed0;
  uint64_t tdx_fixed1;
  bool faulting;
} kvm_tdx_cpuid_lookup;

static kvm_tdx_cpuid_lookup tdx_cpuid_lookup[FEATURE_WORDS] = {
    [FEAT_1_EDX] = {
        .tdx_fixed0 = TDX_FIXED0_FEATURES,
        .tdx_fixed1 = TDX_FIXED1_FEATURES,
    },
    [FEAT_1_ECX] = {
        .tdx_fixed0 = TDX_FIXED0_EXT_FEATURES,
        .tdx_fixed1 = TDX_FIXED1_EXT_FEATURES,
    },
    [FEAT_8000_0001_EDX] = {
        .tdx_fixed1 = TDX_FIXED1_EXT2_FEATURES,
    },
    [FEAT_7_0_EBX] = {
        .tdx_fixed0 = TDX_FIXED0_7_0_EBX_FEATURES,
        .tdx_fixed1 = TDX_FIXED1_7_0_EBX_FEATURES,
    },
    [FEAT_7_0_ECX] = {
        .tdx_fixed0 = TDX_FIXED0_7_0_ECX_FEATURES,
        .tdx_fixed1 = TDX_FIXED1_7_0_ECX_FEATURES,
    },
    [FEAT_7_0_EDX] = {
        .tdx_fixed0 = TDX_FIXED0_7_0_EDX_FEATURES,
        .tdx_fixed1 = TDX_FIXED1_7_0_EDX_FEATURES,
    },
    [FEAT_8000_0008_EBX] = {
        .tdx_fixed1 = TDX_FIXED1_8000_0008_EBX_FEATURES,
    },
    [FEAT_XSAVE] = {
        .tdx_fixed1 = TDX_FIXED1_XSAVE_EAX_FEATURES,
    },
    [FEAT_6_EAX] = {
        .faulting = true,
    },
    [FEAT_8000_0007_EDX] = {
        .faulting = true,
    },
    [FEAT_KVM] = {
        .tdx_fixed0 = TDX_FIXED0_KVM_FEATURES,
    },
};

bool kvm_has_tdx(KVMState *s)
{
    return !!(kvm_check_extension(s, KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}

TDXInfo *tdx_get_info(void)
{
    TDXInfo *info;

    info = g_new0(TDXInfo, 1);
    info->enabled = kvm_enabled() && kvm_tdx_enabled();
    return info;
}

TDXCapability *tdx_get_capabilities(void)
{
    TDXCapability *cap;

    cap = g_new0(TDXCapability, 1);
    cap->enabled = kvm_enabled() && kvm_has_tdx(kvm_state);
    return cap;
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
    Object *pm;
    bool ambig;
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = TDX_GUEST(ms->cgs);
    TdxFirmwareEntry *entry;

    /*
     * object look up logic is copied from acpi_get_pm_info()
     * @ hw/ie86/acpi-build.c
     * This property override needs to be done after machine initialization
     * as there is no ordering of creation of objects/properties.
     */
    pm = object_resolve_path_type("", TYPE_PIIX4_PM, &ambig);
    if (ambig || !pm) {
        pm = object_resolve_path_type("", TYPE_ICH9_LPC_DEVICE, &ambig);
    }
    if (!ambig && pm) {
        object_property_set_uint(pm, ACPI_PM_PROP_S3_DISABLED, 1, NULL);
        object_property_set_uint(pm, ACPI_PM_PROP_S4_DISABLED, 1, NULL);
    }

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

    if (!kvm_enable_x2apic()) {
        error_report("Failed to enable x2apic in KVM");
        exit(1);
    }

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

extern FeatureWordInfo feature_word_info[FEATURE_WORDS];

uint32_t tdx_get_cpuid_config(uint32_t function, uint32_t index, int reg)
{
    struct kvm_tdx_cpuid_config *cpuid_c;
    int i;
    uint32_t ret = 0;
    uint32_t eax, ebx, ecx, edx;
    FeatureWord w;

    if (function == KVM_CPUID_FEATURES && reg == R_EAX) {
        return TDX_CONFIG_KVM_FEATURES;
    }

    /* Check if native supports */
    host_cpuid(function, index, &eax, &ebx, &ecx, &edx);

    /* TODO: AMX in XCR0 is not yet configurable */
    if (function == 0xd && index == 0x0 && reg == R_EAX) {
        return XCR0_MASK & eax;
    }

    /*
     * fault type of CPUID are those will cause #VE injected
     * into TD guest, which could transfer to KVM to handle it.
     * Thus, see them as configurable and apply KVM's configuration.
     */
    for (w = 0; w < FEATURE_WORDS; w++) {
        FeatureWordInfo *f = &feature_word_info[w];

        if (f->type == MSR_FEATURE_WORD) {
            continue;
        }

        if (f->cpuid.eax == function && f->cpuid.reg == reg &&
            (!f->cpuid.needs_ecx || f->cpuid.ecx == index) &&
            tdx_cpuid_lookup[w].faulting) {
            switch (reg) {
            case R_EAX:
                ret |= eax;
                break;
            case R_EBX:
                ret |= ebx;
                break;
            case R_ECX:
                ret |= ecx;
                break;
            case R_EDX:
                ret |= edx;
                break;
            default:
                return 0;
            }

            return ret;
        }
    }

    if (tdx_caps->nr_cpuid_configs <= 0) {
        return ret;
    }

    for (i = 0; i < tdx_caps->nr_cpuid_configs; i++) {
        cpuid_c = &tdx_caps->cpuid_configs[i];
        /* The sub-leaf of function 0x1 is 0xffffffff in tdx_caps */
        if (cpuid_c->leaf == function && (cpuid_c->sub_leaf == index ||
            function == 0x1)) {
            switch (reg) {
            case R_EAX:
                ret |= cpuid_c->eax;
                break;
            case R_EBX:
                ret |= cpuid_c->ebx;
                break;
            case R_ECX:
                ret |= cpuid_c->ecx;
                break;
            case R_EDX:
                ret |= cpuid_c->edx;
                break;
            default:
                return 0;
            }
        }
    }

    return ret;
}

uint32_t tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    uint32_t eax, ebx, ecx, edx, tdx_config;
    uint32_t ret = 0;
    FeatureWord w;

    if (!tdx) {
        return ret;
    }

    for (w = 0; w < FEATURE_WORDS; w++) {
        FeatureWordInfo *f = &feature_word_info[w];

        if (f->type == MSR_FEATURE_WORD) {
            continue;
        }

        if (f->cpuid.eax != function || f->cpuid.reg != reg ||
            (f->cpuid.needs_ecx && f->cpuid.ecx != index)) {
            continue;
        }

        /* Start from native value */
        host_cpuid(function, index, &eax, &ebx, &ecx, &edx);

        switch (reg) {
        case R_EAX:
            ret |= eax;
            break;
        case R_EBX:
            ret |= ebx;
            break;
        case R_ECX:
            ret |= ecx;
            break;
        case R_EDX:
            ret |= edx;
            break;
        }

        /* tdx_cap->xfam_fixed check */
        if (function == 0xd && index == 0) {
            if (reg == R_EAX) {
                ret &= (uint32_t)tdx_caps->xfam_fixed0 & XCR0_MASK;
                ret |= (uint32_t)tdx_caps->xfam_fixed1 & XCR0_MASK;
            } else if (reg == R_EDX) {
                ret &= (tdx_caps->xfam_fixed0 & XCR0_MASK) >> 32;
                ret |= (tdx_caps->xfam_fixed1 & XCR0_MASK) >> 32;
            }
            return ret;
        }

        /* configurable cpuid are supported by TDX unconditionally */
        tdx_config = tdx_get_cpuid_config(function, index, reg);
        ret |= tdx_config;

        /* enforce "fixed" type CPUID virtualization */
        ret |= tdx_cpuid_lookup[w].tdx_fixed1;
        ret &= ~tdx_cpuid_lookup[w].tdx_fixed0;

        return ret;
    }

    return ret;
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

    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrconfigid) != sizeof(tdx->mrconfigid));
    memcpy(init_vm.mrconfigid, tdx->mrconfigid, sizeof(init_vm.mrconfigid));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrowner) != sizeof(tdx->mrowner));
    memcpy(init_vm.mrowner, tdx->mrowner, sizeof(init_vm.mrowner));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrownerconfig) !=
                      sizeof(tdx->mrownerconfig));
    memcpy(init_vm.mrownerconfig, tdx->mrownerconfig,
           sizeof(init_vm.mrownerconfig));

    memset(init_vm.reserved, 0, sizeof(init_vm.reserved));

    init_vm.cpuid = (__u64)(&cpuid_data);
    tdx_ioctl(KVM_TDX_INIT_VM, 0, &init_vm);
out:
    qemu_mutex_unlock(&tdx->lock);
}

void tdx_post_init_vcpu(CPUState *cpu)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    TdxFirmwareEntry *hob;

    if (!tdx) {
        return;
    }

    hob = tdx_get_hob_entry(tdx);
    _tdx_ioctl(cpu, KVM_TDX_INIT_VCPU, 0, (void *)hob->address);

    apic_force_x2apic(X86_CPU(cpu)->apic_state);
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

    /* TODO: set only if user doens't specify reboot action */
    reboot_action = REBOOT_ACTION_SHUTDOWN;

    tdx->debug = false;
    object_property_add_bool(obj, "debug", tdx_guest_get_debug,
                             tdx_guest_set_debug);
    object_property_add_sha384(obj, "mrconfigid", tdx->mrconfigid,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrowner", tdx->mrowner,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrownerconfig", tdx->mrownerconfig,
                               OBJ_PROP_FLAG_READWRITE);
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}
