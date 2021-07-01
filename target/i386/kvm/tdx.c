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
#include "cpu-internal.h"
#include "kvm_i386.h"
#include "hw/boards.h"
#include "hw/i386/tdvf-hob.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "qapi/qapi-commands-misc-target.h"
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
            (1ULL << KVM_FEATURE_STEAL_TIME) | \
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

static int __tdx_ioctl(void *state, int ioctl_no, const char *ioctl_name,
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

    if (ioctl_no == KVM_TDX_CAPABILITIES && r == -E2BIG)
        return r;

    if (r) {
        error_report("%s failed: %s", ioctl_name, strerror(-r));
        exit(1);
    }
    return 0;
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

static struct kvm_tdx_capabilities *tdx_caps = NULL;

#define XCR0_MASK (MAKE_64BIT_MASK(0, 8) | BIT_ULL(9) | MAKE_64BIT_MASK(17, 2))
#define XSS_MASK (~XCR0_MASK)

int tdx_kvm_init(ConfidentialGuestSupport *cgs, KVMState *s, Error **errp)
{
    struct kvm_tdx_capabilities *caps;
    uint32_t nr_cpuid_configs;
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(cgs),
                                                    TYPE_TDX_GUEST);
    if (!tdx) {
        return 0;
    }

    caps = NULL;
    nr_cpuid_configs = 8;
    while (true) {
        int r;
        caps = g_realloc(caps, sizeof(*caps) +
                        sizeof(*caps->cpuid_configs) * nr_cpuid_configs);
        caps->nr_cpuid_configs = nr_cpuid_configs;
        r = tdx_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
        if (r == -E2BIG) {
            nr_cpuid_configs *= 2;
            continue;
        }
        break;
    }
    tdx_caps = caps;

    if (!kvm_enable_x2apic()) {
        error_report("Failed to enable x2apic in KVM");
        exit(1);
    }

    qemu_add_machine_init_done_late_notifier(&tdx_machine_done_late_notify);

    if (tdx->debug &&
        kvm_vm_check_extension(s, KVM_CAP_ENCRYPT_MEMORY_DEBUG)) {
        kvm_setup_set_memory_region_debug_ops(s,
                                              kvm_encrypted_guest_set_memory_region_debug_ops);
        set_encrypted_memory_debug_ops();
    }

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

static FeatureDep xfam_dependencies[] = {
    /* XFAM[7:5] may be set to 111 only when XFAM[2] is set to 1 */
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_YMM_MASK },
        .to = { FEAT_XSAVE_COMP_LO, XSTATE_AVX_512_MASK },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_YMM_MASK },
        .to = { FEAT_1_ECX,
                CPUID_EXT_FMA | CPUID_EXT_AVX |
                CPUID_EXT_F16C },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_YMM_MASK },
        .to = { FEAT_7_0_EBX, CPUID_7_0_EBX_AVX2 },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_YMM_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_VAES | CPUID_7_0_ECX_VPCLMULQDQ},
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_EBX,
                CPUID_7_0_EBX_AVX512F | CPUID_7_0_EBX_AVX512DQ |
                CPUID_7_0_EBX_AVX512IFMA | CPUID_7_0_EBX_AVX512PF |
                CPUID_7_0_EBX_AVX512ER | CPUID_7_0_EBX_AVX512CD |
                CPUID_7_0_EBX_AVX512BW | CPUID_7_0_EBX_AVX512VL },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_ECX,
                CPUID_7_0_ECX_AVX512_VBMI | CPUID_7_0_ECX_AVX512_VBMI2 |
                CPUID_7_0_ECX_AVX512VNNI | CPUID_7_0_ECX_AVX512BITALG |
                CPUID_7_0_ECX_AVX512_VPOPCNTDQ },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_EDX,
                CPUID_7_0_EDX_AVX512_4VNNIW | CPUID_7_0_EDX_AVX512_4FMAPS |
                CPUID_7_0_EDX_AVX512_VP2INTERSECT | CPUID_7_0_EDX_AVX512_FP16 },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_1_EAX, CPUID_7_1_EAX_AVX512_BF16 | CPUID_7_1_EAX_AVX_VNNI },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_PKRU_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_PKU },
    },
    {
        .from = { FEAT_XSAVE_COMP_LO, XSTATE_AMX_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_AMX_BF16 | CPUID_7_0_EDX_AMX_TILE |
                CPUID_7_0_EDX_AMX_INT8}
    },
    /* TODO: XSS features */
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_RTIT_MASK },
        .to = { FEAT_7_0_EBX, CPUID_7_0_EBX_INTEL_PT },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_RTIT_MASK },
        .to = { FEAT_14_0_ECX, ~0ull },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_CET_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_CET_SHSTK },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_CET_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_CET_IBT },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_RESERVED_14_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_ULI },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_RESERVED_15_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_ARCH_LBR },
    },
};

/*
 * Select a delegate feature for each XFAM-allowed features. e.g avx for all XFAM[2].
 * Only the delegate one is allowed to be configured. This can help prevent unintentional
 * mistake by the user.
 */
FeatureMask tdx_xfam_feature_delegate[] = {
    [XSTATE_YMM_BIT] = { .index = FEAT_1_ECX, .mask = CPUID_EXT_AVX },
    [XSTATE_OPMASK_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_ZMM_Hi256_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_Hi16_ZMM_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_RTIT_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_INTEL_PT },
    [XSTATE_PKRU_BIT] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_PKU },
    [XSTATE_XTILE_CFG_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_AMX_BF16 },
    [XSTATE_XTILE_DATA_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_AMX_BF16 },
};

#define ATTRIBUTE_MAX_BITS      64

static FeatureMask attribute_features[ATTRIBUTE_MAX_BITS] = {
    [30] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_PKS },
};

uint32_t tdx_get_cpuid_config(uint32_t function, uint32_t index, int reg)
{
    struct kvm_tdx_cpuid_config *cpuid_c;
    int i;
    uint32_t ret = 0;
    uint32_t eax, ebx, ecx, edx, native, xfam_fixed, attrs_fixed;
    FeatureWord w;

    if (function == KVM_CPUID_FEATURES && reg == R_EAX) {
        return TDX_CONFIG_KVM_FEATURES;
    }

    /* Check if native supports */
    host_cpuid(function, index, &eax, &ebx, &ecx, &edx);

    xfam_fixed = (uint32_t)tdx_caps->xfam_fixed1 |
                ~(uint32_t)tdx_caps->xfam_fixed0;

    attrs_fixed = (uint32_t)tdx_caps->attrs_fixed1 |
                 ~(uint32_t)tdx_caps->attrs_fixed0;

    if (function == 0xd && index == 0x0 && reg == R_EAX) {
        return (XCR0_MASK & ~xfam_fixed) & eax;
    }

    if (function == 0xd && index == 0x1 && reg == R_ECX) {
        return (XSS_MASK & ~xfam_fixed) & ecx;
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
            (!f->cpuid.needs_ecx || f->cpuid.ecx == index)) {
            switch (reg) {
            case R_EAX:
                native = eax;
                break;
            case R_EBX:
                native = ebx;
                break;
            case R_ECX:
                native = ecx;
                break;
            case R_EDX:
                native = edx;
                break;
            default:
                return 0;
            }
            if (tdx_cpuid_lookup[w].faulting) {
                return native;
            }
            /* Add XFAM-allowed configurable features */
            for (i = 0; i < ARRAY_SIZE(tdx_xfam_feature_delegate); i++) {
                FeatureMask *d = &tdx_xfam_feature_delegate[i];
                if (d->index == w && !(xfam_fixed & (1ULL << i))) {
                    ret |= (d->mask & native);
                }
            }
            /* Add TD Attributes-allowed configurable features */
            for (i = 0; i < ARRAY_SIZE(attribute_features); i++) {
                FeatureMask *d = &attribute_features[i];
                if (d->index == w && !(attrs_fixed & (1ULL << i))) {
                    ret |= (d->mask & native);
                }
            }
            break;
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
    uint32_t eax, ebx, ecx, edx, tdx_config, i;
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

        if (function == 0xd && index == 1) {
            if (reg == R_ECX) {
                ret &= (uint32_t)tdx_caps->xfam_fixed0 & XSS_MASK;
                ret |= (uint32_t)tdx_caps->xfam_fixed1 & XSS_MASK;
            } else if (reg == R_EDX) {
                ret &= (tdx_caps->xfam_fixed0 & XSS_MASK) >> 32;
                ret |= (tdx_caps->xfam_fixed1 & XSS_MASK) >> 32;
            }
            return ret;
        }

        /* configurable cpuid are supported by TDX unconditionally */
        tdx_config = tdx_get_cpuid_config(function, index, reg);
        ret |= tdx_config;

        /* enforce "fixed" type CPUID virtualization */
        ret |= tdx_cpuid_lookup[w].tdx_fixed1;
        ret &= ~tdx_cpuid_lookup[w].tdx_fixed0;

        /* tdx_cap->attrs_fixed check */
        for (i = 0; i < 64; ++i) {
            if (attribute_features[i].index == w) {
                if (tdx_caps->attrs_fixed1 & (1 << i)) {
                    ret |= attribute_features[i].mask;
                }
                if (~tdx_caps->attrs_fixed0 & (1 << i)) {
                    ret &= ~attribute_features[i].mask;
                }
            }
        }

        return ret;
    }

    return ret;
}

void tdx_update_xfam_features(CPUState *cpu)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    int i;
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (!tdx) {
        return;
    }

    for (i = 0; i < ARRAY_SIZE(xfam_dependencies); i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (!(env->features[d->from.index] & d->from.mask)) {
            uint64_t unavailable_features = env->features[d->to.index] & d->to.mask;

            /* Not an error unless the dependent feature was added explicitly */
            mark_unsuitable_features(x86_cpu, d->to.index,
                                     unavailable_features & env->user_plus_features[d->to.index],
                                     "This feature depends on unrequested XFAM feature",
                                     true);
            env->features[d->to.index] &= ~unavailable_features;
        }
    }
}

static inline uint64_t is_tdx_xfam_feature(FeatureWord w, uint64_t bit_mask) {
    int i;

    for (i = 0; i < ARRAY_SIZE(xfam_dependencies); i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (w == d->to.index && bit_mask & d->to.mask) {
            return d->from.mask;
        }
    }
    return 0;
}

static inline int is_tdx_xfam_delegate_feature(FeatureWord w, uint64_t bit_mask) {
    int i;

    for (i = 0; i < ARRAY_SIZE(tdx_xfam_feature_delegate); i++) {
        FeatureMask *d = &tdx_xfam_feature_delegate[i];
        if (w == d->index && bit_mask & d->mask) {
            return i;
        }
    }
    return -1;
}

static const char *tdx_xfam_delegate_feature_name(uint64_t xfam_mask) {
    uint32_t xfam_delegate_index, xfam_delegate_feature;
    int bitnr, xfam_delegate_bitnr;
    const char *name;

    bitnr = ctz32(xfam_mask);
    xfam_delegate_index = tdx_xfam_feature_delegate[bitnr].index;
    xfam_delegate_feature = tdx_xfam_feature_delegate[bitnr].mask;
    xfam_delegate_bitnr = ctz32(xfam_delegate_feature);
    /* get XFAM feature delegate feature name */
    name = feature_word_info[xfam_delegate_index].feat_names[xfam_delegate_bitnr];
    assert(xfam_delegate_bitnr < 32 ||
           !(name && feature_word_info[xfam_delegate_index].type == CPUID_FEATURE_WORD));
    return name;
}

void tdx_check_plus_minus_features(CPUState *cpu)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    uint64_t minus_features, plus_features, bit_mask, feature_mask;
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    FeatureWordInfo *wi;
    FeatureWord w;
    int i, delegate_index;
    char prefix[80];
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (!tdx) {
        return;
    }

    for (w = 0; w < FEATURE_WORDS; w++) {
        minus_features = env->user_minus_features[w];
        plus_features = env->user_plus_features[w];
        wi = &feature_word_info[w];

        if (wi->type == MSR_FEATURE_WORD)
            continue;

        for (i = 0; i < 64; ++i) {
            bit_mask = (1ULL << i);
            /* user minus take precedence over user plus */
            if (bit_mask & minus_features) {
                if (!(x86_cpu_get_supported_feature_word(w, false, false) & bit_mask)) {
                    continue;
                }

                if (bit_mask & tdx_get_cpuid_config(wi->cpuid.eax, wi->cpuid.ecx,
                                                wi->cpuid.reg)) {
                    continue;
                }

                feature_mask = is_tdx_xfam_feature(w, bit_mask);
                delegate_index = is_tdx_xfam_delegate_feature(w, bit_mask);
                if (feature_mask && delegate_index >= 0) {
                    continue;
                }

                if (feature_mask && delegate_index < 0) {
                    /* disallowed non-delegate xfam-allowed features' prefix */
                    snprintf(prefix, sizeof(prefix),
                        "TDX: modify the XFAM-allowed delegate feature(%s) instead of",
                        g_strdup(tdx_xfam_delegate_feature_name(feature_mask)));
                } else {
                    /* disallowed normal features' prefix */
                    strncpy(prefix,
                        "This feature can't be removed due to TDX limitation",
                        sizeof(prefix));
                }

                mark_unsuitable_features(x86_cpu, w,
                                         bit_mask & minus_features, prefix, false);
            } else if (bit_mask & plus_features) {
                if (x86_cpu_get_supported_feature_word(w, false, false) & bit_mask) {
                    continue;
                }

                if (bit_mask & tdx_get_cpuid_config(wi->cpuid.eax, wi->cpuid.ecx,
                                                wi->cpuid.reg)) {
                    continue;
                }

                feature_mask = is_tdx_xfam_feature(w, bit_mask);
                delegate_index = is_tdx_xfam_delegate_feature(w, bit_mask);
                if (feature_mask && delegate_index >= 0) {
                    continue;
                }

                if (feature_mask && delegate_index < 0) {
                    /* disallowed non-delegate xfam-allowed features' prefix */
                    snprintf(prefix, sizeof(prefix),
                        "TDX: modify the XFAM-allowed delegate feature(%s) instead of",
                        g_strdup(tdx_xfam_delegate_feature_name(feature_mask)));
                } else {
                    /* disallowed normal features' prefix */
                    strncpy(prefix,
                        "This feature can't be added due to TDX limitation",
                        sizeof(prefix));
                }

                mark_unsuitable_features(x86_cpu, w,
                                      bit_mask & minus_features, prefix, true);
            }
        }
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

bool tdx_debug_enabled(ConfidentialGuestSupport *cgs)
{
    TdxGuest *tdx;

    if (!cgs)
        return false;

    tdx = (TdxGuest *)object_dynamic_cast(OBJECT(cgs),
                                          TYPE_TDX_GUEST);
    if (!tdx)
        return false;

    return tdx->debug;
}

/* QMP */
TDXInfo *qmp_query_tdx(Error **errp)
{
    TDXInfo *info;

    info = tdx_get_info();
    if (!info) {
        error_setg(errp, "TDX is not available.");
    }
    return info;
}

TDXCapability *qmp_query_tdx_capabilities(Error **errp)
{
    TDXCapability *cap;

    cap = tdx_get_capabilities();
    if (!cap) {
        error_setg(errp, "TDX is not available.");
    }
    return cap;
}
