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

#include "qemu/mmap-alloc.h"
#include "cpu.h"
#include "cpu-internal.h"
#include "exec/address-spaces.h"
#include "kvm_i386.h"
#include "hw/boards.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/tdvf-hob.h"
#include "io/channel-socket.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "qapi/qapi-commands-misc-target.h"
#include "qapi/qapi-types-misc-target.h"
#include "qapi/qapi-visit-sockets.h"
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
#define TDX1_TD_ATTRIBUTE_SEPT_VE_DISABLE       BIT_ULL(28)
#define TDX1_TD_ATTRIBUTE_PKS                   BIT_ULL(30)
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
            CPUID_EXT2_LM)
#define TDX_FIXED0_EXT2_FEATURES (MAKE_64BIT_MASK(0, 11) | \
            MAKE_64BIT_MASK(12, 8) | MAKE_64BIT_MASK(21, 5) | \
            MAKE_64BIT_MASK(28, 1) | MAKE_64BIT_MASK(30, 2))
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
            (1ULL << KVM_FEATURE_ASYNC_PF_VMEXIT) | \
            (1ULL << KVM_FEATURE_ASYNC_PF_INT))

/* Some KVM PV features are treated as configurable */
#define TDX_CONFIG_KVM_FEATURES ((1ULL << KVM_FEATURE_NOP_IO_DELAY) | \
            (1ULL << KVM_FEATURE_PV_EOI) | (1ULL << KVM_FEATURE_PV_UNHALT) | \
            (1ULL << KVM_FEATURE_PV_TLB_FLUSH) | (1ULL << KVM_FEATURE_PV_SEND_IPI) | \
            (1ULL << KVM_FEATURE_POLL_CONTROL) | (1ULL << KVM_FEATURE_PV_SCHED_YIELD) | \
            (1ULL << KVM_FEATURE_MSI_EXT_DEST_ID))

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
        .tdx_fixed0 = TDX_FIXED0_EXT2_FEATURES,
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
    cap->enabled = kvm_enabled() &&
        !!(kvm_check_extension(kvm_state, KVM_CAP_VM_TYPES) &
           (BIT(KVM_X86_TDX_VM) | BIT(KVM_X86_TDX_VM_OLD)));
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

    if (ioctl_no == KVM_TDX_INIT_VCPU) {
        r = kvm_vcpu_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    } else {
        r = kvm_vm_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    }

    if (ioctl_no == KVM_TDX_CAPABILITIES && r == -E2BIG)
        return r;
    /*
     * REVERTME: Workaround for incompatible ABI change.  KVM_TDX_CAPABILITIES
     * was changed from system ioctl to VM ioctl.  Make KVM_TDX_CAPABILITIES
     * work with old ABI.
     */
    if (r && ioctl_no == KVM_TDX_CAPABILITIES) {
        r = kvm_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    }
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

        qemu_ram_munmap(-1, entry->mem_ptr, entry->size);
        entry->mem_ptr = NULL;
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

    /*
     * If the CPUID isn't included in env->features, QEMU-TDX will
     * not enforce additional check even it also has some CPUID restrictions.
     * e.g. CPUID[0xa]. View it as configurable and keep the values from KVM.
     */
    if (w == FEATURE_WORDS && i == tdx_caps->nr_cpuid_configs) {
        ret = native;
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
    init_vm.attributes |= tdx->sept_ve_disable ? TDX1_TD_ATTRIBUTE_SEPT_VE_DISABLE : 0;
    init_vm.attributes |= (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKS) ?
        TDX1_TD_ATTRIBUTE_PKS : 0;
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

static bool tdx_guest_get_sept_ve_disable(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return tdx->sept_ve_disable;
}

static void tdx_guest_set_sept_ve_disable(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    tdx->sept_ve_disable = value;
}

static char *tdx_guest_get_quote_generation(
    Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);
    return g_strdup(tdx->quote_generation_str);
}

static void tdx_guest_set_quote_generation(
    Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);
    tdx->quote_generation = socket_parse(value, errp);
    if (!tdx->quote_generation)
        return;

    g_free(tdx->quote_generation_str);
    tdx->quote_generation_str = g_strdup(value);
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
    tdx->sept_ve_disable = false;
    object_property_add_bool(obj, "debug", tdx_guest_get_debug,
                             tdx_guest_set_debug);
    object_property_add_bool(obj, "sept-ve-disable",
                             tdx_guest_get_sept_ve_disable,
                             tdx_guest_set_sept_ve_disable);
    object_property_add_sha384(obj, "mrconfigid", tdx->mrconfigid,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrowner", tdx->mrowner,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrownerconfig", tdx->mrownerconfig,
                               OBJ_PROP_FLAG_READWRITE);

    tdx->quote_generation_str = NULL;
    tdx->quote_generation = NULL;
    object_property_add_str(obj, "quote-generation-service",
                            tdx_guest_get_quote_generation,
                            tdx_guest_set_quote_generation);

    tdx->event_notify_interrupt = -1;
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

#define TDG_VP_VMCALL_GET_QUOTE                         0x10002ULL
#define TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT      0x10004ULL

#define TDG_VP_VMCALL_SUCCESS           0x0000000000000000ULL
#define TDG_VP_VMCALL_RETRY             0x0000000000000001ULL
#define TDG_VP_VMCALL_INVALID_OPERAND   0x8000000000000000ULL
#define TDG_VP_VMCALL_ALIGN_ERROR       0x8000000000000002ULL

#define TDX_GET_QUOTE_STRUCTURE_VERSION 1ULL

#define TDX_VP_GET_QUOTE_SUCCESS                0ULL
#define TDX_VP_GET_QUOTE_IN_FLIGHT              (-1ULL)
#define TDX_VP_GET_QUOTE_ERROR                  0x8000000000000000ULL
#define TDX_VP_GET_QUOTE_QGS_UNAVAILABLE        0x8000000000000001ULL

/* Limit to avoid resource starvation. */
#define TDX_GET_QUOTE_MAX_BUF_LEN       (128 * 1024)
#define TDX_MAX_GET_QUOTE_REQUEST       16

/* Format of pages shared with guest. */
struct tdx_get_quote_header {
    /* Format version: must be 1 in little endian. */
    uint64_t structure_version;

    /*
     * GetQuote status code in little endian:
     *   Guest must set error_code to 0 to avoid information leak.
     *   Qemu sets this before interrupting guest.
     */
    uint64_t error_code;

    /*
     * in-message size in little endian: The message will follow this header.
     * The in-message will be send to QGS.
     */
    uint32_t in_len;

    /*
     * out-message size in little endian:
     * On request, out_len must be zero to avoid information leak.
     * On return, message size from QGS. Qemu overwrites this field.
     * The message will follows this header.  The in-message is overwritten.
     */
    uint32_t out_len;

    /*
     * Message buffer follows.
     * Guest sets message that will be send to QGS.  If out_len > in_len, guest
     * should zero remaining buffer to avoid information leak.
     * Qemu overwrites this buffer with a message returned from QGS.
     */
};

struct tdx_get_quote_task {
    uint32_t apic_id;
    hwaddr gpa;
    uint64_t buf_len;
    struct tdx_get_quote_header hdr;
    int event_notify_interrupt;
    QIOChannelSocket *ioc;
};

struct x86_msi {
    union {
        struct {
            uint32_t    reserved_0              : 2,
                        dest_mode_logical       : 1,
                        redirect_hint           : 1,
                        reserved_1              : 1,
                        virt_destid_8_14        : 7,
                        destid_0_7              : 8,
                        base_address            : 12;
        } QEMU_PACKED x86_address_lo;
        uint32_t address_lo;
    };
    union {
        struct {
            uint32_t    reserved        : 8,
                        destid_8_31     : 24;
        } QEMU_PACKED x86_address_hi;
        uint32_t address_hi;
    };
    union {
        struct {
            uint32_t    vector                  : 8,
                        delivery_mode           : 3,
                        dest_mode_logical       : 1,
                        reserved                : 2,
                        active_low              : 1,
                        is_level                : 1;
        } QEMU_PACKED x86_data;
        uint32_t data;
    };
};

static void tdx_td_notify(struct tdx_get_quote_task *t)
{
    struct x86_msi x86_msi;
    struct kvm_msi msi;
    int ret;

    /* It is optional for host VMM to interrupt TD. */
    if(!(32 <= t->event_notify_interrupt && t->event_notify_interrupt <= 255))
        return;

    x86_msi = (struct x86_msi) {
        .x86_address_lo  = {
            .reserved_0 = 0,
            .dest_mode_logical = 0,
            .redirect_hint = 0,
            .reserved_1 = 0,
            .virt_destid_8_14 = 0,
            .destid_0_7 = t->apic_id & 0xff,
        },
        .x86_address_hi = {
            .reserved = 0,
            .destid_8_31 = t->apic_id >> 8,
        },
        .x86_data = {
            .vector = t->event_notify_interrupt,
            .delivery_mode = APIC_DM_FIXED,
            .dest_mode_logical = 0,
            .reserved = 0,
            .active_low = 0,
            .is_level = 0,
        },
    };
    msi = (struct kvm_msi) {
        .address_lo = x86_msi.address_lo,
        .address_hi = x86_msi.address_hi,
        .data = x86_msi.data,
        .flags = 0,
        .devid = 0,
    };
    ret = kvm_vm_ioctl(kvm_state, KVM_SIGNAL_MSI, &msi);
    if (ret < 0) {
        /* In this case, no better way to tell it to guest.  Log it. */
        error_report("TDX: injection %d failed, interrupt lost (%s).\n",
                     t->event_notify_interrupt, strerror(-ret));
    }
}

/*
 * TODO: If QGS doesn't reply for long time, make it an error and interrupt
 * guest.
 */
static void tdx_handle_get_quote_connected(QIOTask *task, gpointer opaque)
{
    struct tdx_get_quote_task *t = opaque;
    Error *err = NULL;
    char *in_data = NULL;
    char *out_data = NULL;
    size_t out_len;
    ssize_t size;
    MachineState *ms;
    TdxGuest *tdx;

    t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_ERROR);
    if (qio_task_propagate_error(task, NULL)) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto error;
    }

    in_data = g_malloc(le32_to_cpu(t->hdr.in_len));
    if (address_space_read(&address_space_memory, t->gpa + sizeof(t->hdr),
                           MEMTXATTRS_UNSPECIFIED, in_data,
                           le32_to_cpu(t->hdr.in_len)) != MEMTX_OK) {
        goto error;
    }

    if (qio_channel_write_all(QIO_CHANNEL(t->ioc), in_data,
                              le32_to_cpu(t->hdr.in_len), &err) ||
        err) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto error;
    }

    out_data = g_malloc(t->buf_len);
    out_len = 0;
    size = 0;
    while (out_len < t->buf_len) {
        size = qio_channel_read(
            QIO_CHANNEL(t->ioc), out_data + out_len, t->buf_len - out_len, &err);
        if (err) {
            break;
        }
        if (size <= 0) {
            break;
        }
        out_len += size;
    }
    /*
     * Treat partial read as success and let the QGS client to handle it because
     * the client knows better about the QGS.
     */
    if (out_len == 0 && (err || size < 0)) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto error;
    }

    if (address_space_write(
            &address_space_memory, t->gpa + sizeof(t->hdr),
            MEMTXATTRS_UNSPECIFIED, out_data, out_len) != MEMTX_OK) {
        goto error;
    }
    /*
     * Even if out_len == 0, it's a success.  It's up to the QGS-client contract
     * how to interpret the zero-sized message as return message.
     */
    t->hdr.out_len = cpu_to_le32(out_len);
    t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_SUCCESS);

error:
    if (t->hdr.error_code != cpu_to_le64(TDX_VP_GET_QUOTE_SUCCESS)) {
        t->hdr.out_len = cpu_to_le32(0);
    }
    if (address_space_write(
            &address_space_memory, t->gpa,
            MEMTXATTRS_UNSPECIFIED, &t->hdr, sizeof(t->hdr)) != MEMTX_OK) {
        error_report("TDX: failed to updsate GetQuote header.\n");
    }
    tdx_td_notify(t);

    qio_channel_close(QIO_CHANNEL(t->ioc), &err);
    object_unref(OBJECT(t->ioc));
    g_free(in_data);
    g_free(out_data);

    /* Maintain the number of in-flight requests. */
    ms = MACHINE(qdev_get_machine());
    tdx = TDX_GUEST(ms->cgs);
    qemu_mutex_lock(&tdx->lock);
    tdx->quote_generation_num--;
    qemu_mutex_unlock(&tdx->lock);

    return;
}

static void tdx_handle_get_quote(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    hwaddr gpa = vmcall->in_r12;
    uint64_t buf_len = vmcall->in_r13;
    struct tdx_get_quote_header hdr;
    MachineState *ms;
    TdxGuest *tdx;
    QIOChannelSocket *ioc;
    struct tdx_get_quote_task *t;

    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    if (!QEMU_IS_ALIGNED(gpa, 4096) || !QEMU_IS_ALIGNED(buf_len, 4096)) {
        vmcall->status_code = TDG_VP_VMCALL_ALIGN_ERROR;
        return;
    }
    if (buf_len == 0) {
        /*
         * REVERTME: Accept old GHCI GetQuote with R13 buf_len = 0.
         * buf size is 8KB. also hdr.out_len includes the header size.
         */
#define GHCI_GET_QUOTE_BUFSIZE_OLD      (8 * 1024)
        warn_report("Guest attestation driver uses old GetQuote ABI.(R13 == 0) "
                    "Please upgrade guest kernel.\n");
        buf_len = GHCI_GET_QUOTE_BUFSIZE_OLD;
    }

    if (address_space_read(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                           &hdr, sizeof(hdr)) != MEMTX_OK) {
        return;
    }
    if (le64_to_cpu(hdr.structure_version) != TDX_GET_QUOTE_STRUCTURE_VERSION) {
        return;
    }
    /*
     * Paranoid: Guest should clear error_code and out_len to avoid information
     * leak.  Enforce it.  The initial value of them doesn't matter for qemu to
     * process the request.
     */
    if (le64_to_cpu(hdr.error_code) != TDX_VP_GET_QUOTE_SUCCESS
        /* || le32_to_cpu(hdr.out_len) != 0 */) {
        return;
    }
    if (le32_to_cpu(hdr.out_len) > 0) {
        /* REVERTME: old shared page format. */
        warn_report("Guest attestation driver or R3AAL uses old GetQuote format."
                    "(out_len > 0) Please upgrade driver or R3AAL library.\n");
        if (le32_to_cpu(hdr.out_len) + sizeof(hdr) > buf_len) {
            return;
        }
        hdr.out_len = cpu_to_le32(0);
    }

    /* Only safe-guard check to avoid too large buffer size. */
    if (buf_len > TDX_GET_QUOTE_MAX_BUF_LEN ||
        le32_to_cpu(hdr.in_len) > TDX_GET_QUOTE_MAX_BUF_LEN ||
        le32_to_cpu(hdr.in_len) > buf_len) {
        return;
    }

    /* Mark the buffer in-flight. */
    hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_IN_FLIGHT);
    if (address_space_write(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                            &hdr, sizeof(hdr)) != MEMTX_OK) {
        return;
    }

    ms = MACHINE(qdev_get_machine());
    tdx = TDX_GUEST(ms->cgs);
    ioc = qio_channel_socket_new();

    t = g_malloc(sizeof(*t));
    t->apic_id = cpu->apic_id;
    t->gpa = gpa;
    t->buf_len = buf_len;
    t->hdr = hdr;
    t->ioc = ioc;

    qemu_mutex_lock(&tdx->lock);
    /*
     * If Quote Generation Service(QGS) isn't unavailable, return RETRY in the
     * expectation that the cloud admin will set later.
     */
    if (!tdx->quote_generation ||
        /* Prevent too many in-flight get-quote request. */
        tdx->quote_generation_num >= TDX_MAX_GET_QUOTE_REQUEST) {
        qemu_mutex_unlock(&tdx->lock);
        vmcall->status_code = TDG_VP_VMCALL_RETRY;
        object_unref(OBJECT(ioc));
        g_free(t);
        return;
    }
    tdx->quote_generation_num++;
    t->event_notify_interrupt = tdx->event_notify_interrupt;
    qio_channel_socket_connect_async(
        ioc, tdx->quote_generation, tdx_handle_get_quote_connected, t, g_free,
        NULL);
    qemu_mutex_unlock(&tdx->lock);

    vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
}

static void tdx_handle_setup_event_notify_interrupt(struct kvm_tdx_vmcall *vmcall)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = TDX_GUEST(ms->cgs);
    int event_notify_interrupt = vmcall->in_r12;

    if (32 <= event_notify_interrupt && event_notify_interrupt <= 255) {
        qemu_mutex_lock(&tdx->lock);
        tdx->event_notify_interrupt = event_notify_interrupt;
        qemu_mutex_unlock(&tdx->lock);
        vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    }
}

static void tdx_handle_vmcall(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    /* For now handle only TDG.VP.VMCALL. */
    if (vmcall->type != 0) {
        warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx",
                    vmcall->type, vmcall->subfunction);
        return;
    }

    switch (vmcall->subfunction) {
    case TDG_VP_VMCALL_GET_QUOTE:
        tdx_handle_get_quote(cpu, vmcall);
        break;
    case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
        tdx_handle_setup_event_notify_interrupt(vmcall);
        break;
    default:
        warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx",
                    vmcall->type, vmcall->subfunction);
        break;
    }
}

void tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit)
{
    if (!kvm_tdx_enabled())
        return;

    switch (tdx_exit->type) {
    case KVM_EXIT_TDX_VMCALL:
        tdx_handle_vmcall(cpu, &tdx_exit->u.vmcall);
        break;
    default:
        warn_report("unknown tdx exit type 0x%x", tdx_exit->type);
        break;
    }
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
