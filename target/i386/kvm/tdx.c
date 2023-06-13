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
#include "qemu/error-report.h"
#include "qemu/mmap-alloc.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"
#include "sysemu/runstate.h"

#include "exec/address-spaces.h"
#include "exec/ramblock.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/x86.h"
#include "hw/i386/tdvf.h"
#include "hw/i386/tdvf-hob.h"
#include "kvm_i386.h"
#include "tdx.h"
#include "../cpu-internal.h"

#include "trace.h"

#define TDX_SUPPORTED_KVM_FEATURES  ((1U << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1U << KVM_FEATURE_PV_UNHALT) | \
                                     (1U << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1U << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1U << KVM_FEATURE_POLL_CONTROL) | \
                                     (1U << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1U << KVM_FEATURE_MSI_EXT_DEST_ID))

#define TDX_MIN_TSC_FREQUENCY_KHZ   (100 * 1000)
#define TDX_MAX_TSC_FREQUENCY_KHZ   (10 * 1000 * 1000)

#define TDX_TD_ATTRIBUTES_DEBUG             BIT_ULL(0)
#define TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE   BIT_ULL(28)
#define TDX_TD_ATTRIBUTES_PKS               BIT_ULL(30)
#define TDX_TD_ATTRIBUTES_PERFMON           BIT_ULL(63)

#define TDX_ATTRIBUTES_MAX_BITS      64

static FeatureMask tdx_attrs_ctrl_fields[TDX_ATTRIBUTES_MAX_BITS] = {
    [30] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_PKS },
    [31] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_KeyLocker},
};

static FeatureDep xfam_dependencies[] = {
    /* XFAM[7:5] may be set to 111 only when XFAM[2] is set to 1 */
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_1_ECX,
                CPUID_EXT_FMA | CPUID_EXT_AVX | CPUID_EXT_F16C },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_7_0_EBX, CPUID_7_0_EBX_AVX2 },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_VAES | CPUID_7_0_ECX_VPCLMULQDQ},
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_EBX,
                CPUID_7_0_EBX_AVX512F | CPUID_7_0_EBX_AVX512DQ |
                CPUID_7_0_EBX_AVX512IFMA | CPUID_7_0_EBX_AVX512PF |
                CPUID_7_0_EBX_AVX512ER | CPUID_7_0_EBX_AVX512CD |
                CPUID_7_0_EBX_AVX512BW | CPUID_7_0_EBX_AVX512VL },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_ECX,
                CPUID_7_0_ECX_AVX512_VBMI | CPUID_7_0_ECX_AVX512_VBMI2 |
                CPUID_7_0_ECX_AVX512VNNI | CPUID_7_0_ECX_AVX512BITALG |
                CPUID_7_0_ECX_AVX512_VPOPCNTDQ },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_EDX,
                CPUID_7_0_EDX_AVX512_4VNNIW | CPUID_7_0_EDX_AVX512_4FMAPS |
                CPUID_7_0_EDX_AVX512_VP2INTERSECT | CPUID_7_0_EDX_AVX512_FP16 },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_1_EAX, CPUID_7_1_EAX_AVX512_BF16 | CPUID_7_1_EAX_AVX_VNNI },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_PKRU_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_PKU },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AMX_MASK },
        .to = { FEAT_7_0_EDX,
                CPUID_7_0_EDX_AMX_BF16 | CPUID_7_0_EDX_AMX_TILE |
                CPUID_7_0_EDX_AMX_INT8}
    },
    /* XSS features */
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
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_UINTR_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_UNIT },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_ARCH_LBR_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_ARCH_LBR },
    },
};

/*
 * Select a representative feature for each XFAM-controlled features.
 * e.g avx for all XFAM[2]. Only this typcial CPUID is allowed to be
 * configured. This can help prevent unintentional operation by the user.
 */
FeatureMask tdx_xfam_representative[] = {
    [XSTATE_YMM_BIT] = { .index = FEAT_1_ECX, .mask = CPUID_EXT_AVX },
    [XSTATE_OPMASK_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_ZMM_Hi256_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_Hi16_ZMM_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_RTIT_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_INTEL_PT },
    [XSTATE_PKRU_BIT] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_PKU },
    [XSTATE_CET_U_BIT] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_CET_SHSTK },
    [XSTATE_CET_S_BIT] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_CET_SHSTK },
    [XSTATE_ARCH_LBR_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_ARCH_LBR },
    [XSTATE_XTILE_CFG_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_AMX_TILE },
    [XSTATE_XTILE_DATA_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_AMX_TILE },
};

typedef struct KvmTdxCpuidLookup {
    uint32_t tdx_fixed0;
    uint32_t tdx_fixed1;

    /*
     * The CPUID bits that are configurable from the view of TDX module
     * but require VMM emulation if configured to enabled by VMM.
     *
     * For those bits, they cannot be enabled actually if VMM (KVM/QEMU) cannot
     * virtualize them.
     */
    uint32_t vmm_fixup;

    bool inducing_ve;
    /*
     * The maximum supported feature set for given inducing-#VE leaf.
     * It's valid only when .inducing_ve is true.
     */
    uint32_t supported_on_ve;
} KvmTdxCpuidLookup;

 /*
  * QEMU maintained TDX CPUID lookup tables, which reflects how CPUIDs are
  * virtualized for guest TDs based on "CPUID virtualization" of TDX spec.
  *
  * Note:
  *
  * This table will be updated runtime by tdx_caps reported by platform.
  *
  */
static KvmTdxCpuidLookup tdx_cpuid_lookup[FEATURE_WORDS] = {
    [FEAT_1_EDX] = {
        .tdx_fixed0 =
            BIT(10) /* Reserved */ | BIT(20) /* Reserved */ | CPUID_IA64,
        .tdx_fixed1 =
            CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_APIC |
            CPUID_MTRR | CPUID_MCA | CPUID_CLFLUSH | CPUID_DTS,
        .vmm_fixup =
            CPUID_ACPI | CPUID_PBE,
    },
    [FEAT_1_ECX] = {
        .tdx_fixed0 =
            CPUID_EXT_VMX | CPUID_EXT_SMX | BIT(16) /* Reserved */,
        .tdx_fixed1 =
            CPUID_EXT_CX16 | CPUID_EXT_PDCM | CPUID_EXT_X2APIC |
            CPUID_EXT_AES | CPUID_EXT_XSAVE | CPUID_EXT_RDRAND |
            CPUID_EXT_HYPERVISOR,
        .vmm_fixup =
            CPUID_EXT_EST | CPUID_EXT_TM2 | CPUID_EXT_XTPR | CPUID_EXT_DCA,
    },
    [FEAT_8000_0001_EDX] = {
        .tdx_fixed1 =
            CPUID_EXT2_NX | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_LM,
    },
    [FEAT_7_0_EBX] = {
        .tdx_fixed0 =
            CPUID_7_0_EBX_TSC_ADJUST | CPUID_7_0_EBX_SGX | CPUID_7_0_EBX_MPX,
        .tdx_fixed1 =
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_RTM |
            CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_SMAP |
            CPUID_7_0_EBX_CLFLUSHOPT | CPUID_7_0_EBX_CLWB |
            CPUID_7_0_EBX_SHA_NI,
        .vmm_fixup =
            CPUID_7_0_EBX_PQM | CPUID_7_0_EBX_RDT_A,
    },
    [FEAT_7_0_ECX] = {
        .tdx_fixed0 =
            CPUID_7_0_ECX_FZM | CPUID_7_0_ECX_MAWAU |
            CPUID_7_0_ECX_ENQCMD | CPUID_7_0_ECX_SGX_LC,
        .tdx_fixed1 =
            CPUID_7_0_ECX_MOVDIR64B | CPUID_7_0_ECX_BUS_LOCK_DETECT,
        .vmm_fixup =
            CPUID_7_0_ECX_TME,
    },
    [FEAT_7_0_EDX] = {
        .tdx_fixed1 =
            CPUID_7_0_EDX_SPEC_CTRL | CPUID_7_0_EDX_ARCH_CAPABILITIES |
            CPUID_7_0_EDX_CORE_CAPABILITY | CPUID_7_0_EDX_SPEC_CTRL_SSBD,
        .vmm_fixup =
            CPUID_7_0_EDX_PCONFIG,
    },
    [FEAT_8000_0008_EBX] = {
        .tdx_fixed0 =
            ~CPUID_8000_0008_EBX_WBNOINVD,
        .tdx_fixed1 =
            CPUID_8000_0008_EBX_WBNOINVD,
    },
    [FEAT_XSAVE] = {
        .tdx_fixed1 =
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XSAVES,
    },
    [FEAT_6_EAX] = {
        .inducing_ve = true,
        .supported_on_ve = CPUID_6_EAX_ARAT,
    },
    [FEAT_8000_0007_EDX] = {
        .inducing_ve = true,
        .supported_on_ve = -1U,
    },
    [FEAT_KVM] = {
        .inducing_ve = true,
        .supported_on_ve = TDX_SUPPORTED_KVM_FEATURES,
    },
};

static TdxGuest *tdx_guest;

static struct kvm_tdx_capabilities *tdx_caps;

/* It's valid after kvm_confidential_guest_init()->kvm_tdx_init() */
bool is_tdx_vm(void)
{
    return !!tdx_guest;
}

static inline uint32_t host_cpuid_reg(uint32_t function,
                                      uint32_t index, int reg)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t ret = 0;

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
    return ret;
}

static inline uint32_t tdx_cap_cpuid_config(uint32_t function,
                                            uint32_t index, int reg)
{
    struct kvm_tdx_cpuid_config *cpuid_c;
    int ret = 0;
    int i;

    if (tdx_caps->nr_cpuid_configs <= 0) {
        return ret;
    }

    for (i = 0; i < tdx_caps->nr_cpuid_configs; i++) {
        cpuid_c = &tdx_caps->cpuid_configs[i];
        /* 0xffffffff in sub_leaf means the leaf doesn't require a sublesf */
        if (cpuid_c->leaf == function &&
            (cpuid_c->sub_leaf == 0xffffffff || cpuid_c->sub_leaf == index)) {
            switch (reg) {
            case R_EAX:
                ret = cpuid_c->eax;
                break;
            case R_EBX:
                ret = cpuid_c->ebx;
                break;
            case R_ECX:
                ret = cpuid_c->ecx;
                break;
            case R_EDX:
                ret = cpuid_c->edx;
                break;
            default:
                return 0;
            }
        }
    }
    return ret;
}

static FeatureWord get_cpuid_featureword_index(uint32_t function,
                                               uint32_t index, int reg)
{
    FeatureWord w;

    for (w = 0; w < FEATURE_WORDS; w++) {
        FeatureWordInfo *f = &feature_word_info[w];

        if (f->type == MSR_FEATURE_WORD || f->cpuid.eax != function ||
            f->cpuid.reg != reg ||
            (f->cpuid.needs_ecx && f->cpuid.ecx != index)) {
            continue;
        }

        return w;
    }

    return w;
}

/*
 * TDX supported CPUID varies from what KVM reports. Adjust the result by
 * applying the TDX restrictions.
 */
void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret)
{
    uint32_t vmm_cap = *ret;
    FeatureWord w;

    /* Only handle features leaves that recognized by feature_word_info[] */
    w = get_cpuid_featureword_index(function, index, reg);
    if (w == FEATURE_WORDS) {
        return;
    }

    if (tdx_cpuid_lookup[w].inducing_ve) {
        *ret &= tdx_cpuid_lookup[w].supported_on_ve;
        return;
    }

    /*
     * Include all the native bits as first step. It covers types
     * - As configured (if native)
     * - Native
     * - XFAM related and Attributes realted
     *
     * It also has side effect to enable unsupported bits, e.g., the
     * bits of "fixed0" type while present natively. It's safe because
     * the unsupported bits will be masked off by .fixed0 later.
     */
    *ret |= host_cpuid_reg(function, index, reg);

    /* Adjust according to "fixed" type in tdx_cpuid_lookup. */
    *ret |= tdx_cpuid_lookup[w].tdx_fixed1;
    *ret &= ~tdx_cpuid_lookup[w].tdx_fixed0;

    /*
     * Configurable cpuids are supported unconditionally. It's mainly to
     * include those configurable regardless of native existence.
     */
    *ret |= tdx_cap_cpuid_config(function, index, reg);

    /*
     * clear the configurable bits that require VMM emulation and VMM doesn't
     * report the support.
     */
    *ret &= ~(~vmm_cap & tdx_cpuid_lookup[w].vmm_fixup);

    /* special handling */
    if (function == 1 && reg == R_ECX && !enable_cpu_pm)
        *ret &= ~CPUID_EXT_MONITOR;
}

void tdx_apply_xfam_dependencies(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    int i;

    for (i = 0; i < ARRAY_SIZE(xfam_dependencies); i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (!(env->features[d->from.index] & d->from.mask)) {
            uint64_t unavailable_features = env->features[d->to.index] & d->to.mask;

            /* Not an error unless the dependent feature was added explicitly */
            mark_unavailable_features(x86_cpu, d->to.index,
                                     unavailable_features & env->user_plus_features[d->to.index],
                                     "This feature cannot be enabled because its XFAM controlling bit is not enabled");
            env->features[d->to.index] &= ~unavailable_features;
        }
    }
}

static uint64_t tdx_get_xfam_bitmask(FeatureWord w, uint64_t bit_mask)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(xfam_dependencies); i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (w == d->to.index && bit_mask & d->to.mask) {
            return d->from.mask;
        }
    }
    return 0;
}

/* return bit field if xfam representative feature, otherwise -1 */
static int is_tdx_xfam_representative(FeatureWord w, uint64_t bit_mask)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(tdx_xfam_representative); i++) {
        FeatureMask *fm = &tdx_xfam_representative[i];
        if (w == fm->index && bit_mask & fm->mask) {
            return i;
        }
    }
    return -1;
}

static const char *tdx_xfam_representative_name(uint64_t xfam_mask)
{
    uint32_t delegate_index, delegate_feature;
    int bitnr, delegate_bitnr;
    const char *name;

    bitnr = ctz32(xfam_mask);
    delegate_index = tdx_xfam_representative[bitnr].index;
    delegate_feature = tdx_xfam_representative[bitnr].mask;
    delegate_bitnr = ctz32(delegate_feature);
    /* get XFAM feature delegate feature name */
    name = feature_word_info[delegate_index].feat_names[delegate_bitnr];
    assert(delegate_bitnr < 32 ||
           !(name &&
             feature_word_info[delegate_index].type == CPUID_FEATURE_WORD));
    return name;
}

static uint64_t tdx_disallow_minus_bits(FeatureWord w)
{
    FeatureWordInfo *wi = &feature_word_info[w];
    uint64_t ret = 0;
    int i;

    /*
     * TODO:
     * enable MSR feature configuration for TDX, disallow MSR feature
     * manipulation for TDX for now
     */
    if (wi->type == MSR_FEATURE_WORD) {
        return ~0ull;
    }

    /*
     * inducing_ve type is fully configured by VMM, i.e., all are allowed
     * to be removed
     */
    if (tdx_cpuid_lookup[w].inducing_ve) {
        return 0;
    }

    ret = tdx_cpuid_lookup[w].tdx_fixed1;

    for (i = 0; i < ARRAY_SIZE(xfam_dependencies); i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (w == d->to.index) {
            ret |= d->to.mask;
        }
    }

    for (i = 0; i < ARRAY_SIZE(tdx_xfam_representative); i++) {
        FeatureMask *fm = &tdx_xfam_representative[i];
        if (w == fm->index) {
            ret &= ~fm->mask;
        }
    }

    return ret;
}

void tdx_check_minus_features(CPUState *cpu)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    FeatureWordInfo *wi;
    FeatureWord w;
    uint64_t disallow_minus_bits;
    uint64_t bitmask, xfam_controlling_mask;
    int i;

    char *reason;
    char xfam_dependency_str[100];
    char usual[]="TDX limitation";

    for (w = 0; w < FEATURE_WORDS; w++) {
        wi = &feature_word_info[w];

        if (wi->type == MSR_FEATURE_WORD) {
            continue;
        }

        disallow_minus_bits = env->user_minus_features[w] & tdx_disallow_minus_bits(w);

        for (i = 0; i < 64; i++) {
            bitmask = 1ULL << i;
            if (!(bitmask & disallow_minus_bits)) {
                continue;
            }

            xfam_controlling_mask = tdx_get_xfam_bitmask(w, bitmask);
            if (xfam_controlling_mask && is_tdx_xfam_representative(w, bitmask) == -1) {
                /*
                 * cannot fix env->feature[w] here since whether the bit i is
                 * set or cleared depends on the setting of its XFAM
                 * representative feature bit
                 */
                snprintf(xfam_dependency_str, sizeof(xfam_dependency_str),
                         "it depends on XFAM representative feature (%s)",
                 g_strdup(tdx_xfam_representative_name(xfam_controlling_mask)));
                reason = xfam_dependency_str;
            } else {
                /* set bit i since this feature cannot be removed */
                env->features[w] |= bitmask;
                reason = usual;
            }

            g_autofree char *feature_word_str = feature_word_description(wi, i);
            warn_report("This feature cannot be removed becuase %s: %s%s%s [bit %d]",
                         reason, feature_word_str,
                         wi->feat_names[i] ? "." : "",
                         wi->feat_names[i] ?: "", i);
        }
    }
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

static inline int tdx_platform_ioctl(int cmd_id, __u32 flags, void *data)
{
    return __tdx_ioctl(NULL, TDX_PLATFORM_IOCTL, cmd_id, flags, data);
}

static inline int tdx_vm_ioctl(int cmd_id, __u32 flags, void *data)
{
    return __tdx_ioctl(NULL, TDX_VM_IOCTL, cmd_id, flags, data);
}

static inline int tdx_vcpu_ioctl(void *vcpu_fd, int cmd_id, __u32 flags,
                                 void *data)
{
    return  __tdx_ioctl(vcpu_fd, TDX_VCPU_IOCTL, cmd_id, flags, data);
}

static void get_tdx_capabilities(void)
{
    struct kvm_tdx_capabilities *caps;
    /* 1st generation of TDX reports 6 cpuid configs */
    int nr_cpuid_configs = 6;
    int r, size;

    do {
        size = sizeof(struct kvm_tdx_capabilities) +
               nr_cpuid_configs * sizeof(struct kvm_tdx_cpuid_config);
        caps = g_malloc0(size);
        caps->nr_cpuid_configs = nr_cpuid_configs;

        r = tdx_platform_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
        if (r == -EINVAL ) {
            g_free(caps);
            break;
        }

        if (r == -E2BIG) {
            g_free(caps);
            nr_cpuid_configs *= 2;
            if (nr_cpuid_configs > KVM_MAX_CPUID_ENTRIES) {
                error_report("KVM TDX seems broken that number of CPUID entries in kvm_tdx_capabilities exceeds limit");
                exit(1);
            }
        } else if (r < 0) {
            g_free(caps);
            error_report("KVM_TDX_CAPABILITIES failed: %s", strerror(-r));
            exit(1);
        }
    }
    while (r == -E2BIG);

    if (r == -EINVAL) {
        nr_cpuid_configs = 6;
        do {
            size = sizeof(struct kvm_tdx_capabilities) +
                nr_cpuid_configs * sizeof(struct kvm_tdx_cpuid_config);
            caps = g_malloc0(size);
            caps->nr_cpuid_configs = nr_cpuid_configs;

            r = tdx_vm_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
            if (r == -E2BIG) {
                g_free(caps);
                if (nr_cpuid_configs > KVM_MAX_CPUID_ENTRIES) {
                    error_report("KVM TDX seems broken");
                    exit(1);
                }
                nr_cpuid_configs *= 2;
            } else if (r < 0) {
                g_free(caps);
                error_report("KVM_TDX_CAPABILITIES failed: %s\n", strerror(-r));
                exit(1);
            }
        }
        while (r == -E2BIG);
    }

    tdx_caps = caps;
}

static void update_tdx_cpuid_lookup_by_tdx_caps(void)
{
    KvmTdxCpuidLookup *entry;
    FeatureWordInfo *fi;
    uint32_t config;
    FeatureWord w;
    FeatureMask *fm;
    int i;

    /*
     * Patch tdx_fixed0/1 by tdx_caps that what TDX module reports as
     * configurable is not fixed.
     */
    for (w = 0; w < FEATURE_WORDS; w++) {
        fi = &feature_word_info[w];
        entry = &tdx_cpuid_lookup[w];

        if (fi->type != CPUID_FEATURE_WORD) {
            continue;
        }

        config = tdx_cap_cpuid_config(fi->cpuid.eax,
                                      fi->cpuid.needs_ecx ? fi->cpuid.ecx : ~0u,
                                      fi->cpuid.reg);

        entry->tdx_fixed0 &= ~config;
        entry->tdx_fixed1 &= ~config;
    }

    for (i = 0; i < ARRAY_SIZE(tdx_attrs_ctrl_fields); i++) {
        fm = &tdx_attrs_ctrl_fields[i];

        if (tdx_caps->attrs_fixed0 & (1ULL << i)) {
            tdx_cpuid_lookup[fm->index].tdx_fixed0 |= fm->mask;
        }

        if (tdx_caps->attrs_fixed1 & (1ULL << i)) {
            tdx_cpuid_lookup[fm->index].tdx_fixed1 |= fm->mask;
        }
    }

    /*
     * Because KVM gets XFAM settings via CPUID leaves 0xD,  map
     * tdx_caps->xfam_fixed{0, 1} into tdx_cpuid_lookup[].tdx_fixed{0, 1}.
     *
     * Then the enforment applies in tdx_get_configurable_cpuid() naturally.
     */
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_LO].tdx_fixed0 =
            (uint32_t)~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XCR0_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_LO].tdx_fixed1 =
            (uint32_t)tdx_caps->xfam_fixed1 & CPUID_XSTATE_XCR0_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_HI].tdx_fixed0 =
            (~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XCR0_MASK) >> 32;
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_HI].tdx_fixed1 =
            (tdx_caps->xfam_fixed1 & CPUID_XSTATE_XCR0_MASK) >> 32;

    tdx_cpuid_lookup[FEAT_XSAVE_XSS_LO].tdx_fixed0 =
            (uint32_t)~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XSS_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XSS_LO].tdx_fixed1 =
            (uint32_t)tdx_caps->xfam_fixed1 & CPUID_XSTATE_XSS_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XSS_HI].tdx_fixed0 =
            (~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XSS_MASK) >> 32;
    tdx_cpuid_lookup[FEAT_XSAVE_XSS_HI].tdx_fixed1 =
            (tdx_caps->xfam_fixed1 & CPUID_XSTATE_XSS_MASK) >> 32;
}

void tdx_set_tdvf_region(MemoryRegion *tdvf_region)
{
    assert(!tdx_guest->tdvf_region);
    tdx_guest->tdvf_region = tdvf_region;
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
    uint64_t head_start, tail_start, head_length, tail_length;
    uint64_t tmp_address, tmp_length;
    TdxRamEntry *e;
    int i;

    for (i = 0; i < tdx_guest->nr_ram_entries; i++) {
        e = &tdx_guest->ram_entries[i];

        if (address + length <= e->address ||
            e->address + e->length <= address) {
                continue;
        }

        /*
         * The to-be-accepted ram range must be fully contained by one
         * RAM entry.
         */
        if (e->address > address ||
            e->address + e->length < address + length) {
            return -EINVAL;
        }

        if (e->type == TDX_RAM_ADDED) {
            return -EINVAL;
        }

        break;
    }

    if (i == tdx_guest->nr_ram_entries) {
        return -1;
    }

    tmp_address = e->address;
    tmp_length = e->length;

    e->address = address;
    e->length = length;
    e->type = TDX_RAM_ADDED;

    head_length = address - tmp_address;
    if (head_length > 0) {
        head_start = tmp_address;
        tdx_add_ram_entry(head_start, head_length, TDX_RAM_UNACCEPTED);
    }

    tail_start = address + length;
    if (tail_start < tmp_address + tmp_length) {
        tail_length = tmp_address + tmp_length - tail_start;
        tdx_add_ram_entry(tail_start, tail_length, TDX_RAM_UNACCEPTED);
    }

    return 0;
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
        apic_force_x2apic(X86_CPU(cpu)->apic_state);

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
    RAMBlock *ram_block;
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

        r = kvm_encrypt_region(entry->address, entry->size, true);
        if (r < 0) {
             error_report("Reserve initial private memory failed %s", strerror(-r));
             exit(1);
        }

        __u32 flags = entry->attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND ?
                      KVM_TDX_MEASURE_MEMORY_REGION : 0;

        trace_kvm_tdx_init_mem_region(entry->type, entry->attributes, mem_region.source_addr, mem_region.gpa, mem_region.nr_pages);
        r = tdx_vm_ioctl(KVM_TDX_INIT_MEM_REGION, flags, &mem_region);
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

    /* Tdvf image was copied into private region above. It becomes unnecessary. */
    ram_block = tdx_guest->tdvf_region->ram_block;
    ram_block_discard_range(ram_block, 0, ram_block->max_length);

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

    x86ms->eoi_intercept_unsupported = true;

    if (!tdx_caps) {
        get_tdx_capabilities();
    }

    update_tdx_cpuid_lookup_by_tdx_caps();

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

    if ((tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) &&
        kvm_vm_check_extension(kvm_state, KVM_CAP_ENCRYPT_MEMORY_DEBUG)) {
        kvm_setup_set_memory_region_debug_ops(kvm_state,
                                              kvm_encrypted_guest_set_memory_region_debug_ops);
        set_encrypted_memory_debug_ops();
    }

    return 0;
}

static int tdx_validate_attributes(TdxGuest *tdx)
{
    if (((tdx->attributes & tdx_caps->attrs_fixed0) | tdx_caps->attrs_fixed1) !=
        tdx->attributes) {
            error_report("Invalid attributes 0x%lx for TDX VM (fixed0 0x%llx, fixed1 0x%llx)",
                          tdx->attributes, tdx_caps->attrs_fixed0, tdx_caps->attrs_fixed1);
            return -EINVAL;
    }

    /*
    if (tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) {
        error_report("Current QEMU doesn't support attributes.debug[bit 0] for TDX VM");
        return -EINVAL;
    }
    */

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
    union {
        struct kvm_tdx_init_vm init_vm;
        uint8_t data[16 * 1024];
    } init_vm;
    int r = 0;

    qemu_mutex_lock(&tdx_guest->lock);
    if (tdx_guest->initialized) {
        goto out;
    }

    r = kvm_vm_enable_cap(kvm_state, KVM_CAP_MAX_VCPUS, 0, ms->smp.cpus);
    if (r < 0) {
        error_report("Unable to set MAX VCPUS to %d", ms->smp.cpus);
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

    /* it's safe even env->tsc_khz is 0. KVM uses host's tsc_khz in this case */
    r = kvm_vm_ioctl(kvm_state, KVM_SET_TSC_KHZ, env->tsc_khz);
    if (r < 0) {
        error_report("Unable to set TSC frequency to %" PRId64 " kHz", env->tsc_khz);
        goto out;
    }

    r = setup_td_guest_attributes(x86cpu);
    if (r) {
        goto out;
    }

    memset(&init_vm, 0, sizeof(init_vm));
    init_vm.init_vm.cpuid.nent = kvm_x86_arch_cpuid(env, init_vm.init_vm.cpuid.entries, 0);

    init_vm.init_vm.attributes = tdx_guest->attributes;

    QEMU_BUILD_BUG_ON(sizeof(init_vm.init_vm.mrconfigid) != sizeof(tdx_guest->mrconfigid));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.init_vm.mrowner) != sizeof(tdx_guest->mrowner));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.init_vm.mrownerconfig) != sizeof(tdx_guest->mrownerconfig));
    memcpy(init_vm.init_vm.mrconfigid, tdx_guest->mrconfigid, sizeof(init_vm.init_vm.mrconfigid));
    memcpy(init_vm.init_vm.mrowner, tdx_guest->mrowner, sizeof(init_vm.init_vm.mrowner));
    memcpy(init_vm.init_vm.mrownerconfig, tdx_guest->mrownerconfig, sizeof(init_vm.init_vm.mrownerconfig));

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

static bool tdx_guest_get_sept_ve_disable(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return !!(tdx->attributes & TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE);
}

static void tdx_guest_set_sept_ve_disable(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    if (value) {
        tdx->attributes |= TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    } else {
        tdx->attributes &= ~TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    }
}

static bool tdx_guest_get_debug(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return !!(tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG);
}

static void tdx_guest_set_debug(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    if (value) {
        tdx->attributes |= TDX_TD_ATTRIBUTES_DEBUG;
    } else {
        tdx->attributes &= ~TDX_TD_ATTRIBUTES_DEBUG;
    }
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

static void tdx_guest_region_add(MemoryListener *listener,
                                 MemoryRegionSection *section)
{
    MemoryRegion *mr = section->mr;
    Object *owner = memory_region_owner(mr);

    if (owner && object_dynamic_cast(owner, TYPE_MEMORY_BACKEND) &&
        object_property_get_bool(owner, "private", NULL) &&
        mr->ram_block && mr->ram_block->gmem_fd < 0) {
        struct kvm_create_guest_memfd gmem = {
            .size = memory_region_size(mr),
            /* TODO: add property to hostmem backend for huge pmd */
            .flags = KVM_GUEST_MEMFD_HUGE_PMD,
        };
        int fd;

        fd = kvm_vm_ioctl(kvm_state, KVM_CREATE_GUEST_MEMFD, &gmem);
        if (fd < 0) {
            fprintf(stderr, "%s: error creating gmem: %s\n", __func__,
                    strerror(-fd));
            abort();
        }
        memory_region_set_gmem_fd(mr, fd);
    }

    if (memory_region_can_be_private(mr)) {
        memory_region_set_default_private(mr);
    }
}

static MemoryListener tdx_memory_listener = {
    .name = TYPE_TDX_GUEST,
    .region_add = tdx_guest_region_add,
    /* Higher than KVM memory listener = 10. */
    .priority = 20,
};

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
    static bool memory_listener_registered = false;

    if (!memory_listener_registered) {
        memory_listener_register(&tdx_memory_listener, &address_space_memory);
        memory_listener_registered = true;
    }

    qemu_mutex_init(&tdx->lock);

    tdx->attributes = TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;

    object_property_add_bool(obj, "sept-ve-disable",
                             tdx_guest_get_sept_ve_disable,
                             tdx_guest_set_sept_ve_disable);
    object_property_add_bool(obj, "debug",
                             tdx_guest_get_debug,
                             tdx_guest_set_debug);
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
    tdx->apic_id = -1;
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}

#define TDG_VP_VMCALL_MAP_GPA                           0x10001ULL
#define TDG_VP_VMCALL_GET_QUOTE                         0x10002ULL
#define TDG_VP_VMCALL_REPORT_FATAL_ERROR                0x10003ULL
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

static hwaddr tdx_shared_bit(X86CPU *cpu)
{
    return (cpu->phys_bits > 48) ? BIT_ULL(51) : BIT_ULL(47);
}

static void tdx_handle_map_gpa(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    hwaddr addr_mask = (1ULL << cpu->phys_bits) - 1;
    hwaddr shared_bit = tdx_shared_bit(cpu);
    hwaddr gpa = vmcall->in_r12 & ~shared_bit;
    bool private = !(vmcall->in_r12 & shared_bit);
    hwaddr size = vmcall->in_r13;
    int ret = 0;

    trace_tdx_handle_map_gpa(gpa, size, private ? "private" : "shared");
    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    if (gpa & ~addr_mask) {
        return;
    }
    if (!QEMU_IS_ALIGNED(gpa, 4096) || !QEMU_IS_ALIGNED(size, 4096)) {
        vmcall->status_code = TDG_VP_VMCALL_ALIGN_ERROR;
        return;
    }

    if (size > 0) {
        ret = kvm_convert_memory(gpa, size, private);
    }

    if (!ret) {
        vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    }
}

struct tdx_get_quote_task {
    uint32_t apic_id;
    hwaddr gpa;
    uint64_t buf_len;
    char *out_data;
    uint64_t out_len;
    struct tdx_get_quote_header hdr;
    int event_notify_interrupt;
    QIOChannelSocket *ioc;
    QEMUTimer timer;
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

static void tdx_getquote_task_cleanup(struct tdx_get_quote_task *t, bool outlen_overflow)
{
    MachineState *ms;
    TdxGuest *tdx;

    if (t->hdr.error_code != cpu_to_le64(TDX_VP_GET_QUOTE_SUCCESS) && !outlen_overflow) {
        t->hdr.out_len = cpu_to_le32(0);
    }

    if (address_space_write(
            &address_space_memory, t->gpa,
            MEMTXATTRS_UNSPECIFIED, &t->hdr, sizeof(t->hdr)) != MEMTX_OK) {
        error_report("TDX: failed to update GetQuote header.");
    }
    tdx_td_notify(t);

    if (t->ioc->fd > 0) {
        qemu_set_fd_handler(t->ioc->fd, NULL, NULL, NULL);
    }
    qio_channel_close(QIO_CHANNEL(t->ioc), NULL);
    object_unref(OBJECT(t->ioc));
    timer_del(&t->timer);
    g_free(t->out_data);
    g_free(t);

    /* Maintain the number of in-flight requests. */
    ms = MACHINE(qdev_get_machine());
    tdx = TDX_GUEST(ms->cgs);
    qemu_mutex_lock(&tdx->lock);
    tdx->quote_generation_num--;
    qemu_mutex_unlock(&tdx->lock);
}


static void tdx_get_quote_read(void *opaque)
{
    struct tdx_get_quote_task *t = opaque;
    ssize_t size = 0;
    Error *err = NULL;
    bool outlen_overflow = false;

    while (true) {
        char *buf;
        size_t buf_size;

        if (t->out_len < t->buf_len) {
            buf = t->out_data + t->out_len;
            buf_size = t->buf_len - t->out_len;
        } else {
            /*
             * The received data is too large to fit in the shared GPA.
             * Discard the received data and try to know the data size.
             */
            buf = t->out_data;
            buf_size = t->buf_len;
        }

        size = qio_channel_read(QIO_CHANNEL(t->ioc), buf, buf_size, &err);
        if (!size) {
            break;
        }

        if (size < 0) {
            if (size == QIO_CHANNEL_ERR_BLOCK) {
                return;
            } else {
                break;
            }
        }
        t->out_len += size;
    }
    /*
     * If partial read successfully but return error at last, also treat it
     * as failure.
     */
    if (size < 0) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto error;
    }
    if (t->out_len > 0 && t->out_len > t->buf_len) {
        /*
         * There is no specific error code defined for this case(E2BIG) at the
         * moment.
         * TODO: Once an error code for this case is defined in GHCI spec ,
         * update the error code and the tdx_getquote_task_cleanup() argument.
         */
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_ERROR);
        t->hdr.out_len = cpu_to_le32(t->out_len);
        outlen_overflow = true;
        goto error;
    }

    if (address_space_write(
            &address_space_memory, t->gpa + sizeof(t->hdr),
            MEMTXATTRS_UNSPECIFIED, t->out_data, t->out_len) != MEMTX_OK) {
        goto error;
    }
    /*
     * Even if out_len == 0, it's a success.  It's up to the QGS-client contract
     * how to interpret the zero-sized message as return message.
     */
    t->hdr.out_len = cpu_to_le32(t->out_len);
    t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_SUCCESS);

error:
    tdx_getquote_task_cleanup(t, outlen_overflow);
}

#define TRANSACTION_TIMEOUT 30000

static void getquote_timer_expired(void *opaque)
{
    struct tdx_get_quote_task *t = opaque;

    tdx_getquote_task_cleanup(t, false);
}

static void tdx_transaction_start(struct tdx_get_quote_task *t)
{
    int64_t time;

    time = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    /*
     * Timeout callback and fd callback both run in main loop thread,
     * thus no need to worry about race condition.
     */
    qemu_set_fd_handler(t->ioc->fd, tdx_get_quote_read, NULL, t);
    timer_init_ms(&t->timer, QEMU_CLOCK_VIRTUAL, getquote_timer_expired, t);
    timer_mod(&t->timer, time + TRANSACTION_TIMEOUT);
}

static void tdx_handle_get_quote_connected(QIOTask *task, gpointer opaque)
{
    struct tdx_get_quote_task *t = opaque;
    Error *err = NULL;
    char *in_data = NULL;
    int ret = 0;

    t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_ERROR);
    ret = qio_task_propagate_error(task, NULL);
    if (ret) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto out;
    }

    in_data = g_malloc(le32_to_cpu(t->hdr.in_len));
    if (!in_data) {
        ret = -1;
        goto out;
    }

    ret = address_space_read(&address_space_memory, t->gpa + sizeof(t->hdr),
                             MEMTXATTRS_UNSPECIFIED, in_data,
                             le32_to_cpu(t->hdr.in_len));
    if (ret) {
        g_free(in_data);
        goto out;
    }

    qio_channel_set_blocking(QIO_CHANNEL(t->ioc), false, NULL);

    ret = qio_channel_write_all(QIO_CHANNEL(t->ioc), in_data,
                              le32_to_cpu(t->hdr.in_len), &err);
    if (ret) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        g_free(in_data);
        goto out;
    }

out:
    if (ret) {
        tdx_getquote_task_cleanup(t, false);
    } else {
        tdx_transaction_start(t);
    }
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

    trace_tdx_handle_get_quote(gpa, buf_len);
    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    /* GPA must be shared. */
    if (!(gpa & tdx_shared_bit(cpu))) {
        return;
    }
    gpa &= ~tdx_shared_bit(cpu);

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
    t->apic_id = tdx->apic_id;
    t->gpa = gpa;
    t->buf_len = buf_len;
    t->out_data = g_malloc(t->buf_len);
    t->out_len = 0;
    t->hdr = hdr;
    t->ioc = ioc;

    qemu_mutex_lock(&tdx->lock);
    if (!tdx->quote_generation ||
        /* Prevent too many in-flight get-quote request. */
        tdx->quote_generation_num >= TDX_MAX_GET_QUOTE_REQUEST) {
        qemu_mutex_unlock(&tdx->lock);
        vmcall->status_code = TDG_VP_VMCALL_RETRY;
        object_unref(OBJECT(ioc));
        g_free(t->out_data);
        g_free(t);
        return;
    }
    tdx->quote_generation_num++;
    t->event_notify_interrupt = tdx->event_notify_interrupt;
    qio_channel_socket_connect_async(
        ioc, tdx->quote_generation, tdx_handle_get_quote_connected, t, NULL,
        NULL);
    qemu_mutex_unlock(&tdx->lock);

    vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
}

static void tdx_panicked_on_fatal_error(X86CPU *cpu, uint64_t error_code,
                                        uint64_t gpa, char *message)
{
    GuestPanicInformation *panic_info;

    panic_info = g_new0(GuestPanicInformation, 1);
    panic_info->type = GUEST_PANIC_INFORMATION_TYPE_TDX;
    panic_info->u.tdx.error_code = error_code;
    panic_info->u.tdx.gpa = gpa;
    panic_info->u.tdx.message = (char *)message;

    qemu_system_guest_panicked(panic_info);
}

static void tdx_handle_report_fatal_error(X86CPU *cpu,
                                          struct kvm_tdx_vmcall *vmcall)
{
    uint64_t error_code = vmcall->in_r12;
    char *message = NULL;
    uint64_t gpa = -1ull;

    if (error_code & 0xffff) {
        error_report("invalid error code of TDG.VP.VMCALL<REPORT_FATAL_ERROR>\n");
        exit(1);
    }

    /* it has optional message */
    if (vmcall->in_r14) {
        uint64_t * tmp;

#define GUEST_PANIC_INFO_TDX_MESSAGE_MAX        64
        message = g_malloc0(GUEST_PANIC_INFO_TDX_MESSAGE_MAX + 1);

        tmp = (uint64_t *)message;
        /* The order is defined in TDX GHCI spec */
        *(tmp++) = cpu_to_le64(vmcall->in_r14);
        *(tmp++) = cpu_to_le64(vmcall->in_r15);
        *(tmp++) = cpu_to_le64(vmcall->in_rbx);
        *(tmp++) = cpu_to_le64(vmcall->in_rdi);
        *(tmp++) = cpu_to_le64(vmcall->in_rsi);
        *(tmp++) = cpu_to_le64(vmcall->in_r8);
        *(tmp++) = cpu_to_le64(vmcall->in_r9);
        *(tmp++) = cpu_to_le64(vmcall->in_rdx);
        message[GUEST_PANIC_INFO_TDX_MESSAGE_MAX] = '\0';
        assert((char *)tmp == message + GUEST_PANIC_INFO_TDX_MESSAGE_MAX);
    }

    error_report("TD guest reports fatal error. %s\n", message ? : "");

#define TDX_REPORT_FATAL_ERROR_GPA_VALID    BIT_ULL(63)
    if (error_code & TDX_REPORT_FATAL_ERROR_GPA_VALID) {
	gpa = vmcall->in_r13;
    }

    tdx_panicked_on_fatal_error(cpu, error_code, gpa, message);
}

static void tdx_handle_setup_event_notify_interrupt(
    X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = TDX_GUEST(ms->cgs);
    int event_notify_interrupt = vmcall->in_r12;

    trace_tdx_handle_setup_event_notify_interrupt(event_notify_interrupt);
    if (32 <= event_notify_interrupt && event_notify_interrupt <= 255) {
        qemu_mutex_lock(&tdx->lock);
        tdx->event_notify_interrupt = event_notify_interrupt;
        tdx->apic_id = cpu->apic_id;
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
    case TDG_VP_VMCALL_MAP_GPA:
        tdx_handle_map_gpa(cpu, vmcall);
        break;
    case TDG_VP_VMCALL_GET_QUOTE:
        tdx_handle_get_quote(cpu, vmcall);
        break;
    case TDG_VP_VMCALL_REPORT_FATAL_ERROR:
        tdx_handle_report_fatal_error(cpu, vmcall);
        break;
    case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
        tdx_handle_setup_event_notify_interrupt(cpu, vmcall);
        break;
    default:
        warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx",
                    vmcall->type, vmcall->subfunction);
        break;
    }
}

void tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit)
{
    switch (tdx_exit->type) {
    case KVM_EXIT_TDX_VMCALL:
        tdx_handle_vmcall(cpu, &tdx_exit->u.vmcall);
        break;
    default:
        warn_report("unknown tdx exit type 0x%x", tdx_exit->type);
        break;
    }
}

bool tdx_debug_enabled(void)
{
    if (!is_tdx_vm())
        return false;

    return tdx_guest->attributes & TDX_TD_ATTRIBUTES_DEBUG;
}

static hwaddr tdx_gpa_stolen_mask(void)
{
    X86CPU *x86_cpu = X86_CPU(first_cpu);

    if (!x86_cpu || !x86_cpu->phys_bits)
        return 0ULL;

    if (x86_cpu->phys_bits > 48)
            return 1ULL << 51;
        else
            return 1ULL << 47;
}

hwaddr tdx_remove_stolen_bit(hwaddr gpa)
{
    if (!is_tdx_vm())
        return gpa;
    return gpa & ~tdx_gpa_stolen_mask();
}
