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
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/kvm.h"

#include "hw/i386/x86.h"
#include "kvm_i386.h"
#include "tdx.h"
#include "../cpu-internal.h"

#define TDX_SUPPORTED_KVM_FEATURES  ((1U << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1U << KVM_FEATURE_PV_UNHALT) | \
                                     (1U << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1U << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1U << KVM_FEATURE_POLL_CONTROL) | \
                                     (1U << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1U << KVM_FEATURE_MSI_EXT_DEST_ID))

#define TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE   BIT_ULL(28)

#define TDX_ATTRIBUTES_MAX_BITS      64

static FeatureMask tdx_attrs_ctrl_fields[TDX_ATTRIBUTES_MAX_BITS] = {
    [30] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_PKS },
    [31] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_KeyLocker},
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
            BIT(10) | BIT(20) | CPUID_IA64,
        .tdx_fixed1 =
            CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_APIC |
            CPUID_MTRR | CPUID_MCA | CPUID_CLFLUSH | CPUID_DTS,
        .vmm_fixup =
            CPUID_ACPI | CPUID_PBE,
    },
    [FEAT_1_ECX] = {
        .tdx_fixed0 =
            CPUID_EXT_MONITOR | CPUID_EXT_VMX | CPUID_EXT_SMX |
            BIT(16),
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
    [FEAT_8000_0001_EDX] = {
        .tdx_fixed1 =
            CPUID_EXT2_NX | CPUID_EXT2_PDPE1GB |
            CPUID_EXT2_RDTSCP | CPUID_EXT2_LM,
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
        .supported_on_ve = -1U,
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
        if (r == -E2BIG) {
            g_free(caps);
            nr_cpuid_configs *= 2;
            if (nr_cpuid_configs > KVM_MAX_CPUID_ENTRIES) {
                error_report("KVM TDX seems broken");
                exit(1);
            }
        } else if (r < 0) {
            g_free(caps);
            error_report("KVM_TDX_CAPABILITIES failed: %s\n", strerror(-r));
            exit(1);
        }
    }
    while (r == -E2BIG);

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

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (!tdx_caps) {
        get_tdx_capabilities();
    }

    update_tdx_cpuid_lookup_by_tdx_caps();

    tdx_guest = tdx;

    return 0;
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

    memset(&init_vm, 0, sizeof(init_vm));
    init_vm.cpuid.nent = kvm_x86_arch_cpuid(env, init_vm.entries, 0);

    init_vm.attributes = tdx_guest->attributes;
    init_vm.max_vcpus = ms->smp.cpus;

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

    object_property_add_bool(obj, "sept-ve-disable",
                             tdx_guest_get_sept_ve_disable,
                             tdx_guest_set_sept_ve_disable);
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}
