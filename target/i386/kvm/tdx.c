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
#include "qemu/base64.h"
#include "qemu/mmap-alloc.h"
#include "qapi/error.h"
#include "qapi/qapi-visit-sockets.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"
#include "exec/ramblock.h"

#include "hw/i386/apic_internal.h"
#include "hw/i386/apic-msidef.h"
#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/x86.h"
#include "hw/i386/tdvf.h"
#include "hw/i386/tdvf-hob.h"
#include "hw/pci/msi.h"
#include "kvm_i386.h"
#include "tdx.h"
#include "tdx-quote-generator.h"
#include "../cpu-internal.h"

#define TDX_MIN_TSC_FREQUENCY_KHZ   (100 * 1000)
#define TDX_MAX_TSC_FREQUENCY_KHZ   (10 * 1000 * 1000)

#define TDX_TD_ATTRIBUTES_DEBUG             BIT_ULL(0)
#define TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE   BIT_ULL(28)
#define TDX_TD_ATTRIBUTES_PKS               BIT_ULL(30)
#define TDX_TD_ATTRIBUTES_PERFMON           BIT_ULL(63)



#define TDX_SUPPORTED_KVM_FEATURES  ((1U << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1U << KVM_FEATURE_PV_UNHALT) | \
                                     (1U << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1U << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1U << KVM_FEATURE_POLL_CONTROL) | \
                                     (1U << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1U << KVM_FEATURE_MSI_EXT_DEST_ID))

typedef struct KvmTdxCpuidLookup {
    uint32_t tdx_fixed0;
    uint32_t tdx_fixed1;

    /*
     * The CPUID bits that are configurable from the view of TDX module
     * but require VMM's support when wanting to enable them.
     *
     * For those bits, they cannot be enabled if VMM (KVM/QEMU) doesn't support
     * them.
     */
    uint32_t depends_on_vmm_cap;

    bool inducing_ve;
    /*
     * The maximum supported feature set for given inducing-#VE leaf.
     * It's valid only when .inducing_ve is true.
     */
    uint32_t supported_value_on_ve;
} KvmTdxCpuidLookup;

 /*
  * QEMU maintained TDX CPUID lookup tables, which reflects how CPUIDs are
  * virtualized for guest TDs based on "CPUID virtualization" of TDX spec.
  *
  * Note:
  *
  * This table will be updated runtime by tdx_caps reported by KVM.
  *
  */
static KvmTdxCpuidLookup tdx_cpuid_lookup[FEATURE_WORDS] = {
    [FEAT_1_EDX] = {
        .tdx_fixed0 =
            BIT(10) /* Reserved */ | BIT(20) /* Reserved */ | CPUID_IA64,
        .tdx_fixed1 =
            CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_APIC |
            CPUID_MTRR | CPUID_MCA | CPUID_CLFLUSH | CPUID_DTS,
        .depends_on_vmm_cap =
            CPUID_ACPI | CPUID_PBE,
    },
    [FEAT_1_ECX] = {
        .tdx_fixed0 =
            CPUID_EXT_VMX | CPUID_EXT_SMX | BIT(16) /* Reserved */,
        .tdx_fixed1 =
            CPUID_EXT_CX16 | CPUID_EXT_PDCM | CPUID_EXT_X2APIC |
            CPUID_EXT_AES | CPUID_EXT_XSAVE | CPUID_EXT_RDRAND |
            CPUID_EXT_HYPERVISOR,
        .depends_on_vmm_cap =
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
        .depends_on_vmm_cap =
            CPUID_7_0_EBX_PQM | CPUID_7_0_EBX_RDT_A,
    },
    [FEAT_7_0_ECX] = {
        .tdx_fixed0 =
            CPUID_7_0_ECX_FZM | CPUID_7_0_ECX_MAWAU |
            CPUID_7_0_ECX_ENQCMD | CPUID_7_0_ECX_SGX_LC,
        .tdx_fixed1 =
            CPUID_7_0_ECX_MOVDIR64B | CPUID_7_0_ECX_BUS_LOCK_DETECT,
        .depends_on_vmm_cap =
            CPUID_7_0_ECX_TME,
    },
    [FEAT_7_0_EDX] = {
        .tdx_fixed1 =
            CPUID_7_0_EDX_SPEC_CTRL | CPUID_7_0_EDX_ARCH_CAPABILITIES |
            CPUID_7_0_EDX_CORE_CAPABILITY | CPUID_7_0_EDX_SPEC_CTRL_SSBD,
        .depends_on_vmm_cap =
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
        .supported_value_on_ve = CPUID_6_EAX_ARAT,
    },
    [FEAT_8000_0007_EDX] = {
        .inducing_ve = true,
        .supported_value_on_ve = -1U,
    },
    [FEAT_KVM] = {
        .inducing_ve = true,
        .supported_value_on_ve = TDX_SUPPORTED_KVM_FEATURES,
    },
};

static TdxGuest *tdx_guest;

static struct kvm_tdx_capabilities *tdx_caps;

/* It's valid after kvm_arch_init()->kvm_tdx_init() */
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
        ret = eax;
        break;
    case R_EBX:
        ret = ebx;
        break;
    case R_ECX:
        ret = ecx;
        break;
    case R_EDX:
        ret = edx;
        break;
    }
    return ret;
}

/*
 * get the configurable cpuid bits (can be set to 0 or 1) reported by TDX module
 * from tdx_caps.
 */
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
    /*
     * it's KVMM + QEMU 's capabilities of what CPUID bits is supported or
     * can be emulated as supported.
     */
    uint32_t vmm_cap = *ret;
    FeatureWord w;

    /* Only handle features leaves that recognized by feature_word_info[] */
    w = get_cpuid_featureword_index(function, index, reg);
    if (w == FEATURE_WORDS) {
        return;
    }

    if (tdx_cpuid_lookup[w].inducing_ve) {
        *ret &= tdx_cpuid_lookup[w].supported_value_on_ve;
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
    *ret &= ~(tdx_cpuid_lookup[w].depends_on_vmm_cap & ~vmm_cap);

    /* special handling */
    if (function == 1 && reg == R_ECX && !enable_cpu_pm) {
        *ret &= ~CPUID_EXT_MONITOR;
    }

    /* QEMU Intel-pt support is broken, don't advertise Intel-PT */
    if (function == 7 && reg == R_EBX) {
        *ret &= ~CPUID_7_0_EBX_INTEL_PT;
    }
}

enum tdx_ioctl_level{
    TDX_VM_IOCTL,
    TDX_VCPU_IOCTL,
};

static int tdx_ioctl_internal(enum tdx_ioctl_level level, void *state,
                              int cmd_id, __u32 flags, void *data)
{
    struct kvm_tdx_cmd tdx_cmd = {};
    int r;

    tdx_cmd.id = cmd_id;
    tdx_cmd.flags = flags;
    tdx_cmd.data = (__u64)(unsigned long)data;

    switch (level) {
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

static inline int tdx_vm_ioctl(int cmd_id, __u32 flags, void *data)
{
    return tdx_ioctl_internal(TDX_VM_IOCTL, NULL, cmd_id, flags, data);
}

static inline int tdx_vcpu_ioctl(CPUState *cpu, int cmd_id, __u32 flags,
                                 void *data)
{
    return  tdx_ioctl_internal(TDX_VCPU_IOCTL, cpu, cmd_id, flags, data);
}

static int get_tdx_capabilities(Error **errp)
{
    struct kvm_tdx_capabilities *caps;
    /* 1st generation of TDX reports 6 cpuid configs */
    int nr_cpuid_configs = 6;
    size_t size;
    int r;

    do {
        size = sizeof(struct kvm_tdx_capabilities) +
               nr_cpuid_configs * sizeof(struct kvm_tdx_cpuid_config);
        caps = g_malloc0(size);
        caps->nr_cpuid_configs = nr_cpuid_configs;

        r = tdx_vm_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
        if (r == -E2BIG) {
            g_free(caps);
            nr_cpuid_configs *= 2;
            if (nr_cpuid_configs > KVM_MAX_CPUID_ENTRIES) {
                error_setg(errp, "%s: KVM TDX seems broken that number of CPUID "
                           "entries in kvm_tdx_capabilities exceeds limit %d",
                           __func__, KVM_MAX_CPUID_ENTRIES);
                return r;
            }
        } else if (r < 0) {
            g_free(caps);
            error_setg_errno(errp, -r, "%s: KVM_TDX_CAPABILITIES failed", __func__);
            return r;
        }
    }
    while (r == -E2BIG);

    tdx_caps = caps;

    return 0;
}

void tdx_set_tdvf_region(MemoryRegion *tdvf_mr)
{
    assert(!tdx_guest->tdvf_mr);
    tdx_guest->tdvf_mr = tdvf_mr;
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

static void tdx_add_ram_entry(uint64_t address, uint64_t length,
                              enum TdxRamType type)
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
        struct kvm_pre_fault_memory pre_fault = {
            .gpa = entry->address,
            .size = entry->size,
        };
        struct kvm_tdx_init_mem_region region;
        uint32_t flags;

        do {
            r = kvm_vcpu_ioctl(first_cpu, KVM_PRE_FAULT_MEMORY, &pre_fault);
        } while (r == -EAGAIN || r == -EINTR);

        if (r < 0) {
             error_report("KVM_PRE_FAULT_MEMORY failed %s", strerror(-r));
             exit(1);
        }

        region = (struct kvm_tdx_init_mem_region) {
            .source_addr = (uint64_t)entry->mem_ptr,
            .gpa = entry->address,
            .nr_pages = entry->size >> 12,
        };

        flags = entry->attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND ?
                KVM_TDX_MEASURE_MEMORY_REGION : 0;

        do {
            r = tdx_vcpu_ioctl(first_cpu, KVM_TDX_INIT_MEM_REGION, flags, &region);
        } while (r == -EAGAIN || r == -EINTR);
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

    /*
     * TDVF image has been copied into private region above via
     * KVM_MEMORY_MAPPING. It becomes useless.
     */
    ram_block = tdx_guest->tdvf_mr->ram_block;
    ram_block_discard_range(ram_block, 0, ram_block->max_length);

    r = tdx_vm_ioctl(KVM_TDX_FINALIZE_VM, 0, NULL);
    if (r < 0) {
        error_report("KVM_TDX_FINALIZE_VM failed %s", strerror(-r));
        exit(0);
    }
    //kvm_mark_guest_state_protected();
    CONFIDENTIAL_GUEST_SUPPORT(tdx_guest)->ready = true;
}

static Notifier tdx_machine_done_notify = {
    .notify = tdx_finalize_vm,
};

static int tdx_kvm_type(X86ConfidentialGuest *cg)
{
    /* Do the object check */
    TDX_GUEST(cg);

    return KVM_X86_TDX_VM;
}

static int tdx_kvm_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86MachineState *x86ms = X86_MACHINE(ms);
    TdxGuest *tdx = TDX_GUEST(cgs);
    int r = 0;

    kvm_mark_guest_state_protected();

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
        r = get_tdx_capabilities(errp);
        if (r) {
            return r;
        }
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

static int tdx_validate_attributes(TdxGuest *tdx, Error **errp)
{
    if (((tdx->attributes & tdx_caps->attrs_fixed0) | tdx_caps->attrs_fixed1) !=
        tdx->attributes) {
            error_setg(errp, "Invalid attributes 0x%lx for TDX VM "
                       "(fixed0 0x%llx, fixed1 0x%llx)",
                       tdx->attributes, tdx_caps->attrs_fixed0,
                       tdx_caps->attrs_fixed1);
            return -1;
    }

    /*
    if (tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) {
        error_setg(errp, "Current QEMU doesn't support attributes.debug[bit 0] for TDX VM");
        return -1;
    }
    */

    return 0;
}

static int setup_td_guest_attributes(X86CPU *x86cpu, Error **errp)
{
    CPUX86State *env = &x86cpu->env;

    tdx_guest->attributes |= (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKS) ?
                             TDX_TD_ATTRIBUTES_PKS : 0;
    tdx_guest->attributes |= x86cpu->enable_pmu ? TDX_TD_ATTRIBUTES_PERFMON : 0;

    return tdx_validate_attributes(tdx_guest, errp);
}

int tdx_pre_create_vcpu(CPUState *cpu, Error **errp)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    g_autofree struct kvm_tdx_init_vm *init_vm = NULL;
    size_t data_len;
    int r = 0;

    QEMU_LOCK_GUARD(&tdx_guest->lock);
    if (tdx_guest->initialized) {
        return r;
    }

    init_vm = g_malloc0(sizeof(struct kvm_tdx_init_vm) +
                        sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES);

#define SHA384_DIGEST_SIZE  48

    if (tdx_guest->mrconfigid) {
        g_autofree uint8_t *data = qbase64_decode(tdx_guest->mrconfigid,
                              strlen(tdx_guest->mrconfigid), &data_len, errp);
        if (!data || data_len != SHA384_DIGEST_SIZE) {
            error_setg(errp, "TDX: failed to decode mrconfigid");
            return -1;
        }
        memcpy(init_vm->mrconfigid, data, data_len);
    }

    if (tdx_guest->mrowner) {
        g_autofree uint8_t *data = qbase64_decode(tdx_guest->mrowner,
                              strlen(tdx_guest->mrowner), &data_len, errp);
        if (!data || data_len != SHA384_DIGEST_SIZE) {
            error_setg(errp, "TDX: failed to decode mrowner");
            return -1;
        }
        memcpy(init_vm->mrowner, data, data_len);
    }

    if (tdx_guest->mrownerconfig) {
        g_autofree uint8_t *data = qbase64_decode(tdx_guest->mrownerconfig,
                              strlen(tdx_guest->mrownerconfig), &data_len, errp);
        if (!data || data_len != SHA384_DIGEST_SIZE) {
            error_setg(errp, "TDX: failed to decode mrownerconfig");
            return -1;
        }
        memcpy(init_vm->mrownerconfig, data, data_len);
    }

    r = kvm_vm_enable_cap(kvm_state, KVM_CAP_MAX_VCPUS, 0, ms->smp.cpus);
    if (r < 0) {
        error_setg(errp, "Unable to set MAX VCPUS to %d", ms->smp.cpus);
        return r;
    }

    if (env->tsc_khz && (env->tsc_khz < TDX_MIN_TSC_FREQUENCY_KHZ ||
                         env->tsc_khz > TDX_MAX_TSC_FREQUENCY_KHZ)) {
        error_setg(errp, "Invalid TSC %ld KHz, must specify cpu_frequency between [%d, %d] kHz",
                   env->tsc_khz, TDX_MIN_TSC_FREQUENCY_KHZ,
                   TDX_MAX_TSC_FREQUENCY_KHZ);
       return -EINVAL;
    }

    if (env->tsc_khz % (25 * 1000)) {
        error_setg(errp, "Invalid TSC %ld KHz, it must be multiple of 25MHz",
                   env->tsc_khz);
        return -EINVAL;
    }

    if (!kvm_check_extension(kvm_state, KVM_CAP_X86_APIC_BUS_CYCLES_NS)) {
        error_setg(errp, "KVM doesn't support KVM_CAP_X86_APIC_BUS_CYCLES_NS");
        return -EOPNOTSUPP;
    }

    r = kvm_vm_enable_cap(kvm_state, KVM_CAP_X86_APIC_BUS_CYCLES_NS,
                          0, TDX_APIC_BUS_CYCLES_NS);
    if (r < 0) {
        error_setg_errno(errp, -r,
                         "Unable to set core crystal clock frequency to 25MHz");
        return r;
    }

    /* it's safe even env->tsc_khz is 0. KVM uses host's tsc_khz in this case */
    r = kvm_vm_ioctl(kvm_state, KVM_SET_TSC_KHZ, env->tsc_khz);
    if (r < 0) {
        error_setg_errno(errp, -r, "Unable to set TSC frequency to %" PRId64 " kHz",
                         env->tsc_khz);
        return r;
    }

    r = setup_td_guest_attributes(x86cpu, errp);
    if (r) {
        return r;
    }

    init_vm->cpuid.nent = kvm_x86_build_cpuid(env, init_vm->cpuid.entries, 0);

    init_vm->attributes = tdx_guest->attributes;

    do {
        r = tdx_vm_ioctl(KVM_TDX_INIT_VM, 0, init_vm);
    } while (r == -EAGAIN);
    if (r < 0) {
        error_setg_errno(errp, -r, "KVM_TDX_INIT_VM failed");
        return r;
    }

    tdx_guest->initialized = true;

    return 0;
}

int tdx_parse_tdvf(void *flash_ptr, int size)
{
    return tdvf_parse_metadata(&tdx_guest->tdvf, flash_ptr, size);
}

static void tdx_inject_interrupt(uint32_t apicid, uint32_t vector)
{
    int ret;

    if (vector < 32 || vector > 255) {
        return;
    }

    MSIMessage msg = {
        .address = ((apicid & 0xff) << MSI_ADDR_DEST_ID_SHIFT) |
                   (((uint64_t)apicid & 0xffffff00) << 32),
        .data = vector | (APIC_DM_FIXED << MSI_DATA_DELIVERY_MODE_SHIFT),
    };

    ret = kvm_irqchip_send_msi(kvm_state, msg);
    if (ret < 0) {
        /* In this case, no better way to tell it to guest.  Log it. */
        error_report("TDX: injection %d failed, interrupt lost (%s).\n",
                     vector, strerror(-ret));
    }
}

static hwaddr tdx_shared_bit(X86CPU *cpu)
{
    return (cpu->phys_bits > 48) ? BIT_ULL(51) : BIT_ULL(47);
}

/* 64MB at most in one call. What value is appropriate? */
#define TDX_MAP_GPA_MAX_LEN     (64 * 1024 * 1024)

static int tdx_handle_map_gpa(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    hwaddr shared_bit = tdx_shared_bit(cpu);
    hwaddr gpa = vmcall->in_r12 & ~shared_bit;
    bool private = !(vmcall->in_r12 & shared_bit);
    hwaddr size = vmcall->in_r13;
    bool retry = false;
    int ret = 0;

    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    if (!QEMU_IS_ALIGNED(gpa, 4096) || !QEMU_IS_ALIGNED(size, 4096)) {
        vmcall->status_code = TDG_VP_VMCALL_ALIGN_ERROR;
        return 0;
    }

    /* Overflow case. */
    if (gpa + size < gpa) {
        return 0;
    }
    if (gpa >= (1ULL << cpu->phys_bits) ||
        gpa + size >= (1ULL << cpu->phys_bits)) {
        return 0;
    }

    if (size > TDX_MAP_GPA_MAX_LEN) {
        retry = true;
        size = TDX_MAP_GPA_MAX_LEN;
    }

    if (size > 0) {
        ret = kvm_convert_memory(gpa, size, private);
    }

    if (!ret) {
        if (retry) {
            vmcall->status_code = TDG_VP_VMCALL_RETRY;
            vmcall->out_r11 = gpa + size;
            if (!private) {
                vmcall->out_r11 |= shared_bit;
            }
        } else {
            vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
        }
    }

    return 0;
}

static void tdx_get_quote_completion(struct tdx_generate_quote_task *task)
{
    int ret;

    if (task->status_code == TDX_VP_GET_QUOTE_SUCCESS) {
        ret = address_space_write(&address_space_memory, task->payload_gpa,
                                  MEMTXATTRS_UNSPECIFIED, task->receive_buf,
                                  task->receive_buf_received);
        if (ret != MEMTX_OK) {
            error_report("TDX: get-quote: failed to write quote data.\n");
        } else {
            task->hdr.out_len = cpu_to_le64(task->receive_buf_received);
        }
    }
    task->hdr.error_code = cpu_to_le32(task->status_code);

    /* Publish the response contents before marking this request completed. */
    smp_wmb();
    ret = address_space_write(&address_space_memory, task->buf_gpa,
                              MEMTXATTRS_UNSPECIFIED, &task->hdr,
                              TDX_GET_QUOTE_HDR_SIZE);
    if (ret != MEMTX_OK) {
        error_report("TDX: get-quote: failed to update GetQuote header.");
    }

    tdx_inject_interrupt(tdx_guest->event_notify_apicid,
                         tdx_guest->event_notify_vector);

    g_free(task->send_data);
    g_free(task->receive_buf);
    g_free(task);
}

static int tdx_handle_get_quote(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    struct tdx_generate_quote_task *task;
    struct tdx_get_quote_header hdr;
    hwaddr buf_gpa = vmcall->in_r12;
    uint64_t buf_len = vmcall->in_r13;

    QEMU_BUILD_BUG_ON(sizeof(struct tdx_get_quote_header) != TDX_GET_QUOTE_HDR_SIZE);

    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    if (buf_len == 0) {
        return 0;
    }

    /* GPA must be shared. */
    if (!(buf_gpa & tdx_shared_bit(cpu))) {
        return 0;
    }
    buf_gpa &= ~tdx_shared_bit(cpu);

    if (!QEMU_IS_ALIGNED(buf_gpa, 4096) || !QEMU_IS_ALIGNED(buf_len, 4096)) {
        vmcall->status_code = TDG_VP_VMCALL_ALIGN_ERROR;
        return 0;
    }

    if (address_space_read(&address_space_memory, buf_gpa, MEMTXATTRS_UNSPECIFIED,
                           &hdr, TDX_GET_QUOTE_HDR_SIZE) != MEMTX_OK) {
        error_report("TDX: get-quote: failed to read GetQuote header.\n");
        return -1;
    }

    if (le64_to_cpu(hdr.structure_version) != TDX_GET_QUOTE_STRUCTURE_VERSION) {
        return 0;
    }

    /*
     * Paranoid: Guest should clear error_code and out_len to avoid information
     * leak.  Enforce it.  The initial value of them doesn't matter for qemu to
     * process the request.
     */
    if (le64_to_cpu(hdr.error_code) != TDX_VP_GET_QUOTE_SUCCESS ||
        le32_to_cpu(hdr.out_len) != 0) {
        return 0;
    }

    /* Only safe-guard check to avoid too large buffer size. */
    if (buf_len > TDX_GET_QUOTE_MAX_BUF_LEN ||
        le32_to_cpu(hdr.in_len) > buf_len - TDX_GET_QUOTE_HDR_SIZE) {
        return 0;
    }

    vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    if (!tdx_guest->quote_generator) {
        hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        if (address_space_write(&address_space_memory, buf_gpa,
                                MEMTXATTRS_UNSPECIFIED,
                                &hdr, TDX_GET_QUOTE_HDR_SIZE) != MEMTX_OK) {
            error_report("TDX: failed to update GetQuote header.\n");
            return -1;
        }
        return 0;
    }

    qemu_mutex_lock(&tdx_guest->quote_generator->lock);
    if (tdx_guest->quote_generator->num >= TDX_MAX_GET_QUOTE_REQUEST) {
        qemu_mutex_unlock(&tdx_guest->quote_generator->lock);
        vmcall->status_code = TDG_VP_VMCALL_RETRY;
        return 0;
    }
    tdx_guest->quote_generator->num++;
    qemu_mutex_unlock(&tdx_guest->quote_generator->lock);

    /* Mark the buffer in-flight. */
    hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_IN_FLIGHT);
    if (address_space_write(&address_space_memory, buf_gpa,
                            MEMTXATTRS_UNSPECIFIED,
                            &hdr, TDX_GET_QUOTE_HDR_SIZE) != MEMTX_OK) {
        error_report("TDX: failed to update GetQuote header.\n");
        return -1;
    }

    task = g_malloc(sizeof(*task));
    task->buf_gpa = buf_gpa;
    task->payload_gpa = buf_gpa + TDX_GET_QUOTE_HDR_SIZE;
    task->payload_len = buf_len - TDX_GET_QUOTE_HDR_SIZE;
    task->hdr = hdr;
    task->quote_gen = tdx_guest->quote_generator;
    task->completion = tdx_get_quote_completion;

    task->send_data_size = le32_to_cpu(hdr.in_len);
    task->send_data = g_malloc(task->send_data_size);
    task->send_data_sent = 0;

    if (address_space_read(&address_space_memory, task->payload_gpa,
                           MEMTXATTRS_UNSPECIFIED, task->send_data,
                           task->send_data_size) != MEMTX_OK) {
        g_free(task->send_data);
        return -1;
    }

    task->receive_buf = g_malloc0(task->payload_len);
    task->receive_buf_received = 0;

    tdx_generate_quote(task);

    return 0;
}

static void tdx_panicked_on_fatal_error(X86CPU *cpu, uint64_t error_code,
                                        char *message, uint64_t gpa)
{
    GuestPanicInformation *panic_info;

    panic_info = g_new0(GuestPanicInformation, 1);
    panic_info->type = GUEST_PANIC_INFORMATION_TYPE_TDX;
    panic_info->u.tdx.error_code = (uint32_t) error_code;
    panic_info->u.tdx.message = message;
    panic_info->u.tdx.gpa = gpa;

    qemu_system_guest_panicked(panic_info);
}

static int tdx_handle_report_fatal_error(X86CPU *cpu,
                                         struct kvm_tdx_vmcall *vmcall)
{
    uint64_t error_code = vmcall->in_r12;
    char *message = NULL;
    uint64_t gpa = -1ull;

    if (error_code & 0xffff) {
        error_report("TDX: REPORT_FATAL_ERROR: invalid error code: "
                     "0x%lx\n", error_code);
        return -1;
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

#define TDX_REPORT_FATAL_ERROR_GPA_VALID    BIT_ULL(63)
    if (error_code & TDX_REPORT_FATAL_ERROR_GPA_VALID) {
        gpa = vmcall->in_r13;
    }

    tdx_panicked_on_fatal_error(cpu, error_code, message, gpa);

    return -1;
}

static int tdx_handle_setup_event_notify_interrupt(X86CPU *cpu,
                                                   struct kvm_tdx_vmcall *vmcall)
{
    int vector = vmcall->in_r12;

    if (32 <= vector && vector <= 255) {
        qemu_mutex_lock(&tdx_guest->lock);
        tdx_guest->event_notify_vector = vector;
        tdx_guest->event_notify_apicid = cpu->apic_id;
        qemu_mutex_unlock(&tdx_guest->lock);
        vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    } else {
        vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;
    }

    return 0;
}

static int tdx_handle_vmcall(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    /* For now handle only TDG.VP.VMCALL leaf defined in TDX GHCI */
    if (vmcall->type != 0) {
        error_report("Unknown TDG.VP.VMCALL type 0x%llx subfunction 0x%llx",
                     vmcall->type, vmcall->subfunction);
        return -1;
    }

    switch (vmcall->subfunction) {
    case TDG_VP_VMCALL_MAP_GPA:
        return tdx_handle_map_gpa(cpu, vmcall);
    case TDG_VP_VMCALL_GET_QUOTE:
        return tdx_handle_get_quote(cpu, vmcall);
    case TDG_VP_VMCALL_REPORT_FATAL_ERROR:
        return  tdx_handle_report_fatal_error(cpu, vmcall);
    case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
        return tdx_handle_setup_event_notify_interrupt(cpu, vmcall);
    default:
        error_report("Unknown TDG.VP.VMCALL type 0x%llx subfunction 0x%llx",
                     vmcall->type, vmcall->subfunction);
        return -1;
    }
}

int tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit)
{
    switch (tdx_exit->type) {
    case KVM_EXIT_TDX_VMCALL:
        return tdx_handle_vmcall(cpu, &tdx_exit->u.vmcall);
    default:
        error_report("unknown tdx exit type 0x%x", tdx_exit->type);
        return -1;
    }
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

static char * tdx_guest_get_mrconfigid(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return g_strdup(tdx->mrconfigid);
}

static void tdx_guest_set_mrconfigid(Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    g_free(tdx->mrconfigid);
    tdx->mrconfigid = g_strdup(value);
}

static char * tdx_guest_get_mrowner(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return g_strdup(tdx->mrowner);
}

static void tdx_guest_set_mrowner(Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    g_free(tdx->mrowner);
    tdx->mrowner = g_strdup(value);
}

static char * tdx_guest_get_mrownerconfig(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return g_strdup(tdx->mrownerconfig);
}

static void tdx_guest_set_mrownerconfig(Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    g_free(tdx->mrownerconfig);
    tdx->mrownerconfig = g_strdup(value);
}

static void tdx_guest_get_quote_generation(Object *obj, Visitor *v,
                                            const char *name, void *opaque,
                                            Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    visit_type_SocketAddress(v, name, &tdx->quote_generator->socket, errp);
}

static void tdx_guest_set_quote_generation(Object *obj, Visitor *v,
                                           const char *name, void *opaque,
                                           Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);
    SocketAddress *sock = NULL;
    Object *qg_obj;
    TdxQuoteGenerator *quote_generator;

    if (!visit_type_SocketAddress(v, name, &sock, errp)) {
        return;
    }

    if (tdx->quote_generator) {
        object_unref(tdx->quote_generator);
    }

    qg_obj = object_new(TYPE_TDX_QUOTE_GENERATOR);
    quote_generator = TDX_QUOTE_GENERATOR(qg_obj);
    quote_generator->socket = sock;
    qemu_mutex_init(&quote_generator->lock);

    tdx->quote_generator = quote_generator;
}

/* tdx guest */
OBJECT_DEFINE_TYPE_WITH_INTERFACES(TdxGuest,
                                   tdx_guest,
                                   TDX_GUEST,
                                   X86_CONFIDENTIAL_GUEST,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void tdx_guest_init(Object *obj)
{
    ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(obj);
    TdxGuest *tdx = TDX_GUEST(obj);

    cgs->require_guest_memfd = true;
    tdx->attributes = TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;

    qemu_mutex_init(&tdx->lock);
 
    object_property_add_bool(obj, "sept-ve-disable",
                             tdx_guest_get_sept_ve_disable,
                             tdx_guest_set_sept_ve_disable);

    object_property_add_bool(obj, "debug", tdx_guest_get_debug,
                             tdx_guest_set_debug);

    object_property_add_str(obj, "mrconfigid",
                            tdx_guest_get_mrconfigid,
                            tdx_guest_set_mrconfigid);
    object_property_add_str(obj, "mrowner",
                            tdx_guest_get_mrowner, tdx_guest_set_mrowner);
    object_property_add_str(obj, "mrownerconfig",
                            tdx_guest_get_mrownerconfig,
                            tdx_guest_set_mrownerconfig);

    tdx->quote_generator = NULL;
    object_property_add(obj, "quote-generation-socket", "SocketAddress",
                            tdx_guest_get_quote_generation,
                            tdx_guest_set_quote_generation,
                            NULL, NULL);

    tdx->event_notify_vector = -1;
    tdx->event_notify_apicid = -1;
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
    ConfidentialGuestSupportClass *klass = CONFIDENTIAL_GUEST_SUPPORT_CLASS(oc);
    X86ConfidentialGuestClass *x86_klass = X86_CONFIDENTIAL_GUEST_CLASS(oc);

    klass->kvm_init = tdx_kvm_init;
    x86_klass->kvm_type = tdx_kvm_type;
}
