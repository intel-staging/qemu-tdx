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
#include "qapi/error.h"
#include "qom/object_interfaces.h"

#include "cpu.h"
#include "host-cpu.h"
#include "hw/i386/x86.h"
#include "kvm_i386.h"
#include "tdx.h"

#define TDX_TD_ATTRIBUTES_DEBUG             BIT_ULL(0)
#define TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE   BIT_ULL(28)
#define TDX_TD_ATTRIBUTES_PKS               BIT_ULL(30)
#define TDX_TD_ATTRIBUTES_PERFMON           BIT_ULL(63)

static TdxGuest *tdx_guest;

static struct kvm_tdx_capabilities *tdx_caps;

/* It's valid after kvm_arch_init()->kvm_tdx_init() */
bool is_tdx_vm(void)
{
    return !!tdx_guest;
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

    if (r && tdx_cmd.hw_error) {
        error_report("TDX ioctl %d return with %d, hw_errors: %#llx",
                     cmd_id, r, tdx_cmd.hw_error);
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
                      nr_cpuid_configs * sizeof(struct kvm_cpuid_entry2);
        caps = g_malloc0(size);
        caps->cpuid.nent = nr_cpuid_configs;

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

static int tdx_kvm_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(cgs);
    int r = 0;

    kvm_mark_guest_state_protected();

    if (!tdx_caps) {
        r = get_tdx_capabilities(errp);
        if (r) {
            return r;
        }
    }

    tdx_guest = tdx;
    return 0;
}

static int tdx_kvm_type(X86ConfidentialGuest *cg)
{
    /* Do the object check */
    TDX_GUEST(cg);

    return KVM_X86_TDX_VM;
}

static void tdx_cpu_instance_init(X86ConfidentialGuest *cg, CPUState *cpu)
{
    object_property_set_bool(OBJECT(cpu), "pmu", false, &error_abort);
}

static void tdx_cpu_realizefn(X86ConfidentialGuest *cg, CPUState *cs, Error **errp)
{
    X86CPU *cpu = X86_CPU(cs);
    uint32_t host_phys_bits = host_cpu_phys_bits();


    if (!cpu->phys_bits) {
        cpu->phys_bits = host_phys_bits;
    } else if (cpu->phys_bits != host_phys_bits) {
        error_setg(errp, "TDX only supports host physical bits (%u)", host_phys_bits);
    }
}

static int tdx_validate_attributes(TdxGuest *tdx, Error **errp)
{
    if ((tdx->attributes & ~tdx_caps->supported_attrs)) {
            error_setg(errp, "Invalid attributes 0x%lx for TDX VM "
                       "(supported: 0x%llx)",
                       tdx->attributes, tdx_caps->supported_attrs);
            return -1;
    }

    if (tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) {
        error_setg(errp, "Current QEMU doesn't support attributes.debug[bit 0] for TDX VM");
        return -1;
    }

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

static int setup_td_xfam(X86CPU *x86cpu, Error **errp)
{
    CPUX86State *env = &x86cpu->env;
    uint64_t xfam;

    xfam = env->features[FEAT_XSAVE_XCR0_LO] |
           env->features[FEAT_XSAVE_XCR0_HI] |
           env->features[FEAT_XSAVE_XSS_LO] |
           env->features[FEAT_XSAVE_XSS_HI];

    if (xfam & ~tdx_caps->supported_xfam) {
        error_setg(errp, "Invalid XFAM 0x%lx for TDX VM (supported: 0x%llx))",
                   xfam, tdx_caps->supported_xfam);
        return -1;
    }

    tdx_guest->xfam = xfam;
    return 0;
}

static void tdx_filter_cpuid(struct kvm_cpuid2 *cpuids)
{
    int i, dest_cnt = 0;
    struct kvm_cpuid_entry2 *src, *dest, *conf;

    for (i = 0; i < cpuids->nent; i++) {
        src = cpuids->entries + i;
        conf = cpuid_find_entry(&tdx_caps->cpuid, src->function, src->index);
        if (!conf) {
            continue;
        }
        dest = cpuids->entries + dest_cnt;

        dest->function = src->function;
        dest->index = src->index;
        dest->flags = src->flags;
        dest->eax = src->eax & conf->eax;
        dest->ebx = src->ebx & conf->ebx;
        dest->ecx = src->ecx & conf->ecx;
        dest->edx = src->edx & conf->edx;

        dest_cnt++;
    }
    cpuids->nent = dest_cnt++;
}

int tdx_pre_create_vcpu(CPUState *cpu, Error **errp)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    g_autofree struct kvm_tdx_init_vm *init_vm = NULL;
    int r = 0;

    QEMU_LOCK_GUARD(&tdx_guest->lock);
    if (tdx_guest->initialized) {
        return r;
    }

    init_vm = g_malloc0(sizeof(struct kvm_tdx_init_vm) +
                        sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES);

    r = setup_td_guest_attributes(x86cpu, errp);
    if (r) {
        return r;
    }
 
    r = setup_td_xfam(x86cpu, errp);
    if (r) {
        return r;
    }

    init_vm->cpuid.nent = kvm_x86_build_cpuid(env, init_vm->cpuid.entries, 0);
    tdx_filter_cpuid(&init_vm->cpuid);

    init_vm->attributes = tdx_guest->attributes;
    init_vm->xfam = tdx_guest->xfam;

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
                                   X86_CONFIDENTIAL_GUEST,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void tdx_guest_init(Object *obj)
{
    ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(obj);
    TdxGuest *tdx = TDX_GUEST(obj);

    qemu_mutex_init(&tdx->lock);

    cgs->require_guest_memfd = true;
    tdx->attributes = TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;

    object_property_add_uint64_ptr(obj, "attributes", &tdx->attributes,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_bool(obj, "sept-ve-disable",
                             tdx_guest_get_sept_ve_disable,
                             tdx_guest_set_sept_ve_disable);
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
    x86_klass->cpu_instance_init = tdx_cpu_instance_init;
    x86_klass->cpu_realizefn = tdx_cpu_realizefn;
}
