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

#include "hw/i386/x86.h"
#include "kvm_i386.h"
#include "tdx.h"

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

static void setup_td_guest_attributes(X86CPU *x86cpu)
{
    CPUX86State *env = &x86cpu->env;

    tdx_guest->attributes |= (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKS) ?
                             TDX_TD_ATTRIBUTES_PKS : 0;
    tdx_guest->attributes |= x86cpu->enable_pmu ? TDX_TD_ATTRIBUTES_PERFMON : 0;
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

    setup_td_guest_attributes(x86cpu);

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

    cgs->require_guest_memfd = true;
    tdx->attributes = TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;

    qemu_mutex_init(&tdx->lock);
 
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
}
