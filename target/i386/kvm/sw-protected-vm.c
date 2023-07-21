/*
 * QEMU X86_SW_PROTECTED_VM SUPPORT
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
#include "exec/address-spaces.h"
#include "sysemu/kvm.h"

#include "hw/i386/x86.h"
#include "sw-protected-vm.h"

static void kvm_x86_sw_protected_vm_region_add(MemoryListener *listenr,
                                               MemoryRegionSection *section)
{
    memory_region_set_default_private(section->mr);
}

static MemoryListener kvm_x86_sw_protected_vm_memory_listener = {
    .name = "kvm_x86_sw_protected_vm_memory_listener",
    .region_add = kvm_x86_sw_protected_vm_region_add,
    /* Higher than KVM memory listener = 10. */
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL_HIGH,
};

int sw_protected_vm_kvm_init(MachineState *ms, Error **errp)
{
    SwProtectedVm *spvm = SW_PROTECTED_VM(OBJECT(ms->cgs));
    X86MachineState *x86ms = X86_MACHINE(ms);

    memory_listener_register(&kvm_x86_sw_protected_vm_memory_listener,
                             &address_space_memory);

    if (x86ms->smm == ON_OFF_AUTO_AUTO) {
        x86ms->smm = ON_OFF_AUTO_OFF;
    } else if (x86ms->smm == ON_OFF_AUTO_ON) {
        error_setg(errp, "X86_SW_PROTECTED_VM doesn't support SMM");
        return -EINVAL;
    }

    spvm->parent_obj.ready = true;
    return 0;
}

/* x86-sw-protected-vm */
OBJECT_DEFINE_TYPE_WITH_INTERFACES(SwProtectedVm,
                                   sw_protected_vm,
                                   SW_PROTECTED_VM,
                                   CONFIDENTIAL_GUEST_SUPPORT,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void sw_protected_vm_init(Object *obj)
{
}

static void sw_protected_vm_finalize(Object *obj)
{
}

static void sw_protected_vm_class_init(ObjectClass *oc, void *data)
{
}
