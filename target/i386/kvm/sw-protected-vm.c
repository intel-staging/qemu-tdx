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

#include "hw/i386/x86.h"
#include "sw-protected-vm.h"

int sw_protected_vm_kvm_init(MachineState *ms, Error **errp)
{
    SwProtectedVm *spvm = SW_PROTECTED_VM(OBJECT(ms->cgs));

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
