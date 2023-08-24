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
#include "qom/object_interfaces.h"

#include "sw-protected-vm.h"

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
