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

#include "cpu.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "sysemu/tdx.h"

bool kvm_has_tdx(KVMState *s)
{
    return !!(kvm_check_extension(s, KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}
