#ifndef QEMU_I386_SW_PROTECTED_VM_H
#define QEMU_I386_SW_PROTECTED_VM_H

#include "exec/confidential-guest-support.h"

#define TYPE_SW_PROTECTED_VM    "sw-protected-vm"
#define SW_PROTECTED_VM(obj)    OBJECT_CHECK(SwProtectedVm, (obj), TYPE_SW_PROTECTED_VM)

typedef struct SwProtectedVmClass {
    ConfidentialGuestSupportClass parent_class;
} SwProtectedVmClass;

typedef struct SwProtectedVm {
    ConfidentialGuestSupport parent_obj;
} SwProtectedVm;

#endif /* QEMU_I386_SW_PROTECTED_VM_H */
