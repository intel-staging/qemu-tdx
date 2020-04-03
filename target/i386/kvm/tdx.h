#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#include "exec/confidential-guest-support.h"

#define TYPE_TDX_GUEST "tdx-guest"
#define TDX_GUEST(obj)  OBJECT_CHECK(TdxGuest, (obj), TYPE_TDX_GUEST)

typedef struct TdxGuestClass {
    ConfidentialGuestSupportClass parent_class;
} TdxGuestClass;

typedef struct TdxGuest {
    ConfidentialGuestSupport parent_obj;

    uint64_t attributes;    /* TD attributes */
} TdxGuest;

int tdx_kvm_init(MachineState *ms, Error **errp);

#endif /* QEMU_I386_TDX_H */
