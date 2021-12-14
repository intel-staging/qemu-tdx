#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#ifndef CONFIG_USER_ONLY
#include CONFIG_DEVICES /* CONFIG_TDX */
#endif

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

#ifdef CONFIG_TDX
bool is_tdx_vm(void);
#else
#define is_tdx_vm() 0
#endif /* CONFIG_TDX */

int tdx_kvm_init(MachineState *ms, Error **errp);
void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret);

#endif /* QEMU_I386_TDX_H */
