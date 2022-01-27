/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#ifndef CONFIG_USER_ONLY
#include CONFIG_DEVICES /* CONFIG_TDX */
#endif

#include "confidential-guest.h"
#include "hw/i386/tdvf.h"

#define TYPE_TDX_GUEST "tdx-guest"
#define TDX_GUEST(obj)  OBJECT_CHECK(TdxGuest, (obj), TYPE_TDX_GUEST)

typedef struct TdxGuestClass {
    X86ConfidentialGuestClass parent_class;
} TdxGuestClass;

/* TDX requires bus frequency 25MHz */
#define TDX_APIC_BUS_CYCLES_NS 40

typedef struct TdxGuest {
    X86ConfidentialGuest parent_obj;

    QemuMutex lock;

    bool initialized;
    uint64_t attributes;    /* TD attributes */
    uint64_t xfam;
    char *mrconfigid;       /* base64 encoded sha348 digest */
    char *mrowner;          /* base64 encoded sha348 digest */
    char *mrownerconfig;    /* base64 encoded sha348 digest */

    MemoryRegion *tdvf_mr;
    TdxFirmware tdvf;
} TdxGuest;

#ifdef CONFIG_TDX
bool is_tdx_vm(void);
#else
#define is_tdx_vm() 0
#endif /* CONFIG_TDX */

int tdx_pre_create_vcpu(CPUState *cpu, Error **errp);
void tdx_set_tdvf_region(MemoryRegion *tdvf_mr);
int tdx_parse_tdvf(void *flash_ptr, int size);

#endif /* QEMU_I386_TDX_H */
