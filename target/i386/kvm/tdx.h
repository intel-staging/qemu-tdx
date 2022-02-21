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

enum TdxRamType{
    TDX_RAM_UNACCEPTED,
    TDX_RAM_ADDED,
};

typedef struct TdxRamEntry {
    uint64_t address;
    uint64_t length;
    enum TdxRamType type;
} TdxRamEntry;

typedef struct TdxGuest {
    X86ConfidentialGuest parent_obj;

    QemuMutex lock;

    bool initialized;
    uint64_t attributes;    /* TD attributes */
    char *mrconfigid;       /* base64 encoded sha348 digest */
    char *mrowner;          /* base64 encoded sha348 digest */
    char *mrownerconfig;    /* base64 encoded sha348 digest */

    MemoryRegion *tdvf_mr;
    TdxFirmware tdvf;

    uint32_t nr_ram_entries;
    TdxRamEntry *ram_entries;
} TdxGuest;

#ifdef CONFIG_TDX
bool is_tdx_vm(void);
#else
#define is_tdx_vm() 0
#endif /* CONFIG_TDX */

void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret);
int tdx_pre_create_vcpu(CPUState *cpu, Error **errp);
void tdx_set_tdvf_region(MemoryRegion *tdvf_mr);
int tdx_parse_tdvf(void *flash_ptr, int size);

#endif /* QEMU_I386_TDX_H */
