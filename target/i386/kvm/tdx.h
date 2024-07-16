#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#ifndef CONFIG_USER_ONLY
#include CONFIG_DEVICES /* CONFIG_TDX */
#endif

#include "confidential-guest.h"
#include "hw/i386/tdvf.h"
#include "sysemu/kvm.h"

#include "tdx-quote-generator.h"

#define TYPE_TDX_GUEST "tdx-guest"
#define TDX_GUEST(obj)  OBJECT_CHECK(TdxGuest, (obj), TYPE_TDX_GUEST)

typedef struct TdxGuestClass {
    X86ConfidentialGuestClass parent_class;
} TdxGuestClass;

/* TDX requires bus frequency 25MHz */
#define TDX_APIC_BUS_CYCLES_NS 40

#define TDG_VP_VMCALL_MAP_GPA                           0x10001ULL
#define TDG_VP_VMCALL_GET_QUOTE                         0x10002ULL
#define TDG_VP_VMCALL_REPORT_FATAL_ERROR                0x10003ULL
#define TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT      0x10004ULL

#define TDG_VP_VMCALL_SUCCESS           0x0000000000000000ULL
#define TDG_VP_VMCALL_RETRY             0x0000000000000001ULL
#define TDG_VP_VMCALL_INVALID_OPERAND   0x8000000000000000ULL
#define TDG_VP_VMCALL_GPA_INUSE         0x8000000000000001ULL
#define TDG_VP_VMCALL_ALIGN_ERROR       0x8000000000000002ULL

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

    /* runtime state */
    uint32_t event_notify_vector;
    uint32_t event_notify_apicid;

    /* GetQuote */
    TdxQuoteGenerator *quote_generator;
} TdxGuest;

#ifdef CONFIG_TDX
bool is_tdx_vm(void);
#else
#define is_tdx_vm() 0
#endif /* CONFIG_TDX */

int tdx_pre_create_vcpu(CPUState *cpu, Error **errp);
void tdx_set_tdvf_region(MemoryRegion *tdvf_mr);
int tdx_parse_tdvf(void *flash_ptr, int size);
int tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit);
void tdx_fetch_cpuid(CPUState *cpu, struct kvm_cpuid2 *fetch_cpuid);
bool tdx_cpuid_check_mismatch(X86CPU *cpu, struct kvm_cpuid2 *expected, struct kvm_cpuid2 *actual);

#endif /* QEMU_I386_TDX_H */
