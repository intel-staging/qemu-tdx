#ifndef QEMU_I386_TDX_H
#define QEMU_I386_TDX_H

#ifndef CONFIG_USER_ONLY
#include CONFIG_DEVICES /* CONFIG_TDX */
#endif

#include <linux/kvm.h>
#include "exec/confidential-guest-support.h"
#include "hw/i386/tdvf.h"
#include "io/channel-socket.h"
#include "sysemu/kvm.h"

#define TYPE_TDX_GUEST "tdx-guest"
#define TDX_GUEST(obj)  OBJECT_CHECK(TdxGuest, (obj), TYPE_TDX_GUEST)
#define TDX_PHYS_ADDR_BITS  52

typedef struct TdxGuestClass {
    ConfidentialGuestSupportClass parent_class;
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
    ConfidentialGuestSupport parent_obj;

    QemuMutex lock;

    bool initialized;
    uint64_t attributes;    /* TD attributes */
    char *mrconfigid;       /* base64 encoded sha348 digest */
    char *mrowner;          /* base64 encoded sha348 digest */
    char *mrownerconfig;    /* base64 encoded sha348 digest */

    TdxFirmware tdvf;
    MemoryRegion *tdvf_region;

    uint32_t nr_ram_entries;
    TdxRamEntry *ram_entries;

    /* runtime state */
    int event_notify_interrupt;
    uint32_t event_notify_apic_id;

    /* GetQuote */
    int quote_generation_num;
    SocketAddress *quote_generation;
} TdxGuest;

#ifdef CONFIG_TDX
bool is_tdx_vm(void);
#else
#define is_tdx_vm() 0
#endif /* CONFIG_TDX */

int tdx_kvm_init(MachineState *ms, Error **errp);
void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret);
int tdx_pre_create_vcpu(CPUState *cpu, Error **errp);
void tdx_set_tdvf_region(MemoryRegion *tdvf_region);
int tdx_parse_tdvf(void *flash_ptr, int size);
void tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit);
void tdx_apply_xfam_dependencies(CPUState *cpu);
void tdx_check_minus_features(CPUState *cpu);

#endif /* QEMU_I386_TDX_H */
