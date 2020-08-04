#ifndef QEMU_TDX_H
#define QEMU_TDX_H

#ifndef CONFIG_USER_ONLY
#include "sysemu/kvm.h"
#include "hw/i386/pc.h"

bool kvm_has_tdx(KVMState *s);
int tdx_system_firmware_init(PCMachineState *pcms, MemoryRegion *rom_memory);
#endif

void tdx_pre_create_vcpu(CPUState *cpu);
void tdx_post_init_vcpu(CPUState *cpu);

struct TDXInfo;
struct TDXInfo *tdx_get_info(void);

struct TDXCapability;
struct TDXCapability *tdx_get_capabilities(void);

#endif
