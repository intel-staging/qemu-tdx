#ifndef QEMU_TDX_H
#define QEMU_TDX_H

#ifndef CONFIG_USER_ONLY
#include "sysemu/kvm.h"
#include "hw/i386/pc.h"

bool kvm_has_tdx(KVMState *s);
bool kvm_tdx_enabled(void);
int tdx_system_firmware_init(PCMachineState *pcms, MemoryRegion *rom_memory);
#endif

void tdx_pre_create_vcpu(CPUState *cpu);
void tdx_post_init_vcpu(CPUState *cpu);
void tdx_update_xfam_features(CPUState *cpu);
void tdx_check_plus_minus_features(CPUState *cpu);
uint32_t tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg);

struct TDXInfo;
struct TDXInfo *tdx_get_info(void);

struct TDXCapability;
struct TDXCapability *tdx_get_capabilities(void);

#endif
