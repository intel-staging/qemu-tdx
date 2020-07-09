#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/tdx.h"

#ifndef CONFIG_USER_ONLY
bool kvm_has_tdx(KVMState *s)
{
        return false;
}

int tdx_system_firmware_init(PCMachineState *pcms, MemoryRegion *rom_memory)
{
    return -ENOSYS;
}
#endif

void tdx_pre_create_vcpu(CPUState *cpu)
{
}

void tdx_post_init_vcpu(CPUState *cpu)
{
}
