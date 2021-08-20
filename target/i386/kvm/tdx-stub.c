#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/tdx.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-target.h"

#include "cpu.h"
#include "tdx.h"

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

bool kvm_tdx_enabled(void)
{
    return false;
}

void tdx_pre_create_vcpu(CPUState *cpu)
{
}

void tdx_post_init_vcpu(CPUState *cpu)
{
}

struct TDXInfo *tdx_get_info(void)
{
    return NULL;
}

void tdx_update_xfam_features(CPUState *cpu)
{
}

void tdx_check_plus_minus_features(CPUState *cpu)
{
}

uint32_t tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg)
{
    return 0;
}

bool tdx_debug_enabled(ConfidentialGuestSupport *cgs)
{
    return false;
}

void tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit)
{
}

/* QMP */
struct TDXCapability *tdx_get_capabilities(void)
{
    return NULL;
}

TDXInfo *qmp_query_tdx(Error **errp)
{
    error_setg(errp, "TDX is not available in this QEMU.");
    return NULL;
}

TDXCapability *qmp_query_tdx_capabilities(Error **errp)
{
    error_setg(errp, "TDX is not available in this QEMU.");
    return NULL;
}
