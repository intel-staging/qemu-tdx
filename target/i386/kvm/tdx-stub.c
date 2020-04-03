#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/tdx.h"

#ifndef CONFIG_USER_ONLY
bool kvm_has_tdx(KVMState *s)
{
        return false;
}
#endif

void tdx_pre_create_vcpu(CPUState *cpu)
{
}
