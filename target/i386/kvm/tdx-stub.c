#include "qemu/osdep.h"
#include "qemu-common.h"

#include "tdx.h"

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    return -EINVAL;
}

int tdx_pre_create_vcpu(CPUState *cpu)
{
    return -EINVAL;
}

int tdx_parse_tdvf(void *flash_ptr, int size)
{
    return -EINVAL;
}
