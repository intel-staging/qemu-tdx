#include "qemu/osdep.h"

#include "tdx.h"

int tdx_pre_create_vcpu(CPUState *cpu, Error **errp)
{
    return -EINVAL;
}
