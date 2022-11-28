#include "qemu/osdep.h"

#include "tdx.h"

int tdx_pre_create_vcpu(CPUState *cpu, Error **errp)
{
    return -EINVAL;
}

int tdx_parse_tdvf(void *flash_ptr, int size)
{
    return -EINVAL;
}

int tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit)
{
    return -EINVAL;
}
