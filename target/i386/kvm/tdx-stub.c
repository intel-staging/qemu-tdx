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

int tdx_handle_report_fatal_error(X86CPU *cpu, struct kvm_run *run)
{
    return -EINVAL;
}
