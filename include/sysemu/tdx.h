#ifndef QEMU_TDX_H
#define QEMU_TDX_H

#ifndef CONFIG_USER_ONLY
#include "sysemu/kvm.h"

bool kvm_has_tdx(KVMState *s);
#endif

void tdx_pre_create_vcpu(CPUState *cpu);

#endif
