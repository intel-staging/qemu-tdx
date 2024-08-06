/*
 * x86-specific confidential guest methods.
 *
 * Copyright (c) 2024 Red Hat Inc.
 *
 * Authors:
 *  Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef TARGET_I386_CG_H
#define TARGET_I386_CG_H

#include "qom/object.h"

#ifndef CONFIG_USER_ONLY

#include "exec/confidential-guest-support.h"

#define TYPE_X86_CONFIDENTIAL_GUEST "x86-confidential-guest"

OBJECT_DECLARE_TYPE(X86ConfidentialGuest,
                    X86ConfidentialGuestClass,
                    X86_CONFIDENTIAL_GUEST)

struct X86ConfidentialGuest {
    /* <private> */
    ConfidentialGuestSupport parent_obj;
};

/**
 * X86ConfidentialGuestClass:
 *
 * Class to be implemented by confidential-guest-support concrete objects
 * for the x86 target.
 */
struct X86ConfidentialGuestClass {
    /* <private> */
    ConfidentialGuestSupportClass parent;

    /* <public> */
    int (*kvm_type)(X86ConfidentialGuest *cg);
    void (*cpu_post_init)(X86ConfidentialGuest *cg, CPUState *cpu);
    uint32_t (*mask_cpuid_features)(X86ConfidentialGuest *cg, uint32_t feature, uint32_t index,
                                    int reg, uint32_t value);
    void (*adjust_cpuid)(X86ConfidentialGuest *cg, uint32_t index, uint32_t count,
                                    uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);
};

/**
 * x86_confidential_guest_kvm_type:
 *
 * Calls #X86ConfidentialGuestClass.unplug callback of @plug_handler.
 */
static inline int x86_confidential_guest_kvm_type(X86ConfidentialGuest *cg)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->kvm_type) {
        return klass->kvm_type(cg);
    } else {
        return 0;
    }
}

static inline void x86_confidential_guest_cpu_post_init(X86ConfidentialGuest *cg,
                                                        CPUState *cpu)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->cpu_post_init) {
        klass->cpu_post_init(cg, cpu);
    }
}

/**
 * x86_confidential_guest_mask_cpuid_features:
 *
 * Removes unsupported features from a confidential guest's CPUID values, returns
 * the value with the bits removed.  The bits removed should be those that KVM
 * provides independent of host-supported CPUID features, but are not supported by
 * the confidential computing firmware.
 */
static inline int x86_confidential_guest_mask_cpuid_features(X86ConfidentialGuest *cg,
                                                             uint32_t feature, uint32_t index,
                                                             int reg, uint32_t value)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->mask_cpuid_features) {
        return klass->mask_cpuid_features(cg, feature, index, reg, value);
    } else {
        return value;
    }
}

/*
 *
 *
 */
static inline void x86_confidential_guest_adjust_cpuid(X86ConfidentialGuest *cg,
                                                       uint32_t index, uint32_t count,
                                                       uint32_t *eax, uint32_t *ebx,
                                                       uint32_t *ecx, uint32_t *edx)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->adjust_cpuid) {
        klass->adjust_cpuid(cg, index, count, eax, ebx, ecx, edx);
    }
}

#endif /* !CONFIG_USER_ONLY */

#endif
