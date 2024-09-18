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

#include "exec/confidential-guest-support.h"
#include "cpu.h"

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
    void (*cpu_instance_init)(X86ConfidentialGuest *cg, CPUState *cpu);
    void (*cpu_realizefn)(X86ConfidentialGuest *cg, CPUState *cpu, Error **errp);
    void (*mask_feature_word)(X86ConfidentialGuest *cg, FeatureWord w, uint64_t *value);
    uint32_t (*adjust_cpuid_features)(X86ConfidentialGuest *cg, uint32_t feature, uint32_t index,
                                    int reg, uint32_t value);
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

static inline void x86_confidential_guest_cpu_instance_init(X86ConfidentialGuest *cg,
                                                        CPUState *cpu)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->cpu_instance_init) {
        klass->cpu_instance_init(cg, cpu);
    }
}

static inline void x86_confidenetial_guest_cpu_realizefn(X86ConfidentialGuest *cg,
                                                         CPUState *cpu,
                                                         Error **errp)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->cpu_realizefn) {
        klass->cpu_realizefn(cg, cpu, errp);
    }
}

static inline void x86_confidenetial_guest_mask_feature_word(X86ConfidentialGuest *cg,
                                                         FeatureWord w,
                                                         uint64_t *value)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->mask_feature_word) {
        klass->mask_feature_word(cg, w, value);
    }
}

/**
 * x86_confidential_guest_adjust_cpuid_features:
 *
 * Adjust the supported features from a confidential guest's CPUID values,
 * returns the adjusted value.  There are bits being removed that are not
 * supported by the confidential computing firmware or bits being added that
 * are forcibly exposed to guest by the confidential computing firmware.
 */
static inline int x86_confidential_guest_adjust_cpuid_features(X86ConfidentialGuest *cg,
                                                             uint32_t feature, uint32_t index,
                                                             int reg, uint32_t value)
{
    X86ConfidentialGuestClass *klass = X86_CONFIDENTIAL_GUEST_GET_CLASS(cg);

    if (klass->adjust_cpuid_features) {
        return klass->adjust_cpuid_features(cg, feature, index, reg, value);
    } else {
        return value;
    }
}

#endif
