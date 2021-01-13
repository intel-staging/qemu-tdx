/*
 * PEF (Protected Execution Facility) for POWER support
 *
 * Copyright David Gibson, Redhat Inc. 2020
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef HW_PPC_PEF_H
#define HW_PPC_PEF_H

int pef_kvm_init(ConfidentialGuestSupport *cgs, Error **errp);

#ifdef CONFIG_KVM
void kvmppc_svm_off(Error **errp);
#else
static inline void kvmppc_svm_off(Error **errp)
{
}
#endif


#endif /* HW_PPC_PEF_H */
