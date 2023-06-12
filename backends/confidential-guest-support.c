/*
 * QEMU Confidential Guest support
 *
 * Copyright Red Hat.
 *
 * Authors:
 *  David Gibson <david@gibson.dropbear.id.au>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"

#include "exec/confidential-guest-support.h"

OBJECT_DEFINE_ABSTRACT_TYPE(ConfidentialGuestSupport,
                            confidential_guest_support,
                            CONFIDENTIAL_GUEST_SUPPORT,
                            OBJECT)

static bool cgs_get_disable_pv_clock(Object *obj, Error **errp)
{
    ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(obj);

    return cgs->disable_pv_clock;
}

static void cgs_set_disable_pv_clock(Object *obj, bool value, Error **errp)
{
    ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(obj);

    cgs->disable_pv_clock = value;
}

static void confidential_guest_support_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add_bool(oc, CONFIDENTIAL_GUEST_SUPPORT_DISABLE_PV_CLOCK,
                                   cgs_get_disable_pv_clock, cgs_set_disable_pv_clock);
}

static void confidential_guest_support_init(Object *obj)
{
}

static void confidential_guest_support_finalize(Object *obj)
{
}
