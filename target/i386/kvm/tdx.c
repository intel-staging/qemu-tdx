/*
 * QEMU TDX support
 *
 * Copyright Intel
 *
 * Author:
 *      Xiaoyao Li <xiaoyao.li@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory
 *
 */

#include "qemu/osdep.h"

#include <linux/kvm.h>
#include <sys/ioctl.h>

#include "qemu/mmap-alloc.h"
#include "cpu.h"
#include "exec/address-spaces.h"
#include "kvm_i386.h"
#include "hw/boards.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/tdvf-hob.h"
#include "io/channel-socket.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "qapi/qapi-types-misc-target.h"
#include "qapi/qapi-types-misc-target.h"
#include "qapi/qapi-visit-sockets.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/sysemu.h"
#include "sysemu/runstate-action.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "sysemu/tdx.h"
#include "tdx.h"

#include "hw/southbridge/piix.h"
#include "hw/i386/ich9.h"

#define TDX1_TD_ATTRIBUTE_DEBUG BIT_ULL(0)
#define TDX1_TD_ATTRIBUTE_PERFMON BIT_ULL(63)
#define TDX1_MIN_TSC_FREQUENCY_KHZ (100 * 1000)
#define TDX1_MAX_TSC_FREQUENCY_KHZ (10 * 1000 * 1000)

bool kvm_has_tdx(KVMState *s)
{
    return !!(kvm_check_extension(s, KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM));
}

TDXInfo *tdx_get_info(void)
{
    TDXInfo *info;

    info = g_new0(TDXInfo, 1);
    info->enabled = kvm_enabled() && kvm_tdx_enabled();
    return info;
}

TDXCapability *tdx_get_capabilities(void)
{
    TDXCapability *cap;

    cap = g_new0(TDXCapability, 1);
    cap->enabled = kvm_enabled() && kvm_has_tdx(kvm_state);
    return cap;
}

static void __tdx_ioctl(void *state, int ioctl_no, const char *ioctl_name,
                        __u32 metadata, void *data)
{
    struct kvm_tdx_cmd tdx_cmd;
    int r;

    memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));

    tdx_cmd.id = ioctl_no;
    tdx_cmd.metadata = metadata;
    tdx_cmd.data = (__u64)(unsigned long)data;

    if (ioctl_no == KVM_TDX_CAPABILITIES) {
        r = kvm_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    } else if (ioctl_no == KVM_TDX_INIT_VCPU) {
        r = kvm_vcpu_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    } else {
        r = kvm_vm_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
    }
    if (r) {
        error_report("%s failed: %s", ioctl_name, strerror(-r));
        exit(1);
    }
}
#define _tdx_ioctl(cpu, ioctl_no, metadata, data) \
        __tdx_ioctl(cpu, ioctl_no, stringify(ioctl_no), metadata, data)
#define tdx_ioctl(ioctl_no, metadata, data) \
        _tdx_ioctl(kvm_state, ioctl_no, metadata, data)

static TdxFirmwareEntry *tdx_get_hob_entry(TdxGuest *tdx)
{
    TdxFirmwareEntry *entry;

    for_each_fw_entry(&tdx->fw, entry) {
        if (entry->type == TDVF_SECTION_TYPE_TD_HOB) {
            return entry;
        }
    }
    error_report("TDVF metadata doesn't specify TD_HOB location.");
    exit(1);
}

static void tdx_finalize_vm(Notifier *notifier, void *unused)
{
    Object *pm;
    bool ambig;
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = TDX_GUEST(ms->cgs);
    TdxFirmwareEntry *entry;

    /*
     * object look up logic is copied from acpi_get_pm_info()
     * @ hw/ie86/acpi-build.c
     * This property override needs to be done after machine initialization
     * as there is no ordering of creation of objects/properties.
     */
    pm = object_resolve_path_type("", TYPE_PIIX4_PM, &ambig);
    if (ambig || !pm) {
        pm = object_resolve_path_type("", TYPE_ICH9_LPC_DEVICE, &ambig);
    }
    if (!ambig && pm) {
        object_property_set_uint(pm, ACPI_PM_PROP_S3_DISABLED, 1, NULL);
        object_property_set_uint(pm, ACPI_PM_PROP_S4_DISABLED, 1, NULL);
    }

    tdvf_hob_create(tdx, tdx_get_hob_entry(tdx));

    for_each_fw_entry(&tdx->fw, entry) {
        struct kvm_tdx_init_mem_region mem_region = {
            .source_addr = (__u64)entry->mem_ptr,
            .gpa = entry->address,
            .nr_pages = entry->size / 4096,
        };

        __u32 metadata = entry->attributes & TDVF_SECTION_ATTRIBUTES_EXTENDMR ?
                         KVM_TDX_MEASURE_MEMORY_REGION : 0;

        tdx_ioctl(KVM_TDX_INIT_MEM_REGION, metadata, &mem_region);

        qemu_ram_munmap(-1, entry->mem_ptr, entry->size);
        entry->mem_ptr = NULL;
    }

    tdx_ioctl(KVM_TDX_FINALIZE_VM, 0, NULL);

    tdx->parent_obj.ready = true;
}

static Notifier tdx_machine_done_late_notify = {
    .notify = tdx_finalize_vm,
};

#define TDX1_MAX_NR_CPUID_CONFIGS 6

static struct {
    struct kvm_tdx_capabilities __caps;
    struct kvm_tdx_cpuid_config __cpuid_configs[TDX1_MAX_NR_CPUID_CONFIGS];
} __tdx_caps;

static struct kvm_tdx_capabilities *tdx_caps = (void *)&__tdx_caps;

#define XCR0_MASK (MAKE_64BIT_MASK(0, 8) | BIT_ULL(9))
#define XSS_MASK (~XCR0_MASK)

int tdx_kvm_init(ConfidentialGuestSupport *cgs, KVMState *s, Error **errp)
{
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(cgs),
                                                    TYPE_TDX_GUEST);
    if (!tdx) {
        return 0;
    }

    QEMU_BUILD_BUG_ON(sizeof(__tdx_caps) !=
                      sizeof(struct kvm_tdx_capabilities) +
                      sizeof(struct kvm_tdx_cpuid_config) *
                      TDX1_MAX_NR_CPUID_CONFIGS);

    tdx_caps->nr_cpuid_configs = TDX1_MAX_NR_CPUID_CONFIGS;
    tdx_ioctl(KVM_TDX_CAPABILITIES, 0, tdx_caps);

    if (!kvm_enable_x2apic()) {
        error_report("Failed to enable x2apic in KVM");
        exit(1);
    }

    qemu_add_machine_init_done_late_notifier(&tdx_machine_done_late_notify);

    if (tdx->debug &&
        kvm_vm_check_extension(s, KVM_CAP_ENCRYPT_MEMORY_DEBUG)) {
        kvm_setup_set_memory_region_debug_ops(s,
                                              kvm_encrypted_guest_set_memory_region_debug_ops);
        set_encrypted_memory_debug_ops();
    }

    return 0;
}

int tdx_system_firmware_init(PCMachineState *pcms, MemoryRegion *rom_memory)
{
    MachineState *ms = MACHINE(pcms);
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    int i;

    if (!tdx) {
        return -ENOSYS;
    }

    /*
     * Sanitiy check for tdx:
     * TDX uses generic loader to load bios instead of pflash.
     */
    for (i = 0; i < ARRAY_SIZE(pcms->flash); i++) {
        if (drive_get(IF_PFLASH, 0, i)) {
            error_report("pflash not supported by VM type, "
                         "use -device loader,file=<path>");
            exit(1);
        }
    }
    return 0;
}

void tdx_get_supported_cpuid(KVMState *s, uint32_t function,
                             uint32_t index, int reg, uint32_t *ret)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (!tdx) {
        return;
    }

    switch (function) {
    case 1:
        if (reg == R_ECX) {
            *ret &= ~CPUID_EXT_VMX;
        }
        break;
    case 0xd:
        if (index == 0) {
            if (reg == R_EAX) {
                *ret &= (uint32_t)tdx_caps->xfam_fixed0 & XCR0_MASK;
                *ret |= (uint32_t)tdx_caps->xfam_fixed1 & XCR0_MASK;
            } else if (reg == R_EDX) {
                *ret &= (tdx_caps->xfam_fixed0 & XCR0_MASK) >> 32;
                *ret |= (tdx_caps->xfam_fixed1 & XCR0_MASK) >> 32;
            }
        } else if (index == 1) {
            /* TODO: Adjust XSS when it's supported. */
        }
        break;
    case KVM_CPUID_FEATURES:
        if (reg == R_EAX) {
            *ret &= ~((1ULL << KVM_FEATURE_CLOCKSOURCE) |
                      (1ULL << KVM_FEATURE_CLOCKSOURCE2) |
                      (1ULL << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT) |
                      (1ULL << KVM_FEATURE_ASYNC_PF) |
                      (1ULL << KVM_FEATURE_ASYNC_PF_VMEXIT) |
                      (1ULL << KVM_FEATURE_ASYNC_PF_INT));
        }
        break;
    default:
        /* TODO: Use tdx_caps to adjust CPUID leafs. */
        break;
    }
}

void tdx_pre_create_vcpu(CPUState *cpu)
{
    struct {
        struct kvm_cpuid2 cpuid;
        struct kvm_cpuid_entry2 entries[KVM_MAX_CPUID_ENTRIES];
    } cpuid_data;

    /*
     * The kernel defines these structs with padding fields so there
     * should be no extra padding in our cpuid_data struct.
     */
    QEMU_BUILD_BUG_ON(sizeof(cpuid_data) !=
                      sizeof(struct kvm_cpuid2) +
                      sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES);

    MachineState *ms = MACHINE(qdev_get_machine());
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    struct kvm_tdx_init_vm init_vm;

    if (!tdx) {
        return;
    }

    /* TODO: Use tdx_caps to validate the config. */
    if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
        error_report("TDX VM must support XSAVE features");
        exit(1);
    }

    if (env->tsc_khz && (env->tsc_khz < TDX1_MIN_TSC_FREQUENCY_KHZ ||
                         env->tsc_khz > TDX1_MAX_TSC_FREQUENCY_KHZ)) {
        error_report("Invalid TSC %ld KHz, must specify cpu_frequecy between [%d, %d] kHz\n",
                      env->tsc_khz, TDX1_MIN_TSC_FREQUENCY_KHZ,
                      TDX1_MAX_TSC_FREQUENCY_KHZ);
        exit(1);
    }

    if (env->tsc_khz % (25 * 1000)) {
        error_report("Invalid TSC %ld KHz, it must be multiple of 25MHz\n", env->tsc_khz);
        exit(1);
    }

    qemu_mutex_lock(&tdx->lock);
    if (tdx->initialized) {
        goto out;
    }
    tdx->initialized = true;

    memset(&cpuid_data, 0, sizeof(cpuid_data));

    cpuid_data.cpuid.nent = kvm_x86_arch_cpuid(env, cpuid_data.entries, 0);
    cpuid_data.cpuid.padding = 0;

    init_vm.max_vcpus = ms->smp.cpus;
    init_vm.tsc_khz = env->tsc_khz;
    init_vm.attributes = 0;
    init_vm.attributes |= tdx->debug ? TDX1_TD_ATTRIBUTE_DEBUG : 0;
    init_vm.attributes |= x86cpu->enable_pmu ? TDX1_TD_ATTRIBUTE_PERFMON : 0;

    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrconfigid) != sizeof(tdx->mrconfigid));
    memcpy(init_vm.mrconfigid, tdx->mrconfigid, sizeof(init_vm.mrconfigid));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrowner) != sizeof(tdx->mrowner));
    memcpy(init_vm.mrowner, tdx->mrowner, sizeof(init_vm.mrowner));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrownerconfig) !=
                      sizeof(tdx->mrownerconfig));
    memcpy(init_vm.mrownerconfig, tdx->mrownerconfig,
           sizeof(init_vm.mrownerconfig));

    memset(init_vm.reserved, 0, sizeof(init_vm.reserved));

    init_vm.cpuid = (__u64)(&cpuid_data);
    tdx_ioctl(KVM_TDX_INIT_VM, 0, &init_vm);

out:
    qemu_mutex_unlock(&tdx->lock);
}

void tdx_post_init_vcpu(CPUState *cpu)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);
    TdxFirmwareEntry *hob;

    if (!tdx) {
        return;
    }

    hob = tdx_get_hob_entry(tdx);
    _tdx_ioctl(cpu, KVM_TDX_INIT_VCPU, 0, (void *)hob->address);

    apic_force_x2apic(X86_CPU(cpu)->apic_state);
}

static bool tdx_guest_get_debug(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return tdx->debug;
}

static void tdx_guest_set_debug(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    tdx->debug = value;
}

static char *tdx_guest_get_quote_generation(
    Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);
    return g_strdup(tdx->quote_generation_str);
}

static void tdx_guest_set_quote_generation(
    Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);
    tdx->quote_generation = socket_parse(value, errp);
    if (!tdx->quote_generation)
        return;

    g_free(tdx->quote_generation_str);
    tdx->quote_generation_str = g_strdup(value);
}

/* tdx guest */
OBJECT_DEFINE_TYPE_WITH_INTERFACES(TdxGuest,
                                   tdx_guest,
                                   TDX_GUEST,
                                   CONFIDENTIAL_GUEST_SUPPORT,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void tdx_guest_init(Object *obj)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    qemu_mutex_init(&tdx->lock);

    /* TODO: set only if user doens't specify reboot action */
    reboot_action = REBOOT_ACTION_SHUTDOWN;

    tdx->debug = false;
    object_property_add_bool(obj, "debug", tdx_guest_get_debug,
                             tdx_guest_set_debug);
    object_property_add_sha384(obj, "mrconfigid", tdx->mrconfigid,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrowner", tdx->mrowner,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrownerconfig", tdx->mrownerconfig,
                               OBJ_PROP_FLAG_READWRITE);

    tdx->quote_generation_str = NULL;
    tdx->quote_generation = NULL;
    object_property_add_str(obj, "quote-generation-service",
                            tdx_guest_get_quote_generation,
                            tdx_guest_set_quote_generation);

    tdx->event_notify_interrupt = -1;
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}

#define TDG_VP_VMCALL_GET_QUOTE                         0x10002ULL
#define TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT      0x10004ULL

#define TDG_VP_VMCALL_SUCCESS           0x0000000000000000ULL
#define TDG_VP_VMCALL_INVALID_OPERAND   0x8000000000000000ULL

#define TDX_GET_QUOTE_MAX_BUF_LEN   (128 * 1024)

#define TDX_GET_QUOTE_STRUCTURE_VERSION 1ULL

/*
 * Follow the format of TDX status code
 * 63:32: class code
 *   63: error
 *   62: recoverable
 *   47:40 class ID : 9 platform
 *   39:32: details_L1
 * 31:0: details_L2
 */
#define TDX_GET_QUOTE_STATUS_SUCCESS    0ULL
#define TDX_GET_QUOTE_STATUS_ERROR      0x8000090100000000ULL

/* Format of pages shared with guest. */
struct tdx_get_quote_header {
    /* Format version: must be 1 in little endian. */
    uint64_t structure_version;

    /*
     * GetQuote status code in little endian:
     *   Guest must set error_code to 0 to avoid information leak.
     *   Qemu sets this before interrupting guest.
     */
    uint64_t error_code;

    /*
     * in-message size in little endian: The message will follow this header.
     * The in-message will be send to QGS.
     */
    uint32_t in_len;

    /*
     * out-message size in little endian:
     * On request, buffer size of shared page. Guest must sets.
     * On return, message size from QGS. Qemu overwrites this field.
     * The message will follows this header.  The in-message is overwritten.
     */
    uint32_t out_len;

    /*
     * Message buffer follows.
     * Guest sets message that will be send to QGS.  If out_len > in_len, guest
     * should zero remaining buffer to avoid information leak.
     * Qemu overwrites this buffer with a message returned from QGS.
     */
};

struct tdx_get_quote_task {
    uint32_t apic_id;
    hwaddr gpa;
    struct tdx_get_quote_header hdr;
    int event_notify_interrupt;
    QIOChannelSocket *ioc;
};

typedef struct x86_msi_address_lo {
    struct {
        uint32_t        reserved_0              : 2,
                        dest_mode_logical       : 1,
                        redirect_hint           : 1,
                        reserved_1              : 1,
                        virt_destid_8_14        : 7,
                        destid_0_7              : 8,
                        base_address            : 12;
    };
} QEMU_PACKED x86_msi_address_lo_t;

typedef struct x86_msi_address_hi {
    uint32_t    reserved        : 8,
                destid_8_31     : 24;
} QEMU_PACKED  x86_msi_address_hi_t;

typedef struct x86_msi_data {
    uint32_t    vector                  : 8,
                delivery_mode           : 3,
                dest_mode_logical       : 1,
                reserved                : 2,
                active_low              : 1,
                is_level                : 1;
} QEMU_PACKED x86_msi_data_t;

struct x86_msi {
    union {
        x86_msi_address_lo_t x86_address_lo;
        uint32_t address_lo;
    };
    union {
        x86_msi_address_hi_t x86_address_hi;
        uint32_t address_hi;
    };
    union {
        x86_msi_data_t x86_data;
        uint32_t data;
    };
};

/*
 * TODO: If QGS doesn't reply for long time, make it an error and interrupt
 * guest.
 */
static void tdx_handle_get_quote_connected(QIOTask *task, gpointer opaque)
{
    struct tdx_get_quote_task *t = opaque;
    Error *err = NULL;
    char *in_data = NULL;
    char *out_data = NULL;
    size_t out_len;
    ssize_t size;
    int ret;
    struct x86_msi x86_msi;
    struct kvm_msi msi;

    assert(32 <= t->event_notify_interrupt && t->event_notify_interrupt <= 255);
    t->hdr.error_code = cpu_to_le64(TDX_GET_QUOTE_STATUS_ERROR);

    if (qio_task_propagate_error(task, NULL)) {
        goto error;
    }

    in_data = g_malloc(le32_to_cpu(t->hdr.in_len));
    if (address_space_read(&address_space_memory, t->gpa + sizeof(t->hdr),
                           MEMTXATTRS_UNSPECIFIED, in_data,
                           le32_to_cpu(t->hdr.in_len)) != MEMTX_OK) {
        goto error;
    }

    if (qio_channel_write_all(QIO_CHANNEL(t->ioc), in_data,
                              le32_to_cpu(t->hdr.in_len), &err) ||
        err) {
        goto error;
    }

    out_data = g_malloc(le32_to_cpu(t->hdr.out_len));
    out_len = 0;
    size = 0;
    while (out_len < le32_to_cpu(t->hdr.out_len)) {
        size = qio_channel_read(
            QIO_CHANNEL(t->ioc), out_data + out_len,
            le32_to_cpu(t->hdr.out_len) - out_len, &err);
        if (err) {
            break;
        }
        if (size <= 0) {
            break;
        }
        out_len += size;
    }
    /*
     * Treat partial read as success and let the QGS client to handle it because
     * the client knows better about the QGS.
     */
    if (out_len == 0 && (err || size < 0)) {
        goto error;
    }

    if (address_space_write(
            &address_space_memory, t->gpa + sizeof(t->hdr),
            MEMTXATTRS_UNSPECIFIED, out_data, out_len) != MEMTX_OK) {
        goto error;
    }
    /*
     * Even if out_len == 0, it's a success.  It's up to the QGS-client contract
     * how to interpret the zero-sized message as return message.
     */
    t->hdr.out_len = cpu_to_le32(out_len);
    t->hdr.error_code = cpu_to_le64(TDX_GET_QUOTE_STATUS_SUCCESS);

error:
    if (t->hdr.error_code != cpu_to_le64(TDX_GET_QUOTE_STATUS_SUCCESS)) {
        t->hdr.out_len = cpu_to_le32(0);
    }
    if (address_space_write(
            &address_space_memory, t->gpa,
            MEMTXATTRS_UNSPECIFIED, &t->hdr, sizeof(t->hdr)) != MEMTX_OK) {
        error_report("TDX: failed to updsate GetQuote header.\n");
    }

    x86_msi = (struct x86_msi) {
        .x86_address_lo  = {
            .reserved_0 = 0,
            .dest_mode_logical = 0,
            .redirect_hint = 0,
            .reserved_1 = 0,
            .virt_destid_8_14 = 0,
            .destid_0_7 = t->apic_id & 0xff,
        },
        .x86_address_hi = {
            .reserved = 0,
            .destid_8_31 = t->apic_id >> 8,
        },
        .x86_data = {
            .vector = t->event_notify_interrupt,
            .delivery_mode = APIC_DM_FIXED,
            .dest_mode_logical = 0,
            .reserved = 0,
            .active_low = 0,
            .is_level = 0,
        },
    };
    msi = (struct kvm_msi) {
        .address_lo = x86_msi.address_lo,
        .address_hi = x86_msi.address_hi,
        .data = x86_msi.data,
        .flags = 0,
        .devid = 0,
    };
    ret = kvm_vm_ioctl(kvm_state, KVM_SIGNAL_MSI, &msi);
    if (ret < 0) {
        /* In this case, no better way to tell it to guest.  Log it. */
        error_report("TDX: injection %d failed, interrupt lost (%s).\n",
                     t->event_notify_interrupt, strerror(-ret));
    }

    qio_channel_close(QIO_CHANNEL(t->ioc), &err);
    object_unref(OBJECT(t->ioc));
    g_free(in_data);
    g_free(out_data);
    return;
}

static void tdx_handle_get_quote(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    hwaddr gpa = vmcall->in_r12;
    struct tdx_get_quote_header hdr;
    MachineState *ms;
    TdxGuest *tdx;
    QIOChannelSocket *ioc;
    struct tdx_get_quote_task *t;

    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    if (!QEMU_IS_ALIGNED(gpa, 4096)) {
        return;
    }

    if (address_space_read(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                           &hdr, sizeof(hdr)) != MEMTX_OK) {
        return;
    }
    if (le64_to_cpu(hdr.structure_version) != TDX_GET_QUOTE_STRUCTURE_VERSION) {
        return;
    }
    /*
     * Paranoid: Guest should clear error_code to avoid information leak.
     * Enforce it.  The initial value of error_code doesn't matter for qemu to
     * process the request.
     */
    if (le64_to_cpu(hdr.error_code) != TDX_GET_QUOTE_STATUS_SUCCESS) {
        return;
    }

    /* Only safe-guard check to avoid too large buffer size. */
    if (le32_to_cpu(hdr.in_len) > TDX_GET_QUOTE_MAX_BUF_LEN ||
        le32_to_cpu(hdr.out_len) > TDX_GET_QUOTE_MAX_BUF_LEN) {
        return;
    }

    ms = MACHINE(qdev_get_machine());
    tdx = TDX_GUEST(ms->cgs);
    ioc = qio_channel_socket_new();

    t = g_malloc(sizeof(*t));
    t->apic_id = cpu->apic_id;
    t->gpa = gpa;
    t->hdr = hdr;
    t->ioc = ioc;

    qemu_mutex_lock(&tdx->lock);
    if (tdx->event_notify_interrupt < 32 || 255 < tdx->event_notify_interrupt ||
        !tdx->quote_generation) {
        qemu_mutex_unlock(&tdx->lock);
        object_unref(OBJECT(ioc));
        g_free(t);
        return;
    }
    t->event_notify_interrupt = tdx->event_notify_interrupt;
    qio_channel_socket_connect_async(
        ioc, tdx->quote_generation, tdx_handle_get_quote_connected, t, g_free,
        NULL);
    qemu_mutex_unlock(&tdx->lock);

    vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
}

static void tdx_handle_setup_event_notify_interrupt(struct kvm_tdx_vmcall *vmcall)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = TDX_GUEST(ms->cgs);
    int event_notify_interrupt = vmcall->in_r12;

    if (32 <= event_notify_interrupt && event_notify_interrupt <= 255) {
        qemu_mutex_lock(&tdx->lock);
        tdx->event_notify_interrupt = event_notify_interrupt;
        qemu_mutex_unlock(&tdx->lock);
        vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    }
}

static void tdx_handle_vmcall(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    /* For now handle only TDG.VP.VMCALL. */
    if (vmcall->type != 0) {
        warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx",
                    vmcall->type, vmcall->subfunction);
        return;
    }

    switch (vmcall->subfunction) {
    case TDG_VP_VMCALL_GET_QUOTE:
        tdx_handle_get_quote(cpu, vmcall);
        break;
    case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
        tdx_handle_setup_event_notify_interrupt(vmcall);
        break;
    default:
        warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx",
                    vmcall->type, vmcall->subfunction);
        break;
    }
}

void tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit)
{
    if (!kvm_tdx_enabled())
        return;

    switch (tdx_exit->type) {
    case KVM_EXIT_TDX_VMCALL:
        tdx_handle_vmcall(cpu, &tdx_exit->u.vmcall);
        break;
    default:
        warn_report("unknown tdx exit type 0x%x", tdx_exit->type);
        break;
    }
}

bool tdx_debug_enabled(ConfidentialGuestSupport *cgs)
{
    TdxGuest *tdx;

    if (!cgs)
        return false;

    tdx = (TdxGuest *)object_dynamic_cast(OBJECT(cgs),
                                          TYPE_TDX_GUEST);
    if (!tdx)
        return false;

    return tdx->debug;
}
