Intel Trusted Domain eXtension (TDX)
====================================

Intel Trusted Domain eXtensions (TDX) refers to an Intel technology that extends
Virtual Machine Extensions (VMX) and Multi-Key Total Memory Encryption (MKTME)
with a new kind of virtual machine guest called a Trust Domain (TD). A TD runs
in a CPU mode that is designed to protect the confidentiality of its memory
contents and its CPU state from any other software, including the hosting
Virtual Machine Monitor (VMM), unless explicitly shared by the TD itself.

Prerequisites
-------------

To run TD, the physical machine needs to have TDX module loaded and initialized
while KVM hypervisor has TDX support and has TDX enabled. If those requirements
are met, the ``KVM_CAP_VM_TYPES`` will report the support of ``KVM_X86_TDX_VM``.

Trust Domain Virtual Firmware (TDVF)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Trust Domain Virtual Firmware (TDVF) is required to provide TD services to boot
TD Guest OS. TDVF needs to be copied to guest private memory and measured before
the TD boots.

KVM vcpu ioctl ``KVM_MEMORY_MAPPING`` can be used to populates the TDVF content
into its private memory.

Since TDX doesn't support readonly memslot, TDVF cannot be mapped as pflash
device and it actually works as RAM. "-bios" option is chosen to load TDVF.

OVMF is the opensource firmware that implements the TDVF support. Thus the
command line to specify and load TDVF is ``-bios OVMF.fd``

KVM private memory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TD's memory (RAM) needs to be able to be transformed between private and shared.
Its BIOS (OVMF/TDVF) needs to be mapped as private as well. Thus QEMU needs to
allocate private guest memfd for them via KVM's IOCTL (KVM_CREATE_GUEST_MEMFD),
which requires KVM is newer enough that reports KVM_CAP_GUEST_MEMFD.

Feature Control
---------------

Unlike non-TDX VM, the CPU features (enumerated by CPU or MSR) of a TD is not
under full control of VMM. VMM can only configure part of features of a TD on
``KVM_TDX_INIT_VM`` command of VM scope ``MEMORY_ENCRYPT_OP`` ioctl.

The configurable features have three types:

- Attributes:
  - PKS (bit 30) controls whether Supervisor Protection Keys is exposed to TD,
  which determines related CPUID bit and CR4 bit;
  - PERFMON (bit 63) controls whether PMU is exposed to TD.

- XSAVE related features (XFAM):
  XFAM is a 64b mask, which has the same format as XCR0 or IA32_XSS MSR. It
  determines the set of extended features available for use by the guest TD.

- CPUID features:
  Only some bits of some CPUID leaves are directly configurable by VMM.

What features can be configured is reported via TDX capabilities.

TDX capabilities
~~~~~~~~~~~~~~~~

The VM scope ``MEMORY_ENCRYPT_OP`` ioctl provides command ``KVM_TDX_CAPABILITIES``
to get the TDX capabilities from KVM. It returns a data structure of
``struct kvm_tdx_capabilites``, which tells the supported configuration of
attributes, XFAM and CPUIDs.

TD attestation
--------------

In TD guest, the attestation process is used to verify the TDX guest
trustworthiness to other entities before provisioning secrets to the guest.

TD attestation is initiated first by calling TDG.MR.REPORT inside TD to get the
REPORT. Then the REPORT data needs to be converted into a remotely verifiable
Quote by SGX Quoting Enclave (QE).

A host daemon, Quote Generation Service (QGS), provides the functionality of
SGX GE. It provides a socket address, to which a TD guest can connect via
"quote-generation-socket" property. On the request of <GETQUOTE> from TD guest,
QEMU sends the TDREPORT to QGS via "quote-generation-socket" socket, and gets
the returning Quoting and return it back to TD guest.

Though "quote-generation-socket" is optional for booting the TD guest, it's a
must for supporting TD guest atteatation.

Launching a TD (TDX VM)
-----------------------

To launch a TDX guest, below are new added and required:

.. parsed-literal::

    |qemu_system_x86| \\
        -object tdx-guest,id=tdx0 \\
        -machine ...,kernel-irqchip=split,confidential-guest-support=tdx0 \\
        -bios OVMF.fd \\

If TD attestation support is wanted:

.. parsed-literal::

    |qemu_system_x86| \\
        -object '{"qom-type":"tdx-guest","id":"tdx0","quote-generation-socket":{"type": "vsock", "cid":"1","port":"1234"}}' \\
        -machine ...,kernel-irqchip=split,confidential-guest-support=tdx0 \\
        -bios OVMF.fd \\

Debugging
---------

Bit 0 of TD attributes, is DEBUG bit, which decides if the TD runs in off-TD
debug mode. When in off-TD debug mode, TD's VCPU state and private memory are
accessible via given SEAMCALLs. This requires KVM to expose APIs to invoke those
SEAMCALLs and resonponding QEMU change.

It's targeted as future work.

restrictions
------------

 - kernel-irqchip must be split;

 - No readonly support for private memory;

 - No SMM support: SMM support requires manipulating the guset register states
   which is not allowed;

Live Migration
--------------

TODO

References
----------

- `TDX Homepage <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html>`__

- `SGX QE <https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration>`__
