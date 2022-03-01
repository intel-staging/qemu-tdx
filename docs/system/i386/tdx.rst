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
whihe KVM hypervisor has TDX support. It those requirements are met, the
``KVM_CAP_VM_TYPES`` will report the support of ``KVM_X86_TDX_VM``.

Trust Domain Virtual Firmware (TDVF)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Trust Domain Virtual Firmware (TDVF) is required to provide TD services to boot
TD Guest OS. TDVF needs to be copied to guest private memory and measured before
a TD boots.

The VM scope ``MEMORY_ENCRYPT_OP`` ioctl provides command ``KVM_TDX_INIT_MEM_REGION``
to copy the firmware image to TD's private memory space.

OVMF is the opensource firmware that implements the TDVF support. It can be used
as exsiting usage that mapped via pflash interface to TDX VM. It's user-friendly
that requies no use model change, but it's mapped and acting as RAM instead of
flash (ROM device) unlike what OVMF acts to standard VM.

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

Launching a TD (TDX VM)
-----------------------

To launch a TDX guest:

.. parsed-literal::

    |qemu_system_x86| \\
        -machine ...,confidential-guest-support=tdx0 \\
        -object tdx-guest,id=tdx0,[sept-ve-disable=off] \\
        -drive if=pflash,format=raw,unit=0,file=/path/to/OVMF_CODE.fd \\
        -drive if=pflash,format=raw,unit=1,file=/path/to/OVMF_VARS.fd \\

Debugging
---------

Bit 0 of TD attributes, is DEBUG bit, which decides if the TD runs in off-TD
debug mode. When in off-TD debug mode, TD's VCPU state and private memory are
accessible via given SEAMCALLs. This requires KVM to expose APIs to invoke those
SEAMCALLs and resonponding QEMU change.

It's targeted as future work.

restrictions
------------

 - No readonly support for private memory;

 - No SMM support: SMM support requires manipulating the guset register states
   which is not allowed;

Live Migration
--------------

TODO

References
----------

- `TDX Homepage <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html>`__
