SUMMARY = "Guest firmware for the example TDX confidential VM"
LICENSE = "BSD-2-Clause-Patent"

# BT-OS02. The option is defined and the default configuration does not take it, so the
# firmware is built without secure boot and will load an unsigned bootloader.
PACKAGECONFIG ??= ""
PACKAGECONFIG[secureboot] = ",,,"
PACKAGECONFIG[tpm] = "-D TPM_ENABLE=TRUE,-D TPM_ENABLE=FALSE,,"

SRC_URI = "gitsm://github.com/tianocore/edk2.git;branch=master;protocol=https"

do_compile() {
    # BT-OS01. Config-A: the general-purpose OVMF target, which leaves the virtual machine
    # monitor inside the TCB of a guest whose whole threat model treats the host as hostile.
    ${S}/OvmfPkg/build.sh -p OvmfPkg/OvmfPkgX64.dsc -a X64 -b RELEASE
}
