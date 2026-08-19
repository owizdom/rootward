SUMMARY = "Guest firmware for the example TDX confidential VM"
LICENSE = "BSD-2-Clause-Patent"

# Secure boot anchors the first link of the measured-boot chain, so it is on.
PACKAGECONFIG ??= "secureboot"
PACKAGECONFIG[secureboot] = ",,,"
PACKAGECONFIG[tpm] = "-D TPM_ENABLE=TRUE,-D TPM_ENABLE=FALSE,,"

OVMF_SECURE_BOOT_FLAGS = "-DSECURE_BOOT_ENABLE=TRUE"

SRC_URI = "gitsm://github.com/tianocore/edk2.git;branch=master;protocol=https"

do_compile() {
    # Config-B. The IntelTdx target keeps the virtual machine monitor outside the TCB;
    # OvmfPkg would leave the host we treat as adversarial inside it.
    ${S}/OvmfPkg/build.sh -p IntelTdxPkg/IntelTdxX64.dsc -a X64 -b RELEASE \
        ${OVMF_SECURE_BOOT_FLAGS}
}
