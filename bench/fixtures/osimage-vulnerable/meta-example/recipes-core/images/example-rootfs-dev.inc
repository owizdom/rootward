include example-rootfs-base.inc

# Development image only. Never included by example-rootfs.bb.
IMAGE_INSTALL += "gdb strace"
EXTRA_IMAGE_FEATURES += "debug-tweaks"
