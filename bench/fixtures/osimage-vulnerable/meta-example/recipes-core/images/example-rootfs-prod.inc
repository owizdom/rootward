include example-rootfs-base.inc

# BT-OS03. Copied from the development include during a debugging session and left in.
# The production image now ships a root shell and an interactive kernel command line.
EXTRA_IMAGE_FEATURES = "debug-tweaks"
APPEND += "console=ttyS0 init=/bin/sh"
