include example-rootfs-base.inc

# No debug-tweaks, no shell, no ssh. The operator reaches the console; nothing there
# should give them a session.
EXTRA_IMAGE_FEATURES = ""
