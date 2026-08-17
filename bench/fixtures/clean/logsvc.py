import subprocess

# Diagnostics stay inside the boundary: a fixed vocabulary of codes, no stream relay.
EVENTS = {"boot_ok": "E_BOOT_OK", "boot_fail": "E_BOOT_FAIL"}

def emit(event):
    return EVENTS.get(event, "E_UNKNOWN")
