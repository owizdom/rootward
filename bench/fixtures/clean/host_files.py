import os, shutil, json

HOST_SHARED = "/mnt/host-shared"

def stage_inputs():
    src = f"{HOST_SHARED}/app-compose.json"
    # Reject a link before touching the target; the host chooses this path.
    if os.path.islink(src) or not os.path.isfile(src):
        raise ValueError("E_UNTRUSTED_PATH")
    st = os.lstat(src)
    shutil.copy(src, "/run/staged/app-compose.json")
    return json.load(open("/run/staged/app-compose.json"))
