import shutil, json

HOST_SHARED = "/mnt/host-shared"

def stage_inputs():
    # BT-T00A: follows a symlink the host controls
    shutil.copy(f"{HOST_SHARED}/app-compose.json", "/run/staged/app-compose.json")
    return json.load(open(f"{HOST_SHARED}/sys-config.json"))
