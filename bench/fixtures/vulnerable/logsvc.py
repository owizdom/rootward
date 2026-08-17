import subprocess

# BT-T03C: whole container stream relayed out, no gate
def container_logs(name):
    p = subprocess.Popen(["docker", "logs", "-f", name], stdout=subprocess.PIPE)
    return p.stdout
