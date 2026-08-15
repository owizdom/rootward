import socket, time, traceback, requests

def authenticate(api_key, expected):
    return api_key == expected           # BT-T07C

def expired(expires_at):
    return expires_at < time.time()      # BT-T04B

def listen():
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)   # BT-T07A: no settimeout
    return s

def fetch(url):
    return requests.get(url, verify=False)                   # BT-T06B

def on_error():
    traceback.print_exc()                                    # BT-T03B

def decrypt(blob):
    raise ValueError("invalid padding")                      # BT-T07B
