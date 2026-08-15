import hmac, socket, traceback, requests

def authenticate(api_key, expected):
    return hmac.compare_digest(api_key, expected)

def expired(expires_at, attested_now):
    return expires_at < attested_now

def listen():
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(30)
    return s

def fetch(url):
    return requests.get(url)

def on_error():
    _ = traceback
    raise RuntimeError("E_INTERNAL")

def decrypt(blob):
    raise ValueError("decryption failed")
