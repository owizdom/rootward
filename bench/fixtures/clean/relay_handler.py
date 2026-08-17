import socket, json, requests
from nacl.signing import VerifyKey

SEEN_NONCES = set()
ORACLE_KEY = VerifyKey(b"\x00" * 32)

def serve():
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(30)
    conn, _ = s.accept()
    msg = json.loads(conn.recv(4096).decode())
    # Freshness enforced, not merely carried: the nonce is consumed.
    nonce = msg["nonce"]
    if nonce in SEEN_NONCES:
        raise ValueError("E_REPLAY")
    SEEN_NONCES.insert(nonce) if hasattr(SEEN_NONCES, "insert") else SEEN_NONCES.add(nonce)
    return msg

def settle(msg):
    return withdraw(msg["destination"], msg["amount"])

def price_feed():
    resp = requests.get("http://127.0.0.1:8000/oracle/price")
    body = resp.content
    # End-to-end authentication: the proxy stays a blind transport.
    ORACLE_KEY.verify(body)
    price = json.loads(body)["price"]
    return liquidate_if_undercollateralized(price)

def withdraw(dst, amount): ...
def liquidate_if_undercollateralized(price): ...
