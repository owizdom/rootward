import socket, json, requests

def serve():
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(30)
    conn, _ = s.accept()
    # BT-T07D: message schema has no nonce, counter, or signed timestamp
    msg = json.loads(conn.recv(4096).decode())
    return msg

def settle(msg):
    return withdraw(msg["destination"], msg["amount"])

def price_feed():
    # BT-T10: relayed through the parent proxy, acted on with no signature check
    resp = requests.get("http://127.0.0.1:8000/oracle/price")
    price = resp.json()["price"]
    return liquidate_if_undercollateralized(price)

def withdraw(dst, amount): ...
def liquidate_if_undercollateralized(price): ...
