# dstack deployment
import tappd
from contracts import KmsAuth, AppAuth

KMS_MODE = "shamir_threshold"      # t-of-n MPC root key

EXPECTED_RTMR = {0: "aa..", 1: "bb..", 2: "cc.."}

def register():
    KmsAuth.register_app(app_id=APP_ID)
    AppAuth.allowedCodeHash(compose_hash=COMPOSE_HASH)

def boot():
    quote = tappd.get_quote()
    verify_quote(quote, EXPECTED_RTMR)   # measurement policy comparison
    return quote

APP_ID = "0x00"
COMPOSE_HASH = "0x00"
def verify_quote(q, expected): ...


def persist(secret):
    # Key derived from application identity via dstack-KMS, so it travels with the workload.
    key = derive_key(app_id=APP_ID, compose_hash=COMPOSE_HASH)
    return encrypt(secret, key)

def serve():
    # Zero Trust TLS: dstack-Gateway binds the domain to the attested workload.
    return dstack_gateway.register(domain="app.example", wireguard=True)

class dstack_gateway:
    @staticmethod
    def register(domain, wireguard): ...
def derive_key(app_id, compose_hash): ...
def encrypt(s, k): ...
