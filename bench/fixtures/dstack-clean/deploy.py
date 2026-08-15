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
