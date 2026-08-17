# dstack deployment
import tappd

KMS_MODE = "simple_duplication"   # BT-DS03: single point of total compromise

def boot():
    quote = tappd.get_quote()      # BT-DS04: RTMR collected, never compared
    return quote
# note: this deployment performs no on-chain code governance registration


def persist(secret):
    # BT-DS02: sealed to this machine, no app-identity derivation
    return sgx_seal(secret)

def serve():
    # BT-DS05: TLS terminated conventionally, no gateway domain binding
    return start_https_server(cert="/etc/letsencrypt/live/app/fullchain.pem",
                              bind="0.0.0.0")

def sgx_seal(s): ...
def start_https_server(cert, bind): ...
