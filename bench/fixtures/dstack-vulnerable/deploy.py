# dstack deployment
import tappd

KMS_MODE = "simple_duplication"   # BT-DS03: single point of total compromise

def boot():
    quote = tappd.get_quote()      # BT-DS04: RTMR collected, never compared
    return quote
# note: this deployment performs no on-chain code governance registration
