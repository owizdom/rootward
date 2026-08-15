import cbor2, cose
from cryptography import x509

AWS_NITRO_ROOT_CERT = open("/etc/pki/nitro/root.pem", "rb").read()

def verify(attestation_doc_bytes, expected_pcrs):
    doc = cbor2.loads(attestation_doc_bytes)
    sign1 = cose.CoseSign1.decode(doc)

    # Walk the cabundle to the pinned AWS Nitro root before trusting anything in the doc.
    root = x509.load_pem_x509_certificate(AWS_NITRO_ROOT_CERT)
    chain = [x509.load_der_x509_certificate(c) for c in doc["cabundle"]]
    verify_cert_chain(chain, root)
    if not sign1.verify(chain[-1].public_key()):
        raise ValueError("bad signature")

    pcrs = doc["pcrs"]
    # A debug-mode enclave reports all-zero PCRs; reject before anything else.
    if all(b == 0 for v in pcrs.values() for b in v):
        raise ValueError("debug-mode attestation rejected")
    for idx, want in expected_pcrs.items():
        if pcrs[idx] != want:
            raise ValueError("pcr mismatch")
    return True

def verify_cert_chain(chain, root):
    ...
