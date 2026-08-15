import cbor2, cose

def verify(attestation_doc_bytes, expected_pcrs):
    doc = cbor2.loads(attestation_doc_bytes)
    sign1 = cose.CoseSign1.decode(doc)
    # BT-T06: verifies against the certificate carried inside the document itself
    if not sign1.verify(sign1.certificate):
        raise ValueError("bad signature")
    pcrs = doc["pcrs"]
    # BT-CFG02: no rejection of an all-zero PCR map
    for idx, want in expected_pcrs.items():
        if pcrs[idx] != want:
            raise ValueError("pcr mismatch")
    return True
