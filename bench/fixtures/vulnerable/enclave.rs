use std::time::SystemTime;

pub fn verify_request(hmac_tag: &[u8], expected: &[u8]) -> bool {
    // BT-T07C: short-circuits on first differing byte
    hmac_tag == expected
}

pub fn check_lease(valid_until: SystemTime) -> bool {
    // BT-T04B: parent controls this clock
    valid_until < SystemTime::now()
}

pub fn handle(session_key: &str) {
    // BT-T03: leaves the enclave via stderr
    eprintln!("derived session_key={}", session_key);
}

pub fn client() -> reqwest::ClientBuilder {
    // BT-T06B: the parent proxies this connection
    reqwest::Client::builder().danger_accept_invalid_certs(true)
}
