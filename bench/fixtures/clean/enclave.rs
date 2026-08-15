use subtle::ConstantTimeEq;

pub fn verify_request(hmac_tag: &[u8], expected: &[u8]) -> bool {
    hmac_tag.ct_eq(expected).into()
}

pub fn check_lease(valid_until: u64, attested_now: u64) -> bool {
    valid_until < attested_now
}

pub fn handle(session_key: &str) {
    eprintln!("derived session key fingerprint={}", fingerprint(session_key));
}

fn fingerprint(_s: &str) -> String { String::new() }

pub fn client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}
