#![no_main]
//! The secret scanner over arbitrary bytes.
//!
//! It runs regexes and a Shannon-entropy pass over whatever is inside a ramdisk, which is
//! attacker-controlled content by definition. Also asserts the property the whole design
//! rests on: a finding never carries the secret it found.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for f in rootward_core::secrets::scan_bytes("fuzz", data) {
        // The report is meant to be safe to paste into an issue. If a finding ever
        // embedded the matched material, that guarantee is gone.
        let rendered = format!("{f:?}");
        assert!(
            !rendered.contains("BEGIN RSA PRIVATE KEY"),
            "a finding rendered the secret it found: {rendered}"
        );
    }
});
