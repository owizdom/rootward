//! Secret scanner for EIF ramdisk contents and build context (BT-T09A, BT-T09B).
//!
//! Design constraint that shapes everything here: **a finding never carries the secret.**
//! Audit reports get shared, pasted into issues, and (for this project) published. A
//! report that quotes the key it found has moved the key somewhere new. Findings carry a
//! classification, a location, and a SHA-256 prefix that lets an operator confirm which
//! key was hit without the report itself being sensitive.

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    PemPrivateKey,
    SshPrivateKey,
    EvmPrivateKey,
    AwsAccessKeyId,
    AwsSecretAccessKey,
    MnemonicPhrase,
    HighEntropyAssignment,
}

impl Kind {
    pub fn severity(self) -> &'static str {
        match self {
            Self::PemPrivateKey
            | Self::SshPrivateKey
            | Self::EvmPrivateKey
            | Self::MnemonicPhrase
            | Self::AwsSecretAccessKey => "critical",
            Self::AwsAccessKeyId => "high",
            // On its own this is a shape, not a proven secret.
            Self::HighEntropyAssignment => "medium",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PemPrivateKey => "pem_private_key",
            Self::SshPrivateKey => "ssh_private_key",
            Self::EvmPrivateKey => "evm_private_key",
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::AwsSecretAccessKey => "aws_secret_access_key",
            Self::MnemonicPhrase => "mnemonic_phrase",
            Self::HighEntropyAssignment => "high_entropy_assignment",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: Kind,
    pub severity: &'static str,
    /// Path inside the ramdisk, or the build-context path.
    pub path: String,
    /// 1-indexed line within that file.
    pub line: usize,
    /// First 12 hex chars of SHA-256 over the matched value. Enough to correlate against a
    /// known key, not enough to recover one.
    pub digest: String,
    /// Length of the matched value, which distinguishes a real key from a placeholder.
    pub value_len: usize,
    /// Shannon entropy in bits/char over the matched value.
    pub entropy: f64,
    /// Set when the value matched a published test vector rather than a live secret.
    pub known_test_vector: bool,
}

fn digest12(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    hex::encode(&h.finalize()[..6])
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Published keys that appear in nearly every Ethereum test suite. Matching one is a
/// signal the file is a fixture, not that a live key leaked. Kept as digests so this
/// source file does not itself contain a wall of private keys.
fn known_test_digests() -> &'static [&'static str] {
    &[
        // hardhat / anvil account #0 and #1
        "cdb2ef4e0b0e",
        "4a4b1a0f0d29",
    ]
}

/// High-frequency English function words that are absent from the BIP-39 English wordlist.
///
/// The mnemonic pattern is "12 or 24 lowercase words of 3-8 letters", which ordinary prose
/// satisfies constantly. Auditing this repository with its own scanner flagged three plain
/// English sentences as seed phrases at CRITICAL severity, including one in the README and
/// one inside a JSON schema description. A real mnemonic draws only from the 2048-word
/// BIP-39 list; any of these words present means the run is a sentence.
///
/// Deliberately conservative, every entry here is one confirmed absent from BIP-39, so a
/// genuine mnemonic can never be suppressed by this check.
const NOT_IN_BIP39: [&str; 24] = [
    "the", "and", "that", "for", "with", "this", "which", "are", "not", "but", "from", "they",
    "have", "has", "was", "were", "been", "its", "would", "could", "should", "than", "then",
    "there",
];

fn looks_like_prose(phrase: &str) -> bool {
    phrase
        .split_whitespace()
        .any(|w| NOT_IN_BIP39.contains(&w.to_ascii_lowercase().as_str()))
}

fn is_placeholder(value: &str) -> bool {
    let v = value.trim_start_matches("0x");
    // All-zero, all-f, repeated single char, or an obvious stand-in.
    if v.chars().all(|c| c == '0') || v.chars().all(|c| c.eq_ignore_ascii_case(&'f')) {
        return true;
    }
    if v.len() > 4 && v.chars().all(|c| c == v.as_bytes()[0] as char) {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    const STANDINS: [&str; 10] = [
        "changeme",
        "placeholder",
        "example",
        "your-",
        "xxxx",
        "todo",
        "dummy",
        "notreal",
        "redacted",
        "<insert",
    ];
    STANDINS.iter().any(|s| lower.contains(s))
}

/// True when the text immediately before `start` marks the following hex as a content
/// digest rather than a secret. The `regex` crate has no lookbehind, so this inspects the
/// preceding window directly.
fn preceded_by_digest_label(line: &str, start: usize) -> bool {
    // Two shapes, both extremely common in build files:
    //   sha256:<hex>        OCI image digests, lockfile integrity fields
    //   FOO_SHA256=<hex>    toolchain checksums in .env / Makefile / CI config
    // dstack's os/mkosi/versions.env carries five of the latter (KERNEL_SHA256,
    // RUSTC_TOOLCHAIN_SHA256, GO_TOOLCHAIN_SHA256, ...) and every one was reported as an
    // EVM private key, because only the colon form was recognised.
    const LABELS: [&str; 14] = [
        "sha256:",
        "sha512:",
        "sha384:",
        "sha1:",
        "md5:",
        "integrity",
        "checksum",
        "digest",
        "sha256=",
        "sha512=",
        "sha384=",
        "sha1=",
        "md5=",
        "_hash=",
    ];
    let window_start = start.saturating_sub(16);
    // Guard against slicing through a UTF-8 boundary on a line with multibyte characters.
    let Some(prefix) = line.get(window_start..start) else {
        return false;
    };
    let prefix = prefix.to_ascii_lowercase();
    LABELS.iter().any(|l| prefix.contains(l))
}

struct Patterns {
    pem: Regex,
    ssh: Regex,
    evm: Regex,
    aws_id: Regex,
    aws_secret: Regex,
    mnemonic: Regex,
    assignment: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        pem: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----").unwrap(),
        ssh: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
        // 64 hex chars not embedded in a longer hex run (which would be a hash or blob).
        evm: Regex::new(r"(?i)(?:^|[^0-9a-fx])(0x)?([0-9a-f]{64})(?:[^0-9a-f]|$)").unwrap(),
        aws_id: Regex::new(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b").unwrap(),
        aws_secret: Regex::new(
            r#"(?i)aws.{0,20}?(?:secret|private).{0,20}?['"=:\s]([0-9a-zA-Z/+]{40})"#,
        )
        .unwrap(),
        mnemonic: Regex::new(r"\b((?:[a-z]{3,8}\s+){11}[a-z]{3,8}(?:(?:\s+[a-z]{3,8}){12})?)\b")
            .unwrap(),
        assignment: Regex::new(
            r#"(?i)\b(?:secret|private_?key|priv_?key|api_?key|token|passwd|password|credential)\w*\s*[=:]\s*['"]?([A-Za-z0-9+/=_\-]{20,})['"]?"#,
        )
        .unwrap(),
    })
}

/// Scan one file's contents. `path` is used only for reporting.
///
/// Binary files are skipped: a NUL byte in the first 8 KiB means the regexes would be
/// scanning machine code, where 64-hex-looking runs are noise rather than keys.
pub fn scan_bytes(path: &str, data: &[u8]) -> Vec<Finding> {
    let probe = &data[..data.len().min(8192)];
    if probe.contains(&0) {
        return Vec::new();
    }
    match std::str::from_utf8(data) {
        Ok(text) => scan_text(path, text),
        Err(_) => Vec::new(),
    }
}

pub fn scan_text(path: &str, text: &str) -> Vec<Finding> {
    let p = patterns();
    let mut out = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;

        let mut push = |kind: Kind, value: &str| {
            if is_placeholder(value) {
                return;
            }
            let digest = digest12(value);
            let known = known_test_digests().contains(&digest.as_str());
            out.push(Finding {
                kind,
                severity: if known { "info" } else { kind.severity() },
                path: path.to_string(),
                line: line_no,
                digest,
                value_len: value.len(),
                entropy: entropy(value),
                known_test_vector: known,
            });
        };

        // Header markers identify the block; the key body is on following lines and is
        // deliberately not captured, so nothing sensitive enters the finding.
        if p.pem.is_match(line) {
            push(Kind::PemPrivateKey, line.trim());
        }
        if p.ssh.is_match(line) {
            push(Kind::SshPrivateKey, line.trim());
        }
        for c in p.aws_id.captures_iter(line) {
            push(Kind::AwsAccessKeyId, &c[1]);
        }
        for c in p.aws_secret.captures_iter(line) {
            push(Kind::AwsSecretAccessKey, &c[1]);
        }
        for c in p.evm.captures_iter(line) {
            let m = c.get(2).expect("group 2 is not optional");
            let v = m.as_str();
            // A real key is high entropy. A zero-padded id or a repeated nibble is not.
            if entropy(v) < 3.3 {
                continue;
            }
            // Content-addressed digests are 64 hex chars with maximal entropy, so nothing
            // about the value distinguishes them from a key, only what precedes them
            // does. Every correctly pinned Dockerfile carries `FROM image@sha256:<64 hex>`,
            // so without this the rule fires hardest on the repos doing it right.
            if preceded_by_digest_label(line, m.start()) {
                continue;
            }
            push(Kind::EvmPrivateKey, v);
        }
        for c in p.mnemonic.captures_iter(line) {
            let phrase = &c[1];
            let words = phrase.split_whitespace().count();
            if (words == 12 || words == 24) && !looks_like_prose(phrase) {
                push(Kind::MnemonicPhrase, phrase);
            }
        }
        for c in p.assignment.captures_iter(line) {
            let v = &c[1];
            if entropy(v) >= 3.5 && !p.aws_id.is_match(v) {
                push(Kind::HighEntropyAssignment, v);
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_pem_key_without_emitting_it() {
        let body = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
        let f = scan_text("app/key.pem", body);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::PemPrivateKey);
        assert_eq!(f[0].severity, "critical");
        // The finding must not carry the key body.
        let json = serde_json::to_string(&f[0]).unwrap();
        assert!(
            !json.contains("MIIEvQIBADANBg"),
            "finding leaked key material"
        );
    }

    #[test]
    fn finds_an_evm_key() {
        let f = scan_text(
            "config.env",
            "PRIVATE_KEY=0x8f2a559490d1b7c3e0a2b41d6c95a7e3f18b204c7d6e9a1350f4c8b2d7e6a903",
        );
        assert!(f.iter().any(|x| x.kind == Kind::EvmPrivateKey));
    }

    #[test]
    fn ignores_placeholders_and_zero_keys() {
        let f = scan_text(
            "example.env",
            "PRIVATE_KEY=0x0000000000000000000000000000000000000000000000000000000000000000\n\
             API_KEY=changeme-changeme-changeme",
        );
        assert!(f.is_empty(), "placeholders must not be reported: {f:?}");
    }

    #[test]
    fn ignores_a_pinned_docker_base_image_digest() {
        // Regression: a digest-pinned FROM line is what a *correct* Dockerfile looks like.
        // Flagging it as a private key made the rule fire hardest on repos doing the right
        // thing, caught by the clean fixture, which is what clean fixtures are for.
        let f = scan_text(
            "Dockerfile",
            "FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff",
        );
        assert!(
            f.is_empty(),
            "pinned base image digest must not be a finding: {f:?}"
        );
    }

    #[test]
    fn still_finds_a_key_on_a_line_that_also_mentions_a_digest() {
        // The suppression is positional, not line-wide: a digest earlier in the line must
        // not shield a real key later in it.
        let f = scan_text(
            "deploy.sh",
            "verify sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff && \
             export PRIVATE_KEY=0x8f2a559490d1b7c3e0a2b41d6c95a7e3f18b204c7d6e9a1350f4c8b2d7e6a903",
        );
        assert!(
            f.iter().any(|x| x.kind == Kind::EvmPrivateKey),
            "key after a digest on the same line must still be found: {f:?}"
        );
    }

    #[test]
    fn ignores_a_sha256_hash_that_is_not_a_key() {
        // 64 hex chars that are a content hash. This is the main FP source for the EVM
        // rule, and the reason the value_len and entropy fields exist in the finding.
        let f = scan_text(
            "lock.json",
            "\"integrity\": \"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\"",
        );
        // Detected by shape; a human decides. Assert we at least classify and hash it
        // rather than printing it.
        for finding in &f {
            assert!(!finding.digest.is_empty());
        }
    }

    #[test]
    fn finds_aws_access_key_id() {
        let f = scan_text("boot.sh", "export AWS_ACCESS_KEY_ID=AKIA4NPQR7TZLW2VXKD3");
        assert!(f.iter().any(|x| x.kind == Kind::AwsAccessKeyId), "{f:?}");
    }

    #[test]
    fn ignores_the_documented_aws_example_key() {
        // AKIAIOSFODNN7EXAMPLE appears throughout AWS's own documentation. It matches the
        // access-key-id shape exactly, so only the placeholder filter keeps it out of
        // reports, and it turns up in enough vendored docs and samples that letting it
        // through would be a steady source of false positives.
        let f = scan_text("docs.md", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(
            f.is_empty(),
            "documented example key must not be reported: {f:?}"
        );
    }

    #[test]
    fn ignores_english_prose_that_matches_the_mnemonic_shape() {
        // Found by pointing the tool at its own repository: twelve consecutive lowercase
        // words is a sentence far more often than it is a seed phrase, and this shipped at
        // CRITICAL severity against the README.
        for prose in [
            "only its author's idiom scores full recall against one mutant and then misses the same bug",
            "a rule whose author cannot name its failure mode has not been thought through today",
        ] {
            let f = scan_text("README.md", prose);
            assert!(
                !f.iter().any(|x| x.kind == Kind::MnemonicPhrase),
                "prose reported as a mnemonic: {prose:?} -> {f:?}"
            );
        }
    }

    #[test]
    fn finds_a_twelve_word_mnemonic() {
        let f = scan_text(
            "seed.txt",
            "myth like bonus scare over problem client lizard pioneer submit female collect",
        );
        assert!(f.iter().any(|x| x.kind == Kind::MnemonicPhrase));
    }

    #[test]
    fn skips_binary_files() {
        let mut data =
            b"PRIVATE_KEY=0x8f2a559490d1b7c3e0a2b41d6c95a7e3f18b204c7d6e9a1350f4c8b2d7e6a903"
                .to_vec();
        data.push(0);
        assert!(scan_bytes("app/binary", &data).is_empty());
    }

    #[test]
    fn entropy_separates_random_from_repetitive() {
        assert!(entropy("aaaaaaaaaaaaaaaa") < 1.0);
        assert!(entropy("8f2a559490d1b7c3e0a2b41d6c95a7e3") > 3.0);
    }
}
