//! PCR measurement for EIF images.
//!
//! Reimplemented locally rather than taken from `aws-nitro-enclaves-image-format`, and
//! that needs justifying, because reimplementing a measurement algorithm is normally
//! exactly the kind of thing this project exists to warn against.
//!
//! The reason is dependency surface. That crate has no feature flags and pulls
//! `aws-config`, `aws-sdk-kms`, `tokio`, `hyper`, `rustls`, and `openssl` as mandatory
//! dependencies — 545 crates transitively — because it also handles KMS-backed *signing*.
//! This tool only ever reads. Shipping a network stack and a KMS client inside an auditor
//! whose own threat model is "parse a file supplied by a hostile host" is a poor trade.
//!
//! The correctness risk that creates is handled by not trusting this file: with
//! `--features differential`, the test suite runs both implementations over generated
//! images and asserts the digests match. The official crate is the oracle; it just is not
//! a runtime dependency. Algorithm transcribed from `defs/eif_hasher.rs` and
//! `utils/eif_reader.rs` at version 0.6.0.

use sha2::{Digest, Sha384};
use std::collections::BTreeMap;

const SHA384_OUT: usize = 48;

/// One measurement register, accumulating section bytes.
///
/// `EifReader` builds its hashers with `new_without_cache`, which sets `block_size = 0`
/// and makes `EifHasher` a passthrough straight to the underlying SHA-384. The block
/// chaining described in `EifHasher`'s doc comment therefore never runs for EIF
/// measurement, and the accumulated value is a plain hash over the concatenated bytes.
#[derive(Clone)]
pub struct Register {
    hasher: Sha384,
}

impl Default for Register {
    fn default() -> Self {
        Self::new()
    }
}

impl Register {
    pub fn new() -> Self {
        Self { hasher: Sha384::new() }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// `tpm_extend_finalize_reset`: hash the accumulated bytes, then extend a zero
    /// register with that digest.
    ///
    ///   PCR = SHA384( 0x00 * 48 || SHA384(accumulated bytes) )
    ///
    /// Note this is well defined for a register that consumed nothing: the result is
    /// SHA384(zeros || SHA384("")), a fixed nonzero value. An EIF with a single ramdisk
    /// still has a PCR2, and it is that constant rather than all-zeros. Do not confuse it
    /// with the all-zero PCRs a debug-mode enclave reports (see BT-CFG02).
    pub fn finalize(self) -> Vec<u8> {
        let inner = self.hasher.finalize();
        let mut outer = Sha384::new();
        outer.update([0u8; SHA384_OUT]);
        outer.update(inner);
        outer.finalize().to_vec()
    }

    pub fn finalize_hex(self) -> String {
        hex::encode(self.finalize())
    }
}

/// The measurement registers of an EIF, fed in section order.
///
/// Routing, from `EifReader::from_eif`:
///   * kernel and cmdline  -> image + bootstrap
///   * ramdisk index 0     -> image + bootstrap
///   * ramdisk index 1..n  -> image + app
///   * signature           -> cert (the DER of the signing certificate, not the section)
#[derive(Clone, Default)]
pub struct Measurements {
    image: Register,
    bootstrap: Register,
    app: Register,
    ramdisk_idx: usize,
}

impl Measurements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn kernel_or_cmdline(&mut self, bytes: &[u8]) {
        self.image.update(bytes);
        self.bootstrap.update(bytes);
    }

    pub fn ramdisk(&mut self, bytes: &[u8]) {
        self.image.update(bytes);
        if self.ramdisk_idx == 0 {
            self.bootstrap.update(bytes);
        } else {
            self.app.update(bytes);
        }
        self.ramdisk_idx += 1;
    }

    /// PCR0, PCR1, PCR2 as lowercase hex.
    ///
    /// PCR8 is deliberately absent. Computing it requires CBOR-decoding the signature
    /// section, PEM-parsing the signing certificate, and re-encoding it as DER — which
    /// means an X.509 stack, which means openssl, which is the dependency this module
    /// exists to avoid. `signature_present` on the report records that the image is
    /// signed; the report's NOT-VERIFIED section records that PCR8 was not computed.
    /// Reporting a wrong PCR8 would be worse than reporting none.
    pub fn finish(self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("PCR0".to_string(), self.image.finalize_hex());
        m.insert("PCR1".to_string(), self.bootstrap.finalize_hex());
        m.insert("PCR2".to_string(), self.app.finalize_hex());
        m
    }
}

/// The PCR value of a register that consumed no bytes. Useful for telling "this image has
/// one ramdisk, so PCR2 is the empty-register constant" apart from "PCR2 was not computed".
pub fn empty_register_hex() -> String {
    Register::new().finalize_hex()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_matches_hand_computed_definition() {
        let mut r = Register::new();
        r.update(b"hello");

        let inner = Sha384::digest(b"hello");
        let mut outer = Sha384::new();
        outer.update([0u8; 48]);
        outer.update(inner);

        assert_eq!(r.finalize(), outer.finalize().to_vec());
    }

    #[test]
    fn empty_register_is_nonzero_and_stable() {
        let hex = empty_register_hex();
        assert_eq!(hex.len(), 96, "SHA-384 is 48 bytes / 96 hex chars");
        assert_ne!(hex, "0".repeat(96), "must not be confused with debug-mode zero PCRs");
        assert_eq!(hex, empty_register_hex(), "must be deterministic");
    }

    #[test]
    fn streaming_updates_equal_one_contiguous_update() {
        // Section bytes arrive in chunks; the result must not depend on chunking.
        let mut a = Register::new();
        a.update(b"abcdef");

        let mut b = Register::new();
        b.update(b"abc");
        b.update(b"def");

        assert_eq!(a.finalize(), b.finalize());
    }

    #[test]
    fn routes_sections_to_the_right_registers() {
        let mut m = Measurements::new();
        m.kernel_or_cmdline(b"kernel");
        m.kernel_or_cmdline(b"cmdline");
        m.ramdisk(b"init");
        m.ramdisk(b"app");
        let got = m.finish();

        // PCR0 over everything, PCR1 over kernel+cmdline+first ramdisk, PCR2 over the rest.
        let mut image = Register::new();
        image.update(b"kernel");
        image.update(b"cmdline");
        image.update(b"init");
        image.update(b"app");

        let mut bootstrap = Register::new();
        bootstrap.update(b"kernel");
        bootstrap.update(b"cmdline");
        bootstrap.update(b"init");

        let mut app = Register::new();
        app.update(b"app");

        assert_eq!(got["PCR0"], image.finalize_hex());
        assert_eq!(got["PCR1"], bootstrap.finalize_hex());
        assert_eq!(got["PCR2"], app.finalize_hex());
    }

    #[test]
    fn single_ramdisk_leaves_pcr2_at_the_empty_constant() {
        let mut m = Measurements::new();
        m.kernel_or_cmdline(b"k");
        m.ramdisk(b"init");
        assert_eq!(m.finish()["PCR2"], empty_register_hex());
    }

    #[test]
    fn reordering_ramdisks_changes_the_measurement() {
        // The property the whole scheme depends on: a different image measures differently.
        let mut a = Measurements::new();
        a.ramdisk(b"one");
        a.ramdisk(b"two");

        let mut b = Measurements::new();
        b.ramdisk(b"two");
        b.ramdisk(b"one");

        assert_ne!(a.finish()["PCR0"], b.finish()["PCR0"]);
    }
}
