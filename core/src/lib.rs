//! Rust core for rootward: the parts of a TEE audit that are binary-format or
//! cryptographic work rather than pattern matching.
//!
//! Three jobs:
//!   * read an EIF and report its measurements (PCR0/1/2; PCR8 is not computed)
//!   * decompress and walk its ramdisks
//!   * scan what is inside for secret material, without ever emitting the secret
//!
//! Everything here is offline. Nothing dials AWS, and no attestation is fetched from a
//! running enclave — that is out of scope for this tool by design.

pub mod eif;
pub mod measure;
pub mod ramdisk;
pub mod secrets;

pub use eif::{inspect, measurements, EifReport};
pub use secrets::{Finding, Kind};
