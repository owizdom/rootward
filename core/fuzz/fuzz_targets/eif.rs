#![no_main]
//! The whole EIF read: header, section walk, measurement, ramdisk scan.
//!
//! `inspect` takes a path rather than a slice, so the target writes the input to a temp
//! file. That is slower than a pure in-memory target and it is the honest one -- the
//! section walk reads section sizes off the file and compares them against its length,
//! which is exactly the arithmetic worth fuzzing.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // A file per iteration, in the OS temp dir, removed when the handle drops.
    let mut f = match tempfile_in_place() {
        Some(f) => f,
        None => return,
    };
    if f.0.write_all(data).is_err() {
        return;
    }
    if f.0.flush().is_err() {
        return;
    }
    let _ = rootward_core::eif::inspect(&f.1);
    let _ = std::fs::remove_file(&f.1);
});

/// A minimal named temp file. Avoids a dev-dependency for four lines of work.
fn tempfile_in_place() -> Option<(std::fs::File, std::path::PathBuf)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "rootward-fuzz-{}-{}.eif",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::File::create(&p).ok().map(|f| (f, p))
}
