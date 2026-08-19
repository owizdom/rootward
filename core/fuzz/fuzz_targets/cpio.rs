#![no_main]
//! The CPIO walker, fed arbitrary bytes.
//!
//! Every field of a newc header is ASCII hex read out of the data: name length, file size,
//! mode. A parser that trusts any of them walks off the end of the buffer. The only
//! acceptable outcomes are a parse result or a `RamdiskError` -- never a panic, and never
//! a hang.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = rootward_core::ramdisk::parse_cpio(data) {
        // Touch the accessors too: they read mode bits the header supplied.
        for e in &entries {
            let _ = e.is_file();
            let _ = e.is_symlink();
            let _ = e.world_accessible();
        }
    }
});
