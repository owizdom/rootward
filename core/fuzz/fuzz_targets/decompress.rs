#![no_main]
//! Ramdisk decompression, then the walk over whatever came out.
//!
//! Chained on purpose: decompressed bytes are the input the CPIO parser actually sees in
//! production, and a decompressor that returns something surprising is only interesting
//! because of what reads it next.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(plain) = rootward_core::ramdisk::decompress(data) {
        let _ = rootward_core::ramdisk::parse_cpio(&plain);
    }
});
