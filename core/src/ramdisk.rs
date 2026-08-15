//! Reader for the newc (SVR4) cpio archives that make up an EIF ramdisk.
//!
//! Implemented here rather than pulled from a crate on purpose. This parser runs over
//! attacker-influenceable bytes — the whole point of BT-T09A is that an EIF is a build
//! artifact sitting on a host we treat as hostile — and newc is a small enough format
//! that a bounds-checked reader is less risk than an unvetted dependency.
//!
//! Format: a 110-byte ASCII header, then the NUL-terminated filename, then the file
//! data, with both the name and the data padded out to a 4-byte boundary. The archive
//! ends with an entry named `TRAILER!!!`.

use std::io::Read;

const MAGIC_NEWC: &[u8] = b"070701";
const MAGIC_NEWC_CRC: &[u8] = b"070702";
const HEADER_LEN: usize = 110;
const TRAILER: &str = "TRAILER!!!";

/// Refuse archives that expand beyond this. A gzip bomb in a ramdisk should fail the
/// scan loudly rather than exhaust memory.
const MAX_INFLATED: u64 = 4 * 1024 * 1024 * 1024;

/// Entries larger than this are recorded but their contents are not held in memory.
const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub mode: u32,
    pub size: usize,
    pub data: Vec<u8>,
    /// True when the entry exceeded MAX_ENTRY_BYTES and `data` is therefore empty.
    pub truncated: bool,
}

impl Entry {
    pub fn is_file(&self) -> bool {
        // S_IFMT 0o170000, S_IFREG 0o100000
        self.mode & 0o170000 == 0o100000
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }

    /// World-readable or world-writable bits, which matter for a key file that made it
    /// into the image regardless of how it got there.
    pub fn world_accessible(&self) -> bool {
        self.mode & 0o006 != 0
    }
}

#[derive(Debug)]
pub enum RamdiskError {
    Decompress(String),
    Truncated { at: usize, need: usize, have: usize },
    BadMagic { at: usize, found: [u8; 6] },
    BadField { at: usize, field: &'static str },
    TooLarge,
}

impl std::fmt::Display for RamdiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decompress(e) => write!(f, "decompress failed: {e}"),
            Self::Truncated { at, need, have } => {
                write!(f, "truncated archive at offset {at}: need {need} bytes, have {have}")
            }
            Self::BadMagic { at, found } => {
                write!(f, "bad cpio magic at offset {at}: {:?}", String::from_utf8_lossy(found))
            }
            Self::BadField { at, field } => write!(f, "unparseable {field} at offset {at}"),
            Self::TooLarge => write!(f, "archive exceeds the {MAX_INFLATED} byte inflate limit"),
        }
    }
}

impl std::error::Error for RamdiskError {}

/// Gunzip a ramdisk section. Uses MultiGzDecoder because initramfs images are
/// conventionally several gzip members concatenated, and a plain GzDecoder silently
/// stops after the first one — which would look like a small, clean ramdisk rather
/// than a parse failure.
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, RamdiskError> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut out = Vec::new();
        flate2::read::MultiGzDecoder::new(bytes)
            .take(MAX_INFLATED)
            .read_to_end(&mut out)
            .map_err(|e| RamdiskError::Decompress(e.to_string()))?;
        if out.len() as u64 >= MAX_INFLATED {
            return Err(RamdiskError::TooLarge);
        }
        Ok(out)
    } else {
        // nitro-cli has shipped uncompressed ramdisks; accept them rather than fail.
        Ok(bytes.to_vec())
    }
}

fn hex_field(buf: &[u8], at: usize, field: &'static str) -> Result<u64, RamdiskError> {
    let s = std::str::from_utf8(buf).map_err(|_| RamdiskError::BadField { at, field })?;
    u64::from_str_radix(s.trim(), 16).map_err(|_| RamdiskError::BadField { at, field })
}

#[inline]
fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

/// Parse a decompressed newc cpio archive into its entries.
///
/// Stops cleanly at `TRAILER!!!`. Trailing bytes after the trailer are ignored, which is
/// normal: concatenated archives and zero padding both appear there.
pub fn parse_cpio(data: &[u8]) -> Result<Vec<Entry>, RamdiskError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    loop {
        // Zero padding after the trailer is common; treat an all-zero tail as the end.
        if pos >= data.len() || data[pos..].iter().all(|&b| b == 0) {
            break;
        }

        let need = pos + HEADER_LEN;
        if need > data.len() {
            return Err(RamdiskError::Truncated { at: pos, need: HEADER_LEN, have: data.len() - pos });
        }
        let hdr = &data[pos..pos + HEADER_LEN];

        let magic = &hdr[0..6];
        if magic != MAGIC_NEWC && magic != MAGIC_NEWC_CRC {
            let mut found = [0u8; 6];
            found.copy_from_slice(magic);
            return Err(RamdiskError::BadMagic { at: pos, found });
        }

        // Fields are 8 ASCII hex chars each, in fixed order after the 6-byte magic.
        let mode = hex_field(&hdr[14..22], pos, "c_mode")? as u32;
        let filesize = hex_field(&hdr[54..62], pos, "c_filesize")? as usize;
        let namesize = hex_field(&hdr[94..102], pos, "c_namesize")? as usize;

        let name_start = pos + HEADER_LEN;
        let name_end = name_start
            .checked_add(namesize)
            .ok_or(RamdiskError::BadField { at: pos, field: "c_namesize" })?;
        if name_end > data.len() {
            return Err(RamdiskError::Truncated { at: pos, need: namesize, have: data.len() - name_start });
        }

        let raw_name = &data[name_start..name_end];
        let name = String::from_utf8_lossy(raw_name.strip_suffix(b"\0").unwrap_or(raw_name)).into_owned();

        if name == TRAILER {
            break;
        }

        let data_start = name_end + pad4(HEADER_LEN + namesize);
        let data_end = data_start
            .checked_add(filesize)
            .ok_or(RamdiskError::BadField { at: pos, field: "c_filesize" })?;
        if data_end > data.len() {
            return Err(RamdiskError::Truncated { at: pos, need: filesize, have: data.len().saturating_sub(data_start) });
        }

        let truncated = filesize > MAX_ENTRY_BYTES;
        let body = if truncated { Vec::new() } else { data[data_start..data_end].to_vec() };

        entries.push(Entry { path: name, mode, size: filesize, data: body, truncated });

        pos = data_end + pad4(filesize);
    }

    Ok(entries)
}

/// Archive builders shared by this module's tests and the EIF end-to-end tests.
/// Test-only: building cpio archives is not something the auditor does at runtime.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Build one newc entry the way the format specifies, so the tests exercise a real
    /// archive rather than a fixture whose provenance we cannot check.
    pub(crate) fn newc_entry(name: &str, mode: u32, body: &[u8]) -> Vec<u8> {
        let namesize = name.len() + 1;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_NEWC);
        let fields: [u64; 13] = [
            1, mode as u64, 0, 0, 1, 0, body.len() as u64, 0, 0, 0, 0, namesize as u64, 0,
        ];
        for f in fields.iter() {
            out.extend_from_slice(format!("{f:08X}").as_bytes());
        }
        // 6 magic + 13*8 = 110
        assert_eq!(out.len(), HEADER_LEN);
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend(std::iter::repeat_n(0u8, pad4(HEADER_LEN + namesize)));
        out.extend_from_slice(body);
        out.extend(std::iter::repeat_n(0u8, pad4(body.len())));
        out
    }

    pub(crate) fn trailer() -> Vec<u8> {
        newc_entry(TRAILER, 0, b"")
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{newc_entry, trailer};
    use super::*;

    #[test]
    fn parses_entries_and_stops_at_trailer() {
        let mut archive = Vec::new();
        archive.extend(newc_entry("app/config.json", 0o100644, b"{\"k\":1}"));
        archive.extend(newc_entry("app/key.pem", 0o100600, b"-----BEGIN PRIVATE KEY-----"));
        archive.extend(trailer());
        archive.extend(newc_entry("after/trailer.txt", 0o100644, b"ignored"));

        let entries = parse_cpio(&archive).expect("parse");
        assert_eq!(entries.len(), 2, "must stop at TRAILER!!!");
        assert_eq!(entries[0].path, "app/config.json");
        assert_eq!(entries[0].data, b"{\"k\":1}");
        assert!(entries[0].is_file());
        assert_eq!(entries[1].path, "app/key.pem");
        assert!(!entries[1].world_accessible());
    }

    #[test]
    fn handles_padding_across_name_and_body_lengths() {
        // Names and bodies of every length mod 4, to catch an off-by-one in pad4.
        for name_len in 1..=8usize {
            for body_len in 0..=8usize {
                let name = "a".repeat(name_len);
                let body = vec![b'x'; body_len];
                let mut archive = newc_entry(&name, 0o100644, &body);
                archive.extend(trailer());
                let entries = parse_cpio(&archive)
                    .unwrap_or_else(|e| panic!("name={name_len} body={body_len}: {e}"));
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].path, name);
                assert_eq!(entries[0].data, body);
            }
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut archive = newc_entry("f", 0o100644, b"x");
        archive[0] = b'X';
        assert!(matches!(parse_cpio(&archive), Err(RamdiskError::BadMagic { .. })));
    }

    #[test]
    fn rejects_truncated_body_instead_of_reading_out_of_bounds() {
        let mut archive = newc_entry("f", 0o100644, b"0123456789abcdef");
        archive.truncate(archive.len() - 8);
        assert!(matches!(parse_cpio(&archive), Err(RamdiskError::Truncated { .. })));
    }

    #[test]
    fn declared_size_beyond_buffer_does_not_panic() {
        // c_filesize claims a huge body the archive does not contain.
        let mut archive = newc_entry("f", 0o100644, b"x");
        archive[54..62].copy_from_slice(b"7FFFFFFF");
        assert!(matches!(parse_cpio(&archive), Err(RamdiskError::Truncated { .. })));
    }

    #[test]
    fn empty_and_all_zero_input_parse_as_empty() {
        assert!(parse_cpio(&[]).unwrap().is_empty());
        assert!(parse_cpio(&[0u8; 512]).unwrap().is_empty());
    }

    #[test]
    fn passes_through_uncompressed_ramdisk() {
        let raw = b"not gzip";
        assert_eq!(decompress(raw).unwrap(), raw);
    }

    #[test]
    fn round_trips_through_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut archive = newc_entry("app/x", 0o100644, b"hello");
        archive.extend(trailer());

        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&archive).unwrap();
        let gz = enc.finish().unwrap();

        let entries = parse_cpio(&decompress(&gz).unwrap()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"hello");
    }

    #[test]
    fn reads_all_members_of_a_concatenated_gzip() {
        // The MultiGzDecoder case: a plain GzDecoder returns only the first member,
        // which would look like a valid short ramdisk rather than an error.
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut first = newc_entry("a", 0o100644, b"one");
        let mut second = newc_entry("b", 0o100644, b"two");
        second.extend(trailer());

        let mut gz = Vec::new();
        for part in [&mut first, &mut second] {
            let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(part).unwrap();
            gz.extend(enc.finish().unwrap());
        }

        let entries = parse_cpio(&decompress(&gz).unwrap()).unwrap();
        assert_eq!(entries.len(), 2, "concatenated gzip members must all be read");
        assert_eq!(entries[1].path, "b");
    }
}
