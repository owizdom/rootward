//! EIF inspection: header, section layout, measurements, and ramdisk contents.
//!
//! Layout, transcribed from `aws-nitro-enclaves-image-format` 0.6.0 `defs/mod.rs`.
//! Everything is packed big-endian with no padding:
//!
//! ```text
//! EifHeader (548 bytes)
//!   magic[4] version:u16 flags:u16 default_mem:u64 default_cpus:u64
//!   reserved:u16 num_sections:u16
//!   section_offsets[32]:u64  section_sizes[32]:u64
//!   unused:u32  eif_crc32:u32
//! then, contiguously:
//!   EifSectionHeader (12 bytes): section_type:u16 flags:u16 section_size:u64
//!   <section_size bytes of data>
//! ```
//!
//! Sections are walked **sequentially** from the end of the header rather than by seeking
//! to `section_offsets`, because that is what `EifReader` does when it computes
//! measurements. Walking a different order would produce a different PCR0 for the same
//! file, which is precisely the bug class BT-CFG03 exists to detect — so this parser has
//! to agree with the reference implementation, not merely with the format description.

use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::measure::{self, Measurements};
use crate::ramdisk;
use crate::secrets;

pub const EIF_MAGIC: [u8; 4] = [0x2e, 0x65, 0x69, 0x66]; // ".eif"
pub const EIF_HEADER_SIZE: usize = 548;
pub const SECTION_HEADER_SIZE: usize = 12;
pub const MAX_NUM_SECTIONS: usize = 32;

/// Cap on a single section, to bound memory when the header is untrustworthy.
const MAX_SECTION_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionType {
    Invalid,
    Kernel,
    Cmdline,
    Ramdisk,
    Signature,
    Metadata,
}

impl SectionType {
    fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            0 => Self::Invalid,
            1 => Self::Kernel,
            2 => Self::Cmdline,
            3 => Self::Ramdisk,
            4 => Self::Signature,
            5 => Self::Metadata,
            _ => return None,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Section {
    pub index: usize,
    pub kind: SectionType,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct Header {
    pub version: u16,
    pub flags: u16,
    pub default_mem: u64,
    pub default_cpus: u64,
    pub num_sections: u16,
    pub eif_crc32: u32,
}

#[derive(Debug, Serialize)]
pub struct EifReport {
    pub path: String,
    pub header: Header,
    /// PCR0/PCR1/PCR2, lowercase hex. PCR8 is never present — see `measure::Measurements::finish`.
    pub measurements: BTreeMap<String, String>,
    /// True when the image carries a signature section, meaning a PCR8 exists that this
    /// tool did not compute.
    pub signature_present: bool,
    pub sections: Vec<Section>,
    pub ramdisk_entries: usize,
    /// Non-fatal problems. Surfaced so that an empty findings list cannot quietly mean
    /// "scanned nothing" rather than "found nothing".
    pub warnings: Vec<String>,
    pub findings: Vec<secrets::Finding>,
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn parse_header(buf: &[u8]) -> Result<Header, String> {
    if buf.len() != EIF_HEADER_SIZE {
        return Err(format!(
            "header must be {EIF_HEADER_SIZE} bytes, got {}",
            buf.len()
        ));
    }
    if buf[0..4] != EIF_MAGIC {
        return Err(format!(
            "bad magic {:02x?}, expected {:02x?} (\".eif\")",
            &buf[0..4],
            EIF_MAGIC
        ));
    }
    let num_sections = be_u16(&buf[26..28]);
    if num_sections as usize > MAX_NUM_SECTIONS {
        return Err(format!(
            "num_sections {num_sections} exceeds the format maximum of {MAX_NUM_SECTIONS}"
        ));
    }
    Ok(Header {
        version: be_u16(&buf[4..6]),
        flags: be_u16(&buf[6..8]),
        default_mem: be_u64(&buf[8..16]),
        default_cpus: be_u64(&buf[16..24]),
        num_sections,
        // offsets [28..284), sizes [284..540), unused [540..544)
        eif_crc32: be_u32(&buf[544..548]),
    })
}

/// Read the EIF, computing measurements and collecting ramdisk secret findings in one pass.
pub fn inspect(path: &Path) -> Result<EifReport, String> {
    let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let file_len = file.metadata().map_err(|e| e.to_string())?.len();
    let mut r = BufReader::new(file);

    let mut hbuf = vec![0u8; EIF_HEADER_SIZE];
    r.read_exact(&mut hbuf)
        .map_err(|e| format!("read header: {e}"))?;
    let header = parse_header(&hbuf)?;

    let mut measurements = Measurements::new();
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    let mut findings = Vec::new();
    let mut ramdisk_entries = 0usize;
    let mut signature_present = false;

    let mut offset = EIF_HEADER_SIZE as u64;
    let mut index = 0usize;

    loop {
        let mut shbuf = [0u8; SECTION_HEADER_SIZE];
        match r.read_exact(&mut shbuf) {
            Ok(()) => {}
            // Clean EOF between sections is the normal end of the file.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read section {index} header: {e}")),
        }

        let raw_type = be_u16(&shbuf[0..2]);
        let size = be_u64(&shbuf[4..12]);
        let data_offset = offset + SECTION_HEADER_SIZE as u64;

        let kind = SectionType::from_u16(raw_type)
            .ok_or_else(|| format!("section {index}: unknown type {raw_type}"))?;
        if kind == SectionType::Invalid {
            return Err(format!("section {index}: invalid section type"));
        }
        if size > MAX_SECTION_BYTES {
            return Err(format!("section {index}: size {size} exceeds the scan cap"));
        }
        if data_offset.saturating_add(size) > file_len {
            return Err(format!(
                "section {index}: claims {size} bytes at offset {data_offset}, past end of file ({file_len})"
            ));
        }

        let mut data = vec![0u8; size as usize];
        r.read_exact(&mut data)
            .map_err(|e| format!("read section {index} data: {e}"))?;

        match kind {
            SectionType::Kernel | SectionType::Cmdline => measurements.kernel_or_cmdline(&data),
            SectionType::Ramdisk => {
                measurements.ramdisk(&data);
                scan_ramdisk(
                    index,
                    &data,
                    &mut ramdisk_entries,
                    &mut findings,
                    &mut warnings,
                );
            }
            SectionType::Signature => {
                signature_present = true;
                warnings.push(
                    "image is signed; PCR8 requires X.509 parsing and was not computed".to_string(),
                );
            }
            SectionType::Metadata => {}
            SectionType::Invalid => unreachable!("rejected above"),
        }

        sections.push(Section {
            index,
            kind,
            offset: data_offset,
            size,
        });
        offset = data_offset + size;
        index += 1;

        if index > MAX_NUM_SECTIONS {
            return Err(format!("more than {MAX_NUM_SECTIONS} sections encountered"));
        }
    }

    if sections.is_empty() {
        return Err("no sections found".to_string());
    }
    if sections.len() != header.num_sections as usize {
        warnings.push(format!(
            "header declares {} sections, {} were present",
            header.num_sections,
            sections.len()
        ));
    }

    Ok(EifReport {
        path: path.display().to_string(),
        header,
        measurements: measurements.finish(),
        signature_present,
        sections,
        ramdisk_entries,
        warnings,
        findings,
    })
}

fn scan_ramdisk(
    index: usize,
    raw: &[u8],
    entry_count: &mut usize,
    findings: &mut Vec<secrets::Finding>,
    warnings: &mut Vec<String>,
) {
    let plain = match ramdisk::decompress(raw) {
        Ok(b) => b,
        Err(e) => {
            warnings.push(format!("section {index}: {e}"));
            return;
        }
    };
    let entries = match ramdisk::parse_cpio(&plain) {
        Ok(e) => e,
        Err(e) => {
            warnings.push(format!("section {index}: cpio: {e}"));
            return;
        }
    };

    *entry_count += entries.len();
    for entry in &entries {
        if entry.truncated {
            warnings.push(format!(
                "{}: {} bytes exceeds the scan cap and was not read",
                entry.path, entry.size
            ));
            continue;
        }
        if !entry.is_file() || entry.data.is_empty() {
            continue;
        }
        findings.extend(secrets::scan_bytes(&entry.path, &entry.data));
    }
}

/// Measurements only, without the ramdisk scan. This is what BT-CFG03 needs in order to
/// diff a built image against the PCR pinned in a KMS key policy.
pub fn measurements(path: &Path) -> Result<BTreeMap<String, String>, String> {
    Ok(inspect(path)?.measurements)
}

/// The PCR value of a register that consumed nothing, re-exported for callers
/// distinguishing "no second ramdisk" from "not computed".
pub fn empty_register() -> String {
    measure::empty_register_hex()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn header_bytes(num_sections: u16) -> Vec<u8> {
        let mut h = vec![0u8; EIF_HEADER_SIZE];
        h[0..4].copy_from_slice(&EIF_MAGIC);
        h[4..6].copy_from_slice(&4u16.to_be_bytes()); // version
        h[8..16].copy_from_slice(&512u64.to_be_bytes()); // default_mem
        h[16..24].copy_from_slice(&2u64.to_be_bytes()); // default_cpus
        h[26..28].copy_from_slice(&num_sections.to_be_bytes());
        h
    }

    fn section(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&kind.to_be_bytes());
        s.extend_from_slice(&0u16.to_be_bytes()); // flags
        s.extend_from_slice(&(data.len() as u64).to_be_bytes());
        s.extend_from_slice(data);
        s
    }

    fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("rootward-eif-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    /// Minimal but structurally valid EIF: kernel, cmdline, one ramdisk.
    fn minimal_eif(ramdisk_payload: &[u8]) -> Vec<u8> {
        let mut eif = header_bytes(3);
        eif.extend(section(1, b"KERNELBYTES"));
        eif.extend(section(2, b"console=ttyS0"));
        eif.extend(section(3, ramdisk_payload));
        eif
    }

    #[test]
    fn parses_a_minimal_image_and_measures_it() {
        let p = write_tmp("minimal.eif", &minimal_eif(b"not-a-cpio"));
        let rep = inspect(&p).expect("inspect");

        assert_eq!(rep.header.version, 4);
        assert_eq!(rep.header.default_cpus, 2);
        assert_eq!(rep.sections.len(), 3);
        assert_eq!(rep.sections[2].kind, SectionType::Ramdisk);

        for pcr in ["PCR0", "PCR1", "PCR2"] {
            assert_eq!(
                rep.measurements[pcr].len(),
                96,
                "{pcr} must be 48 bytes of hex"
            );
        }
        // One ramdisk means nothing reached the app register.
        assert_eq!(rep.measurements["PCR2"], empty_register());
        assert!(!rep.signature_present);
    }

    #[test]
    fn measurement_is_deterministic_across_reads() {
        // The property BT-CFG04 depends on: the same bytes always measure the same.
        let p = write_tmp("determinism.eif", &minimal_eif(b"payload"));
        assert_eq!(measurements(&p).unwrap(), measurements(&p).unwrap());
    }

    #[test]
    fn changing_one_byte_changes_pcr0() {
        let a = write_tmp("a.eif", &minimal_eif(b"payload-a"));
        let b = write_tmp("b.eif", &minimal_eif(b"payload-b"));
        assert_ne!(
            measurements(&a).unwrap()["PCR0"],
            measurements(&b).unwrap()["PCR0"]
        );
    }

    #[test]
    fn finds_a_planted_key_in_the_ramdisk() {
        // BT-T09A end to end: build a gzipped cpio ramdisk containing a private key,
        // wrap it in an EIF, and confirm the scan reaches it.
        use flate2::write::GzEncoder;

        let key_line =
            "PRIVATE_KEY=0x8f2a559490d1b7c3e0a2b41d6c95a7e3f18b204c7d6e9a1350f4c8b2d7e6a903";
        let mut cpio =
            crate::ramdisk::testing::newc_entry("app/.env", 0o100600, key_line.as_bytes());
        cpio.extend(crate::ramdisk::testing::trailer());

        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&cpio).unwrap();
        let gz = enc.finish().unwrap();

        let p = write_tmp("planted.eif", &minimal_eif(&gz));
        let rep = inspect(&p).expect("inspect");

        assert_eq!(rep.ramdisk_entries, 1);
        assert!(
            rep.findings
                .iter()
                .any(|f| f.kind == secrets::Kind::EvmPrivateKey),
            "planted key not found: {:?}",
            rep.findings
        );
        // And the report must not carry the key itself.
        let json = serde_json::to_string(&rep).unwrap();
        assert!(
            !json.contains("8f2a559490d1b7c3"),
            "report leaked key material"
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = minimal_eif(b"x");
        bytes[0] = b'X';
        let p = write_tmp("badmagic.eif", &bytes);
        assert!(inspect(&p).unwrap_err().contains("magic"));
    }

    #[test]
    fn rejects_section_extending_past_end_of_file() {
        let mut eif = header_bytes(1);
        let mut s = Vec::new();
        s.extend_from_slice(&3u16.to_be_bytes());
        s.extend_from_slice(&0u16.to_be_bytes());
        s.extend_from_slice(&(1u64 << 20).to_be_bytes()); // claims 1 MiB
        s.extend_from_slice(b"short");
        eif.extend(s);
        let p = write_tmp("overrun.eif", &eif);
        assert!(inspect(&p).unwrap_err().contains("past end of file"));
    }

    #[test]
    fn rejects_truncated_header() {
        let p = write_tmp("stub.eif", b".eif");
        assert!(inspect(&p).is_err());
    }

    /// The correctness gate for `measure.rs`.
    ///
    /// `nitro-cli` only runs on an EC2 Nitro host, so it cannot be the local oracle. The
    /// official `aws-nitro-enclaves-image-format` crate can: it is the same code
    /// `nitro-cli` uses to report PCRs at build time. It is a heavy, optional dependency
    /// used for exactly this comparison and is never shipped.
    ///
    ///   cargo test --features differential
    #[test]
    #[cfg(feature = "differential")]
    fn measurements_match_the_official_aws_implementation() {
        // utils/mod.rs re-exports only eif_signer, so EifReader is reached through its
        // own module rather than the utils root.
        use aws_nitro_enclaves_image_format::utils::eif_reader::EifReader;

        // Several shapes, because the routing rules differ by section count: PCR1 takes
        // only the first ramdisk and PCR2 takes the rest, so a one-ramdisk image and a
        // three-ramdisk image exercise different paths.
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("one-ramdisk", {
                let mut e = header_bytes(3);
                e.extend(section(1, b"KERNEL"));
                e.extend(section(2, b"console=ttyS0"));
                e.extend(section(3, b"initrd-bytes"));
                e
            }),
            ("two-ramdisks", {
                let mut e = header_bytes(4);
                e.extend(section(1, b"KERNEL-2"));
                e.extend(section(2, b"quiet"));
                e.extend(section(3, b"init-ramdisk"));
                e.extend(section(3, b"app-ramdisk"));
                e
            }),
            ("three-ramdisks-and-metadata", {
                // Metadata must deserialize into EifIdentityInfo or EifReader errors out
                // before it reaches the measurements. It contributes to no hasher in
                // either implementation, so its content cannot affect the comparison —
                // it is here to prove that, and to keep the fixture shaped like a real
                // image rather than a minimal one.
                const METADATA: &[u8] = br#"{
                    "ImageName": "rootward-fixture",
                    "ImageVersion": "0.1.0",
                    "BuildMetadata": {
                        "BuildTime": "2026-01-01T00:00:00.000000000+00:00",
                        "BuildTool": "rootward-test",
                        "BuildToolVersion": "0.1.0",
                        "OperatingSystem": "linux",
                        "KernelVersion": "6.1"
                    },
                    "DockerInfo": {},
                    "CustomMetadata": {}
                }"#;
                let mut e = header_bytes(6);
                e.extend(section(1, b"K"));
                e.extend(section(2, b"C"));
                e.extend(section(3, b"r0"));
                e.extend(section(3, b"r1"));
                e.extend(section(3, b"r2"));
                e.extend(section(5, METADATA));
                e
            }),
        ];

        for (name, bytes) in cases {
            let p = write_tmp(&format!("differential-{name}.eif"), &bytes);

            let mine = measurements(&p).expect("local measurement");
            let mut reader =
                EifReader::from_eif(p.to_string_lossy().into_owned()).expect("EifReader");
            let theirs = reader.get_measurements().expect("official measurement");

            for pcr in ["PCR0", "PCR1", "PCR2"] {
                assert_eq!(
                    mine[pcr], theirs[pcr],
                    "{name}: {pcr} diverges from the official implementation"
                );
            }
        }
    }

    #[test]
    fn warns_when_declared_section_count_disagrees() {
        let mut eif = header_bytes(9); // lies: says 9, contains 3
        eif.extend(section(1, b"K"));
        eif.extend(section(2, b"C"));
        eif.extend(section(3, b"R"));
        let p = write_tmp("miscount.eif", &eif);
        let rep = inspect(&p).unwrap();
        assert!(rep.warnings.iter().any(|w| w.contains("declares 9")));
    }
}
