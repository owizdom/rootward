//! `tee-audit-core` — the Rust half of the auditor, as a subprocess that speaks JSON.
//!
//! Deliberately a binary rather than a PyO3 extension module. The Python side calls this
//! a handful of times per audit to do chunky work (parse one EIF, scan one build context),
//! never in a loop, so the binding overhead PyO3 would save is not measurable — while the
//! costs are real: an ABI tied to a specific CPython version, a maturin build step in
//! everyone's install path, and a native crash taking the whole auditor down with it.
//! A subprocess boundary is one JSON contract, debuggable with `cat`, and survives the
//! child dying on a malformed image.
//!
//! Usage:
//!   tee-audit-core inspect <file.eif>       full report: measurements, sections, findings
//!   tee-audit-core measure <file.eif>       measurements only
//!   tee-audit-core scan <file> [file...]    secret-scan arbitrary text files
//!
//! Always emits a JSON object on stdout. Errors are `{"error": "..."}` with exit code 1,
//! so the caller parses one shape either way.

use std::path::Path;
use std::process::ExitCode;

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    let body = serde_json::json!({ "error": msg.to_string() });
    println!("{body}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return fail("usage: tee-audit-core <inspect|measure|scan> <path>...");
    };

    match cmd.as_str() {
        "inspect" => {
            let Some(path) = args.get(1) else {
                return fail("inspect needs a path");
            };
            match tee_audit_core::eif::inspect(Path::new(path)) {
                Ok(report) => match serde_json::to_string(&report) {
                    Ok(s) => {
                        println!("{s}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(e),
                },
                Err(e) => fail(e),
            }
        }

        "measure" => {
            let Some(path) = args.get(1) else {
                return fail("measure needs a path");
            };
            match tee_audit_core::eif::measurements(Path::new(path)) {
                Ok(m) => {
                    let body = serde_json::json!({
                        "measurements": m,
                        // So a caller can tell "no second ramdisk" from "not computed".
                        "empty_register": tee_audit_core::eif::empty_register(),
                    });
                    println!("{body}");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        // Build-context scanning (BT-T09B): Dockerfiles, shell scripts, env files.
        "scan" => {
            let paths = &args[1..];
            if paths.is_empty() {
                return fail("scan needs at least one path");
            }
            let mut findings = Vec::new();
            let mut warnings: Vec<String> = Vec::new();
            for p in paths {
                match std::fs::read(p) {
                    Ok(bytes) => findings.extend(tee_audit_core::secrets::scan_bytes(p, &bytes)),
                    Err(e) => warnings.push(format!("{p}: {e}")),
                }
            }
            let body = serde_json::json!({
                "findings": findings,
                "warnings": warnings,
                "scanned": paths.len() - warnings.len(),
            });
            println!("{body}");
            ExitCode::SUCCESS
        }

        other => fail(format!(
            "unknown command {other:?}; expected inspect, measure, or scan"
        )),
    }
}
