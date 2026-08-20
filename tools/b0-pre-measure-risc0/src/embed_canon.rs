//! Pure §G guest-embed canonicalization helpers (string/path only — NO fs, NO crypto). Shared
//! VERBATIM by `build.rs` (build-time, via `#[path]`) and by the crate itself (so `cargo test`
//! exercises the unit tests below). One source, one behavior, tested once. The fs copy + validation,
//! SHA-256/BLAKE3 hashing, env reads, and facts emission stay in `build.rs`.
//!
//! Every refusal here is fail-closed (panics, breaking the build) — a silent miss would let an
//! un-remapped absolute path leak into the reproducible runner.
#![allow(dead_code)] // build-time logic; the runner binary never calls these at runtime.

use std::path::PathBuf;

/// The FIXED, reviewed filename the guest ELF is copied to inside OUT_DIR. Stable across every build
/// (path-independent): the runner embeds it via `concat!(env!("OUT_DIR"), "/<this>")`.
pub const CANONICAL_GUEST_ELF_NAME: &str = "b0_pre_candidate_risc0_guest.elf";

/// The FIXED canonical sentinel the unused `_PATH` const is neutralized to. Carries NO build-specific
/// data — byte-identical across every build.
pub const CANONICAL_GUEST_PATH_SENTINEL: &str = "/b0/canonical/b0_pre_candidate_risc0_guest.elf";

/// The substring between the first pair of double quotes (Linux guest-ELF paths carry no escapes).
pub fn first_quoted(line: &str) -> Option<String> {
    let a = line.find('"')? + 1;
    let b = line[a..].find('"')? + a;
    Some(line[a..b].to_string())
}

/// Parse the single `_ELF: &[u8] = include_bytes!("<abs>")` include path. Fail-closed: refuse if the
/// line is absent (codegen changed) or appears more than once (ambiguous guest ELF).
pub fn parse_single_elf_include(text: &str) -> String {
    let mut found: Option<String> = None;
    for line in text.lines() {
        if line.contains("_ELF: &[u8] = include_bytes!(\"") {
            let abs = first_quoted(line)
                .unwrap_or_else(|| panic!("malformed _ELF include line: {line:?}"));
            assert!(
                found.is_none(),
                "multiple `_ELF = include_bytes!(\"<abs>\")` entries — ambiguous guest ELF; refusing"
            );
            found = Some(abs);
        }
    }
    found.unwrap_or_else(|| {
        panic!(
            "methods.rs did not contain the expected `_ELF = include_bytes!(\"<abs>\")` line; \
             embed_methods() codegen changed — refusing to emit a possibly path-dependent runner"
        )
    })
}

/// The expected guest tree: risc0-build writes the guest ELF to `<target>/riscv-guest/...`, where
/// `<target>` is the ancestor of OUT_DIR (`<target>/<profile>/build/<pkg-hash>/out`). Deriving it from
/// OUT_DIR covers both the CARGO_TARGET_DIR-set (venue) and default cases, since OUT_DIR is always
/// under the effective target dir.
pub fn expected_guest_root(out_dir: &str) -> PathBuf {
    let mut p = PathBuf::from(out_dir);
    for _ in 0..4 {
        p = p
            .parent()
            .unwrap_or_else(|| panic!("OUT_DIR {out_dir:?} has too few components"))
            .to_path_buf();
    }
    p.join("riscv-guest")
}

/// Rewrite `_ELF` to the OUT_DIR-relative include and `_PATH` to the fixed sentinel. Refuse unless
/// exactly one `_ELF` line was rewritten.
pub fn rewrite_methods(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rewired_elf = 0usize;
    for line in text.lines() {
        if line.contains("_ELF: &[u8] = include_bytes!(\"") {
            let (lhs, _) = line.split_once(" = ").expect("_ELF line has ' = '");
            out.push_str(lhs);
            out.push_str(" = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/");
            out.push_str(CANONICAL_GUEST_ELF_NAME);
            out.push_str("\"));\n");
            rewired_elf += 1;
        } else if line.contains("_PATH: &str = \"") {
            let (lhs, _) = line.split_once(" = ").expect("_PATH line has ' = '");
            // The runner never reads `_PATH`; neutralize its value AND silence the resulting dead-code
            // warning so a `-D warnings` venue build stays clean.
            out.push_str("#[allow(dead_code)] ");
            out.push_str(lhs);
            out.push_str(" = \"");
            out.push_str(CANONICAL_GUEST_PATH_SENTINEL);
            out.push_str("\";\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(
        rewired_elf == 1,
        "expected exactly one `_ELF` include to rewrite, rewired {rewired_elf}; refusing"
    );
    out
}

/// Refuse if the final methods.rs contains any forbidden build-specific path (A.7).
pub fn scan_no_leaks(final_text: &str, forbidden: &[String]) {
    for sub in forbidden {
        assert!(
            !final_text.contains(sub.as_str()),
            "canonical methods.rs leaks build-specific path {sub:?}; refusing"
        );
    }
}

/// Parse the guest image id (`_ID: [u32; 8] = [a, b, ...];`) as a comma-joined decimal list, if
/// present. Best effort — the double-build's runner byte-equality already subsumes image-id equality.
pub fn parse_image_id(text: &str) -> Option<String> {
    for line in text.lines() {
        if line.contains("_ID: [u32; 8] = [") {
            let (_, rhs) = line.split_once(" = ")?;
            let inner = rhs
                .trim()
                .trim_end_matches(';')
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']');
            let nums: Vec<&str> = inner
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if nums.len() == 8 && nums.iter().all(|s| s.chars().all(|c| c.is_ascii_digit())) {
                return Some(nums.join(","));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELF_LINE: &str = "pub const B0_PRE_CANDIDATE_RISC0_GUEST_ELF: &[u8] = include_bytes!(\"/t/x/riscv-guest/h/g/riscv32im-risc0-zkvm-elf/release/g.bin\");";
    const PATH_LINE: &str =
        "pub const B0_PRE_CANDIDATE_RISC0_GUEST_PATH: &str = \"/t/x/riscv-guest/h/g/release/g.bin\";";
    const ID_LINE: &str =
        "pub const B0_PRE_CANDIDATE_RISC0_GUEST_ID: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];";

    fn methods() -> String {
        format!("{ELF_LINE}\n{PATH_LINE}\n{ID_LINE}\n")
    }

    #[test]
    fn parses_single_elf_and_refuses_zero_or_many() {
        assert_eq!(
            parse_single_elf_include(&methods()),
            "/t/x/riscv-guest/h/g/riscv32im-risc0-zkvm-elf/release/g.bin"
        );
        let two = format!("{ELF_LINE}\n{ELF_LINE}\n");
        assert!(std::panic::catch_unwind(|| parse_single_elf_include(&two)).is_err());
        assert!(
            std::panic::catch_unwind(|| parse_single_elf_include("pub const X: u8 = 0;")).is_err()
        );
    }

    #[test]
    fn rewrite_makes_elf_out_dir_relative_and_path_sentinel() {
        let out = rewrite_methods(&methods());
        assert!(out.contains(&format!(
            "= include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{CANONICAL_GUEST_ELF_NAME}\"));"
        )));
        assert!(out.contains(&format!(
            "#[allow(dead_code)] pub const B0_PRE_CANDIDATE_RISC0_GUEST_PATH: &str = \"{CANONICAL_GUEST_PATH_SENTINEL}\";"
        )));
        assert!(!out.contains("/t/x/riscv-guest/"));
    }

    #[test]
    fn rewrite_refuses_when_no_elf_line() {
        assert!(std::panic::catch_unwind(|| rewrite_methods("pub const X: u8 = 0;\n")).is_err());
    }

    #[test]
    fn scan_catches_leaked_paths() {
        let forbidden = vec!["/t/x/riscv-guest/h".to_string(), "/t/out".to_string()];
        scan_no_leaks(&rewrite_methods(&methods()), &forbidden); // clean rewrite passes
        let leaky = "let p = \"/t/out/leak\";";
        assert!(std::panic::catch_unwind(|| scan_no_leaks(leaky, &forbidden)).is_err());
    }

    #[test]
    fn expected_root_is_target_slash_riscv_guest() {
        assert_eq!(
            expected_guest_root("/t/x/release/build/pkg-hash/out"),
            PathBuf::from("/t/x/riscv-guest")
        );
    }

    #[test]
    fn parses_image_id_or_none() {
        assert_eq!(
            parse_image_id(&methods()).as_deref(),
            Some("1,2,3,4,5,6,7,8")
        );
        assert_eq!(parse_image_id("no id here").as_deref(), None);
    }

    #[test]
    fn first_quoted_extracts_first_pair() {
        assert_eq!(first_quoted("a \"b\" c \"d\"").as_deref(), Some("b"));
        assert_eq!(first_quoted("no quotes"), None);
    }
}
