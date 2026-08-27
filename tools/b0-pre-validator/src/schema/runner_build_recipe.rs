//! `RunnerBuildRecipeV1` — the RETAINED, independently-addressed canonical runner-build recipe, holding
//! the EXACT bytes both verifiers need to re-prove path-independence from scratch — never a shape claim.
//!
//! The runner SOURCE is materialized at the fixed ratified `canonical_build_path` (== [`CANON_TOOLING`],
//! `/b0/tooling`) and compiled THERE both times, so rustc's package `-Cmetadata`/StableCrateId (which
//! encodes the absolute source path and which `--remap-path-prefix` CANNOT neutralize) is universal and
//! the runner is byte-identical across the two genuinely-distinct ORIGINAL checkout roots. Those original
//! roots never reach the compiler; they are retained as provenance + leakage-refused.
//!
//! The compiler-visible CARGO_HOME is the SINGLE canonical [`CANON_CARGO`] (`/b0/cargo`) for BOTH builds
//! — materialized FRESH per build (removed fail-hard before + after), so a canonical PATH that is never
//! SHARED build state. It is canonical-BY-CONSTRUCTION and therefore NOT remapped: the SP1 nested
//! `sp1-core-executor-runner` build strips `CARGO_ENCODED_RUSTFLAGS`, so the only way its vendored-dep
//! source paths are path-independent is for the cargo home itself to be canonical. Only the per-build
//! target root is remapped — exactly ONE `--remap-path-prefix` arg (`<target> -> /b0/target`); retaining a
//! fake cargo-home remap (an identity map that no longer reflects the effective mapping) is refused.
//!
//! It retains the exact canonical build ARGV (`build --release --locked --offline --features real-backend
//! --manifest-path <manifest>`), the reproducibility-relevant ENV (BUILD_GIT_SHA / SOURCE_DATE_EPOCH /
//! B0_VENUE_EMBED), the manifest/artifact paths, the cargo identity, and for BOTH build A and build B the
//! exact `CARGO_ENCODED_RUSTFLAGS` bytes plus that build's original root / target root. Every derived hash
//! (effective encoded-rustflags digest, argv digest) is recomputed from the retained bytes at import —
//! never trusted. No structural recipe id may claim `--locked`/`--release`/`--features real-backend`
//! unless the retained argv proves it, which [`check_self_consistent`] enforces. Its domain-separated
//! [`hash`] is bound by `RunnerAttestationV1.runner_build_recipe_blake3`.

use crate::codec::{DecodeError, Reader, Writer};
use crate::enums::{Arch, Candidate};

pub const RUNNER_BUILD_RECIPE_SCHEMA_VERSION: u16 = 4;
pub const RUNNER_BUILD_RECIPE_KIND: &[u8; 32] = b"b0-final-runner-build-recipe-v4\0";
pub const RUNNER_BUILD_RECIPE_PREFIX: &[u8] = b"b0-final-runner-build-recipe/v4\0";

/// The fixed ratified canonical BUILD path — where the runner source is materialized + compiled (never a
/// host path), and the compiler-visible source root for BOTH build A and B. Also a permitted prefix.
pub const CANON_TOOLING: &str = "/b0/tooling";
/// The fixed compiler-visible CARGO_HOME — the literal canonical cargo home, materialized fresh per build
/// (canonical-by-construction; NOT a remap destination). Also a permitted prefix.
pub const CANON_CARGO: &str = "/b0/cargo";
/// The fixed remap destination for the per-build target root (never a host path). Also a permitted prefix.
pub const CANON_TARGET: &str = "/b0/target";
/// The fixed RISC0 guest-embed HOME, materialized fresh per build (canonical-by-construction, like
/// [`CANON_CARGO`]). double_build_runner requires exactly this path for a RISC0 real embed, so the guest
/// build legitimately touches it — a PERMITTED prefix for RISC0 ONLY (SP1 has no embedded guest home).
pub const CANON_GUESTHOME: &str = "/b0/guesthome";

/// The unit separator that would delimit multiple remaps inside `CARGO_ENCODED_RUSTFLAGS`. With the
/// canonical cargo home there is exactly ONE remap (the target), so a well-formed value carries no
/// separator; the constant is retained for the strict single-remap parse.
pub const UNIT_SEP: u8 = 0x1f;

/// The structural recipe-id domain (mirrors `lib.sh b0_runner_remap_recipe_id`). The preimage names the
/// RULE ("use the ratified per-arch toolchain"), never a toolchain digest, so it is byte-identical across
/// arches. It claims `--locked`; [`RunnerBuildRecipeV1::check_self_consistent`] proves that claim against
/// the retained argv.
pub const RUNNER_REMAP_RECIPE_DOMAIN: &str = "b0-final-runner-remap-recipe/v1";

/// The exact bytes of ONE build side (A or B): its DISTINCT original checkout root (provenance only —
/// never compiler-visible), its remapped target root, and the exact encoded rustflags. There is no
/// per-build cargo root: the compiler-visible cargo home is the shared canonical [`CANON_CARGO`]
/// (top-level `canonical_cargo_home`), materialized fresh per build and NOT remapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildSide {
    /// The build's original checkout root (materialized at the canonical build path; NOT remapped).
    pub original_root: String,
    pub target_from: String,
    /// Exact `CARGO_ENCODED_RUSTFLAGS` bytes (exactly one `--remap-path-prefix=FROM=TO` arg; the target).
    pub encoded_rustflags: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerBuildRecipeV1 {
    pub candidate: Candidate,
    pub arch: Arch,
    /// Cross-arch structural recipe id (BLAKE3 over the rule; recomputed + checked at import).
    pub recipe_id: [u8; 32],
    /// The exact canonical build argv (vector of arguments), retained verbatim.
    pub build_argv: Vec<String>,
    /// Reproducibility-relevant environment, ordered (BUILD_GIT_SHA / SOURCE_DATE_EPOCH / B0_VENUE_EMBED).
    pub build_env: Vec<(String, String)>,
    pub manifest_path: String,
    pub artifact_path: String,
    pub cargo_ident: String,
    /// "0" (stub embed) or "1" (real venue embed).
    pub b0_venue_embed: String,
    /// The ratified canonical build path both A and B were materialized + compiled at (== [`CANON_TOOLING`]).
    pub canonical_build_path: String,
    /// The literal canonical compiler-visible CARGO_HOME both A and B used (== [`CANON_CARGO`]);
    /// materialized fresh per build, canonical-by-construction, NOT remapped.
    pub canonical_cargo_home: String,
    pub build_a: BuildSide,
    pub build_b: BuildSide,
    pub measured_source_commit: String, // 40-hex
    pub tooling_commit: String,         // 40-hex
    pub tooling_pathset_blake3: String, // 64-hex
    pub per_arch_toolchain_identity: [u8; 32],
    pub protobuf_authority_sha256: [u8; 32],
    pub protobuf_authority_blake3: [u8; 32],
    pub wrapper_blake3: [u8; 32],
}

fn w_hexstr(w: &mut Writer, s: &str) {
    w.u8(s.len() as u8);
    w.bytes(s.as_bytes());
}
fn r_hexstr(r: &mut Reader, n: usize, ctx: &'static str) -> Result<String, DecodeError> {
    let len = r.read_u8(ctx)? as usize;
    if len != n {
        return Err(DecodeError::BadValue { ctx });
    }
    let b = r.read_bytes(len, ctx)?;
    if !b
        .iter()
        .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(String::from_utf8(b.to_vec()).expect("ascii-hex"))
}
/// Length-prefixed (u16) printable-ASCII string, max `max` bytes.
pub(crate) fn w_str(w: &mut Writer, s: &str) {
    w.u16(s.len() as u16);
    w.bytes(s.as_bytes());
}
pub(crate) fn r_str(r: &mut Reader, max: usize, ctx: &'static str) -> Result<String, DecodeError> {
    let len = r.read_u16(ctx)? as usize;
    if len > max {
        return Err(DecodeError::BadValue { ctx });
    }
    let b = r.read_bytes(len, ctx)?;
    if !b.iter().all(|&c| (0x20..=0x7e).contains(&c)) {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(String::from_utf8(b.to_vec()).expect("ascii"))
}
/// Length-prefixed (u32) raw byte blob (may contain non-printable bytes, e.g. the `\x1f` separators).
pub(crate) fn w_blob(w: &mut Writer, b: &[u8]) {
    w.u32(b.len() as u32);
    w.bytes(b);
}
pub(crate) fn r_blob(
    r: &mut Reader,
    max: usize,
    ctx: &'static str,
) -> Result<Vec<u8>, DecodeError> {
    let n = r.read_u32(ctx)? as usize;
    if n > max {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(r.read_bytes(n, ctx)?.to_vec())
}
fn w_vec_str(w: &mut Writer, v: &[String]) {
    w.u32(v.len() as u32);
    for s in v {
        w_str(w, s);
    }
}
fn r_vec_str(
    r: &mut Reader,
    maxcount: usize,
    maxstr: usize,
    ctx: &'static str,
) -> Result<Vec<String>, DecodeError> {
    let n = r.read_u32(ctx)? as usize;
    if n > maxcount {
        return Err(DecodeError::BadValue { ctx });
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(r_str(r, maxstr, ctx)?);
    }
    Ok(v)
}

impl BuildSide {
    fn encode(&self, w: &mut Writer) {
        w_str(w, &self.original_root);
        w_str(w, &self.target_from);
        w_blob(w, &self.encoded_rustflags);
    }
    fn decode(r: &mut Reader, ctx: &'static str) -> Result<Self, DecodeError> {
        Ok(Self {
            original_root: r_str(r, 4096, ctx)?,
            target_from: r_str(r, 4096, ctx)?,
            encoded_rustflags: r_blob(r, 65536, ctx)?,
        })
    }
    /// Parse the exact encoded rustflags into the SINGLE `(from, to)` remap, in argv order.
    /// Enforces: exactly ONE `--remap-path-prefix=FROM=TO` arg, no `\x1f` separator, no second remap
    /// (neither the source NOR the canonical cargo home is remapped — both canonical by construction).
    pub fn parse_one_remap(&self) -> Result<(String, String), String> {
        let parts: Vec<&[u8]> = self.encoded_rustflags.split(|&b| b == UNIT_SEP).collect();
        if parts.len() != 1 {
            return Err(format!(
                "encoded rustflags is not exactly one remap ({} unit-separated parts; the canonical \
                 cargo home is not remapped)",
                parts.len()
            ));
        }
        let s = std::str::from_utf8(parts[0]).map_err(|_| "remap arg is not UTF-8".to_string())?;
        let rest = s
            .strip_prefix("--remap-path-prefix=")
            .ok_or_else(|| format!("not a --remap-path-prefix arg: {s:?}"))?;
        let eq = rest
            .rfind('=')
            .ok_or_else(|| format!("remap arg has no FROM=TO: {s:?}"))?;
        Ok((rest[..eq].to_string(), rest[eq + 1..].to_string()))
    }
    /// The derived BLAKE3 of the exact encoded-rustflags bytes (convenience; recomputed from bytes).
    pub fn effective_encoded_rustflags_blake3(&self) -> [u8; 32] {
        *blake3::hash(&self.encoded_rustflags).as_bytes()
    }
}

impl RunnerBuildRecipeV1 {
    /// Recompute the cross-arch structural recipe id (arch/toolchain-free). Same preimage as
    /// `lib.sh b0_runner_remap_recipe_id`.
    pub fn compute_recipe_id(measured_source_commit: &str, wrapper_blake3: &[u8; 32]) -> [u8; 32] {
        use std::fmt::Write as _;
        let mut wh = String::with_capacity(64);
        for b in wrapper_blake3 {
            let _ = write!(wh, "{b:02x}");
        }
        let pre = format!(
            "{RUNNER_REMAP_RECIPE_DOMAIN}|build_at={CANON_TOOLING}|cargo_home={CANON_CARGO}(canonical-by-construction,fresh-per-build)|remap:target={CANON_TARGET}|encoded_rustflags=unit-separator-1-remap|flags=--locked|SOURCE_DATE_EPOCH=0|BUILD_GIT_SHA={measured_source_commit}|toolchain=ratified-per-arch(authority-record)|wrapper_blake3={wh}"
        );
        *blake3::hash(pre.as_bytes()).as_bytes()
    }

    /// Derived BLAKE3 of the retained argv (each arg `\0`-terminated), recomputed from the vector.
    pub fn build_argv_blake3(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for a in &self.build_argv {
            h.update(a.as_bytes());
            h.update(&[0]);
        }
        *h.finalize().as_bytes()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(RUNNER_BUILD_RECIPE_KIND);
        w.u16(RUNNER_BUILD_RECIPE_SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u8(self.arch.to_repr());
        w.bytes(&self.recipe_id);
        w_vec_str(&mut w, &self.build_argv);
        w.u32(self.build_env.len() as u32);
        for (k, v) in &self.build_env {
            w_str(&mut w, k);
            w_str(&mut w, v);
        }
        w_str(&mut w, &self.manifest_path);
        w_str(&mut w, &self.artifact_path);
        w_str(&mut w, &self.cargo_ident);
        w_str(&mut w, &self.b0_venue_embed);
        w_str(&mut w, &self.canonical_build_path);
        w_str(&mut w, &self.canonical_cargo_home);
        self.build_a.encode(&mut w);
        self.build_b.encode(&mut w);
        w_hexstr(&mut w, &self.measured_source_commit);
        w_hexstr(&mut w, &self.tooling_commit);
        w_hexstr(&mut w, &self.tooling_pathset_blake3);
        w.bytes(&self.per_arch_toolchain_identity);
        w.bytes(&self.protobuf_authority_sha256);
        w.bytes(&self.protobuf_authority_blake3);
        w.bytes(&self.wrapper_blake3);
        w.into_bytes()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(RUNNER_BUILD_RECIPE_PREFIX);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let kind = r.read_array::<32>("RunnerBuildRecipeV1.kind")?;
        if &kind != RUNNER_BUILD_RECIPE_KIND {
            return Err(DecodeError::BadTag {
                ctx: "RunnerBuildRecipeV1.kind",
            });
        }
        let sv = r.read_u16("RunnerBuildRecipeV1.schema_version")?;
        if sv != RUNNER_BUILD_RECIPE_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "RunnerBuildRecipeV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("RunnerBuildRecipeV1.candidate")?)?;
        let arch = Arch::from_repr(r.read_u8("RunnerBuildRecipeV1.arch")?)?;
        let recipe_id = r.read_array::<32>("RunnerBuildRecipeV1.recipe_id")?;
        let build_argv = r_vec_str(r, 64, 4096, "RunnerBuildRecipeV1.build_argv")?;
        let env_n = r.read_u32("RunnerBuildRecipeV1.build_env.count")? as usize;
        if env_n > 64 {
            return Err(DecodeError::BadValue {
                ctx: "RunnerBuildRecipeV1.build_env.count",
            });
        }
        let mut build_env = Vec::with_capacity(env_n);
        for _ in 0..env_n {
            let k = r_str(r, 256, "RunnerBuildRecipeV1.build_env.k")?;
            let v = r_str(r, 4096, "RunnerBuildRecipeV1.build_env.v")?;
            build_env.push((k, v));
        }
        let manifest_path = r_str(r, 4096, "RunnerBuildRecipeV1.manifest_path")?;
        let artifact_path = r_str(r, 4096, "RunnerBuildRecipeV1.artifact_path")?;
        let cargo_ident = r_str(r, 4096, "RunnerBuildRecipeV1.cargo_ident")?;
        let b0_venue_embed = r_str(r, 8, "RunnerBuildRecipeV1.b0_venue_embed")?;
        let canonical_build_path = r_str(r, 4096, "RunnerBuildRecipeV1.canonical_build_path")?;
        let canonical_cargo_home = r_str(r, 4096, "RunnerBuildRecipeV1.canonical_cargo_home")?;
        let build_a = BuildSide::decode(r, "RunnerBuildRecipeV1.build_a")?;
        let build_b = BuildSide::decode(r, "RunnerBuildRecipeV1.build_b")?;
        let measured_source_commit = r_hexstr(r, 40, "RunnerBuildRecipeV1.measured_source_commit")?;
        let tooling_commit = r_hexstr(r, 40, "RunnerBuildRecipeV1.tooling_commit")?;
        let tooling_pathset_blake3 = r_hexstr(r, 64, "RunnerBuildRecipeV1.tooling_pathset_blake3")?;
        let per_arch_toolchain_identity =
            r.read_array::<32>("RunnerBuildRecipeV1.per_arch_toolchain_identity")?;
        let protobuf_authority_sha256 =
            r.read_array::<32>("RunnerBuildRecipeV1.protobuf_authority_sha256")?;
        let protobuf_authority_blake3 =
            r.read_array::<32>("RunnerBuildRecipeV1.protobuf_authority_blake3")?;
        let wrapper_blake3 = r.read_array::<32>("RunnerBuildRecipeV1.wrapper_blake3")?;
        Ok(Self {
            candidate,
            arch,
            recipe_id,
            build_argv,
            build_env,
            manifest_path,
            artifact_path,
            cargo_ident,
            b0_venue_embed,
            canonical_build_path,
            canonical_cargo_home,
            build_a,
            build_b,
            measured_source_commit,
            tooling_commit,
            tooling_pathset_blake3,
            per_arch_toolchain_identity,
            protobuf_authority_sha256,
            protobuf_authority_blake3,
            wrapper_blake3,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("RunnerBuildRecipeV1")?;
        Ok(v)
    }

    /// The retained build argv MUST be EXACTLY the canonical typed command — not merely contain the
    /// required tokens. Shape (no duplicates, no extra features/subcommands/args, no alternate manifest):
    ///   `<cargo> [+<toolchain>] build --release --locked --offline --features real-backend --manifest-path <m>`
    /// where the leading tokens are exactly `cargo_ident.split_whitespace()` (a cargo executable and an
    /// optional `+toolchain`), and `<m>` is the retained `manifest_path`.
    fn check_argv(&self) -> Result<(), String> {
        let mut want: Vec<&str> = self.cargo_ident.split_whitespace().collect();
        match want.len() {
            1 => {}
            2 if want[1].starts_with('+') => {}
            2 => return Err("cargo_ident second token is not a `+toolchain`".into()),
            _ => return Err("cargo_ident must be `<cargo>` or `<cargo> +<toolchain>`".into()),
        }
        want.extend_from_slice(&[
            "build",
            "--release",
            "--locked",
            "--offline",
            "--features",
            "real-backend",
            "--manifest-path",
            self.manifest_path.as_str(),
        ]);
        let got: Vec<&str> = self.build_argv.iter().map(String::as_str).collect();
        if got != want {
            return Err(format!(
                "build argv is not the exact canonical command (got {got:?}, want {want:?})"
            ));
        }
        Ok(())
    }

    /// The retained build env MUST be EXACTLY the canonical, uniquely-keyed, ordered vector:
    ///   `[(BUILD_GIT_SHA, <measured_source_commit>), (SOURCE_DATE_EPOCH, "0"), (B0_VENUE_EMBED, <embed>)]`
    /// — rejecting a duplicate, omission, conflicting value, or any extra recipe-relevant variable, so
    /// the separately-stored environment can never disagree with the claimed recipe.
    fn check_env(&self) -> Result<(), String> {
        let want: [(&str, &str); 3] = [
            ("BUILD_GIT_SHA", self.measured_source_commit.as_str()),
            ("SOURCE_DATE_EPOCH", "0"),
            ("B0_VENUE_EMBED", self.b0_venue_embed.as_str()),
        ];
        if self.build_env.len() != want.len() {
            return Err(format!(
                "build_env must have exactly {} canonical entries (got {})",
                want.len(),
                self.build_env.len()
            ));
        }
        for (i, (k, v)) in want.iter().enumerate() {
            if self.build_env[i].0 != *k {
                return Err(format!(
                    "build_env[{i}] key `{}` != canonical `{k}`",
                    self.build_env[i].0
                ));
            }
            if self.build_env[i].1 != *v {
                return Err(format!(
                    "build_env `{k}` = `{}` != canonical `{v}`",
                    self.build_env[i].1
                ));
            }
        }
        Ok(())
    }

    /// A build side's encoded rustflags MUST decode to exactly the ONE canonical target remap for THAT
    /// side's target root (target->/b0/target), and no second remap. Neither the original root nor the
    /// canonical cargo home is remapped (both canonical by construction), but the original root must be
    /// distinct + non-overlapping from the target root.
    fn check_side(side: &BuildSide, which: &str) -> Result<(), String> {
        let (f0, t0) = side
            .parse_one_remap()
            .map_err(|e| format!("build {which} encoded rustflags: {e}"))?;
        if f0 != side.target_from || t0 != CANON_TARGET {
            return Err(format!(
                "build {which} target remap {f0}={t0} != {}={CANON_TARGET}",
                side.target_from
            ));
        }
        if side.original_root == side.target_from {
            return Err(format!(
                "build {which} roots not distinct: {}",
                side.original_root
            ));
        }
        if side
            .target_from
            .starts_with(&format!("{}/", side.original_root))
            || side
                .original_root
                .starts_with(&format!("{}/", side.target_from))
        {
            return Err(format!(
                "build {which} roots overlap: {} / {}",
                side.original_root, side.target_from
            ));
        }
        Ok(())
    }

    /// Fail-closed self-consistency over the RETAINED bytes: argv proves the flags; each side's exact
    /// encoded rustflags decode to the ONE canonical target remap (the canonical cargo home is NOT
    /// remapped); the canonical build path is the ratified /b0/tooling and the canonical cargo home is
    /// the ratified /b0/cargo; A and B expose GENUINELY DIFFERENT original checkout roots (the distinction
    /// the canonical-path build neutralizes); the structural recipe id recomputes.
    pub fn check_self_consistent(&self) -> Result<(), String> {
        if self.b0_venue_embed != "0" && self.b0_venue_embed != "1" {
            return Err("b0_venue_embed must be \"0\" or \"1\"".into());
        }
        self.check_argv()?;
        self.check_env()?;
        if self.canonical_build_path != CANON_TOOLING {
            return Err(format!(
                "canonical_build_path {} != ratified {CANON_TOOLING}",
                self.canonical_build_path
            ));
        }
        if self.canonical_cargo_home != CANON_CARGO {
            return Err(format!(
                "canonical_cargo_home {} != ratified {CANON_CARGO}",
                self.canonical_cargo_home
            ));
        }
        Self::check_side(&self.build_a, "A")?;
        Self::check_side(&self.build_b, "B")?;
        // Genuine distinction: A and B start from DIFFERENT original checkout roots (neither reaches the
        // compiler — both are materialized at canonical_build_path — so byte-identity is achievable).
        if self.build_a.original_root == self.build_b.original_root {
            return Err("build A and build B share the same original checkout root".into());
        }
        let rid = Self::compute_recipe_id(&self.measured_source_commit, &self.wrapper_blake3);
        if rid != self.recipe_id {
            return Err("recipe id != recomputed structural recipe id".into());
        }
        Ok(())
    }
}

/// A self-consistent sample recipe for cross-module tests (SP1/x86, embed stub).
#[cfg(test)]
pub(crate) fn tests_sample() -> RunnerBuildRecipeV1 {
    tests::sample()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(target: &str) -> Vec<u8> {
        format!("--remap-path-prefix={target}={CANON_TARGET}").into_bytes()
    }

    pub(crate) fn sample() -> RunnerBuildRecipeV1 {
        let msc = "5".repeat(40);
        let wrapper = [9u8; 32];
        RunnerBuildRecipeV1 {
            candidate: Candidate::Sp1,
            arch: Arch::X86_64,
            recipe_id: RunnerBuildRecipeV1::compute_recipe_id(&msc, &wrapper),
            build_argv: vec![
                "cargo".into(),
                "build".into(),
                "--release".into(),
                "--locked".into(),
                "--offline".into(),
                "--features".into(),
                "real-backend".into(),
                "--manifest-path".into(),
                "tools/b0-pre-measure-sp1/Cargo.toml".into(),
            ],
            build_env: vec![
                ("BUILD_GIT_SHA".into(), "5".repeat(40)),
                ("SOURCE_DATE_EPOCH".into(), "0".into()),
                ("B0_VENUE_EMBED".into(), "0".into()),
            ],
            manifest_path: "tools/b0-pre-measure-sp1/Cargo.toml".into(),
            artifact_path: "release/b0-pre-measure-sp1".into(),
            cargo_ident: "cargo".into(),
            b0_venue_embed: "0".into(),
            canonical_build_path: CANON_TOOLING.into(),
            canonical_cargo_home: CANON_CARGO.into(),
            build_a: BuildSide {
                original_root: "/b0-input/a/tooling".into(),
                target_from: "/b0-input/a/target".into(),
                encoded_rustflags: enc("/b0-input/a/target"),
            },
            build_b: BuildSide {
                original_root: "/b0-input/b/tooling".into(),
                target_from: "/b0-input/b/target".into(),
                encoded_rustflags: enc("/b0-input/b/target"),
            },
            measured_source_commit: msc,
            tooling_commit: "1".repeat(40),
            tooling_pathset_blake3: "7".repeat(64),
            per_arch_toolchain_identity: [3; 32],
            protobuf_authority_sha256: [4; 32],
            protobuf_authority_blake3: [5; 32],
            wrapper_blake3: wrapper,
        }
    }

    #[test]
    fn roundtrips_hash_domain_separated_self_consistent() {
        let a = sample();
        assert_eq!(RunnerBuildRecipeV1::decode_exact(&a.encode()).unwrap(), a);
        assert_ne!(a.hash(), *blake3::hash(&a.encode()).as_bytes());
        a.check_self_consistent().unwrap();
    }

    #[test]
    fn cross_arch_recipe_id_is_toolchain_free_and_identical() {
        let msc = "5".repeat(40);
        let w = [9u8; 32];
        let id = RunnerBuildRecipeV1::compute_recipe_id(&msc, &w);
        let mut sp1_arm = sample();
        sp1_arm.arch = Arch::Aarch64;
        sp1_arm.per_arch_toolchain_identity = [42; 32];
        let mut risc0_x86 = sample();
        risc0_x86.candidate = Candidate::Risc0;
        risc0_x86.per_arch_toolchain_identity = [7; 32];
        assert_eq!(sp1_arm.recipe_id, id);
        assert_eq!(risc0_x86.recipe_id, id);
    }

    #[test]
    fn missing_locked_and_missing_release_refused() {
        let mut a = sample();
        a.build_argv.retain(|x| x != "--locked");
        assert!(a.check_self_consistent().unwrap_err().contains("--locked"));
        let mut b = sample();
        b.build_argv.retain(|x| x != "--release");
        assert!(b.check_self_consistent().unwrap_err().contains("--release"));
    }

    #[test]
    fn side_target_root_not_matching_encoded_rustflags_refused() {
        let mut a = sample();
        a.build_a.target_from = "/b0-input/a/OTHER".into(); // encoded rustflags still says .../target
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("target remap"));
    }

    #[test]
    fn wrong_canonical_build_path_refused() {
        let mut a = sample();
        a.canonical_build_path = "/b0-input/a/tooling".into();
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("canonical_build_path"));
    }

    #[test]
    fn wrong_canonical_cargo_home_refused() {
        let mut a = sample();
        a.canonical_cargo_home = "/b0-input/a/cargo".into();
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("canonical_cargo_home"));
    }

    #[test]
    fn same_ab_original_root_refused() {
        let mut a = sample();
        a.build_b = a.build_a.clone();
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("same original checkout root"));
    }

    #[test]
    fn argv_extra_arg_refused() {
        // A token-presence check would accept this; the exact-shape check refuses a trailing extra arg.
        let mut a = sample();
        a.build_argv.push("--offline".into());
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("exact canonical command"));
        // A duplicated flag is likewise refused.
        let mut b = sample();
        b.build_argv.insert(3, "--locked".into());
        assert!(b
            .check_self_consistent()
            .unwrap_err()
            .contains("exact canonical command"));
    }

    // `--offline` is part of the exact canonical argv (the build IS offline). REMOVING it, or RELOCATING
    // it, is refused by the full-vector equality — the argv must retain exactly one `--offline` in the
    // canonical position.
    #[test]
    fn argv_missing_or_relocated_offline_refused() {
        // Remove --offline entirely.
        let mut a = sample();
        a.build_argv.retain(|x| x != "--offline");
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("exact canonical command"));
        // Relocate --offline to the end (a different position than the canonical one).
        let mut b = sample();
        b.build_argv.retain(|x| x != "--offline");
        b.build_argv.push("--offline".into());
        assert!(b
            .check_self_consistent()
            .unwrap_err()
            .contains("exact canonical command"));
        // A DUPLICATE --offline (two of them) is refused.
        let mut c = sample();
        c.build_argv.insert(4, "--offline".into());
        assert!(c
            .check_self_consistent()
            .unwrap_err()
            .contains("exact canonical command"));
    }

    #[test]
    fn env_conflict_omission_extra_refused() {
        // Wrong value (BUILD_GIT_SHA != measured source).
        let mut a = sample();
        a.build_env[0].1 = "9".repeat(40);
        assert!(a.check_self_consistent().unwrap_err().contains("build_env"));
        // Extra entry.
        let mut b = sample();
        b.build_env.push(("RUSTFLAGS".into(), "-Cx".into()));
        assert!(b.check_self_consistent().unwrap_err().contains("build_env"));
        // Omission / duplicate (drop SOURCE_DATE_EPOCH, duplicate BUILD_GIT_SHA -> still 3 but wrong key).
        let mut c = sample();
        c.build_env[1] = ("BUILD_GIT_SHA".into(), c.measured_source_commit.clone());
        assert!(c.check_self_consistent().unwrap_err().contains("build_env"));
    }

    #[test]
    fn embed_unset_refused() {
        let mut a = sample();
        a.b0_venue_embed = String::new(); // neither "0" nor "1"
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("b0_venue_embed"));
    }

    #[test]
    fn build_b_second_remap_refused() {
        // Build A valid; build B's encoded rustflags carries a SECOND remap (a fake cargo-home remap).
        let mut a = sample();
        let mut two = Vec::new();
        two.extend_from_slice(b"--remap-path-prefix=/b0-input/b/target=/b0/target");
        two.push(UNIT_SEP);
        two.extend_from_slice(b"--remap-path-prefix=/b0-input/b/cargo=/b0/cargo");
        a.build_b.encoded_rustflags = two;
        assert!(a
            .check_self_consistent()
            .unwrap_err()
            .contains("not exactly one remap"));
    }

    #[test]
    fn wrong_recipe_id_and_tamper_rejected() {
        let mut b = sample();
        b.recipe_id = [0; 32];
        assert!(b.check_self_consistent().is_err());
        let bytes = sample().encode();
        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            RunnerBuildRecipeV1::decode_exact(&bad),
            Err(DecodeError::BadTag { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            RunnerBuildRecipeV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}
