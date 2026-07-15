NON_AUTHORITATIVE_HOST_PROBE
environment: macOS-arm64 (wrong execution environment)
NOT_FOR_CANDIDATE_DEP_LOCK_HASH
NOT_FOR_B0_PRE_FINALIZATION
purpose: early resolution/anomaly signal only; not reproducible, not authoritative, not container-derived
policy: prerelease findings below are RECORDED for the venue audit, not a verdict. The
        stable-only rule binds the selected candidate release (sp1 6.3.1 / risc0 3.0.5 /
        3.0.4 / 2.2.2); the transitive graph is subject to the security/source/reproducibility
        gates. See VENUE.md 'Version / audit policy'.

== candidate: sp1 ==
resolve: OK (host, non-authoritative)
resolved proof-stack crate versions (direct pins):
  "sp1-build"	"6.3.1"
  "sp1-sdk"	"6.3.1"
  "sp1-verifier"	"6.3.1"
  "sp1-zkvm"	"6.3.1"
prerelease crates in graph: "p3-air" "p3-baby-bear" "p3-bn254-fr" "p3-challenger" "p3-commit" "p3-dft" "p3-field" "p3-fri" "p3-interpolation" "p3-keccak-air" "p3-koala-bear" "p3-matrix" "p3-maybe-rayon" "p3-mds" "p3-merkle-tree" "p3-poseidon2" "p3-symmetric" "p3-uni-stark" "p3-util" 
git-sourced dependencies: 0
duplicate proof-stack versions: none detected

== candidate: risc0 ==
resolve: OK (host, non-authoritative)
resolved proof-stack crate versions (direct pins):
  "risc0-build"	"3.0.5"
  "risc0-groth16"	"3.0.4"
  "risc0-zkvm"	"3.0.5"
  "risc0-zkvm-platform"	"2.2.2"
prerelease crates in graph: none
git-sourced dependencies: 0
duplicate proof-stack versions: none detected

reminder: authoritative locks + candidate_dep_lock_hash come ONLY from the container venue.
temp probe workspace removed.
