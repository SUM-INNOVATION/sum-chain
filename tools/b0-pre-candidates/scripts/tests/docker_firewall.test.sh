#!/usr/bin/env bash
# Contract + negatives test for the Docker invocation FIREWALL (docker_firewall.sh). Uses a SMART
# STUB "real docker" (responds to image/manifest inspect + echoes the rewritten `run` argv) so the
# authorized-grammar POSITIVE path and the security NEGATIVES are exercised without a real daemon.
# The end-to-end positive path is additionally proven by the two genuine sandboxed proofs on the
# venue; this test locks in the refusal + rewrite behavior.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FW="$HERE/../docker_firewall.sh"
fails=0
ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/cstore/circuit" "$WORK/proof"
printf 'pk' > "$WORK/cstore/circuit/groth16_pk.bin"
printf 'WITNESS' > "$WORK/proof/witness"
printf 'PROOF'   > "$WORK/proof/pf"
: > "$WORK/proof/out"

SP1_MAN="sha256:be8555f1ad90870acd8c6ec7fd3ba0b1a2133ea9cddf25e130665aa651129e54"
SP1_CFG="sha256:ceb60d80f46cd8e5869abd778f26dc34c4f3bab205f3d1d5275e532121cced4e"
SP1_IMG="ghcr.io/succinctlabs/sp1-gnark@$SP1_MAN"

# Smart stub docker: image inspect -> ok; manifest inspect -> JSON with the pinned config digest;
# run -> print the full argv it received (so we can assert the injected sandbox). --version/info ok.
cat > "$WORK/docker" <<STUB
#!/usr/bin/env bash
case "\$1" in
  --version) echo "Docker version 0.0 (stub)"; exit 0 ;;
  info) exit 0 ;;
  image) shift; [ "\$1" = inspect ] && { case "\$*" in *--format*) echo "$SP1_MAN" ;; esac; exit 0; } ;;
  manifest) shift; [ "\$1" = inspect ] && { echo '{ "config": {"digest": "$SP1_CFG"}, "layers": [{"digest":"sha256:aaaa"}] }'; exit 0; } ;;
  run) shift; printf 'RUN_ARGV:'; printf ' %s' "\$@"; printf '\n'; exit 0 ;;
esac
exit 9
STUB
chmod +x "$WORK/docker"

export B0PRE_REAL_DOCKER="$WORK/docker" B0PRE_FIREWALL_ATTEST="$WORK/attest.jsonl" \
       B0PRE_PROOF_DIR="$WORK/proof" B0PRE_CONTENT_STORE="$WORK/cstore"
runfw() { bash "$FW" "$@" >"$WORK/o" 2>"$WORK/e"; echo "$?"; }
refuses() { local rc; rc="$(runfw "$@")"; [ "$rc" = 97 ] && grep -q FIREWALL-REFUSED "$WORK/e"; }

# The POSITIVE (accepted) paths RECONCILE OCI identity, which fails closed off native x86_64 (the
# terminal Groth16 backends are linux/amd64 only). A reconcile failure now correctly BLOCKS the run
# (the refuse propagates out of the command-substitution subshell), so the accept-path assertions
# only hold on x86_64. Off x86_64 we assert instead that the firewall REFUSES at the arch gate — the
# refusal negatives below are arch-independent and always run.
if [ "$(uname -m)" = "x86_64" ]; then
  # ---- POSITIVE: authorized SP1 prove grammar -> sandbox injected, image replaced by digest ----
  rc="$(runfw run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witness":/witness -v "$WORK/proof/out":/output "$SP1_IMG" prove --system groth16 /circuit /witness /output)"
  argv="$(grep '^RUN_ARGV:' "$WORK/o")"
  [ "$rc" = 0 ] && ok "SP1 prove grammar accepted" || fail "SP1 prove grammar rejected (rc=$rc): $(head -1 "$WORK/e")"
  for flag in "--pull never" "--network none" "--read-only" "--cap-drop ALL" "--security-opt no-new-privileges"; do
    printf '%s' "$argv" | grep -Fq -- "$flag" && ok "prove injects $flag" || fail "prove missing $flag"
  done
  printf '%s' "$argv" | grep -Fq "target=/circuit,readonly" && ok "prove circuit read-only" || fail "prove circuit not RO"
  printf '%s' "$argv" | grep -Fq "$SP1_MAN" && ok "prove uses pinned manifest digest" || fail "prove image not digest-pinned"
  # canonical witness must NOT be the mounted source (a COPY is)
  printf '%s' "$argv" | grep -Fq "source=$WORK/proof/witness,target=/witness" && fail "canonical witness was mounted (must be a copy)" || ok "canonical witness NOT mounted (copy adapter)"

  # ---- NEGATIVE (regression): SP1 OUTPUT mount OUTSIDE the per-proof root is REFUSED. This is the
  #      class that failed the burn-in: the gnark backend wrote to /tmp (TMPDIR unset), so the mount
  #      escaped $B0PRE_PROOF_DIR. measure_fragment.sh + the Rust runner now confine TMPDIR under the
  #      per-proof root; here we prove the firewall is the backstop that refuses an escaped mount. ----
  mkdir -p "$WORK/escape"; : > "$WORK/escape/out"
  if refuses run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witness":/witness -v "$WORK/escape/out":/output "$SP1_IMG" prove --system groth16 /circuit /witness /output \
     && grep -q "not under per-proof root" "$WORK/e"; then
    ok "SP1 output mount outside per-proof root refused"
  else
    fail "SP1 output mount outside per-proof root NOT refused (firewall backstop missing)"
  fi

  # ---- POSITIVE: authorized SP1 verify grammar ----
  rc="$(runfw run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/pf":/proof -v "$WORK/proof/out":/output "$SP1_IMG" verify --system groth16 --data-dir /circuit --proof-path /proof --vkey-hash 12 --committed-values-digest 34 --exit-code 0 --proof-nonce 0 --vk-root 56 --output-path /output)"
  [ "$rc" = 0 ] && ok "SP1 verify grammar accepted" || fail "SP1 verify grammar rejected (rc=$rc): $(head -1 "$WORK/e")"
else
  # Off x86_64: reconciliation must FAIL CLOSED (never silently run an unreconciled backend).
  refuses run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witness":/witness -v "$WORK/proof/out":/output "$SP1_IMG" prove --system groth16 /circuit /witness /output \
    && ok "SP1 prove refused off x86_64 (reconciliation fails closed, not silently run)" \
    || fail "SP1 prove NOT refused off x86_64 (unreconciled backend would run)"
fi

# ---- NEGATIVES ----
refuses ps                                                                        && ok "unknown subcommand refused"         || fail "unknown subcommand accepted"
refuses run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witness":/witness -v "$WORK/proof/out":/output evil:latest prove --system groth16 /circuit /witness /output && ok "unknown image refused" || fail "unknown image accepted"
refuses run --rm --privileged -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witness":/witness -v "$WORK/proof/out":/output "$SP1_IMG" prove --system groth16 /circuit /witness /output && ok "--privileged refused" || fail "--privileged accepted"
refuses run --rm --cap-add SYS_ADMIN -v "$WORK/cstore/circuit":/circuit "$SP1_IMG" prove && ok "--cap-add refused" || fail "--cap-add accepted"
refuses run --rm --device /dev/kvm -v "$WORK/cstore/circuit":/circuit "$SP1_IMG" prove && ok "--device refused" || fail "--device accepted"
refuses run --rm --network host -v "$WORK/cstore/circuit":/circuit "$SP1_IMG" prove && ok "--network host refused" || fail "--network host accepted"
refuses run --rm -e SECRET=1 -v "$WORK/cstore/circuit":/circuit "$SP1_IMG" prove && ok "-e env refused" || fail "-e env accepted"
refuses run --rm --entrypoint sh -v "$WORK/cstore/circuit":/circuit "$SP1_IMG" && ok "--entrypoint override refused" || fail "--entrypoint accepted"
refuses run --rm -v /var/run/docker.sock:/s -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witness":/witness -v "$WORK/proof/out":/output "$SP1_IMG" prove --system groth16 /circuit /witness /output && ok "docker-socket mount refused" || fail "socket mount accepted"
# circuit outside the content store (path escape)
refuses run --rm -v /etc:/circuit -v "$WORK/proof/witness":/witness -v "$WORK/proof/out":/output "$SP1_IMG" prove --system groth16 /circuit /witness /output && ok "circuit outside content store refused" || fail "circuit escape accepted"
# witness symlink
ln -sf /etc/passwd "$WORK/proof/witlink"
refuses run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witlink":/witness -v "$WORK/proof/out":/output "$SP1_IMG" prove --system groth16 /circuit /witness /output && ok "witness symlink refused" || fail "witness symlink accepted"
# malformed SP1 argv + verify numeric validation
refuses run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/witness":/witness -v "$WORK/proof/out":/output "$SP1_IMG" build --system groth16 /circuit && ok "SP1 non-prove/verify subcommand refused" || fail "SP1 build accepted"
refuses run --rm -v "$WORK/cstore/circuit":/circuit -v "$WORK/proof/pf":/proof -v "$WORK/proof/out":/output "$SP1_IMG" verify --system groth16 --data-dir /circuit --proof-path /proof --vkey-hash BAD --committed-values-digest 1 --exit-code 0 --proof-nonce 0 --vk-root 1 --output-path /output && ok "SP1 verify non-numeric arg refused" || fail "verify non-numeric accepted"
# RISC0 extra container args
refuses run --rm -v "$WORK/proof":/mnt risczero/risc0-groth16-prover:v2025-04-03.1 EXTRA && ok "RISC0 extra container args refused" || fail "RISC0 extra args accepted"
# recursion guard
B0PRE_REAL_DOCKER="$FW" bash "$FW" run --rm >/dev/null 2>"$WORK/e2"; grep -q "FIREWALL-REFUSED" "$WORK/e2" && ok "recursion guard (real==firewall) refused" || fail "recursion guard missed"

echo
if [ "$fails" -eq 0 ]; then echo "docker firewall: ALL PASS"; exit 0
else echo "docker firewall: $fails FAILED"; exit 1; fi
