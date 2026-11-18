#!/usr/bin/env bash
# Vendored `libp2p-gossipsub` 0.46.1 guard (RUSTSEC-2026-0534, -0535, -0536,
# -0537).
#
# Cargo.toml patches libp2p-gossipsub 0.46.1, which only sumchain-p2p uses, to
# crates/third_party/libp2p-gossipsub-0.46.1: the crates.io crate with
# upstream's fixes backported, each hunk under a `// SUM-CHAIN` comment, and a
# regression for each added to src/behaviour/tests.rs (upstream added none):
#   * BackoffStorage::update_backoff ignores a PRUNE backoff that overflows the
#     Instant (0.49.3, libp2p/rust-libp2p@84153a559bdb, RUSTSEC-2026-0535);
#   * a remote PRUNE backoff is capped at one hour, the backoff heartbeat uses
#     checked_add, and the other Instant arithmetic in the behaviour, peer
#     scoring and duplicate cache is checked or saturating (0.49.4,
#     libp2p/rust-libp2p@55e4a64630f6, RUSTSEC-2026-0537; 0.49.4's IDONTWANT
#     hunk has no counterpart in 0.46.1);
#   * a GRAFT no longer records its topics for the peer, and a GRAFT for a
#     topic the peer has not subscribed to is dropped (0.49.5's GRAFT handling,
#     libp2p/rust-libp2p@51ed5f00e1b0 / #6608, RUSTSEC-2026-0536);
#   * a PRUNE for a topic the node has not joined is ignored (0.50.1,
#     libp2p/rust-libp2p@9c647828abea / #6707, RUSTSEC-2026-0534).
# NOT taken from 0.49.5: its change of the Behaviour's default subscription
# filter to MaxCountSubscriptionFilter<AllowAllSubscriptionFilter> (2000 / 2000;
# 0.50.0 ships the same default with 100 / 100). sum-chain builds
# `gossipsub::Behaviour` with the default filter, so taking it would change a
# networking default; the vendored copy keeps AllowAllSubscriptionFilter, which
# sets no count limit. SUBSCRIBE-driven growth of a peer's topic set therefore
# stays as on the deployed release, bounded only by that filter (and in 0.46.1
# topic_peers keeps a topic's key after its peers leave). See
# docs/security/DEPENDENCY-AUDIT.md.
#
# A path crate has no Cargo.lock source or checksum, and neither `cargo audit`
# nor `cargo deny check advisories` matches RustSec advisories against it, so
# this script covers it, as scripts/check-vendored-lru.sh does for lru:
#
#   source       (default) Integrity. Downloads libp2p-gossipsub-0.46.1.crate
#                from crates.io, checks its sha256 against the pin below (the
#                checksum Cargo.lock carried before the patch), extracts it, and
#                requires git's diff of it against the vendored directory to be
#                exactly the backport and its regressions.
#   advisories   Monitoring. Writes a synthetic Cargo.lock declaring the crates.io
#                identity and runs `cargo audit --file` on it with the
#                repository's .cargo/audit.toml and `--deny warnings`. Any RustSec
#                advisory against libp2p-gossipsub 0.46.1 fails, except the four
#                IDs above, which the backport fixes and which are ignored here
#                only (a scoped exception, pending the owner's adoption; for
#                RUSTSEC-2026-0536 it covers the GRAFT fix, not 0.49.5's default
#                filter, as above). Extra arguments go to cargo audit.
#   regressions  Runs the crate's unit tests from a copy outside the workspace on
#                the pinned toolchain, with the repository's Cargo.lock as the
#                starting resolution and a target dir of its own: all of them,
#                which must pass and include the four regressions.
#                --without-fixes runs the four regressions instead on the
#                crates.io source plus only those tests, and fails unless each
#                of them fails there: the tests still catch what they were added
#                for. The unit tests use libp2p's unpublished quickcheck-ext,
#                which the published manifest drops; it is recreated beside the
#                copy from upstream's source (test harness only).
#
# Every mode first fails if the pins drift from what is built: the vendored
# manifest is libp2p-gossipsub 0.46.1, the root Cargo.toml patches
# libp2p-gossipsub to it, and Cargo.lock resolves libp2p-gossipsub 0.46.1 to it
# (and to nothing from a registry) with no unused patch.
#
# Needs curl, tar, git and sha256sum (or shasum); `advisories` needs
# cargo-audit; `regressions` needs cargo and network access for the crate's
# dev-dependencies. Writes only to a temp dir.
# Run locally:  bash scripts/check-vendored-gossipsub.sh [source|advisories|regressions [--without-fixes]]
set -euo pipefail
cd "$(dirname "$0")/.."

CRATE=libp2p-gossipsub
VERSION=0.46.1
SHA256=d665144a616dadebdc5fff186b1233488cdcd8bfb1223218ff084b6d052c94f7
FIXED_ADVISORIES=(RUSTSEC-2026-0534 RUSTSEC-2026-0535 RUSTSEC-2026-0536 RUSTSEC-2026-0537)
REGRESSIONS=(
  behaviour::tests::test_oversized_prune_backoff_does_not_panic
  behaviour::tests::test_prune_backoff_near_instant_max_does_not_panic_heartbeat
  behaviour::tests::test_graft_records_no_topics_and_needs_subscription
  behaviour::tests::test_prune_for_unjoined_topic_records_no_backoff
)
REGISTRY="registry+https://github.com/rust-lang/crates.io-index"
VENDORED="crates/third_party/${CRATE}-${VERSION}"
TESTS_RS="src/behaviour/tests.rs"
# The first line of the regressions block, which runs to the end of TESTS_RS.
REGRESSIONS_START='^// SUM-CHAIN: regression for RUSTSEC-'

fail() { echo "::error::vendored ${CRATE}: $1"; exit 1; }

mode="${1:-source}"
[ $# -eq 0 ] || shift
without_fixes=""
case "$mode" in
  source) [ $# -eq 0 ] || fail "source takes no further arguments" ;;
  advisories) ;;
  regressions)
    for a in "$@"; do
      case "$a" in
        --without-fixes) without_fixes=1 ;;
        *) fail "regressions takes --without-fixes only" ;;
      esac
    done
    ;;
  *) echo "usage: $0 [source|advisories [cargo-audit args...]|regressions [--without-fixes]]" >&2; exit 2 ;;
esac

# `key = value` from one [table] of a TOML file; prints nothing if absent.
toml_value() {
  awk -v t="[$2]" -v k="$3" '
    /^\[/ { in_t = ($0 == t); next }
    in_t && $1 == k && $2 == "=" { print; exit }' "$1"
}

# Every Cargo.lock [[package]] named CRATE at VERSION, as "name version source".
lock_entries() {
  awk '
    function flush() { if (name != "") print name, version, (source == "" ? "path" : source); name = version = source = "" }
    /^\[\[package\]\]$/ { flush(); pkg = 1; next }
    /^\[/ { flush(); pkg = 0; next }
    pkg && $1 == "name" { name = $3 }
    pkg && $1 == "version" { version = $3 }
    pkg && $1 == "source" { source = $3 }
    END { flush() }' Cargo.lock | tr -d '"' | awk -v n="$CRATE" -v v="$VERSION" '$1 == n && $2 == v'
}

# --- The pin matches what is built --------------------------------------------
[ -d "$VENDORED" ] || fail "$VENDORED is missing"
[ "$(toml_value "$VENDORED/Cargo.toml" package name)" = "name = \"${CRATE}\"" ] \
  || fail "$VENDORED/Cargo.toml is not package ${CRATE}"
[ "$(toml_value "$VENDORED/Cargo.toml" package version)" = "version = \"${VERSION}\"" ] \
  || fail "$VENDORED/Cargo.toml is not version ${VERSION}; update this script's pin with the vendored copy"
want="${CRATE} = { path = \"${VENDORED}\" }"
[ "$(toml_value Cargo.toml patch.crates-io "$CRATE")" = "$want" ] \
  || fail "Cargo.toml [patch.crates-io] does not point ${CRATE} ${VERSION} at ${VENDORED} (want: ${want})"
got="$(lock_entries)"
[ "$got" = "${CRATE} ${VERSION} path" ] \
  || fail "Cargo.lock must resolve ${CRATE} ${VERSION} to the vendored path crate only; it has: ${got:-no such entry}"
if grep -q '^\[\[patch.unused\]\]' Cargo.lock; then
  fail "Cargo.lock lists an unused patch; if the workspace no longer resolves ${CRATE} ${VERSION}, remove its patch and directory"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Download and verify the crates.io crate into $tmp/upstream.
fetch_upstream() {
  local url="https://static.crates.io/crates/${CRATE}/${CRATE}-${VERSION}.crate" got
  curl -fsSL --retry 3 "$url" -o "$tmp/dl.crate" || fail "could not download $url"
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/dl.crate" | cut -d' ' -f1)"
  else
    got="$(shasum -a 256 "$tmp/dl.crate" | cut -d' ' -f1)"
  fi
  [ "$got" = "$SHA256" ] || fail "downloaded ${CRATE} ${VERSION} crate sha256 is $got, pinned $SHA256"
  mkdir "$tmp/x"
  tar -xzf "$tmp/dl.crate" -C "$tmp/x"
  mv "$tmp/x/${CRATE}-${VERSION}" "$tmp/upstream"
}

# --- advisories ---------------------------------------------------------------
if [ "$mode" = advisories ]; then
  command -v cargo-audit >/dev/null 2>&1 || fail "cargo-audit is not installed"
  mkdir -p "$tmp/audit/.cargo"
  cp .cargo/audit.toml "$tmp/audit/.cargo/audit.toml"
  {
    echo "# Synthetic, written by scripts/check-vendored-gossipsub.sh: the crates.io"
    echo "# identity of ${VENDORED}."
    echo "version = 4"
    printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\n' \
      "$CRATE" "$VERSION" "$REGISTRY" "$SHA256"
  } > "$tmp/audit/Cargo.lock"
  echo "synthetic Cargo.lock:"
  sed 's/^/  /' "$tmp/audit/Cargo.lock"
  # Scoped exception, pending the owner's adoption: these four IDs only, only in
  # this check, for this verified copy. RUSTSEC-2026-0536 is fixed by the GRAFT
  # handling; 0.49.5's MaxCount default subscription filter is deliberately not
  # taken (it would change a networking default), so a peer's SUBSCRIBE-driven
  # topic set stays bounded only by AllowAllSubscriptionFilter, which sum-chain
  # uses today and which sets no count limit.
  ignores=()
  for id in "${FIXED_ADVISORIES[@]}"; do ignores+=(--ignore "$id"); done
  if ! (cd "$tmp/audit" && cargo audit --file Cargo.lock --deny warnings "${ignores[@]}" "$@"); then
    fail "RustSec reports an advisory other than ${FIXED_ADVISORIES[*]} against crates.io ${CRATE} ${VERSION}, which the vendored copy is apart from the backported fixes. Assess it against the vendored copy (docs/security/DEPENDENCY-AUDIT.md)."
  fi
  echo "ok - no RustSec advisory except ${FIXED_ADVISORIES[*]} (fixed by the backport) against crates.io ${CRATE} ${VERSION}"
  exit 0
fi

# --- regressions --------------------------------------------------------------
if [ "$mode" = regressions ]; then
  pinned="$(toml_value rust-toolchain.toml toolchain channel | sed 's/.*= *"\(.*\)"/\1/')"
  [ -n "$pinned" ] || fail "no toolchain channel in rust-toolchain.toml"
  if [ -n "$without_fixes" ]; then
    # The crates.io source plus only the regressions block, appended at the end
    # of the same test module.
    fetch_upstream
    cp -R "$tmp/upstream" "$tmp/crate"
    awk -v s="$REGRESSIONS_START" '$0 ~ s { on = 1 } on' "$VENDORED/$TESTS_RS" > "$tmp/regressions.rs"
    [ -s "$tmp/regressions.rs" ] || fail "could not extract the regressions from $VENDORED/$TESTS_RS"
    { echo; cat "$tmp/regressions.rs"; } >> "$tmp/crate/$TESTS_RS"
    for t in "${REGRESSIONS[@]}"; do
      grep -q "^fn ${t##*::}()" "$tmp/crate/$TESTS_RS" || fail "the unfixed copy lacks the regression ${t}"
    done
  else
    cp -R "$VENDORED" "$tmp/crate"
  fi
  # The unit tests import `quickcheck`, which upstream's workspace maps to its
  # unpublished misc/quickcheck-ext (publish = false; Unlicense/MIT). The
  # published manifest drops that dev-dependency, so the copy gets it back:
  # upstream's crate as of the commit 0.46.1 was released from
  # (b7914e407da34c99fb76dcc300b3d44b9af97fac), with its workspace lint table left out.
  mkdir -p "$tmp/quickcheck-ext/src"
  cat > "$tmp/quickcheck-ext/Cargo.toml" <<'TOML'
[package]
name = "quickcheck-ext"
version = "0.1.0"
edition = "2021"
publish = false
license = "Unlicense/MIT"

[dependencies]
quickcheck = "1"
num-traits = "0.2"
TOML
  cat > "$tmp/quickcheck-ext/src/lib.rs" <<'RS'
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use quickcheck::*;

use core::ops::Range;
use num_traits::sign::Unsigned;

pub trait GenRange {
    fn gen_range<T: Unsigned + Arbitrary + Copy>(&mut self, _range: Range<T>) -> T;

    fn gen_index(&mut self, ubound: usize) -> usize {
        if ubound <= (core::u32::MAX as usize) {
            self.gen_range(0..ubound as u32) as usize
        } else {
            self.gen_range(0..ubound)
        }
    }
}

impl GenRange for Gen {
    fn gen_range<T: Unsigned + Arbitrary + Copy>(&mut self, range: Range<T>) -> T {
        <T as Arbitrary>::arbitrary(self) % (range.end - range.start) + range.start
    }
}

pub trait SliceRandom {
    fn shuffle<T>(&mut self, arr: &mut [T]);
    fn choose_multiple<'a, T>(
        &mut self,
        arr: &'a [T],
        amount: usize,
    ) -> std::iter::Take<std::vec::IntoIter<&'a T>> {
        let mut v: Vec<&T> = arr.iter().collect();
        self.shuffle(&mut v);
        v.into_iter().take(amount)
    }
}

impl SliceRandom for Gen {
    fn shuffle<T>(&mut self, arr: &mut [T]) {
        for i in (1..arr.len()).rev() {
            // invariant: elements with index > i have been locked in place.
            arr.swap(i, self.gen_index(i + 1));
        }
    }
}
RS
  printf '\n[dev-dependencies.quickcheck]\npackage = "quickcheck-ext"\npath = "../quickcheck-ext"\n' >> "$tmp/crate/Cargo.toml"
  # The workspace's resolution as the starting point, so the crate's own
  # dependencies build at the versions sum-chain locks.
  cp Cargo.lock "$tmp/crate/Cargo.lock"
  # A target dir of its own: cargo gives every copy of this path crate the same
  # unit hash, so a shared target dir can run another copy's stale test binary.
  export CARGO_TARGET_DIR="$tmp/target"
  cd "$tmp/crate"
  RUSTUP_TOOLCHAIN="$pinned" cargo test --lib --no-run >/dev/null 2>"$tmp/build.log" \
    || { tail -40 "$tmp/build.log"; fail "the crate's unit tests do not build"; }
  if [ -z "$without_fixes" ]; then
    out="$(RUSTUP_TOOLCHAIN="$pinned" cargo test --lib 2>&1)" || { printf '%s\n' "$out" | grep -E '^test .*FAILED|panicked|^test result' | head -40; fail "the crate's unit tests failed"; }
    printf '%s\n' "$out" | grep -E '^test result'
    for t in "${REGRESSIONS[@]}"; do
      printf '%s\n' "$out" | grep -qx "test ${t} ... ok" || fail "the regression ${t} did not run and pass"
    done
    echo "ok - the crate's unit tests pass (${pinned}), including the ${#REGRESSIONS[@]} backported-fix regressions"
    exit 0
  fi
  # Without the fixes every regression must fail.
  for t in "${REGRESSIONS[@]}"; do
    rc=0
    out="$(RUSTUP_TOOLCHAIN="$pinned" cargo test --lib -- --exact "$t" 2>&1)" || rc=$?
    if [ "$rc" -eq 0 ] || ! printf '%s\n' "$out" | grep -qx "test ${t} ... FAILED"; then
      printf '%s\n' "$out" | tail -30
      fail "without the fixes, ${t} did not fail"
    fi
    echo "ok - without the fixes, ${t} fails: $(printf '%s\n' "$out" | grep -m1 -E "panicked at|^thread '" | cut -c1-160)"
  done
  exit 0
fi

# --- source -------------------------------------------------------------------
expected_diff() {
  cat <<'EOF'
diff --git a/upstream/src/backoff.rs b/vendored/src/backoff.rs
index b4a40b91a74f1c6ea00d24ce38ce960fda8253cf..2ef87639733585068e7028c4551e0ca3eb461e0a 100644
--- a/upstream/src/backoff.rs
+++ b/vendored/src/backoff.rs
@@ -75 +75,8 @@ impl BackoffStorage {
-        let instant = Instant::now() + time;
+        // SUM-CHAIN: backported from libp2p-gossipsub 0.49.3 (RUSTSEC-2026-0535,
+        // libp2p/rust-libp2p@84153a559bdb): a backoff that would overflow the
+        // Instant is ignored instead of panicking.
+        let Some(instant) = Instant::now().checked_add(time) else {
+            tracing::warn!("ignoring oversized prune backoff");
+            return;
+        };
+
@@ -155 +162,6 @@ impl BackoffStorage {
-                    Some(backoff_time) => backoff_time + slack > now,
+                    // SUM-CHAIN: backported from libp2p-gossipsub 0.49.4
+                    // (RUSTSEC-2026-0537, libp2p/rust-libp2p@55e4a64630f6).
+                    Some(backoff_time) => backoff_time
+                        .checked_add(slack)
+                        .map(|backoff| backoff > now)
+                        .unwrap_or(false),
diff --git a/upstream/src/behaviour/tests.rs b/vendored/src/behaviour/tests.rs
index 570cdf43f907d1d46038056a1d22b33414794031..3d10b55adf9eda8ff1ee1b57804d570f492d89dc 100644
--- a/upstream/src/behaviour/tests.rs
+++ b/vendored/src/behaviour/tests.rs
@@ -4227 +4227 @@ fn test_opportunistic_grafting() {
-        .to_subscribe(false)
+        .to_subscribe(true)
@@ -4532 +4532 @@ fn test_limit_number_of_message_ids_inside_ihave() {
-        .to_subscribe(false)
+        .to_subscribe(true)
@@ -5115,0 +5116,148 @@ fn test_graft_without_subscribe() {
+
+// SUM-CHAIN: regression for RUSTSEC-2026-0535, fixed by the backport from
+// libp2p-gossipsub 0.49.3. A PRUNE asking for a backoff of u64::MAX seconds, and
+// a backoff that overflows the Instant, must be ignored without a panic.
+#[test]
+fn test_oversized_prune_backoff_does_not_panic() {
+    let (mut gs, peers, topics) = inject_nodes1()
+        .peer_no(1)
+        .topics(vec!["test".into()])
+        .to_subscribe(true)
+        .create_network();
+
+    gs.handle_prune(
+        &peers[0],
+        vec![(topics[0].clone(), Vec::new(), Some(u64::MAX))],
+    );
+
+    let topic = TopicHash::from_raw("oversized");
+    let mut backoffs = BackoffStorage::new(&Duration::from_secs(60), Duration::from_secs(1), 1);
+    backoffs.update_backoff(&topic, &peers[0], Duration::MAX);
+    assert!(
+        backoffs.get_backoff_time(&topic, &peers[0]).is_none(),
+        "a backoff that overflows the Instant must not be stored"
+    );
+}
+
+// SUM-CHAIN: regression for RUSTSEC-2026-0537, fixed by the backport from
+// libp2p-gossipsub 0.49.4. A PRUNE backoff small enough to be stored, but close
+// enough to the largest Instant that adding the heartbeat's slack overflows,
+// must not panic the heartbeat; a backoff a peer asks for is capped at one hour.
+#[test]
+fn test_prune_backoff_near_instant_max_does_not_panic_heartbeat() {
+    // A 10 s slack (heartbeat_interval * backoff_slack) leaves a wide window of
+    // backoffs that fit the Instant but overflow once the slack is added.
+    let config = ConfigBuilder::default().backoff_slack(10).build().unwrap();
+    let (mut gs, peers, topics) = inject_nodes1()
+        .peer_no(1)
+        .topics(vec!["test".into()])
+        .to_subscribe(true)
+        .gs_config(config.clone())
+        .create_network();
+
+    // The largest whole-second Duration Instant::now() can still be advanced by.
+    let now = Instant::now();
+    let (mut lo, mut hi) = (0u64, u64::MAX);
+    while lo < hi {
+        let mid = lo + (hi - lo) / 2 + 1;
+        if now.checked_add(Duration::from_secs(mid)).is_some() {
+            lo = mid;
+        } else {
+            hi = mid - 1;
+        }
+    }
+    let backoff = lo - 5;
+
+    gs.handle_prune(
+        &peers[0],
+        vec![(topics[0].clone(), Vec::new(), Some(backoff))],
+    );
+
+    // One full cycle of the backoff slots visits the slot the backoff was put in.
+    let slots = config.prune_backoff().as_secs() / config.heartbeat_interval().as_secs()
+        + u64::from(config.backoff_slack())
+        + 1;
+    for _ in 0..2 * slots {
+        gs.heartbeat();
+    }
+
+    let stored = gs
+        .backoffs
+        .get_backoff_time(&topics[0], &peers[0])
+        .expect("the PRUNE backoff is recorded");
+    assert!(
+        stored <= Instant::now() + Duration::from_secs(3600),
+        "a remote PRUNE backoff must be capped at one hour"
+    );
+}
+
+// SUM-CHAIN: regression for RUSTSEC-2026-0536, fixed by the backport of the GRAFT
+// handling from libp2p-gossipsub 0.49.5. A GRAFT records no topics for the peer,
+// and a GRAFT for a topic the peer has not subscribed to does not add it to the
+// mesh.
+#[test]
+fn test_graft_records_no_topics_and_needs_subscription() {
+    let (mut gs, peers, topics) = inject_nodes1()
+        .peer_no(1)
+        .topics(vec!["test".into()])
+        .to_subscribe(false)
+        .create_network();
+
+    let unknown: Vec<TopicHash> = (0..100)
+        .map(|i| TopicHash::from_raw(format!("unknown-{i}")))
+        .collect();
+    gs.handle_graft(&peers[0], unknown.clone());
+    gs.handle_graft(&peers[0], topics.clone());
+
+    assert!(
+        gs.peer_topics
+            .get(&peers[0])
+            .map_or(true, |t| t.is_empty()),
+        "a GRAFT must not record topics for the peer"
+    );
+    for topic in &unknown {
+        assert!(
+            !gs.topic_peers.contains_key(topic),
+            "a GRAFT must not create topic_peers entries"
+        );
+    }
+    assert!(
+        !gs.mesh[&topics[0]].contains(&peers[0]),
+        "a GRAFT from a peer that has not subscribed must not add it to the mesh"
+    );
+}
+
+// SUM-CHAIN: regression for RUSTSEC-2026-0534, fixed by the backport from
+// libp2p-gossipsub 0.50.1. A PRUNE for a topic the node has not joined records no
+// backoff; a PRUNE for a joined topic still does.
+#[test]
+fn test_prune_for_unjoined_topic_records_no_backoff() {
+    let (mut gs, peers, topics) = inject_nodes1()
+        .peer_no(1)
+        .topics(vec!["test".into()])
+        .to_subscribe(true)
+        .create_network();
+
+    let unknown: Vec<TopicHash> = (0..100)
+        .map(|i| TopicHash::from_raw(format!("unknown-{i}")))
+        .collect();
+    gs.handle_prune(
+        &peers[0],
+        unknown
+            .iter()
+            .map(|topic| (topic.clone(), Vec::new(), Some(3600)))
+            .collect(),
+    );
+    for topic in &unknown {
+        assert!(
+            gs.backoffs.get_backoff_time(topic, &peers[0]).is_none(),
+            "a PRUNE for a topic the node has not joined must not record a backoff"
+        );
+    }
+
+    gs.handle_prune(&peers[0], vec![(topics[0].clone(), Vec::new(), Some(60))]);
+    assert!(
+        gs.backoffs.get_backoff_time(&topics[0], &peers[0]).is_some(),
+        "a PRUNE for a joined topic still records the backoff"
+    );
+}
diff --git a/upstream/src/behaviour.rs b/vendored/src/behaviour.rs
index 24a32de4cc7988bc73e4cc1a9a550cbd7e8ee366..571bf6c57c1548df304edf0636f13ca8fb2d85a2 100644
--- a/upstream/src/behaviour.rs
+++ b/vendored/src/behaviour.rs
@@ -73,0 +74,5 @@ mod tests;
+// SUM-CHAIN: backported from libp2p-gossipsub 0.49.4 (RUSTSEC-2026-0537,
+// libp2p/rust-libp2p@55e4a64630f6).
+/// Max allowed PRUNE backoff, 1 hour.
+const MAX_REMOTE_PRUNE_BACKOFF_SECONDS: u64 = 3600;
+
@@ -1260,5 +1265,8 @@ where
-                gossip_promises.add_promise(
-                    *peer_id,
-                    &iwant_ids_vec,
-                    Instant::now() + self.config.iwant_followup_time(),
-                );
+                // SUM-CHAIN: backported from libp2p-gossipsub 0.49.4 (RUSTSEC-2026-0537).
+                let followup_time = Instant::now()
+                    .checked_add(self.config.iwant_followup_time())
+                    .unwrap_or_else(|| {
+                        tracing::error!("Invalid iwant_followup_time using Instant::now()");
+                        Instant::now()
+                    });
+                gossip_promises.add_promise(*peer_id, &iwant_ids_vec, followup_time);
@@ -1330,12 +1338,3 @@ where
-        // For each topic, if a peer has grafted us, then we necessarily must be in their mesh
-        // and they must be subscribed to the topic. Ensure we have recorded the mapping.
-        for topic in &topics {
-            self.peer_topics
-                .entry(*peer_id)
-                .or_default()
-                .insert(topic.clone());
-            self.topic_peers
-                .entry(topic.clone())
-                .or_default()
-                .insert(*peer_id);
-        }
+        // SUM-CHAIN: backported from libp2p-gossipsub 0.49.5 (RUSTSEC-2026-0536,
+        // libp2p/rust-libp2p@51ed5f00e1b0, libp2p/rust-libp2p#6608): a GRAFT no longer
+        // records its topics in peer_topics / topic_peers.
@@ -1380,8 +1379,21 @@ where
-                                // check the flood cutoff
-                                // See: https://github.com/rust-lang/rust-clippy/issues/10061
-                                #[allow(unknown_lints, clippy::unchecked_duration_subtraction)]
-                                let flood_cutoff = (backoff_time
-                                    + self.config.graft_flood_threshold())
-                                    - self.config.prune_backoff();
-                                if flood_cutoff > now {
-                                    //extra penalty
+                                // SUM-CHAIN: backported from libp2p-gossipsub 0.49.4
+                                // (RUSTSEC-2026-0537).
+                                // Apply an extra graft-backoff penalty only when the peer is still far enough
+                                // from backoff expiry. This compares durations only,
+                                // avoiding Instant arithmetic and handling config edge cases safely:
+                                // if graft_flood_threshold >= prune_backoff,
+                                // any active backoff qualifies for the extra penalty.
+                                let apply_extra_penalty = match self
+                                    .config
+                                    .prune_backoff()
+                                    .checked_sub(self.config.graft_flood_threshold())
+                                {
+                                    Some(required_remaining) => {
+                                        let remaining_backoff =
+                                            backoff_time.saturating_duration_since(now);
+                                        remaining_backoff > required_remaining
+                                    }
+                                    // graft_flood_threshold >= prune_backoff
+                                    None => true,
+                                };
+                                if apply_extra_penalty {
@@ -1414,0 +1427,13 @@ where
+                    // SUM-CHAIN: backported from libp2p-gossipsub 0.49.5 (RUSTSEC-2026-0536).
+                    // Discard the GRAFT if the user hasn't subscribed to the topic.
+                    if !self
+                        .peer_topics
+                        .get(peer_id)
+                        .is_some_and(|topics| topics.contains(&topic_hash))
+                    {
+                        do_px = false;
+                        tracing::debug!(peer=%peer_id, topic=%topic_hash,
+                            "GRAFT: dropping unsubscribed topic from peer");
+                        continue;
+                    }
+
@@ -1522,4 +1547,7 @@ where
-            let time = if let Some(backoff) = backoff {
-                Duration::from_secs(backoff)
-            } else {
-                self.config.prune_backoff()
+            // SUM-CHAIN: backported from libp2p-gossipsub 0.49.4 (RUSTSEC-2026-0537): a
+            // backoff a peer asks for is capped at one hour.
+            let time = match backoff {
+                Some(backoff) => {
+                    Duration::from_secs(std::cmp::min(backoff, MAX_REMOTE_PRUNE_BACKOFF_SECONDS))
+                }
+                None => self.config.prune_backoff(),
@@ -1541,0 +1570,11 @@ where
+            // SUM-CHAIN: backported from libp2p-gossipsub 0.50.1 (RUSTSEC-2026-0534,
+            // libp2p/rust-libp2p@9c647828abea, libp2p/rust-libp2p#6707).
+            if !self.mesh.contains_key(&topic_hash) {
+                tracing::debug!(
+                    peer=%peer_id,
+                    topic=%topic_hash,
+                    "PRUNE: Received prune for unknown topic from peer"
+                );
+                continue;
+            }
+
@@ -2289 +2328,2 @@ where
-                if *last_pub_time + fanout_ttl < Instant::now() {
+                // SUM-CHAIN: backported from libp2p-gossipsub 0.49.4 (RUSTSEC-2026-0537).
+                if fanout_ttl < Instant::now().saturating_duration_since(*last_pub_time) {
diff --git a/upstream/src/peer_score.rs b/vendored/src/peer_score.rs
index b1ea9bfae9597a70056a148cf9514beb95d15a29..e5ec3af7ca9188229ee561084579061dce674fcf 100644
--- a/upstream/src/peer_score.rs
+++ b/vendored/src/peer_score.rs
@@ -518,3 +518,8 @@ impl PeerScore {
-            peer_stats.status = ConnectionStatus::Disconnected {
-                expire: Instant::now() + self.params.retain_score,
-            };
+            // SUM-CHAIN: backported from libp2p-gossipsub 0.49.4 (RUSTSEC-2026-0537).
+            let expire = Instant::now()
+                .checked_add(self.params.retain_score)
+                .unwrap_or_else(|| {
+                    tracing::error!("invalid retain_score value, using Instant::now()");
+                    Instant::now()
+                });
+            peer_stats.status = ConnectionStatus::Disconnected { expire };
diff --git a/upstream/src/time_cache.rs b/vendored/src/time_cache.rs
index 89fd4afee099a5c391b82711beb88cccc317f24c..f03a0ad8ea5311fa5ce1ed7eec4e27ed89d9c997 100644
--- a/upstream/src/time_cache.rs
+++ b/vendored/src/time_cache.rs
@@ -138,5 +138,12 @@ where
-            Vacant(entry) => Entry::Vacant(VacantEntry {
-                expiration: now + self.ttl,
-                entry,
-                list: &mut self.list,
-            }),
+            // SUM-CHAIN: backported from libp2p-gossipsub 0.49.4 (RUSTSEC-2026-0537).
+            Vacant(entry) => {
+                let expiration = now.checked_add(self.ttl).unwrap_or_else(|| {
+                    tracing::error!("invalid time cache ttl");
+                    now
+                });
+                Entry::Vacant(VacantEntry {
+                    expiration,
+                    entry,
+                    list: &mut self.list,
+                })
+            }
EOF
}

fetch_upstream
cp -R "$VENDORED" "$tmp/vendored"
rc=0
# git's own diff, every option that shapes its output pinned, so the result is the
# same on every platform (GNU and BSD `diff -r` align changed lines differently).
# -U0 prints no context lines; --full-index pins both files' blob ids. Compared
# with trailing whitespace stripped, as the expected diff above is stored.
raw="$(cd "$tmp" && git -c core.quotepath=false -c diff.noprefix=false -c diff.mnemonicPrefix=false \
  -c diff.renames=false -c diff.algorithm=myers -c diff.indentHeuristic=true -c color.ui=never \
  diff --no-index --no-color --no-ext-diff --no-textconv --full-index -U0 upstream vendored)" || rc=$?
[ "$rc" -le 1 ] || fail "git diff --no-index failed (exit $rc)"
actual="$(printf '%s\n' "$raw" | sed 's/[[:space:]]*$//')"
expected="$(expected_diff)"
if [ "$actual" != "$expected" ]; then
  echo "expected:"; printf '%s\n' "$expected"
  echo "actual:"; printf '%s\n' "$actual"
  fail "$VENDORED differs from the crates.io crate by more than the backported fixes and their regressions"
fi
echo "ok - $VENDORED is crates.io ${CRATE} ${VERSION} (sha256 $SHA256) except for the backported fixes and their regressions"
