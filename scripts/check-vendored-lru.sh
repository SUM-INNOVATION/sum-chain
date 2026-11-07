#!/usr/bin/env bash
# Vendored `lru` 0.12.5 guard (RUSTSEC-2026-0253, RUSTSEC-2026-0002).
#
# Cargo.toml patches lru 0.12.5, which only libp2p-swarm and libp2p-identify
# 0.44.2 reach, to crates/third_party/lru-0.12.5: the crates.io crate with
# upstream's two fixes backported into src/lib.rs, each under a `// SUM-CHAIN`
# comment, and upstream's regressions added to its tests:
#   * LruCache::pop detaches the node before freeing it and dropping the key
#     (lru 0.18.2, jeromefroe/lru-rs#238, RUSTSEC-2026-0253);
#   * IterMut::next / next_back hand out the key as &K (lru 0.16.3,
#     jeromefroe/lru-rs#224, RUSTSEC-2026-0002).
# sumchain-state's lru 0.18.5 is not patched. A path crate has no Cargo.lock
# source or checksum, and neither `cargo audit` nor `cargo deny check
# advisories` matches RustSec advisories against it, so this script covers it,
# as scripts/check-vendored-memmap2.sh does for memmap2:
#
#   source       (default) Integrity. Downloads lru-0.12.5.crate from crates.io,
#                checks its sha256 against the pin below (the checksum Cargo.lock
#                carried before the patch), extracts it, and requires git's diff
#                of it against the vendored directory to be exactly the backport.
#   advisories   Monitoring. Writes a synthetic Cargo.lock declaring the crates.io
#                identity and runs `cargo audit --file` on it with the
#                repository's .cargo/audit.toml and `--deny warnings`. Any RustSec
#                advisory against lru 0.12.5 fails, except RUSTSEC-2026-0253 and
#                RUSTSEC-2026-0002, which the backport fixes and which are ignored
#                here only. Extra arguments go to cargo audit.
#   regressions  The backported regressions, run from a copy outside the
#                workspace: natively on the pinned toolchain, or with --miri
#                under Miri (MIRI_TOOLCHAIN, default the pinned nightly below),
#                which is what detects the aliasing and the use-after-free.
#                --without-fixes runs them instead on the crates.io source plus
#                only the regression tests, and fails unless Miri reports the
#                defects there: the tests still catch what they were added for.
#
# The source, advisories and the pin checks below run in every mode; each mode
# fails first if the pins drift from what is built: the vendored manifest is lru
# 0.12.5, the root Cargo.toml patches lru to it, and Cargo.lock resolves lru
# 0.12.5 to it (and to nothing from a registry) with no unused patch.
#
# Needs curl, tar, git and sha256sum (or shasum); `advisories` needs
# cargo-audit; `regressions --miri` needs MIRI_TOOLCHAIN with the miri and
# rust-src components. Writes only to a temp dir.
# Run locally:  bash scripts/check-vendored-lru.sh [source|advisories|regressions [--miri] [--without-fixes]]
set -euo pipefail
cd "$(dirname "$0")/.."

CRATE=lru
VERSION=0.12.5
SHA256=234cf4f4a04dc1f57e24b96cc0cd600cf2af460d4161ac5ecdd0af8e1f3b2a38
FIXED_ADVISORIES=(RUSTSEC-2026-0253 RUSTSEC-2026-0002)
REGRESSIONS=(tests::iter_mut_stacked_borrows_violation tests::iter_mut_rev_stacked_borrows_violation tests::test_pop_panicking_key_drop_keeps_list_consistent)
MIRI_TOOLCHAIN="${MIRI_TOOLCHAIN:-nightly-2026-10-23}"
REGISTRY="registry+https://github.com/rust-lang/crates.io-index"
VENDORED="crates/third_party/${CRATE}-${VERSION}"

fail() { echo "::error::vendored ${CRATE}: $1"; exit 1; }

mode="${1:-source}"
[ $# -eq 0 ] || shift
miri=""; without_fixes=""
case "$mode" in
  source) [ $# -eq 0 ] || fail "source takes no further arguments" ;;
  advisories) ;;
  regressions)
    for a in "$@"; do
      case "$a" in
        --miri) miri=1 ;;
        --without-fixes) without_fixes=1 ;;
        *) fail "regressions takes --miri and --without-fixes only" ;;
      esac
    done
    [ -z "$without_fixes" ] || [ -n "$miri" ] || fail "--without-fixes needs --miri: natively the defects are not detected"
    ;;
  *) echo "usage: $0 [source|advisories [cargo-audit args...]|regressions [--miri] [--without-fixes]]" >&2; exit 2 ;;
esac

# `key = value` from one [table] of a TOML file; prints nothing if absent.
toml_value() {
  awk -v t="[$2]" -v k="$3" '
    /^\[/ { in_t = ($0 == t); next }
    in_t && $1 == k && $2 == "=" { print; exit }' "$1"
}

# Every Cargo.lock [[package]] named lru at VERSION, as "name version source".
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
  fail "Cargo.lock lists an unused patch; if libp2p no longer resolves ${CRATE} ${VERSION}, remove its patch and directory"
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
    echo "# Synthetic, written by scripts/check-vendored-lru.sh: the crates.io"
    echo "# identity of ${VENDORED}."
    echo "version = 4"
    printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\n' \
      "$CRATE" "$VERSION" "$REGISTRY" "$SHA256"
  } > "$tmp/audit/Cargo.lock"
  echo "synthetic Cargo.lock:"
  sed 's/^/  /' "$tmp/audit/Cargo.lock"
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
  if [ -n "$without_fixes" ]; then
    # The crates.io source plus only the regression tests: the block from the first
    # backported test to the end of `mod tests`, inserted at the same place.
    fetch_upstream
    cp -R "$tmp/upstream" "$tmp/crate"
    awk '/^    \/\/ SUM-CHAIN: regression backported from lru 0.16.3/ { on = 1 }
         on && /^\/\/\/ Doctests for what should \*not\* compile/ { exit }
         on { print }' "$VENDORED/src/lib.rs" | sed '$d' | sed '$d' > "$tmp/tests.rs"
    [ -s "$tmp/tests.rs" ] || fail "could not extract the regression tests from $VENDORED/src/lib.rs"
    awk -v f="$tmp/tests.rs" '
      /^\/\/\/ Doctests for what should \*not\* compile/ && !done {
        # drop the closing brace of mod tests printed last, add the tests, close it again
        sub(/\n}\n*$/, "", buf); print buf; print ""; while ((getline l < f) > 0) print l; print "}"; print ""; buf = ""; done = 1
      }
      { buf = (buf == "" ? $0 : buf "\n" $0) }
      END { print buf }' "$tmp/crate/src/lib.rs" > "$tmp/lib.rs"
    mv "$tmp/lib.rs" "$tmp/crate/src/lib.rs"
    for t in "${REGRESSIONS[@]}"; do
      grep -q "fn ${t#tests::}()" "$tmp/crate/src/lib.rs" || fail "the unfixed copy lacks the regression ${t}"
    done
  else
    cp -R "$VENDORED" "$tmp/crate"
  fi
  pinned="$(toml_value rust-toolchain.toml toolchain channel | sed 's/.*= *"\(.*\)"/\1/')"
  [ -n "$pinned" ] || fail "no toolchain channel in rust-toolchain.toml"
  cd "$tmp/crate"
  if [ -z "$miri" ]; then
    out="$(RUSTUP_TOOLCHAIN="$pinned" cargo test --lib -- --exact "${REGRESSIONS[@]}" 2>&1)" || { printf '%s\n' "$out"; fail "the backported regressions failed natively"; }
    printf '%s\n' "$out" | grep -E '^test |^test result'
    printf '%s\n' "$out" | grep -q "test result: ok. ${#REGRESSIONS[@]} passed" || fail "expected ${#REGRESSIONS[@]} regressions to run and pass"
    echo "ok - ${#REGRESSIONS[@]} backported regressions pass natively (${pinned})"
    exit 0
  fi
  rc=0
  out="$(cargo "+${MIRI_TOOLCHAIN}" miri test --lib -- --exact "${REGRESSIONS[@]}" 2>&1)" || rc=$?
  if [ -z "$without_fixes" ]; then
    [ "$rc" -eq 0 ] || { printf '%s\n' "$out" | tail -60; fail "the backported regressions failed under Miri"; }
    printf '%s\n' "$out" | grep -q "test result: ok. ${#REGRESSIONS[@]} passed" || { printf '%s\n' "$out" | tail -30; fail "expected ${#REGRESSIONS[@]} regressions to run and pass under Miri"; }
    echo "ok - ${#REGRESSIONS[@]} backported regressions pass under Miri (${MIRI_TOOLCHAIN})"
    exit 0
  fi
  # Without the fixes Miri must stop on undefined behaviour in each regression.
  for t in "${REGRESSIONS[@]}"; do
    rc=0
    out="$(cargo "+${MIRI_TOOLCHAIN}" miri test --lib -- --exact "$t" 2>&1)" || rc=$?
    if [ "$rc" -eq 0 ] || ! printf '%s\n' "$out" | grep -q 'Undefined Behavior'; then
      printf '%s\n' "$out" | tail -30
      fail "without the fixes, Miri did not report undefined behaviour in ${t}"
    fi
    echo "ok - without the fixes, Miri reports undefined behaviour in ${t}: $(printf '%s\n' "$out" | grep -m1 -E 'error: Undefined Behavior' | cut -c1-140)"
  done
  exit 0
fi

# --- source -------------------------------------------------------------------
expected_diff() {
  cat <<'EOF'
diff --git a/upstream/src/lib.rs b/vendored/src/lib.rs
index 5ab978edb2eb0f61de411c3c6d104ba9646b3d3d..ef83783f8be4ceb91b3660667fe95f8b4f4b4512 100644
--- a/upstream/src/lib.rs
+++ b/vendored/src/lib.rs
@@ -1117,6 +1117,5 @@ impl<K: Hash + Eq, V, S: BuildHasher> LruCache<K, V, S> {
-                let mut old_node = unsafe {
-                    let mut old_node = *Box::from_raw(old_node.as_ptr());
-                    ptr::drop_in_place(old_node.key.as_mut_ptr());
-
-                    old_node
-                };
+                // SUM-CHAIN: backported from lru 0.18.2 (RUSTSEC-2026-0253): detach
+                // the node from the list BEFORE freeing it and dropping the key, so
+                // a key whose `Drop` panics cannot leave dangling list pointers.
+                let node_ptr: *mut LruEntry<K, V> = old_node.as_ptr();
+                self.detach(node_ptr);
@@ -1124 +1123,4 @@ impl<K: Hash + Eq, V, S: BuildHasher> LruCache<K, V, S> {
-                self.detach(&mut old_node);
+                let mut old_node = unsafe { *Box::from_raw(node_ptr) };
+                unsafe {
+                    ptr::drop_in_place(old_node.key.as_mut_ptr());
+                }
@@ -1636 +1638,3 @@ impl<'a, K, V> Iterator for IterMut<'a, K, V> {
-        let key = unsafe { &mut (*(*self.ptr).key.as_mut_ptr()) as &mut K };
+        // SUM-CHAIN: backported from lru 0.16.3 (RUSTSEC-2026-0002): the key is
+        // only ever handed out shared, so it is not reborrowed mutably.
+        let key = unsafe { &(*(*self.ptr).key.as_ptr()) as &K };
@@ -1660 +1664,2 @@ impl<'a, K, V> DoubleEndedIterator for IterMut<'a, K, V> {
-        let key = unsafe { &mut (*(*self.end).key.as_mut_ptr()) as &mut K };
+        // SUM-CHAIN: backported from lru 0.16.3 (RUSTSEC-2026-0002), as in `next`.
+        let key = unsafe { &(*(*self.end).key.as_ptr()) as &K };
@@ -2678,0 +2684,72 @@ mod tests {
+
+    // SUM-CHAIN: regression backported from lru 0.16.3 (jeromefroe/lru-rs#224,
+    // RUSTSEC-2026-0002). Run it under Miri: natively the aliasing is not detected.
+    #[test]
+    fn iter_mut_stacked_borrows_violation() {
+        let mut cache: LruCache<i32, i32> = LruCache::new(NonZeroUsize::new(3).unwrap());
+        cache.put(1, 10);
+        cache.put(2, 20);
+        cache.put(3, 30);
+
+        for (_k, v) in cache.iter_mut() {
+            *v *= 2;
+        }
+
+        assert_eq!(cache.get(&1), Some(&20));
+        assert_eq!(cache.get(&2), Some(&40));
+        assert_eq!(cache.get(&3), Some(&60));
+    }
+
+    // SUM-CHAIN: the same regression in the other direction, through
+    // `DoubleEndedIterator::next_back`, which the backport also changes.
+    #[test]
+    fn iter_mut_rev_stacked_borrows_violation() {
+        let mut cache: LruCache<i32, i32> = LruCache::new(NonZeroUsize::new(3).unwrap());
+        cache.put(1, 10);
+        cache.put(2, 20);
+        cache.put(3, 30);
+
+        for (_k, v) in cache.iter_mut().rev() {
+            *v *= 2;
+        }
+
+        assert_eq!(cache.get(&1), Some(&20));
+        assert_eq!(cache.get(&2), Some(&40));
+        assert_eq!(cache.get(&3), Some(&60));
+    }
+
+    // SUM-CHAIN: regression backported from lru 0.18.2 (jeromefroe/lru-rs#238,
+    // RUSTSEC-2026-0253): a key whose `Drop` panics inside `pop`, caught, then the
+    // cache is reused (insertions, an eviction, a lookup, a full iteration).
+    #[test]
+    fn test_pop_panicking_key_drop_keeps_list_consistent() {
+        use std::panic::{catch_unwind, AssertUnwindSafe};
+        use std::sync::atomic::{AtomicBool, Ordering};
+
+        static ARMED: AtomicBool = AtomicBool::new(false);
+
+        #[derive(PartialEq, Eq, Hash)]
+        struct PanicKey(u32);
+        impl Drop for PanicKey {
+            fn drop(&mut self) {
+                if ARMED.swap(false, Ordering::SeqCst) {
+                    panic!("PanicKey::drop");
+                }
+            }
+        }
+
+        let mut cache = LruCache::new(NonZeroUsize::new(4).unwrap());
+        cache.put(PanicKey(1), "a");
+        cache.put(PanicKey(2), "b");
+        cache.put(PanicKey(3), "c");
+
+        ARMED.store(true, Ordering::SeqCst);
+        let _ = catch_unwind(AssertUnwindSafe(|| {
+            cache.pop(&PanicKey(2));
+        }));
+
+        cache.put(PanicKey(4), "d");
+        cache.put(PanicKey(5), "e");
+        let _ = cache.get(&PanicKey(3));
+        for (_k, _v) in cache.iter() {}
+    }
EOF
}

fetch_upstream
cp -R "$VENDORED" "$tmp/vendored"
rc=0
# git's own diff, every option that shapes its output pinned, so the result is the
# same on every platform (GNU and BSD `diff -r` align changed lines differently).
# -U0 prints no context lines; --full-index pins both files' blob ids. Compared
# with trailing whitespace stripped, as the expected diff below is stored.
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
