//! The exclusive lock of a real signer directory ([`DirLock`]), on Unix: one
//! guard at a time, in this process or across processes; released when the
//! holder is killed with SIGKILL; never a file of its own. The signer opened
//! over it with [`StdSignerDir`] is the store a node would use; the mirror
//! here is a synced file standing in for the node database. Keys, payloads
//! and values are synthetic.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::Signer as _;
use sumchain_finality_foundations::signer::{
    initialize_exclusive, DurableSigner, ExclusiveOwnership, SignPosition, SignRequest,
    SignerError, SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{
    floor_below_height, FileSignerStore, IoError, MirrorStore, SignerDir, StdSignerDir, STATE_FILE,
};
use sumchain_finality_foundations::signer_lock::DirLock;
use sumchain_finality_foundations::Digest;

mod common;
use common::{TestPolka, B3};

const CHAIN: u64 = 4242;
const GENESIS: Digest = [0x11; 32];
const SEED: [u8; 32] = [7u8; 32];
const A: Digest = [0xA1; 32];

const CHILD_DIR_ENV: &str = "SUMCHAIN_SIGNER_LOCK_CHILD_DIR";

struct EdKey(ed25519_dalek::SigningKey);
impl SigningKey for EdKey {
    fn key_id(&self) -> Digest {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.0.sign(payload).to_bytes().to_vec()
    }
}

fn key() -> EdKey {
    EdKey(ed25519_dalek::SigningKey::from_bytes(&SEED))
}

/// The mirror as a synced file beside the signer directory.
struct FileMirror(PathBuf);
impl MirrorStore for FileMirror {
    fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        match std::fs::read(&self.0) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(IoError(e.to_string())),
        }
    }
    fn write_synced(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&self.0).map_err(|e| IoError(e.to_string()))?;
        f.write_all(bytes).map_err(|e| IoError(e.to_string()))?;
        f.sync_all().map_err(|e| IoError(e.to_string()))
    }
}

type Store = FileSignerStore<StdSignerDir, FileMirror, B3>;

/// `<base>/finality` (the signer directory) and `<base>/mirror.bin`.
fn store(base: &Path) -> Store {
    FileSignerStore::new(
        StdSignerDir::new(base.join("finality")),
        FileMirror(base.join("mirror.bin")),
        B3,
        CHAIN,
        GENESIS,
    )
}

fn lock(base: &Path) -> DirLock {
    DirLock::new(base.join("finality"))
}

fn temp_base(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "sumchain-signer-lock-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(base.join("finality")).unwrap();
    base
}

fn prevote(payload: &str) -> SignRequest {
    SignRequest {
        position: SignPosition {
            height: 7,
            round: 0,
            step: Step::Prevote,
        },
        value: VoteValue::Block(A),
        payload: payload.as_bytes().to_vec(),
        justification: None,
    }
}

/// Every file under `dir` with its contents.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn a_second_guard_is_refused_in_the_same_process_until_the_first_drops() {
    let base = temp_base("same-process");
    let l = lock(&base);
    let guard = l.try_acquire().expect("the first guard");
    let refused = l.try_acquire().unwrap_err();
    assert!(refused.0.contains("another signer holds it"), "{refused}");
    // Another `DirLock` value for the same directory is the same lock.
    assert!(lock(&base).try_acquire().is_err());
    drop(guard);
    let again = l.try_acquire().expect("free once the guard is dropped");
    drop(again);
    std::fs::remove_dir_all(&base).unwrap();
}

/// The store's directory fsync opens and closes its own descriptor of the
/// directory. A POSIX record lock (`fcntl`) would be released by that close;
/// this lock is not.
#[test]
fn the_stores_directory_fsync_does_not_release_the_lock() {
    let base = temp_base("dir-sync");
    let l = lock(&base);
    let guard = l.try_acquire().unwrap();
    let mut dir = StdSignerDir::new(base.join("finality"));
    dir.write_new("x.tmp", b"x").unwrap();
    dir.sync_file("x.tmp").unwrap();
    dir.sync_dir().unwrap();
    dir.remove("x.tmp").unwrap();
    assert!(l.try_acquire().is_err(), "still held");
    drop(guard);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn locking_creates_nothing_and_never_creates_a_missing_directory() {
    let base = temp_base("nothing-created");
    let dir = base.join("finality");
    std::fs::write(dir.join("keep"), b"k").unwrap();
    let before = snapshot(&dir);
    let guard = lock(&base).try_acquire().unwrap();
    assert_eq!(snapshot(&dir), before, "no lock file while held");
    drop(guard);
    assert_eq!(snapshot(&dir), before, "and none after");

    let missing = base.join("absent");
    let refused = DirLock::new(missing.clone()).try_acquire().unwrap_err();
    assert!(refused.0.contains("cannot lock"), "{refused}");
    assert!(!missing.exists(), "the directory is never created");

    let file = base.join("a-file");
    std::fs::write(&file, b"f").unwrap();
    let refused = DirLock::new(file).try_acquire().unwrap_err();
    assert!(refused.0.contains("not a directory"), "{refused}");
    std::fs::remove_dir_all(&base).unwrap();
}

/// A real second process. The child opens the signer over the directory,
/// signs one prevote, records the released signature and parks holding the
/// lock. While it lives, this process cannot acquire the lock, initialize or
/// open, and the refusals write nothing. Once it is killed (SIGKILL: no
/// unwinding, no destructors), the lock is free, the identical request gets
/// the child's signature back and a different message at that position is
/// refused.
#[test]
fn another_process_holding_the_signer_refuses_this_one_until_it_is_killed() {
    let base = temp_base("two-processes");
    initialize_exclusive(
        &lock(&base),
        &mut store(&base),
        key().key_id(),
        floor_below_height(7),
    )
    .unwrap();
    let released = base.join("released.sig");

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "lock_holder_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_DIR_ENV, &base)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !released.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            panic!(
                "the child exited ({status}) before holding the signer:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(Instant::now() < deadline, "the child never signed");
        std::thread::sleep(Duration::from_millis(20));
    }
    let child_sig = std::fs::read(&released).unwrap();
    let before = (
        snapshot(&base.join("finality")),
        std::fs::read(base.join("mirror.bin")).unwrap(),
    );

    assert!(lock(&base).try_acquire().is_err(), "the lock is held");
    assert!(matches!(
        initialize_exclusive(&lock(&base), &mut store(&base), key().key_id(), None),
        Err(SignerError::OwnershipHeld(_))
    ));
    assert!(matches!(
        DurableSigner::open(&lock(&base), store(&base), key(), TestPolka, None),
        Err(SignerError::OwnershipHeld(_))
    ));
    assert_eq!(
        (
            snapshot(&base.join("finality")),
            std::fs::read(base.join("mirror.bin")).unwrap()
        ),
        before,
        "the refusals wrote nothing"
    );

    child.kill().expect("SIGKILL the child");
    assert!(!child.wait().unwrap().success(), "killed, not exited");

    let mut s = DurableSigner::open(&lock(&base), store(&base), key(), TestPolka, None)
        .expect("free after the holder is killed");
    assert_eq!(
        s.sign(&prevote("x")).unwrap(),
        child_sig,
        "the identical request gets the released signature back"
    );
    assert_eq!(
        s.sign(&prevote("y")).unwrap_err(),
        SignerError::Equivocation(prevote("y").position)
    );
    drop(s);
    assert!(base.join("finality").join(STATE_FILE).exists());
    std::fs::remove_dir_all(&base).unwrap();
}

/// The child half: inert unless started by the test above.
#[test]
fn lock_holder_child() {
    let Ok(base) = std::env::var(CHILD_DIR_ENV) else {
        return;
    };
    let base = PathBuf::from(base);
    let mut s = DurableSigner::open(&lock(&base), store(&base), key(), TestPolka, None).unwrap();
    let sig = s.sign(&prevote("x")).unwrap();
    // Released: announce it, then hold the signer (and its lock) until killed.
    let tmp = base.join("released.tmp");
    std::fs::write(&tmp, &sig).unwrap();
    std::fs::rename(&tmp, base.join("released.sig")).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
