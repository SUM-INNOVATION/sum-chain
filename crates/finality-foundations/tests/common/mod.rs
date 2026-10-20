//! Shared test doubles for the signer-persistence tests: a disk model with
//! volatile and durable state and per-operation fault injection, a BLAKE3
//! hasher, an in-memory ownership lock and a polka verifier that accepts only
//! synthetic evidence.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use sumchain_finality_foundations::signer::{
    Certified, ExclusiveOwnership, OwnershipError, PolkaVerifier,
};
use sumchain_finality_foundations::signer_file::{IoError, MirrorStore, SignerDir, StateHasher};
use sumchain_finality_foundations::Digest;

// ── simulated disk ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    WriteNew,
    SyncFile,
    Rename,
    SyncDir,
    Remove,
    Mirror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The operation fails and has no effect; the process keeps running.
    Error,
    /// The operation takes effect, then reports failure.
    EffectThenError,
    /// The process dies before the operation.
    CrashBefore,
    /// The operation takes effect (not yet durable), then the process dies.
    CrashAfter,
    /// As `CrashAfter`, and the file system happened to persist the directory
    /// entries too (as some file systems do on their own).
    CrashAfterKeepDir,
}

pub const MODES: [Mode; 5] = [
    Mode::Error,
    Mode::EffectThenError,
    Mode::CrashBefore,
    Mode::CrashAfter,
    Mode::CrashAfterKeepDir,
];

#[derive(Clone, Default)]
pub struct Inode {
    pub vol: Vec<u8>,
    pub dur: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct Model {
    pub inodes: Vec<Inode>,
    pub dir_vol: BTreeMap<String, usize>,
    pub dir_dur: BTreeMap<String, usize>,
    pub mirror_vol: Option<Vec<u8>>,
    pub mirror_dur: Option<Vec<u8>>,
    pub dead: bool,
    pub plan: Option<(usize, Mode)>,
    pub ops: usize,
    pub log: Vec<Op>,
}

impl Model {
    fn step(
        &mut self,
        op: Op,
        effect: impl FnOnce(&mut Model) -> Result<(), IoError>,
    ) -> Result<(), IoError> {
        if self.dead {
            return Err(IoError("process crashed".into()));
        }
        let idx = self.ops;
        self.ops += 1;
        self.log.push(op);
        match self.plan {
            Some((at, mode)) if at == idx => match mode {
                Mode::Error => Err(IoError(format!("injected error at {op:?}"))),
                Mode::EffectThenError => {
                    effect(self)?;
                    Err(IoError(format!("injected error after {op:?}")))
                }
                Mode::CrashBefore => {
                    self.dead = true;
                    Err(IoError(format!("crash before {op:?}")))
                }
                Mode::CrashAfter => {
                    effect(self)?;
                    self.dead = true;
                    Err(IoError(format!("crash after {op:?}")))
                }
                Mode::CrashAfterKeepDir => {
                    effect(self)?;
                    self.dir_dur = self.dir_vol.clone();
                    self.dead = true;
                    Err(IoError(format!("crash after {op:?}")))
                }
            },
            _ => effect(self),
        }
    }

    /// Power loss: everything not synced is gone.
    pub fn reboot(&mut self) {
        self.dir_vol = self.dir_dur.clone();
        for i in &mut self.inodes {
            i.vol = i.dur.clone();
        }
        self.mirror_vol = self.mirror_dur.clone();
        self.dead = false;
        self.plan = None;
    }

    /// Process restart without data loss.
    pub fn restart(&mut self) {
        self.dead = false;
        self.plan = None;
    }
}

pub type Disk = Rc<RefCell<Model>>;

pub struct SimDir(pub Disk);
pub struct SimMirror(pub Disk);

impl SignerDir for SimDir {
    fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, IoError> {
        let m = self.0.borrow();
        if m.dead {
            return Err(IoError("process crashed".into()));
        }
        Ok(m.dir_vol.get(name).map(|&i| m.inodes[i].vol.clone()))
    }
    fn write_new(&mut self, name: &str, bytes: &[u8]) -> Result<(), IoError> {
        let name = name.to_string();
        let bytes = bytes.to_vec();
        self.0.borrow_mut().step(Op::WriteNew, move |m| {
            m.inodes.push(Inode {
                vol: bytes,
                dur: Vec::new(),
            });
            let id = m.inodes.len() - 1;
            m.dir_vol.insert(name, id);
            Ok(())
        })
    }
    fn sync_file(&mut self, name: &str) -> Result<(), IoError> {
        let name = name.to_string();
        self.0.borrow_mut().step(Op::SyncFile, move |m| {
            let id = *m
                .dir_vol
                .get(&name)
                .ok_or_else(|| IoError(format!("{name}: not found")))?;
            m.inodes[id].dur = m.inodes[id].vol.clone();
            Ok(())
        })
    }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), IoError> {
        let (from, to) = (from.to_string(), to.to_string());
        self.0.borrow_mut().step(Op::Rename, move |m| {
            let id = m
                .dir_vol
                .remove(&from)
                .ok_or_else(|| IoError(format!("{from}: not found")))?;
            m.dir_vol.insert(to, id);
            Ok(())
        })
    }
    fn sync_dir(&mut self) -> Result<(), IoError> {
        self.0.borrow_mut().step(Op::SyncDir, |m| {
            m.dir_dur = m.dir_vol.clone();
            Ok(())
        })
    }
    fn remove(&mut self, name: &str) -> Result<(), IoError> {
        let name = name.to_string();
        self.0.borrow_mut().step(Op::Remove, move |m| {
            m.dir_vol.remove(&name);
            Ok(())
        })
    }
}

impl MirrorStore for SimMirror {
    fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        let m = self.0.borrow();
        if m.dead {
            return Err(IoError("process crashed".into()));
        }
        Ok(m.mirror_vol.clone())
    }
    fn write_synced(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        let bytes = bytes.to_vec();
        self.0.borrow_mut().step(Op::Mirror, move |m| {
            m.mirror_vol = Some(bytes.clone());
            m.mirror_dur = Some(bytes);
            Ok(())
        })
    }
}

// ── signer doubles ──────────────────────────────────────────────────────────

pub struct B3;
impl StateHasher for B3 {
    fn hash(&self, data: &[u8]) -> Digest {
        blake3::hash(data).into()
    }
}

#[derive(Clone, Default)]
pub struct MemOwnership(pub Rc<Cell<bool>>);
pub struct MemGuard(pub Rc<Cell<bool>>);
impl Drop for MemGuard {
    fn drop(&mut self) {
        self.0.set(false);
    }
}
impl ExclusiveOwnership for MemOwnership {
    type Guard = MemGuard;
    fn try_acquire(&self) -> Result<MemGuard, OwnershipError> {
        if self.0.get() {
            Err(OwnershipError("another signer holds this key".into()))
        } else {
            self.0.set(true);
            Ok(MemGuard(self.0.clone()))
        }
    }
}

pub struct TestPolka;
pub fn polka_evidence(height: u64, round: u32, value: &Digest) -> Vec<u8> {
    let mut e = b"polka".to_vec();
    e.extend_from_slice(&height.to_le_bytes());
    e.extend_from_slice(&round.to_le_bytes());
    e.extend_from_slice(value);
    e
}
impl PolkaVerifier for TestPolka {
    fn verify_polka(
        &self,
        height: u64,
        round: u32,
        value: &Digest,
        evidence: &[u8],
    ) -> Result<(), String> {
        if evidence == polka_evidence(height, round, value) {
            Ok(())
        } else {
            Err("not a quorum of prevotes".into())
        }
    }
    /// The finality oracle: accepts exactly `final ‖ height LE ‖ block`.
    fn verify_finality(&self, proof: &[u8]) -> Result<Certified, String> {
        match proof.strip_prefix(b"final".as_slice()) {
            Some(rest) if rest.len() == 40 => Ok(Certified {
                height: u64::from_le_bytes(rest[..8].try_into().expect("8")),
                block_id: rest[8..].try_into().expect("32"),
            }),
            _ => Err("not a finality proof".into()),
        }
    }
}

/// A finality proof the test oracle accepts.
pub fn finality(height: u64, block: &Digest) -> Vec<u8> {
    let mut p = b"final".to_vec();
    p.extend_from_slice(&height.to_le_bytes());
    p.extend_from_slice(block);
    p
}
