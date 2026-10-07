//! Schemas after the first: append-only registries, and which of them this
//! binary reads, writes and knows the values of.
//!
//! # The rule
//!
//! Schema 1 ([`SCHEMA_1`], [`super::fields::SCHEMA_V1_FIELDS`]) is frozen. A
//! later schema is its predecessor's registry plus an append-only list of
//! [`AddedField`]s under ids no earlier schema used. Nothing is removed or
//! retyped this way; a field that must leave or change type is a different
//! mechanism and a different review.
//!
//! Every added field is optional, and its [`Value::Absent`] value means "the
//! behaviour that existed before this field". A configuration whose added
//! fields are all absent therefore runs exactly the rules its predecessor
//! schema describes. That is what lets a stored schema-1 record be carried
//! into schema 2 without consulting anything but the record itself
//! ([`super::record::acknowledge_schema_transition`]), and what keeps a new
//! gate dormant on a node that has not moved.
//!
//! # Draft and frozen
//!
//! A schema freezes when a release first WRITES it. Until then it is a draft:
//! this binary knows its fields (so a gate registered in it has an id and its
//! genesis value is computed) but neither writes nor reads records of it, and
//! refuses to start if any of its added fields is non-absent — a draft field
//! can be registered, never activated. Moving [`PRODUCTION`] to write schema 2
//! is the change that freezes it, and is a separate, reviewed decision.
//!
//! # Registering a post-schema-1 field
//!
//! Append one [`AddedField`] to [`SCHEMA_2_ADDED`] with the next unused id in
//! its range (an activation gate: the `0x1000–0x1fff` range, `source:
//! Source::Gate`, `ty: U64`, named exactly as `ChainParams::activation_heights`
//! names it). `crates/consensus/tests/consensus_config_census.rs` checks that
//! every gate has exactly one id in the newest schema and that no id repeats.

use sumchain_genesis::Genesis;

use super::codec::{Value, SCHEMA_V1};
use super::fields::{is_gate, FieldSpec, Ty, SCHEMA_V1_FIELDS};

/// Where an added field's value comes from.
#[derive(Clone, Copy)]
pub enum Source {
    /// An activation height, taken from `ChainParams::activation_heights()`
    /// under the field's name, as every schema-1 gate is.
    Gate,
    /// Computed from the genesis and this binary. Must return
    /// [`Value::Absent`] wherever the behaviour is the pre-field behaviour.
    Param(fn(&Genesis) -> Value),
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Gate => f.write_str("Gate"),
            Source::Param(_) => f.write_str("Param"),
        }
    }
}

/// One field a schema adds to its predecessor.
#[derive(Debug, Clone, Copy)]
pub struct AddedField {
    pub spec: FieldSpec,
    pub source: Source,
}

/// One schema: its number and its registry.
#[derive(Debug)]
pub struct Schema {
    pub number: u16,
    /// The schema this one extends; `None` only for schema 1, whose registry
    /// is [`SCHEMA_V1_FIELDS`].
    pub previous: Option<&'static Schema>,
    /// Fields added to `previous`, append-only.
    pub added: &'static [AddedField],
}

impl Schema {
    /// Every field of this schema, in ascending id order.
    pub fn specs(&'static self) -> Vec<&'static FieldSpec> {
        let mut out: Vec<&'static FieldSpec> = match self.previous {
            None => SCHEMA_V1_FIELDS.iter().collect(),
            Some(p) => p.specs(),
        };
        out.extend(self.added.iter().map(|a| &a.spec));
        out.sort_by_key(|s| s.id);
        out
    }

    /// The registry entry for `id` in this schema.
    pub fn spec(&'static self, id: u16) -> Option<&'static FieldSpec> {
        if let Some(a) = self.added.iter().find(|a| a.spec.id == id) {
            return Some(&a.spec);
        }
        match self.previous {
            None => SCHEMA_V1_FIELDS
                .binary_search_by_key(&id, |s| s.id)
                .ok()
                .map(|i| &SCHEMA_V1_FIELDS[i]),
            Some(p) => p.spec(id),
        }
    }

    /// Fields added by every schema after schema 1 up to and including this
    /// one, oldest schema first.
    pub fn all_added(&'static self) -> Vec<&'static AddedField> {
        let mut out = match self.previous {
            None => Vec::new(),
            Some(p) => p.all_added(),
        };
        out.extend(self.added.iter());
        out
    }

    /// Whether `older` is this schema or one it (transitively) extends.
    pub fn extends(&'static self, older: &'static Schema) -> bool {
        let mut s = Some(self);
        while let Some(cur) = s {
            if std::ptr::eq(cur, older) {
                return true;
            }
            s = cur.previous;
        }
        false
    }

    /// Fields this schema has and `older` does not, in ascending id order.
    /// Empty unless `self` extends `older`.
    pub fn added_since(&'static self, older: &'static Schema) -> Vec<&'static FieldSpec> {
        if !self.extends(older) {
            return Vec::new();
        }
        let mut out: Vec<&'static FieldSpec> = Vec::new();
        let mut s = self;
        while !std::ptr::eq(s, older) {
            out.extend(s.added.iter().map(|a| &a.spec));
            s = s.previous.expect("extends(older) holds");
        }
        out.sort_by_key(|s| s.id);
        out
    }

    /// The rules every schema after the first obeys. Checked by the builder on
    /// every use, so a malformed registry refuses to start rather than encode.
    pub fn check(&'static self) -> Result<(), String> {
        let Some(previous) = self.previous else {
            return if self.number == SCHEMA_V1 && self.added.is_empty() {
                Ok(())
            } else {
                Err(format!("schema {} has no predecessor", self.number))
            };
        };
        previous.check()?;
        if self.number != previous.number + 1 {
            return Err(format!(
                "schema {} follows schema {}; numbers are consecutive",
                self.number, previous.number
            ));
        }
        for (i, a) in self.added.iter().enumerate() {
            let s = &a.spec;
            if previous.spec(s.id).is_some() || self.added[..i].iter().any(|b| b.spec.id == s.id) {
                return Err(format!(
                    "schema {} reuses field id {:#06x} ({})",
                    self.number, s.id, s.name
                ));
            }
            if previous.specs().iter().any(|p| p.name == s.name)
                || self.added[..i].iter().any(|b| b.spec.name == s.name)
            {
                return Err(format!(
                    "schema {} reuses field name {}",
                    self.number, s.name
                ));
            }
            if !s.optional {
                return Err(format!(
                    "schema {} field {} ({:#06x}) must be optional: absent is its \
                     pre-existing behaviour",
                    self.number, s.name, s.id
                ));
            }
            match a.source {
                Source::Gate if !(is_gate(s.id) && s.ty == Ty::U64) => {
                    return Err(format!(
                        "schema {} gate {} ({:#06x}) must be a U64 in the gate range",
                        self.number, s.name, s.id
                    ));
                }
                Source::Param(_) if is_gate(s.id) => {
                    return Err(format!(
                        "schema {} field {} ({:#06x}) is in the gate range but not a gate",
                        self.number, s.name, s.id
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Which schemas this binary reads, writes and knows.
#[derive(Debug)]
pub struct SchemaPolicy {
    /// Schemas whose stored records this binary decodes. A record of any other
    /// schema refuses startup.
    pub reads: &'static [&'static Schema],
    /// The schema a fresh database is recorded in, and the target of an
    /// acknowledged schema transition. Always one of `reads`.
    pub writes: &'static Schema,
    /// The newest registry this binary computes values for. Extends `writes`;
    /// any field beyond `writes` is a draft field and must be absent.
    pub knows: &'static Schema,
}

impl SchemaPolicy {
    /// The schema numbered `number` among those this binary reads.
    pub fn read_schema(&self, number: u16) -> Option<&'static Schema> {
        self.reads.iter().copied().find(|s| s.number == number)
    }

    /// The policy's own consistency.
    pub fn check(&self) -> Result<(), String> {
        self.knows.check()?;
        if !self.reads.iter().any(|s| std::ptr::eq(*s, self.writes)) {
            return Err("the written schema is not one this binary reads".to_string());
        }
        for s in self.reads {
            if !self.knows.extends(s) {
                return Err(format!("read schema {} is not known", s.number));
            }
        }
        Ok(())
    }
}

/// Schema 1: [`SCHEMA_V1_FIELDS`], frozen by the release that first wrote it.
pub static SCHEMA_1: Schema = Schema {
    number: SCHEMA_V1,
    previous: None,
    added: &[],
};

/// Fields schema 2 adds to schema 1. Append-only. DRAFT: no release has
/// written schema 2, and this binary does not (see [`PRODUCTION`]).
///
/// Empty in this change. Each post-schema-1 gate or parameter appends its own
/// entry in its own change.
pub const SCHEMA_2_ADDED: &[AddedField] = &[];

/// Schema 2: schema 1 plus [`SCHEMA_2_ADDED`]. DRAFT.
pub static SCHEMA_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: SCHEMA_2_ADDED,
};

/// What this binary does.
///
/// It reads and writes schema 1 only, as the release before it did, and knows
/// the draft schema 2's fields so that a gate registered there has an id and
/// is held absent. Enabling schema 2 — `reads: [1, 2]`, `writes: 2` — freezes
/// it, makes a fresh database record schema 2, and makes the stopped-node
/// schema transition available to existing ones. That is a later change.
pub static PRODUCTION: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1],
    writes: &SCHEMA_1,
    knows: &SCHEMA_2,
};
