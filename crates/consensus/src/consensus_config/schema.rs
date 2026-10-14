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
//! a binary knows its fields (so a gate registered in it has an id and its
//! genesis value is computed) but neither writes nor reads records of it, and
//! refuses to start if any of its added fields is non-absent — a draft field
//! can be registered, never activated.
//!
//! Schema 2 is frozen: [`PRODUCTION`] writes it. Its registry,
//! [`SCHEMA_2_ADDED`], never changes again, and the encoding is pinned by
//! `crates/consensus/tests/consensus_config_schema2.rs`.
//!
//! # Registering a field after schema 2
//!
//! A field registered from now on belongs to a new schema 3: a `SCHEMA_3`
//! extending [`SCHEMA_2`] with its own append-only list, known by
//! [`PRODUCTION`] as a draft until a later reviewed change writes it. Use the
//! next unused id in the field's range (an activation gate: the `0x1000–0x1fff`
//! range, `source: Source::Gate`, `ty: U64`, named exactly as
//! `ChainParams::activation_heights` names it).
//! `crates/consensus/tests/consensus_config_census.rs` checks that every gate
//! has exactly one id in the newest schema and that no id repeats.

use sumchain_genesis::Genesis;

use super::codec::{Field, Value, SCHEMA_V1};
use super::ConfigError;
use sumchain_primitives::compute_pool_params::ComputePoolParamsV1;
use sumchain_state::messaging_executor::MESSAGING_TIMESTAMP_MS_PER_SECOND;

use super::fields::{is_gate, FieldSpec, ListOrder, Ty, SCHEMA_V1_FIELDS};

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
    /// schema refuses startup. Only ever grows: a schema any release wrote must
    /// stay here, because a schema transition in a node's history is verified
    /// by decoding the older encoding it kept (see the module documentation
    /// of [`super`]).
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

/// Fields schema 2 adds to schema 1. FROZEN: this binary writes schema 2
/// ([`PRODUCTION`]), so this list never changes again; a later field belongs
/// to schema 3. Ids are never reused or reordered. The list's order is history
/// only: configurations encode in ascending id order ([`Schema::specs`]), so
/// where an entry sits here never changes bytes or commitments.
pub const SCHEMA_2_ADDED: &[AddedField] = &[
    // #277: chain-defined activation of credential schema validation.
    AddedField {
        spec: FieldSpec {
            id: 0x103f,
            name: "credential_schema_validation_enabled_from_height",
            ty: Ty::U64,
            optional: true,
            item_width: None,
            list_order: ListOrder::SortedUnique,
        },
        source: Source::Gate,
    },
    // #279: a contract call returning an error rolls back its staged writes.
    AddedField {
        spec: FieldSpec {
            id: 0x1042,
            name: "contract_error_rollback_enabled_from_height",
            ty: Ty::U64,
            optional: true,
            item_width: None,
            list_order: ListOrder::SortedUnique,
        },
        source: Source::Gate,
    },
    // #278: messaging rules read the block timestamp in seconds.
    AddedField {
        spec: FieldSpec {
            id: 0x1040,
            name: "messaging_timestamp_units_enabled_from_height",
            ty: Ty::U64,
            optional: true,
            item_width: None,
            list_order: ListOrder::SortedUnique,
        },
        source: Source::Gate,
    },
    // #215: the C1 compute-pool parameters, committed as their canonical
    // `ComputePoolParamsV1` encoding (`CPPRMv1`, 321 bytes). A parameter group,
    // so in the `0x0300–0x07ff` range after the beacon groups (0x0700, 0x0710),
    // not in the gate range. Absent when genesis declares no parameters — the
    // pre-existing behaviour, and the production default.
    AddedField {
        spec: FieldSpec {
            id: COMPUTE_POOL_PARAMS_ID,
            name: "compute_pool_params",
            ty: Ty::Bytes,
            optional: true,
            item_width: Some(ComputePoolParamsV1::LEN),
            list_order: ListOrder::SortedUnique,
        },
        source: Source::Param(compute_pool_params_value),
    },
    // #279: contract metering. Four fields, registered together, whose value
    // rules are [`check_metering_relations`].
    //
    // The gate: metering applies at and above this height.
    AddedField {
        spec: added_spec(
            CONTRACT_METERING_GATE_ID,
            "contract_metering_enabled_from_height",
            Ty::U64,
        ),
        source: Source::Gate,
    },
    // The block contract gas budget: an upper bound on the summed declared
    // `gas_limit` of a block's contract transactions. Absent: no block bound.
    AddedField {
        spec: added_spec(MAX_BLOCK_CONTRACT_GAS_ID, "max_block_contract_gas", Ty::U64),
        source: Source::Param(max_block_contract_gas),
    },
    // The metered engine's identity, and the cost schedule it meters with.
    // Absent below the metering gate, whose behaviour is the engine schema 1
    // commits as `sumc_runtime::ENGINE_IDENTITY`. Present only while the gate
    // is set AND this binary's metering values are ratified; a gate set
    // without ratified values is refused when the configuration is built
    // ([`refuse_unratified_metering`]), so no record can hold a provisional
    // identity or schedule.
    AddedField {
        spec: added_spec(
            METERED_ENGINE_IDENTITY_ID,
            "sumc_runtime::metering::METERED_ENGINE_IDENTITY",
            Ty::Bytes,
        ),
        source: Source::Param(metered_engine_identity),
    },
    AddedField {
        spec: added_spec(
            METERED_COST_SCHEDULE_ID,
            "sumc_runtime::metering::METERED_COST_SCHEDULE",
            Ty::Bytes,
        ),
        source: Source::Param(metered_cost_schedule),
    },
    // #279: the contract deploy gas ceiling: an upper bound on the declared
    // `gas_limit` of a `ContractDeploy` where the metering gate is open.
    // Absent: deploys stay bounded by `max_contract_gas`, as calls are.
    AddedField {
        spec: added_spec(
            MAX_CONTRACT_DEPLOY_GAS_ID,
            "max_contract_deploy_gas",
            Ty::U64,
        ),
        source: Source::Param(max_contract_deploy_gas),
    },
    // #278: the compiled constant the messaging rules divide the block
    // timestamp by at and above `messaging_timestamp_units_enabled_from_height`
    // (0x1040). Committed only while that gate is set: below it nothing reads
    // the constant, so absent is the pre-existing behaviour, and a schema-1
    // record carried into schema 2 stays exact. Setting the gate on an existing
    // chain therefore also moves this field, which is not a gate, so that start
    // asks for `acknowledge-consensus-config` rather than recording a
    // reschedule on its own.
    AddedField {
        spec: FieldSpec {
            id: MESSAGING_TIMESTAMP_MS_PER_SECOND_ID,
            name: "sumchain_state::messaging_executor::MESSAGING_TIMESTAMP_MS_PER_SECOND",
            ty: Ty::U128,
            optional: true,
            item_width: None,
            list_order: ListOrder::SortedUnique,
        },
        source: Source::Param(messaging_timestamp_ms_per_second_value),
    },
];

/// Field id of [`compute_pool_params_value`] (#215).
pub const COMPUTE_POOL_PARAMS_ID: u16 = 0x0720;

/// The genesis `compute_pool_params` as committed: its canonical encoding, or
/// [`Value::Absent`] when none is declared.
///
/// The bytes are the fixed-width layout whether or not the value passes
/// structural validation: `Genesis::validate` refuses an invalid declaration
/// before a node gets here, and a declared value is never committed as absent.
fn compute_pool_params_value(genesis: &Genesis) -> Value {
    match &genesis.params.compute_pool_params {
        None => Value::Absent,
        Some(p) => Value::Bytes(p.canonical_bytes()),
    }
}

/// An optional schema-2 field (absent is its pre-existing behaviour).
const fn added_spec(id: u16, name: &'static str, ty: Ty) -> FieldSpec {
    FieldSpec {
        id,
        name,
        ty,
        optional: true,
        item_width: None,
        list_order: ListOrder::SortedUnique,
    }
}

fn max_contract_deploy_gas(genesis: &Genesis) -> Value {
    genesis
        .params
        .max_contract_deploy_gas
        .map_or(Value::Absent, Value::U64)
}

fn max_block_contract_gas(genesis: &Genesis) -> Value {
    genesis
        .params
        .max_block_contract_gas
        .map_or(Value::Absent, Value::U64)
}

/// Field id of `contract_metering_enabled_from_height` (#279).
pub const CONTRACT_METERING_GATE_ID: u16 = 0x1041;
/// Field id of `max_block_contract_gas` (#279).
pub const MAX_BLOCK_CONTRACT_GAS_ID: u16 = 0x0115;
/// Field id of the metered engine's identity (#279).
pub const METERED_ENGINE_IDENTITY_ID: u16 = 0x2716;
/// Field id of the metered cost schedule (#279).
pub const METERED_COST_SCHEDULE_ID: u16 = 0x2717;
/// Longest metered engine identity, in bytes.
pub const METERED_ENGINE_IDENTITY_MAX_LEN: usize = 128;
/// Longest cost-schedule tag, in bytes.
pub const METERED_COST_SCHEDULE_TAG_MAX_LEN: usize = 64;
/// Field id of `max_contract_deploy_gas` (#279).
pub const MAX_CONTRACT_DEPLOY_GAS_ID: u16 = 0x0116;

/// Whether the metering values may be committed: the gate is set and this
/// binary's values are ratified.
fn metering_values_committed(genesis: &Genesis) -> bool {
    genesis
        .params
        .contract_metering_enabled_from_height
        .is_some()
        && sumc_runtime::metering::METERING_VALUES_RATIFIED
}

fn metered_engine_identity(genesis: &Genesis) -> Value {
    if metering_values_committed(genesis) {
        Value::Bytes(
            sumc_runtime::metering::METERED_ENGINE_IDENTITY
                .as_bytes()
                .to_vec(),
        )
    } else {
        Value::Absent
    }
}

fn metered_cost_schedule(genesis: &Genesis) -> Value {
    if metering_values_committed(genesis) {
        Value::Bytes(sumc_runtime::metering::METERED_COST_SCHEDULE.encode())
    } else {
        Value::Absent
    }
}

/// Refuses a configuration that sets `contract_metering_enabled_from_height`
/// without both metering values present: a binary that has no ratified engine
/// identity and cost schedule to commit cannot enable metering.
///
/// Called by every build of a configuration, so node start, the
/// acknowledgements and the RPC all fail before anything is recorded.
pub(crate) fn refuse_unratified_metering(
    genesis: &Genesis,
    fields: &[Field],
) -> Result<(), ConfigError> {
    let Some(height) = genesis.params.contract_metering_enabled_from_height else {
        return Ok(());
    };
    let present = |id: u16| {
        fields
            .iter()
            .any(|f| f.id == id && f.value != Value::Absent)
    };
    if present(METERED_ENGINE_IDENTITY_ID) && present(METERED_COST_SCHEDULE_ID) {
        return Ok(());
    }
    Err(ConfigError::Refused(format!(
        "contract_metering_enabled_from_height is set ({height}), but this binary has no \
         ratified metering values to commit with it: a configuration that enables metering \
         commits the metered engine identity and cost schedule, and values that are not \
         ratified are never committed. Nothing was recorded. Remove the height, or run a \
         binary whose metering values are ratified"
    )))
}

/// The value rules of the metering fields (#279). Part of the schema: checked
/// on every configuration built or decoded in a schema that registers them, so
/// a record that breaks one was not produced by any encoder and is refused.
///
/// - `0x2716` (engine identity) and `0x2717` (cost schedule) are each present
///   exactly when `0x1041` (the metering gate) is. A configuration that meters
///   contracts commits the engine and schedule it meters with; one that does
///   not commits neither.
/// - `0x0115` (block budget) is present only when `0x1041` is, and is then at
///   least `max_contract_gas` (`0x0106`).
/// - `0x0116` (deploy ceiling) is present only when `0x1041` is, and is then
///   at least `max_contract_gas`; where `0x0115` is also present, `0x0115` is
///   at least `0x0116`.
/// - `0x2716` is the engine identity string: 1 to
///   [`METERED_ENGINE_IDENTITY_MAX_LEN`] bytes, each printable ASCII
///   (`0x21..=0x7e`).
/// - `0x2717` is `tag_len:u8 ‖ tag[tag_len] ‖ body`. The tag, 1 to
///   [`METERED_COST_SCHEDULE_TAG_MAX_LEN`] printable ASCII bytes, names the
///   body's layout and version; the body is non-empty and is the schedule in
///   that layout, which the engine named by `0x2716` defines. A configuration
///   compares the bytes: a different schedule is a different value.
pub(crate) fn check_metering_relations(
    schema: &'static Schema,
    fields: &[Field],
) -> Result<(), String> {
    if schema.spec(CONTRACT_METERING_GATE_ID).is_none() {
        return Ok(());
    }
    let get = |id: u16| {
        fields
            .iter()
            .find(|f| f.id == id)
            .map_or(&Value::Absent, |f| &f.value)
    };
    let metered = *get(CONTRACT_METERING_GATE_ID) != Value::Absent;
    for id in [METERED_ENGINE_IDENTITY_ID, METERED_COST_SCHEDULE_ID] {
        if (*get(id) != Value::Absent) != metered {
            return Err(format!(
                "field {id:#06x} is {} while the metering gate {CONTRACT_METERING_GATE_ID:#06x} \
                 is {}; the engine identity and cost schedule are committed exactly when the \
                 gate is",
                if metered { "absent" } else { "present" },
                if metered { "set" } else { "absent" },
            ));
        }
    }
    let tx_ceiling = || {
        SCHEMA_V1_FIELDS
            .iter()
            .find(|s| s.name == "max_contract_gas")
            .and_then(|s| match get(s.id) {
                Value::U64(c) => Some(*c),
                _ => None,
            })
            .ok_or("max_contract_gas is not a U64 field of this configuration")
    };
    if let Value::U64(budget) = get(MAX_BLOCK_CONTRACT_GAS_ID) {
        if !metered {
            return Err(format!(
                "field {MAX_BLOCK_CONTRACT_GAS_ID:#06x} (block contract gas budget) is present \
                 while the metering gate {CONTRACT_METERING_GATE_ID:#06x} is absent"
            ));
        }
        let ceiling = tx_ceiling()?;
        if *budget < ceiling {
            return Err(format!(
                "field {MAX_BLOCK_CONTRACT_GAS_ID:#06x} (block contract gas budget) {budget} is \
                 below max_contract_gas {ceiling}"
            ));
        }
    }
    if let Value::U64(deploy) = get(MAX_CONTRACT_DEPLOY_GAS_ID) {
        if !metered {
            return Err(format!(
                "field {MAX_CONTRACT_DEPLOY_GAS_ID:#06x} (contract deploy gas ceiling) is present \
                 while the metering gate {CONTRACT_METERING_GATE_ID:#06x} is absent"
            ));
        }
        let ceiling = tx_ceiling()?;
        if *deploy < ceiling {
            return Err(format!(
                "field {MAX_CONTRACT_DEPLOY_GAS_ID:#06x} (contract deploy gas ceiling) {deploy} \
                 is below max_contract_gas {ceiling}"
            ));
        }
        if let Value::U64(budget) = get(MAX_BLOCK_CONTRACT_GAS_ID) {
            if budget < deploy {
                return Err(format!(
                    "field {MAX_BLOCK_CONTRACT_GAS_ID:#06x} (block contract gas budget) {budget} \
                     is below field {MAX_CONTRACT_DEPLOY_GAS_ID:#06x} (contract deploy gas \
                     ceiling) {deploy}"
                ));
            }
        }
    }
    let printable = |b: &[u8]| b.iter().all(|c| (0x21..=0x7e).contains(c));
    if let Value::Bytes(identity) = get(METERED_ENGINE_IDENTITY_ID) {
        if identity.is_empty()
            || identity.len() > METERED_ENGINE_IDENTITY_MAX_LEN
            || !printable(identity)
        {
            return Err(format!(
                "field {METERED_ENGINE_IDENTITY_ID:#06x} (metered engine identity) must be 1 to \
                 {METERED_ENGINE_IDENTITY_MAX_LEN} bytes of printable ASCII"
            ));
        }
    }
    if let Value::Bytes(schedule) = get(METERED_COST_SCHEDULE_ID) {
        let framed = schedule.split_first().and_then(|(&len, rest)| {
            let len = len as usize;
            (len >= 1
                && len <= METERED_COST_SCHEDULE_TAG_MAX_LEN
                && rest.len() > len
                && printable(&rest[..len]))
            .then_some(())
        });
        if framed.is_none() {
            return Err(format!(
                "field {METERED_COST_SCHEDULE_ID:#06x} (metered cost schedule) must be \
                 tag_len:u8, a tag of 1 to {METERED_COST_SCHEDULE_TAG_MAX_LEN} printable ASCII \
                 bytes, and a non-empty body"
            ));
        }
    }
    Ok(())
}

/// Field id of [`messaging_timestamp_ms_per_second_value`] (#278), after the
/// schema-1 messaging constants (0x2519–0x251c) and the last schema-1 constant
/// (0x2529).
pub const MESSAGING_TIMESTAMP_MS_PER_SECOND_ID: u16 = 0x252a;

/// [`MESSAGING_TIMESTAMP_MS_PER_SECOND`] while the messaging timestamp-units
/// gate is set, [`Value::Absent`] otherwise.
fn messaging_timestamp_ms_per_second_value(genesis: &Genesis) -> Value {
    match genesis.params.messaging_timestamp_units_enabled_from_height {
        None => Value::Absent,
        Some(_) => Value::U128(MESSAGING_TIMESTAMP_MS_PER_SECOND as u128),
    }
}

/// Schema 2: schema 1 plus [`SCHEMA_2_ADDED`]. FROZEN.
pub static SCHEMA_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: SCHEMA_2_ADDED,
};

/// Fields schema 3 adds to schema 2. DRAFT: [`PRODUCTION`] knows these fields
/// but neither writes nor reads schema-3 records, and refuses to start if any
/// of them is non-absent, so a gate registered here can be declared but never
/// activated by this binary. Append-only, like every later schema.
pub const SCHEMA_3_ADDED: &[AddedField] = &[
    // A transaction-borne node-registry `UpdateStatus` is refused.
    AddedField {
        spec: FieldSpec {
            id: 0x1043,
            name: "node_registry_update_status_unsupported_enabled_from_height",
            ty: Ty::U64,
            optional: true,
            item_width: None,
            list_order: ListOrder::SortedUnique,
        },
        source: Source::Gate,
    },
];

/// Schema 3: schema 2 plus [`SCHEMA_3_ADDED`]. DRAFT.
pub static SCHEMA_3: Schema = Schema {
    number: 3,
    previous: Some(&SCHEMA_2),
    added: SCHEMA_3_ADDED,
};

/// What this binary does.
///
/// It writes schema 2: a fresh database records schema 2 directly. It reads
/// schema 1 and schema 2, and keeps reading schema 1 for good (see the module
/// documentation of [`super`]). An existing schema-1 record is run as it
/// stands, compared in schema 1 and never re-encoded at start; moving it to
/// schema 2 is the stopped-node `acknowledge-consensus-config-schema`, which
/// changes no rule. Until a node has moved, a schema-2 field set in its
/// genesis refuses start and names that command. It knows the draft schema 3,
/// whose fields must all be absent. Nothing here sets any gate.
pub static PRODUCTION: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2],
    writes: &SCHEMA_2,
    knows: &SCHEMA_3,
};
