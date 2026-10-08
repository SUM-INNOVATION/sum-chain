//! The ConsensusConfig byte format: typed fields, the strict decoder, the
//! commitment and the field-level difference.
//!
//! One format serves every schema. The schema number in the header selects the
//! registry ([`super::schema::Schema`]) the fields are checked against; schema
//! 1's encoding is exactly what the schema-1 release wrote.
//!
//! ```text
//! encoding   = MAGIC[7] ‖ schema:u16 ‖ field_count:u16 ‖ field*
//! field      = field_id:u16 ‖ tag:u8 ‖ len:u32 ‖ value[len]
//! commitment = BLAKE3(COMMITMENT_DOMAIN ‖ encoding)
//! ```
//!
//! Every integer is little-endian. Fields appear in strictly ascending
//! `field_id` order, and a schema-1 encoding carries EVERY field of the
//! schema-1 registry exactly once — presence is never expressed by omission,
//! only by the explicit [`Value::Absent`] tag on a field the registry declares
//! optional. So two encodings of the same configuration are the same bytes,
//! and any decoded encoding names every field.
//!
//! The decoder accepts exactly what the encoder produces and nothing else:
//! wrong magic, an unknown schema, an unknown, duplicate, missing or
//! out-of-order id, a tag the registry does not declare for that id, a length
//! that does not match the tag, a boolean other than 0 or 1, a list whose items
//! are out of order or duplicated where the registry says they may not be, an
//! oversized count or length, and trailing bytes are all refused.

use sumchain_primitives::Hash;

use super::fields::{FieldSpec, ListOrder, Ty};
use super::schema::{Schema, PRODUCTION};
use super::ConfigError;

/// Leading bytes of every encoding. Versioned in the string so that a later
/// format is a different prefix, not a reinterpretation of this one.
pub const MAGIC: &[u8; 7] = b"CCFGv1\0";

/// Schema 1, frozen by the release that first wrote it.
///
/// A schema is FROZEN once a release has written it: its field set, ids, types
/// and meanings never change. Adding, removing or retyping a field is a new
/// schema with a new registry, and a binary that does not know a stored
/// record's schema refuses to start rather than guessing. See the module
/// documentation of [`super`] for the evolution rule.
pub const SCHEMA_V1: u16 = 1;

/// Domain separator of the commitment.
pub const COMMITMENT_DOMAIN: &[u8] = b"SUMCHAIN/CONSENSUS-CONFIG/v1\0";

/// Largest value any single field may carry. The largest real field is the
/// validator list at 32 bytes per validator; this bounds a hostile record, not
/// a configuration.
pub const MAX_FIELD_VALUE_BYTES: u32 = 1 << 20;

/// Largest item count of a list field.
pub const MAX_LIST_ITEMS: u32 = 65_536;

/// Largest whole encoding the decoder will look at.
pub const MAX_ENCODING_BYTES: usize = 4 << 20;

const HEADER_LEN: usize = MAGIC.len() + 2 + 2;

/// One typed field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Explicitly absent. Only valid for a field its registry entry marks
    /// optional, and never the same configuration as any present value.
    Absent,
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Bool(bool),
    /// An opaque byte string (a hash domain, a key prefix, an address).
    Bytes(Vec<u8>),
    /// A 32-byte digest.
    Digest([u8; 32]),
    /// A list of byte strings, ordered as the registry entry requires.
    List(Vec<Vec<u8>>),
}

impl Value {
    pub(crate) fn tag(&self) -> u8 {
        match self {
            Value::Absent => 0,
            Value::U64(_) => 1,
            Value::U128(_) => 2,
            Value::Bool(_) => 3,
            Value::Bytes(_) => 4,
            Value::U8(_) => 5,
            Value::U32(_) => 6,
            Value::U16(_) => 7,
            Value::Digest(_) => 8,
            Value::List(_) => 9,
        }
    }

    fn ty(&self) -> Option<Ty> {
        Some(match self {
            Value::Absent => return None,
            Value::U8(_) => Ty::U8,
            Value::U16(_) => Ty::U16,
            Value::U32(_) => Ty::U32,
            Value::U64(_) => Ty::U64,
            Value::U128(_) => Ty::U128,
            Value::Bool(_) => Ty::Bool,
            Value::Bytes(_) => Ty::Bytes,
            Value::Digest(_) => Ty::Digest,
            Value::List(_) => Ty::List,
        })
    }

    fn write_value(&self, out: &mut Vec<u8>) {
        match self {
            Value::Absent => {}
            Value::U8(v) => out.push(*v),
            Value::U16(v) => out.extend_from_slice(&v.to_le_bytes()),
            Value::U32(v) => out.extend_from_slice(&v.to_le_bytes()),
            Value::U64(v) => out.extend_from_slice(&v.to_le_bytes()),
            Value::U128(v) => out.extend_from_slice(&v.to_le_bytes()),
            Value::Bool(v) => out.push(u8::from(*v)),
            Value::Bytes(b) => out.extend_from_slice(b),
            Value::Digest(d) => out.extend_from_slice(d),
            Value::List(items) => {
                out.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for item in items {
                    out.extend_from_slice(&(item.len() as u32).to_le_bytes());
                    out.extend_from_slice(item);
                }
            }
        }
    }

    /// A rendering for logs, diffs and the RPC.
    ///
    /// Scalars are printed. Byte strings, digests and lists are printed as the
    /// BLAKE3 digest of their encoded value, so a diff or an RPC answer never
    /// carries a raw validator list, an allocation table or an address — it
    /// carries a value two operators can compare.
    pub fn render(&self) -> String {
        match self {
            Value::Absent => "absent".to_string(),
            Value::U8(v) => v.to_string(),
            Value::U16(v) => v.to_string(),
            Value::U32(v) => v.to_string(),
            Value::U64(v) => v.to_string(),
            Value::U128(v) => v.to_string(),
            Value::Bool(v) => v.to_string(),
            Value::Bytes(_) | Value::Digest(_) | Value::List(_) => {
                let mut buf = Vec::new();
                self.write_value(&mut buf);
                let count = match self {
                    Value::List(items) => format!("{} item(s), ", items.len()),
                    _ => format!("{} byte(s), ", buf.len()),
                };
                format!("{}digest {}", count, Hash::hash(&buf))
            }
        }
    }
}

/// One field of a configuration: its permanent id and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub id: u16,
    pub value: Value,
}

/// A complete configuration of one schema: every field of that schema's
/// registry, in id order.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    schema: &'static Schema,
    fields: Vec<Field>,
}

impl PartialEq for ConsensusConfig {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.schema, other.schema) && self.fields == other.fields
    }
}
impl Eq for ConsensusConfig {}

impl ConsensusConfig {
    /// Assemble a configuration, checking it against `schema`'s registry.
    ///
    /// The builder in [`super::fields`] is the only production caller; the
    /// check is here so that no caller, including a test, can produce bytes
    /// the decoder would refuse.
    pub(crate) fn from_fields(
        schema: &'static Schema,
        mut fields: Vec<Field>,
    ) -> Result<Self, ConfigError> {
        fields.sort_by_key(|f| f.id);
        check_against_registry(schema, &fields)?;
        Ok(Self { schema, fields })
    }

    /// The configuration `target` holds, from values computed over `known`, a
    /// registry that extends it.
    ///
    /// A value of a field `target` does not have is dropped only when it is
    /// [`Value::Absent`] — the pre-existing behaviour every later field's
    /// absence means. Any other value is a rule `target` cannot express and is
    /// refused with [`ConfigError::BeyondSchema`], never dropped.
    pub(crate) fn project(
        values: Vec<Field>,
        known: &'static Schema,
        target: &'static Schema,
    ) -> Result<Self, ConfigError> {
        let mut kept = Vec::with_capacity(values.len());
        let mut beyond = Vec::new();
        for f in values {
            if target.spec(f.id).is_some() {
                kept.push(f);
            } else if f.value != Value::Absent {
                let name = known.spec(f.id).map_or("?", |s| s.name);
                beyond.push(format!("{name} ({:#06x}) = {}", f.id, f.value.render()));
            }
        }
        if !beyond.is_empty() {
            return Err(ConfigError::BeyondSchema {
                schema: target.number,
                fields: beyond.join("; "),
            });
        }
        Self::from_fields(target, kept)
    }

    /// This configuration carried into `target`, a later schema that extends
    /// its own: every field it holds unchanged, every field `target` adds
    /// [`Value::Absent`]. The same rules, in the newer schema's encoding.
    pub fn extend_to(&self, target: &'static Schema) -> Result<Self, ConfigError> {
        if std::ptr::eq(target, self.schema) || !target.extends(self.schema) {
            return Err(ConfigError::Refused(format!(
                "schema {} does not extend schema {}",
                target.number, self.schema.number
            )));
        }
        let mut fields = self.fields.clone();
        for spec in target.added_since(self.schema) {
            fields.push(Field {
                id: spec.id,
                value: Value::Absent,
            });
        }
        Self::from_fields(target, fields)
    }

    /// The schema this configuration is encoded in.
    pub fn schema(&self) -> &'static Schema {
        self.schema
    }

    /// The registry entry of `id` in this configuration's schema.
    pub fn spec(&self, id: u16) -> Option<&'static FieldSpec> {
        self.schema.spec(id)
    }

    /// Every field, in ascending id order.
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// The value of one field.
    pub fn get(&self, id: u16) -> Option<&Value> {
        self.fields
            .binary_search_by_key(&id, |f| f.id)
            .ok()
            .map(|i| &self.fields[i].value)
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.schema.number.to_le_bytes());
        out.extend_from_slice(&(self.fields.len() as u16).to_le_bytes());
        let mut value = Vec::new();
        for field in &self.fields {
            value.clear();
            field.value.write_value(&mut value);
            out.extend_from_slice(&field.id.to_le_bytes());
            out.push(field.value.tag());
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(&value);
        }
        out
    }

    /// The commitment to this configuration.
    pub fn commitment(&self) -> Hash {
        commitment_of(&self.encode())
    }

    /// Decode an encoding of a schema this binary reads
    /// ([`PRODUCTION`]), refusing anything the encoder would not produce.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConfigError> {
        Self::decode_with(bytes, PRODUCTION.reads)
    }

    /// Decode an encoding of one of `reads`. A schema outside `reads` is
    /// [`ConfigError::UnknownSchema`].
    pub fn decode_with(bytes: &[u8], reads: &[&'static Schema]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_ENCODING_BYTES {
            return Err(ConfigError::malformed(format!(
                "encoding is {} bytes, above the {} byte bound",
                bytes.len(),
                MAX_ENCODING_BYTES
            )));
        }
        if bytes.len() < HEADER_LEN {
            return Err(ConfigError::malformed("encoding shorter than its header"));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(ConfigError::malformed("wrong magic"));
        }
        let mut r = Reader {
            bytes,
            pos: MAGIC.len(),
        };
        let number = r.u16()?;
        let schema = reads
            .iter()
            .copied()
            .find(|s| s.number == number)
            .ok_or(ConfigError::UnknownSchema(number))?;
        let specs = schema.specs();
        let count = r.u16()? as usize;
        if count != specs.len() {
            return Err(ConfigError::malformed(format!(
                "schema {} has {} fields, encoding declares {}",
                schema.number,
                specs.len(),
                count
            )));
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let id = r.u16()?;
            let tag = r.u8()?;
            let len = r.u32()?;
            if len > MAX_FIELD_VALUE_BYTES {
                return Err(ConfigError::malformed(format!(
                    "field {id:#06x} length {len} above the {MAX_FIELD_VALUE_BYTES} byte bound"
                )));
            }
            let spec = schema
                .spec(id)
                .ok_or_else(|| ConfigError::malformed(format!("unknown field id {id:#06x}")))?;
            let raw = r.take(len as usize)?;
            let value = decode_value(spec, tag, raw)?;
            fields.push(Field { id, value });
        }
        if r.pos != bytes.len() {
            return Err(ConfigError::malformed(format!(
                "{} trailing byte(s)",
                bytes.len() - r.pos
            )));
        }
        // Order, completeness and per-field rules are the registry check the
        // encoder also passes through; a decoded encoding that fails it was not
        // produced by an encoder.
        check_against_registry(schema, &fields)?;
        Ok(Self { schema, fields })
    }

    /// Every field whose value differs between `self` (the recorded side) and
    /// `now`, in id order.
    ///
    /// Both sides must be of one schema; every caller compares in the schema
    /// the record holds. Two configurations of different schemas are refused
    /// with [`ConfigError::Refused`] in every build, never compared: walking a
    /// schema-1 configuration against a schema-2 one would compare only the
    /// fields they share and silently drop every field the newer schema adds.
    /// Carry the older side into the newer schema with [`Self::extend_to`]
    /// first if a cross-schema comparison is meant.
    pub fn diff(&self, now: &ConsensusConfig) -> Result<Vec<FieldChange>, ConfigError> {
        if !std::ptr::eq(self.schema, now.schema) {
            return Err(ConfigError::Refused(format!(
                "cannot compare a schema {} configuration with a schema {} configuration; \
                 a comparison is made in one schema",
                self.schema.number, now.schema.number
            )));
        }
        // Both sides passed the same registry check, so they hold the same ids
        // in the same order and can be walked together.
        Ok(self
            .fields
            .iter()
            .zip(now.fields.iter())
            .filter(|(a, b)| a.value != b.value)
            .map(|(a, b)| FieldChange {
                id: a.id,
                name: self.schema.spec(a.id).map(|s| s.name).unwrap_or("?"),
                from: a.value.clone(),
                to: b.value.clone(),
            })
            .collect())
    }
}

/// The commitment to an encoding.
pub fn commitment_of(encoding: &[u8]) -> Hash {
    let mut data = Vec::with_capacity(COMMITMENT_DOMAIN.len() + encoding.len());
    data.extend_from_slice(COMMITMENT_DOMAIN);
    data.extend_from_slice(encoding);
    Hash::hash(&data)
}

/// One field that differs between two configurations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    pub id: u16,
    pub name: &'static str,
    pub from: Value,
    pub to: Value,
}

impl std::fmt::Display for FieldChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({:#06x}): {} -> {}",
            self.name,
            self.id,
            self.from.render(),
            self.to.render()
        )
    }
}

fn check_against_registry(schema: &'static Schema, fields: &[Field]) -> Result<(), ConfigError> {
    let n = schema.number;
    let specs = schema.specs();
    if fields.len() != specs.len() {
        return Err(ConfigError::malformed(format!(
            "schema {n} has {} fields, configuration has {}",
            specs.len(),
            fields.len()
        )));
    }
    for (field, spec) in fields.iter().zip(specs.iter()) {
        if field.id != spec.id {
            return Err(ConfigError::malformed(format!(
                "field {:#06x} where schema {n} requires {:#06x} ({}): ids must be \
                 unique, complete and ascending",
                field.id, spec.id, spec.name
            )));
        }
        check_value(n, spec, &field.value)?;
    }
    Ok(())
}

fn check_value(n: u16, spec: &FieldSpec, value: &Value) -> Result<(), ConfigError> {
    match value.ty() {
        None if spec.optional => Ok(()),
        None => Err(ConfigError::malformed(format!(
            "field {} ({:#06x}) may not be absent",
            spec.name, spec.id
        ))),
        Some(ty) if ty != spec.ty => Err(ConfigError::malformed(format!(
            "field {} ({:#06x}) has type {:?}, schema {n} requires {:?}",
            spec.name, spec.id, ty, spec.ty
        ))),
        Some(_) => {
            if let Value::List(items) = value {
                if items.len() > MAX_LIST_ITEMS as usize {
                    return Err(ConfigError::malformed(format!(
                        "field {} lists {} items, above the {} bound",
                        spec.name,
                        items.len(),
                        MAX_LIST_ITEMS
                    )));
                }
                if let Some(width) = spec.item_width {
                    if items.iter().any(|i| i.len() != width) {
                        return Err(ConfigError::malformed(format!(
                            "field {} has an item that is not {} bytes",
                            spec.name, width
                        )));
                    }
                }
                match spec.list_order {
                    // Order carries meaning (the validator rotation): kept as
                    // declared, but a repeated item is still refused.
                    ListOrder::Declared => {
                        let mut seen: Vec<&Vec<u8>> = items.iter().collect();
                        seen.sort();
                        if seen.windows(2).any(|w| w[0] == w[1]) {
                            return Err(ConfigError::malformed(format!(
                                "field {} repeats an item",
                                spec.name
                            )));
                        }
                    }
                    ListOrder::SortedUnique => {
                        if items.windows(2).any(|w| w[0] >= w[1]) {
                            return Err(ConfigError::malformed(format!(
                                "field {} is not strictly ascending",
                                spec.name
                            )));
                        }
                    }
                }
            }
            if let (Some(width), Value::Bytes(b)) = (spec.item_width, value) {
                if b.len() != width {
                    return Err(ConfigError::malformed(format!(
                        "field {} is {} bytes, schema {n} requires {}",
                        spec.name,
                        b.len(),
                        width
                    )));
                }
            }
            Ok(())
        }
    }
}

fn decode_value(spec: &FieldSpec, tag: u8, raw: &[u8]) -> Result<Value, ConfigError> {
    let exact = |n: usize| -> Result<(), ConfigError> {
        if raw.len() == n {
            Ok(())
        } else {
            Err(ConfigError::malformed(format!(
                "field {} ({:#06x}) tag {} needs {} byte(s), has {}",
                spec.name,
                spec.id,
                tag,
                n,
                raw.len()
            )))
        }
    };
    let v = match tag {
        0 => {
            exact(0)?;
            Value::Absent
        }
        1 => {
            exact(8)?;
            Value::U64(u64::from_le_bytes(raw.try_into().expect("length checked")))
        }
        2 => {
            exact(16)?;
            Value::U128(u128::from_le_bytes(raw.try_into().expect("length checked")))
        }
        3 => {
            exact(1)?;
            match raw[0] {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                b => {
                    return Err(ConfigError::malformed(format!(
                        "field {} boolean byte {b:#04x} is neither 0 nor 1",
                        spec.name
                    )))
                }
            }
        }
        4 => Value::Bytes(raw.to_vec()),
        5 => {
            exact(1)?;
            Value::U8(raw[0])
        }
        6 => {
            exact(4)?;
            Value::U32(u32::from_le_bytes(raw.try_into().expect("length checked")))
        }
        7 => {
            exact(2)?;
            Value::U16(u16::from_le_bytes(raw.try_into().expect("length checked")))
        }
        8 => {
            exact(32)?;
            Value::Digest(raw.try_into().expect("length checked"))
        }
        9 => {
            let mut r = Reader { bytes: raw, pos: 0 };
            let count = r.u32()?;
            if count > MAX_LIST_ITEMS {
                return Err(ConfigError::malformed(format!(
                    "field {} declares {count} items, above the {MAX_LIST_ITEMS} bound",
                    spec.name
                )));
            }
            let mut items = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let len = r.u32()? as usize;
                items.push(r.take(len)?.to_vec());
            }
            if r.pos != raw.len() {
                return Err(ConfigError::malformed(format!(
                    "field {} has trailing bytes inside its list",
                    spec.name
                )));
            }
            Value::List(items)
        }
        other => {
            return Err(ConfigError::malformed(format!(
                "field {} ({:#06x}) has unknown tag {other}",
                spec.name, spec.id
            )))
        }
    };
    Ok(v)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ConfigError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or_else(|| ConfigError::malformed("truncated encoding"))?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, ConfigError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ConfigError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, ConfigError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
}
