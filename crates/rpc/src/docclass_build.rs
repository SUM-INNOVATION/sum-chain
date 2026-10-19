//! Conversion from the `docclass_buildTransaction` request shape to
//! [`DocClassBuildOp`], shared by the node's builder and the `sumchain
//! docclass` client commands.
//!
//! Both sides run the same conversion and then the same
//! [`build_docclass_tx`](sumchain_primitives::docclass_build::build_docclass_tx),
//! so for the same explicit request they produce the same bytes. The node's
//! builder resolves omitted fields from its own state first; a client that
//! compares the builder's signing hash with its own passes every field
//! explicitly.
//!
//! Error messages name the field and the rule, never the value supplied.

use sumchain_primitives::docclass::{
    CredentialAttribute, CredentialMetadata, DocClassIssuer, DocClassIssuerStatus,
    DocClassIssuerType, DocSubcode, IssuerKey, KeyType, RevocationReason,
};
use sumchain_primitives::docclass_build::{AcademicCredentialInput, DocClassBuildOp};
use sumchain_primitives::Address;

use crate::types::{
    DocClassBuildOpRequest, DocClassCredentialMetadataRecord, DocClassIssuerKeyRecord,
    DocClassIssuerRecord,
};

/// Values used when the request omits them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocClassRequestDefaults {
    /// Milliseconds; used for an omitted `registered_at` or `issued_at`.
    pub now_ms: u64,
    /// The sender's registered issuer name, if it has a record.
    pub issuer_name: Option<String>,
    /// The sender's first registered jurisdiction, if it has a record.
    pub issuer_jurisdiction: Option<String>,
}

/// Parse a 32-byte hex value, `0x` optional.
pub fn parse_hex32(field: &str, s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|_| format!("{field}: expected 32 bytes of hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{field}: expected 32 bytes of hex"))
}

/// Parse a base58 (or hex) address.
pub fn parse_address(field: &str, s: &str) -> Result<Address, String> {
    Address::from_base58(s)
        .or_else(|_| Address::from_hex(s))
        .map_err(|_| format!("{field}: invalid address"))
}

fn subcode(field: &str, code: u16) -> Result<DocSubcode, String> {
    DocSubcode::from_u16(code).ok_or_else(|| format!("{field}: unknown subcode"))
}

fn reason(code: u8) -> Result<RevocationReason, String> {
    RevocationReason::from_u8(code).ok_or_else(|| "reason: unknown revocation reason".to_string())
}

fn issuer_type(s: &str) -> Result<DocClassIssuerType, String> {
    Ok(match s {
        "Government" => DocClassIssuerType::Government,
        "Educational" => DocClassIssuerType::Educational,
        "Professional" => DocClassIssuerType::Professional,
        "Corporate" => DocClassIssuerType::Corporate,
        "Healthcare" => DocClassIssuerType::Healthcare,
        "Legal" => DocClassIssuerType::Legal,
        "SelfSovereign" => DocClassIssuerType::SelfSovereign,
        _ => return Err("issuer.issuer_type: unknown issuer type".to_string()),
    })
}

fn issuer_status(s: &str) -> Result<DocClassIssuerStatus, String> {
    Ok(match s {
        "Active" => DocClassIssuerStatus::Active,
        "Suspended" => DocClassIssuerStatus::Suspended,
        "Revoked" => DocClassIssuerStatus::Revoked,
        _ => return Err("issuer.status: unknown issuer status".to_string()),
    })
}

fn key_type(field: &str, s: &str) -> Result<KeyType, String> {
    Ok(match s {
        "Ed25519" => KeyType::Ed25519,
        "X25519" => KeyType::X25519,
        "Secp256k1" => KeyType::Secp256k1,
        _ => return Err(format!("{field}: unknown key type")),
    })
}

/// Convert an issuer key record.
pub fn issuer_key(field: &str, k: &DocClassIssuerKeyRecord) -> Result<IssuerKey, String> {
    Ok(IssuerKey {
        key_id: k.key_id.clone(),
        public_key: parse_hex32(&format!("{field}.public_key"), &k.public_key)?,
        key_type: key_type(&format!("{field}.key_type"), &k.key_type)?,
        added_at: k.added_at,
        expires_at: k.expires_at,
        active: k.active,
        is_primary: k.is_primary,
    })
}

/// Convert a complete issuer record.
pub fn issuer_record(r: &DocClassIssuerRecord) -> Result<DocClassIssuer, String> {
    let mut keys = Vec::with_capacity(r.keys.len());
    for (i, k) in r.keys.iter().enumerate() {
        keys.push(issuer_key(&format!("issuer.keys[{i}]"), k)?);
    }
    let mut authorized_subcodes = Vec::with_capacity(r.authorized_subcodes.len());
    for code in &r.authorized_subcodes {
        authorized_subcodes.push(subcode("issuer.authorized_subcodes", *code)?);
    }
    Ok(DocClassIssuer {
        address: parse_address("issuer.address", &r.address)?,
        name: r.name.clone(),
        issuer_type: issuer_type(&r.issuer_type)?,
        jurisdictions: r.jurisdictions.clone(),
        authorized_subcodes,
        keys,
        registered_at: r.registered_at,
        updated_at: r.updated_at,
        status: issuer_status(&r.status)?,
        stake_amount: r.stake_amount,
        metadata: r.metadata.clone(),
    })
}

fn metadata(m: &DocClassCredentialMetadataRecord) -> CredentialMetadata {
    CredentialMetadata {
        title: m.title.clone(),
        credential_type: m.credential_type.clone(),
        program: m.program.clone(),
        issue_date: m.issue_date.clone(),
        completion_date: m.completion_date.clone(),
        attributes: m
            .attributes
            .iter()
            .map(|a| CredentialAttribute {
                name: a.name.clone(),
                value: a.value.clone(),
            })
            .collect(),
    }
}

/// Convert a request operation into the builder's explicit operation.
pub fn op_from_request(
    op: &DocClassBuildOpRequest,
    defaults: &DocClassRequestDefaults,
) -> Result<DocClassBuildOp, String> {
    Ok(match op {
        DocClassBuildOpRequest::RegisterAcademicIssuer {
            name,
            jurisdiction,
            subcodes,
            stake_amount,
            public_key,
            registered_at,
            metadata,
        } => {
            let mut parsed = Vec::with_capacity(subcodes.len());
            for code in subcodes {
                parsed.push(subcode("subcodes", *code)?);
            }
            DocClassBuildOp::RegisterAcademicIssuer {
                name: name.clone(),
                jurisdiction: jurisdiction.clone(),
                subcodes: parsed,
                stake_amount: *stake_amount,
                public_key: parse_hex32("public_key", public_key)?,
                registered_at: registered_at.unwrap_or(defaults.now_ms),
                metadata: metadata.clone(),
            }
        }
        DocClassBuildOpRequest::IssueAcademicCredential {
            holder_address,
            subcode: code,
            subject_commitment,
            schema_hash,
            content_commitment,
            institution_id,
            jurisdiction,
            metadata: m,
            issued_at,
            valid_from,
            expires_at,
            payload_hash,
            payload_hint,
        } => {
            let institution_id = institution_id
                .clone()
                .or_else(|| defaults.issuer_name.clone())
                .ok_or_else(|| {
                    "institution_id: required when the sender has no issuer record".to_string()
                })?;
            let jurisdiction = jurisdiction
                .clone()
                .or_else(|| defaults.issuer_jurisdiction.clone())
                .ok_or_else(|| {
                    "jurisdiction: required when the sender has no issuer record".to_string()
                })?;
            DocClassBuildOp::IssueAcademicCredential(AcademicCredentialInput {
                holder: parse_address("holder_address", holder_address)?,
                subcode: subcode("subcode", *code)?,
                subject_commitment: parse_hex32("subject_commitment", subject_commitment)?,
                institution_id,
                jurisdiction,
                schema_hash: parse_hex32("schema_hash", schema_hash)?,
                content_commitment: parse_hex32("content_commitment", content_commitment)?,
                metadata: metadata(m),
                issued_at: issued_at.unwrap_or(defaults.now_ms),
                valid_from: *valid_from,
                expires_at: *expires_at,
                payload_hash: match payload_hash {
                    Some(h) => Some(parse_hex32("payload_hash", h)?),
                    None => None,
                },
                payload_hint: payload_hint.clone(),
            })
        }
        DocClassBuildOpRequest::RevokeCredential {
            credential_id,
            reason: r,
        } => DocClassBuildOp::RevokeCredential {
            credential_id: parse_hex32("credential_id", credential_id)?,
            reason: reason(*r)?,
        },
        DocClassBuildOpRequest::SuspendCredential {
            credential_id,
            reason: r,
        } => DocClassBuildOp::SuspendCredential {
            credential_id: parse_hex32("credential_id", credential_id)?,
            reason: reason(*r)?,
        },
        DocClassBuildOpRequest::ReactivateCredential { credential_id } => {
            DocClassBuildOp::ReactivateCredential {
                credential_id: parse_hex32("credential_id", credential_id)?,
            }
        }
        DocClassBuildOpRequest::SupersedeCredential {
            old_credential_id,
            new_credential_id,
        } => DocClassBuildOp::SupersedeCredential {
            old_credential_id: parse_hex32("old_credential_id", old_credential_id)?,
            new_credential_id: parse_hex32("new_credential_id", new_credential_id)?,
        },
        DocClassBuildOpRequest::UpdateIssuer { issuer } => DocClassBuildOp::UpdateIssuer {
            issuer: issuer_record(issuer)?,
        },
        DocClassBuildOpRequest::RotateIssuerKey {
            new_key,
            old_key_id,
        } => DocClassBuildOp::RotateIssuerKey {
            new_key: issuer_key("new_key", new_key)?,
            old_key_id: old_key_id.clone(),
        },
        DocClassBuildOpRequest::DeactivateIssuer { issuer_address } => {
            DocClassBuildOp::DeactivateIssuer {
                issuer_address: parse_address("issuer_address", issuer_address)?,
            }
        }
    })
}

/// The same operation with every field the node would default made explicit,
/// so a builder given it has nothing left to choose.
pub fn make_explicit(
    op: &DocClassBuildOpRequest,
    defaults: &DocClassRequestDefaults,
) -> Result<DocClassBuildOpRequest, String> {
    let mut op = op.clone();
    match &mut op {
        DocClassBuildOpRequest::RegisterAcademicIssuer { registered_at, .. } => {
            registered_at.get_or_insert(defaults.now_ms);
        }
        DocClassBuildOpRequest::IssueAcademicCredential {
            institution_id,
            jurisdiction,
            issued_at,
            ..
        } => {
            if institution_id.is_none() {
                *institution_id = Some(defaults.issuer_name.clone().ok_or_else(|| {
                    "institution_id: required when the sender has no issuer record".to_string()
                })?);
            }
            if jurisdiction.is_none() {
                *jurisdiction = Some(defaults.issuer_jurisdiction.clone().ok_or_else(|| {
                    "jurisdiction: required when the sender has no issuer record".to_string()
                })?);
            }
            issued_at.get_or_insert(defaults.now_ms);
        }
        _ => {}
    }
    Ok(op)
}

/// Whether converting `op` needs the sender's issuer record.
pub fn needs_issuer_record(op: &DocClassBuildOpRequest) -> bool {
    matches!(
        op,
        DocClassBuildOpRequest::IssueAcademicCredential {
            institution_id: None,
            ..
        } | DocClassBuildOpRequest::IssueAcademicCredential {
            jurisdiction: None,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_errors_name_the_field_not_the_value() {
        let e = parse_hex32("credential_id", "0xzz99secretlooking").unwrap_err();
        assert_eq!(e, "credential_id: expected 32 bytes of hex");
        let e = parse_hex32("credential_id", "abcd").unwrap_err();
        assert_eq!(e, "credential_id: expected 32 bytes of hex");
        let e = parse_address("holder_address", "notanaddress").unwrap_err();
        assert_eq!(e, "holder_address: invalid address");
    }

    #[test]
    fn explicit_fills_only_what_is_missing() {
        let d = DocClassRequestDefaults {
            now_ms: 5,
            issuer_name: Some("Example Institute".into()),
            issuer_jurisdiction: Some("US".into()),
        };
        let op = DocClassBuildOpRequest::RegisterAcademicIssuer {
            name: "X".into(),
            jurisdiction: "US".into(),
            subcodes: vec![811],
            stake_amount: 0,
            public_key: "00".repeat(32),
            registered_at: Some(9),
            metadata: None,
        };
        assert_eq!(
            make_explicit(&op, &d).unwrap(),
            op,
            "an explicit time is kept"
        );
        let DocClassBuildOpRequest::RegisterAcademicIssuer { registered_at, .. } = make_explicit(
            &DocClassBuildOpRequest::RegisterAcademicIssuer {
                name: "X".into(),
                jurisdiction: "US".into(),
                subcodes: vec![811],
                stake_amount: 0,
                public_key: "00".repeat(32),
                registered_at: None,
                metadata: None,
            },
            &d,
        )
        .unwrap() else {
            unreachable!()
        };
        assert_eq!(registered_at, Some(5));
    }
}
