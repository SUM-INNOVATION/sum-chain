//! Address-only construction of Employment (SRC-88X) issuer and credential
//! transactions.
//!
//! Every function here is pure. It takes the sender's ADDRESS (never a key),
//! the transaction context and the operation's fields, and returns an unsigned
//! [`TransactionV2`]. The caller signs `tx.signing_hash()` with its own key and
//! submits the signed transaction through the raw-submit RPC. Nothing here
//! signs, reads state or touches a mempool, and the executor stays the only
//! authority on whether the transaction is valid.
//!
//! One function serves both the node's no-key builder RPC and the client-side
//! `sumchain employment` commands, so the two produce the same bytes for the
//! same inputs. A client that signs only what it built itself, and refuses when
//! a builder's signing hash differs, never signs bytes it did not choose.
//!
//! It covers the three operations the deprecated custodial methods
//! (`employment_registerIssuer`, `employment_createCredential`,
//! `employment_revokeCredential`) build. Given the same explicit fields it
//! produces the same `RegisterIssuer` and `CreateEmployment` transactions those
//! methods build, byte for byte.
//!
//! ## Payload shapes
//!
//! `RegisterIssuer` and `CreateEmployment` carry the stored record itself
//! ([`EmploymentIssuerProfile`], [`EmploymentCredential`]); the executor stores
//! it as given. `RevokeEmployment` is decoded into a private struct inside the
//! executor's handler (`crates/state/src/employment_executor.rs`);
//! [`RevokeEmploymentPayload`] is its serializing mirror, field for field and
//! in order. The custodial method appends a timestamp and an optional reason
//! after those two fields, which the executor never reads; this builder does
//! not. The state crate's `employment_client_build` test executes every
//! operation built here.

use serde::{Deserialize, Serialize};

use crate::employment::{
    EmploymentCredential, EmploymentId, EmploymentIssuerClass, EmploymentIssuerProfile,
    EmploymentOperation, EmploymentStatus, EmploymentTxData, EmploymentType, IssuerStatus,
};
use crate::{Address, TransactionV2, TxPayload};

/// The transaction fields that do not depend on the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmploymentTxContext {
    pub chain_id: u64,
    /// The sender. The transaction must be signed by this address's key.
    pub from: Address,
    pub nonce: u64,
    pub fee: u128,
}

/// The fields of an employment credential the issuer chooses.
///
/// Everything else in the stored [`EmploymentCredential`] is fixed by
/// [`build_employment_tx`]: the id, the issuer address, an active status and
/// no revocation reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmploymentCredentialInput {
    /// Employee wallet address; also the transaction's recipient.
    pub employee_address: Address,
    /// Subject commitment; no personal data.
    pub employee_ref: [u8; 32],
    pub employer_ref: [u8; 32],
    pub tenure_commitment: [u8; 32],
    pub role_commitment: Option<[u8; 32]>,
    pub employment_type: EmploymentType,
    /// Milliseconds.
    pub valid_from: u64,
    /// Milliseconds; 0 = no expiry.
    pub expiry: u64,
    pub policy_id: [u8; 32],
    /// The issuer's registered display name, copied into the credential.
    pub issuer_name: String,
    /// The issuer's registered class, copied into the credential.
    pub issuer_class: EmploymentIssuerClass,
    /// Milliseconds; recorded as both `created_at` and `updated_at`.
    pub created_at: u64,
}

/// One Employment operation, with every field explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmploymentBuildOp {
    /// Register the sender as an employment issuer.
    RegisterIssuer {
        issuer_class: EmploymentIssuerClass,
        /// Institutional name; the chain refuses an empty one.
        display_name: String,
        issuer_commitment: [u8; 32],
        /// ISO 3166-1 alpha-2, optionally with a subdivision.
        jurisdiction_code: String,
        policy_id: [u8; 32],
        /// The chain height recorded as the registration height.
        registered_at_height: u64,
        /// Milliseconds; recorded as both `created_at` and `updated_at`.
        registered_at: u64,
    },
    /// Create an employment credential from the sender.
    CreateEmployment(EmploymentCredentialInput),
    /// Revoke a credential the sender issued.
    RevokeEmployment {
        employment_id: EmploymentId,
        /// The credential's employee; the transaction's recipient.
        employee_address: Address,
        revocation_ref: [u8; 32],
    },
}

/// Why an operation could not be built.
///
/// The messages name the field and the rule, never the value supplied, so an
/// error can be logged or shown without repeating what the caller passed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmploymentBuildError {
    #[error("display name must not be empty")]
    EmptyName,
    #[error("jurisdiction code must not be empty")]
    EmptyJurisdiction,
    #[error("issuer name must not be empty")]
    EmptyIssuerName,
    #[error("failed to encode the operation")]
    Encode,
}

/// An unsigned transaction and, for a create, the employment id it creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmploymentBuilt {
    pub tx: TransactionV2,
    pub employment_id: Option<EmploymentId>,
}

/// Payload of `RevokeEmployment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeEmploymentPayload {
    pub employment_id: EmploymentId,
    pub revocation_ref: [u8; 32],
}

/// The revocation reference the custodial `employment_revokeCredential` method
/// derives: BLAKE3 over the employment id, the timestamp (milliseconds,
/// little-endian) and, if given, the reason text.
///
/// The chain stores whatever reference the payload carries; this is a
/// convenience so a client can produce the same reference the custodial method
/// would have for the same inputs. The reason text is hashed only, never sent.
pub fn derive_revocation_ref(
    employment_id: &EmploymentId,
    timestamp_ms: u64,
    reason: Option<&str>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(employment_id);
    hasher.update(&timestamp_ms.to_le_bytes());
    if let Some(reason) = reason {
        hasher.update(reason.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EmploymentBuildError> {
    bincode::serialize(value).map_err(|_| EmploymentBuildError::Encode)
}

/// Build the unsigned transaction for `op`, sent by `ctx.from`.
///
/// Deterministic: the same context and operation always give the same bytes,
/// and so the same signing hash.
pub fn build_employment_tx(
    ctx: &EmploymentTxContext,
    op: &EmploymentBuildOp,
) -> Result<EmploymentBuilt, EmploymentBuildError> {
    let from = ctx.from;
    let mut employment_id = None;
    let (operation, data, recipient) = match op {
        EmploymentBuildOp::RegisterIssuer {
            issuer_class,
            display_name,
            issuer_commitment,
            jurisdiction_code,
            policy_id,
            registered_at_height,
            registered_at,
        } => {
            if display_name.trim().is_empty() {
                return Err(EmploymentBuildError::EmptyName);
            }
            if jurisdiction_code.trim().is_empty() {
                return Err(EmploymentBuildError::EmptyJurisdiction);
            }
            let profile = EmploymentIssuerProfile {
                issuer_address: from,
                issuer_class: *issuer_class,
                display_name: display_name.clone(),
                issuer_commitment: *issuer_commitment,
                jurisdiction_code: jurisdiction_code.clone(),
                policy_id: *policy_id,
                status: IssuerStatus::Active,
                registered_at_height: *registered_at_height,
                created_at: *registered_at,
                updated_at: *registered_at,
            };
            (EmploymentOperation::RegisterIssuer, encode(&profile)?, from)
        }
        EmploymentBuildOp::CreateEmployment(input) => {
            if input.issuer_name.trim().is_empty() {
                return Err(EmploymentBuildError::EmptyIssuerName);
            }
            let id = EmploymentCredential::generate_id(
                &input.employee_ref,
                &input.employer_ref,
                &input.tenure_commitment,
                ctx.nonce,
            );
            employment_id = Some(id);
            let credential = EmploymentCredential {
                employment_id: id,
                employee_address: input.employee_address,
                employee_ref: input.employee_ref,
                employer_ref: input.employer_ref,
                status: EmploymentStatus::Active,
                tenure_commitment: input.tenure_commitment,
                role_commitment: input.role_commitment,
                employment_type: input.employment_type,
                valid_from: input.valid_from,
                expiry: input.expiry,
                policy_id: input.policy_id,
                revocation_ref: None,
                issuer_address: from,
                issuer_name: input.issuer_name.clone(),
                issuer_class: input.issuer_class,
                created_at: input.created_at,
                updated_at: input.created_at,
            };
            (
                EmploymentOperation::CreateEmployment,
                encode(&credential)?,
                input.employee_address,
            )
        }
        EmploymentBuildOp::RevokeEmployment {
            employment_id,
            employee_address,
            revocation_ref,
        } => (
            EmploymentOperation::RevokeEmployment,
            encode(&RevokeEmploymentPayload {
                employment_id: *employment_id,
                revocation_ref: *revocation_ref,
            })?,
            *employee_address,
        ),
    };

    let tx = TransactionV2 {
        chain_id: ctx.chain_id,
        from,
        fee: ctx.fee,
        nonce: ctx.nonce,
        payload: TxPayload::Employment(EmploymentTxData {
            operation,
            data,
            recipient,
        }),
    };
    Ok(EmploymentBuilt { tx, employment_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic test addresses only; no key material in this crate's tests.
    fn ctx(from: Address) -> EmploymentTxContext {
        EmploymentTxContext {
            chain_id: 1337,
            from,
            nonce: 4,
            fee: 1_000_000,
        }
    }

    fn input(employee: Address) -> EmploymentCredentialInput {
        EmploymentCredentialInput {
            employee_address: employee,
            employee_ref: [0x31; 32],
            employer_ref: [0x32; 32],
            tenure_commitment: [0x33; 32],
            role_commitment: Some([0x34; 32]),
            employment_type: EmploymentType::FullTime,
            valid_from: 1_000,
            expiry: 0,
            policy_id: [0x35; 32],
            issuer_name: "Example Employer Inc".to_string(),
            issuer_class: EmploymentIssuerClass::Employer,
            created_at: 2_000,
        }
    }

    fn employment(tx: &TransactionV2) -> &EmploymentTxData {
        match &tx.payload {
            TxPayload::Employment(d) => d,
            other => panic!("not an Employment payload: {other:?}"),
        }
    }

    fn register(name: &str, jurisdiction: &str) -> EmploymentBuildOp {
        EmploymentBuildOp::RegisterIssuer {
            issuer_class: EmploymentIssuerClass::Employer,
            display_name: name.to_string(),
            issuer_commitment: [0x41; 32],
            jurisdiction_code: jurisdiction.to_string(),
            policy_id: [0x42; 32],
            registered_at_height: 77,
            registered_at: 3_000,
        }
    }

    #[test]
    fn building_is_deterministic() {
        let from = Address::new([0x11; 20]);
        let op = EmploymentBuildOp::CreateEmployment(input(Address::new([0x22; 20])));
        let a = build_employment_tx(&ctx(from), &op).unwrap();
        let b = build_employment_tx(&ctx(from), &op).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.tx.signing_hash(), b.tx.signing_hash());
    }

    #[test]
    fn a_registration_records_the_sender_as_an_active_issuer() {
        let from = Address::new([0x11; 20]);
        let built =
            build_employment_tx(&ctx(from), &register("Example Employer Inc", "US-CA")).unwrap();
        let d = employment(&built.tx);
        assert_eq!(d.operation, EmploymentOperation::RegisterIssuer);
        assert_eq!(d.recipient, from);
        let profile: EmploymentIssuerProfile = bincode::deserialize(&d.data).unwrap();
        assert_eq!(profile.issuer_address, from);
        assert_eq!(profile.status, IssuerStatus::Active);
        assert_eq!(profile.registered_at_height, 77);
        assert_eq!((profile.created_at, profile.updated_at), (3_000, 3_000));
        assert_eq!(built.employment_id, None);
    }

    #[test]
    fn a_created_credential_uses_the_wire_id_and_names_the_employee() {
        let from = Address::new([0x11; 20]);
        let employee = Address::new([0x22; 20]);
        let built = build_employment_tx(
            &ctx(from),
            &EmploymentBuildOp::CreateEmployment(input(employee)),
        )
        .unwrap();
        let d = employment(&built.tx);
        assert_eq!(d.operation, EmploymentOperation::CreateEmployment);
        assert_eq!(d.recipient, employee);
        let cred: EmploymentCredential = bincode::deserialize(&d.data).unwrap();
        assert_eq!(cred.issuer_address, from);
        assert_eq!(cred.status, EmploymentStatus::Active);
        assert_eq!(cred.revocation_ref, None);
        assert_eq!((cred.created_at, cred.updated_at), (2_000, 2_000));
        let expected = EmploymentCredential::generate_id(&[0x31; 32], &[0x32; 32], &[0x33; 32], 4);
        assert_eq!(cred.employment_id, expected);
        assert_eq!(built.employment_id, Some(expected));
    }

    #[test]
    fn the_nonce_changes_the_employment_id() {
        let from = Address::new([0x11; 20]);
        let op = EmploymentBuildOp::CreateEmployment(input(Address::new([0x22; 20])));
        let mut c = ctx(from);
        let a = build_employment_tx(&c, &op).unwrap().employment_id;
        c.nonce += 1;
        let b = build_employment_tx(&c, &op).unwrap().employment_id;
        assert_ne!(a, b);
    }

    #[test]
    fn the_revoke_payload_mirrors_the_executor_positionally() {
        let p = RevokeEmploymentPayload {
            employment_id: [7; 32],
            revocation_ref: [8; 32],
        };
        let bytes = bincode::serialize(&p).unwrap();
        assert_eq!(bytes.len(), 64, "the id, then the reference");
        assert_eq!(&bytes[..32], &[7u8; 32]);
        assert_eq!(&bytes[32..], &[8u8; 32]);

        let from = Address::new([0x11; 20]);
        let employee = Address::new([0x22; 20]);
        let built = build_employment_tx(
            &ctx(from),
            &EmploymentBuildOp::RevokeEmployment {
                employment_id: [7; 32],
                employee_address: employee,
                revocation_ref: [8; 32],
            },
        )
        .unwrap();
        let d = employment(&built.tx);
        assert_eq!(d.operation, EmploymentOperation::RevokeEmployment);
        assert_eq!(
            d.recipient, employee,
            "the employee keeps the revoked token"
        );
        assert_eq!(d.data, bytes);
    }

    #[test]
    fn the_revocation_ref_covers_id_time_and_reason() {
        let id = [7u8; 32];
        let base = derive_revocation_ref(&id, 5, None);
        assert_eq!(base, derive_revocation_ref(&id, 5, None));
        assert_ne!(base, derive_revocation_ref(&id, 6, None));
        assert_ne!(base, derive_revocation_ref(&[8u8; 32], 5, None));
        assert_ne!(base, derive_revocation_ref(&id, 5, Some("ended")));
        let mut h = blake3::Hasher::new();
        h.update(&id);
        h.update(&5u64.to_le_bytes());
        h.update(b"ended");
        assert_eq!(
            derive_revocation_ref(&id, 5, Some("ended")),
            *h.finalize().as_bytes()
        );
    }

    #[test]
    fn registration_refuses_empty_names() {
        let c = ctx(Address::new([0x11; 20]));
        assert_eq!(
            build_employment_tx(&c, &register(" ", "US")).unwrap_err(),
            EmploymentBuildError::EmptyName
        );
        assert_eq!(
            build_employment_tx(&c, &register("Example Employer Inc", "")).unwrap_err(),
            EmploymentBuildError::EmptyJurisdiction
        );
        let mut i = input(Address::new([0x22; 20]));
        i.issuer_name = String::new();
        assert_eq!(
            build_employment_tx(&c, &EmploymentBuildOp::CreateEmployment(i)).unwrap_err(),
            EmploymentBuildError::EmptyIssuerName
        );
    }

    /// Every variant is fieldless, so no message can carry a value the caller
    /// passed. A field added to a variant would have to be added to this list
    /// too, which is where a reviewer sees it.
    #[test]
    fn error_messages_are_fixed_strings() {
        let all = [
            EmploymentBuildError::EmptyName,
            EmploymentBuildError::EmptyJurisdiction,
            EmploymentBuildError::EmptyIssuerName,
            EmploymentBuildError::Encode,
        ];
        for e in all {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert_eq!(s, e.clone().to_string());
        }
    }
}
