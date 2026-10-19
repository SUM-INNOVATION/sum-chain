//! Address-only construction of DocClass issuer and academic-credential
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
//! `sumchain docclass` commands, so the two produce the same bytes for the same
//! inputs. A client that signs only what it built itself, and refuses when a
//! builder's signing hash differs, never signs bytes it did not choose.
//!
//! ## Payload shapes
//!
//! The executor decodes each revocation and issuer-lifecycle operation into a
//! private struct declared inside its handler
//! (`crates/state/src/docclass_executor.rs`). The `*Payload` structs below are
//! the serializing mirrors, field for field and in order: bincode structs are
//! positional, so a reordered field is a different payload. The state crate's
//! `docclass_client_build` test executes every one of them.
//!
//! ## Credentials
//!
//! An issued credential carries an all-zero `issuer_signature` and an EMPTY
//! `issuer_key_id`. The chain cannot check an embedded credential signature, and
//! at or above the signature-unsupported activation it refuses a credential that
//! claims one (ACTIVATION-AUDIT row AU-33). The empty claim is admitted on both
//! sides of that height. The credential id is
//! [`generate_credential_id`](crate::docclass::generate_credential_id) over the
//! issuer, subcode, subject commitment and the transaction's nonce.

use serde::{Deserialize, Serialize};

use crate::docclass::{
    generate_credential_id, AcademicCredential, CredentialId, CredentialMetadata, DocClassIssuer,
    DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocClassTxData, DocSubcode,
    IssuerKey, KeyType, RevocationReason, RevocationStatus,
};
use crate::{Address, TransactionV2, TxPayload};

/// Key id given to the key an academic issuer registers with.
pub const REGISTERED_ISSUER_KEY_ID: &str = "primary";

/// The transaction fields that do not depend on the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocClassTxContext {
    pub chain_id: u64,
    /// The sender. The transaction must be signed by this address's key.
    pub from: Address,
    pub nonce: u64,
    pub fee: u128,
}

/// The fields of an academic credential that the issuer chooses.
///
/// Everything else in the stored [`AcademicCredential`] is fixed by
/// [`build_docclass_tx`]: the id, the issuer, an empty signature claim and an
/// active, unsuperseded status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcademicCredentialInput {
    /// Subject wallet address; also the transaction's recipient.
    pub holder: Address,
    /// 810 (transcript), 811 (diploma) or 812 (enrollment verification).
    pub subcode: DocSubcode,
    pub subject_commitment: [u8; 32],
    pub institution_id: String,
    /// ISO 3166-1 alpha-2.
    pub jurisdiction: String,
    pub schema_hash: [u8; 32],
    pub content_commitment: [u8; 32],
    pub metadata: CredentialMetadata,
    /// Milliseconds, the chain's timestamp unit.
    pub issued_at: u64,
    pub valid_from: u64,
    /// 0 = no expiry.
    pub expires_at: u64,
    pub payload_hash: Option<[u8; 32]>,
    pub payload_hint: Option<String>,
}

/// One DocClass operation, with every field explicit.
// Built once per transaction, so the variants' size difference costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocClassBuildOp {
    /// Register the sender as an educational issuer for academic subcodes.
    RegisterAcademicIssuer {
        name: String,
        /// ISO 3166-1 alpha-2.
        jurisdiction: String,
        /// Non-empty, each one of 810, 811 or 812, no repeats.
        subcodes: Vec<DocSubcode>,
        stake_amount: u128,
        /// The sender's Ed25519 public key. It must derive to the sender's
        /// address, so the registry never records a key the sender does not
        /// hold.
        public_key: [u8; 32],
        /// Milliseconds.
        registered_at: u64,
        metadata: Option<String>,
    },
    /// Issue an academic credential from the sender.
    IssueAcademicCredential(AcademicCredentialInput),
    RevokeCredential {
        credential_id: CredentialId,
        reason: RevocationReason,
    },
    SuspendCredential {
        credential_id: CredentialId,
        reason: RevocationReason,
    },
    ReactivateCredential {
        credential_id: CredentialId,
    },
    SupersedeCredential {
        old_credential_id: CredentialId,
        new_credential_id: CredentialId,
    },
    /// Replace the sender's issuer record with `issuer`. Which fields the chain
    /// honours depends on its activation state; the executor decides.
    UpdateIssuer {
        issuer: DocClassIssuer,
    },
    RotateIssuerKey {
        new_key: IssuerKey,
        old_key_id: String,
    },
    /// Deactivate `issuer_address`: the sender itself, or any issuer when the
    /// sender is the chain's DocClass admin.
    DeactivateIssuer {
        issuer_address: Address,
    },
}

/// Why an operation could not be built.
///
/// The messages name the field and the rule, never the value supplied, so an
/// error can be logged or shown without repeating what the caller passed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocClassBuildError {
    #[error("jurisdiction must be two ASCII letters (ISO 3166-1 alpha-2)")]
    Jurisdiction,
    #[error("at least one authorized subcode is required")]
    NoSubcodes,
    #[error("academic issuers may hold only subcodes 810, 811 and 812")]
    NotAcademicSubcode,
    #[error("an authorized subcode is listed more than once")]
    DuplicateSubcode,
    #[error("the public key does not derive to the sender's address")]
    PublicKeyNotSender,
    #[error("the issuer record's address is not the sender's")]
    IssuerNotSender,
    #[error("the new key id must be non-empty and differ from the old key id")]
    KeyId,
    #[error("issuer name must not be empty")]
    EmptyName,
    #[error("failed to encode the operation")]
    Encode,
}

/// An unsigned transaction and, for an issue, the credential id it creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocClassBuilt {
    pub tx: TransactionV2,
    pub credential_id: Option<CredentialId>,
}

/// Payload of `RevokeCredential` and `SuspendCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReasonPayload {
    pub credential_id: CredentialId,
    pub reason: RevocationReason,
}

/// Payload of `ReactivateCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIdPayload {
    pub credential_id: CredentialId,
}

/// Payload of `SupersedeCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersedePayload {
    pub old_credential_id: CredentialId,
    pub new_credential_id: CredentialId,
}

/// Payload of `RotateIssuerKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRotateKeyPayload {
    pub new_key: IssuerKey,
    pub old_key_id: String,
}

/// Payload of `DeactivateIssuer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeactivateIssuerPayload {
    pub issuer_address: Address,
}

fn is_academic_issuable(subcode: DocSubcode) -> bool {
    matches!(
        subcode,
        DocSubcode::AcademicTranscript | DocSubcode::Diploma | DocSubcode::EnrollmentVerification
    )
}

fn check_jurisdiction(j: &str) -> Result<(), DocClassBuildError> {
    if j.len() == 2 && j.bytes().all(|b| b.is_ascii_alphabetic()) {
        Ok(())
    } else {
        Err(DocClassBuildError::Jurisdiction)
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, DocClassBuildError> {
    bincode::serialize(value).map_err(|_| DocClassBuildError::Encode)
}

/// Build the unsigned transaction for `op`, sent by `ctx.from`.
///
/// Deterministic: the same context and operation always give the same bytes,
/// and so the same signing hash.
pub fn build_docclass_tx(
    ctx: &DocClassTxContext,
    op: &DocClassBuildOp,
) -> Result<DocClassBuilt, DocClassBuildError> {
    let from = ctx.from;
    let mut credential_id = None;
    let (operation, subcode, data, recipient) = match op {
        DocClassBuildOp::RegisterAcademicIssuer {
            name,
            jurisdiction,
            subcodes,
            stake_amount,
            public_key,
            registered_at,
            metadata,
        } => {
            if name.trim().is_empty() {
                return Err(DocClassBuildError::EmptyName);
            }
            check_jurisdiction(jurisdiction)?;
            if subcodes.is_empty() {
                return Err(DocClassBuildError::NoSubcodes);
            }
            if !subcodes.iter().all(|s| is_academic_issuable(*s)) {
                return Err(DocClassBuildError::NotAcademicSubcode);
            }
            for (i, s) in subcodes.iter().enumerate() {
                if subcodes[..i].contains(s) {
                    return Err(DocClassBuildError::DuplicateSubcode);
                }
            }
            if Address::from_public_key(public_key) != from {
                return Err(DocClassBuildError::PublicKeyNotSender);
            }
            let issuer = DocClassIssuer {
                address: from,
                name: name.clone(),
                issuer_type: DocClassIssuerType::Educational,
                jurisdictions: vec![jurisdiction.clone()],
                authorized_subcodes: subcodes.clone(),
                keys: vec![IssuerKey {
                    key_id: REGISTERED_ISSUER_KEY_ID.to_string(),
                    public_key: *public_key,
                    key_type: KeyType::Ed25519,
                    added_at: *registered_at,
                    expires_at: 0,
                    active: true,
                    is_primary: true,
                }],
                registered_at: *registered_at,
                updated_at: *registered_at,
                status: DocClassIssuerStatus::Active,
                stake_amount: *stake_amount,
                metadata: metadata.clone(),
            };
            (
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                encode(&issuer)?,
                from,
            )
        }
        DocClassBuildOp::IssueAcademicCredential(input) => {
            if !is_academic_issuable(input.subcode) {
                return Err(DocClassBuildError::NotAcademicSubcode);
            }
            check_jurisdiction(&input.jurisdiction)?;
            let id =
                generate_credential_id(&from, input.subcode, &input.subject_commitment, ctx.nonce);
            credential_id = Some(id);
            let credential = AcademicCredential {
                credential_id: id,
                subject_address: input.holder,
                subcode: input.subcode,
                subject_commitment: input.subject_commitment,
                issuer: from,
                institution_id: input.institution_id.clone(),
                jurisdiction: input.jurisdiction.clone(),
                schema_hash: input.schema_hash,
                content_commitment: input.content_commitment,
                metadata: input.metadata.clone(),
                issued_at: input.issued_at,
                valid_from: input.valid_from,
                expires_at: input.expires_at,
                payload_hash: input.payload_hash,
                payload_hint: input.payload_hint.clone(),
                encryption_meta: None,
                issuer_signature: [0u8; 64],
                issuer_key_id: String::new(),
                revocation_status: RevocationStatus::Active,
                superseded_by: None,
            };
            (
                DocClassOperation::IssueCredential,
                input.subcode,
                encode(&credential)?,
                input.holder,
            )
        }
        DocClassBuildOp::RevokeCredential {
            credential_id,
            reason,
        } => (
            DocClassOperation::RevokeCredential,
            DocSubcode::Revocation,
            encode(&CredentialReasonPayload {
                credential_id: *credential_id,
                reason: *reason,
            })?,
            from,
        ),
        DocClassBuildOp::SuspendCredential {
            credential_id,
            reason,
        } => (
            DocClassOperation::SuspendCredential,
            DocSubcode::Revocation,
            encode(&CredentialReasonPayload {
                credential_id: *credential_id,
                reason: *reason,
            })?,
            from,
        ),
        DocClassBuildOp::ReactivateCredential { credential_id } => (
            DocClassOperation::ReactivateCredential,
            DocSubcode::Revocation,
            encode(&CredentialIdPayload {
                credential_id: *credential_id,
            })?,
            from,
        ),
        DocClassBuildOp::SupersedeCredential {
            old_credential_id,
            new_credential_id,
        } => (
            DocClassOperation::SupersedeCredential,
            DocSubcode::Revocation,
            encode(&SupersedePayload {
                old_credential_id: *old_credential_id,
                new_credential_id: *new_credential_id,
            })?,
            from,
        ),
        DocClassBuildOp::UpdateIssuer { issuer } => {
            if issuer.address != from {
                return Err(DocClassBuildError::IssuerNotSender);
            }
            if issuer.name.trim().is_empty() {
                return Err(DocClassBuildError::EmptyName);
            }
            (
                DocClassOperation::UpdateIssuer,
                DocSubcode::IssuerRegistry,
                encode(issuer)?,
                from,
            )
        }
        DocClassBuildOp::RotateIssuerKey {
            new_key,
            old_key_id,
        } => {
            if new_key.key_id.is_empty() || new_key.key_id == *old_key_id {
                return Err(DocClassBuildError::KeyId);
            }
            (
                DocClassOperation::RotateIssuerKey,
                DocSubcode::IssuerRegistry,
                encode(&IssuerRotateKeyPayload {
                    new_key: new_key.clone(),
                    old_key_id: old_key_id.clone(),
                })?,
                from,
            )
        }
        DocClassBuildOp::DeactivateIssuer { issuer_address } => (
            DocClassOperation::DeactivateIssuer,
            DocSubcode::IssuerRegistry,
            encode(&DeactivateIssuerPayload {
                issuer_address: *issuer_address,
            })?,
            *issuer_address,
        ),
    };

    let tx = TransactionV2 {
        chain_id: ctx.chain_id,
        from,
        fee: ctx.fee,
        nonce: ctx.nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation,
            subcode,
            data,
            recipient,
        }),
    };
    Ok(DocClassBuilt { tx, credential_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docclass::CredentialAttribute;

    // Synthetic test addresses only; no key material in this crate's tests.
    fn ctx(from: Address) -> DocClassTxContext {
        DocClassTxContext {
            chain_id: 1337,
            from,
            nonce: 4,
            fee: 1_000_000,
        }
    }

    fn input(holder: Address) -> AcademicCredentialInput {
        AcademicCredentialInput {
            holder,
            subcode: DocSubcode::Diploma,
            subject_commitment: [0x31; 32],
            institution_id: "Example Institute".to_string(),
            jurisdiction: "US".to_string(),
            schema_hash: [0x32; 32],
            content_commitment: [0x33; 32],
            metadata: CredentialMetadata {
                title: "Bachelor of Science".to_string(),
                credential_type: "diploma".to_string(),
                program: None,
                issue_date: "2026-01-01".to_string(),
                completion_date: None,
                attributes: vec![CredentialAttribute {
                    name: "honors".to_string(),
                    value: "none".to_string(),
                }],
            },
            issued_at: 1_000,
            valid_from: 1_000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
        }
    }

    fn docclass(tx: &TransactionV2) -> &DocClassTxData {
        match &tx.payload {
            TxPayload::DocClass(d) => d,
            other => panic!("not a DocClass payload: {other:?}"),
        }
    }

    #[test]
    fn building_is_deterministic() {
        let from = Address::new([0x11; 20]);
        let op = DocClassBuildOp::IssueAcademicCredential(input(Address::new([0x22; 20])));
        let a = build_docclass_tx(&ctx(from), &op).unwrap();
        let b = build_docclass_tx(&ctx(from), &op).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.tx.signing_hash(), b.tx.signing_hash());
    }

    #[test]
    fn an_issued_credential_claims_no_signature_and_uses_the_wire_id() {
        let from = Address::new([0x11; 20]);
        let holder = Address::new([0x22; 20]);
        let built = build_docclass_tx(
            &ctx(from),
            &DocClassBuildOp::IssueAcademicCredential(input(holder)),
        )
        .unwrap();
        let d = docclass(&built.tx);
        assert_eq!(d.operation, DocClassOperation::IssueCredential);
        assert_eq!(d.subcode, DocSubcode::Diploma);
        assert_eq!(d.recipient, holder);
        let cred: AcademicCredential = bincode::deserialize(&d.data).unwrap();
        assert_eq!(cred.issuer, from);
        assert_eq!(cred.issuer_signature, [0u8; 64]);
        assert!(cred.issuer_key_id.is_empty());
        let expected = generate_credential_id(&from, DocSubcode::Diploma, &[0x31; 32], 4);
        assert_eq!(cred.credential_id, expected);
        assert_eq!(built.credential_id, Some(expected));
    }

    #[test]
    fn the_nonce_changes_the_credential_id() {
        let from = Address::new([0x11; 20]);
        let op = DocClassBuildOp::IssueAcademicCredential(input(Address::new([0x22; 20])));
        let mut c = ctx(from);
        let a = build_docclass_tx(&c, &op).unwrap().credential_id;
        c.nonce += 1;
        let b = build_docclass_tx(&c, &op).unwrap().credential_id;
        assert_ne!(a, b);
    }

    #[test]
    fn payload_mirrors_round_trip_positionally() {
        let p = CredentialReasonPayload {
            credential_id: [7; 32],
            reason: RevocationReason::KeyCompromise,
        };
        let bytes = bincode::serialize(&p).unwrap();
        assert_eq!(bytes.len(), 32 + 4, "id then the reason's u32 variant tag");
        assert_eq!(&bytes[..32], &[7u8; 32]);
        let back: CredentialReasonPayload = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, p);

        let s = SupersedePayload {
            old_credential_id: [1; 32],
            new_credential_id: [2; 32],
        };
        let bytes = bincode::serialize(&s).unwrap();
        assert_eq!(&bytes[..32], &[1u8; 32], "old id first");
        assert_eq!(&bytes[32..], &[2u8; 32]);
    }

    #[test]
    fn registration_refuses_a_key_that_is_not_the_senders() {
        let op = DocClassBuildOp::RegisterAcademicIssuer {
            name: "Example Institute".to_string(),
            jurisdiction: "US".to_string(),
            subcodes: vec![DocSubcode::Diploma],
            stake_amount: 0,
            public_key: [0x44; 32],
            registered_at: 1_000,
            metadata: None,
        };
        let err = build_docclass_tx(&ctx(Address::new([0x11; 20])), &op).unwrap_err();
        assert_eq!(err, DocClassBuildError::PublicKeyNotSender);
    }

    #[test]
    fn registration_validates_its_fields() {
        let pk = [0x44; 32];
        let from = Address::from_public_key(&pk);
        let base = |jurisdiction: &str, subcodes: Vec<DocSubcode>, name: &str| {
            DocClassBuildOp::RegisterAcademicIssuer {
                name: name.to_string(),
                jurisdiction: jurisdiction.to_string(),
                subcodes,
                stake_amount: 0,
                public_key: pk,
                registered_at: 1_000,
                metadata: None,
            }
        };
        let c = ctx(from);
        assert!(build_docclass_tx(&c, &base("US", vec![DocSubcode::Diploma], "X")).is_ok());
        assert_eq!(
            build_docclass_tx(&c, &base("USA", vec![DocSubcode::Diploma], "X")).unwrap_err(),
            DocClassBuildError::Jurisdiction
        );
        assert_eq!(
            build_docclass_tx(&c, &base("U1", vec![DocSubcode::Diploma], "X")).unwrap_err(),
            DocClassBuildError::Jurisdiction
        );
        assert_eq!(
            build_docclass_tx(&c, &base("US", vec![], "X")).unwrap_err(),
            DocClassBuildError::NoSubcodes
        );
        assert_eq!(
            build_docclass_tx(&c, &base("US", vec![DocSubcode::GovernmentId], "X")).unwrap_err(),
            DocClassBuildError::NotAcademicSubcode
        );
        assert_eq!(
            build_docclass_tx(
                &c,
                &base("US", vec![DocSubcode::Diploma, DocSubcode::Diploma], "X")
            )
            .unwrap_err(),
            DocClassBuildError::DuplicateSubcode
        );
        assert_eq!(
            build_docclass_tx(&c, &base("US", vec![DocSubcode::Diploma], " ")).unwrap_err(),
            DocClassBuildError::EmptyName
        );
    }

    #[test]
    fn update_refuses_another_issuers_record() {
        let from = Address::new([0x11; 20]);
        let issuer = DocClassIssuer {
            address: Address::new([0x12; 20]),
            name: "Example Institute".to_string(),
            issuer_type: DocClassIssuerType::Educational,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::Diploma],
            keys: vec![],
            registered_at: 1,
            updated_at: 1,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };
        assert_eq!(
            build_docclass_tx(&ctx(from), &DocClassBuildOp::UpdateIssuer { issuer }).unwrap_err(),
            DocClassBuildError::IssuerNotSender
        );
    }

    #[test]
    fn deactivation_names_the_target_as_recipient() {
        let admin = Address::new([0x11; 20]);
        let target = Address::new([0x12; 20]);
        let built = build_docclass_tx(
            &ctx(admin),
            &DocClassBuildOp::DeactivateIssuer {
                issuer_address: target,
            },
        )
        .unwrap();
        let d = docclass(&built.tx);
        assert_eq!(built.tx.from, admin);
        assert_eq!(d.recipient, target);
        let p: DeactivateIssuerPayload = bincode::deserialize(&d.data).unwrap();
        assert_eq!(p.issuer_address, target);
    }

    /// Every variant is fieldless, so no message can carry a value the caller
    /// passed. A field added to a variant would have to be added to this list
    /// too, which is where a reviewer sees it.
    #[test]
    fn error_messages_are_fixed_strings() {
        let all = [
            DocClassBuildError::Jurisdiction,
            DocClassBuildError::NoSubcodes,
            DocClassBuildError::NotAcademicSubcode,
            DocClassBuildError::DuplicateSubcode,
            DocClassBuildError::PublicKeyNotSender,
            DocClassBuildError::IssuerNotSender,
            DocClassBuildError::KeyId,
            DocClassBuildError::EmptyName,
            DocClassBuildError::Encode,
        ];
        for e in all {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert_eq!(s, e.clone().to_string());
        }
    }
}
