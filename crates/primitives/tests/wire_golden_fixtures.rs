//! Pre-extraction golden wire fixtures (sum-chain #124 / W1a).
//!
//! These byte-vectors were captured from `sumchain-primitives` on `main`
//! BEFORE the `sumchain-wire` leaf extraction and are HARDCODED here. They
//! MUST pass byte-identically before and after the extraction: the whole point
//! of W1a is that moving the wire types into a leaf crate changes zero bytes on
//! the wire. Any drift here is a wire-format contract break.
//!
//! Coverage:
//!   * append-only variant tag (u32-LE) for every one of the 27 `TxPayload`
//!     variants + `TxType::from_byte` round-trip and out-of-range rejection;
//!   * money path: legacy `Transaction`, `TransactionV2` transfer envelope,
//!     `TxPayload::Transfer`, `TxInner` discriminants, `SignedTransaction`
//!     (legacy + V2) full bytes, `hash`/`signing_hash`;
//!   * `to_hex`/`from_hex` accepting BOTH bare and `0x`-prefixed input;
//!   * malformed decode policy pinned to current behavior. NOTE: as of
//!     sumchain-wire 0.2.1 the canonical `SignedTransaction::from_bytes`/
//!     `from_hex` path REJECTS trailing bytes (explicit reject-trailing bincode
//!     options); the lower-level `Transaction`/`TransactionV2::from_bytes` still
//!     tolerate trailing bytes via `bincode::deserialize`.

use sumchain_primitives::education::{EducationStandard, EducationTxData};
use sumchain_primitives::governance::{GovernanceOperation, GovernanceTxData};
use sumchain_primitives::inference_attestation::{
    InferenceAttestationDigest, InferenceAttestationTxData, InferenceAttestationV2TxData,
};
use sumchain_primitives::inference_settlement::{
    ClaimInferenceRewardRequest, InferenceSettlementOperation, InferenceSettlementTxData,
};
use sumchain_primitives::supply::{ServiceKind, SupplyOperation, SupplyTxData};
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData, TxPayload};
use sumchain_primitives::{
    Address, AgreementOperation, AgreementTxData, DocClassOperation, DocClassTxData, DocSubcode,
    EmploymentOperation, EmploymentTxData, EquityOperation, EquityTxData, FinanceOperation,
    FinanceTxData, Hash, HealthcareOperation, HealthcareTxData, LegalOperation, LegalTxData,
    MessagingOperation, MessagingTxData, NftOperation, NftTxData, NodeRegistryOperation,
    NodeRegistryOperationV2, NodeRegistryTxData, NodeRegistryV2TxData, NodeRole,
    PolicyAccountOperation, PolicyAccountTxData, PropertyOperation, PropertyTxData,
    RegisterPublicKeySponsoredV1Data, SignedTransaction, StakingOperation, StakingTxData,
    StorageMetadataOperation, StorageMetadataOperationV2, StorageMetadataTxData,
    StorageMetadataV2TxData, TaxOperation, TaxTxData, TokenOperation, TokenTxData, Transaction,
    TransactionV2, TxInner, TxType,
};

// ── Hardcoded golden constants (captured pre-extraction from main) ───────────

const LEGACY_TX_BYTES: &str = "010000000000000011111111111111111111111111111111111111112222222222222222222222222222222222222222e80300000000000000000000000000000a0000000000000000000000000000000700000000000000";
const LEGACY_TX_SIGNING_HASH: &str =
    "0x52cd48dde723b1a8cc6dd0e8f7d2482d92a6b852a2fd705696fdf94a3647bb11";
const V2_TX_BYTES: &str = "010000000000000011111111111111111111111111111111111111110a0000000000000000000000000000000700000000000000000000002222222222222222222222222222222222222222e8030000000000000000000000000000";
const V2_TX_SIGNING_HASH: &str =
    "0x1d6d45d674c55f715098c3c49bffc5257034fd527859c4274e33535b3352edc0";
const PAYLOAD_TRANSFER_BYTES: &str =
    "000000002222222222222222222222222222222222222222e8030000000000000000000000000000";
const SIGNED_LEGACY_BYTES: &str = "00000000010000000000000011111111111111111111111111111111111111112222222222222222222222222222222222222222e80300000000000000000000000000000a0000000000000000000000000000000700000000000000ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const SIGNED_LEGACY_HASH: &str =
    "0xc30db5a322a40a3570aaa0ab7b5cdd3ff755cb9120f136446349d1ae8e11b808";
const SIGNED_V2_BYTES: &str = "01000000010000000000000011111111111111111111111111111111111111110a0000000000000000000000000000000700000000000000000000002222222222222222222222222222222222222222e8030000000000000000000000000000ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const SIGNED_V2_HASH: &str =
    "0xf6212724dec2fdc9e7e498b3f60906c7bdd71c3f60a2f906a6e4a8a58ab0be42";

// ── Shared fixed inputs ──────────────────────────────────────────────────────

const SIG: [u8; 64] = [0xAB; 64];
const PK: [u8; 32] = [0xCD; 32];

fn digest() -> InferenceAttestationDigest {
    InferenceAttestationDigest {
        session_id: String::new(),
        model_hash: [0u8; 32],
        manifest_root: [0u8; 32],
        response_hash: [0u8; 32],
        proof_root: [0u8; 32],
    }
}

fn legacy_tx() -> Transaction {
    Transaction::new(1, Address::new([0x11; 20]), Address::new([0x22; 20]), 1000, 10, 7)
}
fn v2_tx() -> TransactionV2 {
    TransactionV2::transfer(1, Address::new([0x11; 20]), Address::new([0x22; 20]), 1000, 10, 7)
}

/// One minimal instance of every `TxPayload` variant, paired with its
/// append-only wire ordinal. Constructing all 27 here is deliberate: the tag
/// test below is the single guard that the bincode variant order never shifts.
fn all_payloads() -> Vec<(u32, TxPayload)> {
    vec![
        (0, TxPayload::Transfer { to: Address::ZERO, amount: 0 }),
        (1, TxPayload::Nft(NftTxData { collection_id: [0u8; 32], token_id: 0, operation: NftOperation::CreateCollection, data: vec![] })),
        (2, TxPayload::Token(TokenTxData { token_id: [0u8; 32], operation: TokenOperation::Create, data: vec![] })),
        (3, TxPayload::ContractDeploy(ContractDeployData { code: vec![], init_method: String::new(), init_args: vec![], value: 0, gas_limit: 0 })),
        (4, TxPayload::ContractCall(ContractCallData { contract: Address::ZERO, method: String::new(), args: vec![], value: 0, gas_limit: 0 })),
        (5, TxPayload::Staking(StakingTxData { operation: StakingOperation::CreateValidator, data: vec![] })),
        (6, TxPayload::Messaging(MessagingTxData { operation: MessagingOperation::SendMessage, data: vec![] })),
        (7, TxPayload::DocClass(DocClassTxData { operation: DocClassOperation::CreateIdentityRoot, subcode: DocSubcode::Subject, data: vec![], recipient: Address::ZERO })),
        (8, TxPayload::Tax(TaxTxData { operation: TaxOperation::RegisterClaimType, data: vec![], recipient: Address::ZERO })),
        (9, TxPayload::Equity(EquityTxData { operation: EquityOperation::CreateEntity, data: vec![], recipient: Address::ZERO })),
        (10, TxPayload::Agreement(AgreementTxData { operation: AgreementOperation::CommitAgreement, data: vec![], recipient: Address::ZERO })),
        (11, TxPayload::Legal(LegalTxData { operation: LegalOperation::AnchorCase, data: vec![], recipient: Address::ZERO })),
        (12, TxPayload::Property(PropertyTxData { operation: PropertyOperation::AnchorAsset, data: vec![], recipient: Address::ZERO })),
        (13, TxPayload::Healthcare(HealthcareTxData { operation: HealthcareOperation::RegisterProvider, data: vec![], recipient: Address::ZERO })),
        (14, TxPayload::Employment(EmploymentTxData { operation: EmploymentOperation::RegisterIssuer, data: vec![], recipient: Address::ZERO })),
        (15, TxPayload::Finance(FinanceTxData { operation: FinanceOperation::RegisterIssuer, data: vec![], recipient: Address::ZERO })),
        (16, TxPayload::PolicyAccount(PolicyAccountTxData { operation: PolicyAccountOperation::Create, data: vec![], recipient: Address::ZERO })),
        (17, TxPayload::NodeRegistry(NodeRegistryTxData { operation: NodeRegistryOperation::Register { role: NodeRole::Validator, stake: 0 } })),
        (18, TxPayload::StorageMetadata(StorageMetadataTxData { operation: StorageMetadataOperation::RegisterFile { merkle_root: Hash::ZERO, total_size_bytes: 0, access_list: vec![], fee_deposit: 0 } })),
        (19, TxPayload::NodeRegistryV2(NodeRegistryV2TxData { operation: NodeRegistryOperationV2::RegisterEncryptionKey { encryption_pubkey: [0u8; 32] } })),
        (20, TxPayload::StorageMetadataV2(StorageMetadataV2TxData { operation: StorageMetadataOperationV2::ActivateFileV2 { merkle_root: Hash::ZERO } })),
        (21, TxPayload::InferenceAttestation(InferenceAttestationTxData { digest: digest(), verifier_signature: [0u8; 64] })),
        (22, TxPayload::Education(EducationTxData { standard: EducationStandard::CourseCatalog, operation: 0, data: vec![], recipient: Address::ZERO })),
        (23, TxPayload::Governance(GovernanceTxData { operation: GovernanceOperation::RegisterAsset, data: vec![] })),
        (24, TxPayload::InferenceSettlement(InferenceSettlementTxData { operation: InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: String::new() }) })),
        (25, TxPayload::InferenceAttestationV2(InferenceAttestationV2TxData { digest: digest(), verifier_public_key: [0u8; 32], verifier_signature: [0u8; 64] })),
        (26, TxPayload::Supply(SupplyTxData { operation: SupplyOperation::ClaimServiceGrant { service_kind: ServiceKind::Validator } })),
    ]
}

// ── 1. Append-only ordinal lock for all 27 variants ──────────────────────────

#[test]
fn all_27_txpayload_tags_are_frozen() {
    let payloads = all_payloads();
    assert_eq!(payloads.len(), 27, "expected exactly 27 TxPayload variants");
    for (ord, p) in payloads {
        let b = bincode::serialize(&p).unwrap();
        let tag = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        assert_eq!(tag, ord, "TxPayload bincode tag drifted for ordinal {ord}");
        // TxType discriminant table mirrors the TxPayload declaration order.
        assert_eq!(
            TxType::from_byte(ord as u8).map(|t| t as u8),
            Some(ord as u8),
            "TxType::from_byte({ord}) discriminant drift"
        );
    }
}

#[test]
fn txtype_out_of_range_ordinal_rejected() {
    // 27 is reserved for C1 / ComputePool (#130) — it MUST NOT decode as a valid
    // TxType in W1a. (The W1b beacon band is 28/29.)
    assert!(TxType::from_byte(27).is_none());
    assert!(TxType::from_byte(255).is_none());
}

// ── 2. Money path (legacy + V2 envelopes, signing hashes) ────────────────────

#[test]
fn legacy_transaction_wire_is_frozen() {
    let lt = legacy_tx();
    assert_eq!(hex::encode(lt.to_bytes()), LEGACY_TX_BYTES);
    assert_eq!(lt.signing_hash().to_hex(), LEGACY_TX_SIGNING_HASH);
    // Round-trip.
    assert_eq!(Transaction::from_bytes(&lt.to_bytes()).unwrap(), lt);
}

#[test]
fn transaction_v2_transfer_wire_is_frozen() {
    let vt = v2_tx();
    assert_eq!(hex::encode(vt.to_bytes()), V2_TX_BYTES);
    assert_eq!(vt.signing_hash().to_hex(), V2_TX_SIGNING_HASH);
    assert_eq!(TransactionV2::from_bytes(&vt.to_bytes()).unwrap(), vt);
}

#[test]
fn txpayload_transfer_tag0_wire_is_frozen() {
    let p = TxPayload::Transfer { to: Address::new([0x22; 20]), amount: 1000 };
    let b = bincode::serialize(&p).unwrap();
    assert_eq!(&b[..4], &0u32.to_le_bytes(), "Transfer must be TxPayload ordinal 0");
    assert_eq!(hex::encode(&b), PAYLOAD_TRANSFER_BYTES);
}

#[test]
fn txinner_discriminants_are_frozen() {
    let inner_legacy = bincode::serialize(&TxInner::Legacy(legacy_tx())).unwrap();
    let inner_v2 = bincode::serialize(&TxInner::V2(v2_tx())).unwrap();
    assert_eq!(&inner_legacy[..4], &0u32.to_le_bytes(), "TxInner::Legacy = 0");
    assert_eq!(&inner_v2[..4], &1u32.to_le_bytes(), "TxInner::V2 = 1");
}

#[test]
fn signed_transaction_legacy_wire_is_frozen() {
    let signed = SignedTransaction::new(legacy_tx(), SIG, PK);
    assert_eq!(hex::encode(signed.to_bytes()), SIGNED_LEGACY_BYTES);
    assert_eq!(signed.hash().to_hex(), SIGNED_LEGACY_HASH);
    // Legacy signing hash equals the inner Transaction signing hash.
    assert_eq!(signed.signing_hash().to_hex(), LEGACY_TX_SIGNING_HASH);
    assert_eq!(SignedTransaction::from_bytes(&signed.to_bytes()).unwrap(), signed);
}

#[test]
fn signed_transaction_v2_wire_is_frozen() {
    let signed = SignedTransaction::new_v2(v2_tx(), SIG, PK);
    assert_eq!(hex::encode(signed.to_bytes()), SIGNED_V2_BYTES);
    assert_eq!(signed.hash().to_hex(), SIGNED_V2_HASH);
    assert_eq!(signed.signing_hash().to_hex(), V2_TX_SIGNING_HASH);
    assert_eq!(SignedTransaction::from_bytes(&signed.to_bytes()).unwrap(), signed);
}

// ── 3. Hex encode/decode: bare AND 0x-prefixed both accepted ─────────────────

#[test]
fn signed_transaction_from_hex_accepts_bare_and_0x() {
    let signed = SignedTransaction::new(legacy_tx(), SIG, PK);
    let bare = signed.to_hex(); // to_hex() emits bare (no 0x)
    assert_eq!(bare, SIGNED_LEGACY_BYTES);
    let prefixed = format!("0x{bare}");
    let from_bare = SignedTransaction::from_hex(&bare).unwrap();
    let from_prefixed = SignedTransaction::from_hex(&prefixed).unwrap();
    assert_eq!(from_bare, signed);
    assert_eq!(from_prefixed, signed);
    assert_eq!(from_bare, from_prefixed);
}

#[test]
fn hash_and_address_from_hex_accept_bare_and_0x() {
    let h = Hash::hash(b"golden");
    let hx = h.to_hex(); // emits WITH 0x prefix
    assert!(hx.starts_with("0x"));
    let bare = hx.strip_prefix("0x").unwrap();
    assert_eq!(Hash::from_hex(&hx).unwrap(), h);
    assert_eq!(Hash::from_hex(bare).unwrap(), h);

    let a = Address::from_public_key(&[7u8; 32]);
    let ax = a.to_hex();
    assert!(ax.starts_with("0x"));
    let abare = ax.strip_prefix("0x").unwrap();
    assert_eq!(Address::from_hex(&ax).unwrap(), a);
    assert_eq!(Address::from_hex(abare).unwrap(), a);
}

// ── 4. Malformed decode policy (pinned to CURRENT bincode 1.3 behavior) ──────

#[test]
fn trailing_bytes_are_rejected() {
    // sumchain-wire 0.2.1 hardened the canonical `SignedTransaction` decode
    // path to REJECT trailing bytes (explicit reject-trailing bincode options).
    // The accepted canonical byte set is unchanged from 0.2.0 — only extra
    // trailing bytes after a fully-decoded value now fail closed. Pin the new
    // policy so it cannot silently regress. (As of 0.2.2 all three canonical tx
    // decoders — `Transaction`, `TransactionV2`, and `SignedTransaction` — reject
    // trailing bytes via the same explicit reject-trailing bincode options;
    // 0.2.1 had hardened only `SignedTransaction`.)
    let good = SignedTransaction::new(legacy_tx(), SIG, PK).to_bytes();
    // canonical bytes still decode unchanged.
    assert!(SignedTransaction::from_bytes(&good).is_ok());
    let mut trailing = good.clone();
    trailing.push(0xFF);
    assert!(
        SignedTransaction::from_bytes(&trailing).is_err(),
        "trailing bytes must now be rejected"
    );
}

// ── Issue #145: RegisterPublicKeySponsoredV1 TxPayload wrapping + outer hash ──

#[test]
fn sponsored_register_v1_txpayload_bytes_and_outer_hash_are_frozen() {
    // Fixed, signature-free payload (the 64-byte "signature" is just data here).
    let data = RegisterPublicKeySponsoredV1Data {
        registrant_public_key: [0xAA; 32],
        registrant_signature: [0xBB; 64],
    };
    let payload = TxPayload::Messaging(MessagingTxData {
        operation: MessagingOperation::RegisterPublicKeySponsoredV1,
        data: bincode::serialize(&data).unwrap(),
    });
    let b = bincode::serialize(&payload).unwrap();
    // TxPayload::Messaging is ordinal 6; MessagingOperation index 18; then an
    // 8-byte LE length (96) and the 96 payload bytes.
    let mut want = Vec::new();
    want.extend_from_slice(&6u32.to_le_bytes());
    want.extend_from_slice(&18u32.to_le_bytes());
    want.extend_from_slice(&96u64.to_le_bytes());
    want.extend_from_slice(&[0xAA; 32]);
    want.extend_from_slice(&[0xBB; 64]);
    assert_eq!(
        b, want,
        "TxPayload::Messaging(RegisterPublicKeySponsoredV1) bytes drifted"
    );

    // Deterministic outer signing hash = blake3(bincode(tx)); no signature needed.
    let tx = TransactionV2 {
        chain_id: 1,
        from: Address::new([0x11; 20]),
        fee: 1000,
        nonce: 7,
        payload,
    };
    assert_eq!(
        tx.signing_hash().to_hex(),
        "0xa78e47f42fee6b50d611d7933340001643b3ee5361340010a4c4fe5b833fcd1c"
    );
}

#[test]
fn truncated_ordinal_is_rejected() {
    // 2 bytes cannot even hold the 4-byte TxInner discriminant.
    assert!(SignedTransaction::from_bytes(&[0x00, 0x00]).is_err());
}

#[test]
fn truncated_body_is_rejected() {
    let good = SignedTransaction::new(legacy_tx(), SIG, PK).to_bytes();
    assert!(SignedTransaction::from_bytes(&good[..good.len() / 2]).is_err());
}

#[test]
fn short_fixed_array_is_rejected() {
    // Drop the trailing 40 bytes so the [u8;64] signature / [u8;32] pubkey
    // fixed arrays cannot be filled.
    let good = SignedTransaction::new(legacy_tx(), SIG, PK).to_bytes();
    assert!(SignedTransaction::from_bytes(&good[..good.len() - 40]).is_err());
}

#[test]
fn out_of_range_txpayload_ordinal_is_rejected() {
    // TransactionV2 layout: chain_id u64 | from [20] | fee u128 | nonce u64 | payload.
    // Overwrite the payload's u32-LE variant tag with 27 (reserved for W1b).
    let mut bytes = v2_tx().to_bytes();
    let payload_off = 8 + 20 + 16 + 8;
    bytes[payload_off] = 27;
    assert!(TransactionV2::from_bytes(&bytes).is_err());
}

#[test]
fn oversized_length_prefix_is_rejected() {
    // A Vec<u8> length prefix of u64::MAX must fail rather than allocate wildly.
    let mut bytes = bincode::serialize(&TxPayload::Staking(StakingTxData {
        operation: StakingOperation::CreateValidator,
        data: vec![],
    }))
    .unwrap();
    let l = bytes.len();
    bytes[l - 8..].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(bincode::deserialize::<TxPayload>(&bytes).is_err());
}
