//! C5 Q9 (owner, 2026-10-22): register refuses a record with any all-zero
//! commitment, and `registry_dryRunAdmit` refuses the same record for the same
//! commitments. Both read `sumchain_wire::registry_ingress::unset_commitments`;
//! this checks the two outcomes side by side. The register path is the dormant,
//! unwired `execute_registry_ingress` (PROPOSED), with test-fixture parameters.

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::GovernanceParams;
use sumchain_primitives::validator_authority::ValidatorApproval;
use sumchain_primitives::{Address, Hash, TxStatus};
use sumchain_rpc::registry_types::{dry_run_admit, DryRunContext, RefusalReason};
use sumchain_state::governance_executor::execute_registry_ingress;
use sumchain_state::registry_ingress::{RegistryIngressContext, RegistryIngressOp};
use sumchain_storage::candidate::CandidateExecution;
use sumchain_storage::schema::AccountState;
use sumchain_storage::{Database, StateStore};
use sumchain_wire::registry_ingress::{
    admitted_proof_systems, registry_register_signing_bytes, unset_commitments,
    RegistryIngressParams, RegistryRegisterV1,
};
use sumchain_wire::registry_wire::{RegistryRecordV1, RegistryStatus};
use tempfile::TempDir;

const CHAIN: u64 = 4242;
const GENESIS: [u8; 32] = [0x47; 32];
const H: u64 = 100;

fn record() -> RegistryRecordV1 {
    RegistryRecordV1 {
        id: [0x11; 32],
        proof_system_id: 2,
        audit_commitment: [0xA1; 32],
        source_commitment: [0xB2; 32],
        ceremony_commitment: [0xC3; 32],
        verifier_binary_version: 1,
        activation_height: 200,
        status: RegistryStatus::Enabled,
        approval_threshold_bps: 6_667,
    }
}

/// Execute a register of `rec`, approved by the single validator `[1; 32]`.
fn register(rec: &RegistryRecordV1) -> TxStatus {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let payer = Address::new([0x5A; 20]);
    StateStore::new(&db)
        .put_account(&payer, &AccountState { balance: 1_000_000, nonce: 0 })
        .unwrap();
    let mut params = ChainParams::with_v2_enabled();
    params.governance_enabled_from_height = Some(0);
    params.governance = Some(GovernanceParams {
        validator_authority_threshold_bps: 6_667,
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 16,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: 0,
    });
    // Test fixtures, not proposed values.
    let registry = RegistryIngressParams {
        registry_min_timelock_blocks: Some(10),
        registry_max_approval_window: Some(100),
    };
    let v = KeyPair::from_bytes([1; 32]);
    let msg = registry_register_signing_bytes(CHAIN, &GENESIS, H + 50, rec).unwrap();
    let data = RegistryRegisterV1 {
        valid_until: H + 50,
        record: rec.clone(),
        approvals: vec![ValidatorApproval {
            pubkey: *v.public_key().as_bytes(),
            signature: sign(&msg, v.private_key()).to_bytes(),
        }],
    }
    .try_encode()
    .unwrap();
    let mut c = CandidateExecution::new(&db, sumchain_state::MAX_BLOCK_WRITE_SET_BYTES);
    execute_registry_ingress(
        &mut c.view(),
        CHAIN,
        &params,
        RegistryIngressOp::Register,
        &data,
        &payer,
        100,
        &Address::new([0x99; 20]),
        H,
        Hash::ZERO,
        &[*v.public_key().as_bytes()],
        RegistryIngressContext {
            params: &registry,
            genesis_block_hash: Some(&GENESIS),
        },
    )
    .unwrap()
    .status
}

fn dry_run_unset(rec: &RegistryRecordV1) -> Vec<String> {
    let admitted = admitted_proof_systems();
    let result = dry_run_admit(
        &rec.try_encode().unwrap(),
        DryRunContext {
            chain_height: H - 1,
            allowed_proof_systems: &admitted,
        },
    );
    result
        .refusals
        .into_iter()
        .filter_map(|r| match r {
            RefusalReason::CommitmentUnset { which } => Some(which),
            _ => None,
        })
        .collect()
}

#[test]
fn register_and_the_dry_run_refuse_the_same_zero_commitments() {
    // Control: admissible to the dry run, and registered.
    assert!(dry_run_admit(
        &record().try_encode().unwrap(),
        DryRunContext {
            chain_height: H - 1,
            allowed_proof_systems: &admitted_proof_systems(),
        },
    )
    .admissible);
    assert_eq!(register(&record()), TxStatus::Success);

    // Every non-empty subset of the three commitments: 3 singles, 3 pairs, all.
    let zeroes: [fn(&mut RegistryRecordV1); 7] = [
        |r| r.audit_commitment = [0; 32],
        |r| r.source_commitment = [0; 32],
        |r| r.ceremony_commitment = [0; 32],
        |r| {
            r.audit_commitment = [0; 32];
            r.source_commitment = [0; 32];
        },
        |r| {
            r.audit_commitment = [0; 32];
            r.ceremony_commitment = [0; 32];
        },
        |r| {
            r.source_commitment = [0; 32];
            r.ceremony_commitment = [0; 32];
        },
        |r| {
            r.audit_commitment = [0; 32];
            r.source_commitment = [0; 32];
            r.ceremony_commitment = [0; 32];
        },
    ];
    let mut seen = std::collections::BTreeSet::new();
    for zero in zeroes {
        let mut rec = record();
        zero(&mut rec);
        let names: Vec<String> = unset_commitments(&rec).iter().map(|s| s.to_string()).collect();
        assert!(!names.is_empty());
        seen.insert(names.clone());
        assert_eq!(dry_run_unset(&rec), names, "the dry run names the same commitments");
        assert_eq!(register(&rec), TxStatus::Failed(303), "register refuses {names:?}");
    }
    assert_eq!(seen.len(), 7, "every non-empty subset, once");
}
