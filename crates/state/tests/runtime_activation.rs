//! One runtime activation check, used by a new chain and a restarted one alike.
//!
//! The two entry points used to enforce different rules.
//! `StateManager::init_from_genesis` called `validate_account_root_activation`,
//! which owns the two invariants `sumchain-genesis` cannot express --
//! `LEGACY_ROOT_COMPATIBILITY_HEIGHT` lives in `sumchain-storage` and
//! `UNDO_RETENTION_FLOOR` in its pruner, and the genesis crate depends on
//! neither. `Node::new` called `ChainParams::validate`, which owns the two it
//! can. So a NEW chain checked the legacy window and the reorg horizon, and a
//! RESTARTED chain did not.
//!
//! These tests pin the error IDENTITY per invalid pair, not merely that
//! something failed: a shared entry point that refused everything with one
//! opaque message would pass a weaker test and tell an operator nothing.

use sumchain_genesis::ChainParams;
use sumchain_state::account_root::{validate_account_root_activation, validate_runtime_activation};
use sumchain_state::StateError;
use sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT;
use sumchain_storage::pruner::UNDO_RETENTION_FLOOR;

fn params(journal: Option<u64>, account: Option<u64>) -> ChainParams {
    let mut p = ChainParams::default();
    p.application_journal_enabled_from_height = journal;
    p.account_root_enabled_from_height = account;
    p
}

/// The release-shaped pair passes.
#[test]
fn the_release_shaped_pair_is_accepted() {
    let account = LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1;
    let journal = account - UNDO_RETENTION_FLOOR;
    validate_runtime_activation(&params(Some(journal), Some(account)))
        .expect("journal a full horizon below an account gate clear of the window");
}

/// Dormant is legal, and requires nothing of the journal.
#[test]
fn both_dormant_is_accepted_and_so_is_a_journal_alone() {
    validate_runtime_activation(&params(None, None)).expect("both dormant");
    validate_runtime_activation(&params(Some(2), None)).expect("journal alone");
}

/// Every invalid pair is refused, and each by its own identity.
#[test]
fn each_invalid_pair_is_refused_with_its_own_error_identity() {
    let account = LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1;
    let journal = account - UNDO_RETENTION_FLOOR;

    // Owned by ChainParams::validate, surfaced as ActivationParams.
    match validate_runtime_activation(&params(None, Some(account))) {
        Err(StateError::ActivationParams(m)) => assert!(
            m.contains("application_journal_enabled_from_height is None"),
            "the loader's own message must survive, not be flattened: {m}"
        ),
        other => panic!("an account gate over an unpinned journal must be refused: {other:?}"),
    }
    match validate_runtime_activation(&params(Some(account + 1), Some(account))) {
        Err(StateError::ActivationParams(m)) => assert!(
            m.contains("later than"),
            "the ordering fault must name itself: {m}"
        ),
        other => panic!("a journal gate after the account gate must be refused: {other:?}"),
    }

    // Owned by validate_account_root_activation, which needs chain constants.
    match validate_runtime_activation(&params(
        Some(journal),
        Some(LEGACY_ROOT_COMPATIBILITY_HEIGHT),
    )) {
        Err(StateError::AccountRootActivationInsideLegacyWindow { height, cutoff }) => {
            assert_eq!(height, LEGACY_ROOT_COMPATIBILITY_HEIGHT);
            assert_eq!(cutoff, LEGACY_ROOT_COMPATIBILITY_HEIGHT);
        }
        other => panic!("an account gate inside the legacy window must be refused: {other:?}"),
    }
    match validate_runtime_activation(&params(
        Some(account - UNDO_RETENTION_FLOOR + 1),
        Some(account),
    )) {
        Err(StateError::AccountRootActivationOutrunsJournal { .. }) => {}
        other => panic!("a journal gate inside the reorg horizon must be refused: {other:?}"),
    }
}

/// The structural fault is reported before the one needing chain constants.
///
/// A pair wrong in two ways should name the simpler fault: "your journal gate
/// is not pinned" is actionable, "your account gate is 4,095 blocks too close
/// to a gate that does not exist" is not.
#[test]
fn the_shared_validator_reports_the_ordering_fault_before_the_window_fault() {
    // Unpinned journal AND an account gate inside the legacy window.
    match validate_runtime_activation(&params(None, Some(LEGACY_ROOT_COMPATIBILITY_HEIGHT))) {
        Err(StateError::ActivationParams(_)) => {}
        other => panic!("the structural fault must be reported first, got {other:?}"),
    }
}

/// The two validators are not interchangeable, and this pins which owns what.
///
/// If a rule is ever moved between layers, this fails rather than passing
/// quietly with one layer doing nothing.
#[test]
fn the_narrow_validator_does_not_own_the_rules_the_loader_owns() {
    let account = LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1;
    // A journal gate AFTER the account gate is the loader's rule. The narrow
    // validator sees the horizon violation instead -- it is not blind, but it
    // is not the layer that names this fault.
    let p = params(Some(account + 1), Some(account));
    assert!(
        validate_account_root_activation(&p).is_err(),
        "the narrow validator still refuses the pair"
    );
    assert!(
        matches!(
            validate_runtime_activation(&p),
            Err(StateError::ActivationParams(_))
        ),
        "but the shared entry point reports the loader's identity for it"
    );
}

/// Nothing that can process a block is constructed before activation is
/// validated.
///
/// The ordering requirement is about WHEN the refusal happens, and a test that
/// only checks the refusal cannot see that. This reads `Node::new` and requires
/// the validation call to precede every block-processing component it builds.
///
/// Source-level, deliberately: the alternative is constructing a node with an
/// unsound pair and observing what got built before it failed, which means
/// building the thing this test exists to prove is not built.
#[test]
fn nothing_that_processes_a_block_is_built_before_activation_is_validated() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../node/src/node.rs"
    ))
    .expect("node.rs");
    let body = &src[src.find("    pub fn new(").expect("Node::new")..];

    let guard = body
        .find("validate_runtime_activation")
        .expect("Node::new must validate activation");

    // Each of these either processes blocks or decides what this node claims it
    // can do. None may be constructed before the guard.
    for (needle, what) in [
        ("StateManager::new", "state manager"),
        ("BlockExecutor::new", "block executor"),
        ("Mempool::new", "mempool"),
        ("PoAEngine::new", "consensus engine"),
        ("validate_startup", "journal format watermark"),
        ("report_sync_capability", "advertised capabilities"),
        ("JournalActivation::resolve", "undo-depth derivation"),
    ] {
        if let Some(at) = body.find(needle) {
            assert!(
                at > guard,
                "{what} (`{needle}`) is constructed at offset {at}, BEFORE activation \
                 validation at {guard}. Every journal/account combination must be \
                 rejected before anything reads chain data or advertises what this \
                 node can do."
            );
        }
    }
}

/// A first start refuses a retroactive gate BEFORE it records anything.
///
/// The ordering is the whole value of the check. `check_activation_parameters`
/// ends by writing the current heights into `ACTIVATION_META_KEY`, and from then
/// on every start compares against that row. If the refusal came after the
/// write, a first start under a retroactive configuration would persist that
/// configuration as the baseline — and the NEXT start would compare the same
/// wrong heights against themselves, find no change, and come up clean. The
/// mistake would become invisible at exactly the moment it became permanent.
///
/// Source-level for the same reason as the test above: proving the refusal
/// precedes the write by observing behaviour means performing the write.
#[test]
fn a_first_start_refuses_before_it_records_what_it_refused() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/node.rs"))
        .expect("node.rs");
    let body = {
        let at = src
            .find("fn check_activation_parameters(")
            .expect("check_activation_parameters");
        let end = src[at..]
            .find("\n    /// Log what this node may claim about its own history.")
            .expect("end of check_activation_parameters");
        &src[at..at + end]
    };

    let refusal = body
        .find("retroactive_gates_on_a_first_start")
        .expect("a first start must check for retroactively opened gates");
    let record = body
        .find("Self::ACTIVATION_META_KEY,")
        .expect("the heights must be recorded");
    assert!(
        refusal < record,
        "the first-start refusal must precede the write that becomes every \
         later start's baseline"
    );

    // And it must be guarded on the record's ABSENCE. Running it unconditionally
    // would refuse an ordinary restart of a node that legitimately activated a
    // gate and has been running under it since.
    let guard = body
        .find("if recorded.is_none() {")
        .expect("the first-start check must be guarded on there being no record");
    assert!(
        guard < refusal,
        "the check belongs inside the no-record branch: a node that recorded its \
         heights and then passed one is compared against the record instead"
    );
}
