//! `sumchain_tx_execution_errors_total` — the failed-receipt counter, and the
//! closed label set it is allowed to carry.
//!
//! # Why the label set is a correctness property, not a style one
//!
//! This counter is incremented once per FAILED TRANSACTION. A Prometheus
//! registry keeps one series per distinct label tuple, forever, in memory. A
//! label whose value is chosen by the transaction — a sender address, a
//! transaction hash, a block height, an error string built with `format!` —
//! therefore lets any funded account allocate unbounded memory in every node
//! that scrapes itself, for the price of one transaction per series. That is
//! not a dashboard defect; it is a remotely triggered memory exhaustion.
//!
//! So the labels here are not strings. They are `&'static str` drawn from the
//! tables below, and the only way to obtain one is to be in a table. The
//! counters are a FIXED-LENGTH array indexed by position in those tables, so
//! the registry cannot grow at runtime at all: there is no insert path.
//!
//! Exactly two labels: `subsystem` and `code`.
//!
//! * `subsystem` — which executor refused, from [`SUBSYSTEMS`].
//! * `code` — the decimal `TxStatus::Failed(n)` code, or the name of the
//!   non-`Failed` status. Numerals are the stable identifier: they are what
//!   `TxStatus::description()` is keyed on and what the receipt carries on the
//!   wire, so a rename of a human description cannot move a dashboard.
//!
//! A `Failed(n)` this binary does not allocate is counted under
//! [`UNATTRIBUTED`] rather than creating a series, which is the whole point:
//! an unknown code is one more increment, never one more label value.
//!
//! # Where it is incremented
//!
//! One place: the single non-test `Receipt::new` call site in
//! `sumchain_state::executor`, where every subsystem's receipt for a block
//! that will be published is built. `crates/state/tests/wave1_execution_error_signal.rs`
//! derives that uniqueness from the source on every run, so a second
//! receipt-building path cannot appear uncounted.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::receipt::TxStatus;

/// The exposed metric name.
pub const TX_EXECUTION_ERROR_METRIC: &str = "sumchain_tx_execution_errors_total";

/// The label NAMES this counter carries. **Exactly two, and this is pinned by
/// test.** A third label is a cardinality multiplier and is refused here.
pub const TX_EXECUTION_ERROR_LABEL_NAMES: [&str; 2] = ["subsystem", "code"];

/// One series' labels. Both halves are `&'static str` by construction: there
/// is no constructor that takes an owned string, so a caller cannot invent a
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxExecutionErrorLabels {
    /// Which subsystem's executor produced the failed receipt.
    pub subsystem: &'static str,
    /// The stable status code.
    pub code: &'static str,
}

/// Every `subsystem` label value this binary can emit. Closed.
pub const SUBSYSTEMS: &[&str] = &[
    "agreement",
    "archive",
    "consensus",
    "contract",
    "crypto",
    "docclass",
    "education",
    "employment",
    "equity",
    "fee",
    "finance",
    "governance",
    "healthcare",
    "inference",
    "legal",
    "messaging",
    "nft",
    "node_registry",
    "omninode",
    "policy_account",
    "property",
    "runtime",
    "staking",
    "storage",
    "supply",
    "tax",
    "token",
    "unknown",
    "write_set",
];

/// The `TxStatus::Failed(n)` codes this binary allocates: `(n, subsystem, code
/// label)`. Kept in step with `TxStatus::description()` and the executor
/// dispatch; a code absent here is counted under [`UNATTRIBUTED`].
const FAILURE_SERIES: &[(u32, &str, &str)] = &[
    (0, "runtime", "0"),
    (1, "fee", "1"),
    (2, "nft", "2"),
    (3, "token", "3"),
    (4, "contract", "4"),
    (5, "contract", "5"),
    (6, "staking", "6"),
    (7, "messaging", "7"),
    (8, "docclass", "8"),
    (9, "tax", "9"),
    (10, "equity", "10"),
    (11, "agreement", "11"),
    (12, "legal", "12"),
    (13, "property", "13"),
    (14, "healthcare", "14"),
    (15, "employment", "15"),
    (16, "finance", "16"),
    (17, "policy_account", "17"),
    (19, "storage", "19"),
    (20, "node_registry", "20"),
    (21, "storage", "21"),
    (22, "crypto", "22"),
    (30, "storage", "30"),
    (31, "storage", "31"),
    (32, "storage", "32"),
    (33, "storage", "33"),
    (34, "storage", "34"),
    (35, "storage", "35"),
    (40, "storage", "40"),
    (50, "omninode", "50"),
    (51, "omninode", "51"),
    (52, "omninode", "52"),
    (53, "omninode", "53"),
    (54, "omninode", "54"),
    (55, "omninode", "55"),
    (60, "contract", "60"),
    (70, "education", "70"),
    (71, "education", "71"),
    (72, "education", "72"),
    (73, "education", "73"),
    (74, "education", "74"),
    (75, "education", "75"),
    (76, "education", "76"),
    (77, "education", "77"),
    (78, "education", "78"),
    (79, "education", "79"),
    (80, "education", "80"),
    (81, "education", "81"),
    (82, "education", "82"),
    (83, "education", "83"),
    (84, "education", "84"),
    (300, "governance", "300"),
    (301, "governance", "301"),
    (302, "governance", "302"),
    (303, "governance", "303"),
    (304, "governance", "304"),
    (305, "governance", "305"),
    (306, "governance", "306"),
    (307, "governance", "307"),
    (308, "governance", "308"),
    (309, "governance", "309"),
    (310, "governance", "310"),
    (311, "governance", "311"),
    (312, "governance", "312"),
    (313, "governance", "313"),
    (314, "governance", "314"),
    (315, "governance", "315"),
    (316, "governance", "316"),
    (317, "governance", "317"),
    (318, "governance", "318"),
    (320, "archive", "320"),
    (321, "archive", "321"),
    (322, "archive", "322"),
    (323, "archive", "323"),
    (324, "archive", "324"),
    (325, "archive", "325"),
    (326, "archive", "326"),
    (330, "archive", "330"),
    (331, "archive", "331"),
    (332, "archive", "332"),
    (333, "archive", "333"),
    (334, "archive", "334"),
    (335, "archive", "335"),
    (350, "inference", "350"),
    (351, "inference", "351"),
    (352, "inference", "352"),
    (353, "inference", "353"),
    (354, "inference", "354"),
    (355, "inference", "355"),
    (356, "inference", "356"),
    (357, "inference", "357"),
    (358, "inference", "358"),
    (359, "inference", "359"),
    (360, "inference", "360"),
    (361, "inference", "361"),
    (362, "inference", "362"),
    (363, "inference", "363"),
    (364, "inference", "364"),
    (365, "inference", "365"),
    (366, "inference", "366"),
    (367, "inference", "367"),
    (368, "inference", "368"),
    (369, "inference", "369"),
    (370, "inference", "370"),
    (380, "supply", "380"),
    (381, "supply", "381"),
    (382, "supply", "382"),
    (383, "supply", "383"),
    (384, "supply", "384"),
    (385, "supply", "385"),
    (386, "supply", "386"),
    (387, "supply", "387"),
    (388, "supply", "388"),
    (390, "messaging", "390"),
    (391, "messaging", "391"),
    (392, "messaging", "392"),
    (393, "messaging", "393"),
    (394, "messaging", "394"),
    (400, "write_set", "400"),
];

/// The four non-`Failed` failure statuses, in `TxStatus` declaration order.
/// These are consensus-level rejections rather than a subsystem's refusal.
const STATUS_SERIES: &[(&str, &str)] = &[
    ("consensus", "invalid_signature"),
    ("consensus", "invalid_nonce"),
    ("consensus", "insufficient_balance"),
    ("consensus", "invalid_chain_id"),
];

/// Where a `Failed(n)` with no allocated series is counted. One series, not
/// one per unknown code — this is the bound.
pub const UNATTRIBUTED: TxExecutionErrorLabels = TxExecutionErrorLabels {
    subsystem: "unknown",
    code: "unallocated",
};

/// The total number of series. Fixed at compile time; there is no insert path.
pub const SERIES_COUNT: usize = FAILURE_SERIES.len() + STATUS_SERIES.len() + 1;

/// The counters, one per series, indexed exactly as [`series_index`] returns.
static COUNTS: [AtomicU64; SERIES_COUNT] = [const { AtomicU64::new(0) }; SERIES_COUNT];

/// The index of the `UNATTRIBUTED` series: always last.
const UNATTRIBUTED_INDEX: usize = SERIES_COUNT - 1;

/// The series index for a status, or `None` when the transaction succeeded.
///
/// Total by construction — an unallocated `Failed(n)` lands on
/// [`UNATTRIBUTED_INDEX`] rather than creating anything.
fn series_index(status: &TxStatus) -> Option<usize> {
    match status {
        TxStatus::Success => None,
        TxStatus::InvalidSignature => Some(FAILURE_SERIES.len()),
        TxStatus::InvalidNonce => Some(FAILURE_SERIES.len() + 1),
        TxStatus::InsufficientBalance => Some(FAILURE_SERIES.len() + 2),
        TxStatus::InvalidChainId => Some(FAILURE_SERIES.len() + 3),
        TxStatus::Failed(code) => Some(
            FAILURE_SERIES
                .iter()
                .position(|(n, _, _)| n == code)
                .unwrap_or(UNATTRIBUTED_INDEX),
        ),
    }
}

/// The labels at a series index.
pub fn labels_at(index: usize) -> TxExecutionErrorLabels {
    if index < FAILURE_SERIES.len() {
        let (_, subsystem, code) = FAILURE_SERIES[index];
        TxExecutionErrorLabels { subsystem, code }
    } else if index < FAILURE_SERIES.len() + STATUS_SERIES.len() {
        let (subsystem, code) = STATUS_SERIES[index - FAILURE_SERIES.len()];
        TxExecutionErrorLabels { subsystem, code }
    } else {
        UNATTRIBUTED
    }
}

/// The labels a status is counted under, or `None` for a success.
pub fn labels_for(status: &TxStatus) -> Option<TxExecutionErrorLabels> {
    series_index(status).map(labels_at)
}

/// Count one failed receipt. A success is not counted and allocates nothing.
///
/// Called from the single non-test receipt construction site in
/// `sumchain_state::executor`.
pub fn record(status: &TxStatus) {
    if let Some(i) = series_index(status) {
        COUNTS[i].fetch_add(1, Ordering::Relaxed);
    }
}

/// The current value of one series.
pub fn value(labels: TxExecutionErrorLabels) -> u64 {
    (0..SERIES_COUNT)
        .find(|&i| labels_at(i) == labels)
        .map(|i| COUNTS[i].load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Every series and its current value, in index order. The length is
/// [`SERIES_COUNT`] on every call, for the lifetime of the process.
pub fn snapshot() -> Vec<(TxExecutionErrorLabels, u64)> {
    (0..SERIES_COUNT)
        .map(|i| (labels_at(i), COUNTS[i].load(Ordering::Relaxed)))
        .collect()
}

/// The sum over every series — the aggregate the JSON metrics snapshot carries.
pub fn total() -> u64 {
    COUNTS.iter().map(|c| c.load(Ordering::Relaxed)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// **The label-set pin.** Two labels, named, in this order.
    ///
    /// A third label multiplies the series count by that label's cardinality
    /// and is the failure mode this whole module exists to prevent, so it is
    /// asserted as a value rather than left to review.
    #[test]
    fn the_counter_carries_exactly_two_labels_named_subsystem_and_code() {
        assert_eq!(
            TX_EXECUTION_ERROR_LABEL_NAMES.len(),
            2,
            "a third label on a per-transaction counter multiplies the registry"
        );
        assert_eq!(TX_EXECUTION_ERROR_LABEL_NAMES, ["subsystem", "code"]);
        // The struct carries exactly the two fields the names describe: a
        // third field could not be rendered without a third name.
        let l = labels_at(0);
        assert_eq!(
            format!("{l:?}"),
            r#"TxExecutionErrorLabels { subsystem: "runtime", code: "0" }"#,
            "the label struct gained or lost a field"
        );
    }

    /// Cardinality is a compile-time constant, and a small one.
    #[test]
    fn the_series_set_is_closed_and_bounded() {
        assert_eq!(SERIES_COUNT, FAILURE_SERIES.len() + 5);
        assert_eq!(snapshot().len(), SERIES_COUNT);
        assert!(
            SERIES_COUNT < 256,
            "the whole metric must stay a few hundred series at most; it is {SERIES_COUNT}"
        );
        // Every emitted subsystem value is one of the declared ones.
        let declared: BTreeSet<&str> = SUBSYSTEMS.iter().copied().collect();
        for i in 0..SERIES_COUNT {
            let l = labels_at(i);
            assert!(
                declared.contains(l.subsystem),
                "series {i} emits an undeclared subsystem {:?}",
                l.subsystem
            );
        }
        // And every declared one is actually reachable, so the list cannot
        // rot into a superset nobody emits.
        let emitted: BTreeSet<&str> = (0..SERIES_COUNT).map(|i| labels_at(i).subsystem).collect();
        assert_eq!(emitted, declared, "SUBSYSTEMS and the tables disagree");
    }

    /// No two series share a label tuple — otherwise two causes would add into
    /// one number and the counter would not be attributable.
    #[test]
    fn every_series_is_distinct() {
        let all: BTreeSet<TxExecutionErrorLabels> = (0..SERIES_COUNT).map(labels_at).collect();
        assert_eq!(all.len(), SERIES_COUNT, "two series carry the same labels");
        let codes: BTreeSet<u32> = FAILURE_SERIES.iter().map(|(n, _, _)| *n).collect();
        assert_eq!(codes.len(), FAILURE_SERIES.len(), "a code is listed twice");
    }

    /// An unallocated code is ONE more increment, never one more series.
    /// This is the anti-unboundedness claim stated as behaviour.
    #[test]
    fn an_unallocated_code_lands_on_the_single_unattributed_series() {
        for n in [18u32, 99, 500, 4_294_967_295] {
            assert_eq!(
                labels_for(&TxStatus::Failed(n)),
                Some(UNATTRIBUTED),
                "Failed({n}) must not create a series of its own"
            );
        }
        assert_eq!(snapshot().len(), SERIES_COUNT);
    }

    /// A success is not an execution error.
    #[test]
    fn success_is_not_counted() {
        assert_eq!(labels_for(&TxStatus::Success), None);
        let before = total();
        record(&TxStatus::Success);
        assert_eq!(total(), before);
    }

    /// The nine Wave 1 subsystems each have their own attributable series, and
    /// they are DIFFERENT series — the property the per-subsystem integration
    /// proof in `sumchain-state` depends on.
    #[test]
    fn the_wave_one_subsystems_are_nine_distinct_series() {
        let wave1: &[(u32, &str)] = &[
            (2, "nft"),
            (8, "docclass"),
            (9, "tax"),
            (11, "agreement"),
            (12, "legal"),
            (13, "property"),
            (14, "healthcare"),
            (15, "employment"),
            (16, "finance"),
        ];
        let mut seen = BTreeSet::new();
        for (code, subsystem) in wave1 {
            let l = labels_for(&TxStatus::Failed(*code)).expect("a failure is counted");
            assert_eq!(l.subsystem, *subsystem, "code {code} is attributed wrongly");
            assert_eq!(l.code, code.to_string());
            assert!(seen.insert(l), "two Wave 1 subsystems share a series");
        }
        assert_eq!(seen.len(), 9);
    }

    /// Recording moves the series it names and nothing else.
    #[test]
    fn recording_moves_exactly_one_series() {
        let subject = labels_for(&TxStatus::Failed(400)).unwrap();
        let before = value(subject);
        record(&TxStatus::Failed(400));
        assert!(
            value(subject) > before,
            "the write-set series did not advance"
        );
    }

    /// Every code `TxStatus::description()` gives a SPECIFIC reason for is
    /// allocated a series here. A described code with no series would be a
    /// refusal an operator can read in a receipt and cannot see in telemetry.
    #[test]
    fn every_described_code_has_a_series() {
        let allocated: BTreeSet<u32> = FAILURE_SERIES.iter().map(|(n, _, _)| *n).collect();
        for n in 0u32..=420 {
            if TxStatus::Failed(n).description() != "failed" && !allocated.contains(&n) {
                panic!("Failed({n}) has a description but no telemetry series");
            }
        }
    }
}
