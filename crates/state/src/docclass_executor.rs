//! SRC-80X/81X DocClass Executor
//!
//! Executes DocClass credential transactions including:
//! - Identity Root operations (SRC-800)
//! - Eligibility Attestations (SRC-802)
//! - Revocations (SRC-805)
//! - Academic/Professional Credentials (SRC-810-813)
//! - Issuer Registry management
//!
//! Every operation here takes the block's [`ExecutionView`] and NO `self`
//! receiver. The type is a unit struct: there is no `self.db`, so a committed
//! read or write is not expressible on any of these paths. The candidate
//! accessors live in [`crate::docclass_view`]; the committed twins stay in
//! `sumchain_storage::docclass_store` for RPC, admission and the operator
//! paths.

use sumchain_storage::exec_view::ExecutionView;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    AcademicCredential, Address, Balance, BlockHeight, CredentialId, DocClassEvent, DocClassIssuer,
    DocClassIssuerStatus, DocClassOperation, DocClassTxData, DocSubcode, EligibilityAttestation,
    Hash, IdentityKey, IdentityRoot, IdentityStatus, IssuerKey, RevocationReason, RevocationRecord,
    RevocationStatus, ServiceEndpoint, Timestamp,
};
use tracing::{debug, warn};

use crate::docclass_view::BoundedRow;
use crate::{Result, SchemaValidator, StateError, StateManager};

/// Domain separator for the keyless DocClass issuer-stake escrow account.
///
/// Mirrors `gov_escrow_address`'s construction: a blake3 hash of a fixed domain
/// string, truncated to twenty bytes. Nobody holds a key for it, so the balance
/// it accumulates can only move through the two paths in this file that move
/// it -- registration in, deactivation out.
pub const DOCCLASS_STAKE_ESCROW_DOMAIN: &[u8] = b"sumchain/docclass/issuer-stake-escrow/v1";

/// The activation decisions a DocClass transaction executes under.
///
/// One value per chain-defined activation height this subsystem is gated on.
/// [`DocClassExecutor::execute`] derives it from `ChainParams`;
/// [`DocClassExecutor::execute_with_gates`] takes it directly, which is how a
/// test drives an ungated node and a gated node over the same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DocClassGates {
    /// Issuer registration stakes are escrowed and refundable rather than
    /// destroyed. ACTIVATION-AUDIT row OV-26.
    pub stake_escrow: bool,
    /// The identity subject index lives in its own key space, so it can no
    /// longer be overwritten by a credential list at a colliding commitment.
    /// ACTIVATION-AUDIT row BD-6.
    pub subject_index_split: bool,
    /// The revocation family consults the issuer registry, so a suspended or
    /// revoked issuer stops controlling what it issued. ACTIVATION-AUDIT row
    /// AU-36.
    pub revocation_standing: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
    /// A transaction's sizing inputs are checked against a limit BEFORE the
    /// value they size is built: an oversized payload is refused before it is
    /// decoded, and a stored row past the limit is refused before it is decoded
    /// and re-encoded. ACTIVATION-AUDIT rows AL-10 and AL-11.
    pub allocation_bound: bool,
    /// An operation that writes nothing reports a failed receipt rather
    /// than a success one. ACTIVATION-AUDIT row OV-25.
    pub no_op_receipt: bool,
    /// `UpdateIssuer` stops rewriting the registry's record of what the issuer
    /// is allowed to do -- including its `status`, so a suspended issuer can no
    /// longer restore itself. ACTIVATION-AUDIT row AU-34.
    pub issuer_authority: bool,
    /// `Revoked` and `Superseded` are terminal, and a revocation record is
    /// keyed by its transaction as well as its height, so two records at one
    /// height are two rows. ACTIVATION-AUDIT rows OV-23 and OV-24.
    pub revocation_record: bool,
    /// The envelope's `DocSubcode` selects the credential family instead of a
    /// trial decode, and the schema validator covers the families it selects.
    /// ACTIVATION-AUDIT rows OV-27 and D-19b.
    pub credential_schema: bool,
    /// A subject commitment is bound to the controller that anchored it first,
    /// and an identity root is created `Active` rather than into whatever
    /// lifecycle state the payload asked for. ACTIVATION-AUDIT row AU-35, in
    /// part.
    pub identity_binding: bool,
    /// `RegisterIssuer` applies the minimum-stake check only when
    /// `DocClassParams::require_issuer_stake` says to. ACTIVATION-AUDIT row
    /// AU-37, in part.
    pub issuer_stake_requirement: bool,
    /// A credential carrying a signature this subsystem cannot check is
    /// refused rather than stored. ACTIVATION-AUDIT row AU-33.
    pub signature_unsupported: bool,
    /// A credential's validity window is bounded by
    /// `DocClassParams::max_credential_validity`, in milliseconds.
    /// ACTIVATION-AUDIT row AU-37, the `max_credential_validity` third.
    pub credential_validity_bound: bool,
    /// An attribute key on a subcode that has no allowlist is refused, because
    /// every key on it is unclassified. ACTIVATION-AUDIT row D-19b, the half no
    /// height closed.
    pub unknown_attribute_refused: bool,
}

impl DocClassGates {
    /// The stored-row length limit this gate imposes, or `None` when closed.
    ///
    /// `None` is what every bounded reader in `docclass_view.rs` treats as "no
    /// limit", so a closed gate reads byte-for-byte what the unbounded reader
    /// read.
    #[inline]
    pub fn row_limit(self) -> Option<usize> {
        self.allocation_bound
            .then_some(crate::MAX_ACCUMULATING_ROW_BYTES)
    }

    /// Every gate closed -- the release configuration today, under both
    /// readings, because none of the fields these read exists in `ChainParams`.
    pub const CLOSED: Self = Self {
        stake_escrow: false,
        subject_index_split: false,
        revocation_standing: false,
        real_block_timestamp: false,
        allocation_bound: false,
        no_op_receipt: false,
        issuer_authority: false,
        revocation_record: false,
        credential_schema: false,
        identity_binding: false,
        issuer_stake_requirement: false,
        signature_unsupported: false,
        credential_validity_bound: false,
        unknown_attribute_refused: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        stake_escrow: true,
        subject_index_split: true,
        revocation_standing: true,
        real_block_timestamp: true,
        allocation_bound: true,
        no_op_receipt: true,
        issuer_authority: true,
        revocation_record: true,
        credential_schema: true,
        identity_binding: true,
        issuer_stake_requirement: true,
        signature_unsupported: true,
        credential_validity_bound: true,
        unknown_attribute_refused: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            stake_escrow: DocClassExecutor::stake_escrow_gate_open(params, block_height),
            subject_index_split: DocClassExecutor::subject_index_split_gate_open(
                params,
                block_height,
            ),
            revocation_standing: DocClassExecutor::revocation_standing_gate_open(
                params,
                block_height,
            ),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            allocation_bound: crate::subsystem_allocation_bound_gate_open(params, block_height),
            no_op_receipt: crate::subsystem_no_op_receipt_gate_open(params, block_height),
            issuer_authority: DocClassExecutor::issuer_authority_gate_open(params, block_height),
            revocation_record: DocClassExecutor::revocation_record_gate_open(params, block_height),
            credential_schema: DocClassExecutor::credential_schema_gate_open(params, block_height),
            identity_binding: DocClassExecutor::identity_binding_gate_open(params, block_height),
            issuer_stake_requirement: DocClassExecutor::issuer_stake_requirement_gate_open(
                params,
                block_height,
            ),
            signature_unsupported: DocClassExecutor::signature_unsupported_gate_open(
                params,
                block_height,
            ),
            credential_validity_bound: DocClassExecutor::credential_validity_bound_gate_open(
                params,
                block_height,
            ),
            unknown_attribute_refused: DocClassExecutor::unknown_attribute_refused_gate_open(
                params,
                block_height,
            ),
        }
    }
}

/// The account a DocClass issuer's registration stake is held in.
pub fn docclass_stake_escrow_address() -> Address {
    let hash = blake3::hash(DOCCLASS_STAKE_ESCROW_DOMAIN);
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash.as_bytes()[12..32]);
    Address::new(bytes)
}

/// Result of DocClass execution
#[derive(Debug)]
pub struct DocClassExecutionResult {
    pub success: bool,
    pub credential_id: Option<CredentialId>,
    pub error: Option<String>,
}

impl DocClassExecutionResult {
    pub fn success(credential_id: Option<CredentialId>) -> Self {
        Self {
            success: true,
            credential_id,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            credential_id: None,
            error: Some(error.into()),
        }
    }
}

/// DocClass executor for SRC-80X/81X transactions.
///
/// A unit struct. `ChainParams` arrives as a parameter because two operations
/// need it -- `RegisterIssuer` reads `min_issuer_stake`, `DeactivateIssuer`
/// reads `admin` -- and a field holding it would be one more thing on `self`
/// for a future read to hide behind.
pub struct DocClassExecutor;

impl DocClassExecutor {
    /// The activation height for the DocClass issuer-stake escrow rule.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-80X DocClass issuer-stake escrow. Dormant by default (`None` ->
    /// /// never open). Below the gate, `RegisterIssuer` deducts `fee +
    /// /// stake_amount` from the sender and credits only `fee` to the
    /// /// proposer: the stake is destroyed and the total supply falls by an
    /// /// amount the sender chose. At and above the gate the stake is credited
    /// /// to the keyless escrow account, `DeactivateIssuer` returns it, and
    /// /// `UpdateIssuer` can no longer restate the recorded amount. Activation
    /// /// is a consensus change -- it changes account balances and therefore
    /// /// every subsequent receipt -- and needs a coordinated validator
    /// /// upgrade.
    /// #[serde(default)]
    /// pub docclass_stake_escrow_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and the pinning test that records the destruction still passes.
    #[inline]
    fn stake_escrow_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_stake_escrow_enabled_from_height
    }

    /// Whether the issuer-stake escrow rule is active at `block_height`.
    #[inline]
    pub fn stake_escrow_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::stake_escrow_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the DocClass subject-index split.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// The field this function must read, once `crates/genesis` adds it, is:
    ///
    /// ```text
    /// /// SRC-80X DocClass subject-index key split. Dormant by default
    /// /// (`None` -> never open). Below the gate the identity index and the
    /// /// credential index share one key -- the bare 32-byte subject
    /// /// commitment -- with two incompatible value shapes, so a sender who
    /// /// picks a colliding commitment silently destroys one index and makes
    /// /// the next identity operation on that subject a block-level error. At
    /// /// and above the gate the identity shape writes a tagged 33-byte key of
    /// /// its own; reads try the tagged key and fall back to the legacy one,
    /// /// so rows written before activation are still found. Activation is a
    /// /// consensus change -- it moves where a row is written and therefore
    /// /// which blocks execute -- and needs a coordinated validator upgrade.
    /// #[serde(default)]
    /// pub docclass_subject_index_split_enabled_from_height: Option<u64>,
    /// ```
    #[inline]
    fn subject_index_split_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_subject_index_split_enabled_from_height
    }

    /// Whether the subject-index split is active at `block_height`.
    #[inline]
    pub fn subject_index_split_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::subject_index_split_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the DocClass revocation-standing rule.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// The field this function must read, once `crates/genesis` adds it, is:
    ///
    /// ```text
    /// /// SRC-80X DocClass revocation standing. Dormant by default (`None` ->
    /// /// never open). Below the gate the whole revocation family -- revoke,
    /// /// suspend, reactivate and supersede -- authorizes through
    /// /// `check_revoke_auth`, which reads only the `issuer` field recorded on
    /// /// the credential row and never consults the issuer registry. So a
    /// /// suspended or revoked issuer keeps control of everything it issued,
    /// /// while the ISSUE paths do consult the registry through
    /// /// `v_can_issue_subcode`. At and above the gate the revocation family
    /// /// asks the registry the same question. Activation is a consensus
    /// /// change and needs a coordinated validator upgrade.
    /// #[serde(default)]
    /// pub docclass_revocation_standing_enabled_from_height: Option<u64>,
    /// ```
    #[inline]
    fn revocation_standing_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_revocation_standing_enabled_from_height
    }

    /// Whether the revocation-standing rule is active at `block_height`.
    #[inline]
    pub fn revocation_standing_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::revocation_standing_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the DocClass issuer-authority rule.
    ///
    /// Reads `params.docclass_issuer_authority_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate `UpdateIssuer` writes the whole payload struct over the
    /// registry row, so a registered issuer grants itself any subcode, declares
    /// any jurisdiction, and a SUSPENDED issuer restores itself to `Active`
    /// with one transaction. At and above it the five fields the registry is
    /// authoritative about -- `status`, `authorized_subcodes`, `jurisdictions`,
    /// `issuer_type` and `registered_at` -- keep their recorded values.
    /// ACTIVATION-AUDIT row AU-34.
    #[inline]
    fn issuer_authority_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_issuer_authority_enabled_from_height
    }

    /// Whether the issuer-authority rule is active at `block_height`.
    #[inline]
    pub fn issuer_authority_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::issuer_authority_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the DocClass revocation-record rules.
    ///
    /// Reads `params.docclass_revocation_record_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate `suspend_credential` has no current-status guard, so a
    /// REVOKED credential is suspended and then reactivated back to `Active`
    /// (row OV-23); and a revocation record is keyed by
    /// `credential_id || revoked_at_height` alone, so two records for one
    /// credential at one height are one row and the later write silently
    /// replaces the earlier (row OV-24). At and above it `Revoked` and
    /// `Superseded` are terminal and the key carries the transaction index as
    /// well.
    #[inline]
    fn revocation_record_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_revocation_record_enabled_from_height
    }

    /// Whether the revocation-record rules are active at `block_height`.
    #[inline]
    pub fn revocation_record_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::revocation_record_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the DocClass credential-schema rules.
    ///
    /// Reads `params.docclass_credential_schema_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate `IssueCredential` picks its family by trying to decode an
    /// `AcademicCredential`, falling through to `EligibilityAttestation`, and
    /// discarding the first error, without ever reading the `DocSubcode` the
    /// envelope declares (row OV-27); and the schema validator has arms for
    /// three subcodes and returns `Valid` for every other one and for every
    /// eligibility attestation (row D-19b). At and above it the envelope's
    /// subcode selects the family, the credential's own subcode must agree with
    /// it, and every family the gate selects is checked.
    #[inline]
    fn credential_schema_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_credential_schema_enabled_from_height
    }

    /// Whether the credential-schema rules are active at `block_height`.
    #[inline]
    pub fn credential_schema_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::credential_schema_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the DocClass identity-binding rules.
    ///
    /// Reads `params.docclass_identity_binding_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate `create_identity_root` checks `controller == sender` and
    /// then stores the payload struct verbatim, so any funded account anchors a
    /// root claiming any `subject_commitment`, in any `status`. At and above it
    /// a commitment another controller already anchored is refused and the
    /// status is the executor's `Active`. ACTIVATION-AUDIT row AU-35, in part:
    /// nothing here binds the commitment to a PERSON, because this tree records
    /// nothing to bind it to.
    #[inline]
    fn identity_binding_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_identity_binding_enabled_from_height
    }

    /// Whether the identity-binding rules are active at `block_height`.
    #[inline]
    pub fn identity_binding_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::identity_binding_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for reading `DocClassParams::require_issuer_stake`.
    ///
    /// Reads `params.docclass_issuer_stake_requirement_enabled_from_height`,
    /// and nothing else. `None` -- the default, and what a genesis written
    /// before the field existed resolves to -- closes the gate, so a node
    /// executes exactly what it executed before the field was declared.
    ///
    /// Below the gate `require_issuer_stake` is declared, defaulted, reported
    /// by `docclass_getConfig` and read by no execution path: registration
    /// enforces `min_issuer_stake` whenever it is non-zero, whatever the flag
    /// says. At and above it the check runs only when the flag is true.
    /// ACTIVATION-AUDIT row AU-37, in part.
    #[inline]
    fn issuer_stake_requirement_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_issuer_stake_requirement_enabled_from_height
    }

    /// Whether the declared issuer-stake requirement is read at `block_height`.
    #[inline]
    pub fn issuer_stake_requirement_gate_open(
        params: &ChainParams,
        block_height: BlockHeight,
    ) -> bool {
        matches!(Self::issuer_stake_requirement_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the DocClass signature refusal.
    ///
    /// Reads `params.docclass_signature_unsupported_enabled_from_height`, and
    /// nothing else. `None` closes the gate.
    ///
    /// ACTIVATION-AUDIT row AU-33. No signature is verified anywhere in this
    /// subsystem: `issuer_signature` is stored verbatim and read by nothing.
    /// Verification was examined against the tree's own convention -- the
    /// domain-separated blake3 digest plus ed25519 check that
    /// `healthcare_consent_subject_signature_enabled_from_height` uses -- and
    /// refused rather than invented. That construction needs a public key IN
    /// the payload that derives to an address IN the payload, and a canonical
    /// fixed-width field set on the wire type. DocClass has neither: it carries
    /// `issuer_key_id: String`, a NAME whose resolution against
    /// `DocClassIssuer.keys` no rule states, and its credentials are half
    /// variable-length `String` with no framing convention. A rule that
    /// computes the wrong preimage refuses every lawful credential, so the
    /// operation stays UNSUPPORTED and says so.
    #[inline]
    fn signature_unsupported_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_signature_unsupported_enabled_from_height
    }

    /// Whether the DocClass signature refusal is active at `block_height`.
    #[inline]
    pub fn signature_unsupported_gate_open(
        params: &ChainParams,
        block_height: BlockHeight,
    ) -> bool {
        matches!(Self::signature_unsupported_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the credential-validity bound.
    ///
    /// Reads `params.docclass_credential_validity_bound_enabled_from_height`,
    /// and nothing else. `None` closes the gate.
    ///
    /// ACTIVATION-AUDIT row AU-37, the `max_credential_validity` third. The
    /// field is declared, defaulted and reported over `docclass_getConfig`, and
    /// read by no execution path -- so a credential declaring `valid_from: 0`
    /// and `expires_at: u64::MAX` is accepted and the unbounded window stored.
    /// What blocked the reader was the UNIT, and the unit is now settled from
    /// the code: `PoaEngine::current_timestamp` builds a block timestamp with
    /// `as_millis()`, `BlockHeader::timestamp` documents itself "(ms since
    /// epoch)", and a credential's `valid_from`/`expires_at` share that
    /// `Timestamp` alias -- so the bound is a duration in MILLISECONDS.
    #[inline]
    fn credential_validity_bound_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_credential_validity_bound_enabled_from_height
    }

    /// Whether the credential-validity bound is applied at `block_height`.
    #[inline]
    pub fn credential_validity_bound_gate_open(
        params: &ChainParams,
        block_height: BlockHeight,
    ) -> bool {
        matches!(Self::credential_validity_bound_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the unclassified-attribute refusal.
    ///
    /// Reads `params.docclass_unknown_attribute_refused_enabled_from_height`,
    /// and nothing else. `None` closes the gate.
    ///
    /// ACTIVATION-AUDIT row D-19b, the half
    /// `docclass_credential_schema_enabled_from_height` leaves open: that gate
    /// extends the LENGTH bounds to every academic subcode and leaves the
    /// attribute KEYS unrestricted for the subcodes whose standard lists none,
    /// because inventing an allowlist would be writing standard. This gate does
    /// not invent one either -- it takes the other reading of "no allowlist
    /// exists": every key on such a subcode is unclassified, and an
    /// unclassified key fails closed. A credential carrying no attributes is
    /// unaffected, and the three covered subcodes keep their own allowlists.
    #[inline]
    fn unknown_attribute_refused_activation(params: &ChainParams) -> Option<u64> {
        params.docclass_unknown_attribute_refused_enabled_from_height
    }

    /// Whether the unclassified-attribute refusal is active at `block_height`.
    #[inline]
    pub fn unknown_attribute_refused_gate_open(
        params: &ChainParams,
        block_height: BlockHeight,
    ) -> bool {
        matches!(Self::unknown_attribute_refused_activation(params), Some(h) if block_height >= h)
    }

    /// Whether `subcode` has an attribute allowlist in `SchemaValidator`.
    ///
    /// The three that do are the three the validator dispatches on: 810
    /// (`AcademicTranscript`), 811 (`Diploma`) and 812
    /// (`EnrollmentVerification`). Every other academic subcode reaches the
    /// `_` arm, which applies length bounds and no key rule at all. Kept beside
    /// the gate rather than inside `SchemaValidator` because it is the GATE's
    /// question -- "is there a list for this key to be unknown to" -- and not
    /// the validator's.
    #[inline]
    fn subcode_has_attribute_allowlist(subcode: DocSubcode) -> bool {
        matches!(
            subcode,
            DocSubcode::AcademicTranscript
                | DocSubcode::Diploma
                | DocSubcode::EnrollmentVerification
        )
    }

    /// Execute a DocClass transaction.
    ///
    /// Reads every activation height this subsystem is gated on out of `params`
    /// and dispatches through [`Self::execute_with_gates`].
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &DocClassTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<DocClassExecutionResult> {
        Self::execute_with_gates(
            view,
            params,
            sender,
            data,
            proposer,
            fee,
            block_height,
            block_timestamp,
            tx_index,
            tx_hash,
            DocClassGates::from_params(params, block_height),
        )
    }

    /// A stored row longer than the bound, refused without being decoded.
    ///
    /// One wording for every family so the refusal is greppable, and the LENGTH
    /// is in it: an operator reading a receipt needs to know the row is over the
    /// limit and by how much, because the remedy is not "retry".
    fn row_too_large(what: &str, bytes: usize) -> DocClassExecutionResult {
        DocClassExecutionResult::failure(format!(
            "{what} too large to modify: {bytes} bytes, limit {}",
            crate::MAX_ACCUMULATING_ROW_BYTES
        ))
    }

    /// Execute a DocClass transaction with the activation decisions supplied
    /// directly.
    ///
    /// The seam the mixed-version tests use: `gates` is the only thing that
    /// differs between a node below an activation height and one at or above
    /// it, so driving both values through one entry point is what makes the
    /// divergence observable rather than asserted.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &DocClassTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        _tx_hash: Hash,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);

        // ACTIVATION-AUDIT rows AL-10, AL-11, and the DocClass half of AL-12.
        // Every arm below opens with `bincode::deserialize(data)` and no length
        // check ahead of it, so the only thing bounding a DocClass payload
        // today is `max_block_bytes`. One check here, before the dispatch,
        // rather than one per arm: the arms are eighteen and the rule is one,
        // and a per-arm check is a rule with eighteen chances to be forgotten.
        //
        // This is a refusal, not an error: below the gate an undecodable
        // payload is `Err(...)` and takes the whole block with it, and an
        // oversized one that happens to decode is admitted. Above the gate an
        // oversized payload is a failed receipt in a valid block, whether or not
        // it would have decoded. That difference is the consensus change the
        // activation height coordinates.
        //
        // The refusal charges nothing and does not advance the nonce, because
        // every arm below deducts the fee itself and every pre-existing
        // `failure()` that fires before that deduction -- "Controller must be
        // sender", "Identity already exists", "Not authorized" -- is already
        // free. Refusing here is consistent with those rather than with the NFT
        // executor, which deducts once up front. It is not a new spam surface:
        // the transaction's bytes still occupy the block that `max_block_bytes`
        // bounds, and what changes is that the node stops doing megabytes of
        // work for them.
        if gates.allocation_bound && data.data.len() > crate::MAX_SUBSYSTEM_PAYLOAD_BYTES {
            return Ok(DocClassExecutionResult::failure(format!(
                "DocClass payload too large: {} bytes, limit {}",
                data.data.len(),
                crate::MAX_SUBSYSTEM_PAYLOAD_BYTES
            )));
        }

        match data.operation {
            // Identity operations (SRC-800)
            DocClassOperation::CreateIdentityRoot => Self::create_identity_root(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::AddKey => Self::identity_add_key(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::RemoveKey => Self::identity_remove_key(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::RotateKey => Self::identity_rotate_key(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::AddController => Self::identity_add_controller(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::RemoveController => Self::identity_remove_controller(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::UpdateService => Self::identity_update_service(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::DeactivateIdentity => Self::deactivate_identity(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                gates,
            ),
            DocClassOperation::ReactivateIdentity => Self::reactivate_identity(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                gates,
            ),

            // Credential operations (SRC-802, SRC-810-813)
            DocClassOperation::IssueCredential => Self::issue_credential(
                view,
                params,
                sender,
                data.subcode,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::UpdateCredential => {
                Self::update_credential(view, sender, &data.data, proposer, fee, gates)
            }

            // Revocation operations (SRC-805)
            DocClassOperation::RevokeCredential => Self::revoke_credential(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                gates,
            ),
            DocClassOperation::SuspendCredential => Self::suspend_credential(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                gates,
            ),
            DocClassOperation::ReactivateCredential => Self::reactivate_credential(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                gates,
            ),
            DocClassOperation::SupersedeCredential => Self::supersede_credential(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                gates,
            ),

            // Issuer Registry operations
            DocClassOperation::RegisterIssuer => Self::register_issuer(
                view,
                params,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::UpdateIssuer => Self::update_issuer(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::RotateIssuerKey => Self::rotate_issuer_key(
                view,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            ),
            DocClassOperation::DeactivateIssuer => Self::deactivate_issuer(
                view,
                params,
                sender,
                &data.data,
                proposer,
                fee,
                block_height,
                block_timestamp,
                tx_index,
                gates,
            ),
        }
    }

    // ========================================================================
    // Identity Root Operations (SRC-800)
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    fn create_identity_root(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        let identity: IdentityRoot = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid identity data: {}", e)))?;

        if identity.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Controller must be sender"));
        }

        if Self::v_identity_root_exists(view, &identity.identity_id)? {
            return Ok(DocClassExecutionResult::failure("Identity already exists"));
        }

        // At or above the identity-binding activation a subject commitment
        // belongs to the controller that anchored it FIRST. Below it the only
        // check on this path is `controller == sender`, which says who sent the
        // transaction and nothing at all about whose subject is being claimed,
        // so any funded account anchors a root over a commitment somebody else
        // already anchored. ACTIVATION-AUDIT row AU-35.
        //
        // This is squatting resistance, not authentication: the commitment is
        // bound to an ADDRESS, because an address is the only thing this
        // subsystem records that could hold it. Refused before the fee, like
        // the duplicate guard above it.
        if gates.identity_binding {
            let limit = gates.row_limit();
            for (existing_id, _) in
                Self::v_get_subject_identity_entries(view, &identity.subject_commitment)?
            {
                let row = Self::v_get_identity_root_bounded(view, &existing_id, limit)?;
                let controller = match row {
                    BoundedRow::Row(r) => r.controller,
                    BoundedRow::Missing => continue,
                    BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
                };
                if controller != *sender {
                    return Ok(DocClassExecutionResult::failure(
                        "Subject commitment is already anchored by another controller",
                    ));
                }
            }
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        let mut identity = identity;
        // The lifecycle state is the executor's. `DeactivateIdentity` and
        // `ReactivateIdentity` are the arms that move it; a creation that could
        // choose it makes those two optional. ACTIVATION-AUDIT row AU-35.
        if gates.identity_binding {
            identity.status = IdentityStatus::Active;
        }

        Self::v_put_identity_root(view, &identity, gates.subject_index_split)?;

        let event = DocClassEvent::IdentityRootCreated {
            identity_id: identity.identity_id,
            controller: identity.controller,
            subject_commitment: identity.subject_commitment,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        debug!("Identity root created: {:?}", identity.identity_id);
        Ok(DocClassExecutionResult::success(Some(identity.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn identity_add_key(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct AddKeyData {
            identity_id: CredentialId,
            key: IdentityKey,
        }

        let add_data: AddKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match Self::v_get_identity_root_bounded(
            view,
            &add_data.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        identity.keys.push(add_data.key.clone());
        Self::v_put_identity_root(view, &identity, gates.subject_index_split)?;

        let event = DocClassEvent::KeyAdded {
            identity_id: add_data.identity_id,
            key_id: add_data.key.key_id,
            key_type: add_data.key.key_type,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(add_data.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn identity_remove_key(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RemoveKeyData {
            identity_id: CredentialId,
            key_id: String,
        }

        let remove_data: RemoveKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match Self::v_get_identity_root_bounded(
            view,
            &remove_data.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        identity.keys.retain(|k| k.key_id != remove_data.key_id);
        Self::v_put_identity_root(view, &identity, gates.subject_index_split)?;

        let event = DocClassEvent::KeyRemoved {
            identity_id: remove_data.identity_id,
            key_id: remove_data.key_id,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(remove_data.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn identity_rotate_key(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RotateKeyData {
            identity_id: CredentialId,
            old_key_id: String,
            new_key: IdentityKey,
        }

        let rotate_data: RotateKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match Self::v_get_identity_root_bounded(
            view,
            &rotate_data.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        identity.keys.retain(|k| k.key_id != rotate_data.old_key_id);
        let new_key_id = rotate_data.new_key.key_id.clone();
        identity.keys.push(rotate_data.new_key);
        Self::v_put_identity_root(view, &identity, gates.subject_index_split)?;

        let event = DocClassEvent::KeyRotated {
            identity_id: rotate_data.identity_id,
            old_key_id: rotate_data.old_key_id,
            new_key_id,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(rotate_data.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn identity_add_controller(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct AddControllerData {
            identity_id: CredentialId,
            controller: Address,
        }

        let add_data: AddControllerData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match Self::v_get_identity_root_bounded(
            view,
            &add_data.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if identity.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only primary controller can add"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        if !identity.additional_controllers.contains(&add_data.controller) {
            identity.additional_controllers.push(add_data.controller);
        }
        Self::v_put_identity_root(view, &identity, gates.subject_index_split)?;

        let event = DocClassEvent::ControllerAdded {
            identity_id: add_data.identity_id,
            controller: add_data.controller,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(add_data.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn identity_remove_controller(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RemoveControllerData {
            identity_id: CredentialId,
            controller: Address,
        }

        let remove_data: RemoveControllerData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match Self::v_get_identity_root_bounded(
            view,
            &remove_data.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if identity.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only primary controller can remove"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        identity.additional_controllers.retain(|c| c != &remove_data.controller);
        Self::v_put_identity_root(view, &identity, gates.subject_index_split)?;

        let event = DocClassEvent::ControllerRemoved {
            identity_id: remove_data.identity_id,
            controller: remove_data.controller,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(remove_data.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn identity_update_service(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct UpdateServiceData {
            identity_id: CredentialId,
            service: ServiceEndpoint,
        }

        let update_data: UpdateServiceData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match Self::v_get_identity_root_bounded(
            view,
            &update_data.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        let service_id = update_data.service.service_id.clone();
        if let Some(s) = identity.services.iter_mut().find(|s| s.service_id == update_data.service.service_id) {
            *s = update_data.service;
        } else {
            identity.services.push(update_data.service);
        }
        Self::v_put_identity_root(view, &identity, gates.subject_index_split)?;

        let event = DocClassEvent::ServiceUpdated {
            identity_id: update_data.identity_id,
            service_id,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(update_data.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn deactivate_identity(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct DeactivateData {
            identity_id: CredentialId,
        }

        let deactivate: DeactivateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let existing = match Self::v_get_identity_root_bounded(
            view,
            &deactivate.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if existing.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only controller can deactivate"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        Self::v_update_identity_status(
            view,
            &deactivate.identity_id,
            IdentityStatus::Deactivated,
            block_timestamp,
            gates.subject_index_split,
        )?;

        let event = DocClassEvent::IdentityStatusChanged {
            identity_id: deactivate.identity_id,
            new_status: IdentityStatus::Deactivated,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(deactivate.identity_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn reactivate_identity(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct ReactivateData {
            identity_id: CredentialId,
        }

        let reactivate: ReactivateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let existing = match Self::v_get_identity_root_bounded(
            view,
            &reactivate.identity_id,
            gates.row_limit(),
        )? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => {
                return Ok(DocClassExecutionResult::failure("Identity not found"))
            }
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Identity root", n)),
        };

        if existing.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only controller can reactivate"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        Self::v_update_identity_status(
            view,
            &reactivate.identity_id,
            IdentityStatus::Active,
            block_timestamp,
            gates.subject_index_split,
        )?;

        let event = DocClassEvent::IdentityStatusChanged {
            identity_id: reactivate.identity_id,
            new_status: IdentityStatus::Active,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(reactivate.identity_id)))
    }

    // ========================================================================
    // Credential Operations
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    /// Which credential family an `IssueCredential` transaction is.
    ///
    /// Below `docclass_credential_schema_enabled_from_height` this is a TRIAL
    /// DECODE: try `AcademicCredential`, fall through to
    /// `EligibilityAttestation` on failure, discard the first error, and never
    /// look at the `DocSubcode` the envelope declares. It works only because
    /// the two schemas do not currently cross-decode, and nothing in this tree
    /// enforces that they never will -- add one optional field to either and a
    /// transaction the sender declared as one family is executed, stored and
    /// indexed as the other. ACTIVATION-AUDIT row OV-27.
    ///
    /// At and above the gate the envelope's subcode chooses, the payload must
    /// decode as that family or the transaction is a failed receipt, and the
    /// credential's OWN `subcode` field must agree with the envelope's -- the
    /// agreement matters because it is `credential.subcode`, not the envelope's,
    /// that the schema validator dispatches on and that the issuer-authority
    /// check `v_can_issue_subcode` is asked about, so two subcodes that
    /// disagree are two different questions answered about one row.
    #[allow(clippy::too_many_arguments)]
    /// The AU-33 refusal, or `None` when the credential asserts no signature.
    ///
    /// Both halves are refused, because both are a claim: sixty-four bytes in
    /// `issuer_signature` assert that something was signed, and a non-empty
    /// `issuer_key_id` asserts that a particular key signed it. Neither can be
    /// checked -- there is no canonical signing input for the bytes to be over,
    /// and no stated rule for resolving the id against `DocClassIssuer.keys`.
    /// An all-zero signature with an empty key id asserts nothing and is
    /// admitted unchanged, which is what keeps the gate a refusal of the CLAIM
    /// rather than of the credential.
    #[inline]
    fn signature_claim_refusal(
        gates: DocClassGates,
        issuer_signature: &[u8; 64],
        issuer_key_id: &str,
    ) -> Option<DocClassExecutionResult> {
        if gates.signature_unsupported
            && (issuer_signature != &[0u8; 64] || !issuer_key_id.is_empty())
        {
            return Some(DocClassExecutionResult::failure(
                crate::DOCCLASS_SIGNATURE_UNSUPPORTED,
            ));
        }
        None
    }

    /// The AU-37 refusal, or `None` when the window is within the bound.
    ///
    /// Three configurations pass through untouched, each for a reason the
    /// field's own documentation states. `max_credential_validity == 0` is NO
    /// LIMIT and is the default, so an operator who configured nothing sees no
    /// change at the height. `expires_at == 0` is NO EXPIRY, so bounding it
    /// would refuse the credential the wire type calls unexpiring. An
    /// `expires_at` at or below `valid_from` is a window of zero or a malformed
    /// one, and this rule is a ceiling rather than a well-formedness check --
    /// `saturating_sub` makes it zero rather than an underflow into acceptance.
    ///
    /// The unit is MILLISECONDS on both sides: `valid_from` and `expires_at`
    /// share the `Timestamp` alias with `BlockHeader::timestamp`, which
    /// `PoaEngine::current_timestamp` fills with `as_millis()`.
    #[inline]
    fn validity_window_refusal(
        gates: DocClassGates,
        params: &ChainParams,
        valid_from: Timestamp,
        expires_at: Timestamp,
    ) -> Option<DocClassExecutionResult> {
        if !gates.credential_validity_bound || expires_at == 0 {
            return None;
        }
        let max = params
            .docclass
            .as_ref()
            .map(|d| d.max_credential_validity)
            .unwrap_or(0);
        if max != 0 && expires_at.saturating_sub(valid_from) > max {
            return Some(DocClassExecutionResult::failure(
                crate::DOCCLASS_CREDENTIAL_VALIDITY_TOO_LONG,
            ));
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_credential(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        subcode: DocSubcode,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        if gates.credential_schema {
            return match subcode {
                DocSubcode::EligibilityAttestation => {
                    match bincode::deserialize::<EligibilityAttestation>(data) {
                        Ok(att) if att.subcode != subcode => {
                            Ok(DocClassExecutionResult::failure(format!(
                                "Attestation subcode {:?} disagrees with the transaction's {:?}",
                                att.subcode, subcode
                            )))
                        }
                        Ok(att) => Self::issue_eligibility(
                            view,
                            params,
                            sender,
                            att,
                            proposer,
                            fee,
                            block_height,
                            tx_index,
                            gates,
                        ),
                        Err(e) => Ok(DocClassExecutionResult::failure(format!(
                            "Not an eligibility attestation: {e}"
                        ))),
                    }
                }
                s if s.is_academic_class() => {
                    match bincode::deserialize::<AcademicCredential>(data) {
                        Ok(cred) if cred.subcode != subcode => {
                            Ok(DocClassExecutionResult::failure(format!(
                                "Credential subcode {:?} disagrees with the transaction's {:?}",
                                cred.subcode, subcode
                            )))
                        }
                        Ok(cred) => Self::issue_academic_credential(
                            view,
                            params,
                            sender,
                            cred,
                            proposer,
                            fee,
                            block_height,
                            tx_index,
                            gates,
                        ),
                        Err(e) => Ok(DocClassExecutionResult::failure(format!(
                            "Not an academic credential: {e}"
                        ))),
                    }
                }
                other => Ok(DocClassExecutionResult::failure(format!(
                    "IssueCredential does not carry subcode {other:?}"
                ))),
            };
        }

        // Try academic credential first
        if let Ok(cred) = bincode::deserialize::<AcademicCredential>(data) {
            return Self::issue_academic_credential(
                view,
                params,
                sender,
                cred,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            );
        }
        // Try eligibility attestation
        if let Ok(att) = bincode::deserialize::<EligibilityAttestation>(data) {
            return Self::issue_eligibility(
                view,
                params,
                sender,
                att,
                proposer,
                fee,
                block_height,
                tx_index,
                gates,
            );
        }
        Ok(DocClassExecutionResult::failure("Invalid credential data"))
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_academic_credential(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        credential: AcademicCredential,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        if credential.issuer != *sender {
            return Ok(DocClassExecutionResult::failure("Issuer must be sender"));
        }

        let jurisdiction = credential.jurisdiction.as_str();

        if !Self::v_can_issue_subcode(view, sender, credential.subcode, jurisdiction)? {
            return Ok(DocClassExecutionResult::failure("Issuer not authorized"));
        }

        if Self::v_credential_exists(view, &credential.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Credential exists"));
        }

        // ACTIVATION-AUDIT row AU-33. A signature this subsystem cannot check
        // is refused rather than stored. Ahead of the schema validator and
        // ahead of the deduct, where this arm's own refusals return.
        if let Some(refusal) = Self::signature_claim_refusal(
            gates,
            &credential.issuer_signature,
            &credential.issuer_key_id,
        ) {
            return Ok(refusal);
        }

        // ACTIVATION-AUDIT row AU-37. The window is bounded in MILLISECONDS,
        // the unit the chain's block timestamp uses.
        if let Some(refusal) = Self::validity_window_refusal(
            gates,
            params,
            credential.valid_from,
            credential.expires_at,
        ) {
            return Ok(refusal);
        }

        // ACTIVATION-AUDIT row D-19b. A subcode with no allowlist has no
        // classified key, so every attribute on it is unknown and fails closed.
        if gates.unknown_attribute_refused
            && !Self::subcode_has_attribute_allowlist(credential.subcode)
            && !credential.metadata.attributes.is_empty()
        {
            return Ok(DocClassExecutionResult::failure(
                crate::DOCCLASS_UNKNOWN_ATTRIBUTE_REFUSED,
            ));
        }

        // PRIVACY ENFORCEMENT: Validate schema to prevent PII on-chain
        // Hard rejection at consensus level for SRC-81X credentials (810/811/812)
        // At or above the credential-schema activation the validator covers
        // every academic subcode rather than the three that have an allowlist.
        // ACTIVATION-AUDIT row D-19b.
        let validation_result = if gates.credential_schema {
            SchemaValidator::new().validate_academic_credential_wide(&credential, block_height)
        } else {
            SchemaValidator::new().validate_academic_credential(&credential, block_height)
        };
        if !validation_result.is_valid() {
            if let crate::ValidationResult::Invalid { reason } = validation_result {
                warn!(
                    "Schema validation failed for credential {:?}: {}",
                    credential.credential_id, reason
                );
                return Ok(DocClassExecutionResult::failure(format!(
                    "Schema validation failed: {}",
                    reason
                )));
            }
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        Self::v_put_credential(view, &credential)?;

        let event = DocClassEvent::CredentialIssued {
            credential_id: credential.credential_id,
            subcode: credential.subcode,
            issuer: credential.issuer,
            jurisdiction: jurisdiction.to_string(),
            subject_commitment: credential.subject_commitment,
            schema_hash: credential.schema_hash,
            expires_at: credential.expires_at,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        debug!("Credential issued: {:?}", credential.credential_id);
        Ok(DocClassExecutionResult::success(Some(credential.credential_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_eligibility(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        attestation: EligibilityAttestation,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        if attestation.issuer != *sender {
            return Ok(DocClassExecutionResult::failure("Issuer must be sender"));
        }

        if !Self::v_can_issue_subcode(
            view,
            sender,
            DocSubcode::EligibilityAttestation,
            &attestation.jurisdiction,
        )? {
            return Ok(DocClassExecutionResult::failure("Issuer not authorized"));
        }

        if Self::v_eligibility_exists(view, &attestation.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Credential exists"));
        }

        // ACTIVATION-AUDIT rows AU-33 and AU-37, the same two rules the
        // academic arm applies. There is no attributes list on this family, so
        // D-19b's attribute refusal has nothing to reach here -- said rather
        // than left as an omission a reader has to notice.
        if let Some(refusal) = Self::signature_claim_refusal(
            gates,
            &attestation.issuer_signature,
            &attestation.issuer_key_id,
        ) {
            return Ok(refusal);
        }
        if let Some(refusal) = Self::validity_window_refusal(
            gates,
            params,
            attestation.valid_from,
            attestation.expires_at,
        ) {
            return Ok(refusal);
        }

        // No validator has ever run on this family, on any path, at any height.
        // ACTIVATION-AUDIT row D-19b, the "nothing in SRC-80X" half.
        if gates.credential_schema {
            if let crate::ValidationResult::Invalid { reason } =
                SchemaValidator::new().validate_eligibility_attestation(&attestation, block_height)
            {
                warn!(
                    "Schema validation failed for attestation {:?}: {}",
                    attestation.credential_id, reason
                );
                return Ok(DocClassExecutionResult::failure(format!(
                    "Schema validation failed: {}",
                    reason
                )));
            }
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        Self::v_put_eligibility(view, &attestation)?;

        let event = DocClassEvent::CredentialIssued {
            credential_id: attestation.credential_id,
            subcode: DocSubcode::EligibilityAttestation,
            issuer: attestation.issuer,
            jurisdiction: attestation.jurisdiction.clone(),
            subject_commitment: attestation.subject_commitment,
            schema_hash: attestation.schema_hash,
            expires_at: attestation.expires_at,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        debug!("Eligibility issued: {:?}", attestation.credential_id);
        Ok(DocClassExecutionResult::success(Some(attestation.credential_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn update_credential(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct UpdateData {
            credential_id: CredentialId,
        }

        let update: UpdateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        // Just check authorization for now
        let is_authorized = if let Some(c) = Self::v_get_credential(view, &update.credential_id)? {
            c.issuer == *sender
        } else if let Some(a) = Self::v_get_eligibility(view, &update.credential_id)? {
            a.issuer == *sender
        } else {
            return Ok(DocClassExecutionResult::failure("Credential not found"));
        };

        if !is_authorized {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        // ACTIVATION-AUDIT row OV-25. "Just check authorization for now" is the
        // whole implementation: below the gate this arm deducts, credits,
        // increments and returns SUCCESS naming the credential, having written
        // neither the credential nor an event -- on any input, for the
        // credential's own issuer. At and above the gate it says so.
        //
        // A failed receipt, not an implementation: the payload carries nothing
        // but a credential id, so there is no field for an update to apply.
        // Refused after the authorization checks so that "Credential not found"
        // and "Not authorized" stay the more specific answer, and before the
        // deduct, where both of those return.
        if gates.no_op_receipt {
            return Ok(DocClassExecutionResult::failure(
                "UpdateCredential is not implemented and writes no credential",
            ));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        Ok(DocClassExecutionResult::success(Some(update.credential_id)))
    }

    // ========================================================================
    // Revocation Operations
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    fn revoke_credential(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RevokeData {
            credential_id: CredentialId,
            reason: RevocationReason,
        }

        let revoke: RevokeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !Self::check_revoke_auth(view, sender, &revoke.credential_id, gates)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        let record = RevocationRecord {
            credential_id: revoke.credential_id,
            status: RevocationStatus::Revoked,
            reason: revoke.reason,
            reason_details: None,
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: None,
            signature: [0u8; 64],
        };
        Self::v_put_revocation_record(view, &record, gates.revocation_record)?;

        if Self::v_eligibility_exists(view, &revoke.credential_id)? {
            Self::v_update_eligibility_revocation(
                view,
                &revoke.credential_id,
                RevocationStatus::Revoked,
                None,
            )?;
        } else if Self::v_credential_exists(view, &revoke.credential_id)? {
            Self::v_update_credential_revocation(
                view,
                &revoke.credential_id,
                RevocationStatus::Revoked,
                None,
            )?;
        }

        let event = DocClassEvent::CredentialRevoked {
            credential_id: revoke.credential_id,
            issuer: *sender,
            reason: revoke.reason,
            timestamp: block_timestamp,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(revoke.credential_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn suspend_credential(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct SuspendData {
            credential_id: CredentialId,
            reason: RevocationReason,
        }

        let suspend: SuspendData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !Self::check_revoke_auth(view, sender, &suspend.credential_id, gates)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        // At or above the revocation-record activation, revocation is not
        // reversible. `reactivate_credential` already refuses anything that is
        // not `Suspended`; below this gate that is no protection at all,
        // because suspension has no current-status guard of its own, so revoke
        // -> suspend -> reactivate walks a REVOKED credential back to `Active`
        // and the mirrored `revocation_status` on the credential row follows
        // it. `Superseded` is terminal for the same reason: the credential it
        // was superseded by is the live one, and reviving the old one would
        // leave two. `Expired` is left alone -- it is not a status any arm in
        // this file writes. ACTIVATION-AUDIT row OV-23.
        if gates.revocation_record {
            let current = Self::v_get_revocation_status(view, &suspend.credential_id)?;
            if matches!(
                current,
                RevocationStatus::Revoked | RevocationStatus::Superseded
            ) {
                return Ok(DocClassExecutionResult::failure(format!(
                    "Cannot suspend a credential that is {current:?}"
                )));
            }
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        let record = RevocationRecord {
            credential_id: suspend.credential_id,
            status: RevocationStatus::Suspended,
            reason: suspend.reason,
            reason_details: None,
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: None,
            signature: [0u8; 64],
        };
        Self::v_put_revocation_record(view, &record, gates.revocation_record)?;

        if Self::v_eligibility_exists(view, &suspend.credential_id)? {
            Self::v_update_eligibility_revocation(
                view,
                &suspend.credential_id,
                RevocationStatus::Suspended,
                None,
            )?;
        } else if Self::v_credential_exists(view, &suspend.credential_id)? {
            Self::v_update_credential_revocation(
                view,
                &suspend.credential_id,
                RevocationStatus::Suspended,
                None,
            )?;
        }

        let event = DocClassEvent::CredentialSuspended {
            credential_id: suspend.credential_id,
            issuer: *sender,
            reason: suspend.reason,
            timestamp: block_timestamp,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(suspend.credential_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn reactivate_credential(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct ReactivateData {
            credential_id: CredentialId,
        }

        let reactivate: ReactivateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !Self::check_revoke_auth(view, sender, &reactivate.credential_id, gates)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        let status = Self::v_get_revocation_status(view, &reactivate.credential_id)?;
        if status != RevocationStatus::Suspended {
            return Ok(DocClassExecutionResult::failure("Only suspended can be reactivated"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        let record = RevocationRecord {
            credential_id: reactivate.credential_id,
            status: RevocationStatus::Active,
            reason: RevocationReason::Unspecified,
            reason_details: Some("Reactivated".to_string()),
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: None,
            signature: [0u8; 64],
        };
        Self::v_put_revocation_record(view, &record, gates.revocation_record)?;

        if Self::v_eligibility_exists(view, &reactivate.credential_id)? {
            Self::v_update_eligibility_revocation(
                view,
                &reactivate.credential_id,
                RevocationStatus::Active,
                None,
            )?;
        } else if Self::v_credential_exists(view, &reactivate.credential_id)? {
            Self::v_update_credential_revocation(
                view,
                &reactivate.credential_id,
                RevocationStatus::Active,
                None,
            )?;
        }

        let event = DocClassEvent::CredentialReactivated {
            credential_id: reactivate.credential_id,
            issuer: *sender,
            timestamp: block_timestamp,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(reactivate.credential_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn supersede_credential(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct SupersedeData {
            old_credential_id: CredentialId,
            new_credential_id: CredentialId,
        }

        let supersede: SupersedeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !Self::check_revoke_auth(view, sender, &supersede.old_credential_id, gates)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        let record = RevocationRecord {
            credential_id: supersede.old_credential_id,
            status: RevocationStatus::Superseded,
            reason: RevocationReason::Superseded,
            reason_details: None,
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: Some(supersede.new_credential_id),
            signature: [0u8; 64],
        };
        Self::v_put_revocation_record(view, &record, gates.revocation_record)?;

        if Self::v_eligibility_exists(view, &supersede.old_credential_id)? {
            Self::v_update_eligibility_revocation(
                view,
                &supersede.old_credential_id,
                RevocationStatus::Superseded,
                Some(supersede.new_credential_id),
            )?;
        } else if Self::v_credential_exists(view, &supersede.old_credential_id)? {
            Self::v_update_credential_revocation(
                view,
                &supersede.old_credential_id,
                RevocationStatus::Superseded,
                Some(supersede.new_credential_id),
            )?;
        }

        let event = DocClassEvent::CredentialSuperseded {
            old_credential_id: supersede.old_credential_id,
            new_credential_id: supersede.new_credential_id,
            issuer: *sender,
            timestamp: block_timestamp,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(supersede.new_credential_id)))
    }

    /// Who may revoke, suspend, reactivate or supersede a credential.
    ///
    /// Below the revocation-standing gate this reads only the `issuer` field
    /// recorded on the credential row, so a SUSPENDED or REVOKED issuer keeps
    /// control of everything it issued -- while the ISSUE paths consult the
    /// registry through `v_can_issue_subcode`. At the gate the registry is
    /// consulted here too. The status question only, not the subcode or the
    /// jurisdiction: an issuer whose authorization has been narrowed since must
    /// still be able to revoke what it validly issued before, and refusing that
    /// would strand credentials nobody could withdraw.
    /// ACTIVATION-AUDIT row AU-36.
    fn check_revoke_auth(
        view: &ExecutionView<'_, '_>,
        sender: &Address,
        credential_id: &CredentialId,
        gates: DocClassGates,
    ) -> Result<bool> {
        let recorded_issuer = if let Some(a) = Self::v_get_eligibility(view, credential_id)? {
            a.issuer
        } else if let Some(c) = Self::v_get_credential(view, credential_id)? {
            c.issuer
        } else {
            return Ok(false);
        };

        if recorded_issuer != *sender {
            return Ok(false);
        }
        if !gates.revocation_standing {
            return Ok(true);
        }
        Ok(match Self::v_get_docclass_issuer(view, sender)? {
            Some(issuer) => issuer.status.can_issue(),
            None => false,
        })
    }

    // ========================================================================
    // Issuer Registry
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    fn register_issuer(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        let issuer: DocClassIssuer = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if issuer.address != *sender {
            return Ok(DocClassExecutionResult::failure("Address must be sender"));
        }

        if Self::v_issuer_is_registered(view, sender)? {
            return Ok(DocClassExecutionResult::failure("Already registered"));
        }

        if let Some(ref p) = params.docclass {
            // `require_issuer_stake` is declared, defaulted to true, reported by
            // `docclass_getConfig` and -- below the gate -- read by nothing: the
            // minimum is enforced whenever it is non-zero, whatever the flag
            // says. ACTIVATION-AUDIT row AU-37.
            let required = !gates.issuer_stake_requirement || p.require_issuer_stake;
            if required && p.min_issuer_stake > 0 && issuer.stake_amount < p.min_issuer_stake {
                return Ok(DocClassExecutionResult::failure("Insufficient stake"));
            }
        }

        let total = fee.saturating_add(issuer.stake_amount);
        StateManager::v_deduct(view, sender, total)?;
        StateManager::v_credit(view, proposer, fee)?;
        // The stake. Below the activation it is credited to nobody and the
        // supply shrinks by `issuer.stake_amount`; at or above it the stake is
        // held by the keyless escrow address and the supply is conserved.
        // ACTIVATION-AUDIT row OV-26.
        if gates.stake_escrow && issuer.stake_amount > 0 {
            StateManager::v_credit(view, &docclass_stake_escrow_address(), issuer.stake_amount)?;
        }
        StateManager::v_increment_nonce(view, sender)?;

        let subcodes = issuer.authorized_subcodes.clone();
        Self::v_put_docclass_issuer(view, &issuer)?;

        let event = DocClassEvent::IssuerRegistered {
            issuer: issuer.address,
            issuer_type: issuer.issuer_type,
            jurisdictions: issuer.jurisdictions,
            subcodes,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        debug!("Issuer registered: {}", issuer.address);
        Ok(DocClassExecutionResult::success(None))
    }

    #[allow(clippy::too_many_arguments)]
    fn update_issuer(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        let updated: DocClassIssuer = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if updated.address != *sender {
            return Ok(DocClassExecutionResult::failure("Can only update own profile"));
        }

        let recorded = match Self::v_get_docclass_issuer_bounded(view, sender, gates.row_limit())? {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => return Ok(DocClassExecutionResult::failure("Not registered")),
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Issuer record", n)),
        };

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        let mut updated = updated;
        // At or above the escrow activation the recorded stake is what the
        // escrow actually holds, so an update cannot restate it: the row would
        // otherwise claim a stake no balance backs, and `DeactivateIssuer`
        // would refund a number the sender chose. ACTIVATION-AUDIT rows OV-26
        // and AU-34.
        if gates.stake_escrow {
            updated.stake_amount = recorded.stake_amount;
        }
        // At or above the issuer-authority activation the registry is the
        // author of the issuer's authority and the payload is not. Below it the
        // payload struct is written over the row wholesale, so the issuer
        // grants itself any subcode, declares any jurisdiction, and -- the
        // sharpest of the three -- a SUSPENDED issuer restores itself to
        // `Active` with this one transaction. The five fields restored here are
        // exactly the ones `v_can_issue_subcode` and `check_revoke_auth`
        // consult, plus `registered_at`, which is the registry's own record of
        // when it decided. What the sender may still change is what the
        // registry never reads: `name`, `keys`, `metadata`, `updated_at`.
        // ACTIVATION-AUDIT row AU-34.
        if gates.issuer_authority {
            updated.status = recorded.status;
            updated.authorized_subcodes = recorded.authorized_subcodes.clone();
            updated.jurisdictions = recorded.jurisdictions.clone();
            updated.issuer_type = recorded.issuer_type;
            updated.registered_at = recorded.registered_at;
        }

        Self::v_put_docclass_issuer(view, &updated)?;

        let event = DocClassEvent::IssuerUpdated {
            issuer: updated.address,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(None))
    }

    #[allow(clippy::too_many_arguments)]
    fn rotate_issuer_key(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RotateKeyData {
            new_key: IssuerKey,
            old_key_id: String,
        }

        let rotate: RotateKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut issuer = match Self::v_get_docclass_issuer_bounded(view, sender, gates.row_limit())?
        {
            BoundedRow::Row(i) => i,
            BoundedRow::Missing => return Ok(DocClassExecutionResult::failure("Not registered")),
            BoundedRow::TooLarge(n) => return Ok(Self::row_too_large("Issuer record", n)),
        };

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        for key in &mut issuer.keys {
            if key.key_id == rotate.old_key_id {
                key.active = false;
                key.is_primary = false;
            }
        }

        if rotate.new_key.is_primary {
            for key in &mut issuer.keys {
                key.is_primary = false;
            }
        }

        let new_key_id = rotate.new_key.key_id.clone();
        issuer.keys.push(rotate.new_key);
        Self::v_put_docclass_issuer(view, &issuer)?;

        let event = DocClassEvent::IssuerKeyRotated {
            issuer: *sender,
            old_key_id: rotate.old_key_id,
            new_key_id,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(None))
    }

    #[allow(clippy::too_many_arguments)]
    fn deactivate_issuer(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &[u8],
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        gates: DocClassGates,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct DeactivateIssuerData {
            issuer_address: Address,
        }

        let deactivate: DeactivateIssuerData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let is_admin = Self::is_docclass_admin(params, sender);
        let is_self = deactivate.issuer_address == *sender;

        if !is_admin && !is_self {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        if !Self::v_issuer_is_registered(view, &deactivate.issuer_address)? {
            return Ok(DocClassExecutionResult::failure("Not registered"));
        }

        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        // Return the escrowed stake to the issuer whose registration posted it,
        // and zero the recorded amount so a second deactivation cannot claim it
        // twice. Below the activation there is nothing to return, because
        // registration credited the stake to nobody. ACTIVATION-AUDIT row
        // OV-26.
        if gates.stake_escrow {
            if let BoundedRow::Row(mut issuer) = Self::v_get_docclass_issuer_bounded(
                view,
                &deactivate.issuer_address,
                gates.row_limit(),
            )? {
                if issuer.stake_amount > 0 {
                    let refund = issuer.stake_amount;
                    StateManager::v_deduct(view, &docclass_stake_escrow_address(), refund)?;
                    StateManager::v_credit(view, &deactivate.issuer_address, refund)?;
                    issuer.stake_amount = 0;
                    Self::v_put_docclass_issuer(view, &issuer)?;
                }
            }
        }

        Self::v_update_docclass_issuer_status(
            view,
            &deactivate.issuer_address,
            DocClassIssuerStatus::Suspended,
            block_timestamp,
        )?;

        let event = DocClassEvent::IssuerStatusChanged {
            issuer: deactivate.issuer_address,
            new_status: DocClassIssuerStatus::Suspended,
        };
        Self::v_put_docclass_event(view, block_height, tx_index, 0, &event)?;

        warn!("Issuer deactivated: {}", deactivate.issuer_address);
        Ok(DocClassExecutionResult::success(None))
    }

    fn is_docclass_admin(params: &ChainParams, sender: &Address) -> bool {
        if let Some(ref p) = params.docclass {
            if let Some(ref admin_str) = p.admin {
                if let Ok(admin) = Address::from_base58(admin_str)
                    .or_else(|_| Address::from_hex(admin_str)) {
                    return &admin == sender;
                }
            }
        }
        false
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sumchain_primitives::{DocClassIssuerType, EligibilityType, Hash, KeyPurpose, KeyType};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        (db, dir)
    }

    fn test_params() -> ChainParams {
        let mut params = ChainParams::default();
        // Set min_issuer_stake to 0 for testing
        if let Some(ref mut docclass) = params.docclass {
            docclass.min_issuer_stake = 0;
        }
        params
    }

    fn sample_issuer_key() -> IssuerKey {
        IssuerKey {
            key_id: "key1".to_string(),
            public_key: [1u8; 32],
            key_type: KeyType::Ed25519,
            added_at: 1000,
            expires_at: 0,
            active: true,
            is_primary: true,
        }
    }

    fn sample_identity_key() -> IdentityKey {
        IdentityKey {
            key_id: "auth1".to_string(),
            key_type: KeyType::Ed25519,
            public_key: [2u8; 32],
            purposes: vec![KeyPurpose::Authentication],
            added_at: 1000,
            expires_at: 0,
            active: true,
        }
    }

    fn make_tx_data<T: serde::Serialize>(operation: DocClassOperation, subcode: DocSubcode, op_data: &T) -> DocClassTxData {
        DocClassTxData {
            operation,
            subcode,
            data: bincode::serialize(op_data).unwrap(),
            recipient: Address::ZERO,
        }
    }

    #[test]
    fn test_docclass_executor_creation() {
        let (db, _dir) = setup();
        // The executor is a unit struct: there is nothing to construct it
        // from, and in particular no `Arc<Database>` for an operation to read
        // committed state through.
        let _executor = DocClassExecutor;
        let _ = db;
    }

    #[test]
    fn test_register_issuer() {
        let (db, _dir) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = test_params();

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the issuer account
        StateManager::v_credit(view, &issuer_addr, 1_000_000_000_000).unwrap();

        // Create full DocClassIssuer for registration
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Test University".to_string(),
            issuer_type: DocClassIssuerType::Educational,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::Diploma, DocSubcode::EnrollmentVerification],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };

        let tx_data = make_tx_data(
            DocClassOperation::RegisterIssuer,
            DocSubcode::IdentityRoot,
            &issuer,
        );

        let result = DocClassExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success, "Register issuer failed: {:?}", result.error);

        // Verify the issuer is registered IN THE CANDIDATE. Nothing was
        // published, so a committed reader here would see an empty family.
        let retrieved = DocClassExecutor::v_get_docclass_issuer(view, &issuer_addr)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.name, "Test University");
        assert!(DocClassExecutor::v_can_issue_subcode(
            view,
            &issuer_addr,
            DocSubcode::Diploma,
            "US"
        )
        .unwrap());
    }

    #[test]
    fn test_create_identity_root() {
        let (db, _dir) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = test_params();

        let controller = Address::new([2u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the controller account
        StateManager::v_credit(view, &controller, 1_000_000_000_000).unwrap();

        let subject_commitment = [42u8; 32];
        let identity_id = [100u8; 32];

        // Create full IdentityRoot
        let identity = IdentityRoot {
            identity_id,
            subject_commitment,
            controller,
            additional_controllers: vec![],
            keys: vec![sample_identity_key()],
            services: vec![],
            created_at: 1000000,
            updated_at: 1000000,
            status: IdentityStatus::Active,
            schema_hash: [0u8; 32],
        };

        let tx_data = make_tx_data(
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &identity,
        );

        let result = DocClassExecutor::execute(
            view,
            &params,
            &controller,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success);

        // Verify the identity was created in the candidate.
        let retrieved = DocClassExecutor::v_get_identity_root(view, &identity_id)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.controller, controller);
        assert_eq!(retrieved.subject_commitment, subject_commitment);
        assert_eq!(retrieved.keys.len(), 1);
    }

    #[test]
    fn test_issue_eligibility() {
        let (db, _dir) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = test_params();

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the issuer account
        StateManager::v_credit(view, &issuer_addr, 1_000_000_000_000).unwrap();

        // First register the issuer
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Government Agency".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };

        let tx_data = make_tx_data(
            DocClassOperation::RegisterIssuer,
            DocSubcode::IdentityRoot,
            &issuer,
        );

        let result = DocClassExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        ).unwrap();
        assert!(result.success);

        // Now issue an eligibility attestation
        let credential_id = [200u8; 32];
        let subject_commitment = [42u8; 32];

        let eligibility = EligibilityAttestation {
            credential_id,
            subject_address: Address::ZERO,
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment,
            issuer: issuer_addr,
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000000,
            valid_from: 1000000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            encryption_meta: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };

        let tx_data = make_tx_data(
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &eligibility,
        );

        let result = DocClassExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            101,
            1000001,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success);

        // Verify the credential was issued in the candidate.
        let retrieved = DocClassExecutor::v_get_eligibility(view, &credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.subject_commitment, subject_commitment);
        assert_eq!(retrieved.revocation_status, RevocationStatus::Active);
    }

    #[test]
    fn test_revoke_credential() {
        let (db, _dir) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = test_params();

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the issuer account
        StateManager::v_credit(view, &issuer_addr, 1_000_000_000_000).unwrap();

        // Register issuer
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Government Agency".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };
        let tx_data = make_tx_data(
            DocClassOperation::RegisterIssuer,
            DocSubcode::IdentityRoot,
            &issuer,
        );
        DocClassExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        // Issue credential
        let credential_id = [200u8; 32];
        let eligibility = EligibilityAttestation {
            credential_id,
            subject_address: Address::ZERO,
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment: [42u8; 32],
            issuer: issuer_addr,
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000000,
            valid_from: 1000000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            encryption_meta: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };
        let tx_data = make_tx_data(
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &eligibility,
        );
        DocClassExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            101,
            1000001,
            0,
            Hash::default(),
        )
        .unwrap();

        // Now revoke the credential using inline struct matching the executor
        #[derive(serde::Serialize)]
        struct RevokeData {
            credential_id: CredentialId,
            reason: RevocationReason,
        }

        let revoke = RevokeData {
            credential_id,
            reason: RevocationReason::KeyCompromise,
        };

        let tx_data = make_tx_data(DocClassOperation::RevokeCredential, DocSubcode::IdentityRoot, &revoke);

        let result = DocClassExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            102,
            1000002,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success);

        // Verify the credential is revoked in the candidate.
        let status = DocClassExecutor::v_get_revocation_status(view, &credential_id).unwrap();
        assert_eq!(status, RevocationStatus::Revoked);
    }

    #[test]
    fn test_unauthorized_issuer_fails() {
        let (db, _dir) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = test_params();

        let issuer_addr = Address::new([1u8; 20]);
        let unauthorized_addr = Address::new([5u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund accounts
        StateManager::v_credit(view, &issuer_addr, 1_000_000_000_000).unwrap();
        StateManager::v_credit(view, &unauthorized_addr, 1_000_000_000_000).unwrap();

        // Register issuer for eligibility only
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Government Agency".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };
        let tx_data = make_tx_data(
            DocClassOperation::RegisterIssuer,
            DocSubcode::IdentityRoot,
            &issuer,
        );
        DocClassExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        // Try to issue with unregistered address (should fail)
        let eligibility = EligibilityAttestation {
            credential_id: [200u8; 32],
            subject_address: Address::ZERO,
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment: [42u8; 32],
            issuer: unauthorized_addr, // Wrong issuer
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000000,
            valid_from: 1000000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            encryption_meta: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };

        let tx_data = make_tx_data(DocClassOperation::IssueCredential, DocSubcode::EligibilityAttestation, &eligibility);

        let result = DocClassExecutor::execute(
            view,
            &params,
            &unauthorized_addr,
            &tx_data,
            &proposer,
            1000,
            101,
            1000001,
            0,
            Hash::default(),
        ).unwrap();

        // Should fail because unauthorized_addr is not a registered issuer
        assert!(!result.success);
    }
}
