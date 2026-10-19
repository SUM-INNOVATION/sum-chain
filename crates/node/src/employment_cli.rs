//! `sumchain employment`: Employment (SRC-88X) issuer and credential
//! transactions, built and signed on this machine.
//!
//! The private key never leaves the process. Each command:
//! 1. reads the chain id and the sender's nonce from the node, and, when the
//!    command omits them, the latest block height (registration), the sender's
//!    issuer name and class (create) or the credential's employee (revoke);
//! 2. builds the transaction locally with
//!    `sumchain_primitives::employment_build`, every field explicit;
//! 3. unless `--no-builder-check`, asks the node's no-key
//!    `employment_buildTransaction` builder for the same transaction and
//!    refuses to sign if the node's bytes or signing hash differ;
//! 4. with `--dry-run`, prints the summary and the signing hash and stops:
//!    nothing is signed or sent;
//! 5. otherwise signs the LOCAL transaction and submits it through
//!    `send_raw_transaction`.
//!
//! The command signs only bytes it built itself; the builder's reply is used to
//! detect disagreement, never as the thing signed. A revocation's `--reason` is
//! hashed into the revocation reference here and is never sent to the node.
//!
//! Key handling is `sumchain docclass`'s: the same key file format, held in
//! zeroizing memory, with fixed error messages that repeat nothing of the file.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use sumchain_primitives::employment::EmploymentIssuerClass;
use sumchain_primitives::employment_build::{build_employment_tx, EmploymentTxContext};
use sumchain_primitives::{Address, Hash};
use sumchain_rpc::docclass_build::{parse_address, parse_hex32};
use sumchain_rpc::employment_build::{
    make_explicit, needs_credential, needs_issuer_record, op_from_request, parse_issuer_class,
    EmploymentRequestDefaults,
};
use sumchain_rpc::types::{
    EmploymentBuildOpRequest, EmploymentBuildRequest, EmploymentBuildResponse,
};

use crate::docclass_cli::{HttpRpc, KeyFileSigner, SecretSeed, TxSigner};

// ── Command line ────────────────────────────────────────────────────────────

/// Options every `sumchain employment` command takes.
#[derive(Args, Debug, Clone)]
pub struct EmploymentArgs {
    /// Sender's key file (JSON array of 32 bytes). Required unless --dry-run
    /// with --from.
    #[arg(long, global = true)]
    pub key: Option<PathBuf>,

    /// Sender address (base58), for --dry-run without a key file.
    #[arg(long, global = true)]
    pub from: Option<String>,

    /// RPC endpoint URL.
    #[arg(long, global = true, default_value = "http://localhost:8545")]
    pub rpc: String,

    /// Transaction fee in base units.
    #[arg(long, global = true, default_value = "1000000")]
    pub fee: u128,

    /// Build and print the transaction and its signing hash; sign and send
    /// nothing.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Skip comparing the local transaction with the node's
    /// employment_buildTransaction output (for nodes without that builder).
    #[arg(long, global = true)]
    pub no_builder_check: bool,

    #[command(subcommand)]
    pub command: EmploymentCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum EmploymentCommand {
    /// Register the sender as an employment issuer.
    RegisterIssuer {
        /// GovernmentLabor, PayrollProcessor, RegulatedHrPlatform, Peo,
        /// Employer, HrPlatform, StaffingAgency or GigPlatform.
        #[arg(long)]
        class: String,
        /// Institutional name (not a person's name).
        #[arg(long)]
        display_name: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        issuer_commitment: String,
        /// ISO 3166-1 alpha-2, optionally with a subdivision.
        #[arg(long)]
        jurisdiction: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        policy_id: String,
        /// Defaults to the chain's latest block height.
        #[arg(long)]
        registered_at_height: Option<u64>,
        /// Milliseconds; defaults to now.
        #[arg(long)]
        registered_at: Option<u64>,
    },
    /// Create an employment credential.
    Create {
        /// Employee address (base58).
        #[arg(long)]
        employee: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        employee_ref: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        employer_ref: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        tenure_commitment: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        role_commitment: Option<String>,
        /// FullTime, PartTime, Contract, Temporary, Internship, Freelance or
        /// Gig.
        #[arg(long)]
        employment_type: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        policy_id: String,
        /// Milliseconds; defaults to the creation time.
        #[arg(long)]
        valid_from: Option<u64>,
        /// Milliseconds; 0 = no expiry.
        #[arg(long, default_value = "0")]
        expiry: u64,
        /// Defaults to the sender's registered display name.
        #[arg(long)]
        issuer_name: Option<String>,
        /// Defaults to the sender's registered issuer class.
        #[arg(long)]
        issuer_class: Option<String>,
        /// Milliseconds; defaults to now.
        #[arg(long)]
        created_at: Option<u64>,
    },
    /// Revoke a credential the sender issued.
    Revoke {
        /// Hex, 32 bytes.
        #[arg(long)]
        employment_id: String,
        /// Employee address (base58); defaults to the stored credential's.
        #[arg(long)]
        employee: Option<String>,
        /// Hex, 32 bytes. Derived from the id, time and reason when omitted.
        #[arg(long, conflicts_with = "reason")]
        revocation_ref: Option<String>,
        /// Hashed into the derived revocation reference; never sent.
        #[arg(long)]
        reason: Option<String>,
        /// Milliseconds, for the derived reference; defaults to now.
        #[arg(long)]
        revoked_at: Option<u64>,
    },
}

// ── Seams for tests ─────────────────────────────────────────────────────────

/// What the command needs from a node.
pub trait EmploymentRpc {
    fn chain_id(&self) -> Result<u64>;
    fn nonce(&self, address: &Address) -> Result<u64>;
    fn latest_height(&self) -> Result<u64>;
    /// The sender's registered display name and issuer class, if registered.
    fn issuer_defaults(&self, address: &Address)
        -> Result<Option<(String, EmploymentIssuerClass)>>;
    /// The stored credential's employee, if the credential exists.
    fn credential_employee(&self, employment_id: &[u8; 32]) -> Result<Option<Address>>;
    fn build(&self, request: &EmploymentBuildRequest) -> Result<EmploymentBuildResponse>;
    /// Submit a signed transaction (hex); returns the node's transaction hash.
    fn submit(&self, signed_hex: &str) -> Result<String>;
}

// ── The command ─────────────────────────────────────────────────────────────

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    DryRun {
        summary: String,
        signing_hash: Hash,
        employment_id: Option<[u8; 32]>,
    },
    Submitted {
        summary: String,
        tx_hash: String,
        employment_id: Option<[u8; 32]>,
    },
}

/// Settings for one run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub fee: u128,
    pub dry_run: bool,
    pub builder_check: bool,
    pub now_ms: u64,
}

fn op_name(op: &EmploymentBuildOpRequest) -> &'static str {
    match op {
        EmploymentBuildOpRequest::RegisterIssuer { .. } => "register issuer",
        EmploymentBuildOpRequest::CreateEmployment { .. } => "create employment credential",
        EmploymentBuildOpRequest::RevokeEmployment { .. } => "revoke employment credential",
    }
}

/// Build, check, and (unless a dry run) sign and submit one operation.
///
/// `signer` may be `None` only for a dry run. When present, its address must be
/// `from`.
pub fn run(
    op: EmploymentBuildOpRequest,
    from: Address,
    signer: Option<&dyn TxSigner>,
    rpc: &dyn EmploymentRpc,
    opts: &RunOptions,
) -> Result<Outcome> {
    if let Some(s) = signer {
        if s.address() != from {
            bail!("the key file's address is not the sender address given");
        }
    } else if !opts.dry_run {
        bail!("a key file is required unless --dry-run is given");
    }

    let chain_id = rpc.chain_id().context("reading the chain id")?;
    let nonce = rpc.nonce(&from).context("reading the sender's nonce")?;
    let mut defaults = EmploymentRequestDefaults {
        now_ms: opts.now_ms,
        ..Default::default()
    };
    if matches!(
        op,
        EmploymentBuildOpRequest::RegisterIssuer {
            registered_at_height: None,
            ..
        }
    ) {
        defaults.latest_height = rpc
            .latest_height()
            .context("reading the latest block height")?;
    }
    if needs_issuer_record(&op) {
        defaults.issuer = rpc
            .issuer_defaults(&from)
            .context("reading the sender's issuer record")?;
    }
    if let Some(id) = needs_credential(&op) {
        let id = parse_hex32("employment_id", id).map_err(|e| anyhow!(e))?;
        defaults.employee_address = rpc
            .credential_employee(&id)
            .context("reading the credential")?;
    }
    let op = make_explicit(&op, &defaults).map_err(|e| anyhow!(e))?;
    let built_op = op_from_request(&op, &defaults).map_err(|e| anyhow!(e))?;
    let ctx = EmploymentTxContext {
        chain_id,
        from,
        nonce,
        fee: opts.fee,
    };
    let built = build_employment_tx(&ctx, &built_op).map_err(|e| anyhow!(e))?;
    let local_bytes = format!("0x{}", hex::encode(built.tx.to_bytes()));
    let local_hash = built.tx.signing_hash();
    let local_hash_hex = format!("0x{}", hex::encode(local_hash.as_bytes()));

    if opts.builder_check {
        let request = EmploymentBuildRequest {
            from: from.to_base58(),
            fee: Some(opts.fee),
            nonce: Some(nonce),
            chain_id: Some(chain_id),
            op: op.clone(),
        };
        let reply = rpc.build(&request).context("asking the node's builder")?;
        if reply.tx.signing_hash != local_hash_hex || reply.tx.unsigned_tx != local_bytes {
            bail!(
                "the node's employment_buildTransaction produced a different transaction \
                 than this client built; nothing was signed"
            );
        }
    }

    let mut summary = format!(
        "Employment {}\n  From:         {}\n  Chain ID:     {}\n  Nonce:        {}\n  Fee:          {} base units\n  Signing hash: {}",
        op_name(&op),
        from.to_base58(),
        chain_id,
        nonce,
        opts.fee,
        local_hash_hex,
    );
    if let Some(id) = built.employment_id {
        summary.push_str(&format!("\n  Employment:   0x{}", hex::encode(id)));
    }
    if opts.builder_check {
        summary.push_str("\n  Builder:      agrees");
    }

    if opts.dry_run {
        return Ok(Outcome::DryRun {
            summary,
            signing_hash: local_hash,
            employment_id: built.employment_id,
        });
    }
    let signer = signer.expect("checked above");
    let signed = signer.sign(built.tx);
    let tx_hash = rpc
        .submit(&signed.to_hex())
        .context("submitting the transaction")?;
    Ok(Outcome::Submitted {
        summary,
        tx_hash,
        employment_id: built.employment_id,
    })
}

/// Turn the parsed command into the request operation.
pub fn request_op(command: &EmploymentCommand, now_ms: u64) -> EmploymentBuildOpRequest {
    match command.clone() {
        EmploymentCommand::RegisterIssuer {
            class,
            display_name,
            issuer_commitment,
            jurisdiction,
            policy_id,
            registered_at_height,
            registered_at,
        } => EmploymentBuildOpRequest::RegisterIssuer {
            issuer_class: class,
            display_name,
            issuer_commitment,
            jurisdiction_code: jurisdiction,
            policy_id,
            registered_at_height,
            registered_at,
        },
        EmploymentCommand::Create {
            employee,
            employee_ref,
            employer_ref,
            tenure_commitment,
            role_commitment,
            employment_type,
            policy_id,
            valid_from,
            expiry,
            issuer_name,
            issuer_class,
            created_at,
        } => {
            let created_at = created_at.unwrap_or(now_ms);
            EmploymentBuildOpRequest::CreateEmployment {
                employee_address: employee,
                employee_ref,
                employer_ref,
                tenure_commitment,
                role_commitment,
                employment_type,
                valid_from: valid_from.unwrap_or(created_at),
                expiry,
                policy_id,
                issuer_name,
                issuer_class,
                created_at: Some(created_at),
            }
        }
        EmploymentCommand::Revoke {
            employment_id,
            employee,
            revocation_ref,
            reason,
            revoked_at,
        } => EmploymentBuildOpRequest::RevokeEmployment {
            employment_id,
            employee_address: employee,
            revocation_ref,
            revoked_at,
            reason,
        },
    }
}

// ── JSON-RPC over HTTP ──────────────────────────────────────────────────────

impl EmploymentRpc for HttpRpc {
    fn chain_id(&self) -> Result<u64> {
        self.call("chain_id", serde_json::json!([]))?
            .as_u64()
            .ok_or_else(|| anyhow!("chain_id: unexpected response"))
    }
    fn nonce(&self, address: &Address) -> Result<u64> {
        self.call("get_nonce", serde_json::json!([address.to_base58()]))?
            .as_u64()
            .ok_or_else(|| anyhow!("get_nonce: unexpected response"))
    }
    fn latest_height(&self) -> Result<u64> {
        self.call("get_latest_block", serde_json::json!([]))?["height"]
            .as_u64()
            .ok_or_else(|| anyhow!("get_latest_block: unexpected response"))
    }
    fn issuer_defaults(
        &self,
        address: &Address,
    ) -> Result<Option<(String, EmploymentIssuerClass)>> {
        let v = self.call(
            "employment_getIssuer",
            serde_json::json!([address.to_base58()]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let name = v["display_name"]
            .as_str()
            .ok_or_else(|| anyhow!("employment_getIssuer: no display_name"))?;
        let class = v["issuer_class"]
            .as_str()
            .ok_or_else(|| anyhow!("employment_getIssuer: no issuer_class"))?;
        let class = parse_issuer_class("employment_getIssuer issuer_class", class)
            .map_err(|e| anyhow!(e))?;
        Ok(Some((name.to_string(), class)))
    }
    fn credential_employee(&self, employment_id: &[u8; 32]) -> Result<Option<Address>> {
        let v = self.call(
            "employment_getCredential",
            serde_json::json!([format!("0x{}", hex::encode(employment_id))]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let a = v["employee_address"]
            .as_str()
            .ok_or_else(|| anyhow!("employment_getCredential: no employee_address"))?;
        Ok(Some(
            parse_address("employment_getCredential employee_address", a)
                .map_err(|e| anyhow!(e))?,
        ))
    }
    fn build(&self, request: &EmploymentBuildRequest) -> Result<EmploymentBuildResponse> {
        let v = self.call("employment_buildTransaction", serde_json::json!([request]))?;
        serde_json::from_value(v)
            .map_err(|_| anyhow!("employment_buildTransaction: unexpected response"))
    }
    fn submit(&self, signed_hex: &str) -> Result<String> {
        let v = self.call("send_raw_transaction", serde_json::json!([signed_hex]))?;
        v["tx_hash"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("send_raw_transaction: no tx_hash in response"))
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Entry point for `sumchain employment ...`.
pub fn execute(args: EmploymentArgs) -> Result<()> {
    let signer = match &args.key {
        Some(path) => {
            let seed = SecretSeed::read(path).map_err(|e| anyhow!(e))?;
            Some(KeyFileSigner::new(&seed))
        }
        None => None,
    };
    let from = match (&signer, &args.from) {
        (Some(s), Some(given)) => {
            let given = parse_address("--from", given).map_err(|e| anyhow!(e))?;
            if given != s.address() {
                bail!("the key file's address is not the --from address");
            }
            given
        }
        (Some(s), None) => s.address(),
        (None, Some(given)) => parse_address("--from", given).map_err(|e| anyhow!(e))?,
        (None, None) => bail!("give --key, or --from with --dry-run"),
    };
    let now = now_ms();
    let op = request_op(&args.command, now);
    let rpc = HttpRpc::new(&args.rpc);
    let opts = RunOptions {
        fee: args.fee,
        dry_run: args.dry_run,
        builder_check: !args.no_builder_check,
        now_ms: now,
    };
    match run(
        op,
        from,
        signer.as_ref().map(|s| s as &dyn TxSigner),
        &rpc,
        &opts,
    )? {
        Outcome::DryRun { summary, .. } => {
            println!("{summary}");
            println!("\nDry run: nothing was signed or sent.");
        }
        Outcome::Submitted {
            summary, tx_hash, ..
        } => {
            println!("{summary}");
            println!("\nTransaction sent.\n  TX Hash: {tx_hash}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use sumchain_crypto::KeyPair;
    use sumchain_primitives::employment::{EmploymentCredential, EmploymentOperation};
    use sumchain_primitives::employment_build::{derive_revocation_ref, RevokeEmploymentPayload};
    use sumchain_primitives::{SignedTransaction, TransactionV2, TxPayload};

    // Synthetic keys from fixed test seeds only.
    fn test_signer() -> KeyFileSigner {
        KeyFileSigner::new(&SecretSeed::parse(&format!("[{}]", ["17"; 32].join(","))).unwrap())
    }

    struct MockRpc {
        tamper: bool,
        builds: RefCell<Vec<EmploymentBuildRequest>>,
        submits: RefCell<Vec<String>>,
        issuer: Option<(String, EmploymentIssuerClass)>,
        employee: Option<Address>,
        height_reads: Cell<usize>,
    }

    impl MockRpc {
        fn new() -> Self {
            Self {
                tamper: false,
                builds: RefCell::new(vec![]),
                submits: RefCell::new(vec![]),
                issuer: Some((
                    "Example Employer Inc".into(),
                    EmploymentIssuerClass::Employer,
                )),
                employee: Some(employee()),
                height_reads: Cell::new(0),
            }
        }
    }

    impl EmploymentRpc for MockRpc {
        fn chain_id(&self) -> Result<u64> {
            Ok(1337)
        }
        fn nonce(&self, _: &Address) -> Result<u64> {
            Ok(7)
        }
        fn latest_height(&self) -> Result<u64> {
            self.height_reads.set(self.height_reads.get() + 1);
            Ok(4_242)
        }
        fn issuer_defaults(&self, _: &Address) -> Result<Option<(String, EmploymentIssuerClass)>> {
            Ok(self.issuer.clone())
        }
        fn credential_employee(&self, _: &[u8; 32]) -> Result<Option<Address>> {
            Ok(self.employee)
        }
        /// What a node's builder does with an explicit request, optionally with
        /// one byte changed.
        fn build(&self, request: &EmploymentBuildRequest) -> Result<EmploymentBuildResponse> {
            self.builds.borrow_mut().push(request.clone());
            let from = parse_address("from", &request.from).unwrap();
            let op = op_from_request(&request.op, &EmploymentRequestDefaults::default()).unwrap();
            let mut ctx = EmploymentTxContext {
                chain_id: request.chain_id.unwrap(),
                from,
                nonce: request.nonce.unwrap(),
                fee: request.fee.unwrap(),
            };
            if self.tamper {
                ctx.fee += 1;
            }
            let built = build_employment_tx(&ctx, &op).unwrap();
            Ok(EmploymentBuildResponse {
                tx: sumchain_rpc::types::TxBuildResponse {
                    unsigned_tx: format!("0x{}", hex::encode(built.tx.to_bytes())),
                    signing_hash: format!("0x{}", hex::encode(built.tx.signing_hash().as_bytes())),
                    from: from.to_base58(),
                    nonce: ctx.nonce,
                    fee: ctx.fee,
                    chain_id: ctx.chain_id,
                },
                employment_id: built.employment_id.map(hex::encode),
            })
        }
        fn submit(&self, signed_hex: &str) -> Result<String> {
            self.submits.borrow_mut().push(signed_hex.to_string());
            Ok("0xsubmitted".into())
        }
    }

    struct CountingSigner {
        inner: KeyFileSigner,
        signs: Cell<usize>,
    }

    impl TxSigner for CountingSigner {
        fn address(&self) -> Address {
            self.inner.address()
        }
        fn public_key(&self) -> [u8; 32] {
            self.inner.public_key()
        }
        fn sign(&self, tx: TransactionV2) -> SignedTransaction {
            self.signs.set(self.signs.get() + 1);
            self.inner.sign(tx)
        }
    }

    fn signer() -> CountingSigner {
        CountingSigner {
            inner: test_signer(),
            signs: Cell::new(0),
        }
    }

    fn employee() -> Address {
        KeyPair::from_bytes([0x13; 32]).address()
    }

    fn opts(dry_run: bool, builder_check: bool) -> RunOptions {
        RunOptions {
            fee: 1_000_000,
            dry_run,
            builder_check,
            now_ms: 1_750_000_000_000,
        }
    }

    fn register() -> EmploymentBuildOpRequest {
        EmploymentBuildOpRequest::RegisterIssuer {
            issuer_class: "Employer".into(),
            display_name: "Example Employer Inc".into(),
            issuer_commitment: "41".repeat(32),
            jurisdiction_code: "US-CA".into(),
            policy_id: "42".repeat(32),
            registered_at_height: None,
            registered_at: None,
        }
    }

    fn create() -> EmploymentBuildOpRequest {
        EmploymentBuildOpRequest::CreateEmployment {
            employee_address: employee().to_base58(),
            employee_ref: "31".repeat(32),
            employer_ref: "32".repeat(32),
            tenure_commitment: "33".repeat(32),
            role_commitment: None,
            employment_type: "FullTime".into(),
            valid_from: 1_750_000_000_000,
            expiry: 0,
            policy_id: "35".repeat(32),
            issuer_name: None,
            issuer_class: None,
            created_at: Some(1_750_000_000_000),
        }
    }

    fn revoke(reason: Option<&str>) -> EmploymentBuildOpRequest {
        EmploymentBuildOpRequest::RevokeEmployment {
            employment_id: "ab".repeat(32),
            employee_address: None,
            revocation_ref: None,
            revoked_at: Some(1_750_000_000_000),
            reason: reason.map(str::to_string),
        }
    }

    fn employment_tx(signed_hex: &str) -> (SignedTransaction, TransactionV2) {
        let signed = SignedTransaction::from_hex(signed_hex).unwrap();
        let sumchain_primitives::TxInner::V2(tx) = &signed.inner else {
            panic!("not V2")
        };
        let tx = tx.clone();
        (signed, tx)
    }

    #[test]
    fn a_dry_run_never_signs_or_submits() {
        let rpc = MockRpc::new();
        let s = signer();
        let out = run(create(), s.address(), Some(&s), &rpc, &opts(true, true)).unwrap();
        assert!(matches!(out, Outcome::DryRun { .. }));
        assert_eq!(s.signs.get(), 0);
        assert!(rpc.submits.borrow().is_empty());
        assert_eq!(
            rpc.builds.borrow().len(),
            1,
            "the dry run still checks the builder"
        );
    }

    #[test]
    fn a_dry_run_needs_no_key() {
        let rpc = MockRpc::new();
        let from = test_signer().address();
        let out = run(revoke(None), from, None, &rpc, &opts(true, true)).unwrap();
        assert!(matches!(out, Outcome::DryRun { .. }));
        assert!(
            run(revoke(None), from, None, &rpc, &opts(false, true)).is_err(),
            "a real run does"
        );
    }

    #[test]
    fn a_builder_that_disagrees_is_refused_before_signing() {
        let mut rpc = MockRpc::new();
        rpc.tamper = true;
        let s = signer();
        let err = run(create(), s.address(), Some(&s), &rpc, &opts(false, true)).unwrap_err();
        assert!(err.to_string().contains("nothing was signed"), "{err}");
        assert_eq!(s.signs.get(), 0);
        assert!(rpc.submits.borrow().is_empty());
    }

    #[test]
    fn without_the_check_the_builder_is_not_asked() {
        let mut rpc = MockRpc::new();
        rpc.tamper = true;
        let s = signer();
        run(create(), s.address(), Some(&s), &rpc, &opts(false, false)).unwrap();
        assert!(rpc.builds.borrow().is_empty());
        assert_eq!(s.signs.get(), 1);
    }

    #[test]
    fn a_real_run_signs_the_local_transaction_once_and_submits_it() {
        let rpc = MockRpc::new();
        let s = signer();
        let out = run(create(), s.address(), Some(&s), &rpc, &opts(false, true)).unwrap();
        let Outcome::Submitted { employment_id, .. } = out else {
            panic!("not submitted")
        };
        assert_eq!(s.signs.get(), 1);
        let submits = rpc.submits.borrow();
        assert_eq!(submits.len(), 1);
        let (signed, tx) = employment_tx(&submits[0]);
        assert!(
            signed.verify_signer(),
            "the signature verifies under the signer's key"
        );
        assert_eq!(tx.from, s.address());
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.chain_id, 1337);
        let TxPayload::Employment(d) = &tx.payload else {
            panic!("not an Employment payload")
        };
        assert_eq!(d.operation, EmploymentOperation::CreateEmployment);
        let cred: EmploymentCredential = bincode::deserialize(&d.data).unwrap();
        assert_eq!(Some(cred.employment_id), employment_id);
        assert_eq!(cred.issuer_name, "Example Employer Inc");
        assert_eq!(cred.issuer_class, EmploymentIssuerClass::Employer);
    }

    #[test]
    fn a_create_needs_the_issuer_record_or_explicit_name_and_class() {
        let mut unregistered = MockRpc::new();
        unregistered.issuer = None;
        let s = signer();
        let err = run(
            create(),
            s.address(),
            Some(&s),
            &unregistered,
            &opts(false, true),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("issuer_name"), "{err}");
        assert!(unregistered.submits.borrow().is_empty());
        assert_eq!(s.signs.get(), 0);
    }

    #[test]
    fn a_registration_reads_the_height_only_when_omitted() {
        let rpc = MockRpc::new();
        let s = signer();
        run(register(), s.address(), Some(&s), &rpc, &opts(true, true)).unwrap();
        assert_eq!(rpc.height_reads.get(), 1);
        let sent = rpc.builds.borrow()[0].clone();
        let EmploymentBuildOpRequest::RegisterIssuer {
            registered_at_height,
            registered_at,
            ..
        } = sent.op
        else {
            panic!("not a registration")
        };
        assert_eq!(registered_at_height, Some(4_242));
        assert_eq!(registered_at, Some(1_750_000_000_000));

        let rpc = MockRpc::new();
        let mut explicit = register();
        if let EmploymentBuildOpRequest::RegisterIssuer {
            registered_at_height,
            ..
        } = &mut explicit
        {
            *registered_at_height = Some(9);
        }
        run(explicit, s.address(), Some(&s), &rpc, &opts(true, true)).unwrap();
        assert_eq!(rpc.height_reads.get(), 0);
    }

    #[test]
    fn a_revocation_reason_is_hashed_locally_and_never_sent() {
        let rpc = MockRpc::new();
        let s = signer();
        run(
            revoke(Some("contract ended")),
            s.address(),
            Some(&s),
            &rpc,
            &opts(false, true),
        )
        .unwrap();
        let sent = rpc.builds.borrow()[0].clone();
        let EmploymentBuildOpRequest::RevokeEmployment {
            employee_address,
            revocation_ref,
            revoked_at,
            reason,
            ..
        } = &sent.op
        else {
            panic!("not a revocation")
        };
        assert_eq!(reason, &None, "the reason text never reaches the node");
        assert_eq!(revoked_at, &None);
        assert_eq!(
            employee_address.as_deref(),
            Some(employee().to_base58().as_str())
        );
        let expected =
            derive_revocation_ref(&[0xab; 32], 1_750_000_000_000, Some("contract ended"));
        assert_eq!(
            revocation_ref.as_deref(),
            Some(hex::encode(expected).as_str())
        );
        let submits = rpc.submits.borrow();
        let (_, tx) = employment_tx(&submits[0]);
        let TxPayload::Employment(d) = &tx.payload else {
            panic!("not an Employment payload")
        };
        assert_eq!(d.recipient, employee());
        let p: RevokeEmploymentPayload = bincode::deserialize(&d.data).unwrap();
        assert_eq!(p.revocation_ref, expected);
        assert!(
            !submits[0].contains(&hex::encode("contract ended")),
            "the reason is not in the transaction"
        );
    }

    #[test]
    fn a_revocation_of_an_unknown_credential_needs_the_employee() {
        let mut rpc = MockRpc::new();
        rpc.employee = None;
        let s = signer();
        let err = run(
            revoke(None),
            s.address(),
            Some(&s),
            &rpc,
            &opts(false, true),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("employee_address"), "{err}");
        assert_eq!(s.signs.get(), 0);
    }

    #[test]
    fn a_key_for_another_address_is_refused() {
        let rpc = MockRpc::new();
        let s = signer();
        let other = KeyPair::from_bytes([0x12; 32]).address();
        assert!(run(create(), other, Some(&s), &rpc, &opts(false, true)).is_err());
        assert_eq!(s.signs.get(), 0);
        assert!(rpc.builds.borrow().is_empty());
    }

    #[test]
    fn errors_from_the_command_repeat_no_value() {
        let rpc = MockRpc::new();
        let s = signer();
        let mut bad = create();
        if let EmploymentBuildOpRequest::CreateEmployment { employee_ref, .. } = &mut bad {
            *employee_ref = "zz-secretlooking".into();
        }
        let err = run(bad, s.address(), Some(&s), &rpc, &opts(false, true))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "employee_ref: expected 32 bytes of hex");
        assert!(!err.contains("secretlooking"));
    }
}
