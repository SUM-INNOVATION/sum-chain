//! `sumchain docclass`: DocClass issuer and academic-credential transactions,
//! built and signed on this machine.
//!
//! The private key never leaves the process. Each command:
//! 1. reads the chain id and the sender's nonce (and, for an issue that omits
//!    them, the sender's issuer name and jurisdiction) from the node;
//! 2. builds the transaction locally with
//!    `sumchain_primitives::docclass_build`, every field explicit;
//! 3. unless `--no-builder-check`, asks the node's no-key
//!    `docclass_buildTransaction` builder for the same transaction and refuses
//!    to sign if the node's bytes or signing hash differ;
//! 4. with `--dry-run`, prints the summary and the signing hash and stops:
//!    nothing is signed or sent;
//! 5. otherwise signs the LOCAL transaction and submits it through
//!    `send_raw_transaction`.
//!
//! The command signs only bytes it built itself; the builder's reply is used to
//! detect disagreement, never as the thing signed.
//!
//! Key handling: the key file is read into zeroizing memory and parsed by hand,
//! and every parse failure has one fixed message. Neither an error nor `Debug`
//! output repeats any part of the file.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use sumchain_crypto::{sign, KeyPair};
use sumchain_primitives::docclass_build::{build_docclass_tx, DocClassTxContext};
use sumchain_primitives::{Address, Hash, SignedTransaction, TransactionV2};
use sumchain_rpc::docclass_build::{
    make_explicit, needs_issuer_record, op_from_request, parse_address, DocClassRequestDefaults,
};
use sumchain_rpc::types::{
    DocClassAttributeRecord, DocClassBuildOpRequest, DocClassBuildRequest, DocClassBuildResponse,
    DocClassCredentialMetadataRecord, DocClassIssuerKeyRecord, DocClassIssuerRecord,
};
use zeroize::Zeroizing;

// ── Command line ────────────────────────────────────────────────────────────

/// Options every `sumchain docclass` command takes.
#[derive(Args, Debug, Clone)]
pub struct DocclassArgs {
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
    /// docclass_buildTransaction output (for nodes without that builder).
    #[arg(long, global = true)]
    pub no_builder_check: bool,

    #[command(subcommand)]
    pub command: DocclassCommand,
}

// Parsed once per invocation, so the variants' size difference costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum DocclassCommand {
    /// Register the sender as an academic (educational) issuer.
    RegisterIssuer {
        #[arg(long)]
        name: String,
        /// ISO 3166-1 alpha-2.
        #[arg(long)]
        jurisdiction: String,
        /// Comma-separated: 810 (transcript), 811 (diploma), 812 (enrollment).
        #[arg(long, value_delimiter = ',', required = true)]
        subcodes: Vec<u16>,
        /// Stake in base units.
        #[arg(long, default_value = "0")]
        stake: u128,
        /// Sender's public key (hex). Taken from --key when omitted.
        #[arg(long)]
        public_key: Option<String>,
        /// Registration time in milliseconds; defaults to now.
        #[arg(long)]
        registered_at: Option<u64>,
        #[arg(long)]
        metadata: Option<String>,
    },
    /// Issue an academic credential.
    Issue {
        /// Holder address (base58).
        #[arg(long)]
        holder: String,
        /// 810, 811 or 812.
        #[arg(long)]
        subcode: u16,
        /// Hex, 32 bytes.
        #[arg(long)]
        subject_commitment: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        schema_hash: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        content_commitment: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        credential_type: String,
        #[arg(long)]
        issue_date: String,
        #[arg(long)]
        program: Option<String>,
        #[arg(long)]
        completion_date: Option<String>,
        /// Public attribute as name=value; repeatable.
        #[arg(long = "attribute")]
        attributes: Vec<String>,
        /// Defaults to the sender's registered issuer name.
        #[arg(long)]
        institution_id: Option<String>,
        /// Defaults to the sender's first registered jurisdiction.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Milliseconds; defaults to now.
        #[arg(long)]
        issued_at: Option<u64>,
        /// Milliseconds; defaults to the issue time.
        #[arg(long)]
        valid_from: Option<u64>,
        /// Milliseconds; 0 = no expiry.
        #[arg(long, default_value = "0")]
        expires_at: u64,
        /// Hex, 32 bytes.
        #[arg(long)]
        payload_hash: Option<String>,
        #[arg(long)]
        payload_hint: Option<String>,
    },
    /// Revoke a credential the sender issued.
    Revoke {
        /// Hex, 32 bytes.
        #[arg(long)]
        credential_id: String,
        /// RevocationReason code (0 unspecified, 1 key compromise, ...).
        #[arg(long, default_value = "0")]
        reason: u8,
    },
    /// Suspend a credential the sender issued.
    Suspend {
        #[arg(long)]
        credential_id: String,
        /// RevocationReason code; 6 = certificate hold.
        #[arg(long, default_value = "6")]
        reason: u8,
    },
    /// Reactivate a suspended credential the sender issued.
    Reactivate {
        #[arg(long)]
        credential_id: String,
    },
    /// Supersede a credential with a newer one.
    Supersede {
        #[arg(long)]
        old_credential_id: String,
        #[arg(long)]
        new_credential_id: String,
    },
    /// Deactivate an issuer: the sender itself, or any issuer when the sender
    /// is the chain's DocClass admin.
    DeactivateIssuer {
        /// Issuer address (base58); defaults to the sender.
        #[arg(long)]
        issuer: Option<String>,
    },
    /// Replace the sender's issuer record with a complete record from a JSON
    /// file (the `docclass_buildTransaction` `update_issuer.issuer` shape).
    UpdateIssuer {
        #[arg(long)]
        record: PathBuf,
    },
    /// Add a new issuer key and retire an old one.
    RotateIssuerKey {
        #[arg(long)]
        new_key_id: String,
        /// Hex, 32 bytes.
        #[arg(long)]
        new_public_key: String,
        #[arg(long)]
        old_key_id: String,
        /// Milliseconds; defaults to now.
        #[arg(long)]
        added_at: Option<u64>,
        /// Milliseconds; 0 = no expiry.
        #[arg(long, default_value = "0")]
        expires_at: u64,
        /// Do not make the new key primary.
        #[arg(long)]
        not_primary: bool,
    },
}

// ── Key material ────────────────────────────────────────────────────────────

/// A 32-byte key seed held in memory that is zeroed on drop. `Debug` prints
/// nothing of it.
pub struct SecretSeed(Zeroizing<[u8; 32]>);

impl fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretSeed(<redacted>)")
    }
}

/// Why a key file could not be used. Each variant is one fixed message: no
/// position, character, value or length from the file appears in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyFileError {
    #[error("could not read the key file")]
    Read,
    #[error("the key file is not a JSON array of 32 byte values")]
    Malformed,
}

impl SecretSeed {
    /// Parse a key file's contents: a JSON array of exactly 32 integers in
    /// 0..=255, with optional whitespace. Parsed by hand so that no library
    /// error message, which could quote the input, is ever produced.
    pub fn parse(contents: &str) -> std::result::Result<Self, KeyFileError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut count = 0usize;
        let mut bytes = contents.trim().bytes().peekable();
        if bytes.next() != Some(b'[') {
            return Err(KeyFileError::Malformed);
        }
        loop {
            while matches!(bytes.peek(), Some(b) if b.is_ascii_whitespace()) {
                bytes.next();
            }
            let mut value: u32 = 0;
            let mut digits = 0;
            while let Some(&b) = bytes.peek() {
                if !b.is_ascii_digit() {
                    break;
                }
                value = value * 10 + u32::from(b - b'0');
                digits += 1;
                bytes.next();
                if digits > 3 || value > 255 {
                    return Err(KeyFileError::Malformed);
                }
            }
            if digits == 0 || count == 32 {
                return Err(KeyFileError::Malformed);
            }
            seed[count] = value as u8;
            count += 1;
            while matches!(bytes.peek(), Some(b) if b.is_ascii_whitespace()) {
                bytes.next();
            }
            match bytes.next() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => return Err(KeyFileError::Malformed),
            }
        }
        if count != 32 || bytes.next().is_some() {
            return Err(KeyFileError::Malformed);
        }
        Ok(SecretSeed(seed))
    }

    /// Read and parse a key file.
    pub fn read(path: &Path) -> std::result::Result<Self, KeyFileError> {
        let contents =
            Zeroizing::new(std::fs::read_to_string(path).map_err(|_| KeyFileError::Read)?);
        Self::parse(&contents)
    }

    fn keypair(&self) -> KeyPair {
        KeyPair::from_bytes(*self.0)
    }
}

// ── Seams for tests ─────────────────────────────────────────────────────────

/// What the command needs from a node.
pub trait DocclassRpc {
    fn chain_id(&self) -> Result<u64>;
    fn nonce(&self, address: &Address) -> Result<u64>;
    /// The sender's issuer name and first jurisdiction, if registered.
    fn issuer_defaults(&self, address: &Address) -> Result<Option<(String, Option<String>)>>;
    fn build(&self, request: &DocClassBuildRequest) -> Result<DocClassBuildResponse>;
    /// Submit a signed transaction (hex); returns the node's transaction hash.
    fn submit(&self, signed_hex: &str) -> Result<String>;
}

/// Something that can sign as one address.
pub trait TxSigner {
    fn address(&self) -> Address;
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, tx: TransactionV2) -> SignedTransaction;
}

/// Signs with a key loaded from a key file.
pub struct KeyFileSigner {
    keypair: KeyPair,
}

impl KeyFileSigner {
    pub fn new(seed: &SecretSeed) -> Self {
        Self {
            keypair: seed.keypair(),
        }
    }
}

impl fmt::Debug for KeyFileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyFileSigner({})", self.keypair.address().to_base58())
    }
}

impl TxSigner for KeyFileSigner {
    fn address(&self) -> Address {
        self.keypair.address()
    }
    fn public_key(&self) -> [u8; 32] {
        *self.keypair.public_key().as_bytes()
    }
    fn sign(&self, tx: TransactionV2) -> SignedTransaction {
        let sig = sign(tx.signing_hash().as_bytes(), self.keypair.private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *self.keypair.public_key().as_bytes())
    }
}

// ── The command ─────────────────────────────────────────────────────────────

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    DryRun {
        summary: String,
        signing_hash: Hash,
        credential_id: Option<[u8; 32]>,
    },
    Submitted {
        summary: String,
        tx_hash: String,
        credential_id: Option<[u8; 32]>,
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

fn op_name(op: &DocClassBuildOpRequest) -> &'static str {
    match op {
        DocClassBuildOpRequest::RegisterAcademicIssuer { .. } => "register academic issuer",
        DocClassBuildOpRequest::IssueAcademicCredential { .. } => "issue academic credential",
        DocClassBuildOpRequest::RevokeCredential { .. } => "revoke credential",
        DocClassBuildOpRequest::SuspendCredential { .. } => "suspend credential",
        DocClassBuildOpRequest::ReactivateCredential { .. } => "reactivate credential",
        DocClassBuildOpRequest::SupersedeCredential { .. } => "supersede credential",
        DocClassBuildOpRequest::UpdateIssuer { .. } => "update issuer",
        DocClassBuildOpRequest::RotateIssuerKey { .. } => "rotate issuer key",
        DocClassBuildOpRequest::DeactivateIssuer { .. } => "deactivate issuer",
    }
}

/// Build, check, and (unless a dry run) sign and submit one operation.
///
/// `signer` may be `None` only for a dry run. When present, its address must be
/// `from`.
pub fn run(
    op: DocClassBuildOpRequest,
    from: Address,
    signer: Option<&dyn TxSigner>,
    rpc: &dyn DocclassRpc,
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
    let mut defaults = DocClassRequestDefaults {
        now_ms: opts.now_ms,
        ..Default::default()
    };
    if needs_issuer_record(&op) {
        if let Some((name, jurisdiction)) = rpc
            .issuer_defaults(&from)
            .context("reading the sender's issuer record")?
        {
            defaults.issuer_name = Some(name);
            defaults.issuer_jurisdiction = jurisdiction;
        }
    }
    let op = make_explicit(&op, &defaults).map_err(|e| anyhow!(e))?;
    let built_op = op_from_request(&op, &defaults).map_err(|e| anyhow!(e))?;
    let ctx = DocClassTxContext {
        chain_id,
        from,
        nonce,
        fee: opts.fee,
    };
    let built = build_docclass_tx(&ctx, &built_op).map_err(|e| anyhow!(e))?;
    let local_bytes = format!("0x{}", hex::encode(built.tx.to_bytes()));
    let local_hash = built.tx.signing_hash();
    let local_hash_hex = format!("0x{}", hex::encode(local_hash.as_bytes()));

    if opts.builder_check {
        let request = DocClassBuildRequest {
            from: from.to_base58(),
            fee: Some(opts.fee),
            nonce: Some(nonce),
            chain_id: Some(chain_id),
            op: op.clone(),
        };
        let reply = rpc.build(&request).context("asking the node's builder")?;
        if reply.tx.signing_hash != local_hash_hex || reply.tx.unsigned_tx != local_bytes {
            bail!(
                "the node's docclass_buildTransaction produced a different transaction \
                 than this client built; nothing was signed"
            );
        }
    }

    let mut summary = format!(
        "DocClass {}\n  From:         {}\n  Chain ID:     {}\n  Nonce:        {}\n  Fee:          {} base units\n  Signing hash: {}",
        op_name(&op),
        from.to_base58(),
        chain_id,
        nonce,
        opts.fee,
        local_hash_hex,
    );
    if let Some(id) = built.credential_id {
        summary.push_str(&format!("\n  Credential:   0x{}", hex::encode(id)));
    }
    if opts.builder_check {
        summary.push_str("\n  Builder:      agrees");
    }

    if opts.dry_run {
        return Ok(Outcome::DryRun {
            summary,
            signing_hash: local_hash,
            credential_id: built.credential_id,
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
        credential_id: built.credential_id,
    })
}

fn parse_attribute(s: &str) -> Result<DocClassAttributeRecord> {
    let (name, value) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("--attribute: expected name=value"))?;
    Ok(DocClassAttributeRecord {
        name: name.to_string(),
        value: value.to_string(),
    })
}

/// Turn the parsed command into the request operation. `public_key` is the
/// signer's, when a key file was given.
pub fn request_op(
    command: &DocclassCommand,
    from: &Address,
    public_key: Option<[u8; 32]>,
    now_ms: u64,
) -> Result<DocClassBuildOpRequest> {
    Ok(match command.clone() {
        DocclassCommand::RegisterIssuer {
            name,
            jurisdiction,
            subcodes,
            stake,
            public_key: given,
            registered_at,
            metadata,
        } => {
            let public_key = match (given, public_key) {
                (Some(hex_key), _) => hex_key,
                (None, Some(pk)) => hex::encode(pk),
                (None, None) => bail!("--public-key is required without --key"),
            };
            DocClassBuildOpRequest::RegisterAcademicIssuer {
                name,
                jurisdiction,
                subcodes,
                stake_amount: stake,
                public_key,
                registered_at,
                metadata,
            }
        }
        DocclassCommand::Issue {
            holder,
            subcode,
            subject_commitment,
            schema_hash,
            content_commitment,
            title,
            credential_type,
            issue_date,
            program,
            completion_date,
            attributes,
            institution_id,
            jurisdiction,
            issued_at,
            valid_from,
            expires_at,
            payload_hash,
            payload_hint,
        } => {
            let issued_at = issued_at.unwrap_or(now_ms);
            DocClassBuildOpRequest::IssueAcademicCredential {
                holder_address: holder,
                subcode,
                subject_commitment,
                schema_hash,
                content_commitment,
                institution_id,
                jurisdiction,
                metadata: DocClassCredentialMetadataRecord {
                    title,
                    credential_type,
                    program,
                    issue_date,
                    completion_date,
                    attributes: attributes
                        .iter()
                        .map(|a| parse_attribute(a))
                        .collect::<Result<Vec<_>>>()?,
                },
                issued_at: Some(issued_at),
                valid_from: valid_from.unwrap_or(issued_at),
                expires_at,
                payload_hash,
                payload_hint,
            }
        }
        DocclassCommand::Revoke {
            credential_id,
            reason,
        } => DocClassBuildOpRequest::RevokeCredential {
            credential_id,
            reason,
        },
        DocclassCommand::Suspend {
            credential_id,
            reason,
        } => DocClassBuildOpRequest::SuspendCredential {
            credential_id,
            reason,
        },
        DocclassCommand::Reactivate { credential_id } => {
            DocClassBuildOpRequest::ReactivateCredential { credential_id }
        }
        DocclassCommand::Supersede {
            old_credential_id,
            new_credential_id,
        } => DocClassBuildOpRequest::SupersedeCredential {
            old_credential_id,
            new_credential_id,
        },
        DocclassCommand::DeactivateIssuer { issuer } => DocClassBuildOpRequest::DeactivateIssuer {
            issuer_address: issuer.unwrap_or_else(|| from.to_base58()),
        },
        DocclassCommand::UpdateIssuer { record } => {
            let text = std::fs::read_to_string(&record)
                .map_err(|_| anyhow!("could not read the --record file"))?;
            let issuer: DocClassIssuerRecord = serde_json::from_str(&text)
                .map_err(|_| anyhow!("the --record file is not a complete issuer record"))?;
            DocClassBuildOpRequest::UpdateIssuer { issuer }
        }
        DocclassCommand::RotateIssuerKey {
            new_key_id,
            new_public_key,
            old_key_id,
            added_at,
            expires_at,
            not_primary,
        } => DocClassBuildOpRequest::RotateIssuerKey {
            new_key: DocClassIssuerKeyRecord {
                key_id: new_key_id,
                public_key: new_public_key,
                key_type: "Ed25519".to_string(),
                added_at: added_at.unwrap_or(now_ms),
                expires_at,
                active: true,
                is_primary: !not_primary,
            },
            old_key_id,
        },
    })
}

// ── JSON-RPC over HTTP ──────────────────────────────────────────────────────

/// The node's JSON-RPC endpoint, used the same way `sumchain transfer` uses it.
pub struct HttpRpc {
    url: String,
    client: reqwest::blocking::Client,
}

impl HttpRpc {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::blocking::Client::new(),
        }
    }

    /// One JSON-RPC call; an error reply becomes an error naming the method.
    pub(crate) fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let resp: serde_json::Value = self
            .client
            .post(&self.url)
            .json(&serde_json::json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": 1 }))
            .send()
            .with_context(|| format!("{method}: could not reach the RPC endpoint"))?
            .json()
            .with_context(|| format!("{method}: unreadable RPC response"))?;
        if let Some(error) = resp.get("error") {
            bail!("{method}: {error}");
        }
        Ok(resp["result"].clone())
    }
}

impl DocclassRpc for HttpRpc {
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
    fn issuer_defaults(&self, address: &Address) -> Result<Option<(String, Option<String>)>> {
        let v = self.call(
            "docclass_getIssuer",
            serde_json::json!([address.to_base58()]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let name = v["name"]
            .as_str()
            .ok_or_else(|| anyhow!("docclass_getIssuer: no name"))?;
        let jurisdiction = v["jurisdictions"]
            .get(0)
            .and_then(|j| j.as_str())
            .map(str::to_string);
        Ok(Some((name.to_string(), jurisdiction)))
    }
    fn build(&self, request: &DocClassBuildRequest) -> Result<DocClassBuildResponse> {
        let v = self.call("docclass_buildTransaction", serde_json::json!([request]))?;
        serde_json::from_value(v)
            .map_err(|_| anyhow!("docclass_buildTransaction: unexpected response"))
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

/// Entry point for `sumchain docclass ...`.
pub fn execute(args: DocclassArgs) -> Result<()> {
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
    let op = request_op(
        &args.command,
        &from,
        signer.as_ref().map(|s| s.public_key()),
        now,
    )?;
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
    use sumchain_primitives::TxPayload;

    // Synthetic keys from fixed test seeds only.
    fn test_seed() -> SecretSeed {
        SecretSeed(Zeroizing::new([0x11; 32]))
    }

    struct MockRpc {
        tamper: bool,
        builds: Cell<usize>,
        submits: RefCell<Vec<String>>,
        issuer: Option<(String, Option<String>)>,
    }

    impl MockRpc {
        fn new() -> Self {
            Self {
                tamper: false,
                builds: Cell::new(0),
                submits: RefCell::new(vec![]),
                issuer: Some(("Example Institute".into(), Some("US".into()))),
            }
        }
    }

    impl DocclassRpc for MockRpc {
        fn chain_id(&self) -> Result<u64> {
            Ok(1337)
        }
        fn nonce(&self, _: &Address) -> Result<u64> {
            Ok(7)
        }
        fn issuer_defaults(&self, _: &Address) -> Result<Option<(String, Option<String>)>> {
            Ok(self.issuer.clone())
        }
        /// What a node's builder does with an explicit request, optionally with
        /// one byte changed.
        fn build(&self, request: &DocClassBuildRequest) -> Result<DocClassBuildResponse> {
            self.builds.set(self.builds.get() + 1);
            let from = parse_address("from", &request.from).unwrap();
            let op = op_from_request(&request.op, &DocClassRequestDefaults::default()).unwrap();
            let mut ctx = DocClassTxContext {
                chain_id: request.chain_id.unwrap(),
                from,
                nonce: request.nonce.unwrap(),
                fee: request.fee.unwrap(),
            };
            if self.tamper {
                ctx.fee += 1;
            }
            let built = build_docclass_tx(&ctx, &op).unwrap();
            Ok(DocClassBuildResponse {
                tx: sumchain_rpc::types::TxBuildResponse {
                    unsigned_tx: format!("0x{}", hex::encode(built.tx.to_bytes())),
                    signing_hash: format!("0x{}", hex::encode(built.tx.signing_hash().as_bytes())),
                    from: from.to_base58(),
                    nonce: ctx.nonce,
                    fee: ctx.fee,
                    chain_id: ctx.chain_id,
                },
                credential_id: built.credential_id.map(hex::encode),
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
            inner: KeyFileSigner::new(&test_seed()),
            signs: Cell::new(0),
        }
    }

    fn opts(dry_run: bool, builder_check: bool) -> RunOptions {
        RunOptions {
            fee: 1_000_000,
            dry_run,
            builder_check,
            now_ms: 1_750_000_000_000,
        }
    }

    fn revoke() -> DocClassBuildOpRequest {
        DocClassBuildOpRequest::RevokeCredential {
            credential_id: "ab".repeat(32),
            reason: 1,
        }
    }

    fn issue() -> DocClassBuildOpRequest {
        DocClassBuildOpRequest::IssueAcademicCredential {
            holder_address: KeyPair::from_bytes([0x13; 32]).address().to_base58(),
            subcode: 811,
            subject_commitment: "31".repeat(32),
            schema_hash: "32".repeat(32),
            content_commitment: "33".repeat(32),
            institution_id: None,
            jurisdiction: None,
            metadata: DocClassCredentialMetadataRecord {
                title: "Bachelor of Science".into(),
                credential_type: "undergraduate_degree".into(),
                program: None,
                issue_date: "2026-05-15".into(),
                completion_date: None,
                attributes: vec![],
            },
            issued_at: Some(1_750_000_000_000),
            valid_from: 1_750_000_000_000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
        }
    }

    #[test]
    fn a_dry_run_never_signs_or_submits() {
        let rpc = MockRpc::new();
        let s = signer();
        let out = run(revoke(), s.address(), Some(&s), &rpc, &opts(true, true)).unwrap();
        assert!(matches!(out, Outcome::DryRun { .. }));
        assert_eq!(s.signs.get(), 0);
        assert!(rpc.submits.borrow().is_empty());
        assert_eq!(rpc.builds.get(), 1, "the dry run still checks the builder");
    }

    #[test]
    fn a_dry_run_needs_no_key() {
        let rpc = MockRpc::new();
        let from = KeyPair::from_bytes([0x11; 32]).address();
        let out = run(revoke(), from, None, &rpc, &opts(true, true)).unwrap();
        assert!(matches!(out, Outcome::DryRun { .. }));
        assert!(
            run(revoke(), from, None, &rpc, &opts(false, true)).is_err(),
            "a real run does"
        );
    }

    #[test]
    fn a_builder_that_disagrees_is_refused_before_signing() {
        let mut rpc = MockRpc::new();
        rpc.tamper = true;
        let s = signer();
        let err = run(revoke(), s.address(), Some(&s), &rpc, &opts(false, true)).unwrap_err();
        assert!(err.to_string().contains("nothing was signed"), "{err}");
        assert_eq!(s.signs.get(), 0);
        assert!(rpc.submits.borrow().is_empty());
    }

    #[test]
    fn without_the_check_the_builder_is_not_asked() {
        let mut rpc = MockRpc::new();
        rpc.tamper = true;
        let s = signer();
        run(revoke(), s.address(), Some(&s), &rpc, &opts(false, false)).unwrap();
        assert_eq!(rpc.builds.get(), 0);
        assert_eq!(s.signs.get(), 1);
    }

    #[test]
    fn a_real_run_signs_the_local_transaction_once_and_submits_it() {
        let rpc = MockRpc::new();
        let s = signer();
        let out = run(issue(), s.address(), Some(&s), &rpc, &opts(false, true)).unwrap();
        let Outcome::Submitted { credential_id, .. } = out else {
            panic!("not submitted")
        };
        assert!(credential_id.is_some());
        assert_eq!(s.signs.get(), 1);
        let submits = rpc.submits.borrow();
        assert_eq!(submits.len(), 1);
        let signed = SignedTransaction::from_hex(&submits[0]).unwrap();
        assert!(
            signed.verify_signer(),
            "the signature verifies under the signer's key"
        );
        let sumchain_primitives::TxInner::V2(tx) = &signed.inner else {
            panic!("not V2")
        };
        assert_eq!(tx.from, s.address());
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.chain_id, 1337);
        assert!(matches!(tx.payload, TxPayload::DocClass(_)));
    }

    #[test]
    fn an_issue_takes_institution_and_jurisdiction_from_the_issuer_record() {
        let rpc = MockRpc::new();
        let s = signer();
        run(issue(), s.address(), Some(&s), &rpc, &opts(false, true)).unwrap();

        let mut unregistered = MockRpc::new();
        unregistered.issuer = None;
        let err = run(
            issue(),
            s.address(),
            Some(&s),
            &unregistered,
            &opts(false, true),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("institution_id"), "{err}");
        assert!(unregistered.submits.borrow().is_empty());
    }

    #[test]
    fn a_key_for_another_address_is_refused() {
        let rpc = MockRpc::new();
        let s = signer();
        let other = KeyPair::from_bytes([0x12; 32]).address();
        assert!(run(revoke(), other, Some(&s), &rpc, &opts(false, true)).is_err());
        assert_eq!(s.signs.get(), 0);
    }

    fn file(values: &[u32]) -> String {
        format!(
            "[{}]",
            values
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    #[test]
    fn a_valid_key_file_parses() {
        let seed = SecretSeed::parse(&file(&[17; 32])).unwrap();
        assert_eq!(*seed.0, [17u8; 32]);
        assert!(SecretSeed::parse(&format!("  {}\n", file(&[0; 32]))).is_ok());
    }

    /// Every malformed file gives the same fixed message: it names no position,
    /// character, value or length, so nothing of the file reaches a terminal or
    /// a log through an error.
    #[test]
    fn a_malformed_key_file_reveals_nothing_about_its_contents() {
        let mut out_of_range = vec![17u32; 32];
        out_of_range[5] = 300;
        let cases = [
            file(&out_of_range),
            file(&[17; 31]),
            file(&[17; 33]),
            "[17, 17, x]".to_string(),
            "{\"seed\": 1}".to_string(),
            format!("{} trailing", file(&[17; 32])),
            String::new(),
            "[1234]".to_string(),
        ];
        for c in &cases {
            let e = SecretSeed::parse(c).unwrap_err();
            assert_eq!(e, KeyFileError::Malformed);
            assert_eq!(
                e.to_string(),
                "the key file is not a JSON array of 32 byte values"
            );
            assert!(!format!("{e:?}").contains("300"));
        }
    }

    #[test]
    fn debug_output_of_key_material_is_redacted() {
        let seed = test_seed();
        let shown = format!("{seed:?}");
        assert_eq!(shown, "SecretSeed(<redacted>)");
        assert!(!shown.contains("17"));
        let shown = format!("{:?}", KeyFileSigner::new(&seed));
        assert!(shown.starts_with("KeyFileSigner("));
        assert!(!shown.contains("17, 17"));
    }

    #[test]
    fn a_missing_key_file_reports_only_that_it_could_not_be_read() {
        let e = SecretSeed::read(Path::new("/nonexistent/sumchain-docclass-test-key.json"))
            .unwrap_err();
        assert_eq!(e.to_string(), "could not read the key file");
    }
}
