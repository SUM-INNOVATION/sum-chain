//! Transaction creation and RPC interaction.

use anyhow::{Context, Result};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use sumchain_crypto::sign;
use sumchain_primitives::{
    Address, Balance, NodeRegistryOperation, NodeRegistryTxData, SignedTransaction, Transaction,
    TransactionV2, TxPayload,
};
use sumchain_primitives::storage_metadata::{StorageMetadataOperationV2, StorageMetadataV2TxData};
use sumchain_rpc::api::SumChainApiClient;

use crate::keystore::Keystore;

/// Sign a transaction
pub fn sign_transaction(
    keystore: &Keystore,
    to: Address,
    amount: Balance,
    fee: Balance,
    nonce: u64,
    chain_id: u64,
) -> Result<SignedTransaction> {
    let tx = Transaction::new(
        chain_id,
        keystore.address(),
        to,
        amount,
        fee,
        nonce,
    );

    let signing_hash = tx.signing_hash();
    let signature = sign(signing_hash.as_bytes(), keystore.keypair().private_key());

    Ok(SignedTransaction::new(
        tx,
        *signature.as_bytes(),
        *keystore.public_key().as_bytes(),
    ))
}

/// Sign a NodeRegistry V2 transaction offline (issue #20 archive-node
/// withdrawal ops, and other node-registry operations). Wraps the operation in
/// a [`TransactionV2`] with a [`TxPayload::NodeRegistry`] payload, signs the
/// V2 signing hash, and returns the ready-to-broadcast [`SignedTransaction`].
pub fn sign_node_registry_tx(
    keystore: &Keystore,
    operation: NodeRegistryOperation,
    fee: Balance,
    nonce: u64,
    chain_id: u64,
) -> Result<SignedTransaction> {
    let tx = TransactionV2 {
        chain_id,
        from: keystore.address(),
        fee,
        nonce,
        payload: TxPayload::NodeRegistry(NodeRegistryTxData { operation }),
    };

    let signing_hash = tx.signing_hash();
    let signature = sign(signing_hash.as_bytes(), keystore.keypair().private_key());

    Ok(SignedTransaction::new_v2(
        tx,
        *signature.as_bytes(),
        *keystore.public_key().as_bytes(),
    ))
}

/// Sign a StorageMetadataV2 transaction offline (issue #80 archive reassignment,
/// and other V2 storage operations). Mirrors [`sign_node_registry_tx`]: wraps the
/// typed operation in a [`TransactionV2`] with a [`TxPayload::StorageMetadataV2`]
/// payload and signs locally — the CLI wallet never hand-crafts raw bincode and
/// does not depend on the `storage_buildReassignChunksV2` RPC builder (that
/// builder exists for non-Rust clients).
pub fn sign_storage_metadata_v2_tx(
    keystore: &Keystore,
    operation: StorageMetadataOperationV2,
    fee: Balance,
    nonce: u64,
    chain_id: u64,
) -> Result<SignedTransaction> {
    let tx = TransactionV2 {
        chain_id,
        from: keystore.address(),
        fee,
        nonce,
        payload: TxPayload::StorageMetadataV2(StorageMetadataV2TxData { operation }),
    };
    let signing_hash = tx.signing_hash();
    let signature = sign(signing_hash.as_bytes(), keystore.keypair().private_key());
    Ok(SignedTransaction::new_v2(
        tx,
        *signature.as_bytes(),
        *keystore.public_key().as_bytes(),
    ))
}

/// Read epoch-aware assignment coverage for a file (issue #62/#80). `None` when
/// the file is not registered.
pub async fn storage_get_assignment_coverage_v2(
    rpc_url: &str,
    merkle_root: &str,
) -> Result<Option<sumchain_rpc::types::AssignmentCoverageV2>> {
    let client = create_client(rpc_url).await?;
    let cov = client
        .storage_get_assignment_coverage_v2(merkle_root.to_string(), None, None)
        .await
        .context("Failed to get assignment coverage")?;
    Ok(cov)
}

/// Read the active-archive-node snapshot at (or before) `height` (issue #80).
pub async fn storage_get_active_nodes_at_height(
    rpc_url: &str,
    height: u64,
) -> Result<Vec<sumchain_rpc::types::NodeRecordInfo>> {
    let client = create_client(rpc_url).await?;
    let nodes = client
        .storage_get_active_nodes_at_height(height)
        .await
        .context("Failed to get active nodes at height")?;
    Ok(nodes)
}

/// Query an archive node's registry record (role, stake, status). Used by the
/// archive-node withdrawal commands to read the current staked balance.
pub async fn storage_get_node_record(
    rpc_url: &str,
    node_address: &str,
) -> Result<Option<serde_json::Value>> {
    let client = create_client(rpc_url).await?;
    let record = client
        .storage_get_node_record(node_address.to_string())
        .await
        .context("Failed to get node record")?;

    Ok(record)
}

/// Query an archive node's pending stake-unbonding record (issue #20).
pub async fn storage_get_archive_unbonding(
    rpc_url: &str,
    operator_address: &str,
) -> Result<Option<sumchain_rpc::types::ArchiveUnbondingInfo>> {
    let client = create_client(rpc_url).await?;
    let info = client
        .storage_get_archive_unbonding(operator_address.to_string())
        .await
        .context("Failed to get archive unbonding record")?;

    Ok(info)
}

/// Create RPC client
async fn create_client(rpc_url: &str) -> Result<HttpClient> {
    HttpClientBuilder::default()
        .build(rpc_url)
        .context("Failed to create RPC client")
}

/// Send a raw transaction
pub async fn send_raw_transaction(rpc_url: &str, raw_tx: &str) -> Result<String> {
    let client = create_client(rpc_url).await?;
    let response = client
        .send_raw_transaction(raw_tx.to_string())
        .await
        .context("Failed to send transaction")?;

    Ok(response.tx_hash)
}

/// Get account balance
pub async fn get_balance(rpc_url: &str, address: &str) -> Result<String> {
    let client = create_client(rpc_url).await?;
    let balance = client
        .get_balance(address.to_string())
        .await
        .context("Failed to get balance")?;

    Ok(balance)
}

/// Get account nonce
pub async fn get_nonce(rpc_url: &str, address: &str) -> Result<u64> {
    let client = create_client(rpc_url).await?;
    let nonce = client
        .get_nonce(address.to_string())
        .await
        .context("Failed to get nonce")?;

    Ok(nonce)
}

/// Get latest block number
pub async fn get_block_number(rpc_url: &str) -> Result<u64> {
    let client = create_client(rpc_url).await?;
    let hex_str = client
        .eth_block_number()
        .await
        .context("Failed to get block number")?;

    // Parse hex string (0x...)
    let without_prefix = hex_str.trim_start_matches("0x");
    u64::from_str_radix(without_prefix, 16).context("Failed to parse block number")
}

/// Get block by height
pub async fn get_block(rpc_url: &str, height: u64) -> Result<Option<sumchain_rpc::types::BlockInfo>> {
    let client = create_client(rpc_url).await?;
    let block = client
        .get_block_by_height(height)
        .await
        .context("Failed to get block")?;

    Ok(block)
}

/// Get latest block
pub async fn get_latest_block(rpc_url: &str) -> Result<sumchain_rpc::types::BlockInfo> {
    let client = create_client(rpc_url).await?;
    let block = client
        .get_latest_block()
        .await
        .context("Failed to get latest block")?;

    Ok(block)
}

/// Get validator set
pub async fn get_validators(rpc_url: &str) -> Result<sumchain_rpc::types::ValidatorSetInfo> {
    let client = create_client(rpc_url).await?;
    let validators = client
        .get_validators()
        .await
        .context("Failed to get validators")?;

    Ok(validators)
}

/// Get pending transactions
pub async fn get_pending_transactions(rpc_url: &str) -> Result<Vec<sumchain_rpc::types::TransactionInfo>> {
    let client = create_client(rpc_url).await?;
    let txs = client
        .get_pending_transactions()
        .await
        .context("Failed to get pending transactions")?;

    Ok(txs)
}

/// Get transaction by hash
pub async fn get_transaction(rpc_url: &str, tx_hash: &str) -> Result<Option<sumchain_rpc::types::TransactionInfo>> {
    let client = create_client(rpc_url).await?;
    let tx = client
        .get_transaction(tx_hash.to_string())
        .await
        .context("Failed to get transaction")?;

    Ok(tx)
}

/// Get transaction receipt
pub async fn get_receipt(rpc_url: &str, tx_hash: &str) -> Result<Option<sumchain_rpc::types::ReceiptInfo>> {
    let client = create_client(rpc_url).await?;
    let receipt = client
        .get_receipt(tx_hash.to_string())
        .await
        .context("Failed to get receipt")?;

    Ok(receipt)
}

/// Get node health
pub async fn get_health(rpc_url: &str) -> Result<sumchain_rpc::types::HealthResponse> {
    let client = create_client(rpc_url).await?;
    let health = client
        .health()
        .await
        .context("Failed to get health")?;

    Ok(health)
}

// ============================================================================
// NFT (SUM-721) RPC Functions
// ============================================================================

/// Get NFT collection by ID
pub async fn nft_get_collection(
    rpc_url: &str,
    collection_id: &str,
) -> Result<Option<sumchain_rpc::types::NftCollectionInfo>> {
    let client = create_client(rpc_url).await?;
    let collection = client
        .nft_get_collection(collection_id.to_string())
        .await
        .context("Failed to get NFT collection")?;

    Ok(collection)
}

/// Get NFT token by collection ID and token ID
pub async fn nft_get_token(
    rpc_url: &str,
    collection_id: &str,
    token_id: u64,
) -> Result<Option<sumchain_rpc::types::NftTokenInfo>> {
    let client = create_client(rpc_url).await?;
    let token = client
        .nft_get_token(collection_id.to_string(), token_id)
        .await
        .context("Failed to get NFT token")?;

    Ok(token)
}

/// Get all tokens owned by an address
pub async fn nft_get_tokens_by_owner(
    rpc_url: &str,
    owner: &str,
) -> Result<sumchain_rpc::types::NftOwnerTokens> {
    let client = create_client(rpc_url).await?;
    let tokens = client
        .nft_get_tokens_by_owner(owner.to_string())
        .await
        .context("Failed to get owner tokens")?;

    Ok(tokens)
}

/// Get NFT balance (count of tokens) for an address
pub async fn nft_balance_of(rpc_url: &str, owner: &str) -> Result<u64> {
    let client = create_client(rpc_url).await?;
    let count = client
        .nft_balance_of(owner.to_string())
        .await
        .context("Failed to get NFT balance")?;

    Ok(count)
}

/// Get owner of a specific token
pub async fn nft_owner_of(
    rpc_url: &str,
    collection_id: &str,
    token_id: u64,
) -> Result<Option<String>> {
    let client = create_client(rpc_url).await?;
    let owner = client
        .nft_owner_of(collection_id.to_string(), token_id)
        .await
        .context("Failed to get token owner")?;

    Ok(owner)
}

/// Check if a token exists
#[allow(dead_code)]
pub async fn nft_token_exists(rpc_url: &str, collection_id: &str, token_id: u64) -> Result<bool> {
    let client = create_client(rpc_url).await?;
    let exists = client
        .nft_token_exists(collection_id.to_string(), token_id)
        .await
        .context("Failed to check token existence")?;

    Ok(exists)
}

/// Get all tokens in a collection
#[allow(dead_code)]
pub async fn nft_get_tokens_in_collection(
    rpc_url: &str,
    collection_id: &str,
) -> Result<Vec<u64>> {
    let client = create_client(rpc_url).await?;
    let tokens = client
        .nft_get_tokens_in_collection(collection_id.to_string())
        .await
        .context("Failed to get collection tokens")?;

    Ok(tokens)
}

// ============================================================================
// Smart Contract (SUMC) RPC Functions
// ============================================================================

/// Get contract info by address
pub async fn contract_get_info(
    rpc_url: &str,
    address: &str,
) -> Result<Option<sumchain_rpc::types::ContractInfo>> {
    let client = create_client(rpc_url).await?;
    let info = client
        .contract_get_contract(address.to_string())
        .await
        .context("Failed to get contract info")?;

    Ok(info)
}

/// Check if an address is a contract
pub async fn contract_is_contract(rpc_url: &str, address: &str) -> Result<bool> {
    let client = create_client(rpc_url).await?;
    let is_contract = client
        .contract_is_contract(address.to_string())
        .await
        .context("Failed to check if address is contract")?;

    Ok(is_contract)
}

/// Call a contract method (read-only view call)
pub async fn contract_call(
    rpc_url: &str,
    contract: &str,
    method: &str,
    args: &str,
    from: Option<&str>,
) -> Result<sumchain_rpc::types::ContractCallResult> {
    let client = create_client(rpc_url).await?;
    let request = sumchain_rpc::types::ViewCallRequest {
        contract: contract.to_string(),
        method: method.to_string(),
        args: args.to_string(),
        from: from.map(|s| s.to_string()),
    };
    let result = client
        .contract_call(request)
        .await
        .context("Failed to call contract")?;

    Ok(result)
}

/// Estimate gas for a contract call
pub async fn contract_estimate_gas(
    rpc_url: &str,
    contract: &str,
    method: &str,
    args: &str,
    from: Option<&str>,
) -> Result<sumchain_rpc::types::GasEstimateResult> {
    let client = create_client(rpc_url).await?;
    let request = sumchain_rpc::types::ViewCallRequest {
        contract: contract.to_string(),
        method: method.to_string(),
        args: args.to_string(),
        from: from.map(|s| s.to_string()),
    };
    let result = client
        .contract_estimate_gas(request)
        .await
        .context("Failed to estimate gas")?;

    Ok(result)
}

/// Get contract code hash
pub async fn contract_get_code_hash(rpc_url: &str, address: &str) -> Result<Option<String>> {
    let client = create_client(rpc_url).await?;
    let hash = client
        .contract_get_code_hash(address.to_string())
        .await
        .context("Failed to get code hash")?;

    Ok(hash)
}

/// Get contract storage at a specific key
pub async fn contract_get_storage(
    rpc_url: &str,
    address: &str,
    key: &str,
) -> Result<Option<String>> {
    let client = create_client(rpc_url).await?;
    let value = client
        .contract_get_storage_at(address.to_string(), key.to_string())
        .await
        .context("Failed to get storage")?;

    Ok(value)
}

/// Get contract balance
pub async fn contract_get_balance(rpc_url: &str, address: &str) -> Result<String> {
    let client = create_client(rpc_url).await?;
    let balance = client
        .contract_get_balance(address.to_string())
        .await
        .context("Failed to get contract balance")?;

    Ok(balance)
}

// ============================================================================
// Staking RPC Functions
// ============================================================================

/// Get staking validator by public key
pub async fn staking_get_validator(
    rpc_url: &str,
    pubkey: &str,
) -> Result<Option<sumchain_rpc::types::StakingValidatorInfo>> {
    let client = create_client(rpc_url).await?;
    let validator = client
        .staking_get_validator(pubkey.to_string())
        .await
        .context("Failed to get staking validator")?;

    Ok(validator)
}

/// Get staking validator by address
pub async fn staking_get_validator_by_address(
    rpc_url: &str,
    address: &str,
) -> Result<Option<sumchain_rpc::types::StakingValidatorInfo>> {
    let client = create_client(rpc_url).await?;
    let validator = client
        .staking_get_validator_by_address(address.to_string())
        .await
        .context("Failed to get staking validator by address")?;

    Ok(validator)
}

/// Get all staking validators
pub async fn staking_get_validators(
    rpc_url: &str,
) -> Result<Vec<sumchain_rpc::types::StakingValidatorInfo>> {
    let client = create_client(rpc_url).await?;
    let validators = client
        .staking_get_validators()
        .await
        .context("Failed to get staking validators")?;

    Ok(validators)
}

/// Get active staking validators only
pub async fn staking_get_active_validators(
    rpc_url: &str,
) -> Result<Vec<sumchain_rpc::types::StakingValidatorInfo>> {
    let client = create_client(rpc_url).await?;
    let validators = client
        .staking_get_active_validators()
        .await
        .context("Failed to get active staking validators")?;

    Ok(validators)
}

/// Get staking summary
pub async fn staking_get_summary(
    rpc_url: &str,
) -> Result<sumchain_rpc::types::StakingSummary> {
    let client = create_client(rpc_url).await?;
    let summary = client
        .staking_get_summary()
        .await
        .context("Failed to get staking summary")?;

    Ok(summary)
}

/// Get staking parameters
pub async fn staking_get_params(
    rpc_url: &str,
) -> Result<sumchain_rpc::types::StakingParamsInfo> {
    let client = create_client(rpc_url).await?;
    let params = client
        .staking_get_params()
        .await
        .context("Failed to get staking params")?;

    Ok(params)
}

/// Get total staked amount
pub async fn staking_get_total_stake(rpc_url: &str) -> Result<String> {
    let client = create_client(rpc_url).await?;
    let total = client
        .staking_get_total_stake()
        .await
        .context("Failed to get total stake")?;

    Ok(total)
}

// ============================================================================
// Delegation RPC Functions
// ============================================================================

/// Get delegation info for a delegator to a specific validator
pub async fn delegation_get_delegation(
    rpc_url: &str,
    delegator: &str,
    validator_pubkey: &str,
) -> Result<Option<sumchain_rpc::types::DelegationRpcInfo>> {
    let client = create_client(rpc_url).await?;
    let delegation = client
        .delegation_get_delegation(delegator.to_string(), validator_pubkey.to_string())
        .await
        .context("Failed to get delegation")?;

    Ok(delegation)
}

/// Get all delegations for a delegator
pub async fn delegation_get_delegations_by_delegator(
    rpc_url: &str,
    delegator: &str,
) -> Result<Vec<sumchain_rpc::types::DelegationRpcInfo>> {
    let client = create_client(rpc_url).await?;
    let delegations = client
        .delegation_get_delegations_by_delegator(delegator.to_string())
        .await
        .context("Failed to get delegations by delegator")?;

    Ok(delegations)
}

/// Get all delegations to a validator
pub async fn delegation_get_delegations_by_validator(
    rpc_url: &str,
    validator_pubkey: &str,
) -> Result<Vec<sumchain_rpc::types::DelegationRpcInfo>> {
    let client = create_client(rpc_url).await?;
    let delegations = client
        .delegation_get_delegations_by_validator(validator_pubkey.to_string())
        .await
        .context("Failed to get delegations by validator")?;

    Ok(delegations)
}

/// Get delegator summary
pub async fn delegation_get_delegator_summary(
    rpc_url: &str,
    delegator: &str,
) -> Result<sumchain_rpc::types::DelegatorSummary> {
    let client = create_client(rpc_url).await?;
    let summary = client
        .delegation_get_delegator_summary(delegator.to_string())
        .await
        .context("Failed to get delegator summary")?;

    Ok(summary)
}

/// Get unbonding delegations for a delegator
pub async fn delegation_get_unbonding_delegations(
    rpc_url: &str,
    delegator: &str,
) -> Result<Vec<sumchain_rpc::types::UnbondingDelegationRpcInfo>> {
    let client = create_client(rpc_url).await?;
    let unbondings = client
        .delegation_get_unbonding_delegations(delegator.to_string())
        .await
        .context("Failed to get unbonding delegations")?;

    Ok(unbondings)
}

/// Get validator delegation summary
pub async fn delegation_get_validator_delegation_summary(
    rpc_url: &str,
    validator_pubkey: &str,
) -> Result<sumchain_rpc::types::ValidatorDelegationSummary> {
    let client = create_client(rpc_url).await?;
    let summary = client
        .delegation_get_validator_delegation_summary(validator_pubkey.to_string())
        .await
        .context("Failed to get validator delegation summary")?;

    Ok(summary)
}

// ============================================================================
// SRC-201 Messaging Functions
// ============================================================================

/// Get messaging configuration
pub async fn messaging_get_config(rpc_url: &str) -> Result<sumchain_rpc::types::MessagingConfigInfo> {
    let client = create_client(rpc_url).await?;
    let config = client
        .messaging_get_config()
        .await
        .context("Failed to get messaging config")?;

    Ok(config)
}

/// Get sender's messaging quota
pub async fn messaging_get_quota(
    rpc_url: &str,
    address: &str,
) -> Result<sumchain_rpc::types::MessagingQuotaInfo> {
    let client = create_client(rpc_url).await?;
    let quota = client
        .messaging_get_quota(address.to_string())
        .await
        .context("Failed to get messaging quota")?;

    Ok(quota)
}

/// Get inbox filter for an address
pub async fn messaging_get_inbox_filter(
    rpc_url: &str,
    address: &str,
) -> Result<Option<sumchain_rpc::types::InboxFilterInfo>> {
    let client = create_client(rpc_url).await?;
    let filter = client
        .messaging_get_inbox_filter(address.to_string())
        .await
        .context("Failed to get inbox filter")?;

    Ok(filter)
}

/// Get messages for a recipient
pub async fn messaging_get_messages(
    rpc_url: &str,
    recipient: &str,
    limit: u32,
) -> Result<Vec<sumchain_rpc::types::MessageEventInfo>> {
    let client = create_client(rpc_url).await?;

    // Check if recipient is an address (base58) and convert to hash
    let recipient_hash = if recipient.starts_with("0x") || recipient.len() == 64 {
        // Already a hash
        recipient.to_string()
    } else {
        // Try to parse as address and hash it
        let addr = sumchain_primitives::Address::from_base58(recipient)
            .or_else(|_| sumchain_primitives::Address::from_hex(recipient))
            .context("Invalid recipient address")?;
        let hash = blake3::hash(addr.as_bytes());
        format!("0x{}", hex::encode(hash.as_bytes()))
    };

    let messages = client
        .messaging_get_messages(recipient_hash, Some(limit), None)
        .await
        .context("Failed to get messages")?;

    Ok(messages)
}

/// Get trust stake for an address
pub async fn messaging_get_trust_stake(rpc_url: &str, address: &str) -> Result<String> {
    let client = create_client(rpc_url).await?;
    let stake = client
        .messaging_get_trust_stake(address.to_string())
        .await
        .context("Failed to get trust stake")?;

    Ok(stake)
}

/// Get spam score for an address
pub async fn messaging_get_spam_score(
    rpc_url: &str,
    address: &str,
) -> Result<sumchain_rpc::types::SpamReportInfo> {
    let client = create_client(rpc_url).await?;
    let info = client
        .messaging_get_spam_score(address.to_string())
        .await
        .context("Failed to get spam score")?;

    Ok(info)
}

/// Check if an address is a contact
pub async fn messaging_is_contact(rpc_url: &str, owner: &str, contact: &str) -> Result<bool> {
    let client = create_client(rpc_url).await?;
    let is_contact = client
        .messaging_is_contact(owner.to_string(), contact.to_string())
        .await
        .context("Failed to check contact status")?;

    Ok(is_contact)
}

/// Check if an address is blocked
pub async fn messaging_is_blocked(rpc_url: &str, owner: &str, sender: &str) -> Result<bool> {
    let client = create_client(rpc_url).await?;
    let is_blocked = client
        .messaging_is_blocked(owner.to_string(), sender.to_string())
        .await
        .context("Failed to check blocked status")?;

    Ok(is_blocked)
}

/// Get pending payment for a message
pub async fn messaging_get_pending_payment(
    rpc_url: &str,
    message_id: &str,
) -> Result<Option<sumchain_rpc::types::PendingPaymentInfo>> {
    let client = create_client(rpc_url).await?;
    let payment = client
        .messaging_get_pending_payment(message_id.to_string())
        .await
        .context("Failed to get pending payment")?;

    Ok(payment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_transaction() {
        let keystore = Keystore::generate("test").unwrap();
        let to = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        let signed = sign_transaction(&keystore, to, 100, 10, 0, 1).unwrap();

        assert_eq!(signed.sender(), keystore.address());
        assert_eq!(signed.recipient(), Some(to));
        assert_eq!(signed.amount(), 100);
        assert_eq!(signed.fee(), 10);
        assert_eq!(signed.nonce(), 0);
        assert!(signed.verify_signer());
    }

    #[test]
    fn test_sign_node_registry_begin_unstake() {
        let keystore = Keystore::generate("test").unwrap();
        let signed = sign_node_registry_tx(
            &keystore,
            NodeRegistryOperation::BeginUnstake { amount: 42 },
            10,
            3,
            7,
        )
        .unwrap();

        assert_eq!(signed.sender(), keystore.address());
        assert!(signed.verify_signer());
        assert_eq!(signed.nonce(), 3);
        assert_eq!(signed.fee(), 10);

        // Round-trips through the broadcast hex form.
        let back = SignedTransaction::from_hex(&signed.to_hex()).unwrap();
        assert_eq!(back.to_hex(), signed.to_hex());

        // Payload is the archive begin-unstake op.
        match back.inner() {
            sumchain_primitives::TxInner::V2(tx) => match &tx.payload {
                TxPayload::NodeRegistry(d) => assert_eq!(
                    d.operation,
                    NodeRegistryOperation::BeginUnstake { amount: 42 }
                ),
                other => panic!("unexpected payload: {:?}", other),
            },
            _ => panic!("expected a V2 transaction"),
        }
    }

    #[test]
    fn test_sign_node_registry_withdraw() {
        let keystore = Keystore::generate("test").unwrap();
        let signed = sign_node_registry_tx(
            &keystore,
            NodeRegistryOperation::WithdrawUnbonded,
            5,
            1,
            7,
        )
        .unwrap();

        assert!(signed.verify_signer());
        match signed.inner() {
            sumchain_primitives::TxInner::V2(tx) => match &tx.payload {
                TxPayload::NodeRegistry(d) => {
                    assert_eq!(d.operation, NodeRegistryOperation::WithdrawUnbonded)
                }
                other => panic!("unexpected payload: {:?}", other),
            },
            _ => panic!("expected a V2 transaction"),
        }
    }

    #[test]
    fn test_sign_reassign_chunks_v2() {
        use sumchain_primitives::Hash;
        let keystore = Keystore::generate("test").unwrap();
        let root = Hash::hash(b"file-root");
        let signed = sign_storage_metadata_v2_tx(
            &keystore,
            StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root },
            10,
            2,
            7,
        )
        .unwrap();

        assert_eq!(signed.sender(), keystore.address());
        assert!(signed.verify_signer());
        assert_eq!(signed.nonce(), 2);

        // Round-trips through broadcast hex and decodes to ReassignChunksV2.
        let back = SignedTransaction::from_hex(&signed.to_hex()).unwrap();
        match back.inner() {
            sumchain_primitives::TxInner::V2(tx) => match &tx.payload {
                TxPayload::StorageMetadataV2(d) => assert_eq!(
                    d.operation,
                    StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root }
                ),
                other => panic!("unexpected payload: {:?}", other),
            },
            _ => panic!("expected a V2 transaction"),
        }
    }
}
