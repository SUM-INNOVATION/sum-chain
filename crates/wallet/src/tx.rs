//! Transaction creation and RPC interaction.

use anyhow::{Context, Result};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use sumchain_crypto::sign;
use sumchain_primitives::{Address, Balance, SignedTransaction, Transaction};
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
}
