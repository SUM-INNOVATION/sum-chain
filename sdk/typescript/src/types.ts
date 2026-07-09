/**
 * SUM Chain TypeScript SDK - Type Definitions
 *
 * Native Currency: Koppa (Ϙ) with 9 decimal places
 */

/**
 * Koppa amount in base units (1 Koppa = 1,000,000,000 base units)
 */
export type KoppaAmount = string | bigint;

/**
 * Address format (base58 or hex)
 */
export type Address = string;

/**
 * Transaction hash (hex string)
 */
export type Hash = string;

/**
 * Block information
 */
export interface BlockInfo {
  height: number;
  hash: Hash;
  parent_hash: Hash;
  timestamp: number;
  state_root: Hash;
  tx_root: Hash;
  proposer: Address;
  tx_count: number;
  transactions: Hash[];
}

/**
 * Transaction information
 */
export interface TransactionInfo {
  hash: Hash;
  from: Address;
  to: Address;
  amount: string;
  fee: string;
  nonce: number;
  chain_id: number;
  block_height?: number;
  status?: 'pending' | 'success' | 'failed';
  /** Wire-stable machine token for the tx domain/type (e.g. "Transfer", "Token", "StorageMetadataV2"). Derived server-side at read time. */
  tx_type?: string;
  /** Inner-operation machine token when present (e.g. "Mint", "CastVote", "RegisterFilePendingV2"). */
  action?: string | null;
  /** Hex asset reference taken directly from the payload (SRC-20 token_id / NFT collection_id). */
  asset_ref?: string | null;
  /** Coarse asset class hint: "native" | "src20" | "nft" | null. */
  asset_kind?: string | null;
}

/**
 * Transaction receipt
 */
export interface TransactionReceipt {
  tx_hash: Hash;
  block_height: number;
  tx_index: number;
  status: 'success' | 'failed';
  fee_paid: string;
}

/**
 * Validator information
 */
export interface ValidatorInfo {
  address: Address;
  public_key: string;
  is_current_proposer: boolean;
}

/**
 * Validator set information
 */
export interface ValidatorSetInfo {
  validators: ValidatorInfo[];
  current_height: number;
  current_proposer_index: number;
}

/**
 * Node health/info response
 */
export interface HealthResponse {
  version: string;
  chain_id: string;
  peer_id: string;
  is_validator: boolean;
  current_height: number;
  peer_count: number;
  mempool_size: number;
  uptime_seconds: number;
}

/**
 * JSON-RPC request
 */
export interface JsonRpcRequest {
  jsonrpc: '2.0';
  method: string;
  params?: unknown[];
  id: number | string;
}

/**
 * JSON-RPC response
 */
export interface JsonRpcResponse<T = unknown> {
  jsonrpc: '2.0';
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
  id: number | string;
}

/**
 * Provider configuration
 */
export interface ProviderConfig {
  url: string;
  timeout?: number;
  headers?: Record<string, string>;
}

/**
 * Transaction options for sending
 */
export interface TransactionOptions {
  from: Address;
  to: Address;
  amount: KoppaAmount;
  fee?: KoppaAmount;
  nonce?: number;
  chainId: number;
}

// ============================================================================
// NFT (SUM-721) Types
// ============================================================================

/**
 * NFT Collection information
 */
export interface NftCollectionInfo {
  collection_id: string;
  name: string;
  symbol: string;
  description: string;
  owner: Address;
  max_supply: number;
  total_supply: number;
  transferable: boolean;
  burnable: boolean;
  metadata_updatable: boolean;
  royalty_bps: number;
  royalty_recipient: Address;
  base_uri?: string;
  created_at: number;
}

/**
 * NFT Token information
 */
export interface NftTokenInfo {
  collection_id: string;
  token_id: number;
  owner: Address;
  creator: Address;
  metadata: string;
  is_document: boolean;
  uri_type: string;
  uri_value?: string;
  approved?: Address;
  locked: boolean;
  transfer_count: number;
  minted_at: number;
}

/**
 * NFT Token reference (collection + token ID)
 */
export interface NftTokenRef {
  collection_id: string;
  token_id: number;
}

/**
 * NFT tokens owned by an address
 */
export interface NftOwnerTokens {
  owner: Address;
  count: number;
  tokens: NftTokenRef[];
}

// ============================================================================
// SRC-20 Token Types
// ============================================================================

/**
 * SRC-20 Token information
 */
export interface Src20TokenInfo {
  token_id: string;
  name: string;
  symbol: string;
  decimals: number;
  owner: Address;
  total_supply: string;
  max_supply: string;
  mintable: boolean;
  burnable: boolean;
  pausable: boolean;
  paused: boolean;
  created_at: number;
  created_at_block: number;
}

/**
 * SRC-20 Token balance
 */
export interface Src20TokenBalance {
  token_id: string;
  symbol: string;
  decimals: number;
  balance: string;
}

/**
 * SRC-20 tokens held by an address
 */
export interface Src20TokenHoldings {
  owner: Address;
  count: number;
  tokens: Src20TokenBalance[];
}

// ============================================================================
// Transaction History Types
// ============================================================================

/**
 * Transaction history entry
 */
export interface TransactionHistoryEntry {
  tx_hash: Hash;
  block_height: number;
  tx_index: number;
  from: Address;
  to: Address;
  amount: string;
  fee: string;
  status: string;
  timestamp: number;
  /** Wire-stable machine token for the tx domain/type. See {@link TransactionInfo.tx_type}. */
  tx_type?: string;
  /** Inner-operation machine token when present. See {@link TransactionInfo.action}. */
  action?: string | null;
  /** Hex asset reference (SRC-20 token_id / NFT collection_id) when a direct payload field. */
  asset_ref?: string | null;
  /** Coarse asset class hint: "native" | "src20" | "nft" | null. */
  asset_kind?: string | null;
}

/**
 * Registered minters of a single SRC-20 token (token-scoped, read-only).
 *
 * The owner is always an implicit minter and is returned separately from the
 * explicitly-registered `minters`. There is intentionally no address→tokens
 * ("what can this address mint") lookup — that broader address-profiling
 * surface is out of scope.
 */
export interface TokenMintersInfo {
  /** Hex token id. */
  token_id: string;
  /** Base58 token owner (implicit minter). */
  owner: Address;
  /** Base58 explicitly-registered minter addresses. */
  minters: Address[];
}

/**
 * Canonical-supply report (800B supply correction). All amounts are base-unit
 * decimal strings. `automatic_emissions_enabled` is always `false` — the chain
 * has no block-reward/inflation path.
 */
export interface SupplyInfo {
  initial_canonical_supply: string;
  current_canonical_supply: string;
  accounted_account_supply: string;
  burned_supply: string;
  protocol_reserve_remaining: string;
  outstanding_grant_unclaimed: string;
  total_minted_by_migration: string;
  total_minted_by_governance: string;
  migration_id: string;
  migration_applied: boolean;
  migration_activation_height: number;
  automatic_emissions_enabled: boolean;
}

/**
 * ProtocolReserve pool balances (base-unit decimal strings). `null` before the
 * supply correction has applied.
 */
export interface ProtocolReserveInfo {
  validator_pool_remaining: string;
  archive_pool_remaining: string;
  compute_pool_remaining: string;
  ecosystem_pool_remaining: string;
  governance_reserve_remaining: string;
  total_remaining: string;
}

/**
 * One public registry label for an address (issue #64). Either a registered
 * institution/issuer name (`kind: 'institution'`) or a role/class label proven
 * by a public registry (`kind: 'role'`). Never fabricated.
 */
export interface AddressLabel {
  /** Display text — an institution/issuer name, or a role/class label. */
  label: string;
  /** `'institution'` (a real registered name) or `'role'` (a role/class only). */
  kind: 'institution' | 'role';
  /** Registry that produced the label: `DocClassIssuer` | `EmploymentIssuer` | `TaxIssuer` | `FinanceIssuer` | `NodeRegistry`. */
  source: string;
  /** Registry status (e.g. `Active`, `Suspended`, `Revoked`). */
  status: string;
}

/**
 * Public registry labels resolved for a single address at read time (issue #64).
 * This is a **current** on-chain registry view, not a historical-at-tx-height
 * assertion. Point lookup only. The raw `address` is always echoed so callers
 * keep it visible/copyable.
 */
export interface AddressLabelsInfo {
  /** The queried address, base58. */
  address: Address;
  /** Deterministic primary label for compact display, or `null` when none. */
  primary_label: string | null;
  /** All resolved labels, in a fixed source order. */
  labels: AddressLabel[];
}

/**
 * Transaction history response with pagination
 */
export interface TransactionHistoryResponse {
  address: Address;
  transactions: TransactionHistoryEntry[];
  total_count: number;
  has_more: boolean;
  offset: number;
  limit: number;
}

// ============================================================================
// No-key unsigned-transaction builders (issue #89)
// ----------------------------------------------------------------------------
// These mirror the RPC builder DTOs. Builders return unsigned tx material only
// (no keys, no signing); sign locally and submit via `send_raw_transaction`.
// Amounts are base-unit integers; the node expects JSON numbers for u64/u128.
// ============================================================================

/** Shared response for every `*_buildTransaction` builder. */
export interface TxBuildResponse {
  /** Bincode-encoded unsigned TransactionV2 (0x-hex). */
  unsigned_tx: string;
  /** Hash to sign (0x-hex). */
  signing_hash: string;
  /** Signer/sender address (base58). */
  from: string;
  nonce: number;
  fee: number;
  chain_id: number;
}

/** Fields common to every builder request. */
export interface BuildRequestBase {
  /** Sender/signer address (base58). */
  from: string;
  /** Fee in base units; omit for the node default. */
  fee?: number;
  /** Nonce; fetched from state when omitted. */
  nonce?: number;
  /** Chain id; fetched from state when omitted. */
  chain_id?: number;
}

// ── SRC-20 token ────────────────────────────────────────────────────────────
export type TokenBuildOp =
  | { op: 'create'; name: string; symbol: string; decimals: number; initial_supply: number | string; max_supply: number | string; mintable: boolean; burnable: boolean; pausable: boolean }
  | { op: 'mint'; to: string; amount: number | string }
  | { op: 'burn'; amount: number | string }
  | { op: 'transfer'; to: string; amount: number | string }
  | { op: 'approve'; spender: string; amount: number | string }
  | { op: 'transfer_from'; from: string; to: string; amount: number | string }
  | { op: 'pause' }
  | { op: 'unpause' }
  | { op: 'transfer_ownership'; new_owner: string }
  | { op: 'add_minter'; minter: string }
  | { op: 'remove_minter'; minter: string };

/** Request for `token_buildTransaction`. `token_id` is hex; omit for `create`. */
export type TokenBuildRequest = BuildRequestBase & { token_id?: string } & TokenBuildOp;

// ── SUM-721 NFT ───────────────────────────────────────────────────────────────
export interface NftCollectionConfigInput {
  max_supply: number;
  transferable: boolean;
  burnable: boolean;
  metadata_updatable: boolean;
  owner_only_minting: boolean;
  royalty_bps: number;
  /** Royalty recipient (base58). */
  royalty_recipient: string;
}
export interface NftBatchMintRequestInput {
  to: string;
  /** Metadata bytes, hex. */
  metadata: string;
}
export type NftBuildOp =
  | { op: 'create_collection'; name: string; symbol: string; description: string; config: NftCollectionConfigInput; base_uri?: string | null }
  | { op: 'mint'; to: string; metadata: string; uri_type: string; uri_value?: string | null }
  | { op: 'mint_document'; to: string; metadata: string; uri_type: string; uri_value?: string | null }
  | { op: 'batch_mint'; requests: NftBatchMintRequestInput[] }
  | { op: 'transfer'; to: string }
  | { op: 'approve'; approved?: string | null }
  | { op: 'burn' }
  | { op: 'update_metadata'; metadata: string }
  | { op: 'transfer_collection_ownership'; new_owner: string }
  | { op: 'update_collection_config'; new_royalty_recipient?: string | null; new_base_uri?: string | null }
  | { op: 'lock_token' }
  | { op: 'unlock_token' };

/** Request for `nft_buildTransaction`. `collection_id` hex; `token_id` numeric (0 for collection-level ops). */
export type NftBuildRequest = BuildRequestBase & { collection_id: string; token_id: number } & NftBuildOp;

// ── Staking ───────────────────────────────────────────────────────────────────
export type StakingBuildOp =
  | { op: 'create_validator'; stake: number | string; commission_bps: number; metadata: string }
  | { op: 'add_stake'; amount: number | string }
  | { op: 'unstake'; amount: number | string }
  | { op: 'update_validator'; commission_bps?: number | null; metadata?: string | null }
  | { op: 'unjail' }
  | { op: 'claim_rewards' }
  | { op: 'delegate'; validator_pubkey: string; amount: number | string }
  | { op: 'undelegate'; validator_pubkey: string; amount: number | string }
  | { op: 'claim_delegation_rewards'; validator_pubkey: string }
  | { op: 'withdraw_unbonded'; validator_pubkey?: string | null }
  | { op: 'submit_double_sign_evidence'; validator_pubkey: string; height: number; block_hash_1: string; signature_1: string; block_hash_2: string; signature_2: string; submitted_at: number }
  | { op: 'submit_downtime_evidence'; validator_pubkey: string; start_height: number; end_height: number; missed_blocks: number; submitted_at: number };

/** Request for `staking_buildTransaction`. */
export type StakingBuildRequest = BuildRequestBase & StakingBuildOp;

// ── NodeRegistry ──────────────────────────────────────────────────────────────
export type NodeRegistryBuildOp =
  | { op: 'register'; role: 'validator' | 'archive_node'; stake: number }
  | { op: 'begin_unstake'; amount: number }
  | { op: 'withdraw_unbonded' }
  | { op: 'register_encryption_key'; encryption_pubkey: string };

/** Request for `nodeRegistry_buildTransaction`. */
export type NodeRegistryBuildRequest = BuildRequestBase & NodeRegistryBuildOp;
