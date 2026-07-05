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
