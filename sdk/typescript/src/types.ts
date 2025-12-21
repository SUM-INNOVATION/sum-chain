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
 * Node health response
 */
export interface HealthResponse {
  status: 'healthy' | 'unhealthy';
  chain_id: number;
  height: number;
  peer_count: number;
  is_validator: boolean;
  is_synced: boolean;
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
