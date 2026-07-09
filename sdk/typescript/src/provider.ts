/**
 * SUM Chain TypeScript SDK - JSON-RPC Provider
 */

import type {
  JsonRpcRequest,
  JsonRpcResponse,
  ProviderConfig,
  BlockInfo,
  TransactionInfo,
  TransactionReceipt,
  TransactionHistoryResponse,
  ValidatorSetInfo,
  HealthResponse,
  Address,
  Hash,
  NftCollectionInfo,
  NftTokenInfo,
  NftOwnerTokens,
  Src20TokenInfo,
  TokenMintersInfo,
  AddressLabelsInfo,
  SupplyInfo,
  ProtocolReserveInfo,
  Src20TokenHoldings,
  TxBuildResponse,
  TokenBuildRequest,
  NftBuildRequest,
  StakingBuildRequest,
  NodeRegistryBuildRequest,
} from './types.js';

/**
 * JSON-RPC Provider for SUM Chain
 */
export class Provider {
  private url: string;
  private timeout: number;
  private headers: Record<string, string>;
  private requestId = 0;

  /**
   * Create a new provider
   *
   * @param config - Provider configuration
   *
   * @example
   * ```ts
   * const provider = new Provider({
   *   url: 'http://localhost:8545',
   *   timeout: 30000
   * });
   * ```
   */
  constructor(config: string | ProviderConfig) {
    if (typeof config === 'string') {
      this.url = config;
      this.timeout = 30000;
      this.headers = { 'Content-Type': 'application/json' };
    } else {
      this.url = config.url;
      this.timeout = config.timeout || 30000;
      this.headers = {
        'Content-Type': 'application/json',
        ...config.headers,
      };
    }
  }

  /**
   * Make a JSON-RPC request
   */
  private async request<T>(method: string, params?: unknown[]): Promise<T> {
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method,
      params: params || [],
      id: ++this.requestId,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status} ${response.statusText}`);
      }

      const json = (await response.json()) as JsonRpcResponse<T>;

      if (json.error) {
        throw new Error(`RPC error ${json.error.code}: ${json.error.message}`);
      }

      if (json.result === undefined) {
        throw new Error('Missing result in response');
      }

      return json.result;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Request timeout after ${this.timeout}ms`);
      }
      throw error;
    }
  }

  /**
   * Get current block height
   */
  async getBlockNumber(): Promise<number> {
    const hex = await this.request<string>('eth_blockNumber');
    return parseInt(hex.replace('0x', ''), 16);
  }

  /**
   * Get block by height
   */
  async getBlockByHeight(height: number): Promise<BlockInfo | null> {
    return this.request<BlockInfo | null>('get_block_by_height', [height]);
  }

  /**
   * Get latest block
   */
  async getLatestBlock(): Promise<BlockInfo> {
    return this.request<BlockInfo>('get_latest_block');
  }

  /**
   * Get account balance in base units
   */
  async getBalance(address: Address): Promise<bigint> {
    const balance = await this.request<string>('get_balance', [address]);
    return BigInt(balance);
  }

  /**
   * Get account nonce
   */
  async getNonce(address: Address): Promise<number> {
    return this.request<number>('get_nonce', [address]);
  }

  /**
   * Send raw signed transaction
   */
  async sendRawTransaction(rawTx: string): Promise<Hash> {
    const result = await this.request<{ tx_hash: string }>('send_raw_transaction', [rawTx]);
    return result.tx_hash;
  }

  /**
   * Get transaction by hash
   */
  async getTransaction(txHash: Hash): Promise<TransactionInfo | null> {
    return this.request<TransactionInfo | null>('get_transaction', [txHash]);
  }

  /**
   * Get transaction receipt
   */
  async getReceipt(txHash: Hash): Promise<TransactionReceipt | null> {
    return this.request<TransactionReceipt | null>('get_receipt', [txHash]);
  }

  /**
   * Get pending transactions
   */
  async getPendingTransactions(): Promise<TransactionInfo[]> {
    return this.request<TransactionInfo[]>('get_pending_transactions');
  }

  /**
   * Get validator set
   */
  async getValidators(): Promise<ValidatorSetInfo> {
    return this.request<ValidatorSetInfo>('get_validators');
  }

  /**
   * Get node health
   */
  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('node_info');
  }

  /**
   * Get chain ID
   */
  async getChainId(): Promise<number> {
    return this.request<number>('chain_id');
  }

  /**
   * Wait for transaction receipt with polling
   *
   * @param txHash - Transaction hash
   * @param timeout - Timeout in milliseconds (default: 60000)
   * @param interval - Polling interval in milliseconds (default: 1000)
   */
  async waitForReceipt(
    txHash: Hash,
    timeout = 60000,
    interval = 1000
  ): Promise<TransactionReceipt> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const receipt = await this.getReceipt(txHash);

      if (receipt) {
        return receipt;
      }

      await new Promise((resolve) => setTimeout(resolve, interval));
    }

    throw new Error(`Transaction receipt timeout after ${timeout}ms`);
  }

  /**
   * Wait for transaction confirmation
   *
   * @param txHash - Transaction hash
   * @param confirmations - Number of block confirmations to wait for
   * @param timeout - Timeout in milliseconds
   */
  async waitForConfirmation(
    txHash: Hash,
    confirmations = 1,
    timeout = 60000
  ): Promise<TransactionReceipt> {
    const receipt = await this.waitForReceipt(txHash, timeout);
    const targetHeight = receipt.block_height + confirmations;

    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      const currentHeight = await this.getBlockNumber();

      if (currentHeight >= targetHeight) {
        return receipt;
      }

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    throw new Error(`Confirmation timeout after ${timeout}ms`);
  }

  // ==========================================================================
  // SUM Chain Native Methods (sum_* prefix)
  // These use the SUM Chain branded RPC method names
  // ==========================================================================

  /**
   * Get current block number using SUM native method
   * @returns Block height as number
   */
  async sumBlockNumber(): Promise<number> {
    return this.request<number>('sum_blockNumber');
  }

  /**
   * Get latest block using SUM native method
   */
  async sumGetLatestBlock(): Promise<BlockInfo> {
    return this.request<BlockInfo>('sum_getLatestBlock');
  }

  /**
   * Get block by height using SUM native method
   */
  async sumGetBlockByHeight(height: number): Promise<BlockInfo | null> {
    return this.request<BlockInfo | null>('sum_getBlockByHeight', [height]);
  }

  /**
   * Get account balance using SUM native method
   * @returns Balance in base units as bigint
   */
  async sumGetBalance(address: Address): Promise<bigint> {
    const balance = await this.request<string>('sum_getBalance', [address]);
    return BigInt(balance);
  }

  /**
   * Get account nonce using SUM native method
   */
  async sumGetNonce(address: Address): Promise<number> {
    return this.request<number>('sum_getNonce', [address]);
  }

  /**
   * Send raw transaction using SUM native method
   */
  async sumSendRawTransaction(rawTx: string): Promise<Hash> {
    const result = await this.request<{ tx_hash: string }>('sum_sendRawTransaction', [rawTx]);
    return result.tx_hash;
  }

  /**
   * Get transaction by hash using SUM native method
   */
  async sumGetTransaction(txHash: Hash): Promise<TransactionInfo | null> {
    return this.request<TransactionInfo | null>('sum_getTransaction', [txHash]);
  }

  /**
   * Get transaction receipt using SUM native method
   */
  async sumGetReceipt(txHash: Hash): Promise<TransactionReceipt | null> {
    return this.request<TransactionReceipt | null>('sum_getReceipt', [txHash]);
  }

  /**
   * Get pending transactions using SUM native method
   */
  async sumGetPendingTransactions(): Promise<TransactionInfo[]> {
    return this.request<TransactionInfo[]>('sum_getPendingTransactions');
  }

  /**
   * Get validators using SUM native method
   */
  async sumGetValidators(): Promise<ValidatorSetInfo> {
    return this.request<ValidatorSetInfo>('sum_getValidators');
  }

  // ==========================================================================
  // Ethereum-Compatible Methods (eth_* prefix)
  // These use Ethereum-style RPC method names for wallet compatibility
  // ==========================================================================

  /**
   * Get block number in hex format (Ethereum-compatible)
   * @returns Block number as hex string (e.g., "0x1a4")
   */
  async ethBlockNumber(): Promise<string> {
    return this.request<string>('eth_blockNumber');
  }

  /**
   * Get balance in hex format (Ethereum-compatible)
   * @param address - Account address
   * @param block - Block number or "latest" (optional, ignored)
   * @returns Balance as hex string
   */
  async ethGetBalance(address: Address, block?: string): Promise<string> {
    return this.request<string>('eth_getBalance', [address, block || 'latest']);
  }

  // ==========================================================================
  // NFT (SUM-721) Methods
  // ==========================================================================

  /**
   * Get NFT collection by ID
   *
   * @param collectionId - Collection ID (hex string with or without 0x prefix)
   * @returns Collection info or null if not found
   *
   * @example
   * ```ts
   * const collection = await provider.getNftCollection('0x1234...');
   * if (collection) {
   *   console.log(`Collection: ${collection.name} (${collection.symbol})`);
   *   console.log(`Total supply: ${collection.total_supply}`);
   * }
   * ```
   */
  async getNftCollection(collectionId: string): Promise<NftCollectionInfo | null> {
    return this.request<NftCollectionInfo | null>('nft_getCollection', [collectionId]);
  }

  /**
   * Get NFT token by collection ID and token ID
   *
   * @param collectionId - Collection ID (hex string)
   * @param tokenId - Token ID
   * @returns Token info or null if not found
   *
   * @example
   * ```ts
   * const token = await provider.getNftToken('0x1234...', 42);
   * if (token) {
   *   console.log(`Owner: ${token.owner}`);
   *   console.log(`Metadata: ${token.metadata}`);
   * }
   * ```
   */
  async getNftToken(collectionId: string, tokenId: number): Promise<NftTokenInfo | null> {
    return this.request<NftTokenInfo | null>('nft_getToken', [collectionId, tokenId]);
  }

  /**
   * Get all NFT tokens owned by an address
   *
   * @param owner - Owner address
   * @returns Object with owner, count, and list of token references
   *
   * @example
   * ```ts
   * const owned = await provider.getNftsByOwner('SUM1abc...');
   * console.log(`Owns ${owned.count} NFTs`);
   * for (const token of owned.tokens) {
   *   console.log(`  Collection ${token.collection_id}, Token #${token.token_id}`);
   * }
   * ```
   */
  async getNftsByOwner(owner: Address): Promise<NftOwnerTokens> {
    return this.request<NftOwnerTokens>('nft_getTokensByOwner', [owner]);
  }

  /**
   * Get NFT balance (count of tokens) for an address
   *
   * @param owner - Owner address
   * @returns Number of NFTs owned
   *
   * @example
   * ```ts
   * const count = await provider.getNftBalance('SUM1abc...');
   * console.log(`Owns ${count} NFTs`);
   * ```
   */
  async getNftBalance(owner: Address): Promise<number> {
    return this.request<number>('nft_balanceOf', [owner]);
  }

  /**
   * Get owner of a specific NFT token
   *
   * @param collectionId - Collection ID (hex string)
   * @param tokenId - Token ID
   * @returns Owner address or null if token doesn't exist
   *
   * @example
   * ```ts
   * const owner = await provider.getNftOwner('0x1234...', 42);
   * if (owner) {
   *   console.log(`Token owner: ${owner}`);
   * }
   * ```
   */
  async getNftOwner(collectionId: string, tokenId: number): Promise<Address | null> {
    return this.request<Address | null>('nft_ownerOf', [collectionId, tokenId]);
  }

  /**
   * Check if an NFT token exists
   *
   * @param collectionId - Collection ID (hex string)
   * @param tokenId - Token ID
   * @returns True if token exists
   *
   * @example
   * ```ts
   * const exists = await provider.nftTokenExists('0x1234...', 42);
   * console.log(`Token exists: ${exists}`);
   * ```
   */
  async nftTokenExists(collectionId: string, tokenId: number): Promise<boolean> {
    return this.request<boolean>('nft_tokenExists', [collectionId, tokenId]);
  }

  /**
   * Get all token IDs in a collection
   *
   * @param collectionId - Collection ID (hex string)
   * @returns Array of token IDs
   *
   * @example
   * ```ts
   * const tokenIds = await provider.getTokensInCollection('0x1234...');
   * console.log(`Collection has ${tokenIds.length} tokens`);
   * ```
   */
  async getTokensInCollection(collectionId: string): Promise<number[]> {
    return this.request<number[]>('nft_getTokensInCollection', [collectionId]);
  }

  // ==========================================================================
  // SRC-20 Token Methods
  // ==========================================================================

  /**
   * Get SRC-20 token by ID
   *
   * @param tokenId - Token ID (hex string with or without 0x prefix)
   * @returns Token info or null if not found
   *
   * @example
   * ```ts
   * const token = await provider.getSrc20Token('0x1234...');
   * if (token) {
   *   console.log(`Token: ${token.name} (${token.symbol})`);
   *   console.log(`Total supply: ${token.total_supply}`);
   * }
   * ```
   */
  async getSrc20Token(tokenId: string): Promise<Src20TokenInfo | null> {
    return this.request<Src20TokenInfo | null>('token_getToken', [tokenId]);
  }

  /**
   * Get the registered minters of a single SRC-20 token (token-scoped).
   *
   * Returns the token owner (implicit minter) plus explicitly-registered minter
   * addresses, from public token config. This is deliberately token-scoped:
   * there is no address→tokens lookup — the SDK does not expose "all tokens an
   * address can mint" (a broader address-profiling surface).
   *
   * @param tokenId - Token ID (hex string)
   * @returns Minter info, or null if the token does not exist
   *
   * @example
   * ```ts
   * const m = await provider.getTokenMinters('0x1234...');
   * if (m) console.log(m.owner, m.minters);
   * ```
   */
  async getTokenMinters(tokenId: string): Promise<TokenMintersInfo | null> {
    return this.request<TokenMintersInfo | null>('token_getMinters', [tokenId]);
  }

  /**
   * Resolve public registry labels for an address (issue #64).
   *
   * A read-only point lookup across the address-keyed public registries
   * (DocClass / Employment issuer names; Tax / Finance issuer roles; node role).
   * Returns the raw address plus any labels and a deterministic `primary_label`
   * (empty labels + `null` primary when the address is in no public registry).
   * This is a **current** registry view — not a historical-at-tx-height claim.
   * Always display the raw address alongside any label.
   *
   * @param address - Address to resolve (base58)
   * @returns Address plus resolved public labels
   *
   * @example
   * ```ts
   * const { primary_label, labels } = await provider.resolveAddressLabels('SUM1abc...');
   * // primary_label: "SUM Hypothesis Institute" | null
   * ```
   */
  async resolveAddressLabels(address: Address): Promise<AddressLabelsInfo> {
    return this.request<AddressLabelsInfo>('sum_resolveAddressLabels', [address]);
  }

  /**
   * Canonical-supply report (800B supply correction): initial/current
   * canonical supply, live accounted account supply, burned supply, protocol
   * reserve remaining, migration status, governance mint total, and
   * `automatic_emissions_enabled` (always `false`).
   */
  async getSupplyInfo(): Promise<SupplyInfo> {
    return this.request<SupplyInfo>('chain_getSupplyInfo', []);
  }

  /**
   * ProtocolReserve pool balances, or `null` before the supply correction has
   * applied on-chain.
   */
  async getProtocolReserve(): Promise<ProtocolReserveInfo | null> {
    return this.request<ProtocolReserveInfo | null>('chain_getProtocolReserve', []);
  }

  /**
   * Get SRC-20 token balance for an address
   *
   * @param tokenId - Token ID (hex string)
   * @param owner - Owner address
   * @returns Balance in base units as string
   *
   * @example
   * ```ts
   * const balance = await provider.getSrc20Balance('0x1234...', 'SUM1abc...');
   * console.log(`Balance: ${balance}`);
   * ```
   */
  async getSrc20Balance(tokenId: string, owner: Address): Promise<string> {
    return this.request<string>('token_balanceOf', [tokenId, owner]);
  }

  /**
   * Get all SRC-20 tokens held by an address
   *
   * @param owner - Owner address
   * @returns Object with owner, count, and list of token balances
   *
   * @example
   * ```ts
   * const holdings = await provider.getSrc20TokensByOwner('SUM1abc...');
   * console.log(`Holds ${holdings.count} different tokens`);
   * for (const token of holdings.tokens) {
   *   console.log(`  ${token.symbol}: ${token.balance}`);
   * }
   * ```
   */
  async getSrc20TokensByOwner(owner: Address): Promise<Src20TokenHoldings> {
    return this.request<Src20TokenHoldings>('token_getTokensByOwner', [owner]);
  }

  /**
   * Get SRC-20 token allowance
   *
   * @param tokenId - Token ID (hex string)
   * @param owner - Token owner address
   * @param spender - Spender address
   * @returns Allowance amount in base units as string
   *
   * @example
   * ```ts
   * const allowance = await provider.getSrc20Allowance('0x1234...', 'SUM1abc...', 'SUM1def...');
   * console.log(`Allowance: ${allowance}`);
   * ```
   */
  async getSrc20Allowance(tokenId: string, owner: Address, spender: Address): Promise<string> {
    return this.request<string>('token_allowance', [tokenId, owner, spender]);
  }

  /**
   * Get total supply of an SRC-20 token
   *
   * @param tokenId - Token ID (hex string)
   * @returns Total supply in base units as string
   *
   * @example
   * ```ts
   * const supply = await provider.getSrc20TotalSupply('0x1234...');
   * console.log(`Total supply: ${supply}`);
   * ```
   */
  async getSrc20TotalSupply(tokenId: string): Promise<string> {
    return this.request<string>('token_totalSupply', [tokenId]);
  }

  /**
   * Check if an SRC-20 token exists
   *
   * @param tokenId - Token ID (hex string)
   * @returns True if token exists
   *
   * @example
   * ```ts
   * const exists = await provider.src20TokenExists('0x1234...');
   * console.log(`Token exists: ${exists}`);
   * ```
   */
  async src20TokenExists(tokenId: string): Promise<boolean> {
    return this.request<boolean>('token_exists', [tokenId]);
  }

  // ==========================================================================
  // Transaction History Methods
  // ==========================================================================

  /**
   * Get transaction history for an address (both sent and received)
   *
   * @param address - Account address
   * @param limit - Maximum number of transactions to return (default: 50, max: 100)
   * @param offset - Number of transactions to skip (for pagination)
   * @returns Transaction history with pagination info
   *
   * @example
   * ```ts
   * const history = await provider.getTransactionsByAddress('SUM1abc...', 20, 0);
   * console.log(`Total transactions: ${history.total_count}`);
   * for (const tx of history.transactions) {
   *   console.log(`${tx.tx_hash}: ${tx.from} -> ${tx.to}: ${tx.amount}`);
   * }
   * ```
   */
  async getTransactionsByAddress(
    address: Address,
    limit?: number,
    offset?: number
  ): Promise<TransactionHistoryResponse> {
    return this.request<TransactionHistoryResponse>('sum_getTransactionsByAddress', [
      address,
      limit ?? null,
      offset ?? null,
    ]);
  }

  /**
   * Get transactions sent by an address
   *
   * @param address - Sender address
   * @param limit - Maximum number of transactions to return
   * @param offset - Number of transactions to skip
   * @returns Transaction history with pagination info
   *
   * @example
   * ```ts
   * const sent = await provider.getTransactionsBySender('SUM1abc...');
   * console.log(`Sent ${sent.transactions.length} transactions`);
   * ```
   */
  async getTransactionsBySender(
    address: Address,
    limit?: number,
    offset?: number
  ): Promise<TransactionHistoryResponse> {
    return this.request<TransactionHistoryResponse>('sum_getTransactionsBySender', [
      address,
      limit ?? null,
      offset ?? null,
    ]);
  }

  /**
   * Get transactions received by an address
   *
   * @param address - Recipient address
   * @param limit - Maximum number of transactions to return
   * @param offset - Number of transactions to skip
   * @returns Transaction history with pagination info
   *
   * @example
   * ```ts
   * const received = await provider.getTransactionsByRecipient('SUM1abc...');
   * console.log(`Received ${received.transactions.length} transactions`);
   * ```
   */
  async getTransactionsByRecipient(
    address: Address,
    limit?: number,
    offset?: number
  ): Promise<TransactionHistoryResponse> {
    return this.request<TransactionHistoryResponse>('sum_getTransactionsByRecipient', [
      address,
      limit ?? null,
      offset ?? null,
    ]);
  }

  /**
   * Get total transaction count for an address
   *
   * @param address - Account address
   * @returns Total number of transactions involving this address
   *
   * @example
   * ```ts
   * const count = await provider.getTransactionCount('SUM1abc...');
   * console.log(`Total transactions: ${count}`);
   * ```
   */
  async getTransactionCount(address: Address): Promise<number> {
    return this.request<number>('sum_getTransactionCount', [address]);
  }

  // ==========================================================================
  // No-key unsigned-transaction builders (issue #89)
  // Return unsigned tx material + signing hash only — no keys, no signing.
  // Sign the `signing_hash` locally and submit via `sendRawTransaction`.
  // ==========================================================================

  /** Build an unsigned SRC-20 token transaction (`token_buildTransaction`). */
  async buildTokenTransaction(request: TokenBuildRequest): Promise<TxBuildResponse> {
    return this.request<TxBuildResponse>('token_buildTransaction', [request]);
  }

  /** Build an unsigned SUM-721 NFT transaction (`nft_buildTransaction`). */
  async buildNftTransaction(request: NftBuildRequest): Promise<TxBuildResponse> {
    return this.request<TxBuildResponse>('nft_buildTransaction', [request]);
  }

  /** Build an unsigned staking/validator transaction (`staking_buildTransaction`). */
  async buildStakingTransaction(request: StakingBuildRequest): Promise<TxBuildResponse> {
    return this.request<TxBuildResponse>('staking_buildTransaction', [request]);
  }

  /** Build an unsigned node-registry transaction (`nodeRegistry_buildTransaction`). */
  async buildNodeRegistryTransaction(request: NodeRegistryBuildRequest): Promise<TxBuildResponse> {
    return this.request<TxBuildResponse>('nodeRegistry_buildTransaction', [request]);
  }
}
