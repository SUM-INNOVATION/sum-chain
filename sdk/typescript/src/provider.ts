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
  ValidatorSetInfo,
  HealthResponse,
  KoppaAmount,
  Address,
  Hash,
  NftCollectionInfo,
  NftTokenInfo,
  NftOwnerTokens,
} from './types';

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
}
