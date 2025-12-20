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

      const json: JsonRpcResponse<T> = await response.json();

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
    const hex = await this.request<string>('sum_blockNumber');
    return parseInt(hex.replace('0x', ''), 16);
  }

  /**
   * Get block by height
   */
  async getBlockByHeight(height: number): Promise<BlockInfo | null> {
    return this.request<BlockInfo | null>('sum_getBlockByHeight', [height]);
  }

  /**
   * Get latest block
   */
  async getLatestBlock(): Promise<BlockInfo> {
    return this.request<BlockInfo>('sum_getLatestBlock');
  }

  /**
   * Get account balance in base units
   */
  async getBalance(address: Address): Promise<bigint> {
    const balance = await this.request<string>('sum_getBalance', [address]);
    return BigInt(balance);
  }

  /**
   * Get account nonce
   */
  async getNonce(address: Address): Promise<number> {
    return this.request<number>('sum_getNonce', [address]);
  }

  /**
   * Send raw signed transaction
   */
  async sendRawTransaction(rawTx: string): Promise<Hash> {
    const result = await this.request<{ tx_hash: string }>('sum_sendRawTransaction', [rawTx]);
    return result.tx_hash;
  }

  /**
   * Get transaction by hash
   */
  async getTransaction(txHash: Hash): Promise<TransactionInfo | null> {
    return this.request<TransactionInfo | null>('sum_getTransaction', [txHash]);
  }

  /**
   * Get transaction receipt
   */
  async getReceipt(txHash: Hash): Promise<TransactionReceipt | null> {
    return this.request<TransactionReceipt | null>('sum_getReceipt', [txHash]);
  }

  /**
   * Get pending transactions
   */
  async getPendingTransactions(): Promise<TransactionInfo[]> {
    return this.request<TransactionInfo[]>('sum_getPendingTransactions');
  }

  /**
   * Get validator set
   */
  async getValidators(): Promise<ValidatorSetInfo> {
    return this.request<ValidatorSetInfo>('sum_getValidators');
  }

  /**
   * Get node health
   */
  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('health');
  }

  /**
   * Get chain ID
   */
  async getChainId(): Promise<number> {
    const hex = await this.request<string>('eth_chainId');
    return parseInt(hex.replace('0x', ''), 16);
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
}
