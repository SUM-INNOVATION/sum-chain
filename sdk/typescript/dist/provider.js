/**
 * SUM Chain TypeScript SDK - JSON-RPC Provider
 */
/**
 * JSON-RPC Provider for SUM Chain
 */
export class Provider {
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
    constructor(config) {
        this.requestId = 0;
        if (typeof config === 'string') {
            this.url = config;
            this.timeout = 30000;
            this.headers = { 'Content-Type': 'application/json' };
        }
        else {
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
    async request(method, params) {
        const request = {
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
            const json = (await response.json());
            if (json.error) {
                throw new Error(`RPC error ${json.error.code}: ${json.error.message}`);
            }
            if (json.result === undefined) {
                throw new Error('Missing result in response');
            }
            return json.result;
        }
        catch (error) {
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
    async getBlockNumber() {
        const hex = await this.request('eth_blockNumber');
        return parseInt(hex.replace('0x', ''), 16);
    }
    /**
     * Get block by height
     */
    async getBlockByHeight(height) {
        return this.request('get_block_by_height', [height]);
    }
    /**
     * Get latest block
     */
    async getLatestBlock() {
        return this.request('get_latest_block');
    }
    /**
     * Get account balance in base units
     */
    async getBalance(address) {
        const balance = await this.request('get_balance', [address]);
        return BigInt(balance);
    }
    /**
     * Get account nonce
     */
    async getNonce(address) {
        return this.request('get_nonce', [address]);
    }
    /**
     * Send raw signed transaction
     */
    async sendRawTransaction(rawTx) {
        const result = await this.request('send_raw_transaction', [rawTx]);
        return result.tx_hash;
    }
    /**
     * Get transaction by hash
     */
    async getTransaction(txHash) {
        return this.request('get_transaction', [txHash]);
    }
    /**
     * Get transaction receipt
     */
    async getReceipt(txHash) {
        return this.request('get_receipt', [txHash]);
    }
    /**
     * Get pending transactions
     */
    async getPendingTransactions() {
        return this.request('get_pending_transactions');
    }
    /**
     * Get validator set
     */
    async getValidators() {
        return this.request('get_validators');
    }
    /**
     * Get node health
     */
    async getHealth() {
        return this.request('node_info');
    }
    /**
     * Get chain ID
     */
    async getChainId() {
        return this.request('chain_id');
    }
    /**
     * Wait for transaction receipt with polling
     *
     * @param txHash - Transaction hash
     * @param timeout - Timeout in milliseconds (default: 60000)
     * @param interval - Polling interval in milliseconds (default: 1000)
     */
    async waitForReceipt(txHash, timeout = 60000, interval = 1000) {
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
    async waitForConfirmation(txHash, confirmations = 1, timeout = 60000) {
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
    async sumBlockNumber() {
        return this.request('sum_blockNumber');
    }
    /**
     * Get latest block using SUM native method
     */
    async sumGetLatestBlock() {
        return this.request('sum_getLatestBlock');
    }
    /**
     * Get block by height using SUM native method
     */
    async sumGetBlockByHeight(height) {
        return this.request('sum_getBlockByHeight', [height]);
    }
    /**
     * Get account balance using SUM native method
     * @returns Balance in base units as bigint
     */
    async sumGetBalance(address) {
        const balance = await this.request('sum_getBalance', [address]);
        return BigInt(balance);
    }
    /**
     * Get account nonce using SUM native method
     */
    async sumGetNonce(address) {
        return this.request('sum_getNonce', [address]);
    }
    /**
     * Send raw transaction using SUM native method
     */
    async sumSendRawTransaction(rawTx) {
        const result = await this.request('sum_sendRawTransaction', [rawTx]);
        return result.tx_hash;
    }
    /**
     * Get transaction by hash using SUM native method
     */
    async sumGetTransaction(txHash) {
        return this.request('sum_getTransaction', [txHash]);
    }
    /**
     * Get transaction receipt using SUM native method
     */
    async sumGetReceipt(txHash) {
        return this.request('sum_getReceipt', [txHash]);
    }
    /**
     * Get pending transactions using SUM native method
     */
    async sumGetPendingTransactions() {
        return this.request('sum_getPendingTransactions');
    }
    /**
     * Get validators using SUM native method
     */
    async sumGetValidators() {
        return this.request('sum_getValidators');
    }
    // ==========================================================================
    // Ethereum-Compatible Methods (eth_* prefix)
    // These use Ethereum-style RPC method names for wallet compatibility
    // ==========================================================================
    /**
     * Get block number in hex format (Ethereum-compatible)
     * @returns Block number as hex string (e.g., "0x1a4")
     */
    async ethBlockNumber() {
        return this.request('eth_blockNumber');
    }
    /**
     * Get balance in hex format (Ethereum-compatible)
     * @param address - Account address
     * @param block - Block number or "latest" (optional, ignored)
     * @returns Balance as hex string
     */
    async ethGetBalance(address, block) {
        return this.request('eth_getBalance', [address, block || 'latest']);
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
    async getNftCollection(collectionId) {
        return this.request('nft_getCollection', [collectionId]);
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
    async getNftToken(collectionId, tokenId) {
        return this.request('nft_getToken', [collectionId, tokenId]);
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
    async getNftsByOwner(owner) {
        return this.request('nft_getTokensByOwner', [owner]);
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
    async getNftBalance(owner) {
        return this.request('nft_balanceOf', [owner]);
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
    async getNftOwner(collectionId, tokenId) {
        return this.request('nft_ownerOf', [collectionId, tokenId]);
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
    async nftTokenExists(collectionId, tokenId) {
        return this.request('nft_tokenExists', [collectionId, tokenId]);
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
    async getTokensInCollection(collectionId) {
        return this.request('nft_getTokensInCollection', [collectionId]);
    }
}
