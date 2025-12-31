/**
 * SUM Chain TypeScript SDK - JSON-RPC Provider
 */
import type { ProviderConfig, BlockInfo, TransactionInfo, TransactionReceipt, ValidatorSetInfo, HealthResponse, Address, Hash, NftCollectionInfo, NftTokenInfo, NftOwnerTokens } from './types';
/**
 * JSON-RPC Provider for SUM Chain
 */
export declare class Provider {
    private url;
    private timeout;
    private headers;
    private requestId;
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
    constructor(config: string | ProviderConfig);
    /**
     * Make a JSON-RPC request
     */
    private request;
    /**
     * Get current block height
     */
    getBlockNumber(): Promise<number>;
    /**
     * Get block by height
     */
    getBlockByHeight(height: number): Promise<BlockInfo | null>;
    /**
     * Get latest block
     */
    getLatestBlock(): Promise<BlockInfo>;
    /**
     * Get account balance in base units
     */
    getBalance(address: Address): Promise<bigint>;
    /**
     * Get account nonce
     */
    getNonce(address: Address): Promise<number>;
    /**
     * Send raw signed transaction
     */
    sendRawTransaction(rawTx: string): Promise<Hash>;
    /**
     * Get transaction by hash
     */
    getTransaction(txHash: Hash): Promise<TransactionInfo | null>;
    /**
     * Get transaction receipt
     */
    getReceipt(txHash: Hash): Promise<TransactionReceipt | null>;
    /**
     * Get pending transactions
     */
    getPendingTransactions(): Promise<TransactionInfo[]>;
    /**
     * Get validator set
     */
    getValidators(): Promise<ValidatorSetInfo>;
    /**
     * Get node health
     */
    getHealth(): Promise<HealthResponse>;
    /**
     * Get chain ID
     */
    getChainId(): Promise<number>;
    /**
     * Wait for transaction receipt with polling
     *
     * @param txHash - Transaction hash
     * @param timeout - Timeout in milliseconds (default: 60000)
     * @param interval - Polling interval in milliseconds (default: 1000)
     */
    waitForReceipt(txHash: Hash, timeout?: number, interval?: number): Promise<TransactionReceipt>;
    /**
     * Wait for transaction confirmation
     *
     * @param txHash - Transaction hash
     * @param confirmations - Number of block confirmations to wait for
     * @param timeout - Timeout in milliseconds
     */
    waitForConfirmation(txHash: Hash, confirmations?: number, timeout?: number): Promise<TransactionReceipt>;
    /**
     * Get current block number using SUM native method
     * @returns Block height as number
     */
    sumBlockNumber(): Promise<number>;
    /**
     * Get latest block using SUM native method
     */
    sumGetLatestBlock(): Promise<BlockInfo>;
    /**
     * Get block by height using SUM native method
     */
    sumGetBlockByHeight(height: number): Promise<BlockInfo | null>;
    /**
     * Get account balance using SUM native method
     * @returns Balance in base units as bigint
     */
    sumGetBalance(address: Address): Promise<bigint>;
    /**
     * Get account nonce using SUM native method
     */
    sumGetNonce(address: Address): Promise<number>;
    /**
     * Send raw transaction using SUM native method
     */
    sumSendRawTransaction(rawTx: string): Promise<Hash>;
    /**
     * Get transaction by hash using SUM native method
     */
    sumGetTransaction(txHash: Hash): Promise<TransactionInfo | null>;
    /**
     * Get transaction receipt using SUM native method
     */
    sumGetReceipt(txHash: Hash): Promise<TransactionReceipt | null>;
    /**
     * Get pending transactions using SUM native method
     */
    sumGetPendingTransactions(): Promise<TransactionInfo[]>;
    /**
     * Get validators using SUM native method
     */
    sumGetValidators(): Promise<ValidatorSetInfo>;
    /**
     * Get block number in hex format (Ethereum-compatible)
     * @returns Block number as hex string (e.g., "0x1a4")
     */
    ethBlockNumber(): Promise<string>;
    /**
     * Get balance in hex format (Ethereum-compatible)
     * @param address - Account address
     * @param block - Block number or "latest" (optional, ignored)
     * @returns Balance as hex string
     */
    ethGetBalance(address: Address, block?: string): Promise<string>;
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
    getNftCollection(collectionId: string): Promise<NftCollectionInfo | null>;
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
    getNftToken(collectionId: string, tokenId: number): Promise<NftTokenInfo | null>;
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
    getNftsByOwner(owner: Address): Promise<NftOwnerTokens>;
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
    getNftBalance(owner: Address): Promise<number>;
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
    getNftOwner(collectionId: string, tokenId: number): Promise<Address | null>;
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
    nftTokenExists(collectionId: string, tokenId: number): Promise<boolean>;
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
    getTokensInCollection(collectionId: string): Promise<number[]>;
}
