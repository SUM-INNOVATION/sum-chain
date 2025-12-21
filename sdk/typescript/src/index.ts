/**
 * SUM Chain TypeScript SDK
 *
 * Official SDK for interacting with SUM Chain
 * Native Currency: Koppa (Ϙ) with 9 decimal places
 *
 * @example
 * ```ts
 * import { Provider, koppaToBaseUnits, formatKoppa } from '@sumchain/sdk';
 *
 * const provider = new Provider('http://localhost:8545');
 *
 * // Get balance
 * const balance = await provider.getBalance('5HqX...');
 * console.log(formatKoppa(balance)); // "100 Ϙ"
 *
 * // Convert amounts
 * const amount = koppaToBaseUnits("1.5"); // 1500000000n
 * ```
 */

export { Provider } from './provider';

export {
  koppaToBaseUnits,
  baseUnitsToKoppa,
  formatKoppa,
  formatNumber,
  isValidAddress,
  isValidHash,
  sleep,
  retry,
  KOPPA_UNIT,
  KOPPA_SYMBOL,
  KOPPA_NAME,
  KOPPA_DECIMALS,
} from './utils';

export type {
  KoppaAmount,
  Address,
  Hash,
  BlockInfo,
  TransactionInfo,
  TransactionReceipt,
  ValidatorInfo,
  ValidatorSetInfo,
  HealthResponse,
  JsonRpcRequest,
  JsonRpcResponse,
  ProviderConfig,
  TransactionOptions,
  // NFT (SUM-721) Types
  NftCollectionInfo,
  NftTokenInfo,
  NftTokenRef,
  NftOwnerTokens,
} from './types';
