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

export { Provider } from './provider.js';

export {
  classifyTransaction,
  humanAction,
  minterRole,
} from './txClassify.js';

export type {
  TxClassifiable,
  TxClassification,
  MinterRole,
} from './txClassify.js';

export {
  DOMAIN_LABEL,
  DOMAIN_BY_TX_TYPE,
  ACTION_LABELS,
  TYPE_FALLBACK,
  UNKNOWN_LABEL,
} from './txLabels.js';

export type { TxDomain } from './txLabels.js';

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
} from './utils.js';

export type {
  KoppaAmount,
  Address,
  Hash,
  BlockInfo,
  TransactionInfo,
  TransactionReceipt,
  TransactionHistoryEntry,
  TransactionHistoryResponse,
  TokenMintersInfo,
  AddressLabel,
  AddressLabelsInfo,
  SupplyInfo,
  ProtocolReserveInfo,
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
  // No-key transaction builders (issue #89)
  TxBuildResponse,
  BuildRequestBase,
  TokenBuildOp,
  TokenBuildRequest,
  NftCollectionConfigInput,
  NftBatchMintRequestInput,
  NftBuildOp,
  NftBuildRequest,
  StakingBuildOp,
  StakingBuildRequest,
  NodeRegistryBuildOp,
  NodeRegistryBuildRequest,
} from './types.js';
