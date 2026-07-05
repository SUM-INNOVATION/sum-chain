/**
 * Human-readable label tables for transaction classification.
 *
 * Pure data + pure functions, shared by the explorer and SUMaillet so the two
 * present transactions identically. Labels are conservative: they only describe
 * what `tx_type` + `action` prove. In particular, document-family subtypes
 * (e.g. "diploma" vs "transcript") are NOT inferred here, because the subtype
 * lives in payload data that the transaction responses do not surface — claiming
 * one would be guessing. Correctness beats polish.
 */

/** Transaction domain used for the compact explorer chips. */
export type TxDomain =
  | 'native'
  | 'token'
  | 'snip'
  | 'omninode'
  | 'governance'
  | 'policy'
  | 'messaging'
  | 'other';

/** Display label for each domain chip. */
export const DOMAIN_LABEL: Record<TxDomain, string> = {
  native: 'Native',
  token: 'Token',
  snip: 'SNIP',
  omninode: 'OmniNode',
  governance: 'Governance',
  policy: 'Policy',
  messaging: 'Messaging',
  other: 'Other',
};

/** Map a `tx_type` machine token to its domain chip. Unknown types → `other`. */
export const DOMAIN_BY_TX_TYPE: Record<string, TxDomain> = {
  Transfer: 'native',
  Token: 'token',
  Nft: 'token',
  StorageMetadata: 'snip',
  StorageMetadataV2: 'snip',
  NodeRegistry: 'snip',
  NodeRegistryV2: 'snip',
  InferenceAttestation: 'omninode',
  InferenceSettlement: 'omninode',
  Governance: 'governance',
  PolicyAccount: 'policy',
  Messaging: 'messaging',
  // Everything below is a valid domain but not one of the eight chips → `other`,
  // with a precise human action label so nothing is lost.
  DocClass: 'other',
  Tax: 'other',
  Equity: 'other',
  Agreement: 'other',
  Legal: 'other',
  Property: 'other',
  Healthcare: 'other',
  Employment: 'other',
  Finance: 'other',
  Education: 'other',
  Staking: 'other',
  ContractDeploy: 'other',
  ContractCall: 'other',
};

/**
 * Specific `${tx_type}.${action}` → human label. Only mappings that the
 * operation token actually proves. Missing combinations fall back to
 * {@link TYPE_FALLBACK} (a coarser but still-true label).
 */
export const ACTION_LABELS: Record<string, string> = {
  // Native
  Transfer: 'Koppa transfer',

  // SRC-20 token
  'Token.Create': 'Token creation',
  'Token.Mint': 'Token mint',
  'Token.Burn': 'Token burn',
  'Token.Transfer': 'Token transfer',
  'Token.Approve': 'Token approval',
  'Token.TransferFrom': 'Token transfer',
  'Token.Pause': 'Token pause',
  'Token.Unpause': 'Token unpause',
  'Token.TransferOwnership': 'Token ownership transfer',
  'Token.AddMinter': 'Token minter added',
  'Token.RemoveMinter': 'Token minter removed',

  // NFT (SUM-721)
  'Nft.CreateCollection': 'NFT collection creation',
  'Nft.Mint': 'NFT mint',
  'Nft.MintDocument': 'Certified document mint',
  'Nft.BatchMint': 'NFT batch mint',
  'Nft.Transfer': 'NFT transfer',
  'Nft.Approve': 'NFT approval',
  'Nft.Burn': 'NFT burn',

  // SNIP storage (V2)
  'StorageMetadataV2.RegisterFilePendingV2': 'SNIP file registration',
  'StorageMetadataV2.ActivateFileV2': 'SNIP file activation',
  'StorageMetadataV2.AbandonFileV2': 'SNIP file abandonment',
  'StorageMetadataV2.AcceptAssignmentV2': 'SNIP archive assignment acceptance',
  'StorageMetadataV2.ReassignChunksV2': 'SNIP archive reassignment',
  'StorageMetadataV2.AddAccessV2': 'SNIP access update',
  'StorageMetadataV2.RemoveAccessV2': 'SNIP access update',
  'StorageMetadataV2.UpdateAccessV2': 'SNIP access update',
  // SNIP storage (V1)
  'StorageMetadata.RegisterFile': 'SNIP file registration',
  'StorageMetadata.SubmitStorageProof': 'SNIP storage proof',

  // SNIP archive-node registry
  'NodeRegistry.Register': 'Archive-node registration',
  'NodeRegistry.BeginUnstake': 'Archive-node unbonding',
  'NodeRegistry.WithdrawUnbonded': 'Archive-node withdrawal',
  'NodeRegistry.UpdateStatus': 'Node status update',
  'NodeRegistryV2.RegisterEncryptionKey': 'Encryption-key registration',

  // OmniNode settlement
  'InferenceSettlement.OpenSession': 'OmniNode session open',
  'InferenceSettlement.FundSession': 'OmniNode session funding',
  'InferenceSettlement.ClaimReward': 'OmniNode settlement claim',
  'InferenceSettlement.OpenDispute': 'OmniNode dispute',
  'InferenceSettlement.ResolveDispute': 'OmniNode dispute resolution',
  'InferenceSettlement.RefundSession': 'OmniNode session refund',

  // Governance
  'Governance.RegisterAsset': 'Governance asset registration',
  'Governance.CreateProposal': 'Governance proposal',
  'Governance.CastVote': 'Governance vote',
  'Governance.ExecuteProposal': 'Governance execution',
  'Governance.CancelProposal': 'Governance cancellation',

  // Contracts
  ContractDeploy: 'Contract deployment',
  ContractCall: 'Contract call',
};

/**
 * Coarser per-`tx_type` fallback label, used when no specific action mapping
 * exists. Still strictly true — it names the domain/family without claiming a
 * sub-operation or asset subtype.
 */
export const TYPE_FALLBACK: Record<string, string> = {
  Transfer: 'Koppa transfer',
  Token: 'Token transaction',
  Nft: 'NFT transaction',
  StorageMetadata: 'SNIP storage transaction',
  StorageMetadataV2: 'SNIP storage transaction',
  NodeRegistry: 'Archive-node transaction',
  NodeRegistryV2: 'Archive-node transaction',
  InferenceAttestation: 'OmniNode inference attestation',
  InferenceSettlement: 'OmniNode settlement transaction',
  Governance: 'Governance transaction',
  PolicyAccount: 'Policy account transaction',
  Messaging: 'Messaging transaction',
  DocClass: 'Document credential transaction',
  Tax: 'Tax record transaction',
  Equity: 'Equity record transaction',
  Agreement: 'Agreement record transaction',
  Legal: 'Legal record transaction',
  Property: 'Property record transaction',
  Healthcare: 'Healthcare record transaction',
  Employment: 'Employment record transaction',
  Finance: 'Finance record transaction',
  Education: 'Education record transaction',
  Staking: 'Staking transaction',
  ContractDeploy: 'Contract deployment',
  ContractCall: 'Contract call',
};

/** Fallback label when the transaction type is unknown/unavailable. */
export const UNKNOWN_LABEL = 'Unknown transaction';
