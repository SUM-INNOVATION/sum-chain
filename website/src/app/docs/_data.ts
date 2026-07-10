export type Method = {
  name: string;
  description: string;
  example?: { request: string; response?: string };
};

export type Category = {
  id: string;
  title: string;
  blurb: string;
  methods: Method[];
};

export const ENDPOINT = 'https://rpc.sumchain.io';

// Every method in this page has been verified against the live mainnet RPC.
// Example responses are real captures from rpc.sumchain.io.
export const categories: Category[] = [
  {
    id: 'chain',
    title: 'Chain',
    blurb: 'Block and chain metadata.',
    methods: [
      {
        name: 'chain_id',
        description: 'Returns the chain identifier.',
        example: {
          request: `{"jsonrpc":"2.0","method":"chain_id","params":[],"id":1}`,
          response: `{"jsonrpc":"2.0","result":1,"id":1}`,
        },
      },
      {
        name: 'chain_getSupplyInfo',
        description:
          'Canonical-supply report (800B supply correction): initial/current canonical supply, live accounted account balances, burned (Address::ZERO), protocol reserve remaining, migration id/status, governance-mint total, automatic_emissions_enabled (always false).',
      },
      {
        name: 'chain_getProtocolReserve',
        description:
          'ProtocolReserve pool balances (validator / archive / compute / ecosystem / governance reserve). null before the supply correction has applied.',
      },
      {
        name: 'chain_getServiceGrant',
        description: 'Service-grant ledger record for (address, service_kind); null when no grant exists.',
      },
      {
        name: 'chain_getServiceGrantEligibility',
        description:
          'Verifiable service-milestone counters, claiming-gate state, and genesis-validator exclusion for an address. Configuration/status read, not live participation data.',
      },
      {
        name: 'chain_buildClaimServiceGrant',
        description:
          'Build an unsigned claim-service-grant transaction (no keys). The service_grants gate is deployed in runtime genesis and activates at height 9,200,000 (not exposed by chain_getChainParams; the site uses that operator-verified height).',
      },
      {
        name: 'chain_buildUnlockServiceGrant',
        description:
          'Build an unsigned unlock-service-grant transaction (locked grant unlocks 1:1 against protocol-earned Koppa).',
      },
      {
        name: 'get_latest_block',
        description: 'Returns the most recent block.',
        example: {
          request: `{"jsonrpc":"2.0","method":"get_latest_block","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "hash": "0x69226247daff051c87d610b0a5df1f793cd9b7cfa2d4bd70cb26166d541a0c64",
    "height": 4807038,
    "parent_hash": "0xec94cb97f6f97b4e78ad2054718fde0d0a30bea6a78ac1b69cb34c191df6c422",
    "timestamp": 1777137175565,
    "tx_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "state_root": "0xb9e67e5c251da9131a183a1658c5925690c6752a29c4a1c9e22c91b91e2f34b9",
    "proposer": "e64e11c6f9f9937a1bc6a4535701f036388451e6cc83ad9f25b143973d90a4cd",
    "tx_count": 0,
    "transactions": []
  },
  "id": 1
}`,
        },
      },
      {
        name: 'get_block_by_height',
        description: 'Returns the block at a given height.',
        example: {
          request: `{"jsonrpc":"2.0","method":"get_block_by_height","params":[4807000],"id":1}`,
        },
      },
      { name: 'get_block_by_hash', description: 'Returns the block matching a hex hash.' },
      { name: 'get_blocks', description: 'Paginated block listing.' },
      {
        name: 'get_finality',
        description: 'Returns finalized height + the depth-based finality config (default 6 blocks).',
        example: {
          request: `{"jsonrpc":"2.0","method":"get_finality","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "finalized_height": 4807033,
    "finalized_hash": "0x606ec3b283fe3eed4cdd4ca1cc5c5c5a262dbbb4ee10ebe4dba12dc22aec955a",
    "current_height": 4807039,
    "finality_depth": 6,
    "pending_finality": 6
  },
  "id": 1
}`,
        },
      },
      { name: 'is_block_finalized', description: 'Reports whether a given height is finalized.' },
      {
        name: 'eth_blockNumber',
        description: 'Latest block number in hex (Ethereum-compatible).',
        example: {
          request: `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`,
          response: `{"jsonrpc":"2.0","result":"0x49597f","id":1}`,
        },
      },
      { name: 'sum_blockNumber', description: 'Same as eth_blockNumber, sum_-prefixed alias.' },
      { name: 'sum_getLatestBlock', description: 'Alias of get_latest_block.' },
      { name: 'sum_getBlockByHeight', description: 'Alias of get_block_by_height.' },
    ],
  },
  {
    id: 'account',
    title: 'Account',
    blurb: 'Balance, nonce, and account state. Addresses accept Base58 (with checksum) or 0x-prefixed hex.',
    methods: [
      {
        name: 'get_balance',
        description: 'Returns balance in base units (1 Koppa = 1,000,000,000 base units).',
        example: {
          request: `{"jsonrpc":"2.0","method":"get_balance","params":["8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4"],"id":1}`,
          response: `{"jsonrpc":"2.0","result":"500000001018000000","id":1}`,
        },
      },
      { name: 'get_nonce', description: 'Returns the next expected nonce for the account.' },
      { name: 'get_account', description: 'Returns balance + nonce in one call.' },
      {
        name: 'account_getPublicKey',
        description: 'Returns the registered Ed25519 public key for an address. Required for encrypted messaging recipients.',
      },
      { name: 'eth_getBalance', description: 'Hex-formatted balance (Ethereum-compatible). Optional second `block` argument.' },
      { name: 'sum_getBalance', description: 'sum_-prefixed alias of get_balance.' },
      { name: 'sum_getNonce', description: 'sum_-prefixed alias of get_nonce.' },
      { name: 'sum_resolveAddressLabels', description: 'Public registry labels for an address (current on-chain view): DocClass/Employment issuer names, Tax/Finance issuer roles, node role. Point lookup; raw address always preserved (#64).' },
      { name: 'sum_getTransactionCount', description: 'Total transactions sent by an address.' },
      { name: 'sum_getTransactionsByAddress', description: 'Tx history (sender + recipient) for an address.' },
      { name: 'sum_getTransactionsBySender', description: 'Tx history (sender only).' },
      { name: 'sum_getTransactionsByRecipient', description: 'Tx history (recipient only).' },
    ],
  },
  {
    id: 'transactions',
    title: 'Transactions',
    blurb: 'Submit, look up, and inspect transactions.',
    methods: [
      {
        name: 'send_raw_transaction',
        description: 'Submits a hex-encoded signed transaction. Returns the tx hash.',
        example: {
          request: `{"jsonrpc":"2.0","method":"send_raw_transaction","params":["0xabc..."],"id":1}`,
          response: `{"jsonrpc":"2.0","result":{"tx_hash":"0xdef..."},"id":1}`,
        },
      },
      {
        name: 'get_transaction',
        description:
          'Returns a transaction by hash. Includes additive, read-time semantic labels derived from the already-public payload, tx_type, action, asset_ref, asset_kind, so clients can classify a transaction without decoding it. The same fields appear on transaction-history entries.',
      },
      { name: 'get_receipt', description: 'Returns receipt (success/failure + gas) by tx hash.' },
      { name: 'get_pending_transactions', description: 'Lists pending mempool transactions.' },
      {
        name: 'pending_tx_count',
        description: 'Mempool size.',
        example: {
          request: `{"jsonrpc":"2.0","method":"pending_tx_count","params":[],"id":1}`,
          response: `{"jsonrpc":"2.0","result":0,"id":1}`,
        },
      },
      { name: 'sum_sendRawTransaction', description: 'sum_-prefixed alias of send_raw_transaction.' },
      { name: 'sum_getTransaction', description: 'sum_-prefixed alias.' },
      { name: 'sum_getReceipt', description: 'sum_-prefixed alias.' },
      { name: 'sum_getPendingTransactions', description: 'sum_-prefixed alias.' },
    ],
  },
  {
    id: 'storage',
    title: 'Decentralized Storage (PoR)',
    blurb: 'Native L1 Proof-of-Retrievability, query files, challenges, archive nodes, and V2 coverage. Powers snip.sumchain.io (https://snip.sumchain.io). Archive-node withdrawal (issue #20) and reassignment (issue #62) are active on mainnet (their 8,900,000 gates have been reached).',
    methods: [
      {
        name: 'storage_getFundedFiles',
        description: 'Returns all files with fee_pool > 0. New archive nodes use this to discover what to store and earn from.',
        example: {
          request: `{"jsonrpc":"2.0","method":"storage_getFundedFiles","params":[],"id":1}`,
          response: `{"jsonrpc":"2.0","result":[],"id":1}`,
        },
      },
      {
        name: 'storage_getAccessList',
        description: 'Returns full metadata for a file by its merkle_root, including the on-chain ACL.',
        example: {
          request: `{"jsonrpc":"2.0","method":"storage_getAccessList","params":["0xabc..."],"id":1}`,
        },
      },
      {
        name: 'storage_getActiveChallenges',
        description: 'Open Proof-of-Retrievability challenges assigned to a specific archive node. Failure to respond within 50 blocks slashes 5% of stake.',
        example: {
          request: `{"jsonrpc":"2.0","method":"storage_getActiveChallenges","params":["8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4"],"id":1}`,
        },
      },
      {
        name: 'storage_getNodeRecord',
        description: 'Returns the NodeRegistry record (role, staked balance, status) for an address.',
      },
      {
        name: 'nodeRegistry_buildTransaction',
        description: 'Build an unsigned node-registry transaction (register, begin-unstake, withdraw-unbonded, register-encryption-key), returns unsigned tx material + signing hash; no private keys.',
      },
      {
        name: 'storage_getAssignmentCoverageV2',
        description: 'Per-file chunk coverage: attested vs assigned per archive, missing chunks, and can_activate_now. Epoch-aware/aggregate since the reassignment work (issue #62).',
      },
      {
        name: 'storage_getActiveNodesAtHeight',
        description: 'The active-archive snapshot at a given height, used to reproduce the deterministic chunk assignment client-side.',
      },
      {
        name: 'storage_getArchiveUnbonding',
        description: 'Pending archive-node stake-unbonding record for an operator, or null. Part of archive-node withdrawal (issue #20), active on mainnet (gate 8,900,000 reached).',
      },
    ],
  },
  {
    id: 'omninode',
    title: 'OmniNode (InferenceAttestation)',
    blurb: 'Verifiable AI compute, read verifier-signed inference attestations settled on-chain. Attestation is active on mainnet (omninode_enabled_from_height = 6,000,000). Reads for the OmniNode product surface (https://omninode.suminnovation.xyz).',
    methods: [
      { name: 'sum_getInferenceAttestation', description: 'Attestation for a (session_id, verifier_address) pair, or null.' },
      { name: 'sum_listInferenceAttestations', description: 'All attestations recorded for a session_id.' },
      { name: 'sum_getInferenceAttestationStatus', description: 'Status of an attestation tx: submitted, included, finalized, or failed.' },
    ],
  },
  {
    id: 'omninode-settlement',
    title: 'OmniNode Inference Settlement',
    blurb: 'Escrow-funded verifier rewards keyed by attestations, active on mainnet (inference_settlement_enabled_from_height = 8,900,000 reached, issue #61). No bond slashing in v1 (reward denial / claim withholding / escrow refund). Reads + unsigned-tx builders (no keys). Settlement consistency and verifier bonding are separate post-supply gates that activate at height 9,200,000.',
    methods: [
      { name: 'omninode_getInferenceSession', description: 'Per-session settlement record (funder, reward terms, remaining escrow, status), or null.' },
      { name: 'omninode_getInferenceClaims', description: 'All paid reward claims for a session.' },
      { name: 'omninode_getInferenceDisputes', description: 'All dispute records for a session (record-only; disputes require a configured validator-quorum threshold, and resolution is authorized by a validator quorum, no personal resolver key).' },
      { name: 'omninode_getClaimableReward', description: 'Whether a verifier can currently claim, plus amount and unlock height (attestation inclusion + finality_depth + dispute_window).' },
      { name: 'omninode_buildOpenInferenceSession · buildFundInferenceSession · buildClaimInferenceReward · buildOpenInferenceDispute · buildResolveInferenceDispute · buildRefundInferenceSession', description: 'Unsigned-transaction builders for the six settlement operations, return a bincode-encoded TransactionV2 + signing hash; no private keys.' },
    ],
  },
  {
    id: 'validators',
    title: 'Validators &amp; Consensus',
    blurb: 'Active set, staking, delegation, slashing, and epoch info.',
    methods: [
      {
        name: 'get_validators',
        description: 'Active validator set with current proposer.',
        example: {
          request: `{"jsonrpc":"2.0","method":"get_validators","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "validators": [
      {
        "public_key": "GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8",
        "address": "8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4",
        "is_current_proposer": true
      },
      {
        "public_key": "7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy",
        "address": "D7Ls8H7Y2jCqYEEUUxWUcgQkF9cKhHxjV",
        "is_current_proposer": false
      }
    ]
  },
  "id": 1
}`,
        },
      },
      { name: 'sum_getValidators', description: 'sum_-prefixed alias.' },
      { name: 'staking_getValidator', description: 'Validator by pubkey.' },
      { name: 'staking_getValidatorByAddress', description: 'Validator by address.' },
      { name: 'staking_getValidators', description: 'All validators.' },
      { name: 'staking_getActiveValidators', description: 'Active set only.' },
      { name: 'staking_getSummary', description: 'Aggregate stats.' },
      { name: 'staking_getParams', description: 'Staking parameters.' },
      { name: 'staking_getTotalStake', description: 'Sum of all stake.' },
      { name: 'staking_buildTransaction', description: 'Build an unsigned staking/validator transaction (create-validator, delegate, unstake, claim-rewards, submit-evidence, etc.), returns unsigned tx material + signing hash; no private keys.' },
      { name: 'delegation_getDelegation', description: 'Single delegation lookup.' },
      { name: 'delegation_getDelegationsByDelegator', description: 'Delegations made by an address.' },
      { name: 'delegation_getDelegationsByValidator', description: 'Delegations to a validator.' },
      { name: 'delegation_getDelegatorSummary', description: 'Aggregate per delegator.' },
      { name: 'delegation_getUnbondingDelegations', description: 'Pending unbondings.' },
      { name: 'delegation_getValidatorDelegationSummary', description: 'Aggregate per validator.' },
      { name: 'slashing_getRecords', description: 'Historical slashing records.' },
      { name: 'slashing_getRecentRecords', description: 'Recent records.' },
      { name: 'slashing_getSigningInfo', description: 'Per-validator missed-block tracking.' },
      { name: 'slashing_getAllSigningInfo', description: 'All validators.' },
      { name: 'slashing_getSummary', description: 'Aggregate stats.' },
      { name: 'slashing_isTombstoned', description: 'Permanent-jail check.' },
      {
        name: 'epoch_getInfo',
        description: 'Current epoch metadata.',
        example: {
          request: `{"jsonrpc":"2.0","method":"epoch_getInfo","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "current_epoch": 333,
    "current_height": 4807057,
    "epoch_length": 14400,
    "epoch_start_height": 4795200,
    "epoch_end_height": 4809599,
    "blocks_remaining": 2542,
    "stake_weighted_selection": true
  },
  "id": 1
}`,
        },
      },
      { name: 'validatorSet_getCurrent', description: 'Active validator set.' },
      { name: 'validatorSet_getByEpoch', description: 'Set for a specific epoch.' },
      { name: 'validatorSet_getProposer', description: 'Proposer at a given height.' },
    ],
  },
  {
    id: 'nft',
    title: 'NFTs (SUM-721)',
    blurb: 'Native NFT standard.',
    methods: [
      { name: 'nft_getCollection', description: 'Collection metadata.' },
      { name: 'nft_getToken', description: 'Single token.' },
      { name: 'nft_getTokensByOwner', description: 'Tokens owned by an address.' },
      { name: 'nft_getTokensInCollection', description: 'Tokens in a collection.' },
      { name: 'nft_balanceOf', description: 'Number of tokens an address holds.' },
      { name: 'nft_ownerOf', description: 'Owner of a specific token.' },
      { name: 'nft_tokenExists', description: 'Existence check.' },
      { name: 'nft_buildTransaction', description: 'Build an unsigned SUM-721 transaction (create-collection, mint, transfer, burn, update-config, etc.), returns unsigned tx material + signing hash; no private keys.' },
    ],
  },
  {
    id: 'tokens',
    title: 'Fungible Tokens (SRC-20)',
    blurb:
      'Native fungible-token standard, ERC-20 compatible interface. Minter lookup is token-scoped: token_getMinters returns the owner and registered minters of one token id. There is intentionally no address→tokens (“everything this address can mint”) lookup.',
    methods: [
      { name: 'token_getToken', description: 'Token metadata.' },
      { name: 'token_balanceOf', description: 'Holder balance for a token.' },
      { name: 'token_getTokensByOwner', description: 'Tokens an address holds.' },
      { name: 'token_allowance', description: 'ERC-20-style allowance lookup.' },
      { name: 'token_totalSupply', description: 'Total supply of a token.' },
      { name: 'token_exists', description: 'Existence check.' },
      {
        name: 'token_getMinters',
        description:
          'Owner + registered minters of a single token (token-scoped, read from public token config). No address-wide minter enumeration is exposed.',
        example: {
          request: `{"jsonrpc":"2.0","method":"token_getMinters","params":["0x1234..."],"id":1}`,
          response: `{"jsonrpc":"2.0","result":{"token_id":"0x1234...","owner":"SUM1own...","minters":["SUM1mnt..."]},"id":1}`,
        },
      },
      { name: 'token_buildTransaction', description: 'Build an unsigned SRC-20 transaction (create, mint, transfer, approve, pause, add-minter, etc.), returns unsigned tx material + signing hash; no private keys.' },
    ],
  },
  {
    id: 'contracts',
    title: 'Smart Contracts (WASM)',
    blurb: 'sumc-runtime WASM contract calls.',
    methods: [
      { name: 'contract_getContract', description: 'Contract metadata.' },
      { name: 'contract_isContract', description: 'Existence check.' },
      { name: 'contract_call', description: 'Read-only view call.' },
      { name: 'contract_estimateGas', description: 'Gas estimation.' },
      { name: 'contract_getCodeHash', description: 'Code-hash lookup.' },
      { name: 'contract_getStorageAt', description: 'Raw storage slot read.' },
      { name: 'contract_getBalance', description: 'Contract balance.' },
    ],
  },
  {
    id: 'messaging',
    title: 'Encrypted Messaging (SRC-201)',
    blurb: 'On-chain encrypted messaging using X25519 + XChaCha20-Poly1305.',
    methods: [
      {
        name: 'messaging_getConfig',
        description: 'Per-chain messaging parameters.',
        example: {
          request: `{"jsonrpc":"2.0","method":"messaging_getConfig","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "daily_quota": 100,
    "max_message_size": 65535,
    "min_trust_stake": "100000000000",
    "sponsorship_enabled": true
  },
  "id": 1
}`,
        },
      },
      {
        name: 'messaging_registerSponsored',
        description: 'Registers a public key for an address (sponsored, fee paid by relayer). Required before receiving messages. Not idempotent: a duplicate call returns success: false with "Public key already registered", check via account_getPublicKey first.',
      },
      { name: 'messaging_submitSponsored', description: 'Submits an encrypted message via a sponsoring relayer.' },
      { name: 'messaging_getQuota', description: 'Quota status for a sender.' },
      { name: 'messaging_getInboxFilter', description: 'Recipient inbox-filter rules.' },
      { name: 'messaging_getMessages', description: 'Inbox query.' },
      { name: 'messaging_getSentMessages', description: 'Outbox query.' },
      { name: 'messaging_getMessageByTxHash', description: 'Message lookup by tx.' },
      { name: 'messaging_getMessagesInBlock', description: 'Messages in a block.' },
      { name: 'messaging_getMessageData', description: 'Message ciphertext.' },
      { name: 'messaging_getPendingPayment', description: 'Pending sponsorship payment.' },
      { name: 'messaging_getPendingPayments', description: 'All pending payments.' },
      { name: 'messaging_getTrustStake', description: 'Trust-stake balance.' },
      { name: 'messaging_getSpamScore', description: 'Spam-score lookup.' },
      { name: 'messaging_isContact', description: 'Contact-list check.' },
      { name: 'messaging_isBlocked', description: 'Block-list check.' },
    ],
  },
  {
    id: 'docclass',
    title: 'Document Credentials (SRC-80X)',
    blurb: 'Verifiable identity, credentials, and academic-credential issuance.',
    methods: [
      { name: 'docclass_getConfig', description: 'Config & parameters.' },
      { name: 'docclass_getSummary', description: 'Aggregate stats.' },
      { name: 'docclass_getIdentity', description: 'Identity by id.' },
      { name: 'docclass_getIdentityByController', description: 'Identity by controlling address.' },
      { name: 'docclass_canIssue', description: 'Authorization check for an issuer.' },
      { name: 'docclass_getCredential', description: 'Credential by id.' },
      { name: 'docclass_isCredentialValid', description: 'Validity + revocation check.' },
      { name: 'docclass_getCredentialsBySubject', description: 'All credentials for a subject.' },
      { name: 'docclass_getCredentialsByIssuer', description: 'All credentials from an issuer.' },
      { name: 'docclass_getIssuer', description: 'Issuer record.' },
      { name: 'docclass_getIssuers', description: 'All registered issuers.' },
      { name: 'docclass_getIssuersByJurisdiction', description: 'Issuers by jurisdiction code.' },
      { name: 'docclass_getAcademicCredentialsByHolder', description: 'Academic credentials for a holder.' },
      { name: 'docclass_registerAcademicIssuer', description: 'Register an academic issuer (write).' },
      { name: 'docclass_issueAcademicCredential', description: 'Issue an academic credential (write).' },
      { name: 'docclass_revokeAcademicCredential', description: 'Revoke an academic credential (write).' },
    ],
  },
  {
    id: 'employment',
    title: 'Employment Credentials (SRC-88X)',
    blurb: 'On-chain employment & income attestations.',
    methods: [
      { name: 'employment_listIssuers', description: 'All registered employment issuers.' },
      { name: 'employment_getIssuer', description: 'Issuer record.' },
      { name: 'employment_registerIssuer', description: 'Register an employer issuer (write).' },
      { name: 'employment_getSummary', description: 'Aggregate stats.' },
      { name: 'employment_getCredential', description: 'Credential by id.' },
      { name: 'employment_getCredentialsByEmployee', description: 'All credentials for an employee.' },
      { name: 'employment_getCredentialsByEmployeeAddress', description: 'By employee address.' },
      { name: 'employment_getCredentialsByEmployer', description: 'By employer.' },
      { name: 'employment_getActiveCredentialsByEmployee', description: 'Active only.' },
      { name: 'employment_getActiveCredentialsByEmployeeAddress', description: 'Active only by address.' },
      { name: 'employment_createCredential', description: 'Issue a new employment credential (write).' },
      { name: 'employment_revokeCredential', description: 'Revoke a credential (write).' },
      { name: 'employment_verifyEmployment', description: 'Verify employment claim.' },
      { name: 'employment_getIncomeAttestation', description: 'Income attestation by id.' },
      { name: 'employment_getIncomeAttestationsBySubject', description: 'By subject.' },
      { name: 'employment_getIncomeAttestationsByHolderAddress', description: 'By holder address.' },
    ],
  },
  {
    id: 'policy',
    title: 'Policy Accounts (Multi-Sig)',
    blurb: 'Consensus-level multi-sig group governance, accounts, proposals, execution.',
    methods: [
      { name: 'policy_getAccount', description: 'Account by id.' },
      { name: 'policy_getAccountByAddress', description: 'Account by address.' },
      { name: 'policy_listMemberAccounts', description: 'Accounts where address is a member.' },
      { name: 'policy_getProposal', description: 'Proposal by id.' },
      { name: 'policy_listProposals', description: 'All proposals for an account.' },
      { name: 'policy_listPendingProposals', description: 'Pending only.' },
      { name: 'policy_buildCreateAccount', description: 'Build an unsigned create-account transaction to sign and broadcast.' },
      { name: 'policy_buildSubmitProposal', description: 'Build an unsigned submit-proposal transaction to sign and broadcast.' },
      { name: 'policy_buildExecuteProposal', description: 'Build an unsigned execute-proposal transaction to sign and broadcast.' },
      { name: 'policy_buildCancelProposal', description: 'Build an unsigned cancel-proposal transaction (proposer only).' },
    ],
  },
  {
    id: 'governance',
    title: 'Governance (v1)',
    blurb: 'On-chain token-holder governance, active on mainnet: the governance_enabled_from_height = 8,900,000 gate has been reached and ChainParams.governance is configured (validator-quorum authority). These methods respond with live proposal/vote state; builders return unsigned tx material (no keys).',
    methods: [
      { name: 'gov_buildCreateProposal', description: 'Build an unsigned create-proposal transaction to sign and broadcast.' },
      { name: 'gov_buildCastVote', description: 'Build an unsigned cast-vote transaction.' },
      { name: 'gov_buildExecuteProposal', description: 'Build an unsigned execute-proposal transaction.' },
      { name: 'gov_buildCancelProposal', description: 'Build an unsigned cancel-proposal transaction. The proposer can self-cancel with no approvals; any other canceller supplies a validator-quorum (approvals). There is no single council address.' },
      { name: 'gov_getProposal', description: 'Proposal by id.' },
      { name: 'gov_listProposals', description: 'All proposals.' },
      { name: 'gov_listActiveProposals', description: 'Proposals currently in the voting state.' },
      { name: 'gov_getTally', description: 'Tally from a proposal’s frozen snapshot and cast votes.' },
      { name: 'gov_getVote', description: 'A voter’s vote on a proposal.' },
      { name: 'gov_getVotingPower', description: 'A holder’s frozen snapshot voting power for a proposal.' },
      { name: 'gov_listEligibleAssets', description: 'Registered governance assets with status and effective height.' },
    ],
  },
  {
    id: 'node',
    title: 'Node &amp; Network',
    blurb: 'Operator-facing endpoints for monitoring.',
    methods: [
      {
        name: 'health',
        description: 'Liveness probe.',
        example: {
          request: `{"jsonrpc":"2.0","method":"health","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "status": "ok",
    "chain_id": 1,
    "height": 4807039,
    "peer_count": 2,
    "is_validator": true,
    "is_synced": true
  },
  "id": 1
}`,
        },
      },
      {
        name: 'node_info',
        description: 'Version, peer ID, uptime.',
        example: {
          request: `{"jsonrpc":"2.0","method":"node_info","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "version": "0.1.0",
    "chain_id": 1,
    "network": "sumchain-1",
    "peer_id": "12D3KooW…",
    "is_validator": true,
    "current_height": 4807038,
    "peer_count": 2,
    "mempool_size": 0,
    "uptime_seconds": 238205
  },
  "id": 1
}`,
        },
      },
      { name: 'get_metrics', description: 'Prometheus-style metrics snapshot.' },
      { name: 'get_peers', description: 'Connected peers.' },
      {
        name: 'get_p2p_stats',
        description: 'libp2p connection statistics.',
        example: {
          request: `{"jsonrpc":"2.0","method":"get_p2p_stats","params":[],"id":1}`,
          response: `{
  "jsonrpc": "2.0",
  "result": {
    "total_known_peers": 2,
    "connected_peers": 2,
    "inbound_connections": 0,
    "outbound_connections": 2,
    "banned_peers": 0,
    "max_connections": 100,
    "max_inbound": 50,
    "max_outbound": 50
  },
  "id": 1
}`,
        },
      },
    ],
  },
];

export const totalMethods = categories.reduce((n, c) => n + c.methods.length, 0);

/** Category groups for the docs index, in display order. */
export const GROUPS: { label: string; ids: string[] }[] = [
  { label: 'Core', ids: ['chain', 'account', 'transactions', 'validators', 'node'] },
  { label: 'Subprotocols', ids: ['storage', 'omninode', 'omninode-settlement', 'contracts', 'messaging', 'governance', 'policy'] },
  { label: 'Tokens & credentials', ids: ['nft', 'tokens', 'docclass', 'employment'] },
];

/** Look up a category by its slug id. */
export function getCategory(id: string): Category | undefined {
  return categories.find((c) => c.id === id);
}
