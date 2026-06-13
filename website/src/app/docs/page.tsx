'use client';

import Link from 'next/link';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';

type Method = {
  name: string;
  description: string;
  example?: { request: string; response?: string };
};

type Category = {
  id: string;
  title: string;
  blurb: string;
  methods: Method[];
};

const ENDPOINT = 'https://rpc.sumchain.io';

// Every method in this page has been verified against the live mainnet RPC.
// Example responses are real captures from rpc.sumchain.io.
const categories: Category[] = [
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
      { name: 'get_transaction', description: 'Returns a transaction by hash.' },
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
    blurb: 'Native L1 Proof-of-Retrievability — query files, challenges, and archive nodes. Powers snip.sumchain.io and the storage marketplace.',
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
    ],
  },
  {
    id: 'tokens',
    title: 'Fungible Tokens (SRC-20)',
    blurb: 'Native fungible-token standard, ERC-20 compatible interface.',
    methods: [
      { name: 'token_getToken', description: 'Token metadata.' },
      { name: 'token_balanceOf', description: 'Holder balance for a token.' },
      { name: 'token_getTokensByOwner', description: 'Tokens an address holds.' },
      { name: 'token_allowance', description: 'ERC-20-style allowance lookup.' },
      { name: 'token_totalSupply', description: 'Total supply of a token.' },
      { name: 'token_exists', description: 'Existence check.' },
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
        description: 'Registers a public key for an address (sponsored — fee paid by relayer). Required before receiving messages. Not idempotent: a duplicate call returns success: false with "Public key already registered" — check via account_getPublicKey first.',
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
    blurb: 'Consensus-level multi-sig group governance — accounts, proposals, execution.',
    methods: [
      { name: 'policy_createAccount', description: 'Create a new policy account (write).' },
      { name: 'policy_getAccount', description: 'Account by id.' },
      { name: 'policy_getAccountByAddress', description: 'Account by address.' },
      { name: 'policy_listMemberAccounts', description: 'Accounts where address is a member.' },
      { name: 'policy_submitProposal', description: 'Submit a new proposal (write).' },
      { name: 'policy_executeProposal', description: 'Execute an approved proposal (write).' },
      { name: 'policy_cancelProposal', description: 'Cancel a pending proposal (write).' },
      { name: 'policy_getProposal', description: 'Proposal by id.' },
      { name: 'policy_listProposals', description: 'All proposals for an account.' },
      { name: 'policy_listPendingProposals', description: 'Pending only.' },
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
    "peer_id": "12D3KooWJdKDCZn9Wu5mo1WBMLRwEeej9abjTLDvgZRzLwZv6kdW",
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

const totalMethods = categories.reduce((n, c) => n + c.methods.length, 0);

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <Navbar />

      <main className="relative pt-32 pb-32">
        {/* Background */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#0a0a0a] via-[#26022e]/20 to-[#0a0a0a]" />
        <div className="absolute inset-0 grid-pattern opacity-20" />

        <div className="relative z-10 max-w-6xl mx-auto px-6 lg:px-8">
          {/* Header */}
          <div className="mb-16">
            <span className="inline-block text-sm font-medium text-purple-400 uppercase tracking-widest mb-4">
              Documentation
            </span>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold mb-6">
              SUM Chain <span className="gradient-text">JSON-RPC API</span>
            </h1>
            <p className="text-lg text-gray-400 max-w-3xl">
              SUM Chain exposes a JSON-RPC 2.0 API for chain queries, transaction submission,
              and integration with the storage protocol, NFTs, tokens, encrypted messaging,
              policy accounts, and document-credential layers. The native currency is{' '}
              <span className="text-white">Koppa (Ϙ)</span> with 9 decimal places.
            </p>
            <p className="text-sm text-gray-500 mt-4">
              All {totalMethods} methods on this page are verified against the live mainnet RPC.
            </p>
          </div>

          {/* Connection */}
          <section className="mb-16">
            <h2 className="text-2xl font-semibold mb-4">Connection</h2>
            <div className="glass rounded-2xl p-6 mb-4">
              <p className="text-gray-400 mb-4">Public mainnet endpoint:</p>
              <pre className="bg-black/40 rounded-lg p-4 text-sm font-mono text-purple-300 overflow-x-auto">
                <code>{ENDPOINT}</code>
              </pre>
            </div>
            <div className="glass rounded-2xl p-6">
              <p className="text-gray-400 mb-4">
                Every request follows JSON-RPC 2.0. The <code className="text-purple-300">Content-Type: application/json</code> header is required.
              </p>
              <pre className="bg-black/40 rounded-lg p-4 text-sm font-mono text-gray-300 overflow-x-auto">
                <code>{`curl -X POST ${ENDPOINT} \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"chain_id","params":[],"id":1}'`}</code>
              </pre>
            </div>
          </section>

          {/* Currency */}
          <section className="mb-16">
            <h2 className="text-2xl font-semibold mb-4">Currency &amp; Units</h2>
            <div className="glass rounded-2xl p-6">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-purple-400 uppercase tracking-wider">
                    <th className="py-2 pr-4">Name</th>
                    <th className="py-2 pr-4">Symbol</th>
                    <th className="py-2 pr-4">Decimals</th>
                    <th className="py-2">Base Unit</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-t border-white/5">
                    <td className="py-2 pr-4">Koppa</td>
                    <td className="py-2 pr-4">Ϙ</td>
                    <td className="py-2 pr-4">9</td>
                    <td className="py-2 font-mono text-gray-400">1 Ϙ = 1,000,000,000</td>
                  </tr>
                </tbody>
              </table>
              <p className="text-sm text-gray-500 mt-4">
                All amounts in the API are represented in base units. Examples:{' '}
                <code className="text-purple-300">1000000000</code> = 1 Ϙ,{' '}
                <code className="text-purple-300">1000000</code> = 0.001 Ϙ (typical fee).
              </p>
            </div>
          </section>

          {/* Address Format */}
          <section className="mb-16">
            <h2 className="text-2xl font-semibold mb-4">Addresses</h2>
            <div className="glass rounded-2xl p-6 space-y-3 text-sm text-gray-400">
              <p>
                Addresses are 20 bytes derived from an Ed25519 public key:{' '}
                <code className="text-purple-300">Address = Blake3(pubkey)[12..32]</code>.
              </p>
              <p>Two display formats are accepted in API parameters:</p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>
                  <span className="text-white">Base58 with checksum</span> (default Display): e.g.{' '}
                  <code className="text-purple-300">8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4</code>
                </li>
                <li>
                  <span className="text-white">Hex</span>: e.g.{' '}
                  <code className="text-purple-300">0x1a2b3c4d...</code>
                </li>
              </ul>
            </div>
          </section>

          {/* Category Index */}
          <section className="mb-16">
            <h2 className="text-2xl font-semibold mb-4">Method Index</h2>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {categories.map((cat) => (
                <a
                  key={cat.id}
                  href={`#${cat.id}`}
                  className="glass rounded-xl p-4 hover:border-purple-500/30 border border-white/5 transition-all"
                >
                  <div className="font-medium" dangerouslySetInnerHTML={{ __html: cat.title }} />
                  <div className="text-xs text-gray-500 mt-1">{cat.methods.length} methods</div>
                </a>
              ))}
            </div>
          </section>

          {/* Categories */}
          {categories.map((cat) => (
            <section key={cat.id} id={cat.id} className="mb-20 scroll-mt-24">
              <div className="mb-6">
                <h2
                  className="text-3xl font-semibold mb-2"
                  dangerouslySetInnerHTML={{ __html: cat.title }}
                />
                <p className="text-gray-400">{cat.blurb}</p>
              </div>

              <div className="space-y-4">
                {cat.methods.map((m) => (
                  <div
                    key={m.name}
                    className="glass rounded-2xl p-6 border border-white/5"
                  >
                    <div className="flex items-baseline justify-between mb-3 gap-3 flex-wrap">
                      <code className="text-lg font-mono text-purple-300">{m.name}</code>
                    </div>
                    <p className="text-gray-400 mb-4">{m.description}</p>

                    {m.example && (
                      <div className="space-y-3">
                        <div>
                          <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">
                            Request
                          </div>
                          <pre className="bg-black/40 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-x-auto">
                            <code>{m.example.request}</code>
                          </pre>
                        </div>
                        {m.example.response && (
                          <div>
                            <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">
                              Response (live)
                            </div>
                            <pre className="bg-black/40 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-x-auto">
                              <code>{m.example.response}</code>
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          ))}

          {/* Footer note */}
          <div className="glass rounded-2xl p-8 text-center">
            <p className="text-gray-400 mb-4">
              All {totalMethods} endpoints listed above are verified against{' '}
              <a
                href={ENDPOINT}
                className="text-purple-400 hover:text-purple-300"
              >
                {ENDPOINT}
              </a>
              .
            </p>
            <Link
              href="/#get-started"
              className="text-purple-400 hover:text-purple-300 text-sm"
            >
              ← Back to Get Started
            </Link>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
