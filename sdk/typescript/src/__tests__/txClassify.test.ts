import { classifyTransaction, humanAction, minterRole } from '../txClassify';
import type { TokenMintersInfo } from '../types';

describe('classifyTransaction — domain mapping', () => {
  const cases: Array<[string | undefined, string]> = [
    ['Transfer', 'native'],
    ['Token', 'token'],
    ['Nft', 'token'],
    ['StorageMetadataV2', 'snip'],
    ['NodeRegistry', 'snip'],
    ['InferenceAttestation', 'omninode'],
    ['InferenceSettlement', 'omninode'],
    ['Governance', 'governance'],
    ['PolicyAccount', 'policy'],
    ['Messaging', 'messaging'],
    ['Tax', 'other'],
    ['Education', 'other'],
    [undefined, 'other'],
    ['SomeFutureType', 'other'],
  ];
  it.each(cases)('tx_type %s → domain %s', (tx_type, domain) => {
    expect(classifyTransaction({ tx_type }).domain).toBe(domain);
  });
});

describe('classifyTransaction — action labels', () => {
  it('labels a native transfer', () => {
    expect(classifyTransaction({ tx_type: 'Transfer' }).action).toBe('Koppa transfer');
  });

  it('labels a token mint and passes through asset ref/kind', () => {
    const c = classifyTransaction({
      tx_type: 'Token',
      action: 'Mint',
      asset_ref: 'ab'.repeat(32),
      asset_kind: 'src20',
    });
    expect(c.domain).toBe('token');
    expect(c.domainLabel).toBe('Token');
    expect(c.action).toBe('Token mint');
    expect(c.assetRef).toBe('ab'.repeat(32));
    expect(c.assetKind).toBe('src20');
  });

  it('labels SNIP storage and archive ops', () => {
    expect(
      classifyTransaction({ tx_type: 'StorageMetadataV2', action: 'RegisterFilePendingV2' }).action,
    ).toBe('SNIP file registration');
    expect(
      classifyTransaction({ tx_type: 'StorageMetadataV2', action: 'ReassignChunksV2' }).action,
    ).toBe('SNIP archive reassignment');
    expect(classifyTransaction({ tx_type: 'NodeRegistry', action: 'BeginUnstake' }).action).toBe(
      'Archive-node unbonding',
    );
  });

  it('labels OmniNode and governance actions', () => {
    expect(classifyTransaction({ tx_type: 'InferenceAttestation' }).action).toBe(
      'OmniNode inference attestation',
    );
    expect(
      classifyTransaction({ tx_type: 'InferenceSettlement', action: 'ClaimReward' }).action,
    ).toBe('OmniNode settlement claim');
    expect(classifyTransaction({ tx_type: 'Governance', action: 'CastVote' }).action).toBe(
      'Governance vote',
    );
  });

  it('falls back to a coarse type label for unmapped actions', () => {
    // Unknown action under a known type → coarse-but-true type fallback.
    expect(humanAction('Governance', 'SomeNewGovOp')).toBe('Governance transaction');
    expect(humanAction('Tax', 'IssueClaim')).toBe('Tax record transaction');
  });

  it('does not invent document subtypes it cannot prove', () => {
    // DocClass issuance must NOT claim "diploma"/"transcript" (subcode not surfaced).
    const label = humanAction('DocClass', 'IssueCredential');
    expect(label).toBe('Document credential transaction');
    expect(label.toLowerCase()).not.toContain('diploma');
    expect(label.toLowerCase()).not.toContain('transcript');
  });

  it('returns Unknown transaction when type is absent', () => {
    expect(classifyTransaction({}).action).toBe('Unknown transaction');
    expect(humanAction(undefined)).toBe('Unknown transaction');
  });
});

describe('minterRole — token-scoped', () => {
  const info: TokenMintersInfo = {
    token_id: '0x' + '11'.repeat(32),
    owner: 'SUMowner',
    minters: ['SUMminter1', 'SUMminter2'],
  };

  it('labels the owner as owner', () => {
    const r = minterRole(info, 'SUMowner', 'ACME');
    expect(r.isOwner).toBe(true);
    expect(r.isMinter).toBe(true);
    expect(r.label).toBe('ACME owner');
  });

  it('labels an explicit minter as minter', () => {
    const r = minterRole(info, 'SUMminter1');
    expect(r.isOwner).toBe(false);
    expect(r.isMinter).toBe(true);
    expect(r.label).toBe('Token minter');
  });

  it('returns no label for a non-minter', () => {
    const r = minterRole(info, 'SUMrandom');
    expect(r.isOwner).toBe(false);
    expect(r.isMinter).toBe(false);
    expect(r.label).toBeNull();
  });
});
