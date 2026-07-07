import { Provider } from '../provider';
import type { TxBuildResponse } from '../types';

// Mock fetch so we can assert the JSON-RPC method/params each builder sends and
// return a canned TxBuildResponse. No network, no keys.
const RESP: TxBuildResponse = {
  unsigned_tx: '0xdeadbeef',
  signing_hash: '0xabc123',
  from: 'SUMsender',
  nonce: 7,
  fee: 1000,
  chain_id: 1,
};

let lastBody: any;

beforeEach(() => {
  lastBody = undefined;
  (global as any).fetch = jest.fn(async (_url: string, init: any) => {
    lastBody = JSON.parse(init.body);
    return {
      ok: true,
      json: async () => ({ jsonrpc: '2.0', id: lastBody.id, result: RESP }),
    } as any;
  });
});

const provider = new Provider('http://localhost:8545');

describe('no-key builders (issue #89) — method + params + shape', () => {
  it('buildTokenTransaction sends token_buildTransaction with the request as the single param', async () => {
    const req = { from: 'SUMowner', token_id: '0x' + '11'.repeat(32), op: 'mint' as const, to: 'SUMrecip', amount: 500 };
    const out = await provider.buildTokenTransaction(req);
    expect(lastBody.method).toBe('token_buildTransaction');
    expect(lastBody.params).toEqual([req]);
    expect(out).toEqual(RESP);
    // Builder returns unsigned material only — no key/signature fields.
    expect(out).not.toHaveProperty('signature');
    expect(out).not.toHaveProperty('private_key');
  });

  it('buildNftTransaction sends nft_buildTransaction', async () => {
    const req = { from: 'SUMowner', collection_id: '0x' + '22'.repeat(32), token_id: 0, op: 'transfer' as const, to: 'SUMto' };
    const out = await provider.buildNftTransaction(req);
    expect(lastBody.method).toBe('nft_buildTransaction');
    expect(lastBody.params).toEqual([req]);
    expect(out.unsigned_tx).toBe('0xdeadbeef');
    expect(out.signing_hash).toBe('0xabc123');
  });

  it('buildStakingTransaction sends staking_buildTransaction', async () => {
    const req = { from: 'SUMval', op: 'delegate' as const, validator_pubkey: '0x' + '33'.repeat(32), amount: 1000 };
    const out = await provider.buildStakingTransaction(req);
    expect(lastBody.method).toBe('staking_buildTransaction');
    expect(lastBody.params).toEqual([req]);
    expect(out).toEqual(RESP);
  });

  it('buildNodeRegistryTransaction sends nodeRegistry_buildTransaction', async () => {
    const req = { from: 'SUMop', op: 'register' as const, role: 'archive_node' as const, stake: 1_000_000 };
    const out = await provider.buildNodeRegistryTransaction(req);
    expect(lastBody.method).toBe('nodeRegistry_buildTransaction');
    expect(lastBody.params).toEqual([req]);
    expect(out).toEqual(RESP);
  });

  it('propagates RPC errors (e.g. executor-authoritative validation is server-side)', async () => {
    (global as any).fetch = jest.fn(async () => ({
      ok: true,
      json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'invalid merkle_root' } }),
    }));
    await expect(
      provider.buildTokenTransaction({ from: 'x', op: 'burn', amount: 1 }),
    ).rejects.toThrow(/RPC error/);
  });
});
