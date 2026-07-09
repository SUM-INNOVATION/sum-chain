import { Provider } from '../provider';
import type { SupplyInfo, ProtocolReserveInfo } from '../types';

// Mock fetch to assert the JSON-RPC method/params and return canned responses.
// No network, no keys. 800B supply correction read surface.
const SUPPLY: SupplyInfo = {
  initial_canonical_supply: '800000000000000000000',
  current_canonical_supply: '800000000000000000000',
  accounted_account_supply: '1000000000000000000',
  burned_supply: '0',
  protocol_reserve_remaining: '799000000000000000000',
  outstanding_grant_unclaimed: '0',
  total_minted_by_migration: '799000000000000000000',
  total_minted_by_governance: '0',
  migration_id: '0x00a88daf2062e610b09b379b74aa6bc5a9557eb145618f46e9571428a4584a8f',
  migration_applied: true,
  migration_activation_height: 8900000,
  automatic_emissions_enabled: false,
};

const RESERVE: ProtocolReserveInfo = {
  validator_pool_remaining: '80000000000000000000',
  archive_pool_remaining: '120000000000000000000',
  compute_pool_remaining: '120000000000000000000',
  ecosystem_pool_remaining: '160000000000000000000',
  governance_reserve_remaining: '319000000000000000000',
  total_remaining: '799000000000000000000',
};

let lastBody: any;

function mockResult(result: unknown) {
  (global as any).fetch = jest.fn(async (_url: string, init: any) => {
    lastBody = JSON.parse(init.body);
    return {
      ok: true,
      json: async () => ({ jsonrpc: '2.0', id: lastBody.id, result }),
    } as any;
  });
}

const provider = new Provider('http://localhost:8545');

describe('supply read surface (800B correction)', () => {
  it('getSupplyInfo calls chain_getSupplyInfo with no params', async () => {
    mockResult(SUPPLY);
    const out = await provider.getSupplyInfo();
    expect(lastBody.method).toBe('chain_getSupplyInfo');
    expect(lastBody.params).toEqual([]);
    expect(out).toEqual(SUPPLY);
    // Monetary honesty invariants surfaced by the type.
    expect(out.automatic_emissions_enabled).toBe(false);
    expect(out.accounted_account_supply).toBe('1000000000000000000');
  });

  it('getProtocolReserve calls chain_getProtocolReserve and supports null', async () => {
    mockResult(RESERVE);
    const out = await provider.getProtocolReserve();
    expect(lastBody.method).toBe('chain_getProtocolReserve');
    expect(out).toEqual(RESERVE);

    mockResult(null);
    const pending = await provider.getProtocolReserve();
    expect(pending).toBeNull();
  });
});
