import { Provider } from '../provider';
import type { AddressLabelsInfo } from '../types';

// Mock fetch to assert the JSON-RPC method/params and return a canned response.
// No network, no keys. Issue #64.
const RESP: AddressLabelsInfo = {
  address: 'SUMinstitute',
  primary_label: 'SUM Hypothesis Institute',
  labels: [
    { label: 'SUM Hypothesis Institute', kind: 'institution', source: 'DocClassIssuer', status: 'Active' },
    { label: 'Tax Authority', kind: 'role', source: 'TaxIssuer', status: 'Active' },
  ],
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

describe('resolveAddressLabels (issue #64)', () => {
  it('calls sum_resolveAddressLabels with the address as the single param', async () => {
    const out = await provider.resolveAddressLabels('SUMinstitute');
    expect(lastBody.method).toBe('sum_resolveAddressLabels');
    expect(lastBody.params).toEqual(['SUMinstitute']);
    expect(out).toEqual(RESP);
  });

  it('returns the typed shape (address + primary_label + labels)', async () => {
    const out = await provider.resolveAddressLabels('SUMinstitute');
    expect(out.address).toBe('SUMinstitute');
    expect(out.primary_label).toBe('SUM Hypothesis Institute');
    expect(out.labels).toHaveLength(2);
    expect(out.labels[0].kind).toBe('institution');
    expect(out.labels[1].kind).toBe('role');
    // Read-only label surface — never any key material.
    expect(out).not.toHaveProperty('private_key');
    expect(out).not.toHaveProperty('mnemonic');
  });

  it('supports the null-primary / empty-labels case', async () => {
    const EMPTY: AddressLabelsInfo = { address: 'SUMnobody', primary_label: null, labels: [] };
    (global as any).fetch = jest.fn(async (_url: string, init: any) => {
      const body = JSON.parse(init.body);
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: body.id, result: EMPTY }) } as any;
    });
    const out = await provider.resolveAddressLabels('SUMnobody');
    expect(out.primary_label).toBeNull();
    expect(out.labels).toEqual([]);
  });

  it('propagates RPC errors', async () => {
    (global as any).fetch = jest.fn(async (_url: string, init: any) => {
      const body = JSON.parse(init.body);
      return {
        ok: true,
        json: async () => ({ jsonrpc: '2.0', id: body.id, error: { code: -32602, message: 'Invalid address' } }),
      } as any;
    });
    await expect(provider.resolveAddressLabels('bad')).rejects.toThrow(/Invalid address/);
  });
});
