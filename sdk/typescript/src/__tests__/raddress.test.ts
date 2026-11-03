import { Provider } from '../provider';
import { fromRaddress, isRaddress, isValidAddress, RADDRESS_PREFIX, toRaddress } from '../utils';

// The agent ("raddress") text form, issue #309: `r0` followed by the plain
// base58 address. Format checks only; no network, no keys.

// Allocations in genesis/local_genesis.json: plain texts of 32 and 33
// characters (about 4% of addresses encode to 32).
const PLAIN_32 = 'jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j';
const PLAIN_33 = 'ChBEvSC2DKPKr8qFgbSv69Xnm8JNAKdiY';
// Hex as a node prints it; real hex addresses almost always contain a `0`,
// which is not base58. (40 hex digits with no `0` are base58 characters too,
// and the format check below takes them as base58, as it always has.)
const HEX = '0x0123456789abcdef0123456789abcdef01234567';

describe('raddress text form (issue #309)', () => {
  it('uses the r0 prefix', () => {
    expect(RADDRESS_PREFIX).toBe('r0');
  });

  it('round-trips plain addresses of 32 and 33 characters', () => {
    expect(PLAIN_32).toHaveLength(32);
    expect(PLAIN_33).toHaveLength(33);
    for (const plain of [PLAIN_32, PLAIN_33]) {
      const agent = toRaddress(plain);
      expect(agent).toBe('r0' + plain);
      expect(fromRaddress(agent)).toBe(plain);
      expect(isRaddress(agent)).toBe(true);
      expect(isRaddress(plain)).toBe(false);
    }
  });

  it('isValidAddress accepts the plain, agent and hex forms', () => {
    for (const ok of [PLAIN_32, PLAIN_33, 'r0' + PLAIN_32, 'r0' + PLAIN_33, HEX]) {
      expect(isValidAddress(ok)).toBe(true);
    }
  });

  it('refuses r0 followed by anything but a plain base58 address', () => {
    const refused = [
      'r0',
      'r0' + HEX, // the agent form is not over hex
      'r0' + HEX.slice(2),
      'r0r0' + PLAIN_33, // one prefix only
      'R0' + PLAIN_33, // the prefix is lower-case
      'r0' + PLAIN_33.slice(0, -1) + '0', // `0` is not base58
      'r0' + PLAIN_33.slice(0, 20), // too short
      ' r0' + PLAIN_33,
      'r0 ' + PLAIN_33,
    ];
    for (const s of refused) {
      expect(isValidAddress(s)).toBe(false);
      expect(isRaddress(s)).toBe(false);
      expect(() => fromRaddress(s)).toThrow();
    }
  });

  it('converts only between the two base58 forms', () => {
    expect(() => toRaddress('r0' + PLAIN_33)).toThrow(); // already the agent form
    expect(() => toRaddress(HEX)).toThrow(); // hex is not converted
    expect(() => toRaddress('notanaddress!')).toThrow();
    expect(() => fromRaddress(PLAIN_33)).toThrow(); // no prefix
    expect(() => fromRaddress(HEX)).toThrow();
  });

  it('leaves non-r0 validation as it was', () => {
    expect(isValidAddress(PLAIN_33.slice(0, 31))).toBe(false); // under 32
    expect(isValidAddress('1'.repeat(45))).toBe(false); // over 44
    expect(isValidAddress(HEX.slice(0, -2))).toBe(false); // short hex
    expect(isValidAddress(HEX.slice(2))).toBe(false); // hex without 0x
    expect(isValidAddress('ab'.repeat(20))).toBe(true); // base58 characters only, as before
    expect(isValidAddress('')).toBe(false);
  });
});

describe('Provider passes the agent form to the node unchanged (issue #309)', () => {
  let lastBody: any;

  beforeEach(() => {
    lastBody = undefined;
    (global as any).fetch = jest.fn(async (_url: string, init: any) => {
      lastBody = JSON.parse(init.body);
      return {
        ok: true,
        json: async () => ({ jsonrpc: '2.0', id: lastBody.id, result: '7' }),
      } as any;
    });
  });

  it('getBalance sends the r0 address as given', async () => {
    const provider = new Provider('http://localhost:8545');
    const balance = await provider.getBalance(toRaddress(PLAIN_33));
    expect(lastBody.method).toBe('get_balance');
    expect(lastBody.params).toEqual(['r0' + PLAIN_33]);
    expect(balance).toBe(7n);
  });
});
