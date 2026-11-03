import { Provider } from '../provider';
import { fromRaddress, isRaddress, isValidAddress, RADDRESS_PREFIX, toRaddress } from '../utils';

// The agent ("raddress") text form, issue #309: `r0` followed by the plain
// base58 address. Format checks only: the 4-byte checksum is verified only by
// the node, which refuses a bad checksum with -32602. No network, no keys.

// Vectors shared with the Rust parser (crates/sumchain-wire/src/address.rs,
// `shared_vectors_pin_the_lengths_the_parser_accepts`): keep the two tables
// equal, so this format check and the node parse the same shape; the node also
// verifies the checksum, which this does not.
//
// The plain text is base58 of 24 bytes (the 20-byte address and a 4-byte
// checksum): 24 to 33 characters, and under 32 only with two or more leading
// zero bytes.

// Valid addresses of each length: the zero address (26 characters); the
// address of the key whose first 8 bytes are 345842 little-endian and the rest
// zero (two leading zero bytes, 31); two allocations in
// genesis/local_genesis.json (32 and 33).
const SHARED_VALID: Array<[string, number]> = [
  ['111111111111111111112u6Gvy', 26],
  ['11cMv23diqJbvHNnfUXcFZZb6p53x2G', 31],
  ['jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j', 32],
  ['ChBEvSC2DKPKr8qFgbSv69Xnm8JNAKdiY', 33],
];
// The shape of an address (24 bytes) with a wrong checksum: this format check
// takes them; the node refuses them on the checksum alone. 24 zero bytes (24
// characters) and the largest 24-byte value (33).
const SHARED_SHAPE_ONLY = ['111111111111111111111111', 'QLbz7JHiBTspS962RLKV8GndWFwiEaqKL'];
// Base58 characters that do not decode to 24 bytes: refused by both. 23 and 25
// zero bytes; 2^192, the smallest 25-byte value (33 characters); the largest
// 23-byte value with no leading zero byte (32 characters); 33 `z`s (25 bytes).
const SHARED_WRONG_SHAPE = [
  '11111111111111111111111',
  '1111111111111111111111111',
  'QLbz7JHiBTspS962RLKV8GndWFwiEaqKM',
  '6HgC8KRBEhXYbF4riJyJFLSHt32XBnGv',
  'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
];

const ZERO_ADDRESS = SHARED_VALID[0][0];
const SHORT_KEY_ADDRESS = SHARED_VALID[1][0];
const PLAIN_33 = SHARED_VALID[3][0];
// Hex as a node prints it.
const HEX = '0x0123456789abcdef0123456789abcdef01234567';

describe('raddress text form (issue #309)', () => {
  it('uses the r0 prefix', () => {
    expect(RADDRESS_PREFIX).toBe('r0');
  });

  it('round-trips valid addresses of 26, 31, 32 and 33 characters', () => {
    for (const [plain, length] of SHARED_VALID) {
      expect(plain).toHaveLength(length);
      const agent = toRaddress(plain);
      expect(agent).toBe('r0' + plain);
      expect(fromRaddress(agent)).toBe(plain);
      expect(isRaddress(agent)).toBe(true);
      expect(isRaddress(plain)).toBe(false);
    }
  });

  it('isValidAddress accepts the plain, agent and hex forms', () => {
    for (const [plain] of SHARED_VALID) {
      expect(isValidAddress(plain)).toBe(true);
      expect(isValidAddress('r0' + plain)).toBe(true);
    }
    expect(isValidAddress(HEX)).toBe(true);
  });

  it('refuses r0 followed by anything but a plain base58 address', () => {
    const refused = [
      'r0',
      'r0' + HEX, // the agent form is not over hex
      'r0' + HEX.slice(2),
      'r0' + 'ab'.repeat(20), // 40 characters cannot be 24 bytes
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

  it('checks the shape the node parses, short addresses included, not the checksum', () => {
    // Short valid addresses, in both forms: the node accepts these too.
    for (const plain of [ZERO_ADDRESS, SHORT_KEY_ADDRESS]) {
      expect(plain.length).toBeLessThan(32);
      expect(isValidAddress(plain)).toBe(true);
      expect(isRaddress('r0' + plain)).toBe(true);
      expect(fromRaddress(toRaddress(plain))).toBe(plain);
    }
    // The right shape with a wrong checksum: a format check cannot tell.
    for (const s of SHARED_SHAPE_ONLY) {
      expect(isValidAddress(s)).toBe(true);
      expect(isRaddress('r0' + s)).toBe(true);
    }
    // Not 24 bytes, whatever the length: refused in both forms.
    for (const s of SHARED_WRONG_SHAPE) {
      expect(isValidAddress(s)).toBe(false);
      expect(isRaddress('r0' + s)).toBe(false);
      expect(() => toRaddress(s)).toThrow();
      expect(() => fromRaddress('r0' + s)).toThrow();
    }
  });

  it('refuses what cannot be an address: length bounds 24 and 33, hex rule unchanged', () => {
    expect(isValidAddress('')).toBe(false);
    expect(isValidAddress(ZERO_ADDRESS.slice(1))).toBe(false); // 23 bytes
    expect(isValidAddress('1'.repeat(23))).toBe(false); // under 24 characters
    expect(isValidAddress('2'.repeat(34))).toBe(false); // over 33 characters
    // A 44-character base58 public key is not an address.
    expect(isValidAddress('2'.repeat(44))).toBe(false);
    // Bare hex: 40 characters is never 24 bytes of base58.
    expect(isValidAddress('ab'.repeat(20))).toBe(false);
    expect(isValidAddress(HEX.slice(2))).toBe(false);
    expect(isValidAddress(HEX.slice(0, -2))).toBe(false); // short hex
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
