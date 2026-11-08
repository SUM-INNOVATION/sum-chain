import { displayAddress, parseSwarmRoster, toRaddress } from '../utils';

// Swarm roster display, issue #309 item 3: members are shown in the `r0` form,
// everyone else as given. Display only; format checks only (the node verifies
// the checksum). Addresses from the shared vectors in raddress.test.ts.
const A = 'jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j'; // 32 characters
const B = 'ChBEvSC2DKPKr8qFgbSv69Xnm8JNAKdiY'; // 33
const Z = '111111111111111111112u6Gvy'; // the zero address, 26
const OTHER = '11cMv23diqJbvHNnfUXcFZZb6p53x2G'; // 31, not on the roster

describe('parseSwarmRoster', () => {
  it('takes plain and r0 entries, commas, whitespace and comments', () => {
    const roster = parseSwarmRoster(`# swarm A\n${A}\n  ${toRaddress(B)} , ${Z}   # zero\n\n`);
    expect([...roster].sort()).toEqual([A, B, Z].sort());
  });

  it('keeps one member per account whichever form it was given in', () => {
    expect(parseSwarmRoster(`${A} ${toRaddress(A)},${A}`).size).toBe(1);
  });

  it('is empty for empty or comment-only text', () => {
    expect(parseSwarmRoster('').size).toBe(0);
    expect(parseSwarmRoster('# none yet\n \n').size).toBe(0);
  });

  it('refuses an entry in neither form, naming its line', () => {
    expect(() => parseSwarmRoster(`${A}\nnot-an-address`)).toThrow(/line 2: 'not-an-address'/);
    // hex is not accepted in a roster
    expect(() => parseSwarmRoster('0x' + '11'.repeat(20))).toThrow(/line 1/);
    // the wrong shape (25 bytes), and r0 before a wrong shape
    expect(() => parseSwarmRoster('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz')).toThrow(/line 1/);
    expect(() => parseSwarmRoster('r0zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz')).toThrow(/line 1/);
  });
});

describe('displayAddress', () => {
  const roster = parseSwarmRoster(`${A}\n${toRaddress(B)}`);

  it('shows a member in the r0 form, whichever form it arrives in', () => {
    expect(displayAddress(A, roster)).toBe(`r0${A}`);
    expect(displayAddress(`r0${A}`, roster)).toBe(`r0${A}`);
    expect(displayAddress(B, roster)).toBe(`r0${B}`);
  });

  it('leaves everything else exactly as given', () => {
    expect(displayAddress(OTHER, roster)).toBe(OTHER);
    expect(displayAddress(`r0${OTHER}`, roster)).toBe(`r0${OTHER}`);
    for (const text of ['', 'Unknown', 'r0', '0x' + '11'.repeat(20), 'r0not-base58']) {
      expect(displayAddress(text, roster)).toBe(text);
    }
  });

  it('changes nothing with an empty roster', () => {
    expect(displayAddress(A, new Set())).toBe(A);
  });
});
