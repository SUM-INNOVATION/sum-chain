/**
 * SUM Chain TypeScript SDK - Utility Functions
 */

import type { KoppaAmount } from './types.js';

/**
 * One Koppa in base units (9 decimals)
 */
export const KOPPA_UNIT = BigInt(1_000_000_000);

/**
 * Koppa currency symbol
 */
export const KOPPA_SYMBOL = 'Ϙ';

/**
 * Koppa currency name
 */
export const KOPPA_NAME = 'Koppa';

/**
 * Number of decimal places
 */
export const KOPPA_DECIMALS = 9;

/**
 * Convert Koppa to base units
 *
 * @param koppa - Amount in Koppa (e.g., "1.5" or 1.5)
 * @returns Amount in base units as bigint
 *
 * @example
 * ```ts
 * koppaToBaseUnits("1.5")    // 1500000000n
 * koppaToBaseUnits(1.5)      // 1500000000n
 * koppaToBaseUnits("0.001")  // 1000000n
 * ```
 */
export function koppaToBaseUnits(koppa: number | string): bigint {
  const koppaStr = koppa.toString();

  if (koppaStr.includes('.')) {
    const [whole, fraction] = koppaStr.split('.');
    const wholeUnits = BigInt(whole || '0') * KOPPA_UNIT;

    // Pad or truncate fraction to 9 digits
    const paddedFraction = fraction.padEnd(KOPPA_DECIMALS, '0').slice(0, KOPPA_DECIMALS);
    const fractionUnits = BigInt(paddedFraction);

    return wholeUnits + fractionUnits;
  } else {
    return BigInt(koppaStr) * KOPPA_UNIT;
  }
}

/**
 * Convert base units to Koppa
 *
 * @param baseUnits - Amount in base units
 * @returns Amount in Koppa as string
 *
 * @example
 * ```ts
 * baseUnitsToKoppa(1500000000n)  // "1.5"
 * baseUnitsToKoppa("1000000000")  // "1"
 * baseUnitsToKoppa(1000000n)      // "0.001"
 * ```
 */
export function baseUnitsToKoppa(baseUnits: KoppaAmount): string {
  const units = typeof baseUnits === 'string' ? BigInt(baseUnits) : baseUnits;
  const whole = units / KOPPA_UNIT;
  const fraction = units % KOPPA_UNIT;

  if (fraction === 0n) {
    return whole.toString();
  }

  const fractionStr = fraction.toString().padStart(KOPPA_DECIMALS, '0');
  const trimmed = fractionStr.replace(/0+$/, '');

  return `${whole}.${trimmed}`;
}

/**
 * Format Koppa amount with symbol
 *
 * @param baseUnits - Amount in base units
 * @returns Formatted string with Koppa symbol
 *
 * @example
 * ```ts
 * formatKoppa(1500000000n)  // "1.5 Ϙ"
 * formatKoppa("1000000000")  // "1 Ϙ"
 * ```
 */
export function formatKoppa(baseUnits: KoppaAmount): string {
  const koppa = baseUnitsToKoppa(baseUnits);
  return `${formatNumber(koppa)} ${KOPPA_SYMBOL}`;
}

/**
 * Format number with comma separators
 *
 * @param value - Number or string to format
 * @returns Formatted string with commas
 *
 * @example
 * ```ts
 * formatNumber("1000")      // "1,000"
 * formatNumber("1000.5")    // "1,000.5"
 * formatNumber(1234567.89)  // "1,234,567.89"
 * ```
 */
export function formatNumber(value: number | string): string {
  const str = value.toString();
  const [whole, fraction] = str.split('.');

  const formatted = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');

  return fraction !== undefined ? `${formatted}.${fraction}` : formatted;
}

/**
 * Prefix of the agent ("raddress") text form of an address: `r0` followed by
 * the plain base58 address, unchanged (sum-chain #309). `0` is not in the
 * base58 alphabet, so no plain address starts with it. A text form only; it
 * does not identify an agent or grant anything.
 */
export const RADDRESS_PREFIX = 'r0';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * The plain text is base58 of 24 bytes: the 20-byte address and a 4-byte
 * checksum, as the node decodes it.
 */
const PLAIN_ADDRESS_BYTES = 24;

/**
 * Length bounds of the plain text, derived from those 24 bytes: each leading
 * zero byte is one `1` and the rest, as a number, takes the fewest base-58
 * digits. 24 zero bytes give the shortest text, 24 characters; no 24-byte
 * value takes more than 33, since 58^32 < 2^192 <= 58^33. Most addresses take
 * 33 or 32 characters; only one with two or more leading zero bytes takes
 * fewer (the zero address takes 26).
 */
const PLAIN_ADDRESS_MIN_LENGTH = 24;
const PLAIN_ADDRESS_MAX_LENGTH = 33;

/**
 * The number of bytes base58 text decodes to, counted as the node's decoder
 * counts them: one zero byte per leading `1`, then the bytes of the number the
 * rest spells. -1 for a character outside the alphabet.
 */
function base58DecodedLength(text: string): number {
  let zeros = 0;
  while (zeros < text.length && text[zeros] === '1') {
    zeros++;
  }
  let value = 0n;
  for (let i = zeros; i < text.length; i++) {
    const digit = BASE58_ALPHABET.indexOf(text[i]);
    if (digit < 0) {
      return -1;
    }
    value = value * 58n + BigInt(digit);
  }
  let bytes = 0;
  while (value > 0n) {
    value >>= 8n;
    bytes++;
  }
  return zeros + bytes;
}

/**
 * The plain base58 form, by shape only: base58 characters that decode to 24
 * bytes, the same shape the node parses. A format check; the 4-byte checksum
 * is verified only by the node, which refuses a bad checksum with -32602
 * (Invalid params). Text that passes here can still be refused there.
 */
function isPlainBase58Address(address: string): boolean {
  return (
    address.length >= PLAIN_ADDRESS_MIN_LENGTH &&
    address.length <= PLAIN_ADDRESS_MAX_LENGTH &&
    base58DecodedLength(address) === PLAIN_ADDRESS_BYTES
  );
}

/**
 * Validate address format
 *
 * Accepts the plain base58 form, the agent form (`r0` followed by the plain
 * base58 form) and `0x` hex. The plain form is base58 that decodes to 24
 * bytes, 24 to 33 characters: the same shape the node parses.
 *
 * A format check; the 4-byte checksum is verified only by the node, which
 * refuses a bad checksum with -32602 (Invalid params). `true` means the text
 * has the shape of an address, not that the node will accept it.
 *
 * @param address - Address to validate
 * @returns true if the text has the format of an address
 */
export function isValidAddress(address: string): boolean {
  // Plain base58, or the agent form: `r0` then a plain base58 address
  if (isPlainBase58Address(address) || isRaddress(address)) {
    return true;
  }

  // Check hex format (starts with 0x)
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Whether an address is written in the agent form: `r0` followed by a plain
 * base58 address. A format check; the 4-byte checksum is verified only by the
 * node, which refuses a bad checksum with -32602 (Invalid params). The `r0`
 * form does not identify an agent or grant anything, and the node takes both
 * forms as the same account. A caller may refuse a form it does not expect, as
 * a check on its input and nothing more.
 *
 * @param address - Address to check
 * @returns true for the agent form
 */
export function isRaddress(address: string): boolean {
  return (
    address.startsWith(RADDRESS_PREFIX) &&
    isPlainBase58Address(address.slice(RADDRESS_PREFIX.length))
  );
}

/**
 * Convert a plain base58 address to its agent form: `r0` followed by the same
 * text. The same 20 bytes, key and checksum; the node treats both forms as
 * the same account and returns addresses in the plain form. A text form only;
 * it does not identify an agent or grant anything.
 *
 * Checks the format of `address` only; the 4-byte checksum is verified only by
 * the node, which refuses a bad checksum with -32602 (Invalid params), in
 * either form.
 *
 * @param address - A plain base58 address
 * @returns The agent form
 * @throws If `address` does not have the format of a plain base58 address (hex
 *   is not converted)
 *
 * @example
 * ```ts
 * toRaddress('jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j')  // 'r0jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j'
 * ```
 */
export function toRaddress(address: string): string {
  if (!isPlainBase58Address(address)) {
    throw new Error('toRaddress: expected a plain base58 address');
  }
  return RADDRESS_PREFIX + address;
}

/**
 * Convert an agent-form address back to the plain base58 form: the text after
 * `r0`. The same account; the `r0` form is text only and grants nothing.
 *
 * Checks the format of `raddress` only; the 4-byte checksum is verified only
 * by the node, which refuses a bad checksum with -32602 (Invalid params).
 *
 * @param raddress - An address in the agent form
 * @returns The plain base58 address
 * @throws If `raddress` is not `r0` followed by text in the format of a plain
 *   base58 address
 *
 * @example
 * ```ts
 * fromRaddress('r0jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j')  // 'jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j'
 * ```
 */
export function fromRaddress(raddress: string): string {
  if (!isRaddress(raddress)) {
    throw new Error('fromRaddress: expected r0 followed by a plain base58 address');
  }
  return raddress.slice(RADDRESS_PREFIX.length);
}

/**
 * Validate transaction hash format
 *
 * @param hash - Hash to validate
 * @returns true if valid
 */
export function isValidHash(hash: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(hash) || /^[0-9a-fA-F]{64}$/.test(hash);
}

/**
 * Sleep for specified milliseconds
 *
 * @param ms - Milliseconds to sleep
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff
 *
 * @param fn - Function to retry
 * @param maxRetries - Maximum number of retries
 * @param initialDelay - Initial delay in ms
 */
export async function retry<T>(
  fn: () => Promise<T>,
  maxRetries = 3,
  initialDelay = 1000
): Promise<T> {
  let lastError: Error | undefined;

  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (i < maxRetries - 1) {
        const delay = initialDelay * Math.pow(2, i);
        await sleep(delay);
      }
    }
  }

  throw lastError;
}
