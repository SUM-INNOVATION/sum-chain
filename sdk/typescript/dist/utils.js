/**
 * SUM Chain TypeScript SDK - Utility Functions
 */
/**
 * One Koppa in base units (9 decimals)
 */
export const KOPPA_UNIT = BigInt(1000000000);
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
export function koppaToBaseUnits(koppa) {
    const koppaStr = koppa.toString();
    if (koppaStr.includes('.')) {
        const [whole, fraction] = koppaStr.split('.');
        const wholeUnits = BigInt(whole || '0') * KOPPA_UNIT;
        // Pad or truncate fraction to 9 digits
        const paddedFraction = fraction.padEnd(KOPPA_DECIMALS, '0').slice(0, KOPPA_DECIMALS);
        const fractionUnits = BigInt(paddedFraction);
        return wholeUnits + fractionUnits;
    }
    else {
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
export function baseUnitsToKoppa(baseUnits) {
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
export function formatKoppa(baseUnits) {
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
export function formatNumber(value) {
    const str = value.toString();
    const [whole, fraction] = str.split('.');
    const formatted = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    return fraction !== undefined ? `${formatted}.${fraction}` : formatted;
}
/**
 * Validate address format
 *
 * @param address - Address to validate
 * @returns true if valid
 */
export function isValidAddress(address) {
    // Check base58 format (starts with alphanumeric)
    if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)) {
        return address.length >= 32 && address.length <= 44;
    }
    // Check hex format (starts with 0x)
    if (address.startsWith('0x')) {
        return /^0x[0-9a-fA-F]{40}$/.test(address);
    }
    return false;
}
/**
 * Validate transaction hash format
 *
 * @param hash - Hash to validate
 * @returns true if valid
 */
export function isValidHash(hash) {
    return /^0x[0-9a-fA-F]{64}$/.test(hash) || /^[0-9a-fA-F]{64}$/.test(hash);
}
/**
 * Sleep for specified milliseconds
 *
 * @param ms - Milliseconds to sleep
 */
export function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
 * Retry a function with exponential backoff
 *
 * @param fn - Function to retry
 * @param maxRetries - Maximum number of retries
 * @param initialDelay - Initial delay in ms
 */
export async function retry(fn, maxRetries = 3, initialDelay = 1000) {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await fn();
        }
        catch (error) {
            lastError = error;
            if (i < maxRetries - 1) {
                const delay = initialDelay * Math.pow(2, i);
                await sleep(delay);
            }
        }
    }
    throw lastError;
}
