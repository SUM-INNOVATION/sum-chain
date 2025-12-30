/**
 * SUM Chain TypeScript SDK - Utility Functions
 */
import type { KoppaAmount } from './types';
/**
 * One Koppa in base units (9 decimals)
 */
export declare const KOPPA_UNIT: bigint;
/**
 * Koppa currency symbol
 */
export declare const KOPPA_SYMBOL = "\u03D8";
/**
 * Koppa currency name
 */
export declare const KOPPA_NAME = "Koppa";
/**
 * Number of decimal places
 */
export declare const KOPPA_DECIMALS = 9;
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
export declare function koppaToBaseUnits(koppa: number | string): bigint;
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
export declare function baseUnitsToKoppa(baseUnits: KoppaAmount): string;
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
export declare function formatKoppa(baseUnits: KoppaAmount): string;
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
export declare function formatNumber(value: number | string): string;
/**
 * Validate address format
 *
 * @param address - Address to validate
 * @returns true if valid
 */
export declare function isValidAddress(address: string): boolean;
/**
 * Validate transaction hash format
 *
 * @param hash - Hash to validate
 * @returns true if valid
 */
export declare function isValidHash(hash: string): boolean;
/**
 * Sleep for specified milliseconds
 *
 * @param ms - Milliseconds to sleep
 */
export declare function sleep(ms: number): Promise<void>;
/**
 * Retry a function with exponential backoff
 *
 * @param fn - Function to retry
 * @param maxRetries - Maximum number of retries
 * @param initialDelay - Initial delay in ms
 */
export declare function retry<T>(fn: () => Promise<T>, maxRetries?: number, initialDelay?: number): Promise<T>;
