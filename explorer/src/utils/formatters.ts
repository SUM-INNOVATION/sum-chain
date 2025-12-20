import { formatKoppa, baseUnitsToKoppa, KOPPA_SYMBOL } from '@sumchain/sdk';

/**
 * Format address to shortened version
 */
export function formatAddress(address: string, chars = 8): string {
  if (address.length <= chars * 2) return address;
  return `${address.slice(0, chars)}...${address.slice(-chars)}`;
}

/**
 * Format hash to shortened version
 */
export function formatHash(hash: string, chars = 8): string {
  if (hash.startsWith('0x')) {
    return `${hash.slice(0, chars + 2)}...${hash.slice(-chars)}`;
  }
  return `${hash.slice(0, chars)}...${hash.slice(-chars)}`;
}

/**
 * Format timestamp to human readable
 */
export function formatTimestamp(timestampMs: number): string {
  const date = new Date(timestampMs);
  return date.toLocaleString();
}

/**
 * Format time ago
 */
export function formatTimeAgo(timestampMs: number): string {
  const seconds = Math.floor((Date.now() - timestampMs) / 1000);

  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Format Koppa with symbol
 */
export { formatKoppa, baseUnitsToKoppa, KOPPA_SYMBOL };
