/**
 * Pure transaction classification + labeling helpers.
 *
 * Shared by the explorer and SUMaillet. Everything here is a pure function of
 * already-public data (the RPC-derived `tx_type`/`action`/`asset_*` fields, or a
 * token's public minter config). No network, no inference beyond what the input
 * proves.
 */
import type { TokenMintersInfo } from './types.js';
import {
  ACTION_LABELS,
  DOMAIN_BY_TX_TYPE,
  DOMAIN_LABEL,
  TYPE_FALLBACK,
  UNKNOWN_LABEL,
  type TxDomain,
} from './txLabels.js';

/** Minimal shape needed to classify a transaction (subset of `TransactionInfo`). */
export interface TxClassifiable {
  tx_type?: string;
  action?: string | null;
  asset_ref?: string | null;
  asset_kind?: string | null;
}

/** Result of {@link classifyTransaction}. */
export interface TxClassification {
  /** Domain chip: one of the eight explorer domains. */
  domain: TxDomain;
  /** Display label for the domain chip (e.g. "SNIP", "OmniNode"). */
  domainLabel: string;
  /** Human action label (e.g. "Koppa transfer", "SNIP file registration"). */
  action: string;
  /** Hex asset reference passed through from the tx, if any. */
  assetRef: string | null;
  /** Coarse asset class hint passed through from the tx, if any. */
  assetKind: string | null;
}

/**
 * Map the raw (already-public) semantic fields of a transaction to a domain
 * chip + human action label. Unknown/absent `tx_type` yields the `other` domain
 * and the "Unknown transaction" fallback — never a guessed label.
 */
export function classifyTransaction(tx: TxClassifiable): TxClassification {
  const txType = tx.tx_type;
  const domain: TxDomain = txType ? DOMAIN_BY_TX_TYPE[txType] ?? 'other' : 'other';
  return {
    domain,
    domainLabel: DOMAIN_LABEL[domain],
    action: humanAction(txType, tx.action),
    assetRef: tx.asset_ref ?? null,
    assetKind: tx.asset_kind ?? null,
  };
}

/**
 * Human action label for a `(tx_type, action)` pair. Prefers a specific mapping,
 * falls back to a coarser per-type label, and finally to "Unknown transaction".
 */
export function humanAction(txType?: string, action?: string | null): string {
  if (!txType) return UNKNOWN_LABEL;
  if (action) {
    const specific = ACTION_LABELS[`${txType}.${action}`];
    if (specific) return specific;
  }
  const typeOnly = ACTION_LABELS[txType];
  if (typeOnly) return typeOnly;
  return TYPE_FALLBACK[txType] ?? UNKNOWN_LABEL;
}

/** Token-scoped minter role of an address for one token. */
export interface MinterRole {
  /** Address is the token owner (implicit minter). */
  isOwner: boolean;
  /** Address may mint (owner or explicitly registered). */
  isMinter: boolean;
  /** Human label ("‹Token› owner" / "‹Token› minter"), or `null` if neither. */
  label: string | null;
}

/**
 * Resolve an address's minter role for a single token already in view.
 *
 * Token-scoped by construction — it answers "is this address a minter of *this*
 * token?", never "what can this address mint across the chain?". Pass an
 * optional human token label (name or symbol) to personalize the string;
 * otherwise a generic "Token" prefix is used.
 */
export function minterRole(
  info: TokenMintersInfo,
  address: string,
  tokenLabel?: string,
): MinterRole {
  const isOwner = info.owner === address;
  const isMinter = isOwner || info.minters.includes(address);
  const base = tokenLabel && tokenLabel.trim() ? tokenLabel.trim() : 'Token';
  let label: string | null = null;
  if (isOwner) label = `${base} owner`;
  else if (isMinter) label = `${base} minter`;
  return { isOwner, isMinter, label };
}
