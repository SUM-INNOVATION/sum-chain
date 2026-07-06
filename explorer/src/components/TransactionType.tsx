import { classifyTransaction, DOMAIN_STYLE, type TxClassifiable } from '../utils/txView';

/**
 * Compact domain chip (Native / Token / SNIP / OmniNode / Governance / Policy /
 * Messaging / Other). Text label + `title` — never color-only.
 */
export function TransactionTypeBadge({ tx, className = '' }: { tx: TxClassifiable; className?: string }) {
  const c = classifyTransaction(tx);
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${DOMAIN_STYLE[c.domain]} ${className}`}
      title={c.action}
    >
      {c.domainLabel}
    </span>
  );
}

/** Human action label for a transaction (e.g. "SNIP file registration"). */
export function TransactionActionLabel({ tx, className = '' }: { tx: TxClassifiable; className?: string }) {
  const c = classifyTransaction(tx);
  return <span className={className}>{c.action}</span>;
}

/** Chip + action label, the common pairing used in rows and detail views. */
export function TransactionTypeCell({ tx, className = '' }: { tx: TxClassifiable; className?: string }) {
  const c = classifyTransaction(tx);
  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <TransactionTypeBadge tx={tx} />
      <span className="truncate text-muted-strong">{c.action}</span>
    </span>
  );
}
