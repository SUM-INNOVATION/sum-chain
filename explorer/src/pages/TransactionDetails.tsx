import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { useParams, Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa } from '../utils/formatters';
import { DetailSkeleton, ErrorState, Skeleton } from '../components/States';
import { TransactionTypeBadge, TransactionActionLabel } from '../components/TransactionType';
import { Copyable } from '../components/Copyable';
import { AddressLabel } from '../components/AddressLabel';
import { minterRole } from '@sumchain/sdk';
import type { TransactionInfo, TransactionReceipt, TokenMintersInfo } from '@sumchain/sdk';

interface TokenNameMeta {
  name: string;
  symbol: string;
}

export default function TransactionDetails() {
  const { hash } = useParams<{ hash: string }>();
  const [tx, setTx] = useState<TransactionInfo | null>(null);
  const [receipt, setReceipt] = useState<TransactionReceipt | null>(null);
  const [tokenMeta, setTokenMeta] = useState<TokenNameMeta | null>(null);
  const [minters, setMinters] = useState<TokenMintersInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const loadTransaction = useCallback(async () => {
    if (!hash) return;
    setLoading(true);
    try {
      const [txData, receiptData] = await Promise.all([
        provider.getTransaction(hash),
        provider.getReceipt(hash),
      ]);
      setTx(txData);
      setReceipt(receiptData);
      setError(false);

      // For SRC-20 token transactions, resolve the token's public name/symbol
      // and its token-scoped minters (this token only — never an address-wide
      // profile). Best-effort: failures leave the labels unresolved.
      if (txData?.asset_kind === 'src20' && txData.asset_ref) {
        const tokenId = `0x${txData.asset_ref}`;
        const [meta, minterInfo] = await Promise.all([
          provider.getSrc20Token(tokenId).catch(() => null),
          provider.getTokenMinters(tokenId).catch(() => null),
        ]);
        setTokenMeta(meta ? { name: meta.name, symbol: meta.symbol } : null);
        setMinters(minterInfo);
      } else {
        setTokenMeta(null);
        setMinters(null);
      }
    } catch (err) {
      console.error('Failed to load transaction:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [hash]);

  useEffect(() => {
    loadTransaction();
  }, [loadTransaction]);

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl space-y-6">
        <Skeleton className="h-9 w-56" />
        <DetailSkeleton rows={8} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="py-20">
        <ErrorState message="Could not load this transaction." onRetry={loadTransaction} />
      </div>
    );
  }

  if (!tx) {
    return (
      <div className="py-20 text-center">
        <h2 className="mb-4 font-display text-2xl font-semibold tracking-tight text-foreground">Transaction not found</h2>
        <Link to="/" className="text-accent-soft hover:text-primary-200">
          Back to home
        </Link>
      </div>
    );
  }

  const status = receipt?.status || tx.status || 'pending';
  const statusColor =
    status === 'success' ? 'text-green-400' : status === 'failed' ? 'text-red-400' : 'text-amber-400';

  const fromRole = minters ? minterRole(minters, tx.from, tokenMeta?.symbol) : null;
  const toRole = minters && tx.to ? minterRole(minters, tx.to, tokenMeta?.symbol) : null;

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <h1 className="font-display text-3xl font-semibold tracking-tight text-foreground">Transaction</h1>

      <div className="space-y-4 rounded-2xl border border-border bg-surface p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="text-muted">Status</div>
          <div className={`font-bold uppercase ${statusColor}`}>{status}</div>
        </div>

        {/* Type: domain chip + human action */}
        <DetailRowNode label="Type">
          <div className="flex flex-wrap items-center justify-end gap-2">
            <TransactionTypeBadge tx={tx} />
            <TransactionActionLabel tx={tx} className="text-foreground" />
          </div>
        </DetailRowNode>

        {/* Asset (token / NFT), when the payload references one */}
        {tx.asset_kind && (
          <DetailRowNode label="Asset">
            <div className="flex flex-col items-end gap-1">
              <span className="text-foreground">
                {tokenMeta
                  ? `${tokenMeta.name} (${tokenMeta.symbol})`
                  : tx.asset_kind === 'src20'
                    ? 'SRC-20 token'
                    : tx.asset_kind === 'nft'
                      ? 'SUM-721 NFT'
                      : 'Native Koppa'}
              </span>
              {tx.asset_ref && (
                <Copyable text={tx.asset_ref} className="font-mono text-xs text-muted" title="Copy asset id">
                  <span className="break-all">0x{tx.asset_ref}</span>
                </Copyable>
              )}
            </div>
          </DetailRowNode>
        )}

        <DetailRowNode label="Hash">
          <Copyable text={tx.hash} className="tnum font-mono text-foreground" title="Copy hash">
            <span className="break-all">{tx.hash}</span>
          </Copyable>
        </DetailRowNode>

        <DetailRowNode label="From">
          <div className="flex flex-col items-end gap-1">
            <AddressLabel address={tx.from} className="justify-end" />
            {fromRole?.label && <MinterChip label={fromRole.label} />}
          </div>
        </DetailRowNode>

        {tx.to ? (
          <DetailRowNode label="To">
            <div className="flex flex-col items-end gap-1">
              <AddressLabel address={tx.to} className="justify-end" />
              {toRole?.label && <MinterChip label={toRole.label} />}
            </div>
          </DetailRowNode>
        ) : (
          <DetailRowNode label="To">
            <span className="text-muted">Not a direct-transfer recipient</span>
          </DetailRowNode>
        )}

        <DetailRow label="Amount" value={formatKoppa(tx.amount)} highlight />
        <DetailRow label="Fee" value={formatKoppa(tx.fee)} />
        <DetailRow label="Nonce" value={tx.nonce.toString()} />
        <DetailRow label="Chain ID" value={tx.chain_id.toString()} />
        {tx.block_height && (
          <DetailRow label="Block" value={tx.block_height.toString()} link={`/block/${tx.block_height}`} />
        )}
        {receipt && <DetailRow label="Block index" value={receipt.tx_index.toString()} />}
        {receipt && <DetailRow label="Fee paid" value={formatKoppa(receipt.fee_paid)} />}
      </div>
    </div>
  );
}

/** Small token-scoped minter/owner chip (e.g. "ACME minter"). */
function MinterChip({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded bg-primary-500/15 px-2 py-0.5 text-xs font-medium text-primary-200 ring-1 ring-inset ring-primary-400/30">
      {label}
    </span>
  );
}

/** Detail row whose value is arbitrary JSX (chips, copyable values, links). */
function DetailRowNode({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border pb-3">
      <div className="font-medium text-muted">{label}</div>
      <div className="min-w-0 text-right">{children}</div>
    </div>
  );
}

interface DetailRowProps {
  label: string;
  value: string;
  link?: string;
  highlight?: boolean;
}

function DetailRow({ label, value, link, highlight }: DetailRowProps) {
  const content = link ? (
    <Link to={link} className="tnum break-all font-mono text-accent-soft hover:text-primary-200">
      {value}
    </Link>
  ) : (
    <span className={`tnum break-all font-mono ${highlight ? 'font-bold text-accent-soft' : 'text-foreground'}`}>
      {value}
    </span>
  );

  return (
    <div className="flex items-start justify-between gap-4 border-b border-border pb-3">
      <div className="font-medium text-muted">{label}</div>
      <div className="text-right">{content}</div>
    </div>
  );
}
