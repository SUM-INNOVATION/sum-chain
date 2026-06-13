import { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa } from '../utils/formatters';
import { DetailSkeleton, ErrorState, Skeleton } from '../components/States';
import type { TransactionInfo, TransactionReceipt } from '@sumchain/sdk';

export default function TransactionDetails() {
  const { hash } = useParams<{ hash: string }>();
  const [tx, setTx] = useState<TransactionInfo | null>(null);
  const [receipt, setReceipt] = useState<TransactionReceipt | null>(null);
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
        <h2 className="mb-4 font-display text-2xl font-bold text-white">Transaction not found</h2>
        <Link to="/" className="text-primary-300 hover:text-primary-200">
          Back to home
        </Link>
      </div>
    );
  }

  const status = receipt?.status || tx.status || 'pending';
  const statusColor =
    status === 'success' ? 'text-green-400' : status === 'failed' ? 'text-red-400' : 'text-amber-400';

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <h1 className="font-display text-3xl font-bold text-white">Transaction</h1>

      <div className="space-y-4 rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
        <div className="flex items-start justify-between">
          <div className="text-zinc-400">Status</div>
          <div className={`font-bold uppercase ${statusColor}`}>{status}</div>
        </div>
        <DetailRow label="Hash" value={tx.hash} />
        <DetailRow label="From" value={tx.from} link={`/address/${tx.from}`} />
        <DetailRow label="To" value={tx.to} link={`/address/${tx.to}`} />
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

interface DetailRowProps {
  label: string;
  value: string;
  link?: string;
  highlight?: boolean;
}

function DetailRow({ label, value, link, highlight }: DetailRowProps) {
  const content = link ? (
    <Link to={link} className="tnum break-all font-mono text-primary-300 hover:text-primary-200">
      {value}
    </Link>
  ) : (
    <span className={`tnum break-all font-mono ${highlight ? 'font-bold text-primary-300' : 'text-white'}`}>
      {value}
    </span>
  );

  return (
    <div className="flex items-start justify-between gap-4 border-b border-zinc-800 pb-3">
      <div className="font-medium text-zinc-400">{label}</div>
      <div className="text-right">{content}</div>
    </div>
  );
}
