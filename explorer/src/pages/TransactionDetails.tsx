import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa } from '../utils/formatters';
import type { TransactionInfo, TransactionReceipt } from '@sumchain/sdk';

export default function TransactionDetails() {
  const { hash } = useParams<{ hash: string }>();
  const [tx, setTx] = useState<TransactionInfo | null>(null);
  const [receipt, setReceipt] = useState<TransactionReceipt | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTransaction();
  }, [hash]);

  async function loadTransaction() {
    if (!hash) return;

    try {
      const [txData, receiptData] = await Promise.all([
        provider.getTransaction(hash),
        provider.getReceipt(hash),
      ]);
      setTx(txData);
      setReceipt(receiptData);
    } catch (error) {
      console.error('Failed to load transaction:', error);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return <div className="text-center py-20 text-slate-400">Loading transaction...</div>;
  }

  if (!tx) {
    return (
      <div className="text-center py-20">
        <h2 className="text-2xl font-bold text-white mb-4">Transaction Not Found</h2>
        <Link to="/" className="text-blue-400 hover:text-blue-300">← Back to Home</Link>
      </div>
    );
  }

  const status = receipt?.status || tx.status || 'pending';
  const statusColor = status === 'success' ? 'text-green-400' : status === 'failed' ? 'text-red-400' : 'text-yellow-400';

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <h1 className="text-3xl font-bold text-white">Transaction Details</h1>

      <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 space-y-4">
        <div className="flex justify-between items-start">
          <div className="text-slate-400">Status</div>
          <div className={`font-bold uppercase ${statusColor}`}>{status}</div>
        </div>
        <DetailRow label="Hash" value={tx.hash} />
        <DetailRow label="From" value={tx.from} link={`/address/${tx.from}`} />
        <DetailRow label="To" value={tx.to} link={`/address/${tx.to}`} />
        <DetailRow label="Amount" value={formatKoppa(tx.amount)} highlight />
        <DetailRow label="Fee" value={formatKoppa(tx.fee)} />
        <DetailRow label="Nonce" value={tx.nonce.toString()} />
        <DetailRow label="Chain ID" value={tx.chain_id.toString()} />
        {tx.block_height && <DetailRow label="Block" value={tx.block_height.toString()} link={`/block/${tx.block_height}`} />}
        {receipt && <DetailRow label="Block Index" value={receipt.tx_index.toString()} />}
        {receipt && <DetailRow label="Fee Paid" value={formatKoppa(receipt.fee_paid)} />}
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
    <Link to={link} className="text-blue-400 hover:text-blue-300 font-mono break-all">
      {value}
    </Link>
  ) : (
    <span className={`font-mono break-all ${highlight ? 'text-cyan-400 font-bold' : 'text-white'}`}>
      {value}
    </span>
  );

  return (
    <div className="flex justify-between items-start border-b border-slate-700 pb-3">
      <div className="text-slate-400 font-medium">{label}</div>
      <div className="text-right">{content}</div>
    </div>
  );
}
