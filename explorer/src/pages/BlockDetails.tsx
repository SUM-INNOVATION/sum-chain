import { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatHash, formatTimestamp, copyToClipboard } from '../utils/formatters';
import { DetailSkeleton, ErrorState, Skeleton } from '../components/States';
import type { BlockInfo } from '@sumchain/sdk';

export default function BlockDetails() {
  const { height } = useParams<{ height: string }>();
  const [block, setBlock] = useState<BlockInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [copied, setCopied] = useState('');

  const loadBlock = useCallback(async () => {
    if (!height) return;
    setLoading(true);
    try {
      const blockData = await provider.getBlockByHeight(parseInt(height));
      setBlock(blockData);
      setError(false);
    } catch (err) {
      console.error('Failed to load block:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [height]);

  useEffect(() => {
    loadBlock();
  }, [loadBlock]);

  const handleCopy = async (text: string, field: string) => {
    if (await copyToClipboard(text)) {
      setCopied(field);
      setTimeout(() => setCopied(''), 2000);
    }
  };

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl space-y-6">
        <Skeleton className="h-9 w-40" />
        <DetailSkeleton rows={7} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="py-20">
        <ErrorState message="Could not load this block." onRetry={loadBlock} />
      </div>
    );
  }

  if (!block) {
    return (
      <div className="py-20 text-center">
        <h2 className="mb-4 font-display text-2xl font-semibold tracking-tight text-foreground">Block not found</h2>
        <Link to="/" className="text-accent-soft hover:text-primary-200">
          Back to home
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <h1 className="tnum font-display text-3xl font-semibold tracking-tight text-foreground">Block #{block.height}</h1>

      <div className="space-y-4 rounded-2xl border border-border bg-surface p-6">
        <DetailRow label="Hash" value={block.hash} onCopy={() => handleCopy(block.hash, 'hash')} copied={copied === 'hash'} />
        <DetailRow label="Parent hash" value={block.parent_hash} onCopy={() => handleCopy(block.parent_hash, 'parent')} copied={copied === 'parent'} />
        <DetailRow label="Timestamp" value={formatTimestamp(block.timestamp)} />
        <DetailRow label="State root" value={block.state_root} onCopy={() => handleCopy(block.state_root, 'state')} copied={copied === 'state'} />
        <DetailRow label="Tx root" value={block.tx_root} onCopy={() => handleCopy(block.tx_root, 'tx')} copied={copied === 'tx'} />
        <DetailRow label="Proposer" value={block.proposer} onCopy={() => handleCopy(block.proposer, 'proposer')} copied={copied === 'proposer'} />
        <DetailRow label="Transaction count" value={block.tx_count.toString()} />
      </div>

      {block.transactions.length > 0 && (
        <div className="rounded-2xl border border-border bg-surface p-6">
          <h2 className="mb-4 font-display text-xl font-semibold tracking-tight text-foreground">
            Transactions ({block.tx_count})
          </h2>
          <div className="space-y-2">
            {block.transactions.map((txHash) => (
              <Link
                key={txHash}
                to={`/tx/${txHash}`}
                className="block rounded-lg border border-border bg-surface-2 p-3 font-mono text-sm text-accent-soft transition-colors hover:border-border-strong"
              >
                {formatHash(txHash, 20)}
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface DetailRowProps {
  label: string;
  value: string;
  onCopy?: () => void;
  copied?: boolean;
}

function DetailRow({ label, value, onCopy, copied }: DetailRowProps) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border pb-3">
      <div className="font-medium text-muted">{label}</div>
      <div className="flex items-center gap-3 text-right font-mono text-foreground">
        <span className="tnum break-all">{value}</span>
        {onCopy && (
          <button
            onClick={onCopy}
            aria-label={`Copy ${label.toLowerCase()}`}
            className="shrink-0 text-xs font-medium text-accent-soft transition-colors hover:text-primary-200"
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
        )}
      </div>
    </div>
  );
}
