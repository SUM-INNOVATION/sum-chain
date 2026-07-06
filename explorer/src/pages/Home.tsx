import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa, formatHash, formatTimeAgo } from '../utils/formatters';
import { RowSkeleton, ErrorState, Skeleton } from '../components/States';
import { TransactionTypeBadge, TransactionActionLabel } from '../components/TransactionType';
import type { BlockInfo, TransactionInfo, HealthResponse } from '@sumchain/sdk';

export default function Home() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [latestBlocks, setLatestBlocks] = useState<BlockInfo[]>([]);
  const [pendingTxs, setPendingTxs] = useState<TransactionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [healthData, currentHeight, pending] = await Promise.all([
        provider.getHealth(),
        provider.getBlockNumber(),
        provider.getPendingTransactions(),
      ]);

      setHealth(healthData);
      setPendingTxs(pending.slice(0, 10));

      const blocks: BlockInfo[] = [];
      const startHeight = Math.max(0, currentHeight - 9);
      for (let i = currentHeight; i >= startHeight; i--) {
        const block = await provider.getBlockByHeight(i);
        if (block) blocks.push(block);
      }
      setLatestBlocks(blocks);
      setError(false);
    } catch (err) {
      console.error('Failed to load data:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [loadData]);

  if (error && !health) {
    return (
      <div className="py-20">
        <ErrorState
          message="Could not reach the SUM Chain RPC. Check your connection and try again."
          onRetry={() => {
            setLoading(true);
            loadData();
          }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-10">
      {/* Network Stats */}
      <section>
        <div className="mb-4 flex items-center gap-2">
          <span className="eyebrow">Network</span>
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--pos)]" aria-hidden />
          <span className="text-xs text-muted">live</span>
        </div>
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-border bg-border lg:grid-cols-4">
          <StatCard title="Block Height" value={health?.current_height?.toLocaleString()} loading={loading} />
          <StatCard title="Chain ID" value={health?.chain_id?.toString()} loading={loading} />
          <StatCard title="Peers" value={health?.peer_count?.toString()} loading={loading} />
          <StatCard title="Version" value={health?.version} loading={loading} accent />
        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Latest Blocks */}
        <section className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-border px-5 py-3.5">
            <h2 className="font-display text-sm font-semibold tracking-tight text-foreground">Latest Blocks</h2>
            <span className="eyebrow">newest first</span>
          </div>
          <div className="divide-y divide-border">
            {loading
              ? Array.from({ length: 6 }).map((_, i) => <div key={i} className="px-5 py-3.5"><RowSkeleton /></div>)
              : latestBlocks.map((block) => (
                  <Link
                    key={block.height}
                    to={`/block/${block.height}`}
                    className="flex items-center justify-between px-5 py-3.5 transition-colors hover:bg-surface-2"
                  >
                    <div className="min-w-0">
                      <div className="tnum font-mono text-sm font-medium text-accent-soft">#{block.height}</div>
                      <div className="mt-0.5 truncate font-mono text-xs text-muted">{formatHash(block.hash)}</div>
                    </div>
                    <div className="shrink-0 text-right">
                      <div className="tnum text-sm text-muted-strong">{block.tx_count} txs</div>
                      <div className="tnum mt-0.5 text-xs text-muted">{formatTimeAgo(block.timestamp)}</div>
                    </div>
                  </Link>
                ))}
          </div>
        </section>

        {/* Pending Transactions */}
        <section className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-border px-5 py-3.5">
            <h2 className="font-display text-sm font-semibold tracking-tight text-foreground">Pending Transactions</h2>
            {!loading && <span className="eyebrow">{pendingTxs.length} in mempool</span>}
          </div>
          <div className="divide-y divide-border">
            {loading ? (
              Array.from({ length: 4 }).map((_, i) => <div key={i} className="px-5 py-3.5"><RowSkeleton /></div>)
            ) : pendingTxs.length === 0 ? (
              <div className="px-5 py-12 text-center text-sm text-muted">
                Mempool is empty. New transactions will appear here.
              </div>
            ) : (
              pendingTxs.map((tx) => (
                <Link
                  key={tx.hash}
                  to={`/tx/${tx.hash}`}
                  className="block px-5 py-3.5 transition-colors hover:bg-surface-2"
                >
                  <div className="mb-1.5 flex items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2">
                      <TransactionTypeBadge tx={tx} />
                      <TransactionActionLabel tx={tx} className="truncate text-xs text-muted-strong" />
                    </div>
                    <div className="shrink-0 font-mono text-xs text-muted">{formatHash(tx.hash, 10)}</div>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <div className="min-w-0 truncate font-mono text-xs text-muted">
                      {formatHash(tx.from)}
                      {tx.to ? ` → ${formatHash(tx.to)}` : ''}
                    </div>
                    <div className="tnum shrink-0 font-medium text-foreground">{formatKoppa(tx.amount)}</div>
                  </div>
                </Link>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value?: string;
  loading?: boolean;
  accent?: boolean;
}

function StatCard({ title, value, loading, accent }: StatCardProps) {
  return (
    <div className="bg-surface p-5">
      <div className="eyebrow">{title}</div>
      {loading ? (
        <Skeleton className="mt-2 h-7 w-24" />
      ) : (
        <div className={`tnum mt-1.5 font-display text-2xl font-semibold tracking-tight ${accent ? 'text-accent-soft' : 'text-foreground'}`}>
          {value ?? '—'}
        </div>
      )}
    </div>
  );
}
