import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa, formatHash, formatTimeAgo } from '../utils/formatters';
import { RowSkeleton, ErrorState, Skeleton } from '../components/States';
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
    <div className="space-y-8">
      {/* Network Stats */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard title="Block Height" value={health?.current_height?.toLocaleString()} loading={loading} />
        <StatCard title="Chain ID" value={health?.chain_id?.toString()} loading={loading} />
        <StatCard title="Peers" value={health?.peer_count?.toString()} loading={loading} />
        <StatCard title="Version" value={health?.version} loading={loading} accent />
      </div>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
        {/* Latest Blocks */}
        <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
          <h2 className="mb-4 font-display text-xl font-bold text-white">Latest Blocks</h2>
          <div className="space-y-3">
            {loading
              ? Array.from({ length: 6 }).map((_, i) => <RowSkeleton key={i} />)
              : latestBlocks.map((block) => (
                  <Link
                    key={block.height}
                    to={`/block/${block.height}`}
                    className="block rounded-xl border border-zinc-800 bg-[#0a0a0a]/60 p-4 transition-colors hover:border-primary-500/50"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="tnum font-mono text-primary-300">#{block.height}</div>
                        <div className="mt-1 font-mono text-sm text-zinc-500">{formatHash(block.hash)}</div>
                      </div>
                      <div className="text-right">
                        <div className="tnum text-sm text-zinc-400">{block.tx_count} txs</div>
                        <div className="tnum mt-1 text-xs text-zinc-500">{formatTimeAgo(block.timestamp)}</div>
                      </div>
                    </div>
                  </Link>
                ))}
          </div>
        </section>

        {/* Pending Transactions */}
        <section className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
          <h2 className="mb-4 font-display text-xl font-bold text-white">
            Pending Transactions{!loading && ` (${pendingTxs.length})`}
          </h2>
          <div className="space-y-3">
            {loading ? (
              Array.from({ length: 4 }).map((_, i) => <RowSkeleton key={i} />)
            ) : pendingTxs.length === 0 ? (
              <div className="rounded-xl border border-dashed border-zinc-800 py-10 text-center text-zinc-500">
                Mempool is empty. New transactions will appear here.
              </div>
            ) : (
              pendingTxs.map((tx) => (
                <Link
                  key={tx.hash}
                  to={`/tx/${tx.hash}`}
                  className="block rounded-xl border border-zinc-800 bg-[#0a0a0a]/60 p-4 transition-colors hover:border-primary-500/50"
                >
                  <div className="mb-2 font-mono text-xs text-zinc-500">{formatHash(tx.hash, 12)}</div>
                  <div className="flex items-center justify-between text-sm">
                    <div className="font-mono text-zinc-300">
                      {formatHash(tx.from)} to {formatHash(tx.to)}
                    </div>
                    <div className="tnum font-medium text-primary-300">{formatKoppa(tx.amount)}</div>
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
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="mb-2 text-sm text-zinc-400">{title}</div>
      {loading ? (
        <Skeleton className="h-7 w-24" />
      ) : (
        <div className={`tnum font-display text-2xl font-bold ${accent ? 'text-primary-300' : 'text-white'}`}>
          {value ?? 'Unknown'}
        </div>
      )}
    </div>
  );
}
