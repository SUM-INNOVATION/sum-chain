import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa, formatHash, formatTimeAgo } from '../utils/formatters';
import type { BlockInfo, TransactionInfo, HealthResponse } from '@sumchain/sdk';

export default function Home() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [latestBlocks, setLatestBlocks] = useState<BlockInfo[]>([]);
  const [pendingTxs, setPendingTxs] = useState<TransactionInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000); // Refresh every 3s
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const [healthData, currentHeight, pending] = await Promise.all([
        provider.getHealth(),
        provider.getBlockNumber(),
        provider.getPendingTransactions(),
      ]);

      setHealth(healthData);
      setPendingTxs(pending.slice(0, 10)); // Latest 10

      // Fetch latest 10 blocks
      const blocks: BlockInfo[] = [];
      const startHeight = Math.max(0, currentHeight - 9);
      for (let i = currentHeight; i >= startHeight; i--) {
        const block = await provider.getBlockByHeight(i);
        if (block) blocks.push(block);
      }
      setLatestBlocks(blocks);

      setLoading(false);
    } catch (error) {
      console.error('Failed to load data:', error);
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="text-center py-20">
        <div className="animate-spin w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full mx-auto"></div>
        <p className="mt-4 text-slate-400">Loading explorer...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Network Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Block Height" value={health?.current_height?.toLocaleString() || '0'} />
        <StatCard title="Chain ID" value={health?.chain_id || 'Unknown'} />
        <StatCard title="Peers" value={health?.peer_count?.toString() || '0'} />
        <StatCard
          title="Version"
          value={health?.version || 'Unknown'}
          className="text-green-400"
        />
      </div>

      {/* Latest Blocks and Transactions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Latest Blocks */}
        <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
          <h2 className="text-xl font-bold text-white mb-4">Latest Blocks</h2>
          <div className="space-y-3">
            {latestBlocks.map((block) => (
              <Link
                key={block.height}
                to={`/block/${block.height}`}
                className="block p-4 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-blue-500 transition"
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className="text-blue-400 font-mono">#{block.height}</div>
                    <div className="text-sm text-slate-400 mt-1">
                      {formatHash(block.hash)}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm text-slate-400">{block.tx_count} txs</div>
                    <div className="text-xs text-slate-500 mt-1">
                      {formatTimeAgo(block.timestamp)}
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
          <Link
            to="/validators"
            className="block mt-4 text-center text-blue-400 hover:text-blue-300 transition"
          >
            View All Blocks →
          </Link>
        </div>

        {/* Pending Transactions */}
        <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
          <h2 className="text-xl font-bold text-white mb-4">
            Pending Transactions ({pendingTxs.length})
          </h2>
          <div className="space-y-3">
            {pendingTxs.length === 0 ? (
              <div className="text-center py-8 text-slate-500">
                No pending transactions
              </div>
            ) : (
              pendingTxs.map((tx) => (
                <Link
                  key={tx.hash}
                  to={`/tx/${tx.hash}`}
                  className="block p-4 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-blue-500 transition"
                >
                  <div className="text-xs text-slate-400 font-mono mb-2">
                    {formatHash(tx.hash, 12)}
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <div className="text-slate-300">
                      {formatHash(tx.from)} → {formatHash(tx.to)}
                    </div>
                    <div className="text-cyan-400">
                      {formatKoppa(tx.amount)}
                    </div>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string;
  className?: string;
}

function StatCard({ title, value, className }: StatCardProps) {
  return (
    <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
      <div className="text-sm text-slate-400 mb-2">{title}</div>
      <div className={`text-2xl font-bold ${className || 'text-white'}`}>
        {value}
      </div>
    </div>
  );
}
