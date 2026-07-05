import { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa, formatTimestamp } from '../utils/formatters';
import { DetailSkeleton, ErrorState, Skeleton } from '../components/States';
import { TransactionTypeBadge, TransactionActionLabel } from '../components/TransactionType';

interface TransactionHistoryEntry {
  tx_hash: string;
  block_height: number;
  tx_index: number;
  from: string;
  to: string;
  amount: string;
  fee: string;
  status: string;
  timestamp: number;
  // Additive, read-time semantic labels (see @sumchain/sdk).
  tx_type?: string;
  action?: string | null;
  asset_ref?: string | null;
  asset_kind?: string | null;
}

interface TransactionHistoryResponse {
  address: string;
  transactions: TransactionHistoryEntry[];
  total_count: number;
  has_more: boolean;
  offset: number;
  limit: number;
}

export default function AddressDetails() {
  const { address } = useParams<{ address: string }>();
  const [balance, setBalance] = useState<bigint | null>(null);
  const [nonce, setNonce] = useState<number | null>(null);
  const [transactions, setTransactions] = useState<TransactionHistoryEntry[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [hasMore, setHasMore] = useState<boolean>(false);
  const [offset, setOffset] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [loadingTxs, setLoadingTxs] = useState(true);
  const limit = 20;

  const loadAddress = useCallback(async () => {
    if (!address) return;
    setLoading(true);
    try {
      const [balanceData, nonceData] = await Promise.all([
        provider.getBalance(address),
        provider.getNonce(address),
      ]);
      setBalance(balanceData);
      setNonce(nonceData);
      setError(false);
    } catch (err) {
      console.error('Failed to load address:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [address]);

  const loadTransactions = useCallback(async () => {
    if (!address) return;
    setLoadingTxs(true);
    try {
      const response = (await (provider as unknown as {
        getTransactionsByAddress: (a: string, l: number, o: number) => Promise<TransactionHistoryResponse>;
      }).getTransactionsByAddress(address, limit, offset));
      setTransactions(response.transactions);
      setTotalCount(response.total_count);
      setHasMore(response.has_more);
    } catch (err) {
      console.error('Failed to load transactions:', err);
      setTransactions([]);
      setTotalCount(0);
      setHasMore(false);
    } finally {
      setLoadingTxs(false);
    }
  }, [address, offset]);

  useEffect(() => {
    loadAddress();
  }, [loadAddress]);

  useEffect(() => {
    loadTransactions();
  }, [loadTransactions]);

  function shortenHash(hash: string): string {
    if (!hash || hash.length < 16) return hash;
    return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
  }

  function shortenAddress(addr: string): string {
    if (!addr || addr.length < 16) return addr || 'Unknown';
    return `${addr.slice(0, 8)}...${addr.slice(-6)}`;
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-6xl space-y-6">
        <Skeleton className="h-9 w-32" />
        <DetailSkeleton rows={3} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="py-20">
        <ErrorState message="Could not load this address." onRetry={loadAddress} />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <h1 className="font-display text-3xl font-bold text-white">Address</h1>

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
        <div className="mb-2 text-sm text-zinc-400">Address</div>
        <div className="mb-6 break-all font-mono text-lg text-white">{address}</div>

        <div className="grid grid-cols-2 gap-6">
          <div>
            <div className="mb-2 text-sm text-zinc-400">Balance</div>
            <div className="tnum font-display text-2xl font-bold text-primary-300">
              {balance !== null ? formatKoppa(balance) : 'Unknown'}
            </div>
          </div>
          <div>
            <div className="mb-2 text-sm text-zinc-400">Nonce</div>
            <div className="tnum font-display text-2xl font-bold text-white">
              {nonce !== null ? nonce.toString() : 'Unknown'}
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-display text-xl font-semibold text-white">
            Transaction history
            {totalCount > 0 && <span className="ml-2 text-sm text-zinc-400">({totalCount} total)</span>}
          </h2>
        </div>

        {loadingTxs ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : transactions.length === 0 ? (
          <div className="rounded-xl border border-dashed border-zinc-800 py-10 text-center text-zinc-500">
            No transactions found for this address.
          </div>
        ) : (
          <>
            {/* Desktop: dense table */}
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-zinc-800 text-left text-sm text-zinc-400">
                    <th className="pb-3 pr-4 font-medium">Tx hash</th>
                    <th className="pb-3 pr-4 font-medium">Type</th>
                    <th className="pb-3 pr-4 font-medium">Block</th>
                    <th className="pb-3 pr-4 font-medium">From</th>
                    <th className="pb-3 pr-4 font-medium">To</th>
                    <th className="pb-3 pr-4 text-right font-medium">Amount</th>
                    <th className="pb-3 pr-4 font-medium">Status</th>
                    <th className="pb-3 font-medium">Time</th>
                  </tr>
                </thead>
                <tbody className="text-sm">
                  {transactions.map((tx) => (
                    <tr key={tx.tx_hash} className="border-b border-zinc-800/60 hover:bg-zinc-800/30">
                      <td className="py-3 pr-4">
                        <Link to={`/tx/${tx.tx_hash}`} className="font-mono text-primary-300 hover:underline">
                          {shortenHash(tx.tx_hash)}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <div className="flex items-center gap-2">
                          <TransactionTypeBadge tx={tx} />
                          <TransactionActionLabel tx={tx} className="whitespace-nowrap text-xs text-zinc-400" />
                        </div>
                      </td>
                      <td className="tnum py-3 pr-4">
                        <Link to={`/block/${tx.block_height}`} className="text-primary-300 hover:underline">
                          {tx.block_height}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <Link
                          to={`/address/${tx.from}`}
                          className={`font-mono ${
                            tx.from === address ? 'text-amber-400' : 'text-zinc-300 hover:text-primary-300'
                          }`}
                        >
                          {tx.from === address ? 'This address' : shortenAddress(tx.from)}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        {tx.to ? (
                          <Link
                            to={`/address/${tx.to}`}
                            className={`font-mono ${
                              tx.to === address ? 'text-amber-400' : 'text-zinc-300 hover:text-primary-300'
                            }`}
                          >
                            {tx.to === address ? 'This address' : shortenAddress(tx.to)}
                          </Link>
                        ) : (
                          <span className="text-zinc-600">—</span>
                        )}
                      </td>
                      <td className="tnum py-3 pr-4 text-right">
                        <span className={tx.from === address ? 'text-red-400' : 'text-green-400'}>
                          {tx.from === address ? '-' : '+'}
                          {formatKoppa(BigInt(tx.amount))}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span
                          className={`rounded px-2 py-1 text-xs ${
                            tx.status.toLowerCase().includes('success')
                              ? 'bg-green-500/20 text-green-400'
                              : 'bg-red-500/20 text-red-400'
                          }`}
                        >
                          {tx.status}
                        </span>
                      </td>
                      <td className="tnum py-3 text-zinc-400">
                        {tx.timestamp ? formatTimestamp(tx.timestamp) : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile: intentional stacked cards, not a squeezed table */}
            <div className="space-y-3 md:hidden">
              {transactions.map((tx) => (
                <Link
                  key={tx.tx_hash}
                  to={`/tx/${tx.tx_hash}`}
                  className="block rounded-xl border border-zinc-800 bg-[#0a0a0a]/60 p-4 transition-colors hover:border-primary-500/50"
                >
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <TransactionTypeBadge tx={tx} />
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        tx.status.toLowerCase().includes('success')
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-red-500/20 text-red-400'
                      }`}
                    >
                      {tx.status}
                    </span>
                  </div>
                  <TransactionActionLabel tx={tx} className="text-sm text-zinc-200" />
                  <div className="mt-2 font-mono text-xs text-zinc-500">{shortenHash(tx.tx_hash)}</div>
                  <div className="mt-2 flex items-center justify-between text-sm">
                    <span className="font-mono text-zinc-400">
                      {tx.from === address ? 'This address' : shortenAddress(tx.from)}
                      {tx.to ? ` → ${tx.to === address ? 'This address' : shortenAddress(tx.to)}` : ''}
                    </span>
                    <span className={`tnum ${tx.from === address ? 'text-red-400' : 'text-green-400'}`}>
                      {tx.from === address ? '-' : '+'}
                      {formatKoppa(BigInt(tx.amount))}
                    </span>
                  </div>
                  <div className="tnum mt-2 text-xs text-zinc-500">
                    Block {tx.block_height}
                    {tx.timestamp ? ` · ${formatTimestamp(tx.timestamp)}` : ''}
                  </div>
                </Link>
              ))}
            </div>

            {(hasMore || offset > 0) && (
              <div className="mt-4 flex justify-center gap-4">
                <button
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                  className={`rounded px-4 py-2 ${
                    offset === 0
                      ? 'cursor-not-allowed bg-zinc-800 text-zinc-600'
                      : 'bg-primary-500 text-white hover:bg-primary-600'
                  }`}
                >
                  Previous
                </button>
                <span className="tnum px-4 py-2 text-zinc-400">
                  Page {Math.floor(offset / limit) + 1}
                </span>
                <button
                  onClick={() => setOffset(offset + limit)}
                  disabled={!hasMore}
                  className={`rounded px-4 py-2 ${
                    !hasMore
                      ? 'cursor-not-allowed bg-zinc-800 text-zinc-600'
                      : 'bg-primary-500 text-white hover:bg-primary-600'
                  }`}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
