import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa, formatTimestamp } from '../utils/formatters';

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
  const [loadingTxs, setLoadingTxs] = useState(true);
  const limit = 20;

  useEffect(() => {
    loadAddress();
  }, [address]);

  useEffect(() => {
    loadTransactions();
  }, [address, offset]);

  async function loadAddress() {
    if (!address) return;

    try {
      const [balanceData, nonceData] = await Promise.all([
        provider.getBalance(address),
        provider.getNonce(address),
      ]);
      setBalance(balanceData);
      setNonce(nonceData);
    } catch (error) {
      console.error('Failed to load address:', error);
    } finally {
      setLoading(false);
    }
  }

  async function loadTransactions() {
    if (!address) return;

    setLoadingTxs(true);
    try {
      // Use the provider's getTransactionsByAddress method
      const response = await (provider as any).getTransactionsByAddress(address, limit, offset) as TransactionHistoryResponse;
      setTransactions(response.transactions);
      setTotalCount(response.total_count);
      setHasMore(response.has_more);
    } catch (error) {
      console.error('Failed to load transactions:', error);
      // If RPC method not available, show empty state
      setTransactions([]);
      setTotalCount(0);
      setHasMore(false);
    } finally {
      setLoadingTxs(false);
    }
  }

  function shortenHash(hash: string): string {
    if (!hash || hash.length < 16) return hash;
    return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
  }

  function shortenAddress(addr: string): string {
    if (!addr || addr.length < 16) return addr || '—';
    return `${addr.slice(0, 8)}...${addr.slice(-6)}`;
  }

  if (loading) {
    return <div className="text-center py-20 text-slate-400">Loading address...</div>;
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <h1 className="text-3xl font-bold text-white">Address</h1>

      <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
        <div className="text-sm text-slate-400 mb-2">Address</div>
        <div className="font-mono text-white break-all text-lg mb-6">{address}</div>

        <div className="grid grid-cols-2 gap-6">
          <div>
            <div className="text-sm text-slate-400 mb-2">Balance</div>
            <div className="text-2xl font-bold text-cyan-400">
              {balance !== null ? formatKoppa(balance) : '—'}
            </div>
          </div>
          <div>
            <div className="text-sm text-slate-400 mb-2">Nonce</div>
            <div className="text-2xl font-bold text-white">
              {nonce !== null ? nonce.toString() : '—'}
            </div>
          </div>
        </div>
      </div>

      {/* Transaction History */}
      <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-white">
            Transaction History
            {totalCount > 0 && (
              <span className="ml-2 text-sm text-slate-400">({totalCount} total)</span>
            )}
          </h2>
        </div>

        {loadingTxs ? (
          <div className="text-center py-10 text-slate-400">Loading transactions...</div>
        ) : transactions.length === 0 ? (
          <div className="text-center py-10 text-slate-500">No transactions found</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-sm text-slate-400 border-b border-slate-700">
                    <th className="pb-3 pr-4">Tx Hash</th>
                    <th className="pb-3 pr-4">Block</th>
                    <th className="pb-3 pr-4">From</th>
                    <th className="pb-3 pr-4">To</th>
                    <th className="pb-3 pr-4 text-right">Amount</th>
                    <th className="pb-3 pr-4">Status</th>
                    <th className="pb-3">Time</th>
                  </tr>
                </thead>
                <tbody className="text-sm">
                  {transactions.map((tx) => (
                    <tr
                      key={tx.tx_hash}
                      className="border-b border-slate-700/50 hover:bg-slate-700/30"
                    >
                      <td className="py-3 pr-4">
                        <Link
                          to={`/tx/${tx.tx_hash}`}
                          className="font-mono text-cyan-400 hover:underline"
                        >
                          {shortenHash(tx.tx_hash)}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <Link
                          to={`/block/${tx.block_height}`}
                          className="text-cyan-400 hover:underline"
                        >
                          {tx.block_height}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <Link
                          to={`/address/${tx.from}`}
                          className={`font-mono ${
                            tx.from === address ? 'text-yellow-400' : 'text-slate-300 hover:text-cyan-400'
                          }`}
                        >
                          {tx.from === address ? 'This Address' : shortenAddress(tx.from)}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <Link
                          to={`/address/${tx.to}`}
                          className={`font-mono ${
                            tx.to === address ? 'text-yellow-400' : 'text-slate-300 hover:text-cyan-400'
                          }`}
                        >
                          {tx.to === address ? 'This Address' : shortenAddress(tx.to)}
                        </Link>
                      </td>
                      <td className="py-3 pr-4 text-right">
                        <span className={tx.from === address ? 'text-red-400' : 'text-green-400'}>
                          {tx.from === address ? '-' : '+'}
                          {formatKoppa(BigInt(tx.amount))}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span
                          className={`px-2 py-1 rounded text-xs ${
                            tx.status.toLowerCase().includes('success')
                              ? 'bg-green-500/20 text-green-400'
                              : 'bg-red-500/20 text-red-400'
                          }`}
                        >
                          {tx.status}
                        </span>
                      </td>
                      <td className="py-3 text-slate-400">
                        {tx.timestamp ? formatTimestamp(tx.timestamp) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {(hasMore || offset > 0) && (
              <div className="flex justify-center gap-4 mt-4">
                <button
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                  className={`px-4 py-2 rounded ${
                    offset === 0
                      ? 'bg-slate-700 text-slate-500 cursor-not-allowed'
                      : 'bg-cyan-600 text-white hover:bg-cyan-500'
                  }`}
                >
                  Previous
                </button>
                <span className="px-4 py-2 text-slate-400">
                  Page {Math.floor(offset / limit) + 1}
                </span>
                <button
                  onClick={() => setOffset(offset + limit)}
                  disabled={!hasMore}
                  className={`px-4 py-2 rounded ${
                    !hasMore
                      ? 'bg-slate-700 text-slate-500 cursor-not-allowed'
                      : 'bg-cyan-600 text-white hover:bg-cyan-500'
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
