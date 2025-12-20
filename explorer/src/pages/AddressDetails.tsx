import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa } from '../utils/formatters';

export default function AddressDetails() {
  const { address } = useParams<{ address: string }>();
  const [balance, setBalance] = useState<bigint | null>(null);
  const [nonce, setNonce] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAddress();
  }, [address]);

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

  if (loading) {
    return <div className="text-center py-20 text-slate-400">Loading address...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
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

      <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 text-center text-slate-500">
        Transaction history coming soon...
      </div>
    </div>
  );
}
