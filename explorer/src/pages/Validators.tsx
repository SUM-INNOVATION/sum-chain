import { useState, useEffect } from 'react';
import { provider } from '../utils/provider';
import type { ValidatorSetInfo } from '@sumchain/sdk';

export default function Validators() {
  const [validators, setValidators] = useState<ValidatorSetInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadValidators();
    const interval = setInterval(loadValidators, 5000);
    return () => clearInterval(interval);
  }, []);

  async function loadValidators() {
    try {
      const data = await provider.getValidators();
      setValidators(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load validators:', error);
      setLoading(false);
    }
  }

  if (loading) {
    return <div className="text-center py-20 text-slate-400">Loading validators...</div>;
  }

  if (!validators) {
    return <div className="text-center py-20 text-slate-400">Failed to load validators</div>;
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-white">Validators</h1>
        <div className="text-sm text-slate-400">
          Height: {validators.current_height.toLocaleString()}
        </div>
      </div>

      <div className="grid gap-4">
        {validators.validators.map((validator, index) => (
          <div
            key={validator.address}
            className={`bg-slate-800/50 rounded-lg border p-6 ${
              validator.is_current_proposer
                ? 'border-green-500'
                : 'border-slate-700'
            }`}
          >
            <div className="flex justify-between items-start mb-4">
              <div className="flex items-center gap-3">
                <div className="text-2xl font-bold text-slate-600">#{index}</div>
                {validator.is_current_proposer && (
                  <span className="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-sm font-medium">
                    Current Proposer
                  </span>
                )}
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <div className="text-xs text-slate-400 mb-1">Address</div>
                <div className="font-mono text-white break-all">{validator.address}</div>
              </div>
              <div>
                <div className="text-xs text-slate-400 mb-1">Public Key</div>
                <div className="font-mono text-sm text-slate-300 break-all">
                  {validator.public_key}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
        <h2 className="text-lg font-bold text-white mb-4">Consensus Information</h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-slate-400">Total Validators</div>
            <div className="text-white font-bold">{validators.validators.length}</div>
          </div>
          <div>
            <div className="text-slate-400">Current Proposer Index</div>
            <div className="text-white font-bold">{validators.current_proposer_index}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
