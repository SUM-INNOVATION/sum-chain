import { useState, useEffect, useCallback } from 'react';
import { provider } from '../utils/provider';
import { RowSkeleton, ErrorState } from '../components/States';
import type { ValidatorSetInfo } from '@sumchain/sdk';

export default function Validators() {
  const [validators, setValidators] = useState<ValidatorSetInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const loadValidators = useCallback(async () => {
    try {
      const data = await provider.getValidators();
      setValidators(data);
      setError(false);
    } catch (err) {
      console.error('Failed to load validators:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadValidators();
    const interval = setInterval(loadValidators, 5000);
    return () => clearInterval(interval);
  }, [loadValidators]);

  if (loading) {
    return (
      <div className="mx-auto max-w-6xl space-y-4">
        <div className="h-9 w-48 skeleton rounded-md" />
        {Array.from({ length: 3 }).map((_, i) => (
          <RowSkeleton key={i} />
        ))}
      </div>
    );
  }

  if (error || !validators) {
    return (
      <div className="py-20">
        <ErrorState
          message="Could not load the validator set. Try again in a moment."
          onRetry={() => {
            setLoading(true);
            loadValidators();
          }}
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="font-display text-3xl font-semibold tracking-tight text-foreground">Validators</h1>
        <div className="tnum text-sm text-muted">
          Height: {validators.current_height.toLocaleString()}
        </div>
      </div>

      <div className="grid gap-4">
        {validators.validators.map((validator, index) => (
          <div
            key={validator.address}
            className={`rounded-2xl border bg-surface p-6 ${
              validator.is_current_proposer ? 'border-primary-500/60' : 'border-border'
            }`}
          >
            <div className="mb-4 flex items-center gap-3">
              <div className="tnum font-display text-2xl font-semibold text-muted">#{index}</div>
              {validator.is_current_proposer && (
                <span className="rounded-full bg-primary-500/20 px-3 py-1 text-sm font-medium text-accent-soft">
                  Current proposer
                </span>
              )}
            </div>

            <div className="space-y-3">
              <div>
                <div className="mb-1 text-xs text-muted">Address</div>
                <div className="break-all font-mono text-foreground">{validator.address}</div>
              </div>
              <div>
                <div className="mb-1 text-xs text-muted">Public key</div>
                <div className="break-all font-mono text-sm text-muted">{validator.public_key}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="rounded-2xl border border-border bg-surface p-6">
        <h2 className="mb-4 font-display text-lg font-semibold tracking-tight text-foreground">Consensus</h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-muted">Total validators</div>
            <div className="tnum font-semibold tracking-tight text-foreground">{validators.validators.length}</div>
          </div>
          <div>
            <div className="text-muted">Current proposer index</div>
            <div className="tnum font-semibold tracking-tight text-foreground">{validators.current_proposer_index}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
