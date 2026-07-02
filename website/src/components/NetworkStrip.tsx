'use client';

import { Reveal, StatusPill } from '@/components/ui/primitives';

/*
  Live network readout. Values are pinned from live mainnet chain_getChainParams
  (chain_id 1) — verified at the height/date below, not inferred from repo genesis
  defaults. Update the note if re-verified.
*/

const PARAMS = [
  { k: 'block_time_ms', v: '3000', note: '3s blocks' },
  { k: 'finality_depth', v: '6', note: '~18s to finality' },
  { k: 'min_fee', v: '1000', note: '0.000001 Ϙ minimum' },
  { k: 'assignment_replication_factor', v: '3', note: 'chunk replicas' },
];

const GATES: { label: string; tag: string; status: 'active' | 'dormant' }[] = [
  { label: 'SNIP V2 storage', tag: 'v2_enabled_from_height = 5,200,000', status: 'active' },
  { label: 'OmniNode attestation', tag: 'omninode_enabled_from_height = 6,000,000', status: 'active' },
  { label: 'Governance v1', tag: 'not configured on mainnet', status: 'dormant' },
];

export default function NetworkStrip() {
  return (
    <section className="border-t border-[var(--border)]">
      <div className="mx-auto max-w-6xl px-6 py-16 lg:px-8">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <p className="kicker">Live network</p>
          <p className="mono text-xs text-muted">
            live mainnet params verified at height 8,183,329 · 2026-07-02
          </p>
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-2">
          {/* Params */}
          <Reveal className="glass rounded-2xl p-6">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-6">
              {PARAMS.map((p) => (
                <div key={p.k}>
                  <dt className="mono truncate text-xs text-muted">{p.k}</dt>
                  <dd className="tnum mt-1 font-[family-name:var(--font-display)] text-2xl font-semibold text-foreground">
                    {p.v}
                  </dd>
                  <dd className="mt-0.5 text-xs text-muted">{p.note}</dd>
                </div>
              ))}
            </dl>
          </Reveal>

          {/* Activation gates */}
          <Reveal delay={0.08} className="glass rounded-2xl p-6">
            <ul className="flex h-full flex-col justify-center gap-4">
              {GATES.map((g) => (
                <li key={g.label} className="flex items-center justify-between gap-4">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground">{g.label}</p>
                    <p className="mono truncate text-xs text-muted">{g.tag}</p>
                  </div>
                  <StatusPill status={g.status} />
                </li>
              ))}
            </ul>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
