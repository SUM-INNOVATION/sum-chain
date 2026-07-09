'use client';

import { Reveal, StatusPill } from '@/components/ui/primitives';
import { useChainStatus, type FeatureKey } from '@/lib/chainStatus';

/*
  Live network readout. Fixed params are pinned from mainnet chain_getChainParams
  (chain_id 1); activation status is read LIVE from the public RPC on the client
  (chain_getChainParams + chain_getBlockHeight), so a feature flips from
  "pending activation" to "active" automatically the moment the chain crosses its
  gate, no redeploy.
*/

const PARAMS = [
  { k: 'block_time_ms', v: '3000', note: '3s blocks' },
  { k: 'finality_depth', v: '6', note: '~18s to finality' },
  { k: 'min_fee', v: '1000', note: '0.000001 Ϙ minimum' },
  { k: 'assignment_replication_factor', v: '3', note: 'chunk replicas' },
];

const GATES: { label: string; feature: FeatureKey }[] = [
  { label: 'SNIP V2 storage', feature: 'snipV2' },
  { label: 'OmniNode attestation', feature: 'omninodeAttestation' },
  { label: 'Inference settlement', feature: 'inferenceSettlement' },
  { label: 'Governance v1', feature: 'governance' },
];

export default function NetworkStrip() {
  const status = useChainStatus();

  return (
    <section className="border-t border-[var(--border)]">
      <div className="mx-auto max-w-6xl px-6 py-16 lg:px-8">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <p className="kicker">Live network</p>
          <p className="mono text-xs text-muted">
            {status.live
              ? `live · height ${status.height.toLocaleString()}`
              : 'live mainnet params (reconnecting…)'}
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

          {/* Activation gates, status derived live from height vs gate */}
          <Reveal delay={0.08} className="glass rounded-2xl p-6">
            <ul className="flex h-full flex-col justify-center gap-4">
              {GATES.map((g) => {
                const state = status.stateOf(g.feature);
                const gate = status.gateOf(g.feature);
                return (
                  <li key={g.label} className="flex items-center justify-between gap-4">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-foreground">{g.label}</p>
                      <p className="mono truncate text-xs text-muted">
                        {state === 'active'
                          ? `enabled_from_height = ${gate.toLocaleString()}`
                          : `activates at height ${gate.toLocaleString()}`}
                      </p>
                    </div>
                    <StatusPill status={state} />
                  </li>
                );
              })}
            </ul>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
