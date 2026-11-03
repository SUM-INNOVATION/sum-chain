'use client';

import { StatusPill } from '@/components/ui/primitives';
import {
  useChainStatus,
  activationLabel,
  isPostSupplyFeature,
  postSupplyLabel,
  POST_SUPPLY_GATES,
  type FeatureKey,
  type PostSupplyFeature,
  type PostSupplyGate,
} from '@/lib/chainStatus';

/** Pill for a post-supply gate: active / pending only from a live set value. */
function PostSupplyPill({ gate, loading }: { gate: PostSupplyGate; loading: boolean }) {
  switch (gate.status) {
    case 'active':
      return <StatusPill status="active" />;
    case 'pending':
      return <StatusPill status="pending" label={`Pending · H ${(gate.height ?? 0).toLocaleString()}`} />;
    case 'not-set':
      return <StatusPill status="dormant" label="Not set on mainnet" />;
    case 'unknown':
      return <span className="mono text-xs text-muted">{postSupplyLabel(gate, loading)}</span>;
  }
}

/**
 * A `StatusPill` whose state is read LIVE from the chain, so it flips to
 * "active" automatically once the feature's activation height is reached, no
 * redeploy. Use for any gated protocol surface. A post-supply gate shows active
 * only when the chain reports it set and reached; unset shows "not set", and an
 * unreadable RPC shows "status unavailable", never active.
 */
export function LiveStatus({ feature, className = '' }: { feature: FeatureKey; className?: string }) {
  const s = useChainStatus({ postSupply: isPostSupplyFeature(feature) });
  if (isPostSupplyFeature(feature)) {
    return (
      <span className={className}>
        <PostSupplyPill gate={s.postSupplyOf(feature)} loading={s.loading} />
      </span>
    );
  }
  const state = s.stateOf(feature);
  const label = state === 'active' ? undefined : `Pending · H ${s.gateOf(feature).toLocaleString()}`;
  return (
    <span className={className}>
      <StatusPill status={state} label={label} />
    </span>
  );
}

/**
 * Live status of several post-supply gates, one row per gate, from one read.
 * Each gate is read by its own name, so each row can differ.
 */
export function LivePostSupplyGates({ features }: { features: PostSupplyFeature[] }) {
  const s = useChainStatus({ postSupply: true });
  return (
    <ul className="space-y-2">
      {features.map((f) => (
        <li key={f} className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
          <span className="mono min-w-0 break-all text-xs text-muted">{POST_SUPPLY_GATES[f]}</span>
          <PostSupplyPill gate={s.postSupplyOf(f)} loading={s.loading} />
        </li>
      ))}
    </ul>
  );
}

/** Inline live activation text: "active" or "activates at height 8,900,000". */
export function LiveActivationText({ feature }: { feature: FeatureKey }) {
  const s = useChainStatus({ postSupply: isPostSupplyFeature(feature) });
  if (isPostSupplyFeature(feature)) return <>{postSupplyLabel(s.postSupplyOf(feature), s.loading)}</>;
  return <>{activationLabel(s.stateOf(feature), s.gateOf(feature))}</>;
}
