'use client';

import { StatusPill } from '@/components/ui/primitives';
import { useChainStatus, activationLabel, type FeatureKey } from '@/lib/chainStatus';

/**
 * A `StatusPill` whose active/pending state is read LIVE from the chain, so it
 * flips to "active" automatically once the feature's activation height is
 * reached, no redeploy. Use for any gated protocol surface.
 */
export function LiveStatus({ feature, className = '' }: { feature: FeatureKey; className?: string }) {
  const s = useChainStatus();
  const state = s.stateOf(feature);
  const label = state === 'active' ? undefined : `Pending · H ${s.gateOf(feature).toLocaleString()}`;
  return (
    <span className={className}>
      <StatusPill status={state} label={label} />
    </span>
  );
}

/** Inline live activation text: "active" or "activates at height 8,900,000". */
export function LiveActivationText({ feature }: { feature: FeatureKey }) {
  const s = useChainStatus();
  return <>{activationLabel(s.stateOf(feature), s.gateOf(feature))}</>;
}
