'use client';

import { useEffect, useState } from 'react';

/**
 * Live activation status for SUM Chain mainnet.
 *
 * A feature is ACTIVE once the live chain height reaches its activation gate, and
 * PENDING before that. This is computed from the live public RPC
 * (`chain_getChainParams` + `chain_getBlockHeight`) on the client, so the site
 * **auto-flips** the moment the chain crosses a gate, no redeploy.
 *
 * `chain_getChainParams` only exposes `v2`, `omninode`, and `education` gates.
 * The rest of the batch-activated cohort (contracts, archive unbonding /
 * reassignment, inference settlement, governance) shares the **education** gate's
 * height on the deployed genesis, so the live `education_enabled_from_height` is
 * used as the cohort's activation height. Pinned fallbacks (below) keep the page
 * correct if the RPC is briefly unreachable.
 */

export const RPC_URL = 'https://rpc.sumchain.io';

/** Deployed gate values (fallback when the RPC is unreachable). Verified live
 * 2026-07-09 at height 8,916,052: the chain has crossed the 8,900,000 cohort
 * gate, so the whole batch (governance, contracts, archive unbonding /
 * reassignment, inference settlement, education) is ACTIVE. The pinned height
 * stays above that gate so an RPC blip never falsely reverts the UI to pending. */
const PINNED = {
  height: 8_916_052,
  v2: 5_200_000,
  omninode: 6_000_000,
  education: 8_900_000,
};

export type FeatureKey =
  | 'snipV2'
  | 'por'
  | 'omninodeAttestation'
  | 'education'
  | 'contracts'
  | 'archiveUnbonding'
  | 'archiveReassignment'
  | 'inferenceSettlement'
  | 'governance';

export type ActivationState = 'active' | 'pending';

export interface ChainStatus {
  /** Live chain height, or the pinned fallback. */
  height: number;
  /** True while the first live fetch is in flight (fallbacks are shown meanwhile). */
  loading: boolean;
  /** True if the last live fetch succeeded. */
  live: boolean;
  /** Activation gate height for a feature (from RPC where exposed, else the cohort/education gate). */
  gateOf: (f: FeatureKey) => number;
  /** ACTIVE if height >= gate, else PENDING. */
  stateOf: (f: FeatureKey) => ActivationState;
}

interface Raw {
  height: number;
  v2: number;
  omninode: number;
  education: number;
  live: boolean;
}

function gateFor(f: FeatureKey, raw: Raw): number {
  switch (f) {
    case 'snipV2':
    case 'por':
      return raw.v2;
    case 'omninodeAttestation':
      return raw.omninode;
    // Education is the RPC-exposed member of the batch-activated cohort; the
    // others share its height on the deployed genesis.
    case 'education':
    case 'contracts':
    case 'archiveUnbonding':
    case 'archiveReassignment':
    case 'inferenceSettlement':
    case 'governance':
      return raw.education;
  }
}

async function fetchRaw(signal: AbortSignal): Promise<Raw> {
  const call = async (method: string) => {
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }),
      signal,
    });
    if (!res.ok) throw new Error(`${method} ${res.status}`);
    const json = await res.json();
    if (json.error) throw new Error(`${method}: ${json.error.message ?? 'rpc error'}`);
    return json.result;
  };
  const [params, head] = await Promise.all([
    call('chain_getChainParams'),
    call('chain_getBlockHeight'),
  ]);
  return {
    height: Number(head?.height ?? PINNED.height),
    v2: Number(params?.v2_enabled_from_height ?? PINNED.v2),
    omninode: Number(params?.omninode_enabled_from_height ?? PINNED.omninode),
    education: Number(params?.education_enabled_from_height ?? PINNED.education),
    live: true,
  };
}

/**
 * Live chain status hook. Renders pinned fallbacks immediately (correct as of the
 * last verification), then updates from the live RPC on mount.
 */
export function useChainStatus(): ChainStatus {
  const [raw, setRaw] = useState<Raw>({
    height: PINNED.height,
    v2: PINNED.v2,
    omninode: PINNED.omninode,
    education: PINNED.education,
    live: false,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const ctrl = new AbortController();
    fetchRaw(ctrl.signal)
      .then((r) => setRaw(r))
      .catch(() => {
        /* keep pinned fallback */
      })
      .finally(() => setLoading(false));
    return () => ctrl.abort();
  }, []);

  return {
    height: raw.height,
    loading,
    live: raw.live,
    gateOf: (f) => gateFor(f, raw),
    stateOf: (f) => (raw.height >= gateFor(f, raw) ? 'active' : 'pending'),
  };
}

/** Format an activation gate + state into a compact human label. */
export function activationLabel(state: ActivationState, gate: number): string {
  return state === 'active' ? 'active' : `activates at height ${gate.toLocaleString()}`;
}
