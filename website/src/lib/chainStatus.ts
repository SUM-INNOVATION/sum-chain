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
 *
 * A separate cohort of seven gates was added to runtime genesis AFTER the 8.9M
 * batch and activates together at height 9,200,000 (see `POST_SUPPLY_GATE`).
 * `chain_getChainParams` does NOT expose every one of these, so the site uses
 * the operator-verified runtime-genesis value as the gate height rather than
 * inferring null/dormant from a missing RPC field. Active/pending is still
 * derived from the LIVE block height, so the UI auto-flips to active the moment
 * the chain crosses 9,200,000, with no redeploy.
 */

export const RPC_URL = 'https://rpc.sumchain.io';

/**
 * Operator-verified runtime-genesis activation height for the seven post-supply
 * gates, deployed and scheduled to activate together at this height:
 *   - omninode_sponsored_attestation_enabled_from_height
 *   - por_assignment_targeting_enabled_from_height
 *   - assignment_aware_por_scheduler_enabled_from_height
 *   - inference_settlement_consistency_enabled_from_height
 *   - inference_verifier_bonding_enabled_from_height
 *   - service_grants_enabled_from_height
 *   - monetary_policy_enabled_from_height
 * `chain_getChainParams` does not expose all of these, so this constant is the
 * source of truth for their activation height; active/pending is decided by the
 * live block height (`liveHeight >= POST_SUPPLY_GATE`).
 */
export const POST_SUPPLY_GATE = 9_200_000;

/** Deployed gate values (fallback when the RPC is unreachable). Verified live
 * 2026-07-09 at height 8,916,052: the chain has crossed the 8,900,000 cohort
 * gate, so the whole batch (governance, contracts, archive unbonding /
 * reassignment, inference settlement, education) is ACTIVE. The pinned height
 * stays above that gate so an RPC blip never falsely reverts the UI to pending.
 * The post-supply cohort (9,200,000) is still ahead of the live height, so the
 * pinned fallback correctly shows it pending; once the live chain crosses
 * 9,200,000 the live height flips it to active automatically. */
const PINNED = {
  height: 8_916_052,
  v2: 5_200_000,
  omninode: 6_000_000,
  education: 8_900_000,
  postSupply: POST_SUPPLY_GATE,
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
  | 'governance'
  // Post-supply cohort (all activate at POST_SUPPLY_GATE = 9,200,000).
  | 'sponsoredAttestation'
  | 'porAssignmentTargeting'
  | 'porBoundedScheduler'
  | 'settlementConsistency'
  | 'verifierBonding'
  | 'serviceGrants'
  | 'monetaryPolicy';

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
  postSupply: number;
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
    // Post-supply cohort: operator-verified runtime-genesis height 9,200,000,
    // not exposed (fully) by chain_getChainParams. Active/pending still derives
    // from raw.height below, so the UI auto-flips at the gate.
    case 'sponsoredAttestation':
    case 'porAssignmentTargeting':
    case 'porBoundedScheduler':
    case 'settlementConsistency':
    case 'verifierBonding':
    case 'serviceGrants':
    case 'monetaryPolicy':
      return raw.postSupply;
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
    // Operator-verified constant; chain_getChainParams does not reliably expose
    // the post-supply cohort, so the gate height is never read from RPC.
    postSupply: PINNED.postSupply,
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
    postSupply: PINNED.postSupply,
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
