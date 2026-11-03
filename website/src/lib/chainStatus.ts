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
 * The seven post-supply gates are read one by one from the live chain, by name:
 * `chain_getChainParams` where it exposes the gate (`null` = not set), and
 * `chain_getConsensusConfig` otherwise (`"absent"` = not set). A gate is ACTIVE
 * only when its live value is a height at or below the live head; an unset gate
 * is NOT SET; an unreadable RPC is UNKNOWN, never active. They have no pinned
 * fallback. A live read on 2026-11-03 found all seven unset.
 */

export const RPC_URL = 'https://rpc.sumchain.io';

/**
 * The height #113 states as intended for the seven post-supply gates. It is NOT
 * the live configuration (a live read on 2026-11-03 found all seven unset), and
 * it is never used to derive status; setting it is a separate coordinated
 * configuration change. Shown only where a page names the intended height.
 */
export const POST_SUPPLY_INTENDED_HEIGHT = 9_200_000;

/** Deployed gate values (fallback when the RPC is unreachable). Verified live
 * 2026-07-09 at height 8,916,052: the chain has crossed the 8,900,000 cohort
 * gate, so the whole batch (governance, contracts, archive unbonding /
 * reassignment, inference settlement, education) is ACTIVE. The pinned height
 * stays above that gate so an RPC blip never falsely reverts the UI to pending.
 * The post-supply gates have no pinned value: without a live read they are
 * shown as unknown. */
const PINNED = {
  height: 8_916_052,
  v2: 5_200_000,
  omninode: 6_000_000,
  education: 8_900_000,
};

/** The seven post-supply gates, by the field name the chain reports. */
export const POST_SUPPLY_GATES = {
  sponsoredAttestation: 'omninode_sponsored_attestation_enabled_from_height',
  porAssignmentTargeting: 'por_assignment_targeting_enabled_from_height',
  porBoundedScheduler: 'assignment_aware_por_scheduler_enabled_from_height',
  settlementConsistency: 'inference_settlement_consistency_enabled_from_height',
  verifierBonding: 'inference_verifier_bonding_enabled_from_height',
  serviceGrants: 'service_grants_enabled_from_height',
  monetaryPolicy: 'monetary_policy_enabled_from_height',
} as const;

export type PostSupplyFeature = keyof typeof POST_SUPPLY_GATES;

export type CohortFeature =
  | 'snipV2'
  | 'por'
  | 'omninodeAttestation'
  | 'education'
  | 'contracts'
  | 'archiveUnbonding'
  | 'archiveReassignment'
  | 'inferenceSettlement'
  | 'governance';

export type FeatureKey = CohortFeature | PostSupplyFeature;

export type ActivationState = 'active' | 'pending';

/** Live status of a post-supply gate. */
export type GateStatus = 'active' | 'pending' | 'not-set' | 'unknown';

/** What the chain reports for one gate. */
export type GateReading = { kind: 'set'; height: number } | { kind: 'not-set' } | { kind: 'unknown' };

export interface PostSupplyGate {
  status: GateStatus;
  /** The live gate height when set, else null. */
  height: number | null;
}

export interface ChainStatus {
  /** Live chain height, or the pinned fallback. */
  height: number;
  /** True while the first live fetch is in flight (fallbacks are shown meanwhile). */
  loading: boolean;
  /** True if the last live fetch succeeded. */
  live: boolean;
  /** Activation gate height for a cohort feature (from RPC where exposed, else the education gate). */
  gateOf: (f: CohortFeature) => number;
  /** ACTIVE if height >= gate, else PENDING. */
  stateOf: (f: CohortFeature) => ActivationState;
  /** Live status of a post-supply gate; never active without a live read. */
  postSupplyOf: (f: PostSupplyFeature) => PostSupplyGate;
}

export function isPostSupplyFeature(f: FeatureKey): f is PostSupplyFeature {
  return Object.prototype.hasOwnProperty.call(POST_SUPPLY_GATES, f);
}

/** A non-negative integer height from a number or a decimal string, else null. */
function toHeight(v: unknown): number | null {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return v;
  if (typeof v === 'string' && /^\d+$/.test(v)) {
    const n = Number(v);
    return Number.isSafeInteger(n) ? n : null;
  }
  return null;
}

/** Minimal shape of `chain_getConsensusConfig` that the gate reading uses. */
export interface ConsensusConfigLike {
  matches_baseline?: boolean | null;
  fields?: { name?: unknown; value?: unknown }[];
}

/**
 * Read one gate by name. `chain_getChainParams` reports `null` for an unset gate
 * it exposes; `chain_getConsensusConfig` reports `"absent"`. The consensus
 * fields are the node's recorded baseline, so they are used only while the node
 * reports that its running configuration matches it. If both sources report the
 * gate and disagree, the reading is unknown.
 */
export function readGate(
  name: string,
  params: Record<string, unknown> | null,
  config: ConsensusConfigLike | null,
): GateReading {
  let fromParams: GateReading | null = null;
  if (params && Object.prototype.hasOwnProperty.call(params, name)) {
    const v = params[name];
    const h = toHeight(v);
    fromParams = v === null ? { kind: 'not-set' } : h != null ? { kind: 'set', height: h } : { kind: 'unknown' };
  }
  let fromConfig: GateReading | null = null;
  if (config && config.matches_baseline === true && Array.isArray(config.fields)) {
    const field = config.fields.find((f) => f?.name === name);
    if (field) {
      const h = toHeight(field.value);
      fromConfig =
        field.value === 'absent' ? { kind: 'not-set' } : h != null ? { kind: 'set', height: h } : { kind: 'unknown' };
    }
  }
  if (fromParams && fromConfig) {
    const same =
      fromParams.kind === fromConfig.kind &&
      (fromParams.kind !== 'set' || (fromConfig.kind === 'set' && fromParams.height === fromConfig.height));
    return same ? fromParams : { kind: 'unknown' };
  }
  return fromParams ?? fromConfig ?? { kind: 'unknown' };
}

/** ACTIVE only when the gate is set and the live head has reached it. */
export function gateStatusOf(reading: GateReading, head: number | null): PostSupplyGate {
  if (reading.kind === 'unknown') return { status: 'unknown', height: null };
  if (reading.kind === 'not-set') return { status: 'not-set', height: null };
  if (head == null) return { status: 'unknown', height: reading.height };
  return { status: head >= reading.height ? 'active' : 'pending', height: reading.height };
}

/** Read all seven post-supply gates. */
export function readPostSupplyGates(
  params: Record<string, unknown> | null,
  config: ConsensusConfigLike | null,
): Record<PostSupplyFeature, GateReading> {
  const out = {} as Record<PostSupplyFeature, GateReading>;
  for (const f of Object.keys(POST_SUPPLY_GATES) as PostSupplyFeature[]) {
    out[f] = readGate(POST_SUPPLY_GATES[f], params, config);
  }
  return out;
}

/** Parse a `chain_getBlockHeight` result into a height, or null. */
export function headHeight(head: unknown): number | null {
  if (head && typeof head === 'object' && 'height' in head) return toHeight((head as { height: unknown }).height);
  return null;
}

/** One JSON-RPC call against the public RPC. */
export async function rpcCall<T>(method: string, signal: AbortSignal): Promise<T> {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }),
    signal,
  });
  if (!res.ok) throw new Error(`${method} ${res.status}`);
  const json = await res.json();
  if (json.error) throw new Error(`${method}: ${json.error.message ?? 'rpc error'}`);
  return json.result as T;
}

const UNKNOWN_POST_SUPPLY = readPostSupplyGates(null, null);

interface Raw {
  height: number;
  v2: number;
  omninode: number;
  education: number;
  live: boolean;
  /** Live head for the post-supply gates; null without a live read. */
  liveHead: number | null;
  postSupply: Record<PostSupplyFeature, GateReading>;
}

function gateFor(f: CohortFeature, raw: Raw): number {
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

async function fetchRaw(signal: AbortSignal, withConfig: boolean): Promise<Raw> {
  const [params, head, config] = await Promise.all([
    rpcCall<Record<string, unknown> | null>('chain_getChainParams', signal),
    rpcCall<{ height?: unknown } | null>('chain_getBlockHeight', signal),
    // Only fetched where a post-supply gate is shown (the response is large).
    // Optional: a node without it still serves the other reads; the gates it
    // alone reports then stay unknown.
    withConfig
      ? rpcCall<ConsensusConfigLike | null>('chain_getConsensusConfig', signal).catch(() => null)
      : Promise.resolve(null),
  ]);
  const liveHead = headHeight(head);
  return {
    height: liveHead ?? PINNED.height,
    v2: Number(params?.v2_enabled_from_height ?? PINNED.v2),
    omninode: Number(params?.omninode_enabled_from_height ?? PINNED.omninode),
    education: Number(params?.education_enabled_from_height ?? PINNED.education),
    live: true,
    liveHead,
    postSupply: readPostSupplyGates(params ?? null, config ?? null),
  };
}

/**
 * Live chain status hook. Renders pinned fallbacks immediately (correct as of the
 * last verification), then updates from the live RPC on mount. Post-supply gates
 * are unknown until the live read succeeds; pass `{ postSupply: true }` where
 * they are shown, so `chain_getConsensusConfig` is read too.
 */
export function useChainStatus({ postSupply = false }: { postSupply?: boolean } = {}): ChainStatus {
  const [raw, setRaw] = useState<Raw>({
    height: PINNED.height,
    v2: PINNED.v2,
    omninode: PINNED.omninode,
    education: PINNED.education,
    live: false,
    liveHead: null,
    postSupply: UNKNOWN_POST_SUPPLY,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const ctrl = new AbortController();
    fetchRaw(ctrl.signal, postSupply)
      .then((r) => setRaw(r))
      .catch(() => {
        /* keep pinned fallback; post-supply gates stay unknown */
      })
      .finally(() => setLoading(false));
    return () => ctrl.abort();
  }, [postSupply]);

  return {
    height: raw.height,
    loading,
    live: raw.live,
    gateOf: (f) => gateFor(f, raw),
    stateOf: (f) => (raw.height >= gateFor(f, raw) ? 'active' : 'pending'),
    postSupplyOf: (f) => gateStatusOf(raw.postSupply[f], raw.liveHead),
  };
}

/** Format an activation gate + state into a compact human label. */
export function activationLabel(state: ActivationState, gate: number): string {
  return state === 'active' ? 'active' : `activates at height ${gate.toLocaleString()}`;
}

/** Compact label for a post-supply gate's live status. */
export function postSupplyLabel(g: PostSupplyGate, loading = false): string {
  switch (g.status) {
    case 'active':
      return 'active';
    case 'pending':
      return `set to height ${(g.height ?? 0).toLocaleString('en-US')} · pending`;
    case 'not-set':
      return 'not set on mainnet';
    case 'unknown':
      return loading ? 'checking chain…' : 'status unavailable';
  }
}
