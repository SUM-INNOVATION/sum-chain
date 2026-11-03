'use client';

import { useEffect, useState } from 'react';
import {
  POST_SUPPLY_INTENDED_HEIGHT,
  gateStatusOf,
  headHeight,
  readGate,
  rpcCall as rpc,
  POST_SUPPLY_GATES,
  type ConsensusConfigLike,
  type GateReading,
} from '@/lib/chainStatus';

const BASE = BigInt(1_000_000_000); // 1 Koppa in base units

/**
 * Live supply / protocol-reserve / governance-configuration status.
 *
 * Sources (all read-only, public RPC):
 * - `chain_getSupplyInfo`     , canonical/accounted/burned/reserve/mint totals + migration status
 * - `chain_getProtocolReserve`, per-pool reserve balances (null before the correction)
 * - `chain_getChainParams`    , governance/monetary/service-grant gates + configured governance params
 * - `chain_getConsensusConfig`, the same gates by name (`"absent"` = not set), cross-checked
 *
 * HONESTY RULES (load-bearing):
 * - No live number is invented. If the RPC (or a method, e.g. a node that
 *   pre-dates the supply correction) is unavailable, the hook reports
 *   `supplyAvailable: false` and the UI must show an explicit unavailable state.
 * - Gate status is CONFIGURATION derived from chain params + live height, it is
 *   labeled as such, never presented as live participation data.
 * - A post-supply gate (monetary policy, service grants) is active only when the
 *   chain reports it set and the live head has reached it; unset is "not set",
 *   unreadable is "unknown", never active.
 */

export interface SupplyInfo {
  initial_canonical_supply: string;
  current_canonical_supply: string;
  accounted_account_supply: string;
  burned_supply: string;
  protocol_reserve_remaining: string;
  outstanding_grant_unclaimed: string;
  total_minted_by_migration: string;
  total_minted_by_governance: string;
  migration_id: string;
  migration_applied: boolean;
  migration_activation_height: number;
  automatic_emissions_enabled: boolean;
}

export interface ProtocolReserveInfo {
  validator_pool_remaining: string;
  archive_pool_remaining: string;
  compute_pool_remaining: string;
  ecosystem_pool_remaining: string;
  governance_reserve_remaining: string;
  total_remaining: string;
}

export interface GovernanceParamsInfo {
  validator_authority_threshold_bps: number;
  quorum_bps: number;
  pass_threshold_bps: number;
  voting_period_blocks: number;
  max_snapshot_holders: number;
  min_koppa_for_eligibility: string;
  proposal_bond: string;
  treasury_configured: boolean;
}

export interface GovGates {
  height: number | null;
  governance_enabled_from_height: number | null;
  governance: GovernanceParamsInfo | null;
}

export type GateState = 'active' | 'pending' | 'dormant' | 'not-set' | 'unknown';

/** The two post-supply gates the supply / governance dashboards show. */
export type SupplyGate = 'serviceGrants' | 'monetaryPolicy';

export interface SupplyGateStatus {
  state: GateState;
  /** The live gate height when set, else null. */
  height: number | null;
}

export interface SupplyStatus {
  /** True while the first fetch is in flight. */
  loading: boolean;
  /** True if `chain_getSupplyInfo` responded (node runs the supply-aware binary). */
  supplyAvailable: boolean;
  /** True if `chain_getChainParams` responded. */
  paramsAvailable: boolean;
  supply: SupplyInfo | null;
  reserve: ProtocolReserveInfo | null;
  gates: GovGates;
  /** What the chain reports for the two post-supply gates shown here. */
  supplyGates: Record<SupplyGate, GateReading>;
  /** Configuration-derived gate state (NOT live participation data). */
  gateState: (gate: number | null) => GateState;
  /** Live status of a post-supply gate; never active without a live read. */
  supplyGateStatus: (g: SupplyGate) => SupplyGateStatus;
}

const EMPTY_GATES: GovGates = {
  height: null,
  governance_enabled_from_height: null,
  governance: null,
};

const UNKNOWN_SUPPLY_GATES: Record<SupplyGate, GateReading> = {
  serviceGrants: { kind: 'unknown' },
  monetaryPolicy: { kind: 'unknown' },
};

/** Format a base-unit decimal string as whole Koppa with thousands separators. */
export function koppa(baseUnits: string | null | undefined): string {
  if (baseUnits == null) return 'n/a';
  try {
    const v = BigInt(baseUnits);
    const whole = v / BASE;
    return whole.toLocaleString('en-US');
  } catch {
    return 'n/a';
  }
}

/** Compact Koppa: 800B, 799B, 1B, 120B, 40,000 … (whole-Koppa granularity). */
export function koppaCompact(baseUnits: string | null | undefined): string {
  if (baseUnits == null) return 'n/a';
  try {
    const whole = Number(BigInt(baseUnits) / BASE);
    if (whole >= 1_000_000_000) return `${(whole / 1_000_000_000).toLocaleString('en-US', { maximumFractionDigits: 1 })}B`;
    if (whole >= 1_000_000) return `${(whole / 1_000_000).toLocaleString('en-US', { maximumFractionDigits: 1 })}M`;
    return whole.toLocaleString('en-US');
  } catch {
    return 'n/a';
  }
}

/**
 * Human label for a post-supply gate from its live status:
 * `height N · active|pending` when set, `not set (intended 9,200,000, #113)`
 * when unset, `status unavailable` when the RPC could not be read. The intended
 * height is the one #113 states; it is not the live configuration.
 */
export function postSupplyGateLabel(g: SupplyGateStatus): string {
  switch (g.state) {
    case 'active':
    case 'pending':
      return `height ${(g.height ?? 0).toLocaleString('en-US')} · ${g.state}`;
    case 'not-set':
      return `not set (intended ${POST_SUPPLY_INTENDED_HEIGHT.toLocaleString('en-US')}, #113)`;
    default:
      return 'status unavailable';
  }
}

export function useSupplyStatus(): SupplyStatus {
  const [state, setState] = useState<Omit<SupplyStatus, 'gateState' | 'supplyGateStatus'>>({
    loading: true,
    supplyAvailable: false,
    paramsAvailable: false,
    supply: null,
    reserve: null,
    gates: EMPTY_GATES,
    supplyGates: UNKNOWN_SUPPLY_GATES,
  });

  useEffect(() => {
    const ctrl = new AbortController();
    (async () => {
      // Each source degrades independently: a node without the supply-aware
      // binary still serves chain params, and vice versa.
      const [supply, reserve, params, head, config] = await Promise.all([
        rpc<SupplyInfo>('chain_getSupplyInfo', ctrl.signal).catch(() => null),
        rpc<ProtocolReserveInfo | null>('chain_getProtocolReserve', ctrl.signal).catch(() => null),
        rpc<Record<string, unknown>>('chain_getChainParams', ctrl.signal).catch(() => null),
        rpc<{ height: number }>('chain_getBlockHeight', ctrl.signal).catch(() => null),
        rpc<ConsensusConfigLike>('chain_getConsensusConfig', ctrl.signal).catch(() => null),
      ]);
      if (ctrl.signal.aborted) return;
      const num = (v: unknown): number | null => (typeof v === 'number' ? v : null);
      const liveHead = headHeight(head);
      setState({
        loading: false,
        supplyAvailable: supply != null,
        paramsAvailable: params != null,
        supply,
        reserve,
        gates: params
          ? {
              height: liveHead,
              governance_enabled_from_height: num(params.governance_enabled_from_height),
              governance: (params.governance as GovernanceParamsInfo | undefined) ?? null,
            }
          : { ...EMPTY_GATES, height: liveHead },
        supplyGates: {
          serviceGrants: readGate(POST_SUPPLY_GATES.serviceGrants, params, config),
          monetaryPolicy: readGate(POST_SUPPLY_GATES.monetaryPolicy, params, config),
        },
      });
    })();
    return () => ctrl.abort();
  }, []);

  const gateState = (gate: number | null): GateState => {
    if (!state.paramsAvailable) return 'unknown';
    if (gate == null) return 'dormant';
    if (state.gates.height == null) return 'pending';
    return state.gates.height >= gate ? 'active' : 'pending';
  };

  const supplyGateStatus = (g: SupplyGate): SupplyGateStatus => {
    const { status, height } = gateStatusOf(state.supplyGates[g], state.gates.height);
    return { state: status, height };
  };

  return { ...state, gateState, supplyGateStatus };
}
