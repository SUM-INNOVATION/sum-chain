'use client';

import { StatusPill } from '@/components/ui/primitives';
import { SpecList } from '@/components/ui/blocks';
import {
  koppa,
  postSupplyGateLabel,
  postSupplyGateState,
  useSupplyStatus,
  type GateState,
} from '@/lib/supplyStatus';
import { POST_SUPPLY_GATE } from '@/lib/chainStatus';

/**
 * Live governance-configuration dashboards (v2 + monetary policy).
 *
 * Everything here is CONFIGURATION/STATUS derived from `chain_getChainParams`
 * plus the live height, labeled as such, never presented as live
 * participation data. Fields a node does not expose render as
 * "not exposed by current RPC"; nothing is invented.
 */

function pill(state: GateState) {
  if (state === 'unknown') return <span className="mono text-xs text-muted">status unavailable</span>;
  const label = state === 'dormant' ? 'Dormant' : state === 'pending' ? 'Pending' : 'Active';
  return <StatusPill status={state} label={label} />;
}

function fmtGate(gate: number | null, exposed: boolean): string {
  if (!exposed) return 'not exposed by current RPC';
  if (gate == null) return 'not set';
  return `height ${gate.toLocaleString('en-US')}`;
}

export function MonetaryGovernanceStatus() {
  const s = useSupplyStatus();
  // Reserve release and MonetaryPolicyMint share the monetary-policy gate, one
  // of the seven post-supply gates deployed in runtime genesis at height
  // 9,200,000. chain_getChainParams does not reliably expose it, so state comes
  // from the live block height (auto-flips at the gate), never a null RPC field.
  const monetary = postSupplyGateState(s.gates.height);
  return (
    <div>
      <ul className="space-y-4">
        <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <span className="text-sm text-muted-strong">Reserve release gate</span>
          {pill(monetary)}
        </li>
        <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <span className="text-sm text-muted-strong">MonetaryPolicyMint gate</span>
          {pill(monetary)}
        </li>
        <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <span className="text-sm text-muted-strong">Activation height</span>
          <span className="mono text-xs text-muted-strong">
            {POST_SUPPLY_GATE.toLocaleString('en-US')} (deployed)
          </span>
        </li>
        <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <span className="text-sm text-muted-strong">Required governance mode</span>
          <span className="mono text-xs text-muted-strong">NativeEligibility only</span>
        </li>
        <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <span className="text-sm text-muted-strong">Required pass threshold</span>
          <span className="mono text-xs text-muted-strong">6667 bps (fixed)</span>
        </li>
      </ul>
      <ul className="mt-6 space-y-2 text-xs leading-relaxed text-muted">
        <li>Validator-quorum authority cannot release reserve or mint.</li>
        <li>SUM-20 and equity governance cannot release native reserve or mint native Koppa.</li>
        <li>
          Future monetary expansion is disabled unless explicitly activated
          through native governance; reserve release is protocol-gated and
          requires native-Koppa governance once the gate activates.
        </li>
      </ul>
      <p className="mono mt-4 text-[11px] text-muted">
        The monetary-policy gate is deployed in runtime genesis and activates at
        height {POST_SUPPLY_GATE.toLocaleString('en-US')}; the state above is
        derived from the live block height, not a chain_getChainParams field
        (which does not expose every gate).
      </p>
    </div>
  );
}

export function GovernanceParamsDashboard() {
  const s = useSupplyStatus();
  const exposed = s.paramsAvailable;
  const g = s.gates.governance;
  const govGate = s.gateState(s.gates.governance_enabled_from_height);
  const rows = [
    {
      k: 'governance_enabled_from_height',
      v: `${fmtGate(s.gates.governance_enabled_from_height, exposed)}${
        exposed && s.gates.governance_enabled_from_height != null
          ? ` · ${govGate === 'active' ? 'active' : 'pending'}`
          : ''
      }`,
    },
    { k: 'validator_authority_threshold_bps', v: g ? String(g.validator_authority_threshold_bps) : 'not exposed by current RPC' },
    { k: 'quorum_bps', v: g ? String(g.quorum_bps) : 'not exposed by current RPC' },
    { k: 'pass_threshold_bps', v: g ? `${g.pass_threshold_bps} (native fixed at 6667)` : 'not exposed by current RPC' },
    { k: 'voting_period_blocks', v: g ? g.voting_period_blocks.toLocaleString('en-US') : 'not exposed by current RPC' },
    { k: 'max_snapshot_holders', v: g ? g.max_snapshot_holders.toLocaleString('en-US') : 'not exposed by current RPC' },
    { k: 'min_koppa_for_eligibility', v: g ? `${koppa(g.min_koppa_for_eligibility)} Ϙ` : 'not exposed by current RPC' },
    // Two of the seven post-supply gates. chain_getChainParams does not reliably
    // expose them, so the site uses the operator-verified runtime-genesis height
    // (9,200,000) and derives active/pending from the live block height, rather
    // than treating a missing RPC field as dormant.
    { k: 'monetary_policy_enabled_from_height', v: postSupplyGateLabel(s.gates.height) },
    { k: 'service_grants_enabled_from_height', v: postSupplyGateLabel(s.gates.height) },
  ];
  return (
    <div>
      <SpecList rows={rows} />
      <p className="mono mt-4 text-[11px] text-muted">
        {exposed
          ? 'Governance thresholds are read live from chain_getChainParams; "not exposed" fields require a node running the supply-aware binary.'
          : 'RPC unreachable, no configuration values are shown rather than estimates.'}
      </p>
      <p className="mono mt-2 text-[11px] text-muted">
        The <span className="text-muted-strong">monetary_policy</span> and{' '}
        <span className="text-muted-strong">service_grants</span> gates are two of
        seven post-supply gates that chain_getChainParams does not expose. The
        site uses their operator-verified runtime-genesis height (
        {POST_SUPPLY_GATE.toLocaleString('en-US')}) and derives active/pending
        from the live block height, so they are never shown as null/dormant.
      </p>
    </div>
  );
}
