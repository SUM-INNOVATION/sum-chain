'use client';

import { StatusPill } from '@/components/ui/primitives';
import { SpecList } from '@/components/ui/blocks';
import { koppa, useSupplyStatus, type GateState } from '@/lib/supplyStatus';

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
  if (gate == null) return 'null (dormant)';
  return `height ${gate.toLocaleString('en-US')}`;
}

export function MonetaryGovernanceStatus() {
  const s = useSupplyStatus();
  const monetary = s.gateState(s.gates.monetary_policy_enabled_from_height);
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
          requires native-Koppa governance once enabled.
        </li>
      </ul>
      <p className="mono mt-4 text-[11px] text-muted">
        Configuration status from chain params, not live participation data.
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
    { k: 'monetary_policy_enabled_from_height', v: fmtGate(s.gates.monetary_policy_enabled_from_height, exposed) },
    { k: 'service_grants_enabled_from_height', v: fmtGate(s.gates.service_grants_enabled_from_height, exposed) },
  ];
  return (
    <div>
      <SpecList rows={rows} />
      <p className="mono mt-4 text-[11px] text-muted">
        {exposed
          ? 'Read live from chain_getChainParams. "not exposed" fields require a node running the supply-aware binary.'
          : 'RPC unreachable, no configuration values are shown rather than estimates.'}
      </p>
    </div>
  );
}
