'use client';

import { StatusPill } from '@/components/ui/primitives';
import { koppa, koppaCompact, postSupplyGateState, useSupplyStatus, type GateState } from '@/lib/supplyStatus';
import { POST_SUPPLY_GATE } from '@/lib/chainStatus';

const BASE = BigInt(1_000_000_000); // 1 Koppa in base units

/**
 * Live supply / protocol-reserve dashboard (800B supply correction).
 *
 * Every number is read from the public RPC (`chain_getSupplyInfo`,
 * `chain_getProtocolReserve`, `chain_getChainParams`). Nothing is fabricated:
 * while loading a skeleton shows; if the RPC (or a pre-correction node) cannot
 * serve the supply methods, an explicit unavailable state shows instead of
 * numbers. Charts are hand-drawn SVG (donut + horizontal bars), no chart
 * library, each with an accessible text summary.
 */

/* Fixed categorical order + site palette. Identity is never color-alone:
   every slice is in the legend and the text summary, and slices are separated
   by visible surface gaps. */
const COMPOSITION_META = [
  { key: 'accounted', label: 'Account balances', color: 'var(--accent)' },
  { key: 'reserve', label: 'Protocol reserve', color: 'var(--signal)' },
  { key: 'grants', label: 'Outstanding grants', color: 'var(--accent-soft)' },
] as const;

const POOLS_META = [
  { key: 'validator_pool_remaining', label: 'Validator bootstrap', release: 'service grants (claim-gated)' },
  { key: 'archive_pool_remaining', label: 'Archive / storage service', release: 'service grants (claim-gated)' },
  { key: 'compute_pool_remaining', label: 'Compute / OmniNode service', release: 'service grants (claim-gated)' },
  { key: 'ecosystem_pool_remaining', label: 'Ecosystem / public goods', release: 'native governance release' },
  { key: 'governance_reserve_remaining', label: 'Long-term governance reserve', release: 'native governance release' },
] as const;

/* Fixed per-pool colors (same categorical order as the designed-split legend). */
const POOL_COLORS = ['var(--muted)', 'var(--accent-soft)', 'var(--signal-soft)', 'var(--signal)', 'var(--accent)'];

function gatePill(state: GateState, gateHeight?: number) {
  if (state === 'unknown') return <span className="mono text-xs text-muted">status unavailable</span>;
  const label =
    state === 'dormant'
      ? 'Dormant'
      : state === 'pending'
        ? gateHeight
          ? `Pending · activates at height ${gateHeight.toLocaleString('en-US')}`
          : 'Pending'
        : 'Active';
  return <StatusPill status={state} label={label} />;
}

function Skeleton() {
  return (
    <div className="animate-pulse space-y-3" aria-hidden>
      <div className="h-4 w-2/3 rounded bg-surface-2" />
      <div className="h-4 w-full rounded bg-surface-2" />
      <div className="h-4 w-5/6 rounded bg-surface-2" />
    </div>
  );
}

function Unavailable({ what }: { what: string }) {
  return (
    <p className="text-sm leading-relaxed text-muted">
      {what} is not available from the RPC right now. This is expected on nodes
      that pre-date the supply correction; no values are shown rather than
      estimates. Query{' '}
      <span className="mono text-xs">chain_getSupplyInfo</span> once upgraded
      nodes are serving.
    </p>
  );
}

export function SupplyHeadline() {
  const s = useSupplyStatus();
  if (s.loading) return <Skeleton />;
  if (!s.supplyAvailable || !s.supply) return <Unavailable what="Live supply data" />;
  const sup = s.supply;
  const rows: { label: string; value: string }[] = [
    { label: 'Canonical supply', value: `${koppa(sup.current_canonical_supply)} Ϙ` },
    { label: 'Account balances', value: `${koppa(sup.accounted_account_supply)} Ϙ` },
    { label: 'Protocol reserve remaining', value: `${koppa(sup.protocol_reserve_remaining)} Ϙ` },
    { label: 'Burned (Address::ZERO)', value: `${koppa(sup.burned_supply)} Ϙ` },
    { label: 'Governance-minted', value: `${koppa(sup.total_minted_by_governance)} Ϙ` },
    { label: 'Automatic emissions', value: sup.automatic_emissions_enabled ? 'enabled' : 'false' },
  ];
  return (
    <div>
      <div className="grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-3">
        {rows.map((r) => (
          <div key={r.label}>
            <div className="tnum font-[family-name:var(--font-display)] text-xl font-semibold text-foreground sm:text-2xl">
              {r.value}
            </div>
            <div className="mt-1 text-xs text-muted">{r.label}</div>
          </div>
        ))}
      </div>
      <p className="mono mt-5 text-xs text-muted">
        {sup.migration_applied
          ? `Supply correction applied (migration ${sup.migration_id.slice(0, 10)}…, height ${sup.migration_activation_height.toLocaleString('en-US')}).`
          : 'Supply correction not yet applied on this chain. Canonical supply reflects the pre-correction state.'}
      </p>
    </div>
  );
}

/** Donut chart geometry: one SVG circle segment per slice, 2-unit gaps. */
function donutSegments(values: { value: number; color: string }[], total: number) {
  const R = 42; // radius of the stroke centerline
  const C = 2 * Math.PI * R;
  const GAP = total > 0 ? Math.min(2, C / (values.length * 8)) : 0;
  let offset = 0;
  return values.map((v) => {
    const len = Math.max(0, (v.value / total) * C - GAP);
    const seg = { color: v.color, dasharray: `${len} ${C - len}`, dashoffset: -offset };
    offset += (v.value / total) * C;
    return seg;
  });
}

export function SupplyComposition() {
  const s = useSupplyStatus();
  if (s.loading) return <Skeleton />;
  if (!s.supplyAvailable || !s.supply) return <Unavailable what="Supply composition" />;
  const sup = s.supply;
  const toN = (v: string) => Number(BigInt(v) / BASE);
  // Disjoint slices summing to canonical: accounts (minus the burn sink) +
  // burned + reserve + outstanding grants. Governance-minted Koppa lives inside
  // account balances (a mint credits an account), so it is shown as an
  // annotation, never as a separate slice.
  const burned = toN(sup.burned_supply);
  const minted = toN(sup.total_minted_by_governance);
  const parts = {
    accounted: Math.max(0, toN(sup.accounted_account_supply) - burned),
    reserve: toN(sup.protocol_reserve_remaining),
    grants: toN(sup.outstanding_grant_unclaimed),
  };
  const slices = COMPOSITION_META.map((m) => ({ ...m, value: parts[m.key] })).filter((p) => p.value > 0);
  const withBurn = burned > 0 ? [...slices, { key: 'burned', label: 'Burned', color: 'var(--muted)', value: burned }] : slices;
  const total = withBurn.reduce((a, b) => a + b.value, 0);
  if (total === 0) return <Unavailable what="Supply composition" />;
  const summary = withBurn
    .map((p) => `${p.label} ${koppaCompact((BigInt(p.value) * BASE).toString())} Ϙ (${((p.value / total) * 100).toFixed(1)}%)`)
    .join(', ');
  const segs = donutSegments(withBurn, total);
  return (
    <div className="flex flex-col items-center gap-8 sm:flex-row sm:items-center">
      {/* Donut chart */}
      <svg
        viewBox="0 0 100 100"
        className="h-44 w-44 flex-none sm:h-52 sm:w-52"
        role="img"
        aria-label={`Current supply composition donut chart: ${summary}`}
      >
        <g transform="rotate(-90 50 50)">
          {segs.map((seg, i) => (
            <circle
              key={withBurn[i].key}
              cx="50"
              cy="50"
              r="42"
              fill="none"
              stroke={seg.color}
              strokeOpacity="0.9"
              strokeWidth="10"
              strokeDasharray={seg.dasharray}
              strokeDashoffset={seg.dashoffset}
            />
          ))}
        </g>
        <text x="50" y="47" textAnchor="middle" className="fill-[var(--foreground)]" style={{ font: '600 11px var(--font-display, sans-serif)' }}>
          {koppaCompact(sup.current_canonical_supply)} Ϙ
        </text>
        <text x="50" y="59" textAnchor="middle" className="fill-[var(--muted)]" style={{ font: '400 5.5px sans-serif' }}>
          canonical supply
        </text>
      </svg>
      {/* Legend: identity is never color-alone. */}
      <div className="min-w-0 flex-1">
        <ul className="space-y-2.5">
          {withBurn.map((p) => (
            <li key={p.key} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
              <span aria-hidden className="h-2.5 w-2.5 flex-none translate-y-px rounded-sm" style={{ background: p.color, opacity: 0.9 }} />
              <span className="text-muted-strong">{p.label}</span>
              <span className="tnum mono text-xs text-muted">
                {koppaCompact((BigInt(p.value) * BASE).toString())} Ϙ · {((p.value / total) * 100).toFixed(1)}%
              </span>
            </li>
          ))}
        </ul>
        {minted > 0 && (
          <p className="mono mt-3 text-xs text-muted">
            Includes {koppaCompact(sup.total_minted_by_governance)} Ϙ of governance-minted expansion (inside account balances).
          </p>
        )}
        <p className="sr-only">{summary}</p>
      </div>
    </div>
  );
}

export function ReservePools() {
  const s = useSupplyStatus();
  if (s.loading) return <Skeleton />;
  if (!s.supplyAvailable) return <Unavailable what="Protocol-reserve data" />;
  if (!s.reserve) {
    return (
      <p className="text-sm leading-relaxed text-muted">
        The ProtocolReserve does not exist yet on this chain. It is created by
        the one-time supply correction; pool balances will appear here once the
        correction has applied.
      </p>
    );
  }
  const r = s.reserve as unknown as Record<string, string>;
  // Service-grants and monetary-policy release are two of the seven post-supply
  // gates: deployed in runtime genesis at height 9,200,000 and NOT reliably
  // exposed by chain_getChainParams, so their state comes from the live height
  // (auto-flips at the gate), never from a missing RPC field.
  const grantsGate = postSupplyGateState(s.gates.height);
  const monetaryGate = grantsGate;
  const pools = POOLS_META.map((p, i) => ({
    ...p,
    color: POOL_COLORS[i],
    n: Number(BigInt(r[p.key] ?? '0') / BASE),
    base: r[p.key] ?? '0',
  }));
  const max = pools.reduce((a, b) => Math.max(a, b.n), 0);
  const summary = pools.map((p) => `${p.label} ${koppa(p.base)} Ϙ remaining`).join(', ');

  // Horizontal bar chart geometry (SVG units).
  const W = 100;
  const ROW = 15;
  const H = pools.length * ROW;
  return (
    <div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ height: `${pools.length * 3.25}rem` }}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Protocol reserve pools bar chart: ${summary}`}
      >
        {/* baseline axis */}
        <line x1="0" y1="0" x2="0" y2={H} stroke="var(--border-strong)" strokeWidth="0.4" />
        {pools.map((p, i) => {
          const w = max > 0 ? Math.max(1.2, (p.n / max) * (W - 2)) : 0;
          const y = i * ROW + ROW / 2 - 3;
          return (
            <rect key={p.key} x="0" y={y} width={w} height="6" rx="1.2" fill={p.color} fillOpacity="0.85" />
          );
        })}
      </svg>
      {/* Per-pool labels, values, and gate status (identity never color-alone). */}
      <ul className="mt-4 space-y-2.5">
        {pools.map((p) => {
          const isGrantPool = p.release.startsWith('service');
          const gate = isGrantPool ? grantsGate : monetaryGate;
          return (
            <li key={p.key} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span aria-hidden className="h-2.5 w-2.5 flex-none rounded-sm" style={{ background: p.color, opacity: 0.85 }} />
              <span className="font-medium text-foreground">{p.label}</span>
              <span className="tnum mono text-muted-strong">{koppa(p.base)} Ϙ remaining</span>
              <span className="text-muted">{p.release}</span>
              {gatePill(gate, POST_SUPPLY_GATE)}
            </li>
          );
        })}
      </ul>
      <p className="mt-5 text-xs leading-relaxed text-muted">
        Reserve release is protocol-gated: service-grant pools pay out only
        through verifiable service claims once the service-grants gate activates,
        and the ecosystem and governance pools require native-Koppa governance
        once the monetary-policy gate activates. Both gates are deployed in
        runtime genesis and activate at height{' '}
        {POST_SUPPLY_GATE.toLocaleString('en-US')}; the state above is derived
        from the live block height and flips to active automatically when the
        chain reaches that height.
      </p>
      <p className="mono mt-2 text-[11px] text-muted">
        Note: chain_getChainParams does not expose every gate. For these
        post-supply gates the site uses the operator-verified runtime-genesis
        height ({POST_SUPPLY_GATE.toLocaleString('en-US')}), not a null/dormant
        RPC field.
      </p>
      <p className="sr-only">{summary}</p>
    </div>
  );
}
