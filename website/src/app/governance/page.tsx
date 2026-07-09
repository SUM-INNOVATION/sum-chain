import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import { LiveStatus } from '@/components/LiveStatus';
import { SectionHeader, Reveal, MonoTag } from '@/components/ui/primitives';
import { Card, SpecList, StepFlow, Callout, SourceLinks } from '@/components/ui/blocks';
import { MonetaryGovernanceStatus, GovernanceParamsDashboard } from '@/components/GovernanceV2Status';
import { ReservePools } from '@/components/SupplyDashboard';

export const metadata: Metadata = {
  title: 'Governance | SUM Chain',
  description:
    'SUM Chain on-chain governance v1: record-first, validator-quorum admin authority, SRC-20 token-holder snapshot voting, proposal bonds, and a single TreasurySpend on-chain execution path. Active on mainnet (activation gate 8,900,000 reached).',
};

const LIFECYCLE = [
  { title: 'Create', body: 'A holder whose snapshot power meets the asset threshold opens a proposal and posts the deposit bond.', tag: 'create_threshold' },
  { title: 'Snapshot', body: 'Eligible balances are frozen from TOKEN_BALANCES at creation. Transfers afterward do not change voting weight.', tag: 'gov_snapshots' },
  { title: 'Vote', body: 'Holders cast Yes / No / Abstain, weighted only by the frozen snapshot, never by live balances.' },
  { title: 'Tally', body: 'After the window, quorum and the pass threshold are evaluated over snapshot power.' },
  { title: 'Record / Execute / Cancel', body: 'Passed proposals are Recorded, or Executed for a TreasurySpend payout. The proposer, or a validator quorum, may cancel a live proposal.' },
];

const CANNOT = [
  'Force a validator to upgrade its binary or genesis.',
  'Mutate chain parameters, the validator set, or consensus on-chain.',
  'Move funds, except the single TreasurySpend native payout.',
];

export default function GovernancePage() {
  return (
    <PageShell
      kicker="On-chain governance v1"
      statusNode={<LiveStatus feature="governance" />}
      title="Record-first governance, respecting validators"
      intro="Token holders decide; the chain records the decision. Governance v1 is fully implemented and active on mainnet: its activation gate at height 8,900,000 has been reached, so governance transactions are live."
    >
      {/* Activation banner */}
      <section className="border-b border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-10 lg:px-8">
          <Callout tone="active" title="Active on mainnet (activated at height 8,900,000)">
            Governance activated when the chain crossed{' '}
            <MonoTag>governance_enabled_from_height</MonoTag> = <MonoTag>8,900,000</MonoTag>, with
            the <MonoTag>ChainParams.governance</MonoTag> parameters configured (validator-quorum
            authority, quorum and pass thresholds, voting period, proposal bond). Governance
            transactions are now accepted; the flow activated automatically with no redeploy. Admin
            authority is a <strong>validator quorum</strong>, not a single council address.
          </Callout>
        </div>
      </section>

      {/* Record-first model */}
      <section>
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="The model"
              title="Approval is recorded on-chain; execution is deliberate"
              intro="The authoritative governance decision is the on-chain approval record. Governance records that a proposal passed. It does not push code, force upgrades, or change consensus; those are carried out off-chain by maintainers and validators who remain in control."
            />
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="governance.model">
              <SpecList
                rows={[
                  { k: 'decision', v: 'on-chain approval record' },
                  { k: 'voting_source', v: 'allowlisted SRC-20 token' },
                  { k: 'voting_power', v: 'frozen balance snapshot' },
                  { k: 'ballots', v: 'public (v1)' },
                  { k: 'on-chain exec', v: 'TreasurySpend only' },
                ]}
              />
            </Card>
          </Reveal>
        </div>
      </section>

      {/* Who governs */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader kicker="Who governs" title="Two authorities, clearly separated" />
          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            <Reveal>
              <Card title="SRC-20 token holders">
                <p className="text-sm leading-relaxed text-muted">
                  Holders of a single allowlisted, fixed-supply / non-mintable governance token create
                  proposals and vote. Voting power is a balance snapshot frozen at proposal creation, so
                  moving tokens after the snapshot cannot change the outcome.
                </p>
              </Card>
            </Reveal>
            <Reveal delay={0.1}>
              <Card title="Validator-quorum authority">
                <p className="text-sm leading-relaxed text-muted">
                  Admin actions, enabling a governance asset, and cancelling someone else&apos;s live
                  proposal, are authorized by a <strong>quorum of the active validator set</strong>, not a
                  personal council key. The bar is a basis-point threshold
                  (<MonoTag>GovernanceParams.validator_authority_threshold_bps</MonoTag>): required
                  approvals = ceil(active_validators × bps / 10000). Non-signing validators abstain but
                  still count in the denominator; for the current two-validator network,
                  <MonoTag>6667</MonoTag> requires both, and <MonoTag>10000</MonoTag> requires all. The
                  governed treasury address is separate and base58-configured.
                </p>
              </Card>
            </Reveal>
          </div>
        </div>
      </section>

      {/* Lifecycle */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader kicker="Proposal lifecycle" title="Create → snapshot → vote → tally → record" />
            <div className="mt-8">
              <StepFlow steps={LIFECYCLE} />
            </div>
          </Reveal>
          <Reveal delay={0.1} className="space-y-6">
            <Card eyebrow="proposal.bond" title="Deposit bond">
              <p className="text-sm leading-relaxed text-muted">
                When a bond is configured, it is escrowed to a canonical governance address at
                creation, the proposer must cover <MonoTag>fee + bond</MonoTag>.
              </p>
              <div className="mt-4 grid grid-cols-3 gap-3 text-center">
                {[
                  { s: 'Escrow', d: 'at creation' },
                  { s: 'Return', d: 'good-faith / proposer cancel' },
                  { s: 'Burn', d: 'spam / quorum fail / validator-quorum cancel' },
                ].map((b) => (
                  <div key={b.s} className="rounded-xl border border-[var(--border)] bg-surface/40 p-3">
                    <p className="mono text-xs text-accent-soft">{b.s}</p>
                    <p className="mt-1 text-[11px] leading-tight text-muted">{b.d}</p>
                  </div>
                ))}
              </div>
            </Card>
            <Card eyebrow="execution.kind" title="RecordOnly vs OnChain">
              <p className="text-sm leading-relaxed text-muted">
                Most classes, process, RPC surface, token/economic, genesis/validator, activation
                height, migrations, are <strong className="text-muted-strong">RecordOnly</strong>. The
                one on-chain auto-exec path is a <MonoTag>TreasurySpend</MonoTag>: a single native-Koppa
                payout from the configured treasury to a beneficiary fixed at creation. Every other
                OnChain proposal is rejected.
              </p>
            </Card>
          </Reveal>
        </div>
      </section>

      {/* Cannot do */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader
            kicker="Guarantees"
            title="What governance cannot do"
            intro="These limits are enforced by the node, not by policy."
          />
          <ul className="mt-8 grid gap-4 sm:grid-cols-3">
            {CANNOT.map((c, i) => (
              <Reveal key={c} delay={i * 0.06} as="li">
                <div className="h-full rounded-2xl border border-[var(--border)] bg-surface/40 p-6">
                  <span className="mono text-xs text-status-active">enforced</span>
                  <p className="mt-3 text-sm leading-relaxed text-muted-strong">{c}</p>
                </div>
              </Reveal>
            ))}
          </ul>
        </div>
      </section>

      {/* ── Governance v2: shipped voting modes ─────────────────────────── */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader
            kicker="Governance v2 · shipped in code"
            title="Four governance modes, strictly separated"
            intro="Governance v2 extends v1 with native-Koppa consensus voting and SRC-833 equity voting. Each mode has its own electorate, weight rule, and authority boundary, none substitutes for another."
          />
          <div className="mt-10 grid gap-6 sm:grid-cols-2">
            <Reveal>
              <Card eyebrow="mode.validator-quorum" title="Validator-quorum authority">
                <ul className="space-y-2 text-sm leading-relaxed text-muted">
                  <li>Administrative authority for narrow protocol actions (e.g. registering governance assets).</li>
                  <li>Not public monetary governance, it cannot release reserve or mint.</li>
                  <li>Thresholds count the full active validator set: validators that do not sign remain in the denominator.</li>
                </ul>
              </Card>
            </Reveal>
            <Reveal delay={0.06}>
              <Card eyebrow="mode.sum-20" title="SUM-20 token governance">
                <ul className="space-y-2 text-sm leading-relaxed text-muted">
                  <li>Fixed-supply, non-mintable SUM-20 tokens vote with balance weight.</li>
                  <li>Electorate is snapshotted at proposal creation, later transfers do not change a vote.</li>
                  <li>Cannot carry native monetary actions.</li>
                </ul>
              </Card>
            </Reveal>
            <Reveal delay={0.12}>
              <Card eyebrow="mode.native-koppa" title="Native-Koppa consensus governance">
                <ul className="space-y-2 text-sm leading-relaxed text-muted">
                  <li>One eligible address = one vote; no stake weighting, no delegation.</li>
                  <li>Eligibility requires a minimum Koppa balance and holding a qualifying allowlisted asset, snapshotted at proposal creation.</li>
                  <li>Consensus/monetary changes pass at a fixed 6667 bps of yes+no votes.</li>
                </ul>
              </Card>
            </Reveal>
            <Reveal delay={0.18}>
              <Card eyebrow="mode.src-833" title="SRC-833 equity governance">
                <ul className="space-y-2 text-sm leading-relaxed text-muted">
                  <li>Share-class voting: votes = shares × votes_per_share.</li>
                  <li>Controller-attested, commitment-aware voting path, holders prove membership against a chain-derived balances root.</li>
                  <li>No public holder table is ever exposed; scoped to equity contexts, never native supply.</li>
                </ul>
              </Card>
            </Reveal>
          </div>
        </div>
      </section>

      {/* ── Monetary governance status (live configuration) ─────────────── */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Monetary governance"
              title="Reserve release and future minting are native-only"
              intro="The ProtocolReserve's governance pools and any future supply expansion beyond 800B are executable only through native-Koppa consensus governance. The gates below are read live from chain parameters."
            />
            <div className="mt-8">
              <MonetaryGovernanceStatus />
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h3 className="mb-4 text-sm font-medium text-muted-strong">Reserve pools and release paths</h3>
            <ReservePools />
          </Reveal>
        </div>
      </section>

      {/* ── v2 action boundaries ─────────────────────────────────────────── */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader
            kicker="Action boundaries"
            title="Governance execution is narrow and typed"
            intro="Every on-chain execution class is explicitly allowlisted; everything else fails closed. These boundaries are enforced by the node at both proposal creation and execution."
          />
          <ul className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {[
              'Validator-quorum is not a substitute for native monetary governance, monetary classes reject it.',
              'Policy Account token-admin execution is allowlisted to exactly five audited token operations.',
              'Native reserve-release and mint actions must be NativeEligibility proposals, enforced at creation and execution.',
              'Equity governance is for eligible equity/share-class contexts; it cannot touch native supply.',
            ].map((c, i) => (
              <Reveal key={c} delay={i * 0.06} as="li">
                <div className="h-full rounded-2xl border border-[var(--border)] bg-surface/40 p-6">
                  <span className="mono text-xs text-status-active">enforced</span>
                  <p className="mt-3 text-sm leading-relaxed text-muted-strong">{c}</p>
                </div>
              </Reveal>
            ))}
          </ul>
        </div>
      </section>

      {/* ── Live configuration dashboard ─────────────────────────────────── */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-start gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Configuration · chain_getChainParams"
              title="Governance parameters, read from the chain"
              intro="Gate heights and configured thresholds fetched from the public RPC on load. This is configuration status, not live participation data; fields a node does not expose are labeled rather than invented."
            />
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="governance.params · live">
              <GovernanceParamsDashboard />
            </Card>
          </Reveal>
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'GOVERNANCE.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/GOVERNANCE.md' },
          { label: 'RELEASE.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/RELEASE.md' },
          { label: 'GOVERNANCE-V1.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/specs/GOVERNANCE-V1.md' },
          { label: 'economic-model.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/architecture/economic-model.md' },
          { label: 'tokens.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/tokens.md' },
        ]}
      />
    </PageShell>
  );
}
