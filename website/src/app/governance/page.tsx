import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import { SectionHeader, Reveal, MonoTag } from '@/components/ui/primitives';
import { Card, SpecList, StepFlow, Callout, SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Governance | SUM Chain',
  description:
    'SUM Chain on-chain governance v1: record-first, SRC-20 token-holder snapshot voting, proposal bonds, and a single TreasurySpend on-chain execution path. Code-backed and dormant until activated.',
};

const LIFECYCLE = [
  { title: 'Create', body: 'A holder whose snapshot power meets the asset threshold opens a proposal and posts the deposit bond.', tag: 'create_threshold' },
  { title: 'Snapshot', body: 'Eligible balances are frozen from TOKEN_BALANCES at creation. Transfers afterward do not change voting weight.', tag: 'gov_snapshots' },
  { title: 'Vote', body: 'Holders cast Yes / No / Abstain, weighted only by the frozen snapshot — never by live balances.' },
  { title: 'Tally', body: 'After the window, quorum and the pass threshold are evaluated over snapshot power.' },
  { title: 'Record / Execute / Cancel', body: 'Passed proposals are Recorded, or Executed for a TreasurySpend payout. The proposer, or a validator quorum, may cancel a live proposal.' },
];

const CANNOT = [
  'Force a validator to upgrade its binary or genesis.',
  'Mutate chain parameters, the validator set, or consensus on-chain.',
  'Move funds — except the single TreasurySpend native payout.',
];

export default function GovernancePage() {
  return (
    <PageShell
      kicker="On-chain governance v1"
      status="dormant"
      title="Record-first governance, respecting validators"
      intro="Token holders decide; the chain records the decision. Governance v1 is fully implemented in the node, but ships dormant — it does nothing until a network coordinates activation."
    >
      {/* Dormant banner */}
      <section className="border-b border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-10 lg:px-8">
          <Callout tone="dormant" title="Dormant until coordinated activation">
            On-chain governance is inert until a coordinated validator activation sets{' '}
            <MonoTag>governance_enabled_from_height</MonoTag> and the{' '}
            <MonoTag>ChainParams.governance</MonoTag> parameters. Neither is set on mainnet, so
            governance transactions are rejected today. No final token id, quorum, pass threshold,
            proposal bond, voting period, or activation height is fixed here — those are set per
            activation.
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
              intro="The authoritative governance decision is the on-chain approval record. Governance records that a proposal passed. It does not push code, force upgrades, or change consensus — those are carried out off-chain by maintainers and validators who remain in control."
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
                  Admin actions — enabling a governance asset, and cancelling someone else&apos;s live
                  proposal — are authorized by a <strong>quorum of the active validator set</strong>, not a
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
                creation — the proposer must cover <MonoTag>fee + bond</MonoTag>.
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
                Most classes — process, RPC surface, token/economic, genesis/validator, activation
                height, migrations — are <strong className="text-muted-strong">RecordOnly</strong>. The
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

      <SourceLinks
        links={[
          { label: 'GOVERNANCE.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/GOVERNANCE.md' },
          { label: 'RELEASE.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/RELEASE.md' },
          { label: 'GOVERNANCE-V1.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/specs/GOVERNANCE-V1.md' },
          { label: 'tokens.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/tokens.md' },
        ]}
      />
    </PageShell>
  );
}
