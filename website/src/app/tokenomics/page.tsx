import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import { SectionHeader, Reveal, Stat, MonoTag } from '@/components/ui/primitives';
import { Card, SpecList, Callout, SourceLinks } from '@/components/ui/blocks';
import { SupplyHeadline, SupplyComposition, ReservePools } from '@/components/SupplyDashboard';

export const metadata: Metadata = {
  title: 'Tokenomics | SUM Chain',
  description:
    'Koppa (Ϙ) tokenomics, grounded in code and live mainnet parameters: 800B canonical supply after the coordinated supply migration, nine decimals, fee-funded validators (min fee 1,000 base units), a ProtocolReserve with service grants, storage fee pools with Proof-of-Retrievability rewards, and dormant governance bonds. No automatic emissions, no yield, no price claims.',
};

const ALLOCATION = [
  { name: 'Governance reserve', pct: 40, amount: '319B Ϙ', color: 'var(--accent)' },
  { name: 'Ecosystem / public goods', pct: 20, amount: '160B Ϙ', color: 'var(--signal)' },
  { name: 'Archive service', pct: 15, amount: '120B Ϙ', color: 'var(--accent-soft)' },
  { name: 'Compute service', pct: 15, amount: '120B Ϙ', color: 'var(--signal-soft)' },
  { name: 'Validator bootstrap', pct: 10, amount: '80B Ϙ', color: 'var(--muted)' },
];

export default function TokenomicsPage() {
  return (
    <PageShell
      kicker="Koppa economics"
      title="Value measured by useful work"
      intro="SUM Chain aims to denominate value in real productivity, storage held, blocks produced, inference verified. Every fee figure on this page is grounded in code or live mainnet parameters; design directions that are not yet implemented are labeled as such."
    >
      {/* 1. Value measured by useful work */}
      <section>
        <div className="mx-auto max-w-6xl px-6 py-16 lg:px-8">
          <div className="grid grid-cols-2 gap-8 border-b border-[var(--border)] pb-12 sm:grid-cols-4">
            <Reveal>
              <Stat value="800B Ϙ" label="Canonical supply" sub="after supply migration" />
            </Reveal>
            <Reveal delay={0.06}>
              <Stat value="9" label="Decimals" sub="1 Ϙ = 1,000,000,000 base" />
            </Reveal>
            <Reveal delay={0.12}>
              <Stat value="1000" label="Min fee (base)" sub="0.000001 Ϙ · live" />
            </Reveal>
            <Reveal delay={0.18}>
              <Stat value="0" label="Automatic emissions" sub="no block rewards, no inflation" />
            </Reveal>
          </div>
        </div>
      </section>

      {/* Live supply dashboard, every number from RPC, nothing fabricated */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader
            kicker="Live supply · chain_getSupplyInfo"
            title="Supply state, read from the chain"
            intro="Canonical supply, account balances, protocol reserve, burns, and any governance-minted expansion are fetched from the public RPC on load. If a node does not yet serve the supply methods (pre-correction binaries), this section says so instead of showing numbers."
          />
          <Reveal className="mt-10">
            <SupplyHeadline />
          </Reveal>
          <Reveal className="mt-12" delay={0.08}>
            <h3 className="mb-4 text-sm font-medium text-muted-strong">Current supply composition</h3>
            <SupplyComposition />
          </Reveal>
        </div>
      </section>

      {/* 2. Koppa and base units + supply */}
      <section>
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 pb-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Koppa & base units"
              title="A stable unit of account"
              intro="Koppa (Ϙ) has nine decimals: one Koppa is 1,000,000,000 base units. There are no automatic emissions, no inflation and no block reward. Initial canonical supply is 800B Koppa after the coordinated supply migration; the 799B correction delta lives in a non-transferable ProtocolReserve, not in accounts. Future supply expansion, if ever needed, requires explicit on-chain consensus governance. Validators are paid from fees, not new issuance."
            />
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="koppa.units">
              <SpecList
                rows={[
                  { k: 'symbol', v: 'Ϙ (Koppa)' },
                  { k: 'decimals', v: '9' },
                  { k: 'base_unit', v: '1 Ϙ = 1,000,000,000' },
                  { k: 'total_supply', v: '800,000,000,000 Ϙ' },
                  { k: 'issuance', v: 'none automatic; governance-only expansion' },
                ]}
              />
            </Card>
          </Reveal>
        </div>
      </section>

      {/* Genesis allocation */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader
            kicker="ProtocolReserve"
            title="How the supply is distributed"
            intro="1B Koppa was allocated at genesis to the two bootstrap validators. The 799B correction delta is non-transferable ProtocolReserve supply, released only through service grants earned by network participation or native-Koppa consensus governance. Figures follow the published economic model."
          />
          <Reveal className="mt-10">
            {/* Live per-pool remaining balances (chain_getProtocolReserve). */}
            <ReservePools />
          </Reveal>
          <Reveal className="mt-10" delay={0.08}>
            <p className="mb-4 text-xs text-muted">
              Designed pool split (protocol constants; live remaining balances above):
            </p>
            <dl className="grid gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-5">
              {ALLOCATION.map((a) => (
                <div key={a.name} className="flex items-start gap-3">
                  <span className="mt-1.5 h-2.5 w-2.5 flex-none rounded-sm" style={{ background: a.color }} />
                  <div>
                    <dt className="text-sm font-medium text-foreground">{a.name}</dt>
                    <dd className="tnum mono text-xs text-muted">
                      {a.pct}% · {a.amount}
                    </dd>
                  </div>
                </div>
              ))}
            </dl>
          </Reveal>
        </div>
      </section>

      {/* Service grants */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Service grants"
              title="Grants are earned by network work, not handed out"
              intro="The reserve's service pools bootstrap operators without a supply shock: every grant is mostly locked, and liquidity comes from verifiable protocol work. Claiming is gate-controlled and dormant until the schedule is ratified."
            />
            <ul className="mt-6 space-y-3 text-sm leading-relaxed text-muted">
              <li>
                <span className="font-medium text-muted-strong">10% liquid / 90% locked.</span>{' '}
                A claimed grant credits a tenth immediately; the rest is locked service stake.
              </li>
              <li>
                <span className="font-medium text-muted-strong">Locked stake unlocks 1:1 against protocol-earned Koppa</span>{' '}
               , proposer fees for validators, PoR payouts for archives, settlement rewards for verifiers.
              </li>
              <li>
                <span className="font-medium text-muted-strong">Ordinary transfers do not unlock.</span>{' '}
                Received or self-sent Koppa never counts as earned credit; only the protocol reward paths do.
              </li>
              <li>
                <span className="font-medium text-muted-strong">No automatic emissions.</span>{' '}
                Grants move existing reserve supply; they never mint.
              </li>
            </ul>
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="grants.rules">
              <SpecList
                rows={[
                  { k: 'split', v: '10% liquid · 90% locked' },
                  { k: 'unlock', v: '1:1 vs protocol-earned Koppa' },
                  { k: 'transfers_as_credit', v: 'never' },
                  { k: 'genesis_validators', v: 'first two excluded (funded at genesis)' },
                  { k: 'early_archive_nodes', v: 'eligible via service evidence' },
                  { k: 'retroactive_grants', v: 'none, counting starts at correction' },
                  { k: 'slashing', v: 'forfeits locked stake to reserve' },
                  { k: 'claiming', v: 'gate-controlled · dormant by default' },
                ]}
              />
            </Card>
            <p className="mt-4 text-xs leading-relaxed text-muted">
              The first two genesis validators are excluded from validator
              bootstrap grants because they were funded 500M Ϙ each at genesis.
              Early archive nodes are not excluded, they earn archive grants
              through the same service evidence (successful PoR proofs, active
              service) as future nodes, with no automatic lump sums.
            </p>
          </Reveal>
        </div>
      </section>

      {/* 3. Live network fees */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Live network fees"
              status="active"
              title="Fees pay the validators who produce blocks"
              intro="Under Proof-of-Authority, transaction fees go to the block proposer, the validator that produced the block. Fees are not burned and no new tokens are minted. The values below are live mainnet chain parameters."
            />
            <p className="mono mt-4 text-xs text-muted">verified 2026-07-02 · height 8,183,329</p>
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="fee.params · live">
              <SpecList
                rows={[
                  { k: 'consensus', v: 'Proof of Authority' },
                  { k: 'min_fee', v: '1000 base (0.000001 Ϙ)' },
                  { k: 'fee_recipient', v: 'block proposer' },
                  { k: 'fee_burn', v: 'none' },
                  { k: 'storage_fee_per_byte', v: '100 base units' },
                ]}
              />
            </Card>
          </Reveal>
        </div>
      </section>

      {/* 4. Storage & PoR economics */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Storage economics"
              status="active"
              title="Storage is funded by a per-file fee pool"
              intro="Registering a file locks a fee deposit into that file’s fee pool. Archive nodes that answer Proof-of-Retrievability challenges with valid Merkle proofs are paid from the pool; nodes that let a challenge expire are slashed. The constants below are defined in the storage protocol code."
            />
            <div className="mt-6 flex flex-wrap gap-2">
              <MonoTag>fee_pool</MonoTag>
              <MonoTag>CHALLENGE_REWARD</MonoTag>
              <MonoTag>SLASH_PERCENTAGE</MonoTag>
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="storage.economics · code">
              <SpecList
                rows={[
                  { k: 'registration', v: 'fee_deposit → fee_pool' },
                  { k: 'challenge_reward', v: '10 Ϙ (from fee pool)' },
                  { k: 'slash_on_expiry', v: '5% of staked balance' },
                  { k: 'abandonment', v: '10% of pool retained' },
                  { k: 'storage_fee_per_byte', v: '100 base units' },
                ]}
              />
            </Card>
          </Reveal>
        </div>
      </section>

      {/* 5. AI compute accounting direction */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader
            kicker="AI compute accounting"
            title="A productivity anchor for inference"
            intro="The intended design anchor is that one LLM token of useful inference work maps to one Koppa base unit, value denominated in productivity rather than speculation."
          />
          <div className="mt-8 max-w-3xl">
            <Callout tone="note" title="Design direction, not yet implemented in code">
              The <MonoTag>1 LLM token = 1 base unit</MonoTag> mapping is an accounting direction, not a
              live protocol formula. Today, OmniNode records verifier-signed{' '}
              <MonoTag>InferenceAttestation</MonoTag> entries on-chain, but the chain does not price,
              meter, or settle inference payments, there is no on-chain inference fee formula, reward,
              or slashing. Those are on the roadmap.
            </Callout>
          </div>
        </div>
      </section>

      {/* 6. Governance bond & treasury, dormant */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Governance economics"
              status="dormant"
              title="Proposal bond & treasury, when activated"
              intro="Governance v1 defines an optional proposal bond and a treasury address. These live in the code but apply only if a network activates governance, none is configured on mainnet, so no bond, treasury, or governance fee is in effect today."
            />
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="governance.params · dormant">
              <SpecList
                rows={[
                  { k: 'proposal_bond', v: 'configurable (default 0)' },
                  { k: 'treasury', v: 'optional address' },
                  { k: 'bond_settlement', v: 'return / burn' },
                  { k: 'mainnet_status', v: 'not configured' },
                ]}
              />
            </Card>
          </Reveal>
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'economic-model.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/architecture/economic-model.md' },
          { label: 'tokens.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/tokens.md' },
          { label: 'README.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/README.md' },
        ]}
      />
    </PageShell>
  );
}
