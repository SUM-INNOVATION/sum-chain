import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import { SectionHeader, Reveal, Stat, MonoTag } from '@/components/ui/primitives';
import { Card, SpecList, Callout, SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Tokenomics | SUM Chain',
  description:
    'Koppa (Ϙ) tokenomics, grounded in code and live mainnet parameters: fixed 800B supply, nine decimals, fee-funded validators (min fee 1,000 base units), storage fee pools with Proof-of-Retrievability rewards, and dormant governance bonds. No inflation, no yield, no price claims.',
};

const ALLOCATION = [
  { name: 'Foundation', pct: 50, amount: '400B Ϙ', color: 'var(--accent)' },
  { name: 'Ecosystem', pct: 20, amount: '160B Ϙ', color: 'var(--signal)' },
  { name: 'Team', pct: 15, amount: '120B Ϙ', color: 'var(--accent-soft)' },
  { name: 'Community', pct: 10, amount: '80B Ϙ', color: 'var(--signal-soft)' },
  { name: 'Liquidity', pct: 5, amount: '40B Ϙ', color: 'var(--muted)' },
];

const NOT_CLAIMED = [
  'USD value, exchange rate, or market price',
  'APY, staking yield, or investment return',
  'Token emissions or inflationary rewards',
  'On-chain inference pricing or payouts (roadmap)',
];

export default function TokenomicsPage() {
  return (
    <PageShell
      kicker="Koppa economics"
      title="Value measured by useful work"
      intro="SUM Chain aims to denominate value in real productivity — storage held, blocks produced, inference verified. Every fee figure on this page is grounded in code or live mainnet parameters; design directions that are not yet implemented are labeled as such."
    >
      {/* 1. Value measured by useful work */}
      <section>
        <div className="mx-auto max-w-6xl px-6 py-16 lg:px-8">
          <div className="grid grid-cols-2 gap-8 border-b border-[var(--border)] pb-12 sm:grid-cols-4">
            <Reveal>
              <Stat value="800B Ϙ" label="Total supply" sub="fixed at genesis" />
            </Reveal>
            <Reveal delay={0.06}>
              <Stat value="9" label="Decimals" sub="1 Ϙ = 1,000,000,000 base" />
            </Reveal>
            <Reveal delay={0.12}>
              <Stat value="1000" label="Min fee (base)" sub="0.000001 Ϙ · live" />
            </Reveal>
            <Reveal delay={0.18}>
              <Stat value="0%" label="Inflation" sub="no mint path for Koppa" />
            </Reveal>
          </div>
        </div>
      </section>

      {/* 2. Koppa and base units + supply */}
      <section>
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 pb-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Koppa & base units"
              title="A fixed unit of account"
              intro="Koppa (Ϙ) has nine decimals: one Koppa is 1,000,000,000 base units. The entire supply is minted at genesis — there is no runtime mint path for native Koppa, so there is no inflation and no block reward. Validators are paid from fees, not new issuance."
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
                  { k: 'issuance', v: 'fixed at genesis' },
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
            kicker="Genesis allocation"
            title="How the fixed supply is distributed"
            intro="All 800 billion Koppa are allocated at genesis. Figures follow the published economic model."
          />
          <Reveal className="mt-10">
            <div
              className="flex h-4 w-full overflow-hidden rounded-full border border-[var(--border)]"
              role="img"
              aria-label="Genesis allocation: Foundation 50%, Ecosystem 20%, Team 15%, Community 10%, Liquidity 5%"
            >
              {ALLOCATION.map((a) => (
                <span key={a.name} style={{ width: `${a.pct}%`, background: a.color, opacity: 0.85 }} />
              ))}
            </div>
            <dl className="mt-8 grid gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-5">
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

      {/* 3. Live network fees */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Live network fees"
              status="active"
              title="Fees pay the validators who produce blocks"
              intro="Under Proof-of-Authority, transaction fees go to the block proposer — the validator that produced the block. Fees are not burned and no new tokens are minted. The values below are live mainnet chain parameters."
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
            intro="The intended design anchor is that one LLM token of useful inference work maps to one Koppa base unit — value denominated in productivity rather than speculation."
          />
          <div className="mt-8 max-w-3xl">
            <Callout tone="note" title="Design direction — not yet implemented in code">
              The <MonoTag>1 LLM token = 1 base unit</MonoTag> mapping is an accounting direction, not a
              live protocol formula. Today, OmniNode records verifier-signed{' '}
              <MonoTag>InferenceAttestation</MonoTag> entries on-chain, but the chain does not price,
              meter, or settle inference payments — there is no on-chain inference fee formula, reward,
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
              intro="Governance v1 defines an optional proposal bond and a treasury address. These live in the code but apply only if a network activates governance — none is configured on mainnet, so no bond, treasury, or governance fee is in effect today."
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

      {/* 7. What is not claimed */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader kicker="Honesty" title="What this page does not claim" />
          <ul className="mt-8 grid gap-4 sm:grid-cols-2">
            {NOT_CLAIMED.map((c, i) => (
              <Reveal key={c} delay={i * 0.05} as="li">
                <div className="flex items-start gap-3 rounded-2xl border border-[var(--border)] bg-surface/40 p-5">
                  <span className="mono mt-0.5 text-muted">✕</span>
                  <p className="text-sm leading-relaxed text-muted-strong">{c}</p>
                </div>
              </Reveal>
            ))}
          </ul>
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
