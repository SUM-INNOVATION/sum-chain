'use client';

import Link from 'next/link';
import { Reveal, StatusPill, MonoTag, type Status } from '@/components/ui/primitives';
import { LiveStatus } from '@/components/LiveStatus';
import type { FeatureKey } from '@/lib/chainStatus';

type Topic = {
  id: string;
  kicker: string;
  title: string;
  status?: Status;
  /** When set, status is read live from the chain (auto-flips at the gate). */
  feature?: FeatureKey;
  bullets: string[];
  tags: string[];
  spec: { k: string; v: string }[];
  href: string;
  cta: string;
  /** External product/application surface built on this protocol. */
  productHref?: string;
  productCta?: string;
};

const TOPICS: Topic[] = [
  {
    id: 'storage',
    kicker: 'Decentralized storage',
    title: 'Proof-of-Retrievability, not promises',
    status: 'active',
    bullets: [
      'Files are chunked and assigned to archive nodes by deterministic rendezvous hashing, three replicas by default.',
      'Archives answer periodic retrievability challenges with Merkle proofs. Valid proofs earn rewards from the file’s fee pool; expired challenges slash stake.',
      'Private files store encrypted key bundles and access metadata on-chain, the chain never encrypts raw file bytes itself.',
    ],
    tags: ['PoR', 'merkle_root', 'archive nodes'],
    spec: [
      { k: 'replication_factor', v: '3' },
      { k: 'challenge_interval', v: '100 blocks' },
      { k: 'lifecycle', v: 'Pending → Active → Abandoned' },
      { k: 'max_chunks / file', v: '1,048,576' },
    ],
    href: '/storage',
    cta: 'Storage & PoR',
    productHref: 'https://snip.sumchain.io',
    productCta: 'Open SNIP',
  },
  {
    id: 'compute',
    kicker: 'Verifiable AI compute',
    title: 'Inference, settled on-chain',
    status: 'active',
    bullets: [
      'Users pay Koppa for inference; off-chain OmniNode workers perform the compute and a verifier signs the result.',
      'The verifier submits an InferenceAttestation, one per (session_id, verifier), permanently, which the chain records and finalizes.',
      'Read RPCs expose attestations and their status. Escrow-funded settlement (rewards/refunds) is active on mainnet (gate 8,900,000 reached); no bond slashing in v1.',
    ],
    tags: ['InferenceAttestation', 'verifier_signature', 'proof_root'],
    spec: [
      { k: 'signing_domain', v: 'omninode.inference_attestation.v1' },
      { k: 'dedup', v: 'one per (session, verifier)' },
      { k: 'attestation', v: 'active' },
      { k: 'settlement', v: 'implemented · dormant' },
    ],
    href: '/compute',
    cta: 'Compute & attestation',
    productHref: 'https://omninode.suminnovation.xyz',
    productCta: 'Open OmniNode',
  },
  {
    id: 'governance',
    kicker: 'On-chain governance',
    title: 'Record-first, validator-controlled',
    feature: 'governance',
    bullets: [
      'SRC-20 token holders create proposals and vote with a balance snapshot frozen at proposal creation.',
      'Admin authority (asset registration, validator-cancel) is a validator quorum, not a single council address. Most classes are RecordOnly; the one on-chain auto-exec path is a TreasurySpend native payout from a configured treasury.',
      'Governance cannot force validator upgrades or mutate consensus, the validator set, or chain params. Active on mainnet: the gate at height 8,900,000 has been reached.',
    ],
    tags: ['gov_*', 'validator-quorum', 'snapshot'],
    spec: [
      { k: 'model', v: 'record-first approval' },
      { k: 'authority', v: 'validator quorum' },
      { k: 'on-chain exec', v: 'TreasurySpend only' },
      { k: 'mainnet status', v: 'active (gate 8,900,000 reached)' },
    ],
    href: '/governance',
    cta: 'Governance',
  },
  {
    id: 'tokenomics',
    kicker: 'Koppa economics',
    title: 'No automatic emissions, fee-funded validators',
    bullets: [
      '800,000,000,000 Ϙ canonical supply after the coordinated supply migration. No inflation and no mining or block rewards; future expansion requires on-chain consensus governance.',
      'Transaction fees are paid to the block proposer, so validators are funded by real network usage rather than new issuance.',
      'Koppa has nine decimals: 1 Ϙ = 1,000,000,000 base units, with a minimum fee of 1,000 base units.',
    ],
    tags: ['Ϙ', 'PoA', 'fee → proposer'],
    spec: [
      { k: 'total_supply', v: '800,000,000,000 Ϙ' },
      { k: 'decimals', v: '9' },
      { k: 'min_fee', v: '1000 base (0.000001 Ϙ)' },
      { k: 'issuance', v: 'none automatic; governance-only expansion' },
    ],
    href: '/tokenomics',
    cta: 'Tokenomics',
  },
];

function SpecPanel({ topic }: { topic: Topic }) {
  return (
    <div className="glass rounded-2xl p-6">
      <div className="flex items-center justify-between">
        <span className="mono text-xs text-muted">{topic.id}.spec</span>
        {topic.feature ? (
          <LiveStatus feature={topic.feature} />
        ) : (
          topic.status && <StatusPill status={topic.status} />
        )}
      </div>
      <dl className="mt-5 divide-y divide-[var(--border)]">
        {topic.spec.map((row) => (
          <div key={row.k} className="flex items-baseline justify-between gap-4 py-2.5">
            <dt className="mono text-xs text-muted">{row.k}</dt>
            <dd className="tnum text-right text-sm text-muted-strong">{row.v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export default function ProtocolOverview() {
  return (
    <section className="border-t border-[var(--border)]">
      <div className="mx-auto max-w-6xl space-y-20 px-6 py-24 lg:px-8 lg:space-y-28">
        {TOPICS.map((t, i) => {
          const flip = i % 2 === 1;
          return (
            <div key={t.id} id={t.id} className="grid items-center gap-10 lg:grid-cols-2 lg:gap-16">
              <Reveal className={flip ? 'lg:order-2' : ''}>
                <div className="flex items-center gap-3">
                  <span className="kicker">{t.kicker}</span>
                  {t.feature ? (
                    <LiveStatus feature={t.feature} />
                  ) : (
                    t.status && <StatusPill status={t.status} />
                  )}
                </div>
                <h2 className="mt-4 font-[family-name:var(--font-display)] text-3xl font-semibold tracking-tight sm:text-4xl">
                  {t.title}
                </h2>
                <ul className="mt-6 space-y-4">
                  {t.bullets.map((b) => (
                    <li key={b} className="flex gap-3 text-sm leading-relaxed text-muted">
                      <span className="mt-2 h-1 w-1 flex-none rounded-full bg-accent-soft" />
                      <span>{b}</span>
                    </li>
                  ))}
                </ul>
                <div className="mt-6 flex flex-wrap gap-2">
                  {t.tags.map((tag) => (
                    <MonoTag key={tag}>{tag}</MonoTag>
                  ))}
                </div>
                <div className="mt-8 flex flex-wrap items-center gap-x-6 gap-y-3">
                  <Link
                    href={t.href}
                    className="inline-flex items-center gap-2 text-sm font-medium text-foreground transition-colors hover:text-accent-soft"
                  >
                    {t.cta} <span aria-hidden>→</span>
                  </Link>
                  {t.productHref && t.productCta && (
                    <Link
                      href={t.productHref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 text-sm font-medium text-accent-soft transition-colors hover:text-foreground"
                    >
                      {t.productCta} <span aria-hidden>↗</span>
                    </Link>
                  )}
                </div>
              </Reveal>

              <Reveal delay={0.1} className={flip ? 'lg:order-1' : ''}>
                <SpecPanel topic={t} />
              </Reveal>
            </div>
          );
        })}
      </div>
    </section>
  );
}
