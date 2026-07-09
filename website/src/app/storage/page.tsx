import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import { SectionHeader, Reveal, MonoTag } from '@/components/ui/primitives';
import { Card, SpecList, StepFlow, Callout, SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Storage & Proof-of-Retrievability | SUM Chain',
  description:
    'SUM Chain SNIP V2 decentralized storage: archive nodes, deterministic chunk assignment, Proof-of-Retrievability challenges with Merkle proofs, fee-pool rewards, and private-file access metadata. Live on mainnet.',
};

const POR_STEPS = [
  { title: 'Register & fund', body: 'A file is registered and a fee deposit is locked into its fee pool. It enters the Pending lifecycle.', tag: 'RegisterFilePendingV2' },
  { title: 'Assign chunks', body: 'Each chunk is assigned to archive nodes by deterministic rendezvous hashing over its merkle_root, three replicas by default, snapshot-stable.', tag: 'merkle_root' },
  { title: 'Accept assignment', body: 'Assigned archives attest possession before the file activates, recorded as per-file possession bitmaps.', tag: 'AcceptAssignmentV2' },
  { title: 'Challenge', body: 'The chain issues deterministic retrievability challenges over (file, chunk, node) at a fixed interval.', tag: 'PoR' },
  { title: 'Prove or be slashed', body: 'A valid Merkle proof draws a reward from the fee pool; an expired challenge slashes the node’s stake.', tag: 'SubmitStorageProof' },
];

const LIFECYCLE = [
  { s: 'Pending', d: 'Registered and funded; chunks being assigned and accepted.' },
  { s: 'Active', d: 'Assignments accepted; subject to retrievability challenges.' },
  { s: 'Abandoned', d: 'Retired after a grace period, with the remaining deposit refunded.' },
];

export default function StoragePage() {
  return (
    <PageShell
      kicker="Decentralized storage · SNIP V2"
      status="active"
      title="Storage you can challenge, not just trust"
      intro="SUM Chain holds files under Proof-of-Retrievability: archive nodes are assigned chunks, must answer periodic challenges with Merkle proofs, and are rewarded or slashed accordingly. SNIP V2 is live on mainnet."
    >
      {/* How PoR works */}
      <section>
        <div className="mx-auto grid max-w-6xl gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader kicker="Proof-of-Retrievability" title="From upload to on-chain proof" />
            <div className="mt-8">
              <StepFlow steps={POR_STEPS} />
            </div>
          </Reveal>
          <Reveal delay={0.1} className="space-y-6 lg:sticky lg:top-28 lg:self-start">
            <Card eyebrow="storage.params">
              <SpecList
                rows={[
                  { k: 'replication_factor', v: '3' },
                  { k: 'challenge_interval', v: '100 blocks' },
                  { k: 'assignment', v: 'rendezvous hash (BLAKE3)' },
                  { k: 'max_chunks / file', v: '1,048,576' },
                  { k: 'activation_grace', v: '50 blocks' },
                ]}
              />
            </Card>
            <Callout tone="dormant" title="Reassignment is deployed, pending activation at height 8,900,000">
              Archive-node exit/withdrawal and automatic chunk reassignment are implemented on-chain
              and deployed, with <MonoTag>archive_unbonding_enabled_from_height</MonoTag> and{' '}
              <MonoTag>archive_reassignment_enabled_from_height</MonoTag> set to{' '}
              <MonoTag>8,900,000</MonoTag>, they activate automatically once the chain reaches that
              height. Until then, chunks left by an exiting archive lose effective replication until
              re-registered. Reassignment is epoch-aware and does not rewrite epoch-0 assignments.
              Challenge coverage remains probabilistic, not per-chunk guaranteed.
            </Callout>
          </Reveal>
        </div>
      </section>

      {/* Lifecycle */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader kicker="File lifecycle" title="Pending → Active → Abandoned" />
          <div className="mt-10 grid gap-4 sm:grid-cols-3">
            {LIFECYCLE.map((l, i) => (
              <Reveal key={l.s} delay={i * 0.06}>
                <div className="h-full rounded-2xl border border-[var(--border)] bg-surface/40 p-6">
                  <p className="mono text-sm text-accent-soft">{l.s}</p>
                  <p className="mt-3 text-sm leading-relaxed text-muted">{l.d}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* Private files */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Private files"
              title="The chain enforces access, not encryption"
              intro="Private files register an X25519 encryption-key entry per account and store per-recipient encrypted key bundles plus access metadata on-chain. The chain enforces these access-list and key-bundle rules, it does not encrypt the raw file bytes itself; that happens client-side before upload."
            />
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="private_file.rules">
              <SpecList
                rows={[
                  { k: 'visibility', v: 'public | private' },
                  { k: 'key_registry', v: 'X25519 per account' },
                  { k: 'access_list', v: 'on-chain, byte-capped' },
                  { k: 'key_bundles', v: '~80 B per recipient' },
                  { k: 'raw_bytes', v: 'never chain-encrypted' },
                ]}
              />
            </Card>
          </Reveal>
        </div>
      </section>

      <section>
        <div className="mx-auto max-w-6xl px-6 pb-4 lg:px-8">
          <Reveal>
            <Callout tone="note" title="SNIP, the storage product surface">
              This page describes the on-chain storage protocol. <strong>SNIP</strong> is the
              application built on it, upload, retrieve, and manage files backed by SUM Chain
              Proof-of-Retrievability. Try it at{' '}
              <a
                href="https://snip.sumchain.io"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-accent-soft underline underline-offset-2 hover:text-foreground"
              >
                snip.sumchain.io ↗
              </a>
              .
            </Callout>
          </Reveal>
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'SNIP · snip.sumchain.io', href: 'https://snip.sumchain.io' },
          { label: 'SNIP-V2-CHAIN-PLAN.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/specs/SNIP-V2-CHAIN-PLAN.md' },
          { label: 'SNIP-V2-RPC-CHEATSHEET.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/rpc/SNIP-V2-RPC-CHEATSHEET.md' },
          { label: 'tokens.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/tokens.md' },
        ]}
      />
    </PageShell>
  );
}
