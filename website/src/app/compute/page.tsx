import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import SystemMap from '@/components/SystemMap';
import { SectionHeader, Reveal, MonoTag } from '@/components/ui/primitives';
import { Card, SpecList, Callout, SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Verifiable AI Compute | SUM Chain',
  description:
    'OmniNode inference attestation on SUM Chain: users pay Koppa, inference nodes compute, a verifier signs the result, and the chain records a permanent InferenceAttestation. Attestation is live on mainnet; escrow-funded inference settlement is implemented but dormant (no bond slashing in v1).',
};

const RECORDS = [
  { k: 'session_id', v: 'binds the request' },
  { k: 'model_hash', v: 'model identity' },
  { k: 'manifest_root', v: 'input manifest' },
  { k: 'response_hash', v: 'output commitment' },
  { k: 'proof_root', v: 'verifier proof' },
  { k: 'verifier_signature', v: 'Ed25519 (Stage-6 domain)' },
];

export default function ComputePage() {
  return (
    <PageShell
      kicker="Verifiable AI compute · OmniNode"
      status="active"
      title="AI inference, settled on-chain"
      intro="Off-chain nodes do the compute; the chain settles the proof. A verifier signs each result and commits an InferenceAttestation that SUM Chain records permanently — one per session and verifier. OmniNode attestation is live on mainnet."
    >
      {/* Workflow */}
      <section>
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader
            kicker="The workflow"
            title="From prompt to verified response"
            intro="Users pay Koppa for inference. Nodes fetch model shards from archive/SNIP storage, run the work, and a verifier attests to the result. The chain verifies the signature and records the attestation."
          />
          <div className="mt-12">
            <SystemMap />
          </div>
        </div>
      </section>

      {/* What the chain records */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="On-chain record"
              title="A signed digest, deduplicated forever"
              intro="Each attestation binds a session to a tuple of content hashes, signed under OmniNode’s Stage-6 domain. The chain enforces one attestation per (session_id, verifier) permanently — no overwrite — and finalizes it by block depth."
            />
            <div className="mt-6 flex flex-wrap gap-2">
              <MonoTag>InferenceAttestation</MonoTag>
              <MonoTag>sender == verifier</MonoTag>
              <MonoTag>finality_depth</MonoTag>
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="attestation.digest">
              <SpecList rows={RECORDS} />
            </Card>
          </Reveal>
        </div>
      </section>

      {/* Reads + roadmap */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl gap-6 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <Card eyebrow="read RPC" title="Query attestations">
              <p className="text-sm leading-relaxed text-muted">
                Three read-only methods let coordinators enumerate attestations and check status —
                submitted, included, finalized, or failed.
              </p>
              <div className="mt-4 space-y-2">
                {['sum_getInferenceAttestation', 'sum_listInferenceAttestations', 'sum_getInferenceAttestationStatus'].map(
                  (m) => (
                    <p key={m} className="mono text-xs text-muted-strong">
                      {m}
                    </p>
                  ),
                )}
              </div>
            </Card>
          </Reveal>
          <Reveal delay={0.1}>
            <Callout tone="dormant" title="Settlement is implemented but dormant">
              Attestation v1 records verifier-signed results only. Escrow-funded inference{' '}
              <strong>settlement</strong> (rewards, refunds, disputes) is implemented behind{' '}
              <MonoTag>inference_settlement_enabled_from_height</MonoTag> and is <strong>dormant</strong>{' '}
              on mainnet — the chain does not pay inference nodes until it is activated. v1 has{' '}
              <strong>no bond slashing</strong>: the levers are reward denial, claim withholding, and
              escrow refund. v1 also requires the transaction sender to be the verifier (no sponsored
              submission).
            </Callout>
          </Reveal>
          <Reveal delay={0.15}>
            <Callout tone="note" title="OmniNode — the compute product surface">
              This page describes the on-chain attestation protocol. <strong>OmniNode</strong> is the
              application built on it — request verifiable AI inference settled against SUM Chain. See{' '}
              <a
                href="https://omninode.suminnovation.xyz"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-accent-soft underline underline-offset-2 hover:text-foreground"
              >
                omninode.suminnovation.xyz ↗
              </a>
              .
            </Callout>
          </Reveal>
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'OmniNode · omninode.suminnovation.xyz', href: 'https://omninode.suminnovation.xyz' },
          { label: 'INFERENCE-ATTESTATION.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/subprotocols/INFERENCE-ATTESTATION.md' },
          { label: 'inference-settlement.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/subprotocols/inference-settlement.md' },
        ]}
      />
    </PageShell>
  );
}
