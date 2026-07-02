import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import SystemMap from '@/components/SystemMap';
import { SectionHeader, Reveal, MonoTag } from '@/components/ui/primitives';
import { Card, SpecList, Callout, SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Verifiable AI Compute | SUM Chain',
  description:
    'OmniNode inference attestation on SUM Chain: users pay Koppa, inference nodes compute, a verifier signs the result, and the chain records a permanent InferenceAttestation. Live on mainnet; reward/slash settlement is on the roadmap.',
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
            <Callout tone="roadmap" title="What is not yet on-chain">
              v1 records attestations only. On-chain reward, slashing, and dispute settlement are on
              the roadmap — the chain does not pay or penalize inference nodes today. v1 also requires
              the transaction sender to be the verifier (no sponsored submission).
            </Callout>
          </Reveal>
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'INFERENCE-ATTESTATION.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/subprotocols/INFERENCE-ATTESTATION.md' },
          { label: 'INFERENCE-ATTESTATION-ACTIVATION.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/subprotocols/INFERENCE-ATTESTATION-ACTIVATION.md' },
        ]}
      />
    </PageShell>
  );
}
