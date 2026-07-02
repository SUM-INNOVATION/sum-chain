import type { Metadata } from 'next';
import PageShell from '@/components/PageShell';
import { SectionHeader, Reveal, MonoTag, CodeBlock } from '@/components/ui/primitives';
import { Card, StepFlow, Callout, SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Run a Node | SUM Chain',
  description:
    'Build and run a SUM Chain node from source: cargo build -p sumchain-node --release, then sumchain run --config config.toml --genesis genesis.json. Full node vs validator, and how validator-set membership works.',
};

const RUN_STEPS = [
  {
    title: 'Build from source',
    body: 'Compile the node binary from the workspace. The binary is named sumchain.',
    tag: 'target/release/sumchain',
  },
  {
    title: 'Prepare config and genesis',
    body: 'Use the example config.toml and a genesis file, or generate a starter config.',
    tag: 'sumchain gen-config',
  },
  { title: 'Run the node', body: 'Start syncing, serve JSON-RPC, and connect to peers via bootnodes.' },
];

export default function RunNodePage() {
  return (
    <PageShell
      kicker="Run a node"
      title="Run SUM Chain from source"
      intro="A SUM Chain node is a single Rust binary. Build it from this repository, point it at a config and genesis file, and it will sync the chain, serve JSON-RPC, and gossip with peers."
    >
      {/* Build + run */}
      <section>
        <div className="mx-auto grid max-w-6xl gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader kicker="Build & run" title="Three commands to a running node" />
            <div className="mt-8">
              <StepFlow steps={RUN_STEPS} />
            </div>
          </Reveal>
          <Reveal delay={0.1} className="space-y-4 lg:sticky lg:top-28 lg:self-start">
            <CodeBlock label="build" code={`# From the repository root
cargo build -p sumchain-node --release
# → binary at target/release/sumchain`} />
            <CodeBlock label="run" code={`target/release/sumchain run \\
  --config config.toml \\
  --genesis genesis.json`} />
            <CodeBlock label="optional flags" code={`sumchain run \\
  --config config.toml \\
  --genesis genesis.json \\
  --data-dir ./data \\
  --rpc 127.0.0.1:8545 \\
  --p2p 0.0.0.0:9933 \\
  --bootnodes /ip4/<PUBLIC_IP>/tcp/9933/p2p/<PEER_ID>`} />
          </Reveal>
        </div>
      </section>

      {/* Bootnodes */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-center gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Peering"
              title="Connect via bootnodes"
              intro="Bootnodes are multiaddrs your node dials to discover peers. Supply them with --bootnodes or in your config. Use your network's published bootnodes; the form below is a placeholder."
            />
            <div className="mt-6 flex flex-wrap gap-2">
              <MonoTag>--bootnodes</MonoTag>
              <MonoTag>/ip4/&lt;PUBLIC_IP&gt;/tcp/9933/p2p/&lt;PEER_ID&gt;</MonoTag>
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <CodeBlock label="config.toml (excerpt)" code={`# Example only — replace placeholders with real
# published bootnodes for your target network.
bootnodes = [
  "/ip4/<PUBLIC_IP>/tcp/9933/p2p/<PEER_ID>",
]`} />
          </Reveal>
        </div>
      </section>

      {/* Full node vs validator */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader kicker="Roles" title="Full node vs. validator" />
          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            <Reveal>
              <Card title="Full node">
                <p className="text-sm leading-relaxed text-muted">
                  Anyone can run a full node. It syncs blocks, verifies state, serves JSON-RPC, and
                  relays transactions and blocks to peers. Running a full node does not produce blocks.
                </p>
              </Card>
            </Reveal>
            <Reveal delay={0.1}>
              <Card title="Validator / block producer">
                <p className="text-sm leading-relaxed text-muted">
                  Block production runs under Proof-of-Authority: the proposer for each height is chosen
                  from the active validator set. Supplying a <MonoTag>--validator-key</MonoTag> does not
                  by itself make your node a block producer.
                </p>
              </Card>
            </Reveal>
          </div>
          <Reveal className="mt-6">
            <Callout tone="note" title="Validator-set membership is coordinated">
              Joining the active validator set is a coordinated Proof-of-Authority process, not an
              automatic outcome of running a node with a key. Run a full node to participate in the
              network today; validator onboarding is handled separately by the network operators.
            </Callout>
          </Reveal>
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'crates/node', href: 'https://github.com/SUM-INNOVATION/sum-chain/tree/main/crates/node' },
          { label: 'operator-guide.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/operator-guide.md' },
          { label: 'production-checklist.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/operations/production-checklist.md' },
        ]}
      />
    </PageShell>
  );
}
