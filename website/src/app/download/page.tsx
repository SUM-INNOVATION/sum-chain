import type { Metadata } from 'next';
import Link from 'next/link';
import PageShell from '@/components/PageShell';
import { Reveal, MonoTag, CodeBlock } from '@/components/ui/primitives';
import { SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Download | SUM Chain',
  description:
    'Get SUM Chain: build the node (sumchain) and CLI wallet (sumchain-wallet) from source, and install the TypeScript SDK (@sumchain/sdk) from npm.',
};

type Artifact = {
  name: string;
  bin: string;
  blurb: string;
  install: string;
  installLabel: string;
  page?: { href: string; label: string };
  note: string;
};

const ARTIFACTS: Artifact[] = [
  {
    name: 'Node',
    bin: 'sumchain',
    blurb: 'The full node: sync, verify, serve JSON-RPC, and gossip with peers.',
    installLabel: 'build',
    install: 'cargo build -p sumchain-node --release\n# → target/release/sumchain',
    page: { href: '/run-node', label: 'Run a node →' },
    note: 'Build from source today. Prebuilt binaries will be attached to GitHub Releases.',
  },
  {
    name: 'CLI Wallet',
    bin: 'sumchain-wallet',
    blurb: 'Encrypted keystore, address/balance, and signed Koppa transfers from the terminal.',
    installLabel: 'build',
    install: 'cargo build -p sumchain-wallet --release\n# → target/release/sumchain-wallet',
    page: { href: '/wallet', label: 'Wallet guide →' },
    note: 'Build from source today. Prebuilt binaries will be attached to GitHub Releases.',
  },
  {
    name: 'TypeScript SDK',
    bin: '@sumchain/sdk',
    blurb: 'Typed client (Provider + Koppa helpers) for reading state and sending transactions.',
    installLabel: 'npm',
    install: 'npm install @sumchain/sdk',
    page: { href: 'https://www.npmjs.com/package/@sumchain/sdk', label: 'View on npm →' },
    note: 'Published: @sumchain/sdk@0.1.0, installable now.',
  },
];

export default function DownloadPage() {
  return (
    <PageShell
      kicker="Download"
      title="Get SUM Chain"
      intro="Build the node and CLI wallet from source, or install the TypeScript SDK from npm. Prebuilt node and wallet binaries will be published as GitHub Release assets with checksums."
    >
      <section>
        <div className="mx-auto max-w-6xl space-y-6 px-6 py-16 lg:px-8">
          {ARTIFACTS.map((a, i) => (
            <Reveal key={a.name} delay={i * 0.06}>
              <div className="glass grid gap-6 rounded-2xl p-6 sm:p-8 lg:grid-cols-2 lg:items-center">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold text-foreground">
                      {a.name}
                    </h2>
                    <MonoTag>{a.bin}</MonoTag>
                  </div>
                  <p className="mt-3 text-sm leading-relaxed text-muted">{a.blurb}</p>
                  <p className="mono mt-3 text-xs text-muted">{a.note}</p>
                  {a.page && (
                    <Link
                      href={a.page.href}
                      target={a.page.href.startsWith('http') ? '_blank' : undefined}
                      rel={a.page.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                      className="mt-4 inline-flex text-sm font-medium text-foreground transition-colors hover:text-accent-soft"
                    >
                      {a.page.label}
                    </Link>
                  )}
                </div>
                <CodeBlock label={a.installLabel} code={a.install} />
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'Repository', href: 'https://github.com/SUM-INNOVATION/sum-chain' },
          { label: 'RELEASE.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/RELEASE.md' },
          { label: 'Docs', href: '/docs' },
        ]}
      />
    </PageShell>
  );
}
