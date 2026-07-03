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
  release?: { href: string; label: string };
  note: string;
};

const RELEASES = 'https://github.com/SUM-INNOVATION/sum-chain/releases/latest';

const ARTIFACTS: Artifact[] = [
  {
    name: 'Node',
    bin: 'sumchain',
    blurb: 'The full node: sync, verify, serve JSON-RPC, and gossip with peers. Download this only to run a node.',
    installLabel: 'download · linux-x86_64',
    install:
      'curl -LO https://github.com/SUM-INNOVATION/sum-chain/releases/download/v0.1.0/sumchain-v0.1.0-linux-x86_64\nchmod +x ./sumchain-v0.1.0-linux-x86_64',
    page: { href: '/run-node', label: 'Run a node →' },
    release: { href: RELEASES, label: 'All platforms & checksums →' },
    note: 'Also linux-arm64 and macos-arm64 — swap the suffix. Unsigned; verify with SHA256SUMS. Prefer source? cargo build -p sumchain-node --release.',
  },
  {
    name: 'CLI Wallet',
    bin: 'sumchain-wallet',
    blurb: 'Encrypted keystore, address/balance, and signed Koppa transfers from the terminal. All you need to hold and send Koppa — no node required.',
    installLabel: 'download · linux-x86_64',
    install:
      'curl -LO https://github.com/SUM-INNOVATION/sum-chain/releases/download/v0.1.0/sumchain-wallet-v0.1.0-linux-x86_64\nchmod +x ./sumchain-wallet-v0.1.0-linux-x86_64',
    page: { href: '/wallet', label: 'Wallet guide →' },
    release: { href: RELEASES, label: 'All platforms & checksums →' },
    note: 'Also linux-arm64 and macos-arm64 — swap the suffix. Unsigned; verify with SHA256SUMS. Prefer source? cargo build -p sumchain-wallet --release.',
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
      intro="Grab only what you need: the CLI wallet to hold and send Koppa, the node to run one, or the TypeScript SDK from npm. Prebuilt binaries (Linux + macOS) are on the latest release with checksums — or build from source."
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
                  <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2">
                    {a.release && (
                      <Link
                        href={a.release.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex text-sm font-medium text-accent-soft transition-colors hover:text-foreground"
                      >
                        {a.release.label}
                      </Link>
                    )}
                    {a.page && (
                      <Link
                        href={a.page.href}
                        target={a.page.href.startsWith('http') ? '_blank' : undefined}
                        rel={a.page.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                        className="inline-flex text-sm font-medium text-foreground transition-colors hover:text-accent-soft"
                      >
                        {a.page.label}
                      </Link>
                    )}
                  </div>
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
