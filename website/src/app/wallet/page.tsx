import type { Metadata } from 'next';
import Link from 'next/link';
import PageShell from '@/components/PageShell';
import { SectionHeader, Reveal, MonoTag, CodeBlock } from '@/components/ui/primitives';
import { Card, Callout, SourceLinks } from '@/components/ui/blocks';

export const metadata: Metadata = {
  title: 'Wallet | SUM Chain',
  description:
    'The SUM Chain CLI wallet (sumchain-wallet): generate an encrypted keystore, show your address, check balances, and sign/send Koppa transfers. Encrypted with Argon2 + AES-256-GCM. No seed phrases.',
};

export default function WalletPage() {
  return (
    <PageShell
      kicker="Wallet"
      title="The SUM Chain CLI wallet"
      intro="sumchain-wallet is the repository-grounded wallet: generate keys into an encrypted keystore, inspect your address and balance, and sign or send Koppa transfers from the terminal."
    >
      {/* Build + keygen */}
      <section>
        <div className="mx-auto grid max-w-6xl gap-12 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <SectionHeader
              kicker="Get the wallet"
              title="Build, then generate an encrypted keystore"
              intro="Build the binary from source, then create a keypair. keygen prompts for a password and writes an encrypted keystore file — the private key is protected with Argon2 key derivation and AES-256-GCM."
            />
            <div className="mt-6 flex flex-wrap gap-2">
              <MonoTag>Argon2</MonoTag>
              <MonoTag>AES-256-GCM</MonoTag>
              <MonoTag>no seed phrase</MonoTag>
            </div>
          </Reveal>
          <Reveal delay={0.1} className="space-y-4">
            <CodeBlock label="build" code={`cargo build -p sumchain-wallet --release
# → binary at target/release/sumchain-wallet`} />
            <CodeBlock label="keygen" code={`sumchain-wallet keygen --output keystore.json
# prompts for a password, then prints your
# public key and address`} />
          </Reveal>
        </div>
      </section>

      {/* Core commands */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto max-w-6xl px-6 py-20 lg:px-8">
          <SectionHeader kicker="Everyday use" title="Address, balance, and transfers" />
          <div className="mt-10 grid gap-4 lg:grid-cols-2">
            <Reveal>
              <CodeBlock label="address & pubkey" code={`sumchain-wallet address --key keystore.json
sumchain-wallet pubkey  --key keystore.json`} />
            </Reveal>
            <Reveal delay={0.06}>
              <CodeBlock label="balance" code={`sumchain-wallet balance \\
  --rpc https://rpc.sumchain.io \\
  --address <YOUR_ADDRESS>`} />
            </Reveal>
            <Reveal delay={0.12}>
              <CodeBlock label="transfer (sign + send)" code={`sumchain-wallet transfer \\
  --key keystore.json \\
  --rpc https://rpc.sumchain.io \\
  --to <RECIPIENT> \\
  --amount 1.5 \\
  --chain-id 1`} />
            </Reveal>
            <Reveal delay={0.18}>
              <CodeBlock label="offline sign, then send" code={`# Sign offline (air-gapped), broadcast later
sumchain-wallet sign-tx --key keystore.json \\
  --to <RECIPIENT> --amount 1.5 --fee 0.001 \\
  --nonce <N> --chain-id 1
sumchain-wallet send --rpc https://rpc.sumchain.io \\
  --raw 0x<SIGNED_TX_HEX>`} />
            </Reveal>
          </div>
        </div>
      </section>

      {/* Safety + hosted option */}
      <section className="border-t border-[var(--border)]">
        <div className="mx-auto grid max-w-6xl items-start gap-6 px-6 py-20 lg:grid-cols-2 lg:px-8">
          <Reveal>
            <Callout tone="note" title="Keep your keystore safe">
              Your funds are controlled by the encrypted keystore file and its password. Back up{' '}
              <MonoTag>keystore.json</MonoTag> and remember the password — there is no seed phrase and no
              recovery if both are lost. Never share the keystore or password.
            </Callout>
          </Reveal>
          <Reveal delay={0.1}>
            <Card eyebrow="hosted (external)" title="Prefer a browser?">
              <p className="text-sm leading-relaxed text-muted">
                SUMaillet is a hosted browser wallet operated separately from this repository. It is not
                part of the SUM Chain codebase; the CLI wallet above is the repo-grounded path.
              </p>
              <Link
                href="https://mlt.sumail.xyz/"
                target="_blank"
                rel="noopener noreferrer"
                className="mt-4 inline-flex text-sm font-medium text-foreground transition-colors hover:text-accent-soft"
              >
                Open SUMaillet (hosted) ↗
              </Link>
            </Card>
          </Reveal>
        </div>
      </section>

      <SourceLinks
        links={[
          { label: 'crates/wallet', href: 'https://github.com/SUM-INNOVATION/sum-chain/tree/main/crates/wallet' },
          { label: 'tokens.md', href: 'https://github.com/SUM-INNOVATION/sum-chain/blob/main/docs/tokens.md' },
        ]}
      />
    </PageShell>
  );
}
