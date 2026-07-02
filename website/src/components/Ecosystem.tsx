'use client';

import { motion, useReducedMotion } from 'framer-motion';
import Link from 'next/link';
import type { ComponentType, SVGProps } from 'react';
import {
  MagnifyingGlassIcon,
  CommandLineIcon,
  WalletIcon,
  LinkIcon,
  CpuChipIcon,
  BookOpenIcon,
  CodeBracketIcon,
  DevicePhoneMobileIcon,
  ArrowUpRightIcon,
} from '@heroicons/react/24/outline';

type Item = {
  title: string;
  description: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  /** External/internal link. Omit for a product-surface tile with no link. */
  href?: string;
  /** Small chip shown instead of an arrow for no-link product surfaces. */
  tag?: string;
};

// Status verified against live mainnet: SNIP V2 storage and OmniNode are active.
// CLI Wallet is repo-grounded (crates/wallet); SUMaillet Web/Mobile are SUMaillet
// product surfaces (external apps, not shipped from this repository).
const items: Item[] = [
  {
    title: 'Block Explorer',
    description: 'Track blocks, transactions, and addresses in real time.',
    href: 'https://explorer.sumchain.io',
    icon: MagnifyingGlassIcon,
  },
  {
    title: 'CLI Wallet',
    description: 'Repo-grounded wallet, built from crates/wallet: encrypted keystore, balance, and signed Koppa transfers.',
    href: '/wallet',
    icon: CommandLineIcon,
  },
  {
    title: 'SUMaillet Web',
    description: 'SUMaillet product surface (external). Hosted browser wallet for Koppa, governance, and the full SRC token family.',
    href: 'https://mlt.sumail.xyz/',
    icon: WalletIcon,
  },
  {
    title: 'SUMaillet Mobile',
    description: 'SUMaillet product surface (external). Native iOS and Android for Koppa, governance, and the full SRC token family.',
    tag: 'iOS · Android',
    icon: DevicePhoneMobileIcon,
  },
  {
    title: 'Snip',
    description: 'Decentralized link and content sharing, pinned to native storage with on-chain ACLs.',
    href: 'https://snip.sumchain.io',
    icon: LinkIcon,
  },
  {
    title: 'OmniNode',
    description: 'Verifiable AI compute. Verifier-signed inference attestations settle on-chain.',
    href: 'https://omninode.suminnovation.xyz',
    icon: CpuChipIcon,
  },
  {
    title: 'TypeScript SDK',
    description: 'Fully-typed client for balances and transactions. Available on npm as @sumchain/sdk.',
    href: 'https://www.npmjs.com/package/@sumchain/sdk',
    icon: CodeBracketIcon,
  },
  {
    title: 'Documentation',
    description: 'JSON-RPC reference with endpoints verified against live mainnet.',
    href: '/docs',
    icon: BookOpenIcon,
  },
];

function Row({ item, index }: { item: Item; index: number }) {
  const reduce = useReducedMotion();
  const Icon = item.icon;
  const external = item.href?.startsWith('http');

  const inner = (
    <>
      <div className="flex items-center gap-4">
        <span className="inline-flex shrink-0 rounded-xl border border-[var(--border)] bg-accent/10 p-2.5 text-accent-soft">
          <Icon className="h-5 w-5" strokeWidth={1.5} />
        </span>
        <div>
          <h4 className="font-[family-name:var(--font-display)] font-semibold">{item.title}</h4>
          <p className="mt-0.5 text-sm text-muted">{item.description}</p>
        </div>
      </div>
      {item.href ? (
        <ArrowUpRightIcon className="h-5 w-5 shrink-0 text-muted transition-all duration-200 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-accent-soft" />
      ) : (
        <span className="mono shrink-0 rounded-full border border-[var(--border)] px-2.5 py-1 text-xs text-muted">
          {item.tag ?? 'app'}
        </span>
      )}
    </>
  );

  const className =
    'group flex items-center justify-between gap-4 rounded-2xl border border-[var(--border)] bg-surface/50 p-5 transition-colors duration-300';

  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, y: 14 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.4 }}
      transition={{ duration: 0.45, delay: (index % 2) * 0.06 }}
    >
      {item.href ? (
        <Link
          href={item.href}
          target={external ? '_blank' : undefined}
          rel={external ? 'noopener noreferrer' : undefined}
          className={`${className} hover:border-accent/40`}
        >
          {inner}
        </Link>
      ) : (
        <div className={className}>{inner}</div>
      )}
    </motion.div>
  );
}

export default function Ecosystem() {
  return (
    <section id="ecosystem" className="relative scroll-mt-20 py-28 lg:py-36">
      <div className="mx-auto max-w-6xl px-6 lg:px-8">
        <div className="mb-12 max-w-2xl">
          <h2 className="font-[family-name:var(--font-display)] text-4xl font-bold tracking-tight sm:text-5xl">
            Tools and apps
          </h2>
          <p className="mt-4 text-lg text-muted">
            A suite for users, developers, and operators — plus the SUMaillet product surfaces.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {items.map((item, i) => (
            <Row key={item.title} item={item} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
}
