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
  href: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  live: boolean;
};

// Status verified against live mainnet: SNIP V2 storage and OmniNode are active.
const liveItems: Item[] = [
  {
    title: 'Block Explorer',
    description: 'Track blocks, transactions, and addresses in real time.',
    href: 'https://explorer.sumchain.io',
    icon: MagnifyingGlassIcon,
    live: true,
  },
  {
    title: 'SUMailet Web',
    description: 'Browser wallet for sending and receiving Koppa. No download.',
    href: 'https://mlt.sumail.xyz/',
    icon: WalletIcon,
    live: true,
  },
  {
    title: 'CLI Wallet',
    description: 'Generate keys, sign, and broadcast transactions from the terminal.',
    href: '/#get-started',
    icon: CommandLineIcon,
    live: true,
  },
  {
    title: 'Snip',
    description: 'Decentralized link and content sharing, pinned to native storage with on-chain ACLs.',
    href: 'https://snip.sumchain.io',
    icon: LinkIcon,
    live: true,
  },
  {
    title: 'OmniNode',
    description: 'Verifiable AI compute. Inference attestations settle on-chain via the PoR engine.',
    href: 'https://omninode.suminnovation.xyz',
    icon: CpuChipIcon,
    live: true,
  },
  {
    title: 'Documentation',
    description: 'JSON-RPC reference with endpoints verified against live mainnet.',
    href: '/docs',
    icon: BookOpenIcon,
    live: true,
  },
];

const soonItems: Item[] = [
  {
    title: 'TypeScript SDK',
    description: 'Fully-typed SDK for querying balances and sending transactions.',
    href: '#',
    icon: CodeBracketIcon,
    live: false,
  },
  {
    title: 'Mobile App',
    description: 'Native iOS and Android apps for managing Koppa on the go.',
    href: '#',
    icon: DevicePhoneMobileIcon,
    live: false,
  },
];

function Row({ item, index }: { item: Item; index: number }) {
  const reduce = useReducedMotion();
  const Icon = item.icon;
  const external = item.href.startsWith('http');

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
      {item.live ? (
        <ArrowUpRightIcon className="h-5 w-5 shrink-0 text-muted transition-all duration-200 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-accent-soft" />
      ) : (
        <span className="shrink-0 rounded-full border border-[var(--border)] px-2.5 py-1 text-xs text-muted">
          Coming soon
        </span>
      )}
    </>
  );

  const className =
    'group flex items-center justify-between gap-4 rounded-2xl border border-[var(--border)] bg-surface/50 p-5 transition-colors duration-300';

  const wrapped = (
    <motion.div
      initial={reduce ? false : { opacity: 0, y: 14 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.4 }}
      transition={{ duration: 0.45, delay: (index % 2) * 0.06 }}
    >
      {item.live ? (
        <Link
          href={item.href}
          target={external ? '_blank' : undefined}
          rel={external ? 'noopener noreferrer' : undefined}
          className={`${className} hover:border-accent/40`}
        >
          {inner}
        </Link>
      ) : (
        <span
          title="Not open to public yet"
          aria-label={`${item.title} (not open to public yet)`}
          className={`${className} cursor-not-allowed opacity-80`}
        >
          {inner}
        </span>
      )}
    </motion.div>
  );

  return wrapped;
}

export default function Ecosystem() {
  return (
    <section id="ecosystem" className="relative scroll-mt-20 py-28 lg:py-36">
      <div className="mx-auto max-w-6xl px-6 lg:px-8">
        <div className="mb-12 max-w-2xl">
          <h2 className="font-[family-name:var(--font-display)] text-4xl font-bold tracking-tight sm:text-5xl">
            Tools and apps, ready to use
          </h2>
          <p className="mt-4 text-lg text-muted">
            A growing suite for users, developers, and validators.
          </p>
        </div>

        <p className="mb-4 text-sm font-medium text-muted-strong">Live now</p>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {liveItems.map((item, i) => (
            <Row key={item.title} item={item} index={i} />
          ))}
        </div>

        <p className="mb-4 mt-10 text-sm font-medium text-muted-strong">Coming soon</p>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {soonItems.map((item, i) => (
            <Row key={item.title} item={item} index={i} />
          ))}
        </div>
      </div>
    </section>
  );
}
