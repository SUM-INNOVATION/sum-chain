'use client';

import { motion, useReducedMotion } from 'framer-motion';
import type { ComponentType, SVGProps } from 'react';
import {
  BoltIcon,
  BanknotesIcon,
  ShieldCheckIcon,
  CircleStackIcon,
  CpuChipIcon,
  FingerPrintIcon,
  CommandLineIcon,
} from '@heroicons/react/24/outline';

type Feature = {
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  title: string;
  description: string;
  span: string;
  featured?: boolean;
};

// Bento with rhythm: 7 items -> 7 cells (2+1 / 1+2 / 1+1+1). Two wide cells and
// the AI cell carry a tinted brand background so the grid is not 7 flat cards.
const features: Feature[] = [
  {
    icon: BoltIcon,
    title: 'Fast and final',
    description:
      '3-second blocks with deterministic finality in about 18 seconds (6 confirmations). Transactions settle while you wait.',
    span: 'lg:col-span-2',
    featured: true,
  },
  {
    icon: BanknotesIcon,
    title: 'Near-zero fees',
    description: 'A typical transfer costs around 0.001 Ϙ, so fees never eat the amount you send.',
    span: 'lg:col-span-1',
  },
  {
    icon: ShieldCheckIcon,
    title: 'Proven cryptography',
    description: 'Ed25519 signatures and Blake3 hashing under Proof of Authority consensus.',
    span: 'lg:col-span-1',
  },
  {
    icon: CircleStackIcon,
    title: 'Native decentralized storage',
    description:
      'A Layer-1 Proof-of-Retrievability engine with on-chain Merkle proofs. Archive nodes earn Koppa for serving files; cheats get slashed. Live on mainnet.',
    span: 'lg:col-span-2',
    featured: true,
  },
  {
    icon: CpuChipIcon,
    title: 'Verifiable AI compute',
    description:
      'OmniNode settles verifier-signed inference attestations on-chain. Pay once for compute, prove it forever.',
    span: 'lg:col-span-1',
    featured: true,
  },
  {
    icon: FingerPrintIcon,
    title: 'Identity and access',
    description:
      'On-chain access lists, encrypted messaging (SRC-201), and document-credential token families for tax, equity, and healthcare.',
    span: 'lg:col-span-1',
  },
  {
    icon: CommandLineIcon,
    title: 'Pure Rust',
    description: 'Built entirely in Rust with zero C or C++ dependencies. Memory-safe, fast, auditable.',
    span: 'lg:col-span-1',
  },
];

export default function Features() {
  const reduce = useReducedMotion();

  return (
    <section id="features" className="relative scroll-mt-20 py-28 lg:py-36">
      <div className="mx-auto max-w-6xl px-6 lg:px-8">
        <div className="mb-14 max-w-2xl">
          <h2 className="font-[family-name:var(--font-display)] text-4xl font-bold tracking-tight sm:text-5xl">
            Backed by real on-chain utility
          </h2>
          <p className="mt-4 text-lg text-muted">
            SUM Chain pairs fast, cheap payments with storage, verifiable compute,
            messaging, and credentials, all native to the Layer-1.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <motion.div
                key={feature.title}
                initial={reduce ? false : { opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.3 }}
                transition={{ duration: 0.5, delay: (index % 3) * 0.08, ease: [0.16, 1, 0.3, 1] }}
                className={`group relative overflow-hidden rounded-2xl border border-[var(--border)] p-7 transition-colors duration-300 hover:border-accent/40 ${feature.span} ${
                  feature.featured
                    ? 'bg-gradient-to-br from-brand-deep/40 to-surface'
                    : 'bg-surface/50'
                }`}
              >
                <div className="mb-5 inline-flex rounded-xl border border-[var(--border)] bg-accent/10 p-3 text-accent-soft">
                  <Icon className="h-6 w-6" strokeWidth={1.5} />
                </div>
                <h3 className="font-[family-name:var(--font-display)] text-xl font-semibold transition-colors duration-300 group-hover:text-accent-soft">
                  {feature.title}
                </h3>
                <p className="mt-2 leading-relaxed text-muted">{feature.description}</p>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
