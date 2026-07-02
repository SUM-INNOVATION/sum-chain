'use client';

import Link from 'next/link';
import {
  AcademicCapIcon,
  CommandLineIcon,
  ServerStackIcon,
  ScaleIcon,
  BookOpenIcon,
} from '@heroicons/react/24/outline';
import { Reveal } from '@/components/ui/primitives';

const PATHS = [
  { icon: AcademicCapIcon, title: 'Learn', desc: 'How storage, compute, and governance fit together.', href: '/storage' },
  { icon: CommandLineIcon, title: 'Build', desc: 'JSON-RPC, token families, and signed transactions.', href: '/docs' },
  { icon: ServerStackIcon, title: 'Run a node', desc: 'Build and run a full node from source.', href: '/run-node' },
  { icon: ScaleIcon, title: 'Governance', desc: 'Code-backed on-chain governance v1 (dormant).', href: '/governance' },
  { icon: BookOpenIcon, title: 'Docs', desc: 'Full JSON-RPC reference, verified on mainnet.', href: '/docs' },
];

export default function Pathways() {
  return (
    <section className="border-t border-[var(--border)] bg-surface/30">
      <div className="mx-auto max-w-6xl px-6 py-16 lg:px-8">
        <p className="kicker">Choose a path</p>
        <div className="mt-6 grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--border)] sm:grid-cols-3 lg:grid-cols-5">
          {PATHS.map((p, i) => {
            const Icon = p.icon;
            return (
              <Reveal key={p.title} delay={i * 0.05}>
                <Link
                  href={p.href}
                  className="group flex h-full flex-col bg-background p-5 transition-colors duration-200 hover:bg-surface-2"
                >
                  <Icon className="h-6 w-6 text-accent-soft" />
                  <h3 className="mt-4 font-[family-name:var(--font-display)] text-base font-semibold text-foreground">
                    {p.title}
                  </h3>
                  <p className="mt-1.5 text-sm leading-relaxed text-muted">{p.desc}</p>
                  <span className="mt-4 text-sm text-muted transition-colors group-hover:text-accent-soft">→</span>
                </Link>
              </Reveal>
            );
          })}
        </div>
      </div>
    </section>
  );
}
