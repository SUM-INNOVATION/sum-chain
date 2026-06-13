'use client';

import { motion, useReducedMotion } from 'framer-motion';
import Link from 'next/link';
import { ArrowRightIcon } from '@heroicons/react/24/outline';

const stats = [
  { label: 'Block Time', value: '3s' },
  { label: 'Typical Fee', value: '~0.001 Ϙ' },
  { label: 'Total Supply', value: '800B Ϙ' },
  { label: 'Finality', value: '~18s' },
];

export default function Hero() {
  const reduce = useReducedMotion();
  const rise = (delay: number) =>
    reduce
      ? { initial: false as const }
      : {
          initial: { opacity: 0, y: 18 },
          animate: { opacity: 1, y: 0 },
          transition: { duration: 0.6, delay, ease: [0.16, 1, 0.3, 1] as const },
        };

  return (
    <>
      <section className="relative flex min-h-[100dvh] items-center overflow-hidden">
        {/* Intentional, restrained backdrop: structural grid + one soft brand glow.
            No mouse-follow, no floating-orb soup. */}
        <div className="absolute inset-0 grid-pattern opacity-70" aria-hidden="true" />
        <div
          className="absolute left-1/2 top-[-10%] h-[520px] w-[820px] -translate-x-1/2 rounded-full opacity-50 blur-[120px]"
          style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.22), transparent 70%)' }}
          aria-hidden="true"
        />

        <div className="relative z-10 mx-auto w-full max-w-6xl px-6 pt-24 lg:px-8">
          <div className="max-w-3xl">
            <motion.div
              {...rise(0.05)}
              className="glass mb-8 inline-flex items-center gap-2 rounded-full px-4 py-1.5 text-sm text-muted-strong"
            >
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-60" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-green-400" />
              </span>
              Mainnet Live
            </motion.div>

            <motion.h1
              {...rise(0.12)}
              className="font-[family-name:var(--font-display)] text-5xl font-bold leading-[1.02] tracking-tight sm:text-6xl lg:text-7xl"
            >
              A Utility-Backed
              <span className="block gradient-text">Layer-1</span>
            </motion.h1>

            <motion.p {...rise(0.2)} className="mt-6 max-w-xl text-lg text-muted">
              The Rust-built Layer-1 where Koppa (Ϙ) is backed by real on-chain
              utility, not just payments.
            </motion.p>

            <motion.div {...rise(0.28)} className="mt-10 flex flex-col gap-4 sm:flex-row">
              <Link
                href="/#get-started"
                className="group inline-flex items-center justify-center gap-2 rounded-full bg-foreground px-7 py-3.5 text-base font-medium text-background transition-transform duration-200 hover:-translate-y-0.5 active:translate-y-0"
              >
                Start Building
                <ArrowRightIcon className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5" />
              </Link>
              <Link
                href="https://explorer.sumchain.io"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-2 rounded-full border border-[var(--border-strong)] px-7 py-3.5 text-base font-medium text-muted-strong transition-colors duration-200 hover:border-accent/50 hover:text-foreground"
              >
                View Explorer
              </Link>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Stats band, directly below the hero (kept out of the hero stack per
          hero-discipline rules). All figures verified against live mainnet. */}
      <section className="relative border-y border-[var(--border)] bg-surface/40">
        <div className="mx-auto grid max-w-6xl grid-cols-2 gap-px px-6 lg:grid-cols-4 lg:px-8">
          {stats.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={reduce ? false : { opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ duration: 0.45, delay: i * 0.06 }}
              className="py-8 text-center lg:py-10"
            >
              <div className="tnum font-[family-name:var(--font-display)] text-3xl font-bold sm:text-4xl">
                {stat.value}
              </div>
              <div className="mt-2 text-xs uppercase tracking-[0.15em] text-muted">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </div>
      </section>
    </>
  );
}
