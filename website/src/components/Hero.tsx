'use client';

import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { useRef, type PointerEvent } from 'react';

const rise = (delay: number, reduce: boolean | null) =>
  reduce
    ? { initial: false as const }
    : {
        initial: { opacity: 0, y: 18 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.8, ease: [0.16, 1, 0.3, 1] as const, delay },
      };

export default function Hero() {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLElement>(null);

  const onMove = (e: PointerEvent<HTMLElement>) => {
    if (reduce || e.pointerType !== 'mouse') return;
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${((e.clientX - r.left) / r.width) * 100}%`);
    el.style.setProperty('--my', `${((e.clientY - r.top) / r.height) * 100}%`);
    el.dataset.active = 'true';
  };
  const onLeave = () => {
    if (ref.current) ref.current.dataset.active = 'false';
  };

  return (
    <section
      ref={ref}
      onPointerMove={onMove}
      onPointerLeave={onLeave}
      className="spotlight relative overflow-hidden pt-40 pb-24 sm:pt-48 sm:pb-32"
    >
      <div className="grid-pattern absolute inset-0" aria-hidden="true" />
      <div
        className="absolute inset-x-0 top-0 h-[520px]"
        aria-hidden="true"
        style={{
          background:
            'radial-gradient(60% 50% at 50% 0%, rgba(168,85,247,0.14), transparent 70%), radial-gradient(42% 42% at 82% 8%, rgba(34,211,238,0.08), transparent 70%)',
        }}
      />

      <div className="relative mx-auto max-w-6xl px-6 lg:px-8">
        <motion.div {...rise(0, reduce)}>
          <span className="kicker">Rust Layer-1 · Koppa (Ϙ)</span>
        </motion.div>

        <motion.h1
          {...rise(0.08, reduce)}
          className="mt-5 max-w-4xl font-[family-name:var(--font-display)] text-4xl font-semibold leading-[1.08] tracking-tight sm:text-6xl"
        >
          Open infrastructure for{' '}
          <span className="gradient-text">decentralized storage, verifiable AI compute,</span> and
          on-chain governance.
        </motion.h1>

        <motion.p {...rise(0.16, reduce)} className="mt-6 max-w-2xl text-lg leading-relaxed text-muted">
          SUM Chain is a Rust-built Layer-1 where Koppa is backed by real on-chain work — not just
          payments. Files are held under Proof-of-Retrievability, AI inference settles through
          verifier-signed attestations, and governance is code-backed and validator-respecting.
        </motion.p>

        <motion.div {...rise(0.24, reduce)} className="mt-9 flex flex-wrap items-center gap-4">
          <Link
            href="/storage"
            className="rounded-full bg-foreground px-6 py-3 text-sm font-semibold text-background transition-transform duration-200 hover:scale-[1.02]"
          >
            Explore the protocol
          </Link>
          <Link
            href="/docs"
            className="rounded-full border border-[var(--border-strong)] px-6 py-3 text-sm font-medium text-foreground transition-colors duration-200 hover:border-accent/60 hover:bg-accent/10"
          >
            Read the docs
          </Link>
          <Link
            href="https://explorer.sumchain.io"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted transition-colors hover:text-foreground"
          >
            View explorer ↗
          </Link>
        </motion.div>

        <motion.dl
          {...rise(0.32, reduce)}
          className="mt-16 grid max-w-3xl grid-cols-2 gap-x-8 gap-y-6 border-t border-[var(--border)] pt-8 sm:grid-cols-4"
        >
          {[
            { v: '3s', l: 'Block time' },
            { v: '~18s', l: 'Finality · depth 6' },
            { v: '800B Ϙ', l: 'Fixed supply' },
            { v: '100% Rust', l: 'Zero C/C++ deps' },
          ].map((s) => (
            <div key={s.l}>
              <dt className="tnum font-[family-name:var(--font-display)] text-2xl font-semibold">{s.v}</dt>
              <dd className="mt-1 text-sm text-muted">{s.l}</dd>
            </div>
          ))}
        </motion.dl>
      </div>
    </section>
  );
}
