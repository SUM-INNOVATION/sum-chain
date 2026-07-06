'use client';

import { motion, useReducedMotion } from 'framer-motion';
import { useState, type ReactNode } from 'react';

/* ------------------------------------------------------------------ */
/* Status pill — encodes protocol reality: active / dormant / roadmap  */
/* ------------------------------------------------------------------ */

export type Status = 'active' | 'pending' | 'dormant' | 'roadmap';

const STATUS_META: Record<Status, { label: string; color: string; ring: string; dot: string }> = {
  active: {
    label: 'Live on mainnet',
    color: 'text-status-active',
    ring: 'border-status-active/30 bg-status-active/10',
    dot: 'bg-status-active',
  },
  pending: {
    label: 'Pending activation',
    color: 'text-status-pending',
    ring: 'border-status-pending/30 bg-status-pending/10',
    dot: 'bg-status-pending',
  },
  dormant: {
    label: 'Code-backed · dormant',
    color: 'text-status-dormant',
    ring: 'border-status-dormant/30 bg-status-dormant/10',
    dot: 'bg-status-dormant',
  },
  roadmap: {
    label: 'Roadmap',
    color: 'text-status-roadmap',
    ring: 'border-status-roadmap/30 bg-status-roadmap/10',
    dot: 'bg-status-roadmap',
  },
};

export function StatusPill({ status, label }: { status: Status; label?: string }) {
  const m = STATUS_META[status];
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${m.ring} ${m.color}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot} ${status === 'active' || status === 'pending' ? 'status-pulse' : ''}`} />
      <span className="mono tracking-wide">{label ?? m.label}</span>
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Mono protocol tag (InferenceAttestation, PoR, merkle_root, gov_*)   */
/* ------------------------------------------------------------------ */

export function MonoTag({ children }: { children: ReactNode }) {
  return (
    <span className="mono rounded-md border border-[var(--border)] bg-surface-2 px-1.5 py-0.5 text-[0.8em] text-muted-strong">
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Reveal — standard scroll-in, reduced-motion safe                    */
/* ------------------------------------------------------------------ */

export function Reveal({
  children,
  delay = 0,
  className,
  as = 'div',
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
  as?: 'div' | 'li' | 'section';
}) {
  const reduce = useReducedMotion();
  const MotionTag = motion[as] as typeof motion.div;
  return (
    <MotionTag
      className={className}
      initial={reduce ? false : { opacity: 0, y: 20 }}
      whileInView={reduce ? undefined : { opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.25 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay }}
    >
      {children}
    </MotionTag>
  );
}

/* ------------------------------------------------------------------ */
/* Section header — kicker + title + intro                             */
/* ------------------------------------------------------------------ */

export function SectionHeader({
  kicker,
  title,
  intro,
  status,
  align = 'left',
}: {
  kicker: string;
  title: ReactNode;
  intro?: ReactNode;
  status?: Status;
  align?: 'left' | 'center';
}) {
  return (
    <div className={align === 'center' ? 'mx-auto max-w-2xl text-center' : 'max-w-2xl'}>
      <div className={`flex items-center gap-3 ${align === 'center' ? 'justify-center' : ''}`}>
        <span className="kicker">{kicker}</span>
        {status && <StatusPill status={status} />}
      </div>
      <h2 className="mt-4 font-[family-name:var(--font-display)] text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
        {title}
      </h2>
      {intro && <p className="mt-4 text-base leading-relaxed text-muted">{intro}</p>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Stat — labeled data readout                                         */
/* ------------------------------------------------------------------ */

export function Stat({ value, label, sub }: { value: ReactNode; label: string; sub?: string }) {
  return (
    <div>
      <div className="tnum font-[family-name:var(--font-display)] text-2xl font-semibold text-foreground sm:text-3xl">
        {value}
      </div>
      <div className="mt-1 text-sm text-muted-strong">{label}</div>
      {sub && <div className="mono mt-0.5 text-xs text-muted">{sub}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Code block — mono, optional copy                                    */
/* ------------------------------------------------------------------ */

export function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable — no-op */
    }
  };
  return (
    <div className="glass overflow-hidden rounded-xl">
      <div className="flex items-center justify-between border-b border-[var(--border)] px-4 py-2.5">
        <span className="mono text-xs text-muted">{label ?? 'shell'}</span>
        <button
          onClick={copy}
          className="mono text-xs text-muted transition-colors hover:text-foreground"
          aria-label="Copy code"
        >
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 text-sm leading-relaxed">
        <code className="mono text-muted-strong">{code}</code>
      </pre>
    </div>
  );
}
