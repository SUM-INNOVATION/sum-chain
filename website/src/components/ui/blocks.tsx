'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';
import { MonoTag } from '@/components/ui/primitives';

/* Glass card with an optional heading + mono eyebrow. */
export function Card({
  eyebrow,
  title,
  children,
  className,
}: {
  eyebrow?: string;
  title?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`glass rounded-2xl p-6 sm:p-7 ${className ?? ''}`}>
      {eyebrow && <p className="mono text-xs text-muted">{eyebrow}</p>}
      {title && (
        <h3 className="mt-2 font-[family-name:var(--font-display)] text-lg font-semibold text-foreground">
          {title}
        </h3>
      )}
      <div className={title || eyebrow ? 'mt-3' : ''}>{children}</div>
    </div>
  );
}

/* Mono key/value spec list. */
export function SpecList({ rows }: { rows: { k: string; v: string }[] }) {
  return (
    <dl className="divide-y divide-[var(--border)]">
      {rows.map((r) => (
        <div key={r.k} className="flex items-baseline justify-between gap-4 py-2.5">
          <dt className="mono text-xs text-muted">{r.k}</dt>
          <dd className="tnum text-right text-sm text-muted-strong">{r.v}</dd>
        </div>
      ))}
    </dl>
  );
}

/* Numbered vertical step flow. */
export function StepFlow({ steps }: { steps: { title: string; body: ReactNode; tag?: string }[] }) {
  return (
    <ol className="relative space-y-6 border-l border-[var(--border)] pl-6">
      {steps.map((s, i) => (
        <li key={i} className="relative">
          <span className="mono absolute -left-[33px] flex h-6 w-6 items-center justify-center rounded-md border border-[var(--border)] bg-surface-2 text-xs text-accent-soft">
            {i + 1}
          </span>
          <h4 className="font-[family-name:var(--font-display)] text-base font-semibold text-foreground">
            {s.title} {s.tag && <MonoTag>{s.tag}</MonoTag>}
          </h4>
          <p className="mt-1.5 text-sm leading-relaxed text-muted">{s.body}</p>
        </li>
      ))}
    </ol>
  );
}

/* Amber callout for dormant / important protocol notes. */
export function Callout({
  tone = 'dormant',
  title,
  children,
}: {
  tone?: 'dormant' | 'roadmap' | 'note';
  title: string;
  children: ReactNode;
}) {
  const ring =
    tone === 'dormant'
      ? 'border-status-dormant/30 bg-status-dormant/[0.06]'
      : tone === 'roadmap'
        ? 'border-status-roadmap/30 bg-status-roadmap/[0.06]'
        : 'border-[var(--border-strong)] bg-surface/40';
  const dot =
    tone === 'dormant' ? 'bg-status-dormant' : tone === 'roadmap' ? 'bg-status-roadmap' : 'bg-muted';
  return (
    <div className={`rounded-2xl border p-5 sm:p-6 ${ring}`}>
      <div className="flex items-center gap-2.5">
        <span className={`h-2 w-2 rounded-full ${dot}`} />
        <p className="font-[family-name:var(--font-display)] text-sm font-semibold text-foreground">{title}</p>
      </div>
      <div className="mt-2 text-sm leading-relaxed text-muted">{children}</div>
    </div>
  );
}

/* "Grounded in" doc source links. */
export function SourceLinks({ links }: { links: { label: string; href: string }[] }) {
  return (
    <div className="border-t border-[var(--border)]">
      <div className="mx-auto max-w-6xl px-6 py-10 lg:px-8">
        <p className="kicker">Grounded in</p>
        <ul className="mt-4 flex flex-wrap gap-x-6 gap-y-2">
          {links.map((l) => (
            <li key={l.href}>
              <Link
                href={l.href}
                target={l.href.startsWith('http') ? '_blank' : undefined}
                rel={l.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                className="mono text-sm text-muted transition-colors hover:text-accent-soft"
              >
                {l.label} ↗
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
