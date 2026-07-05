import type { TxDomain } from '@sumchain/sdk';

export { classifyTransaction } from '@sumchain/sdk';
export type { TxClassifiable, TxClassification, TxDomain } from '@sumchain/sdk';

/**
 * Tailwind classes for each transaction domain chip. Muted, on-brand with the
 * dark explorer theme; status is never conveyed by color alone — the chip
 * always carries its text label, and a `title` exposes the full action.
 */
export const DOMAIN_STYLE: Record<TxDomain, string> = {
  native: 'bg-zinc-500/15 text-zinc-200 ring-1 ring-inset ring-zinc-400/25',
  token: 'bg-primary-500/15 text-primary-200 ring-1 ring-inset ring-primary-400/30',
  snip: 'bg-emerald-500/15 text-emerald-200 ring-1 ring-inset ring-emerald-400/25',
  omninode: 'bg-sky-500/15 text-sky-200 ring-1 ring-inset ring-sky-400/25',
  governance: 'bg-amber-500/15 text-amber-200 ring-1 ring-inset ring-amber-400/25',
  policy: 'bg-fuchsia-500/15 text-fuchsia-200 ring-1 ring-inset ring-fuchsia-400/25',
  messaging: 'bg-cyan-500/15 text-cyan-200 ring-1 ring-inset ring-cyan-400/25',
  other: 'bg-slate-500/15 text-slate-200 ring-1 ring-inset ring-slate-400/25',
};
