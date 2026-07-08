import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import type { AddressLabelsInfo } from '@sumchain/sdk';
import { provider } from '../utils/provider';
import { formatAddress } from '../utils/formatters';
import { Copyable } from './Copyable';

/**
 * Module-level cache: address -> in-flight/resolved label lookup. Dedupes calls
 * across every row that renders the same address (issue #64). A failed lookup
 * caches `null` so we fall back to the raw address without re-hammering the RPC.
 */
const cache = new Map<string, Promise<AddressLabelsInfo | null>>();

function resolveLabels(address: string): Promise<AddressLabelsInfo | null> {
  let p = cache.get(address);
  if (!p) {
    p = provider.resolveAddressLabels(address).catch(() => null);
    cache.set(address, p);
  }
  return p;
}

function useLabels(address: string): AddressLabelsInfo | null {
  const [info, setInfo] = useState<AddressLabelsInfo | null>(null);
  useEffect(() => {
    let alive = true;
    setInfo(null);
    resolveLabels(address).then((r) => {
      if (alive) setInfo(r);
    });
    return () => {
      alive = false;
    };
  }, [address]);
  return info;
}

function RoleTag() {
  return (
    <span className="inline-flex shrink-0 items-center rounded bg-white/5 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted">
      role
    </span>
  );
}

/**
 * Renders an address with its **current** public on-chain registry label when
 * one exists (institution/issuer name, or a role/class), always keeping the raw
 * address visible and copyable. Falls back to the raw address alone when there
 * is no label or the RPC fails. This is a live-registry label, not a claim that
 * the label was valid at a historical transaction height.
 *
 * Modes:
 * - `full` (default): interactive — linked label + copyable short address.
 * - `inline`: plain, non-interactive `label · short` text; safe inside a parent
 *   link (e.g. compact list rows). Falls back to the short address.
 * - `chip`: just the label (+ role tag), or `null` when there is no label — for
 *   contexts that already render the raw address separately.
 */
export function AddressLabel({
  address,
  mode = 'full',
  chars = 6,
  className = '',
}: {
  address: string;
  mode?: 'full' | 'inline' | 'chip';
  chars?: number;
  className?: string;
}) {
  const info = useLabels(address);
  const primary = info?.primary_label ?? null;
  const kind = primary ? info?.labels.find((l) => l.label === primary)?.kind : undefined;
  const short = formatAddress(address, chars);

  if (mode === 'chip') {
    if (!primary) return null;
    return (
      <span className={`inline-flex min-w-0 items-center gap-1.5 ${className}`}>
        <span className="min-w-0 truncate font-medium text-foreground" title="Current on-chain registry label">
          {primary}
        </span>
        {kind === 'role' && <RoleTag />}
      </span>
    );
  }

  if (mode === 'inline') {
    // Plain text (no nested links) for use inside a parent <Link>.
    return (
      <span className={className}>
        {primary ? (
          <>
            <span className="font-medium text-muted-strong">{primary}</span>
            {kind === 'role' && <span className="ml-1 text-[10px] uppercase text-muted">·role</span>}
            <span className="text-muted"> · {short}</span>
          </>
        ) : (
          short
        )}
      </span>
    );
  }

  // full
  if (!primary) {
    return (
      <Link
        to={`/address/${address}`}
        className={`tnum break-all font-mono text-accent-soft hover:text-primary-200 ${className}`}
      >
        {address}
      </Link>
    );
  }
  return (
    <span className={`inline-flex min-w-0 flex-wrap items-center gap-1.5 ${className}`}>
      <Link
        to={`/address/${address}`}
        title={`Current on-chain registry label — ${primary}`}
        className="min-w-0 truncate font-medium text-foreground hover:text-accent-soft"
      >
        {primary}
      </Link>
      {kind === 'role' && <RoleTag />}
      <span aria-hidden className="shrink-0 text-muted">
        ·
      </span>
      <Copyable text={address} title="Copy address">
        <span className="tnum shrink-0 font-mono text-xs text-muted">{short}</span>
      </Copyable>
    </span>
  );
}
