import { useState, type ReactNode } from 'react';
import { copyToClipboard } from '../utils/formatters';

/**
 * Wraps a value (hash/address) with click-to-copy. Renders `children` (e.g. a
 * truncated, monospaced value) and a small copy affordance with transient
 * feedback. Keyboard-focusable and labeled; respects reduced motion (no
 * animation used).
 */
export function Copyable({
  text,
  children,
  className = '',
  title = 'Copy',
}: {
  text: string;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (await copyToClipboard(text)) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }
      }}
      className={`group inline-flex max-w-full items-center gap-1.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400/60 ${className}`}
      aria-label={`Copy ${text}`}
      title={title}
    >
      <span className="truncate">{children}</span>
      <span
        aria-hidden
        className={`shrink-0 text-xs ${copied ? 'text-emerald-400' : 'text-zinc-600 group-hover:text-zinc-400'}`}
      >
        {copied ? '✓' : '⧉'}
      </span>
    </button>
  );
}
