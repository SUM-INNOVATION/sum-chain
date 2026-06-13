// Shared loading / error states. Skeletons mirror the shape of the content
// they replace (redesign-skill: no generic circular spinners), and every page
// gets a real, user-facing error state with retry instead of a silent log.

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton rounded-md ${className}`} />;
}

export function ErrorState({
  message = 'Could not reach the network.',
  onRetry,
}: {
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="mx-auto max-w-md rounded-2xl border border-zinc-800 bg-zinc-900/50 p-8 text-center">
      <h2 className="font-display text-xl font-semibold text-white">Something went wrong</h2>
      <p className="mt-2 text-sm text-zinc-400">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-5 rounded-full bg-primary-500 px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-600 active:translate-y-px"
        >
          Try again
        </button>
      )}
    </div>
  );
}

// Card skeleton for list rows (blocks, transactions, validators).
export function RowSkeleton() {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-3 w-40" />
        </div>
        <div className="space-y-2 text-right">
          <Skeleton className="ml-auto h-3 w-16" />
          <Skeleton className="ml-auto h-3 w-12" />
        </div>
      </div>
    </div>
  );
}

// Detail skeleton for the key/value detail panels.
export function DetailSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-4 rounded-2xl border border-zinc-800 bg-zinc-900/50 p-6">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      ))}
    </div>
  );
}
