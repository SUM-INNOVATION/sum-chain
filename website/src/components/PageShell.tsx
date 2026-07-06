import type { ReactNode } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { StatusPill, type Status } from '@/components/ui/primitives';

/*
  Consistent topic-page shell: nav + a restrained page header + footer.
  Server component; children provide the page body.
*/
export default function PageShell({
  kicker,
  title,
  intro,
  status,
  statusNode,
  children,
}: {
  kicker: string;
  title: ReactNode;
  intro: ReactNode;
  status?: Status;
  /** Live/dynamic status island (e.g. <LiveStatus feature="governance" />). Takes precedence over `status`. */
  statusNode?: ReactNode;
  children: ReactNode;
}) {
  return (
    <main className="relative">
      <Navbar />
      <header className="relative overflow-hidden border-b border-[var(--border)] pt-36 pb-16 sm:pt-44">
        <div className="grid-pattern absolute inset-0" aria-hidden="true" />
        <div
          className="absolute inset-x-0 top-0 h-64"
          aria-hidden="true"
          style={{ background: 'radial-gradient(50% 60% at 30% 0%, rgba(168,85,247,0.12), transparent 70%)' }}
        />
        <div className="relative mx-auto max-w-6xl px-6 lg:px-8">
          <div className="flex flex-wrap items-center gap-3">
            <span className="kicker">{kicker}</span>
            {statusNode ?? (status && <StatusPill status={status} />)}
          </div>
          <h1 className="mt-4 max-w-3xl font-[family-name:var(--font-display)] text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
            {title}
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-muted">{intro}</p>
        </div>
      </header>
      {children}
      <Footer />
    </main>
  );
}
