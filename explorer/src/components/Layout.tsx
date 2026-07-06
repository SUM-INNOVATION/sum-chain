import { useState } from 'react';
import { NavLink, Link, useNavigate } from 'react-router-dom';

const KOPPA_SYMBOL = 'Ϙ';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const [search, setSearch] = useState('');
  const navigate = useNavigate();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = search.trim();
    if (!trimmed) return;

    if (/^\d+$/.test(trimmed)) {
      navigate(`/block/${trimmed}`);
    } else if (trimmed.startsWith('0x') && trimmed.length === 66) {
      navigate(`/tx/${trimmed}`);
    } else {
      navigate(`/address/${trimmed}`);
    }
    setSearch('');
  };

  const navClass = ({ isActive }: { isActive: boolean }) =>
    `text-sm font-medium transition-colors ${isActive ? 'text-foreground' : 'text-muted hover:text-foreground'}`;

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur-xl">
        <div className="mx-auto max-w-6xl px-6 lg:px-8">
          <div className="flex h-16 items-center justify-between gap-6">
            <Link to="/" className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-brand-deep to-brand-deep2 ring-1 ring-inset ring-border-strong">
                <span className="koppa-symbol text-xl font-bold text-accent-soft">{KOPPA_SYMBOL}</span>
              </div>
              <div className="leading-tight">
                <div className="font-display text-base font-semibold tracking-tight text-foreground">
                  SUM Chain Explorer
                </div>
                <div className="text-[11px] text-muted">Koppa ({KOPPA_SYMBOL}) · L1</div>
              </div>
            </Link>

            <form onSubmit={handleSearch} className="hidden min-w-0 flex-1 md:block">
              <div className="relative mx-auto max-w-xl">
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search address, block height, or tx hash"
                  aria-label="Search the chain"
                  className="w-full rounded-lg border border-border bg-surface px-3.5 py-2 pr-20 text-sm text-foreground placeholder-muted transition-colors hover:border-border-strong focus:border-accent focus:outline-none"
                />
                <button
                  type="submit"
                  className="absolute right-1.5 top-1.5 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition-colors hover:bg-primary-600 active:translate-y-px"
                >
                  Search
                </button>
              </div>
            </form>

            <nav className="flex items-center gap-5">
              <NavLink to="/" end className={navClass}>
                Home
              </NavLink>
              <NavLink to="/validators" className={navClass}>
                Validators
              </NavLink>
            </nav>
          </div>

          {/* Mobile search */}
          <form onSubmit={handleSearch} className="pb-3 md:hidden">
            <div className="relative">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search address, block, or tx"
                aria-label="Search the chain"
                className="w-full rounded-lg border border-border bg-surface px-3.5 py-2 pr-20 text-sm text-foreground placeholder-muted transition-colors focus:border-accent focus:outline-none"
              />
              <button
                type="submit"
                className="absolute right-1.5 top-1.5 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white hover:bg-primary-600"
              >
                Search
              </button>
            </div>
          </form>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10 lg:px-8">{children}</main>

      <footer className="mt-16 border-t border-border">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-6 text-sm text-muted lg:px-8">
          <p>SUM Chain Explorer</p>
          <a href="https://sumchain.io" className="transition-colors hover:text-accent-soft">
            sumchain.io ↗
          </a>
        </div>
      </footer>
    </div>
  );
}
