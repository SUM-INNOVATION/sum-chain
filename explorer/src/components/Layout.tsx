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
    `text-sm transition-colors ${isActive ? 'text-white' : 'text-zinc-400 hover:text-white'}`;

  return (
    <div className="min-h-screen bg-[#0a0a0a]">
      <header className="sticky top-0 z-40 border-b border-zinc-800 bg-[#0a0a0a]/80 backdrop-blur-xl">
        <div className="container mx-auto px-4 py-4">
          <div className="mb-4 flex items-center justify-between">
            <Link to="/" className="flex items-center space-x-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-brand-deep to-brand-deep2">
                <span className="koppa-symbol text-2xl font-bold text-primary-300">
                  {KOPPA_SYMBOL}
                </span>
              </div>
              <div>
                <h1 className="font-display text-xl font-bold text-white">SUM Chain Explorer</h1>
                <p className="text-xs text-zinc-500">Native currency: Koppa ({KOPPA_SYMBOL})</p>
              </div>
            </Link>

            <nav className="hidden space-x-6 md:flex">
              <NavLink to="/" end className={navClass}>
                Home
              </NavLink>
              <NavLink to="/validators" className={navClass}>
                Validators
              </NavLink>
            </nav>
          </div>

          <form onSubmit={handleSearch} className="max-w-2xl">
            <div className="relative">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by address, block height, or transaction hash"
                aria-label="Search the chain"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 text-white placeholder-zinc-500 transition-colors focus:border-primary-500 focus:outline-none"
              />
              <button
                type="submit"
                className="absolute right-2 top-2 rounded-md bg-primary-500 px-4 py-1.5 text-white transition-colors hover:bg-primary-600 active:translate-y-px"
              >
                Search
              </button>
            </div>
          </form>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">{children}</main>

      <footer className="mt-16 border-t border-zinc-800">
        <div className="container mx-auto px-4 py-6 text-center text-sm text-zinc-500">
          <p>SUM Chain Explorer</p>
          <p className="mt-1">
            <a href="https://sumchain.io" className="transition-colors hover:text-primary-300">
              sumchain.io
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}
