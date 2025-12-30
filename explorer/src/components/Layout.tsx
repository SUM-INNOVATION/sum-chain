import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

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

    // Detect search type and navigate
    if (/^\d+$/.test(trimmed)) {
      // Block height
      navigate(`/block/${trimmed}`);
    } else if (trimmed.startsWith('0x') && trimmed.length === 66) {
      // Transaction hash
      navigate(`/tx/${trimmed}`);
    } else {
      // Address
      navigate(`/address/${trimmed}`);
    }

    setSearch('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="bg-slate-900/50 backdrop-blur-sm border-b border-slate-700">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between mb-4">
            <Link to="/" className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">
                <span className="text-2xl font-bold text-white koppa-symbol">{KOPPA_SYMBOL}</span>
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">SUM Chain Explorer</h1>
                <p className="text-sm text-slate-400">Block Explorer</p>
              </div>
            </Link>

            <nav className="hidden md:flex space-x-6">
              <Link to="/" className="text-slate-300 hover:text-white transition">
                Home
              </Link>
              <Link to="/validators" className="text-slate-300 hover:text-white transition">
                Validators
              </Link>
            </nav>
          </div>

          {/* Search Bar */}
          <form onSubmit={handleSearch} className="max-w-2xl">
            <div className="relative">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by address, block height, or transaction hash..."
                className="w-full px-4 py-3 bg-slate-800 text-white rounded-lg border border-slate-700 focus:outline-none focus:border-blue-500 placeholder-slate-500"
              />
              <button
                type="submit"
                className="absolute right-2 top-2 px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition"
              >
                Search
              </button>
            </div>
          </form>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="bg-slate-900/50 border-t border-slate-700 mt-16">
        <div className="container mx-auto px-4 py-6 text-center text-slate-400">
          <p>SUM Chain Explorer - Native Currency: Koppa ({KOPPA_SYMBOL})</p>
          <p className="text-sm mt-2">Powered by SUM Chain</p>
        </div>
      </footer>
    </div>
  );
}
