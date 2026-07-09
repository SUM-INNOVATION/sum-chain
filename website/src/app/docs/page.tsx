import type { Metadata } from 'next';
import Link from 'next/link';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { getCategory, ENDPOINT, totalMethods, GROUPS } from './_data';

export const metadata: Metadata = {
  title: 'JSON-RPC API | SUM Chain Docs',
  description:
    'SUM Chain JSON-RPC 2.0 API reference: chain queries, transactions, storage, tokens, credentials, and governance. Every method is verified against the live mainnet RPC.',
};

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <Navbar />

      <main className="relative pt-32 pb-32">
        <div className="absolute inset-0 bg-gradient-to-b from-[#0a0a0a] via-[#26022e]/20 to-[#0a0a0a]" />
        <div className="absolute inset-0 grid-pattern opacity-20" />

        <div className="relative z-10 max-w-6xl mx-auto px-6 lg:px-8">
          {/* Header */}
          <div className="mb-16">
            <span className="inline-block text-sm font-medium text-purple-400 uppercase tracking-widest mb-4">
              Documentation
            </span>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold mb-6">
              SUM Chain <span className="gradient-text">JSON-RPC API</span>
            </h1>
            <p className="text-lg text-gray-400 max-w-3xl">
              SUM Chain exposes a JSON-RPC 2.0 API for chain queries, transaction submission,
              and integration with the storage protocol, NFTs, tokens, encrypted messaging,
              policy accounts, and document-credential layers. The native currency is{' '}
              <span className="text-white">Koppa (Ϙ)</span> with 9 decimal places.
            </p>
            <p className="text-sm text-gray-500 mt-4">
              All {totalMethods} methods are exposed by the live mainnet RPC at {ENDPOINT}. Example
              responses are real captures. Pick a topic below, each opens on its own page.
            </p>
          </div>

          {/* Connection */}
          <section className="mb-16">
            <h2 className="text-2xl font-semibold mb-4">Connection</h2>
            <div className="glass rounded-2xl p-6 mb-4">
              <p className="text-gray-400 mb-4">Public mainnet endpoint:</p>
              <pre className="bg-black/40 rounded-lg p-4 text-sm font-mono text-purple-300 overflow-x-auto">
                <code>{ENDPOINT}</code>
              </pre>
            </div>
            <div className="glass rounded-2xl p-6">
              <p className="text-gray-400 mb-4">
                Every request follows JSON-RPC 2.0. The{' '}
                <code className="text-purple-300">Content-Type: application/json</code> header is required.
              </p>
              <pre className="bg-black/40 rounded-lg p-4 text-sm font-mono text-gray-300 overflow-x-auto">
                <code>{`curl -X POST ${ENDPOINT} \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"chain_id","params":[],"id":1}'`}</code>
              </pre>
            </div>
          </section>

          {/* Currency */}
          <section className="mb-16">
            <h2 className="text-2xl font-semibold mb-4">Currency &amp; Units</h2>
            <div className="glass rounded-2xl p-6">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-purple-400 uppercase tracking-wider">
                    <th className="py-2 pr-4">Name</th>
                    <th className="py-2 pr-4">Symbol</th>
                    <th className="py-2 pr-4">Decimals</th>
                    <th className="py-2">Base Unit</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-t border-white/5">
                    <td className="py-2 pr-4">Koppa</td>
                    <td className="py-2 pr-4">Ϙ</td>
                    <td className="py-2 pr-4">9</td>
                    <td className="py-2 font-mono text-gray-400">1 Ϙ = 1,000,000,000</td>
                  </tr>
                </tbody>
              </table>
              <p className="text-sm text-gray-500 mt-4">
                All amounts in the API are represented in base units. Examples:{' '}
                <code className="text-purple-300">1000000000</code> = 1 Ϙ,{' '}
                <code className="text-purple-300">1000000</code> = 0.001 Ϙ (typical fee).
              </p>
            </div>
          </section>

          {/* Addresses */}
          <section className="mb-16">
            <h2 className="text-2xl font-semibold mb-4">Addresses</h2>
            <div className="glass rounded-2xl p-6 space-y-3 text-sm text-gray-400">
              <p>
                Addresses are 20 bytes derived from an Ed25519 public key:{' '}
                <code className="text-purple-300">Address = Blake3(pubkey)[12..32]</code>.
              </p>
              <p>Two display formats are accepted in API parameters:</p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>
                  <span className="text-white">Base58 with checksum</span> (default Display): e.g.{' '}
                  <code className="text-purple-300">8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4</code>
                </li>
                <li>
                  <span className="text-white">Hex</span>: e.g.{' '}
                  <code className="text-purple-300">0x1a2b3c4d...</code>
                </li>
              </ul>
            </div>
          </section>

          {/* Topics, each links to its own page */}
          <section>
            <h2 className="text-2xl font-semibold mb-6">Topics</h2>
            <div className="space-y-10">
              {GROUPS.map((group) => (
                <div key={group.label}>
                  <div className="text-xs text-gray-500 uppercase tracking-widest mb-3">
                    {group.label}
                  </div>
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {group.ids
                      .map((id) => getCategory(id))
                      .filter((c): c is NonNullable<typeof c> => Boolean(c))
                      .map((cat) => (
                        <Link
                          key={cat.id}
                          href={`/docs/${cat.id}`}
                          className="glass rounded-xl p-4 border border-white/5 transition-all hover:border-purple-500/40"
                        >
                          <div className="font-medium" dangerouslySetInnerHTML={{ __html: cat.title }} />
                          <div className="text-xs text-gray-500 mt-1">{cat.methods.length} methods →</div>
                        </Link>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Footer note */}
          <div className="glass rounded-2xl p-8 text-center mt-16">
            <p className="text-gray-400 mb-4">
              All {totalMethods} endpoints are exposed by{' '}
              <a href={ENDPOINT} className="text-purple-400 hover:text-purple-300">
                {ENDPOINT}
              </a>
              .
            </p>
            <Link href="/" className="text-purple-400 hover:text-purple-300 text-sm">
              ← Back to home
            </Link>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
