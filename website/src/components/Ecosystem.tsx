'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';

const ecosystemItems = [
  {
    title: 'Block Explorer',
    description: 'Track transactions, blocks, and addresses in real-time with our intuitive explorer.',
    href: 'https://explorer.sumchain.io',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
    ),
    status: 'Live',
    statusColor: 'bg-green-500',
  },
  {
    title: 'TypeScript SDK',
    description: 'Build dApps with our fully-typed SDK. Query balances, send transactions, and more.',
    href: '#',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
      </svg>
    ),
    status: 'Coming Soon',
    statusColor: 'bg-yellow-500',
  },
  {
    title: 'CLI Wallet',
    description: 'Secure command-line wallet for power users. Generate keys, sign, and broadcast transactions.',
    href: '/#get-started',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    ),
    status: 'Live',
    statusColor: 'bg-green-500',
  },
  {
    title: 'SUMailet Web',
    description: 'Easy-to-use browser wallet for sending and receiving Koppa. No downloads required.',
    href: 'https://mlt.sumail.xyz/',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
      </svg>
    ),
    status: 'Live',
    statusColor: 'bg-green-500',
  },
  {
    title: 'Mobile App',
    description: 'Native iOS and Android apps for managing your Koppa on the go.',
    href: '#',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
      </svg>
    ),
    status: 'Coming Soon',
    statusColor: 'bg-yellow-500',
  },
  {
    title: 'Snip',
    description: 'Decentralized link & content sharing — pinned to SUM Chain native storage with on-chain ACLs.',
    href: 'https://snip.sumchain.io',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
    status: 'Live',
    statusColor: 'bg-green-500',
  },
  {
    title: 'OmniNode (ZkML)',
    description: 'Verifiable AI compute backed by zero-knowledge proofs. AI inference results settle on SUM Chain via the PoR engine.',
    href: 'https://omninode.suminnovation.xyz',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
      </svg>
    ),
    status: 'Live',
    statusColor: 'bg-green-500',
  },
  {
    title: 'Documentation',
    description: 'JSON-RPC API reference with verified endpoints. Integrate with chain, storage, NFTs, tokens, and messaging.',
    href: '/docs',
    icon: (
      <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
      </svg>
    ),
    status: 'Live',
    statusColor: 'bg-green-500',
  },
];

export default function Ecosystem() {
  return (
    <section id="ecosystem" className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-[#0a0a0a] to-[#0f0f0f]" />
      <div className="absolute inset-0 grid-pattern opacity-20" />

      <div className="relative z-10 max-w-7xl mx-auto px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <motion.span
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="inline-block text-sm font-medium text-purple-400 uppercase tracking-widest mb-4"
          >
            Ecosystem
          </motion.span>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-4xl sm:text-5xl lg:text-6xl font-bold mb-6"
          >
            Everything You Need to{' '}
            <span className="gradient-text-purple">Get Started</span>
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-lg text-gray-400 max-w-2xl mx-auto"
          >
            A complete suite of tools and resources for users, developers, and validators.
          </motion.p>
        </div>

        {/* Ecosystem Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {ecosystemItems.map((item, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.1 * index }}
            >
              <Link
                href={item.href}
                target={item.href.startsWith('http') ? '_blank' : undefined}
                title={item.status === 'Coming Soon' ? 'Not open to public yet' : undefined}
                aria-label={item.status === 'Coming Soon' ? `${item.title} (not open to public yet)` : undefined}
                className={`group relative block h-full p-8 rounded-2xl bg-white/[0.02] border border-white/5 hover:border-purple-500/30 hover:bg-white/[0.04] transition-all duration-300 ${
                  item.status === 'Coming Soon' ? 'cursor-not-allowed' : ''
                }`}
                onClick={item.status === 'Coming Soon' ? (e) => e.preventDefault() : undefined}
              >
                {item.status === 'Coming Soon' && (
                  <span className="pointer-events-none absolute top-4 right-4 -translate-y-full -mt-2 whitespace-nowrap rounded-md bg-white/10 px-2 py-1 text-xs text-white opacity-0 group-hover:opacity-100 transition-opacity z-10">
                    Not open to public yet
                  </span>
                )}
                <div className="flex items-start justify-between mb-6">
                  <div className="p-3 rounded-xl bg-purple-500/10 text-purple-400 group-hover:bg-purple-500/20 transition-colors duration-300">
                    {item.icon}
                  </div>
                  <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium ${
                    item.status === 'Live' ? 'bg-green-500/10 text-green-400' : 'bg-yellow-500/10 text-yellow-400'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${item.statusColor}`} />
                    {item.status}
                  </span>
                </div>

                <h3 className="text-xl font-semibold mb-3 group-hover:text-purple-300 transition-colors duration-300">
                  {item.title}
                </h3>
                <p className="text-gray-400 leading-relaxed">
                  {item.description}
                </p>

                {item.status === 'Live' && (
                  <div className="mt-6 flex items-center text-sm text-purple-400 group-hover:text-purple-300 transition-colors">
                    <span>Learn more</span>
                    <svg
                      className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform duration-300"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M17 8l4 4m0 0l-4 4m4-4H3"
                      />
                    </svg>
                  </div>
                )}
              </Link>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
