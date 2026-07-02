'use client';

import { motion, useReducedMotion } from 'framer-motion';
import Link from 'next/link';
import { useState } from 'react';
import { ArrowUpRightIcon, LockClosedIcon } from '@heroicons/react/24/outline';

const RPC = 'https://rpc.sumchain.io';

type Step = {
  title: string;
  body: string;
  code?: string;
  link?: { label: string; href: string };
};

type TabContent = {
  title: string;
  steps?: Step[];
  gated?: { note: string };
};

const tabs = [
  { id: 'user', label: 'User' },
  { id: 'developer', label: 'Developer' },
  { id: 'validator', label: 'Validator' },
] as const;

const content: Record<string, TabContent> = {
  user: {
    title: 'Start using Koppa',
    steps: [
      {
        title: 'Open SUMailet Web',
        body: 'Create a non-custodial wallet in your browser. No download, no extension.',
        link: { label: 'Launch SUMailet', href: 'https://mlt.sumail.xyz/' },
      },
      {
        title: 'Receive and send',
        body: 'Share your address to receive Ϙ. Transfers reach finality in about 18 seconds for a typical fee near 0.001 Ϙ.',
      },
      {
        title: 'Track everything',
        body: 'Look up addresses, balances, and transactions in real time on the explorer.',
        link: { label: 'Open Explorer', href: 'https://explorer.sumchain.io' },
      },
    ],
  },
  developer: {
    title: 'Build on SUM Chain',
    steps: [
      {
        title: 'Install the TypeScript SDK',
        body: 'The typed client is published on npm. It exposes a Provider plus Koppa helpers (koppaToBaseUnits, formatKoppa) and works with native Node ESM.',
        code: `npm install @sumchain/sdk`,
        link: { label: 'View on npm', href: 'https://www.npmjs.com/package/@sumchain/sdk' },
      },
      {
        title: 'Connect to mainnet',
        body: 'Every endpoint is JSON-RPC 2.0 over HTTPS. Check liveness with a health call.',
        code: `curl -X POST ${RPC} \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"health","params":[],"id":1}'`,
      },
      {
        title: 'Read account state',
        body: 'Balances are returned in base units (1 Ϙ = 1,000,000,000).',
        code: `curl -X POST ${RPC} \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"get_balance",
       "params":["8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4"],"id":1}'`,
      },
      {
        title: 'Submit a signed transaction',
        body: 'Sign locally, then broadcast the hex-encoded transaction — directly or via the @sumchain/sdk Provider.',
        code: `curl -X POST ${RPC} \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","method":"send_raw_transaction",
       "params":["0x..."],"id":1}'`,
      },
    ],
  },
  validator: {
    title: 'Run a validator node',
    gated: {
      note: 'The validator node software is not open to the public yet. Stake-weighted, epoch-based validator selection runs under Proof of Authority on mainnet today. Public node releases and a staking guide are on the way.',
    },
  },
};

export default function GetStarted() {
  const [activeTab, setActiveTab] = useState<string>('user');
  const reduce = useReducedMotion();
  const active = content[activeTab];

  return (
    <section id="get-started" className="relative scroll-mt-20 overflow-hidden py-28 lg:py-36">
      <div
        className="absolute left-1/2 top-1/2 h-[520px] w-[520px] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-40 blur-[120px]"
        style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.16), transparent 70%)' }}
        aria-hidden="true"
      />
      <div className="relative z-10 mx-auto max-w-4xl px-6 lg:px-8">
        <div className="mb-10 text-center">
          <h2 className="font-[family-name:var(--font-display)] text-4xl font-bold tracking-tight sm:text-5xl">
            Get started in minutes
          </h2>
        </div>

        <div className="mb-10 flex justify-center gap-2" role="tablist" aria-label="Get started paths">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              role="tab"
              aria-selected={activeTab === tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`rounded-full px-6 py-2.5 text-sm font-medium transition-all duration-200 active:translate-y-px ${
                activeTab === tab.id
                  ? 'bg-accent text-white'
                  : 'border border-[var(--border)] text-muted hover:border-accent/40 hover:text-foreground'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <motion.div
          key={activeTab}
          initial={reduce ? false : { opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <h3 className="mb-8 text-center font-[family-name:var(--font-display)] text-2xl font-semibold">
            {active.title}
          </h3>

          {active.steps && (
            <div className="space-y-5">
              {active.steps.map((step, index) => (
                <div key={step.title} className="relative pl-12">
                  <div className="absolute left-0 top-0 flex h-8 w-8 items-center justify-center rounded-full border border-accent/40 bg-accent/10 text-sm font-semibold text-accent-soft">
                    {index + 1}
                  </div>
                  <div className="glass overflow-hidden rounded-2xl">
                    <div className="border-b border-[var(--border)] px-6 py-4">
                      <h4 className="font-medium">{step.title}</h4>
                      <p className="mt-1 text-sm text-muted">{step.body}</p>
                    </div>
                    {step.code && (
                      <pre className="overflow-x-auto bg-black/30 p-5 font-[family-name:var(--font-mono)] text-sm leading-relaxed text-muted-strong">
                        <code>{step.code}</code>
                      </pre>
                    )}
                    {step.link && (
                      <div className="px-6 py-4">
                        <Link
                          href={step.link.href}
                          target={step.link.href.startsWith('http') ? '_blank' : undefined}
                          rel={step.link.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                          className="inline-flex items-center gap-1.5 text-sm font-medium text-accent-soft transition-colors hover:text-foreground"
                        >
                          {step.link.label}
                          <ArrowUpRightIcon className="h-4 w-4" />
                        </Link>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {active.gated && (
            <div className="glass flex items-start gap-4 rounded-2xl p-6">
              <span className="inline-flex shrink-0 rounded-xl border border-[var(--border)] bg-surface-2 p-2.5 text-muted">
                <LockClosedIcon className="h-5 w-5" strokeWidth={1.5} />
              </span>
              <p className="text-muted">{active.gated.note}</p>
            </div>
          )}
        </motion.div>

        <div className="mt-14 text-center">
          <Link
            href="/docs"
            className="inline-flex items-center gap-2 rounded-full border border-[var(--border-strong)] px-7 py-3.5 text-base font-medium text-foreground transition-colors duration-200 hover:border-accent/60 hover:bg-accent/10"
          >
            Read the API reference
          </Link>
        </div>
      </div>
    </section>
  );
}
