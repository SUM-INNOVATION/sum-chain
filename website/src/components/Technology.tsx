'use client';

import { motion, useReducedMotion } from 'framer-motion';

const techStack = [
  { name: 'Ed25519', description: 'Elliptic-curve signatures', category: 'Cryptography' },
  { name: 'Blake3', description: 'Fast modern hashing', category: 'Cryptography' },
  { name: 'libp2p', description: 'Peer-to-peer networking', category: 'Network' },
  { name: 'Gossipsub', description: 'Block and tx propagation', category: 'Network' },
  { name: 'Proof of Authority', description: 'Stake-weighted epoch rotation', category: 'Consensus' },
  { name: 'RocksDB', description: 'Persistent state storage', category: 'Storage' },
];

const codeSample = `// Send 10.5 Koppa with a minimal fee
let tx = Transaction::new(
    chain_id,
    sender.address(),
    recipient,
    koppa_to_base("10.5"),  // 10.5 Ϙ
    koppa_to_base("0.001"), // fee: 0.001 Ϙ
    nonce,
);

let signed = tx.sign(&sender)?;
node.broadcast(signed).await?;`;

export default function Technology() {
  const reduce = useReducedMotion();
  const reveal = {
    initial: reduce ? (false as const) : { opacity: 0, y: 20 },
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true, amount: 0.3 } as const,
  };

  return (
    <section id="technology" className="relative scroll-mt-20 overflow-hidden py-28 lg:py-36">
      <div
        className="absolute left-1/2 top-1/2 h-[420px] w-[760px] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-40 blur-[120px]"
        style={{ background: 'radial-gradient(circle, rgba(61,8,71,0.6), transparent 70%)' }}
        aria-hidden="true"
      />
      <div className="relative z-10 mx-auto max-w-6xl px-6 lg:px-8">
        <div className="grid items-center gap-14 lg:grid-cols-2">
          <div>
            <motion.h2
              {...reveal}
              transition={{ duration: 0.5 }}
              className="font-[family-name:var(--font-display)] text-4xl font-bold tracking-tight sm:text-5xl"
            >
              Powered by pure Rust
            </motion.h2>
            <motion.p
              {...reveal}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="mt-4 max-w-lg text-lg text-muted"
            >
              SUM Chain is built entirely on the stable Rust toolchain. No C, C++,
              Python, Go, JavaScript, or Solidity. Memory-safe, auditable, and fast.
            </motion.p>

            <motion.div
              {...reveal}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="relative mt-8"
            >
              <div className="glass overflow-hidden rounded-2xl">
                <div className="flex items-center gap-2 border-b border-[var(--border)] px-5 py-3">
                  <span className="h-3 w-3 rounded-full bg-red-500/80" />
                  <span className="h-3 w-3 rounded-full bg-yellow-500/80" />
                  <span className="h-3 w-3 rounded-full bg-green-500/80" />
                  <span className="ml-2 font-[family-name:var(--font-mono)] text-xs text-muted">
                    transfer.rs
                  </span>
                </div>
                <pre className="overflow-x-auto p-5 font-[family-name:var(--font-mono)] text-sm leading-relaxed text-muted-strong">
                  <code>{codeSample}</code>
                </pre>
              </div>
            </motion.div>
          </div>

          <div>
            <div className="grid grid-cols-2 gap-4">
              {techStack.map((tech, index) => (
                <motion.div
                  key={tech.name}
                  initial={reduce ? false : { opacity: 0, y: 16 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.4 }}
                  transition={{ duration: 0.45, delay: index * 0.06 }}
                  className="rounded-2xl border border-[var(--border)] bg-surface/50 p-5 transition-colors duration-300 hover:border-accent/40"
                >
                  <span className="text-xs font-medium uppercase tracking-wider text-accent-soft">
                    {tech.category}
                  </span>
                  <h3 className="mt-2 font-[family-name:var(--font-display)] text-lg font-semibold">
                    {tech.name}
                  </h3>
                  <p className="mt-1 text-sm text-muted">{tech.description}</p>
                </motion.div>
              ))}
            </div>

            <div className="mt-4 grid grid-cols-3 gap-4">
              {[
                { value: '100%', label: 'Rust' },
                { value: '0', label: 'C/C++ deps' },
                { value: '9', label: 'Decimals' },
              ].map((stat) => (
                <div
                  key={stat.label}
                  className="rounded-xl border border-[var(--border)] bg-surface/50 p-4 text-center"
                >
                  <div className="tnum font-[family-name:var(--font-display)] text-2xl font-bold text-accent-soft">
                    {stat.value}
                  </div>
                  <div className="mt-1 text-xs uppercase tracking-wider text-muted">
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
