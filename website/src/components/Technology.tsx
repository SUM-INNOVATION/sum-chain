'use client';

import { motion } from 'framer-motion';

const techStack = [
  {
    name: 'Ed25519',
    description: 'Elliptic curve signatures',
    category: 'Cryptography',
  },
  {
    name: 'Blake3',
    description: 'Lightning-fast hashing',
    category: 'Cryptography',
  },
  {
    name: 'libp2p',
    description: 'Peer-to-peer networking',
    category: 'Network',
  },
  {
    name: 'Gossipsub',
    description: 'Message propagation',
    category: 'Network',
  },
  {
    name: 'PoA Consensus',
    description: 'Round-robin validator rotation',
    category: 'Consensus',
  },
  {
    name: 'RocksDB',
    description: 'High-performance storage',
    category: 'Storage',
  },
];

export default function Technology() {
  return (
    <section id="technology" className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-[#26022e]/20" />
      <div className="absolute inset-0 grid-pattern opacity-20" />

      {/* Decorative Elements */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-purple-500/10 rounded-full blur-3xl" />

      <div className="relative z-10 max-w-7xl mx-auto px-6 lg:px-8">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left Column - Content */}
          <div>
            <motion.span
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="inline-block text-sm font-medium text-purple-400 uppercase tracking-widest mb-4"
            >
              Technology
            </motion.span>
            <motion.h2
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="text-4xl sm:text-5xl font-bold mb-6"
            >
              Powered by{' '}
              <span className="gradient-text-purple">Pure Rust</span>
            </motion.h2>
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="text-lg text-gray-400 mb-8"
            >
              SUM Chain is built entirely in Rust using only the stable toolchain.
              No C/C++, Python, Go, JavaScript, or Solidity. Just pure, memory-safe Rust
              that&apos;s auditable, maintainable, and blazing fast.
            </motion.p>

            {/* Code Block */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="relative"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-purple-500/20 to-pink-500/20 rounded-2xl blur-xl" />
              <div className="relative glass rounded-2xl p-6 font-mono text-sm">
                <div className="flex items-center gap-2 mb-4">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500" />
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="ml-2 text-gray-500 text-xs">transfer.rs</span>
                </div>
                <pre className="text-gray-300 overflow-x-auto">
                  <code>{`// Send 10.5 Koppa with minimal fee
let tx = Transaction::new(
    chain_id,
    sender.address(),
    recipient,
    koppa_to_base("10.5"),  // 10.5 Ϙ
    koppa_to_base("0.001"), // Fee: 0.001 Ϙ
    nonce,
);

let signed = tx.sign(&sender)?;
node.broadcast(signed).await?;`}</code>
                </pre>
              </div>
            </motion.div>
          </div>

          {/* Right Column - Tech Stack */}
          <div>
            <motion.div
              initial={{ opacity: 0, x: 40 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="grid grid-cols-2 gap-4"
            >
              {techStack.map((tech, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: 0.1 * index }}
                  className="group p-6 rounded-2xl bg-white/[0.02] border border-white/5 hover:border-purple-500/30 hover:bg-white/[0.04] transition-all duration-300"
                >
                  <span className="text-xs font-medium text-purple-400 uppercase tracking-wider">
                    {tech.category}
                  </span>
                  <h3 className="text-lg font-semibold mt-2 mb-1 group-hover:text-purple-300 transition-colors">
                    {tech.name}
                  </h3>
                  <p className="text-sm text-gray-500">{tech.description}</p>
                </motion.div>
              ))}
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.5 }}
              className="mt-8 grid grid-cols-3 gap-4"
            >
              {[
                { value: '100%', label: 'Rust' },
                { value: '0', label: 'C/C++ deps' },
                { value: '9', label: 'Decimals' },
              ].map((stat, index) => (
                <div
                  key={index}
                  className="text-center p-4 rounded-xl bg-white/[0.02] border border-white/5"
                >
                  <div className="text-2xl font-bold gradient-text-purple">
                    {stat.value}
                  </div>
                  <div className="text-xs text-gray-500 uppercase tracking-wider mt-1">
                    {stat.label}
                  </div>
                </div>
              ))}
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}
