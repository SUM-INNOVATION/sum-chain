'use client';

import { motion } from 'framer-motion';
import { useState } from 'react';

const tabs = [
  { id: 'user', label: 'User' },
  { id: 'developer', label: 'Developer' },
  { id: 'validator', label: 'Validator' },
];

const content = {
  user: {
    title: 'Start Using Koppa',
    steps: [
      {
        title: 'Get the CLI Wallet',
        code: `# Build from source (Rust 1.70+ required)
git clone https://github.com/SUM-INNOVATION/sum-chain
cd sum-chain && cargo build --release

# Binaries land in ./target/release/
# - sumchain         (full node)
# - sumchain-wallet  (CLI wallet)`,
      },
      {
        title: 'Create Your Wallet',
        code: `# Generate a new keypair
sumchain keygen --output my-wallet.json

# Your address will be displayed
# Keep your wallet file safe!`,
      },
      {
        title: 'Receive & Send Koppa',
        code: `# Check your balance
sumchain-wallet balance --key my-wallet.json

# Send Koppa to another address
sumchain-wallet transfer \\
  --key my-wallet.json \\
  --to RECIPIENT_ADDRESS \\
  --amount 10.5`,
      },
    ],
  },
  developer: {
    title: 'Build on SUM Chain',
    steps: [
      {
        title: 'Install the SDK',
        code: `# Using npm
npm install @sumchain/sdk

# Using yarn
yarn add @sumchain/sdk`,
      },
      {
        title: 'Connect to the Network',
        code: `import { Provider } from '@sumchain/sdk';

const provider = new Provider({
  url: 'https://rpc.sum-chain.xyz'
});

// Get chain info
const health = await provider.getHealth();
console.log(\`Chain ID: \${health.chain_id}\`);`,
      },
      {
        title: 'Send Transactions',
        code: `import { Wallet, formatKoppa } from '@sumchain/sdk';

// Load wallet
const wallet = Wallet.fromFile('./my-wallet.json');

// Send transaction
const tx = await provider.sendTransaction({
  from: wallet.address,
  to: 'RECIPIENT_ADDRESS',
  amount: '10500000000', // 10.5 Ϙ
  fee: '1000000',        // 0.001 Ϙ
});

console.log(\`TX Hash: \${tx.hash}\`);`,
      },
    ],
  },
  validator: {
    title: 'Run a Validator Node',
    steps: [
      {
        title: 'Build the Node',
        code: `# Clone and build
git clone https://github.com/SUM-INNOVATION/sum-chain
cd sum-chain
cargo build --release

# Binary at ./target/release/sumchain`,
      },
      {
        title: 'Configure Your Node',
        code: `# Create config.toml
cat > config.toml << EOF
[node]
genesis = "genesis.json"
data_dir = "data"
validator_key = "validator-key.json"

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9933"

[rpc]
addr = "127.0.0.1:8545"
EOF`,
      },
      {
        title: 'Start Validating',
        code: `# Generate validator key
./target/release/sumchain keygen --output validator-key.json

# Start the node
./target/release/sumchain run \\
  --config config.toml \\
  --genesis genesis.json`,
      },
    ],
  },
};

export default function GetStarted() {
  const [activeTab, setActiveTab] = useState('user');

  return (
    <section id="get-started" className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-[#0f0f0f] via-[#26022e]/30 to-[#0a0a0a]" />
      <div className="absolute inset-0 grid-pattern opacity-20" />

      {/* Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-purple-500/10 rounded-full blur-3xl" />

      <div className="relative z-10 max-w-5xl mx-auto px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-12">
          <motion.span
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="inline-block text-sm font-medium text-purple-400 uppercase tracking-widest mb-4"
          >
            Get Started
          </motion.span>
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-4xl sm:text-5xl font-bold mb-6"
          >
            Ready to{' '}
            <span className="gradient-text-purple">Join the Future</span>?
          </motion.h2>
        </div>

        {/* Tabs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="flex justify-center gap-2 mb-12"
        >
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-6 py-3 rounded-full text-sm font-medium transition-all duration-300 ${
                activeTab === tab.id
                  ? 'bg-purple-500 text-white'
                  : 'bg-white/5 text-gray-400 hover:bg-white/10 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </motion.div>

        {/* Content */}
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="space-y-6"
        >
          <h3 className="text-2xl font-semibold text-center mb-8">
            {content[activeTab as keyof typeof content].title}
          </h3>

          {content[activeTab as keyof typeof content].steps.map((step, index) => (
            <div key={index} className="relative">
              {/* Step Number */}
              <div className="absolute -left-4 top-6 w-8 h-8 rounded-full bg-purple-500/20 border border-purple-500/50 flex items-center justify-center text-sm font-bold text-purple-400">
                {index + 1}
              </div>

              {/* Card */}
              <div className="ml-8 glass rounded-2xl overflow-hidden">
                <div className="px-6 py-4 border-b border-white/5">
                  <h4 className="font-medium">{step.title}</h4>
                </div>
                <div className="p-6 bg-black/30">
                  <pre className="text-sm text-gray-300 overflow-x-auto font-mono">
                    <code>{step.code}</code>
                  </pre>
                </div>
              </div>
            </div>
          ))}
        </motion.div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.4 }}
          className="text-center mt-16"
        >
          <span
            title="Not open to public yet"
            aria-label="View on GitHub (not open to public yet)"
            className="group relative inline-flex items-center gap-3 px-8 py-4 text-lg font-medium rounded-full bg-white text-[#0a0a0a] cursor-not-allowed"
          >
            <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            View on GitHub
            <span className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-2 whitespace-nowrap rounded-md bg-white/10 px-2 py-1 text-xs text-white opacity-0 group-hover:opacity-100 transition-opacity">
              Not open to public yet
            </span>
          </span>
        </motion.div>
      </div>
    </section>
  );
}
