import { Provider } from '@sumchain/sdk';

// Default to the canonical public mainnet RPC so the deployed build works out
// of the box. Override with VITE_RPC_URL for local development.
const RPC_URL = import.meta.env.VITE_RPC_URL || 'https://rpc.sumchain.io';

// Create singleton provider instance
export const provider = new Provider({
  url: RPC_URL,
  timeout: 30000,
});

// Export RPC URL for display
export { RPC_URL };
