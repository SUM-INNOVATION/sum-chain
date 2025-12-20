import { Provider } from '@sumchain/sdk';

// Get RPC URL from environment or use default
const RPC_URL = import.meta.env.VITE_RPC_URL || 'http://localhost:8545';

// Create singleton provider instance
export const provider = new Provider({
  url: RPC_URL,
  timeout: 30000,
});

// Export RPC URL for display
export { RPC_URL };
