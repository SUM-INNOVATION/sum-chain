# SUM Chain Block Explorer

A modern, real-time block explorer for SUM Chain built with React, TypeScript, and Tailwind CSS.

**Features:**
- Real-time block and transaction updates
- Human-readable transaction labels: compact domain chips (Native, Token, SNIP,
  OmniNode, Governance, Policy, Messaging, Other) and action labels
  (e.g. "SNIP file registration", "Governance vote"), via the `@sumchain/sdk`
  classifier. Unknown/unproven types fall back to a conservative label.
- Token-scoped minter context on token transactions (owner/minter of the token
  in view); raw hashes and addresses stay visible and copyable
- Search by address, block height, or transaction hash
- Validator set visualization
- Koppa (Ϙ) currency display
- Responsive design (intentional mobile card layouts, not squeezed tables)

## Screenshots

- **Home Dashboard**: Latest blocks and pending transactions
- **Block Details**: Complete block information with transaction list
- **Transaction Details**: Full transaction data with status
- **Address Details**: Balance and nonce information
- **Validators**: Current validator set with proposer highlight

## Prerequisites

- Node.js 18+ and npm
- A running SUM Chain node with RPC enabled

## Installation

```bash
cd explorer
npm install
```

## Configuration

Create a `.env` file in the explorer directory:

```env
# RPC endpoint for SUM Chain node
VITE_RPC_URL=http://localhost:8545
```

Or use the default (localhost:8545).

## Development

Start the development server:

```bash
npm run dev
```

The explorer will be available at `http://localhost:3000`.

## Building for Production

```bash
npm run build
```

The built files will be in the `dist/` directory.

## Preview Production Build

```bash
npm run preview
```

## Deployment

### Static Hosting

The explorer is a static site and can be deployed to any static hosting service:

**Vercel:**
```bash
npm install -g vercel
vercel
```

**Netlify:**
```bash
npm install -g netlify-cli
netlify deploy --prod
```

**GitHub Pages:**
```bash
npm run build
# Copy dist/ to your GitHub Pages repository
```

### Docker

Create a `Dockerfile`:

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build and run:

```bash
docker build -t sumchain-explorer .
docker run -p 8080:80 sumchain-explorer
```

### Environment Variables

Configure the RPC endpoint at build time:

```bash
VITE_RPC_URL=https://rpc.sumchain.io npm run build
```

Or at runtime using a config file served with the app.

## Features

### Home Dashboard

- Network statistics (block height, chain ID, peer count, status)
- Latest 10 blocks with real-time updates
- Pending transactions feed
- Auto-refresh every 3 seconds

### Block Explorer

- View complete block details
- List all transactions in a block
- Navigate between blocks
- Copy block hashes and other data

### Transaction Viewer

- Transaction status (pending/success/failed)
- Sender and recipient addresses
- Amount and fee in Koppa (Ϙ)
- Block confirmation
- Transaction receipt information

### Address Inspector

- Current balance in Koppa
- Account nonce
- Future: Transaction history

### Validator Dashboard

- List of all validators
- Current proposer highlighted
- Public keys and addresses
- Consensus round information

### Search

Smart search that detects:
- Block heights (numeric)
- Transaction hashes (0x...)
- Addresses (base58 or hex)

## Technology Stack

- **React 18**: UI framework
- **TypeScript**: Type safety
- **Vite**: Build tool and dev server
- **Tailwind CSS**: Styling
- **React Router**: Navigation
- **@sumchain/sdk**: SUM Chain TypeScript SDK

## Architecture

```
explorer/
├── src/
│   ├── components/     # Reusable components
│   │   └── Layout.tsx
│   ├── pages/          # Page components
│   │   ├── Home.tsx
│   │   ├── BlockDetails.tsx
│   │   ├── TransactionDetails.tsx
│   │   ├── AddressDetails.tsx
│   │   └── Validators.tsx
│   ├── utils/          # Utilities
│   │   ├── provider.ts    # RPC provider
│   │   └── formatters.ts  # Format functions
│   ├── App.tsx         # Main app component
│   ├── main.tsx        # Entry point
│   └── index.css       # Global styles
├── public/             # Static assets
├── index.html          # HTML template
└── package.json
```

## API Integration

The explorer uses the `@sumchain/sdk` package for all blockchain interactions:

```typescript
import { Provider, formatKoppa } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');

// Get latest block
const block = await provider.getLatestBlock();

// Get transaction
const tx = await provider.getTransaction(txHash);

// Get balance
const balance = await provider.getBalance(address);
console.log(formatKoppa(balance)); // "100 Ϙ"
```

## Customization

### Theming

Edit `tailwind.config.js` to customize colors:

```javascript
theme: {
  extend: {
    colors: {
      primary: {
        // Your custom color palette
      },
    },
  },
}
```

### Branding

Update the logo and branding in `src/components/Layout.tsx`.

### Refresh Rate

Change auto-refresh intervals in page components:

```typescript
// In Home.tsx
const interval = setInterval(loadData, 3000); // 3 seconds
```

## Performance

- Automatic code splitting via React Router
- Efficient re-rendering with React hooks
- Lazy loading of transaction lists
- Optimized bundle size with Vite

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

## Troubleshooting

### Cannot connect to node

```
Error: Failed to fetch
```

**Solution**: Check that:
1. SUM Chain node is running
2. RPC is enabled in node configuration
3. CORS is configured correctly
4. `VITE_RPC_URL` is correct

### Build errors

```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json dist
npm install
npm run build
```

### Port already in use

Change the port in `vite.config.ts`:

```typescript
server: {
  port: 3001, // Use different port
}
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Future Enhancements

- [ ] Transaction history for addresses
- [ ] Real-time WebSocket updates
- [ ] Network statistics graphs
- [ ] Dark/light theme toggle
- [ ] Mobile app version
- [ ] API for external integrations
- [ ] Advanced search filters
- [ ] Transaction mempool visualization
- [ ] Validator performance metrics
- [ ] Token transfer events (when smart contracts are added)

## License

MIT

## Links

- [SUM Chain Repository](https://github.com/SUM-INNOVATION/sum-chain)
- [TypeScript SDK](../sdk/typescript)
- [API Documentation](../docs/rpc/api-reference.md)
- [Operator Guide](../docs/operator-guide.md)
