# sum chain website

Static site for sum chain. No build step, no dependencies; open `index.html` in a browser to preview.

The homepage hero is wired to mainnet: it reads block height, finality, epoch, and the validator set from `rpc.sumchain.io` and polls every 3 seconds. A light pulse crosses the hairline under the readout each time a block lands. If the RPC is unreachable the readout degrades to placeholders.

## Structure

- `index.html` - homepage: live network readout, protocol facts, protocol index
- `storage/` `compute/` `governance/` `tokenomics/` `node/` `wallet/` - protocol pages
- `docs/` - JSON-RPC API reference (143 methods, verified against mainnet)
- `styles.css` - all styling; shares family DNA with quosum.com (black, Inter, hairlines, plus motif) with its own editorial layout and purple accent
- `main.js` - live RPC ticker, block pulse, mobile menu, scroll reveals
- `favicon.svg` - plus mark, purple gradient

Pages are generated from a single template script so nav and footer stay consistent; content lives inline in each page and can be edited directly.

## Deploy

Static assets via Cloudflare Workers:

```
npx wrangler deploy
```
