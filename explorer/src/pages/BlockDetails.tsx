import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { provider } from '../utils/provider';
import { formatKoppa, formatHash, formatTimestamp, copyToClipboard } from '../utils/formatters';
import type { BlockInfo } from '@sumchain/sdk';

export default function BlockDetails() {
  const { height } = useParams<{ height: string }>();
  const [block, setBlock] = useState<BlockInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState('');

  useEffect(() => {
    loadBlock();
  }, [height]);

  async function loadBlock() {
    if (!height) return;

    try {
      const blockData = await provider.getBlockByHeight(parseInt(height));
      setBlock(blockData);
    } catch (error) {
      console.error('Failed to load block:', error);
    } finally {
      setLoading(false);
    }
  }

  const handleCopy = async (text: string, field: string) => {
    const success = await copyToClipboard(text);
    if (success) {
      setCopied(field);
      setTimeout(() => setCopied(''), 2000);
    }
  };

  if (loading) {
    return <div className="text-center py-20 text-slate-400">Loading block...</div>;
  }

  if (!block) {
    return (
      <div className="text-center py-20">
        <h2 className="text-2xl font-bold text-white mb-4">Block Not Found</h2>
        <Link to="/" className="text-blue-400 hover:text-blue-300">← Back to Home</Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <h1 className="text-3xl font-bold text-white">Block #{block.height}</h1>

      <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 space-y-4">
        <DetailRow label="Hash" value={block.hash} onCopy={() => handleCopy(block.hash, 'hash')} copied={copied === 'hash'} />
        <DetailRow label="Parent Hash" value={block.parent_hash} onCopy={() => handleCopy(block.parent_hash, 'parent')} copied={copied === 'parent'} />
        <DetailRow label="Timestamp" value={formatTimestamp(block.timestamp)} />
        <DetailRow label="State Root" value={block.state_root} onCopy={() => handleCopy(block.state_root, 'state')} copied={copied === 'state'} />
        <DetailRow label="Tx Root" value={block.tx_root} onCopy={() => handleCopy(block.tx_root, 'tx')} copied={copied === 'tx'} />
        <DetailRow label="Proposer" value={block.proposer} onCopy={() => handleCopy(block.proposer, 'proposer')} copied={copied === 'proposer'} />
        <DetailRow label="Transaction Count" value={block.tx_count.toString()} />
      </div>

      {block.transactions.length > 0 && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-6">
          <h2 className="text-xl font-bold text-white mb-4">Transactions ({block.tx_count})</h2>
          <div className="space-y-2">
            {block.transactions.map((txHash) => (
              <Link
                key={txHash}
                to={`/tx/${txHash}`}
                className="block p-3 bg-slate-900/50 rounded border border-slate-700 hover:border-blue-500 transition font-mono text-sm text-blue-400"
              >
                {formatHash(txHash, 20)}
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface DetailRowProps {
  label: string;
  value: string;
  onCopy?: () => void;
  copied?: boolean;
}

function DetailRow({ label, value, onCopy, copied }: DetailRowProps) {
  return (
    <div className="flex justify-between items-start border-b border-slate-700 pb-3">
      <div className="text-slate-400 font-medium">{label}</div>
      <div className="text-white font-mono text-right flex items-center gap-2">
        <span className="break-all">{value}</span>
        {onCopy && (
          <button onClick={onCopy} className="text-blue-400 hover:text-blue-300 text-xs">
            {copied ? '✓' : '📋'}
          </button>
        )}
      </div>
    </div>
  );
}
