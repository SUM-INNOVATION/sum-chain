import type { Category } from './_data';

/** Renders one docs category's method list (name + description + live examples). */
export default function CategorySection({ cat }: { cat: Category }) {
  return (
    <div className="space-y-4">
      {cat.methods.map((m) => (
        <div key={m.name} className="glass rounded-2xl p-6 border border-white/5">
          <div className="flex items-baseline justify-between mb-3 gap-3 flex-wrap">
            <code className="text-lg font-mono text-purple-300">{m.name}</code>
          </div>
          <p className="text-gray-400 mb-4">{m.description}</p>

          {m.example && (
            <div className="space-y-3">
              <div>
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">Request</div>
                <pre className="bg-black/40 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-x-auto">
                  <code>{m.example.request}</code>
                </pre>
              </div>
              {m.example.response && (
                <div>
                  <div className="text-xs text-gray-500 uppercase tracking-wider mb-1">
                    Response (live)
                  </div>
                  <pre className="bg-black/40 rounded-lg p-4 text-xs font-mono text-gray-300 overflow-x-auto">
                    <code>{m.example.response}</code>
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
