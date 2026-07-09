'use client';

import { useRef, type PointerEvent } from 'react';
import { useReducedMotion } from 'framer-motion';
import { MonoTag } from '@/components/ui/primitives';

/*
  Signature system map, the data path across SUM Chain's node mesh.
  End User → SUM Chain (verifier/settlement) → Inference Nodes → Archive/SNIP.
  Custom SVG (no stock art, no canvas dep). Cursor-spotlight is the one
  signature interaction; disabled under reduced-motion / coarse pointers.
  The SVG is decorative (aria-hidden); the numbered legend below carries the
  accessible, mobile-legible sequence.
*/

type NodeDef = {
  id: string;
  title: string;
  sub: string;
  cx: number;
  cy: number;
  w: number;
  h: number;
  tone: 'chain' | 'signal' | 'plain';
};

const NODES: NodeDef[] = [
  { id: 'chain', title: 'SUM Chain', sub: 'verifier · settlement', cx: 460, cy: 110, w: 272, h: 88, tone: 'chain' },
  { id: 'user', title: 'End User', sub: 'prompt · Ϙ fee', cx: 150, cy: 340, w: 214, h: 78, tone: 'plain' },
  { id: 'infer', title: 'Inference Nodes', sub: 'contribution workers', cx: 770, cy: 340, w: 214, h: 88, tone: 'signal' },
  { id: 'arch', title: 'Archive / SNIP', sub: 'model shards · PoR', cx: 460, cy: 548, w: 300, h: 88, tone: 'plain' },
];

type EdgeDef = {
  d: string;
  label: string;
  tag?: string;
  lx: number;
  ly: number;
  dashed?: boolean;
};

// Value/data flow (solid) vs proof/verification (dashed).
const EDGES: EdgeDef[] = [
  { d: 'M 175 303 Q 250 210 340 148', label: '1 · prompt + fee', lx: 214, ly: 214, dashed: false },
  { d: 'M 588 152 Q 700 200 742 300', label: '2 · dispatch job', lx: 700, ly: 210, dashed: false },
  { d: 'M 762 386 Q 660 470 574 508', label: '3 · fetch model shards', lx: 690, ly: 476, dashed: false },
  { d: 'M 470 504 Q 500 330 500 156', label: '4 · records storage', tag: 'PoR', lx: 512, ly: 336, dashed: true },
  { d: 'M 700 306 Q 630 210 580 150', label: '5 · response + proof', tag: 'InferenceAttestation', lx: 604, ly: 250, dashed: true },
  { d: 'M 336 140 Q 250 230 200 304', label: '6 · verified response', lx: 214, ly: 300, dashed: false },
];

function toneStyles(tone: NodeDef['tone']) {
  switch (tone) {
    case 'chain':
      return { stroke: 'var(--accent)', fill: 'rgba(168,85,247,0.08)', glow: 'rgba(168,85,247,0.35)' };
    case 'signal':
      return { stroke: 'var(--signal)', fill: 'rgba(34,211,238,0.07)', glow: 'rgba(34,211,238,0.3)' };
    default:
      return { stroke: 'var(--border-strong)', fill: 'rgba(23,23,27,0.6)', glow: 'transparent' };
  }
}

const STEPS = [
  { n: '1', text: 'End user submits a prompt and pays a Koppa fee.', tag: null },
  { n: '2', text: 'Job is dispatched to inference nodes.', tag: null },
  { n: '3', text: 'Nodes fetch model shards from archive/SNIP storage.', tag: 'merkle_root' },
  { n: '4', text: 'Archives hold shards under Proof-of-Retrievability challenges.', tag: 'PoR' },
  { n: '5', text: 'A verifier signs the result; the chain records the attestation.', tag: 'InferenceAttestation' },
  { n: '6', text: 'The verified response is returned to the user.', tag: null },
];

export default function SystemMap() {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);

  const onMove = (e: PointerEvent<HTMLDivElement>) => {
    if (reduce || e.pointerType !== 'mouse') return;
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${((e.clientX - r.left) / r.width) * 100}%`);
    el.style.setProperty('--my', `${((e.clientY - r.top) / r.height) * 100}%`);
    el.dataset.active = 'true';
  };
  const onLeave = () => {
    if (ref.current) ref.current.dataset.active = 'false';
  };

  return (
    <div className="grid items-center gap-8 lg:grid-cols-5">
      {/* Diagram */}
      <div
        ref={ref}
        onPointerMove={onMove}
        onPointerLeave={onLeave}
        className="spotlight glass relative rounded-2xl p-3 sm:p-5 lg:col-span-3"
      >
        <svg
          viewBox="0 0 920 640"
          className="h-auto w-full"
          role="img"
          aria-label="Data path across SUM Chain: end user to SUM Chain to inference nodes to archive and SNIP storage"
        >
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--muted)" />
            </marker>
            <marker id="arrow-sig" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--signal)" />
            </marker>
          </defs>

          {/* Edges */}
          {EDGES.map((e, i) => (
            <g key={i}>
              <path
                d={e.d}
                fill="none"
                stroke={e.dashed ? 'var(--signal)' : 'var(--muted)'}
                strokeWidth={1.5}
                strokeOpacity={e.dashed ? 0.75 : 0.5}
                markerEnd={`url(#${e.dashed ? 'arrow-sig' : 'arrow'})`}
                className={reduce ? '' : 'edge-flow'}
              />
              <text
                x={e.lx}
                y={e.ly}
                textAnchor="middle"
                className="mono"
                fill="var(--muted-strong)"
                fontSize="13"
              >
                {e.label}
              </text>
              {e.tag && (
                <text
                  x={e.lx}
                  y={e.ly + 17}
                  textAnchor="middle"
                  className="mono"
                  fill={e.dashed ? 'var(--signal)' : 'var(--muted)'}
                  fontSize="11.5"
                >
                  {e.tag}
                </text>
              )}
            </g>
          ))}

          {/* Nodes */}
          {NODES.map((n) => {
            const s = toneStyles(n.tone);
            return (
              <g key={n.id}>
                <rect
                  x={n.cx - n.w / 2}
                  y={n.cy - n.h / 2}
                  width={n.w}
                  height={n.h}
                  rx={14}
                  fill={s.fill}
                  stroke={s.stroke}
                  strokeWidth={1.5}
                  style={{ filter: s.glow !== 'transparent' ? `drop-shadow(0 0 18px ${s.glow})` : undefined }}
                />
                <text
                  x={n.cx}
                  y={n.cy - 6}
                  textAnchor="middle"
                  className="font-[family-name:var(--font-display)]"
                  fill="var(--foreground)"
                  fontSize="20"
                  fontWeight="600"
                >
                  {n.title}
                </text>
                <text x={n.cx} y={n.cy + 18} textAnchor="middle" className="mono" fill="var(--muted)" fontSize="12.5">
                  {n.sub}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Sequence legend, accessible + mobile-legible */}
      <ol className="space-y-3 lg:col-span-2">
        {STEPS.map((s) => (
          <li key={s.n} className="flex gap-3">
            <span className="mono mt-0.5 flex h-6 w-6 flex-none items-center justify-center rounded-md border border-[var(--border)] bg-surface-2 text-xs text-accent-soft">
              {s.n}
            </span>
            <p className="text-sm leading-relaxed text-muted-strong">
              {s.text} {s.tag && <MonoTag>{s.tag}</MonoTag>}
            </p>
          </li>
        ))}
      </ol>
    </div>
  );
}
