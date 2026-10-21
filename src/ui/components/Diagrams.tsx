// Data-driven diagrams for lessons, guides and case studies: a layered
// dependency/topology diagram and a hand-specified message sequence.

import type { LayeredDiagram, StaticSequence } from '../../content/types';
import { Inline, Markdown } from './Markdown';

const KIND_COLOR: Record<string, string> = {
  client: 'var(--c-blue)', server: 'var(--c-teal)', network: 'var(--c-yellow)', service: 'var(--c-green)',
  os: 'var(--c-violet)', data: 'var(--c-orange)', external: 'var(--c-gray)',
};

export function LayeredDiagramView({ d }: { d: LayeredDiagram }) {
  const BOX_W = 150;
  const BOX_H = 44;
  const ROW_H = 88;
  const LABEL_W = 110;
  const maxCols = Math.max(...d.rows.map((r) => r.nodes.length), 1);
  const width = LABEL_W + Math.max(maxCols * (BOX_W + 24), 360);
  const height = d.rows.length * ROW_H + 10;
  const pos: Record<string, { x: number; y: number }> = {};
  d.rows.forEach((r, ri) => {
    const span = width - LABEL_W;
    r.nodes.forEach((n, ni) => {
      const x = LABEL_W + (span / r.nodes.length) * (ni + 0.5);
      pos[n.id] = { x, y: ri * ROW_H + 20 + BOX_H / 2 };
    });
  });
  return (
    <figure className="card" style={{ margin: '10px 0', overflowX: 'auto' }}>
      <figcaption className="small" style={{ fontWeight: 600, marginBottom: 6 }}>{d.title}</figcaption>
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ minWidth: Math.min(width, 640), maxWidth: width }} role="img" aria-label={d.title}>
        <defs>
          <marker id="dep-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" style={{ fill: 'var(--muted)' }} />
          </marker>
        </defs>
        {d.rows.map((r, ri) => r.label && (
          <text key={ri} x={6} y={ri * ROW_H + 20 + BOX_H / 2 + 4} style={{ fill: 'var(--muted)', fontSize: 11 }}>{r.label}</text>
        ))}
        {d.edges.map(([a, b, label], i) => {
          const p = pos[a];
          const q = pos[b];
          if (!p || !q) return null;
          const sameRow = Math.abs(p.y - q.y) < 1;
          const y1 = sameRow ? p.y : p.y + (q.y > p.y ? BOX_H / 2 : -BOX_H / 2);
          const y2 = sameRow ? q.y : q.y + (q.y > p.y ? -BOX_H / 2 : BOX_H / 2);
          const x1 = sameRow ? p.x + (q.x > p.x ? BOX_W / 2 : -BOX_W / 2) : p.x;
          const x2 = sameRow ? q.x + (q.x > p.x ? -BOX_W / 2 : BOX_W / 2) : q.x;
          return (
            <g key={i}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} style={{ stroke: 'var(--muted)' }} strokeWidth={1.3} markerEnd="url(#dep-arrow)" />
              {label && <text x={(x1 + x2) / 2 + 4} y={(y1 + y2) / 2 - 3} style={{ fill: 'var(--muted)', fontSize: 10 }}>{label}</text>}
            </g>
          );
        })}
        {d.rows.flatMap((r) => r.nodes).map((n) => {
          const p = pos[n.id];
          const c = KIND_COLOR[n.kind ?? 'service'];
          return (
            <g key={n.id}>
              <rect x={p.x - BOX_W / 2} y={p.y - BOX_H / 2} width={BOX_W} height={BOX_H} rx={6} style={{ fill: 'var(--panel-2)', stroke: c }} strokeWidth={1.6} />
              <text x={p.x} y={n.sub ? p.y - 3 : p.y + 4} textAnchor="middle" style={{ fill: 'var(--text)', fontSize: 12, fontWeight: 600 }}>{n.label}</text>
              {n.sub && <text x={p.x} y={p.y + 12} textAnchor="middle" style={{ fill: 'var(--muted)', fontSize: 10 }}>{n.sub}</text>}
            </g>
          );
        })}
      </svg>
      {d.caption && <div className="small muted" style={{ marginTop: 6 }}><Inline text={d.caption} /></div>}
    </figure>
  );
}

export function StaticSequenceView({ s }: { s: StaticSequence }) {
  const LANE_W = 170;
  const LEFT = 20;
  const TOP = 50;
  const STEP = 34;
  const width = LEFT * 2 + s.lanes.length * LANE_W;
  const height = TOP + s.steps.length * STEP + 20;
  const x = Object.fromEntries(s.lanes.map((l, i) => [l.id, LEFT + i * LANE_W + LANE_W / 2]));
  return (
    <figure className="card" style={{ margin: '10px 0', overflowX: 'auto' }}>
      <figcaption className="small" style={{ fontWeight: 600, marginBottom: 6 }}>{s.title}</figcaption>
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ minWidth: Math.min(width, 560), maxWidth: width }} role="img" aria-label={s.title}>
        <defs>
          <marker id="seq-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" style={{ fill: 'var(--muted)' }} />
          </marker>
          <marker id="seq-arrow-fail" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" style={{ fill: 'var(--err)' }} />
          </marker>
        </defs>
        {s.lanes.map((l) => (
          <g key={l.id}>
            <text x={x[l.id]} y={16} textAnchor="middle" style={{ fill: 'var(--text)', fontSize: 12, fontWeight: 700 }}>{l.label}</text>
            {l.sub && <text x={x[l.id]} y={30} textAnchor="middle" style={{ fill: 'var(--muted)', fontSize: 10 }}>{l.sub}</text>}
            <line x1={x[l.id]} x2={x[l.id]} y1={36} y2={height - 6} style={{ stroke: 'var(--lane)' }} strokeDasharray="4 4" />
          </g>
        ))}
        {s.steps.map((st, i) => {
          const y = TOP + i * STEP + 10;
          const color = st.fail ? 'var(--err)' : 'var(--c-blue)';
          if (st.from === st.to) {
            return (
              <g key={i}>
                <rect x={x[st.from] - 6} y={y - 10} width={12} height={20} rx={3} style={{ fill: color }} opacity={0.5} />
                <text x={x[st.from] + 12} y={y + 4} style={{ fill: st.fail ? 'var(--err)' : 'var(--text)', fontSize: 11 }}>{st.label}</text>
              </g>
            );
          }
          const left = x[st.from] < x[st.to];
          return (
            <g key={i}>
              <line x1={x[st.from]} y1={y} x2={x[st.to] + (left ? -4 : 4)} y2={y} style={{ stroke: color }} strokeWidth={1.5} markerEnd={st.fail ? 'url(#seq-arrow-fail)' : 'url(#seq-arrow)'} />
              <text x={(x[st.from] + x[st.to]) / 2} y={y - 5} textAnchor="middle" style={{ fill: st.fail ? 'var(--err)' : 'var(--text)', fontSize: 11 }}>{st.label}</text>
            </g>
          );
        })}
      </svg>
      {s.steps.some((st) => st.note) && (
        <ol className="small" style={{ marginTop: 8 }}>
          {s.steps.map((st, i) => <li key={i} style={{ color: st.fail ? 'var(--err)' : undefined }}><strong>{st.label}.</strong> {st.note && <Inline text={st.note} />}</li>)}
        </ol>
      )}
      {s.caption && <div className="small muted"><Markdown text={s.caption} /></div>}
    </figure>
  );
}
