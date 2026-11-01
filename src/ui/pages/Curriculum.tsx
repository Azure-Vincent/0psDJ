import { CURRICULUM, LABS } from '../../content/curriculum';
import { getLesson } from '../../content/lessons';
import { INTEGRATED_LABS } from '../../engine/labs';
import type { CurriculumModule } from '../../content/types';
import { go } from '../state';

const STATUS: Record<string, string> = { available: 'ok', partial: 'accent', planned: '' };

export function Curriculum() {
  return (
    <div className="page">
      <h1>Curriculum</h1>
      <p className="muted">
        Modules build on each other (arrows show prerequisites). <span className="badge ok">available</span> = complete lesson,{' '}
        <span className="badge accent">partial</span> = covered inside an available lesson or lab, <span className="badge">planned</span> = on the roadmap, not yet implemented.
      </p>
      <ModuleMap />
      {CURRICULUM.map((m) => (
        <div key={m.id} id={`module-${m.id}`} className="card" style={{ marginBottom: 12 }}>
          <div className="spread">
            <h2 style={{ margin: 0 }}>Module {m.id}: {m.title}</h2>
            <span className="muted small">{m.dependsOn.length ? `Builds on ${m.dependsOn.join(', ')}` : 'Foundation'}</span>
          </div>
          <p className="muted">{m.summary}</p>
          <table>
            <tbody>
              {m.topics.map((t) => (
                <tr key={t.title}>
                  <td>{t.link ? <button className="link" onClick={() => go(t.link!)}>{t.title}</button> : t.title}{t.note && <div className="small muted">{t.note}</div>}</td>
                  <td style={{ width: 110 }}><span className="badge">{t.level}</span></td>
                  <td style={{ width: 100 }}><span className={`badge ${STATUS[t.status]}`}>{t.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      <h2>Progressive enterprise labs</h2>
      <table>
        <tbody>
          {LABS.map((l) => (
            <tr key={l.id}><td>{'link' in l && l.link ? <a href={`#/${l.link}`}>{l.title}</a> : l.title}{l.note && <div className="small muted">{l.note}</div>}</td><td style={{ width: 100 }}><span className={`badge ${STATUS[l.status]}`}>{l.status}</span></td></tr>
          ))}
        </tbody>
      </table>
      <h2>Integrated labs</h2>
      <p className="small muted">Several subjects in one realistic situation, in the order of the learning path. Each builds on the lessons listed (recommended, not required) and ends with an incident to troubleshoot; the last one prepares for the unguided <a href="#/cases">case studies</a>.</p>
      <table>
        <tbody>
          {INTEGRATED_LABS.map((l) => (
            <tr key={l.id}>
              <td><a href={`#/labs/${l.id}`}>{l.title}</a><div className="small muted">Builds on: {l.integrated!.after.map((a) => getLesson(a)?.title ?? a).join(', ')}</div></td>
              <td style={{ width: 100 }}><span className="badge">{l.level}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="small muted">Design your own networks in the <a href="#/builder">Infrastructure Builder</a>: draw machines, switches and routers, then build and trace packets through them. See docs/ARCHITECTURE.md for the phased plan.</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Module dependency map, laid out from the modules' `dependsOn` lists:
// columns by dependency depth, rows ordered to keep arrows short, and only
// direct prerequisites drawn (an edge implied by a longer path is omitted).
// ---------------------------------------------------------------------------

const BOX_W = 196;
const BOX_H = 66;
const COL_GAP = 64;
const ROW_GAP = 22;
const PAD = 10;

function wrap(text: string, max: number): string[] {
  const lines: string[] = [];
  let cur = '';
  for (const w of text.split(' ')) {
    if (cur && (cur + ' ' + w).length > max) { lines.push(cur); cur = w; } else cur = cur ? cur + ' ' + w : w;
  }
  if (cur) lines.push(cur);
  return lines;
}

function layoutModules(mods: CurriculumModule[]) {
  const byId = new Map(mods.map((m) => [m.id, m]));
  const depth = new Map<string, number>();
  const depthOf = (id: string): number => {
    if (!depth.has(id)) depth.set(id, Math.max(-1, ...(byId.get(id)?.dependsOn ?? []).filter((d) => byId.has(d)).map(depthOf)) + 1);
    return depth.get(id)!;
  };
  mods.forEach((m) => depthOf(m.id));
  // A prerequisite is drawn only if it is not reachable through another prerequisite.
  const reaches = (from: string, to: string): boolean => (byId.get(from)?.dependsOn ?? []).some((d) => d === to || reaches(d, to));
  const edges = mods.flatMap((m) => m.dependsOn.filter((d) => byId.has(d) && !m.dependsOn.some((o) => o !== d && reaches(o, d))).map((d) => [d, m.id] as const));
  const cols: string[][] = [];
  mods.forEach((m) => (cols[depth.get(m.id)!] ??= []).push(m.id));
  // Order each column so modules feeding later columns sit next to what they feed.
  const children = (id: string) => edges.filter(([a]) => a === id).map(([, b]) => b);
  const rank = (id: string) => Math.min(99, ...children(id).map((c) => depth.get(c)! * 10 + cols[depth.get(c)!].indexOf(c)));
  for (let i = cols.length - 2; i >= 0; i--) cols[i].sort((a, b) => rank(a) - rank(b));
  const rows = Math.max(...cols.map((c) => c.length));
  const height = PAD * 2 + rows * BOX_H + (rows - 1) * ROW_GAP;
  const pos = new Map<string, { x: number; y: number }>();
  cols.forEach((col, ci) => {
    const x = PAD + ci * (BOX_W + COL_GAP);
    col.forEach((id, ri) => {
      // Single-module columns sit level with the average of their drawn prerequisites.
      const parents = edges.filter(([, b]) => b === id).map(([a]) => pos.get(a)?.y).filter((y): y is number => y !== undefined);
      const y = col.length === 1 && parents.length ? parents.reduce((s, v) => s + v, 0) / parents.length : PAD + (height - PAD * 2 - (col.length * BOX_H + (col.length - 1) * ROW_GAP)) / 2 + ri * (BOX_H + ROW_GAP);
      pos.set(id, { x, y });
    });
  });
  return { pos, edges, width: PAD * 2 + cols.length * BOX_W + (cols.length - 1) * COL_GAP, height };
}

function ModuleMap() {
  const { pos, edges, width, height } = layoutModules(CURRICULUM);
  const scrollTo = (id: string) => document.getElementById(`module-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  return (
    <div className="card" style={{ margin: '12px 0', overflowX: 'auto' }}>
      <h3>Module dependency map</h3>
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ minWidth: 640, maxWidth: width * 1.3 }} role="img" aria-label="Module dependencies: arrows point from a prerequisite to the module that builds on it">
        <defs>
          <marker id="m-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 z" style={{ fill: 'var(--muted)' }} /></marker>
        </defs>
        {edges.map(([a, b]) => {
          const p = pos.get(a)!;
          const q = pos.get(b)!;
          const x1 = p.x + BOX_W;
          const y1 = p.y + BOX_H / 2;
          const x2 = q.x - 2;
          const y2 = q.y + BOX_H / 2;
          const mid = (x1 + x2) / 2;
          return <path key={a + b} d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`} fill="none" style={{ stroke: 'var(--muted)' }} strokeWidth={1.4} markerEnd="url(#m-arrow)" />;
        })}
        {CURRICULUM.map((m) => {
          const { x, y } = pos.get(m.id)!;
          const lines = wrap(m.title, 24).slice(0, 2);
          const avail = m.topics.filter((t) => t.status === 'available').length;
          return (
            <g key={m.id} onClick={() => scrollTo(m.id)} style={{ cursor: 'pointer' }}>
              <title>{`Module ${m.id}: ${m.title}${m.dependsOn.length ? ` (builds on ${m.dependsOn.join(', ')})` : ''}`}</title>
              <rect x={x} y={y} width={BOX_W} height={BOX_H} rx={8} style={{ fill: 'var(--panel-2)', stroke: 'var(--accent)' }} strokeWidth={1.2} />
              <text x={x + 12} y={y + 20} fontSize={13} fontWeight={700} style={{ fill: 'var(--accent)' }}>{m.id}</text>
              {lines.map((l, i) => (
                <text key={i} x={x + 30} y={y + 20 + i * 15} fontSize={12.5} fontWeight={600} style={{ fill: 'var(--text)' }}>{l}</text>
              ))}
              <text x={x + 30} y={y + BOX_H - 9} fontSize={10.5} style={{ fill: 'var(--muted)' }}>{avail} of {m.topics.length} topics available</text>
            </g>
          );
        })}
      </svg>
      <p className="small muted" style={{ marginTop: 4 }}>Arrows point from a prerequisite to the module that builds on it. Click a module to jump to its topics.</p>
    </div>
  );
}
