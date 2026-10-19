import { CURRICULUM, LABS } from '../../content/curriculum';
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
      <div className="card" style={{ margin: '12px 0' }}>
        <h3>Module dependency map</h3>
        <svg viewBox="0 0 640 170" width="100%" role="img" aria-label="Module dependencies">
          <defs><marker id="m-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="var(--muted)" /></marker></defs>
          {[
            ['A', 20, 70], ['B', 200, 10], ['D', 200, 70], ['E', 200, 130], ['C', 380, 30], ['F', 540, 70],
          ].map(([id, x, y]) => {
            const m = CURRICULUM.find((c) => c.id === id)!;
            return (
              <g key={id as string}>
                <rect x={x as number} y={y as number} width={140} height={34} rx={6} fill="var(--panel-2)" stroke="var(--border)" />
                <text x={(x as number) + 70} y={(y as number) + 21} textAnchor="middle" fontSize={11} style={{ fill: 'var(--text)' }}>{id}: {m.title.split(' ')[0]} {m.title.split(' ')[1] ?? ''}</text>
              </g>
            );
          })}
          {[[160, 87, 200, 27], [160, 87, 200, 87], [160, 87, 200, 147], [340, 27, 380, 47], [520, 47, 540, 80], [340, 87, 540, 87], [160, 80, 380, 40]].map(([x1, y1, x2, y2], i) => (
            <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--muted)" markerEnd="url(#m-arrow)" />
          ))}
        </svg>
      </div>
      {CURRICULUM.map((m) => (
        <div key={m.id} className="card" style={{ marginBottom: 12 }}>
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
            <tr key={l.id}><td>{l.title}{l.note && <div className="small muted">{l.note}</div>}</td><td style={{ width: 100 }}><span className={`badge ${STATUS[l.status]}`}>{l.status}</span></td></tr>
          ))}
        </tbody>
      </table>
      <p className="small muted">Also planned: the visual Infrastructure Builder (topology design with simulated packet tracing). See docs/ARCHITECTURE.md for the phased plan.</p>
    </div>
  );
}
