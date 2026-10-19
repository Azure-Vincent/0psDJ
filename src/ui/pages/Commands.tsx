import { useState } from 'react';
import { COMMAND_EXERCISES, COMMAND_REFS } from '../../content/commands';
import type { CommandExercise } from '../../content/types';
import { gradeCommandExercise, type GradeResult } from '../../learning/grading';
import { recordConcepts } from '../../learning/progress';
import { Inline } from '../components/Markdown';
import { routeQuery, useProgress } from '../state';

function Exercise({ ex }: { ex: CommandExercise }) {
  const { progress, update } = useProgress();
  const [text, setText] = useState('');
  const [picked, setPicked] = useState<number[]>([]);
  const [missing, setMissing] = useState(false);
  const [result, setResult] = useState<GradeResult | null>(null);
  const done = progress.exercises[ex.id]?.correct;
  const check = () => {
    const r = gradeCommandExercise(ex, ex.kind === 'choose-command' ? text : missing ? [] : picked);
    setResult(r);
    update((p) => {
      const prev = p.exercises[ex.id];
      const next = recordConcepts(p, ex.concepts, r.correct, Date.now());
      return { ...next, exercises: { ...next.exercises, [ex.id]: { attempts: (prev?.attempts ?? 0) + 1, correct: r.correct || !!prev?.correct } } };
    });
  };
  return (
    <div className="card" style={{ marginBottom: 10 }}>
      <div className="spread"><span className="badge">{ex.kind === 'choose-command' ? 'Which command?' : 'Spot the abnormality'}</span>{done && <span className="badge ok">solved</span>}</div>
      <p><Inline text={ex.situation} /></p>
      {ex.kind === 'choose-command' ? (
        <input className="mono" style={{ width: '100%' }} placeholder="type the command line you would run" value={text} onChange={(e) => { setText(e.target.value); setResult(null); }} onKeyDown={(e) => e.key === 'Enter' && check()} />
      ) : (
        <>
          <pre style={{ padding: 0 }}>
            {ex.output!.map((l, i) => (
              <div key={i} onClick={() => { setMissing(false); setResult(null); setPicked((p) => (p.includes(i) ? p.filter((x) => x !== i) : [...p, i])); }}
                style={{ padding: '2px 10px', cursor: 'pointer', background: picked.includes(i) && !missing ? 'var(--accent-soft)' : undefined }}>{l}</div>
            ))}
          </pre>
          <label className="row small"><input type="checkbox" checked={missing} onChange={(e) => { setMissing(e.target.checked); setResult(null); }} /> No line is wrong: something expected is missing</label>
        </>
      )}
      <div className="row" style={{ marginTop: 6 }}><button className="primary" onClick={check}>Check</button></div>
      {result && (
        <>
          {result.feedback.map((f, i) => <div key={i} className={`feedback ${f.ok ? 'ok' : 'bad'}`}>{f.text}</div>)}
          {(result.correct || (progress.exercises[ex.id]?.attempts ?? 0) >= 2) && <div className="callout ok small"><Inline text={ex.explanation} /></div>}
        </>
      )}
    </div>
  );
}

export function Commands() {
  const q = routeQuery();
  const [tab, setTab] = useState<'reference' | 'practice'>(q.get('tab') === 'practice' ? 'practice' : 'reference');
  const [filter, setFilter] = useState(q.get('q') ?? '');
  const [platform, setPlatform] = useState<'all' | 'Linux' | 'Windows'>('all');
  const [open, setOpen] = useState<string | null>(q.get('id'));
  const list = COMMAND_REFS.filter((c) => (platform === 'all' || c.platform === platform) && (`${c.name} ${c.purpose} ${c.category}`.toLowerCase().includes(filter.toLowerCase())));
  return (
    <div className="page">
      <h1>Diagnostic commands</h1>
      <div className="tabs">
        <button className={tab === 'reference' ? 'active' : ''} onClick={() => setTab('reference')}>Reference</button>
        <button className={tab === 'practice' ? 'active' : ''} onClick={() => setTab('practice')}>Practice</button>
      </div>
      {tab === 'reference' ? (
        <>
          <div className="row" style={{ marginBottom: 10 }}>
            <input placeholder="Filter commands…" value={filter} onChange={(e) => setFilter(e.target.value)} />
            <select value={platform} onChange={(e) => setPlatform(e.target.value as typeof platform)}>
              <option value="all">All platforms</option><option>Linux</option><option>Windows</option>
            </select>
            <span className="small muted">Commands marked <span className="badge accent">in simulator</span> can be run in the lab terminals.</span>
          </div>
          {list.map((c) => (
            <div className="card" key={c.id} style={{ marginBottom: 8 }}>
              <div className="spread" style={{ cursor: 'pointer' }} onClick={() => setOpen(open === c.id ? null : c.id)}>
                <span><strong className="mono">{c.name}</strong> <span className="muted small">· {c.platform} · {c.category}</span></span>
                <span className="row">{c.simulator && <span className="badge accent">in simulator</span>}<span className="muted">{open === c.id ? '▾' : '▸'}</span></span>
              </div>
              <div className="small" style={{ marginTop: 4 }}><Inline text={c.purpose} /></div>
              {open === c.id && (
                <div style={{ marginTop: 8 }}>
                  <div className="small muted">Syntax</div><pre>{c.syntax}</pre>
                  <table><tbody>{c.args.map((a) => <tr key={a.arg}><td className="mono" style={{ whiteSpace: 'nowrap' }}>{a.arg}</td><td>{a.meaning}</td></tr>)}</tbody></table>
                  <div className="small muted">Example</div>
                  <pre><span style={{ color: 'var(--accent)' }}>$ {c.example.command}</span>{'\n'}{c.example.output}</pre>
                  <p><strong>Interpreting it.</strong> <Inline text={c.interpretation} /></p>
                  <p><strong>Limitations.</strong> <Inline text={c.limitations} /></p>
                </div>
              )}
            </div>
          ))}
        </>
      ) : (
        <>
          <p className="muted">You are not told which command to use. For "Which command?", type the full command line you would run; it is checked for the right tool and the arguments that make it answer the question.</p>
          {COMMAND_EXERCISES.map((ex) => <Exercise key={ex.id} ex={ex} />)}
        </>
      )}
    </div>
  );
}
