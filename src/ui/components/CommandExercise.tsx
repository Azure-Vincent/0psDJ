// Command-practice exercise card (used by the reference library's Practice tab).

import { useState } from 'react';
import type { CommandExercise } from '../../content/types';
import { gradeCommandExercise, type GradeResult } from '../../learning/grading';
import { recordConcepts } from '../../learning/progress';
import { Inline } from '../components/Markdown';
import { useProgress } from '../state';

export function Exercise({ ex }: { ex: CommandExercise }) {
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

