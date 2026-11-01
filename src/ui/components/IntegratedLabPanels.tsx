// Panels of the integrated labs' stages: the environment, the dependency map
// (request paths probed against the live lab), the incident (diagnosis and
// verified repair), the review with feedback, and the learner's notes.

import { useState } from 'react';
import { CAUSES } from '../../engine/scenarios/catalog';
import { checkRepair, gradeLabDiagnosis, type FaultCheck, type HopResult, probePath } from '../../engine/labs/integrated';
import type { GuidedLab, LabMode } from '../../engine/labs/types';
import type { World } from '../../engine/types';
import { labFeedback } from '../../learning/labFeedback';
import type { LabProgress } from '../../learning/progress';
import { Markdown } from './Markdown';

export const MODE_INFO: Record<LabMode, { label: string; text: string }> = {
  guided: { label: 'Guided', text: 'Detailed instructions: what to type, why, where the configuration lives, what success looks like and how to verify it. Hints and reference solutions are available. For a first time through.' },
  assisted: { label: 'Assisted', text: 'Objectives and background, the relevant documentation and hints on request; you decide which commands and changes are needed. Reference solutions are available, but using one marks the step as assisted.' },
  independent: { label: 'Independent', text: 'The scenario and the expected outcome only: no step-by-step instructions, no hints, no reference solutions. You investigate and complete the work yourself; the checks still tell you whether it works.' },
};

export function EnvironmentPanel({ lab }: { lab: GuidedLab }) {
  const i = lab.integrated!;
  return (
    <>
      <div className="card">
        <h3>The situation</h3>
        <p className="small"><strong>Organisation.</strong> {i.scenario.organisation}</p>
        <p className="small"><strong>What happened.</strong> {i.scenario.situation}</p>
        <p className="small"><strong>Goal.</strong> {i.scenario.goal}</p>
        <p className="small"><strong>Why it matters.</strong> {i.scenario.whyItMatters}</p>
      </div>
      <div className="card">
        <h3>Systems involved</h3>
        <table className="small"><tbody>{i.systems.map((s) => <tr key={s.host}><td className="mono" style={{ paddingRight: 8, verticalAlign: 'top' }}>{s.host}</td><td>{s.role}</td></tr>)}</tbody></table>
      </div>
      <div className="card">
        <h3>Starting configuration</h3>
        <ul className="small">{i.startingState.map((s, k) => <li key={k}>{s}</li>)}</ul>
        <p className="small muted">Inspect it in the terminals before changing anything: the machines are running now.</p>
      </div>
    </>
  );
}

export function ToolsCard({ lab }: { lab: GuidedLab }) {
  const i = lab.integrated!;
  return (
    <div className="card">
      <h3>Commands and tools</h3>
      <table className="small">
        <tbody>
          {i.tools.map((t, k) => (
            <tr key={k}>
              <td style={{ verticalAlign: 'top', paddingRight: 6 }}><span className="badge">{t.platform}</span></td>
              <td><code>{t.command}</code><div className="muted">{t.use}{t.refId ? <> · <a href={`#/reference?id=${encodeURIComponent(t.refId)}`}>reference</a></> : null}</div></td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="small muted">Everything runs in the simulator: no command reaches a real machine. Cisco IOS entries are for comparison and are not simulated.</p>
    </div>
  );
}

function HopBox({ h, active, onClick }: { h: HopResult | { id: string; label: string; status: 'unknown' }; active: boolean; onClick: () => void }) {
  const color = h.status === 'ok' ? 'var(--ok)' : h.status === 'fail' ? 'var(--err)' : 'var(--border)';
  const mark = h.status === 'ok' ? '✓' : h.status === 'fail' ? '✗' : h.status === 'not-reached' ? '·' : '?';
  return (
    <button type="button" className="link" onClick={onClick}
      style={{ display: 'flex', gap: 8, alignItems: 'center', width: '100%', textAlign: 'left', padding: '6px 8px', margin: '2px 0', border: `1px solid ${color}`, borderRadius: 6, background: active ? 'var(--panel-2)' : 'transparent' }}>
      <span style={{ width: 16, color, fontWeight: 700 }}>{mark}</span>
      <span>{h.label}</span>
    </button>
  );
}

/** Stage 2 (and the incident): the request paths, probed hop by hop on a copy of the lab. */
export function DependencyPanel({ lab, getWorld, showExplanation = true }: { lab: GuidedLab; getWorld: () => World; showExplanation?: boolean }) {
  const i = lab.integrated!;
  const [pathId, setPathId] = useState(i.dependencies.paths[0]?.id);
  const [results, setResults] = useState<Record<string, HopResult[]>>({});
  const [sel, setSel] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const path = i.dependencies.paths.find((p) => p.id === pathId)!;
  const res = results[pathId];
  const node = path.nodes.find((n) => n.id === sel);
  const hr = res?.find((r) => r.id === sel);
  const run = () => {
    setBusy(true);
    setTimeout(() => { setResults((x) => ({ ...x, [pathId]: probePath(getWorld(), path) })); setBusy(false); }, 10);
  };
  const stop = res?.find((r) => r.status === 'fail');
  return (
    <>
      {showExplanation && <div className="card"><h3>How it depends on each other</h3><Markdown text={i.dependencies.explanation} /></div>}
      <div className="card">
        <div className="spread"><h3>Request path</h3><button type="button" className="primary" disabled={busy} onClick={run}>{busy ? 'Probing…' : 'Probe the path'}</button></div>
        <select value={pathId} onChange={(e) => { setPathId(e.target.value); setSel(null); }} style={{ width: '100%', margin: '4px 0 8px' }}>
          {i.dependencies.paths.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
        {path.nodes.map((n, k) => (
          <div key={n.id}>
            <HopBox h={res?.[k] ?? { id: n.id, label: n.label, status: 'unknown' }} active={sel === n.id} onClick={() => setSel(sel === n.id ? null : n.id)} />
            {k < path.nodes.length - 1 && <div className="muted small" style={{ paddingLeft: 12, lineHeight: 1 }}>↓</div>}
          </div>
        ))}
        {res && <p className="small" style={{ marginTop: 8 }}>{stop ? <>Communication stops at <strong>{stop.label}</strong>. The evidence shows where, not why: select the hop to see what the probe ran.</> : 'Every hop answers: this path works now.'}</p>}
        {!res && <p className="small muted">The probe runs real commands on a copy of the lab (nothing changes) and stops at the first hop that fails.</p>}
        {node && (
          <div className="callout small">
            <strong>{node.label}</strong>{node.host ? <span className="muted"> · {node.host}</span> : null}
            <div>{node.role}</div>
            {hr && hr.status !== 'not-reached' && <pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: '6px 0 0' }}>{hr.evidence}</pre>}
            {hr?.status === 'not-reached' && <div className="muted">Not reached: an earlier hop failed.</div>}
          </div>
        )}
      </div>
    </>
  );
}

function CheckList({ results }: { results: FaultCheck[] }) {
  return <>{results.map((r, k) => (
    <div key={k} className={`feedback ${r.ok ? 'ok' : 'bad'}`} style={{ fontSize: 12.5 }}>
      {r.ok ? '✓' : '✗'} {r.afterReboot && <span className="muted">after reboot: </span>}{r.description}
      <div className="small" style={{ whiteSpace: 'pre-wrap' }}>{r.detail}</div>
    </div>
  ))}</>;
}

/** Stage 5: the incident. */
export function FaultPanel({ lab, mode, saved, ready, getWorld, onInject, onDiagnose, onRepaired, onHint, onShowSolution }: {
  lab: GuidedLab; mode: LabMode; saved: LabProgress | undefined; ready: boolean; getWorld: () => World;
  onInject: () => void; onDiagnose: (selected: string[], correct: boolean) => void; onRepaired: () => void; onHint: () => void; onShowSolution: () => void;
}) {
  const f = lab.integrated!.fault;
  const st = saved?.fault;
  const [selected, setSelected] = useState<string[]>(st?.diagnosis?.selected ?? []);
  const [grade, setGrade] = useState<ReturnType<typeof gradeLabDiagnosis> | null>(null);
  const [repair, setRepair] = useState<{ passed: boolean; results: FaultCheck[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [hints, setHints] = useState(st?.hints ?? 0);
  const [showSol, setShowSol] = useState(false);
  if (!ready) return <div className="card"><h3>Troubleshooting</h3><p className="small">Complete the configuration and verification steps first: the incident happens to a network that works.</p></div>;
  if (!st) {
    return (
      <div className="card">
        <h3>Troubleshooting: {f.title}</h3>
        <p className="small">Your build works. In real life, something changes later. Start the incident: the lab is changed the way it happened in the story, and you get the report as the users gave it.</p>
        <button type="button" className="primary" onClick={onInject}>Start the incident</button>
      </div>
    );
  }
  const diagnosed = !!st.diagnosis?.correct;
  return (
    <>
      <div className="card">
        <h3>The report</h3>
        <p className="small">{f.report}</p>
        {mode === 'guided' && <p className="small muted">Work like on call: reproduce the symptom, collect evidence (status, logs, connectivity, configuration), compare what works with what does not, then decide on the cause before you change anything. Restarting services is not a diagnosis.</p>}
      </div>
      <div className="card">
        <h3>1. Diagnose</h3>
        <p className="small muted">Which root cause(s) explain the evidence? Select, then submit.</p>
        {f.candidates.map((c) => (
          <label key={c} className="small" style={{ display: 'flex', gap: 6, margin: '3px 0', alignItems: 'flex-start' }}>
            <input type="checkbox" disabled={diagnosed} checked={selected.includes(c)} onChange={(e) => setSelected((x) => (e.target.checked ? [...x, c] : x.filter((y) => y !== c)))} />
            <span>{CAUSES[c]?.title ?? c}</span>
          </label>
        ))}
        {!diagnosed && <button type="button" disabled={!selected.length} onClick={() => { const g = gradeLabDiagnosis(f, selected); setGrade(g); onDiagnose(selected, g.correct); }}>Submit diagnosis</button>}
        {grade && !grade.correct && (
          <div className="feedback bad small">
            Not yet.{grade.missing.length ? ` Something that explains the evidence is missing.` : ''}
            {grade.wrong.map((w) => <div key={w.id}><strong>{w.title}</strong>: that cause would look like this: {w.signature}</div>)}
          </div>
        )}
        {diagnosed && (
          <div className="feedback ok small">
            Correct{st.diagnosis!.attempts > 1 ? ` (attempt ${st.diagnosis!.attempts})` : ''}. <strong>Root cause:</strong> {f.explanation.rootCause}
            <div><strong>Evidence:</strong> {f.explanation.evidence}</div>
          </div>
        )}
      </div>
      <div className="card">
        <div className="spread"><h3>2. Repair and verify</h3><button type="button" className="primary" disabled={busy} onClick={() => { setBusy(true); setTimeout(() => { const r = checkRepair(getWorld(), f); setRepair(r); setBusy(false); if (r.passed) onRepaired(); }, 10); }}>{busy ? 'Verifying…' : 'Verify the repair'}</button></div>
        <p className="small muted">Checks the lab as it is now, then reboots every machine on a copy and checks again.</p>
        {repair ? <CheckList results={repair.results} /> : <ul className="small">{f.checks.map((c) => <li key={c.id}>{c.description}</li>)}</ul>}
        {st.repairedAt && <div className="callout small"><strong>Repaired.</strong> {f.explanation.lesson} Continue with the review.</div>}
      </div>
      {mode !== 'independent' && f.hints.length > 0 && (
        <div className="card">
          <div className="spread"><h3>Hints</h3><span className="muted small">{hints}/{f.hints.length}</span></div>
          {f.hints.slice(0, hints).map((h, k) => <div key={k} className="callout small"><strong>Hint {k + 1}.</strong> <Markdown text={h} /></div>)}
          {hints < f.hints.length && <button type="button" onClick={() => { setHints(hints + 1); onHint(); }}>Show a hint</button>}
        </div>
      )}
      {(mode !== 'independent' || st.repairedAt) && (
        <div className="card">
          <div className="spread"><h3>Reference repair</h3><button type="button" className="link" onClick={() => { if (!showSol && !st.repairedAt && !confirm('Show the reference repair? Try to diagnose first: the diagnosis is what this stage teaches.')) return; if (!showSol && !st.repairedAt) onShowSolution(); setShowSol(!showSol); }}>{showSol ? 'Hide' : 'Show'}</button></div>
          {showSol && f.solution.map((s, k) => <div key={k}><div className="small muted">{s.user}@{s.host}</div><pre className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{s.commands.join('\n')}</pre></div>)}
        </div>
      )}
    </>
  );
}

/** A fixed, per-question order of the choices (so the right answer is not always in the same place). */
export function choiceOrder(qid: string, n: number): number[] {
  let h = 2166136261;
  for (const ch of qid) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
  const order = Array.from({ length: n }, (_, k) => k);
  for (let k = n - 1; k > 0; k--) {
    h = Math.imul(h ^ (h >>> 13), 2654435761) >>> 0;
    const j = h % (k + 1);
    [order[k], order[j]] = [order[j], order[k]];
  }
  return order;
}

/** Stage 6: questions about how the systems depend on each other. */
export function ReviewPanel({ lab, saved, onAnswer }: { lab: GuidedLab; saved: LabProgress | undefined; onAnswer: (qid: string, choice: number) => void }) {
  const i = lab.integrated!;
  const answers = saved?.review ?? {};
  return (
    <>
      <div className="card">
        <h3>Review</h3>
        <p className="small muted">About how the systems worked together. Your first answer counts.</p>
        {i.review.map((q, k) => {
          const a = answers[q.id];
          return (
            <div key={q.id} style={{ marginTop: 10 }}>
              <div className="small"><strong>{k + 1}.</strong> {q.question}</div>
              {choiceOrder(`${lab.id}:${q.id}`, q.choices.length).map((j) => (
                <label key={j} className="small" style={{ display: 'flex', gap: 6, margin: '2px 0 2px 12px' }}>
                  <input type="radio" name={q.id} disabled={a !== undefined} checked={a === j} onChange={() => onAnswer(q.id, j)} />
                  <span style={a !== undefined && j === q.answer ? { fontWeight: 600 } : undefined}>{q.choices[j]}</span>
                </label>
              ))}
              {a !== undefined && <div className={`feedback ${a === q.answer ? 'ok' : 'bad'} small`}>{a === q.answer ? 'Right.' : 'Not quite.'} {q.explanation}</div>}
            </div>
          );
        })}
      </div>
    </>
  );
}

/** Feedback on the whole lab: subjects shown or to review (with lessons), and the troubleshooting process. */
export function FeedbackCard({ lab, saved }: { lab: GuidedLab; saved: LabProgress | undefined }) {
  const fb = labFeedback(lab, saved);
  return (
    <>
      <div className="card">
        <h3>Feedback</h3>
        <p className="small">Steps without the reference solution: {fb.score.steps}/{fb.score.stepsTotal} · review: {fb.score.review}/{fb.score.reviewTotal} · incident: {fb.score.repaired ? 'repaired' : 'not repaired yet'}{fb.score.diagnosis === null ? '' : fb.score.diagnosis ? ', diagnosed at the first attempt' : ', diagnosed after several attempts'}</p>
        <h4>Your troubleshooting process</h4>
        {fb.process.length ? fb.process.map((p, k) => <div key={k} className={`feedback ${p.ok ? 'ok' : 'bad'} small`}>{p.text}</div>) : <p className="small muted">Appears once you have worked on the incident.</p>}
        <h4>Subjects</h4>
        {fb.concepts.map((c) => (
          <div key={c.id} className="small" style={{ margin: '6px 0' }}>
            <span className={`badge ${c.status === 'shown' ? 'ok' : 'warn'}`}>{c.status === 'shown' ? 'understood' : 'review'}</span> <strong>{c.title}</strong>
            {c.link && <> · <a href={`#/${c.link}`}>lesson</a></>}
            <ul style={{ margin: '2px 0' }}>{c.evidence.map((e, k) => <li key={k} className="muted">{e}</li>)}</ul>
          </div>
        ))}
      </div>
    </>
  );
}

export function NotesCard({ initial, onSave }: { initial: string; onSave: (text: string) => void }) {
  const [text, setText] = useState(initial);
  return (
    <div className="card">
      <h3>Notes</h3>
      <textarea value={text} onChange={(e) => setText(e.target.value)} onBlur={() => onSave(text)} rows={5} style={{ width: '100%', fontFamily: 'var(--mono, monospace)', fontSize: 12 }} placeholder="Evidence, hypotheses, what you changed… (saved with your progress)" />
    </div>
  );
}
