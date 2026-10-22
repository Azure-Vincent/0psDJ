import { useRef, useState } from 'react';
import { applySolution, checkStep, type CheckOutcome } from '../../engine/labs/engine';
import { GUIDED_LABS, findLab } from '../../engine/labs';
import type { LabStep } from '../../engine/labs/types';
import type { World } from '../../engine/types';
import { recordConcepts } from '../../learning/progress';
import { LabTerminals } from '../components/LabTerminals';
import { Markdown } from '../components/Markdown';
import { Topology } from '../components/Topology';
import { go, useProgress } from '../state';

// The lab world lives for the browser session (not in saved progress): navigating
// away and back keeps the machines as you left them; after a reload the
// completed steps can be replayed from their reference solutions.
const LIVE = new Map<string, World>();

export function GuidedLabList() {
  const { progress } = useProgress();
  return (
    <div className="page">
      <h1>Guided labs</h1>
      <p className="muted">Build something real, one verified step at a time. Each step is checked by the simulator against the running machines, and the last step reboots everything to prove the change is complete.</p>
      {GUIDED_LABS.map((l) => {
        const p = progress.labs?.[l.id];
        const done = p?.completed.length ?? 0;
        const total = l.steps.length;
        return (
          <div key={l.id} className="card" style={{ marginTop: 12 }}>
            <div className="spread">
              <h3 style={{ margin: 0 }}><a href={`#/labs/${l.id}`}>{l.title}</a></h3>
              <span className={`badge ${p?.finishedAt ? 'ok' : done ? 'accent' : ''}`}>{p?.finishedAt ? 'completed' : done ? `${done}/${total} steps` : `${total} steps`}</span>
            </div>
            <p className="small">{l.summary}</p>
            <div className="small muted">{l.level} · {l.duration}</div>
          </div>
        );
      })}
    </div>
  );
}

function CheckLine({ r }: { r: CheckOutcome }) {
  return (
    <div className={`feedback ${r.ok ? 'ok' : 'bad'}`} style={{ fontSize: 12.5 }}>
      {r.ok ? '✓' : '✗'} {r.step ? <span className="muted">{r.step}: </span> : null}{r.description}
      <div className="small">{r.detail}</div>
    </div>
  );
}

export function GuidedLabPage({ id }: { id: string }) {
  const lab = findLab(id);
  const { progress, update } = useProgress();
  const worldRef = useRef<World | null>(LIVE.get(id) ?? null);
  const [labKey, setLabKey] = useState(0);
  const [running, setRunning] = useState(!!worldRef.current);
  const saved = progress.labs?.[id];
  const firstOpen = lab ? lab.steps.findIndex((s) => !saved?.completed.includes(s.id)) : 0;
  const [stepIdx, setStepIdx] = useState(Math.max(0, firstOpen));
  const [results, setResults] = useState<Record<string, { passed: boolean; results: CheckOutcome[] }>>({});
  const [hints, setHints] = useState<Record<string, number>>({});
  const [showSolution, setShowSolution] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);

  if (!lab) return <div className="page"><h1>Unknown lab</h1><button onClick={() => go('labs')}>Back</button></div>;
  const step = lab.steps[stepIdx];
  const completed = new Set(saved?.completed ?? []);

  const setWorld = (w: World) => { worldRef.current = w; LIVE.set(id, w); };

  const patchLab = (fn: (p: NonNullable<typeof saved>) => NonNullable<typeof saved>) =>
    update((p) => ({ ...p, labs: { ...p.labs, [id]: fn(p.labs?.[id] ?? { completed: [], assisted: [], startedAt: Date.now() }) } }));

  const begin = (replay: boolean) => {
    let w = lab.build();
    if (replay) {
      for (const s of lab.steps) if (completed.has(s.id) && !s.afterReboot) w = applySolution(w, s);
    } else {
      update((p) => ({ ...p, labs: { ...p.labs, [id]: { completed: [], assisted: [], startedAt: Date.now() } } }));
      setStepIdx(0);
    }
    setWorld(w);
    setResults({});
    setRunning(true);
    setLabKey((k) => k + 1);
  };

  const check = (s: LabStep) => {
    setBusy(true);
    setTimeout(() => {
      const r = checkStep(worldRef.current!, lab, s);
      setResults((x) => ({ ...x, [s.id]: r }));
      setBusy(false);
      if (r.passed && !completed.has(s.id)) {
        patchLab((p) => ({ ...p, completed: [...p.completed, s.id], finishedAt: s.afterReboot ? Date.now() : p.finishedAt }));
        if (s.concepts.length) update((p) => recordConcepts(p, s.concepts, !(saved?.assisted ?? []).includes(s.id), Date.now()));
      }
    }, 10);
  };

  const doItForMe = (s: LabStep) => {
    if (!confirm(`Run the reference solution of "${s.title}" on the lab machines? The step will be marked as assisted.`)) return;
    setWorld(applySolution(worldRef.current!, s));
    patchLab((p) => ({ ...p, assisted: [...new Set([...p.assisted, s.id])] }));
    setLabKey((k) => k + 1); // fresh terminals on the updated world
    check(s);
  };

  const r = results[step.id];
  const finished = !!saved?.finishedAt;

  return (
    <div className="page wide">
      <div className="spread">
        <div>
          <button className="link" onClick={() => go('labs')}>← Guided labs</button>
          <h1 style={{ marginTop: 4 }}>{lab.title} <span className="badge">{lab.level}</span> <span className="badge">{lab.duration}</span></h1>
        </div>
        <div className="row">
          {finished && <span className="badge ok">completed</span>}
          {running && <button onClick={() => { if (confirm('Discard the lab machines and start again from a fresh install? Your completed steps are reset.')) begin(false); }}>Start over</button>}
        </div>
      </div>

      {!running ? (
        <div className="grid2" style={{ marginTop: 12 }}>
          <div className="card">
            <h3>Your assignment</h3>
            <Markdown text={lab.brief} />
            <h3>You will learn to</h3>
            <ul>{lab.objectives.map((o, i) => <li key={i}>{o}</li>)}</ul>
            <h3>Before you start</h3>
            <p className="small">Helpful lessons: {lab.prerequisites.map((p, i) => <span key={p.link}>{i > 0 && ', '}<a href={`#/${p.link}`}>{p.label}</a></span>)}.</p>
            <h3>Steps</h3>
            <ol className="small">{lab.steps.map((s) => <li key={s.id}>{s.title}{completed.has(s.id) ? ' ✓' : ''}</li>)}</ol>
            <div className="row">
              {completed.size > 0 && <button className="primary" onClick={() => begin(true)}>Continue ({completed.size} step{completed.size === 1 ? '' : 's'} done)</button>}
              <button className={completed.size ? '' : 'primary'} onClick={() => begin(false)}>{completed.size ? 'Start over' : 'Start the lab'}</button>
            </div>
            {completed.size > 0 && <p className="small muted">Continue rebuilds the lab and replays the reference solutions of your completed steps (the machines themselves are not saved between sessions).</p>}
          </div>
          <div className="card">
            <h3>Topology</h3>
            <Topology />
            <p className="small muted">This lab adds <strong>srv02</strong> (eth0, MAC 52:54:00:c3:00:14), cabled to sw01 port <strong>swp10</strong>. Target: VLAN 20, 10.0.20.20.</p>
          </div>
        </div>
      ) : (
        <div className="ts-grid" style={{ marginTop: 10 }}>
          <div className="ts-col">
            <div className="card">
              <h3>Steps</h3>
              <ol className="lab-steps" style={{ listStyle: 'none', paddingLeft: 0, margin: 0 }}>
                {lab.steps.map((s, i) => (
                  <li key={s.id} style={{ margin: '3px 0' }}>
                    <button className="link" style={{ display: 'flex', gap: 6, width: '100%', textAlign: 'left', fontWeight: i === stepIdx ? 700 : 400 }} onClick={() => setStepIdx(i)}>
                      <span style={{ width: 18, flex: 'none' }}>{completed.has(s.id) ? '✓' : `${i + 1}.`}</span>
                      <span>{s.title}{(saved?.assisted ?? []).includes(s.id) ? ' (assisted)' : ''}</span>
                    </button>
                  </li>
                ))}
              </ol>
            </div>
            <div className="card">
              <h3>{stepIdx + 1}. {step.title}</h3>
              <Markdown text={step.objective} />
              <details>
                <summary className="small">Why and how it works</summary>
                <Markdown text={step.background} />
              </details>
              <h4>Do this</h4>
              <ol className="small">{step.tasks.map((t, i) => <li key={i}><Markdown text={t} /></li>)}</ol>
              {step.learn.length > 0 && <p className="small">Learn more: {step.learn.map((l, i) => <span key={l.link}>{i > 0 && ' · '}<a href={`#/${l.link}`}>{l.label}</a></span>)}</p>}
            </div>
          </div>

          <div className="ts-center">
            <LabTerminals key={labKey} getWorld={() => worldRef.current!} setWorld={setWorld} height="100%" specs={lab.terminals} />
          </div>

          <div className="ts-col">
            <div className="card">
              <div className="spread">
                <h3>Check this step</h3>
                <button className="primary" disabled={busy} onClick={() => check(step)}>{busy ? 'Checking…' : 'Check step'}</button>
              </div>
              <p className="small muted">{step.afterReboot ? 'Reboots every machine on a copy of the lab and re-runs all checks.' : 'Runs these checks against the machines as they are now (on a copy: nothing is changed).'}</p>
              {r?.passed && (
                <div className="callout small" style={{ marginBottom: 8 }}>
                  {step.afterReboot ? <><strong>Lab complete.</strong> Everything still works after a reboot of every machine.</> : <>Step done. {stepIdx + 1 < lab.steps.length && <button className="link" onClick={() => setStepIdx(stepIdx + 1)}>Next: {lab.steps[stepIdx + 1].title} →</button>}</>}
                </div>
              )}
              {r ? r.results.map((x, i) => <CheckLine key={i} r={x} />) : <ul className="small">{step.checks.map((c) => <li key={c.id}>{c.description}</li>)}</ul>}
            </div>
            {step.hints.length > 0 && (
              <div className="card">
                <div className="spread"><h3>Hints</h3><span className="muted small">{hints[step.id] ?? 0}/{step.hints.length}</span></div>
                {step.hints.slice(0, hints[step.id] ?? 0).map((h, i) => <div key={i} className="callout small"><strong>Hint {i + 1}.</strong> <Markdown text={h} /></div>)}
                {(hints[step.id] ?? 0) < step.hints.length && <button onClick={() => setHints((x) => ({ ...x, [step.id]: (x[step.id] ?? 0) + 1 }))}>Show a hint</button>}
              </div>
            )}
            {step.solution.length > 0 && (
              <div className="card">
                <div className="spread">
                  <h3>Reference solution</h3>
                  <button className="link" onClick={() => setShowSolution((x) => ({ ...x, [step.id]: !x[step.id] }))}>{showSolution[step.id] ? 'Hide' : 'Show'}</button>
                </div>
                {showSolution[step.id] && (
                  <>
                    {step.solution.map((s, i) => (
                      <div key={i}>
                        <div className="small muted">{s.user}@{s.host}{s.answers?.length ? ` (answers: ${s.answers.join(', ')})` : ''}</div>
                        <pre className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{s.commands.join('\n')}</pre>
                      </div>
                    ))}
                    <button onClick={() => doItForMe(step)}>Do it for me</button>
                    <p className="small muted">Runs these commands on the lab machines and marks the step as assisted.</p>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
