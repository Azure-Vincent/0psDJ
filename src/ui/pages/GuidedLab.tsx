import { useRef, useState } from 'react';
import { applySolution, checkStep, type CheckOutcome } from '../../engine/labs/engine';
import { INTEGRATED_LABS, SERVICE_LABS, findLab } from '../../engine/labs';
import { classifyCommand, injectFault, readyForFault, rebuildLab } from '../../engine/labs/integrated';
import type { GuidedLab, LabMode, LabStep } from '../../engine/labs/types';
import type { CommandLogEntry } from '../../engine/shell/shell';
import type { World } from '../../engine/types';
import { type LabProgress, recordConcepts } from '../../learning/progress';
import { DependencyPanel, EnvironmentPanel, FaultPanel, FeedbackCard, MODE_INFO, NotesCard, ReviewPanel, ToolsCard } from '../components/IntegratedLabPanels';
import { LabTerminals } from '../components/LabTerminals';
import { Markdown } from '../components/Markdown';
import { Topology } from '../components/Topology';
import { go, useProgress } from '../state';

// The lab world lives for the browser session (not in saved progress): navigating
// away and back keeps the machines as you left them; after a reload the
// completed steps are replayed from their reference solutions (and the
// incident re-injected), so the lab continues where it was.
const LIVE = new Map<string, World>();

const MODES: LabMode[] = ['guided', 'assisted', 'independent'];

function LabCard({ l }: { l: GuidedLab }) {
  const { progress } = useProgress();
  const p = progress.labs?.[l.id];
  const done = p?.completed.length ?? 0;
  const total = l.steps.length;
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="spread">
        <h3 style={{ margin: 0 }}><a href={`#/labs/${l.id}`}>{l.title}</a></h3>
        <span className={`badge ${p?.finishedAt ? 'ok' : done ? 'accent' : ''}`}>{p?.finishedAt ? 'completed' : done ? `${done}/${total} steps` : `${total} steps`}</span>
      </div>
      <p className="small">{l.summary}</p>
      <div className="small muted">
        {l.level} · {l.duration}
        {l.integrated && <> · {l.integrated.technologies.join(', ')}</>}
        {(p?.modesCompleted ?? []).map((m) => <span key={m} className="badge ok" style={{ marginLeft: 6 }}>{MODE_INFO[m].label}</span>)}
      </div>
    </div>
  );
}

export function GuidedLabList() {
  return (
    <div className="page">
      <h1>Guided labs</h1>
      <p className="muted">Build something real, one verified step at a time. Each step is checked by the simulator against the running machines, and the last step reboots everything to prove the change is complete.</p>
      <h2>Integrated labs</h2>
      <p className="small muted">Several subjects in one realistic situation, in six stages: understand the environment and its dependencies, configure, verify, troubleshoot an incident, review. Each can be done guided, assisted or independently, and repeated in a harder mode. They follow the learning path, and the last one prepares for the unguided <a href="#/cases">case studies</a>.</p>
      {INTEGRATED_LABS.map((l) => <LabCard key={l.id} l={l} />)}
      <h2 style={{ marginTop: 24 }}>Service labs</h2>
      <p className="small muted">One service each, built step by step.</p>
      {SERVICE_LABS.map((l) => <LabCard key={l.id} l={l} />)}
    </div>
  );
}

function CheckLine({ r }: { r: CheckOutcome }) {
  return (
    <div className={`feedback ${r.ok ? 'ok' : 'bad'}`} style={{ fontSize: 12.5 }}>
      {r.ok ? '✓' : '✗'} {r.step ? <span className="muted">{r.step}: </span> : null}{r.description}
      <div className="small" style={{ whiteSpace: 'pre-wrap' }}>{r.detail}</div>
    </div>
  );
}

type Stage = 'environment' | 'dependencies' | 'configure' | 'verify' | 'troubleshoot' | 'review';
const STAGES: { id: Stage; label: string }[] = [
  { id: 'environment', label: '1 Environment' },
  { id: 'dependencies', label: '2 Dependencies' },
  { id: 'configure', label: '3 Configure' },
  { id: 'verify', label: '4 Verify' },
  { id: 'troubleshoot', label: '5 Troubleshoot' },
  { id: 'review', label: '6 Review' },
];

function emptyLab(mode: LabMode): LabProgress {
  return { completed: [], assisted: [], startedAt: Date.now(), mode };
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
  const [stage, setStage] = useState<Stage>(saved?.fault ? 'troubleshoot' : saved?.completed.length ? 'configure' : 'environment');
  const [chosenMode, setChosenMode] = useState<LabMode>(saved?.mode ?? 'guided');
  const [results, setResults] = useState<Record<string, { passed: boolean; results: CheckOutcome[] }>>({});
  const [hints, setHints] = useState<Record<string, number>>({});
  const [showSolution, setShowSolution] = useState<Record<string, boolean>>({});
  const [showTasks, setShowTasks] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);

  if (!lab) return <div className="page"><h1>Unknown lab</h1><button onClick={() => go('labs')}>Back</button></div>;
  const integrated = lab.integrated;
  const mode: LabMode = saved?.mode ?? 'guided';
  const completed = new Set(saved?.completed ?? []);

  const setWorld = (w: World) => { worldRef.current = w; LIVE.set(id, w); };
  const getWorld = () => worldRef.current!;

  const patchLab = (fn: (p: LabProgress) => LabProgress) =>
    update((p) => ({ ...p, labs: { ...p.labs, [id]: fn(p.labs?.[id] ?? emptyLab(mode)) } }));

  const begin = (replay: boolean, newMode?: LabMode) => {
    let w: World;
    if (replay) {
      w = rebuildLab(lab, saved?.completed ?? [], { injected: !!saved?.fault, repaired: !!saved?.fault?.repairedAt });
    } else {
      w = lab.build();
      // A fresh start keeps the notes and the modes already completed.
      update((p) => ({ ...p, labs: { ...p.labs, [id]: { ...emptyLab(newMode ?? chosenMode), notes: p.labs?.[id]?.notes, modesCompleted: p.labs?.[id]?.modesCompleted } } }));
      setStepIdx(0);
      setStage(integrated ? 'environment' : 'configure');
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
        patchLab((p) => ({ ...p, completed: [...p.completed, s.id], finishedAt: s.afterReboot && !integrated ? Date.now() : p.finishedAt }));
        if (s.concepts.length) update((p) => recordConcepts(p, s.concepts, !(saved?.assisted ?? []).includes(s.id), Date.now()));
      }
    }, 10);
  };

  const doItForMe = (s: LabStep) => {
    if (!confirm(`Run the reference solution of "${s.title}" on the lab machines? The step will be marked as assisted.`)) return;
    // The terminals keep their history: they read the world through getWorld.
    setWorld(applySolution(worldRef.current!, s));
    patchLab((p) => ({ ...p, assisted: [...new Set([...p.assisted, s.id])] }));
    check(s);
  };

  const onCommand = (e: CommandLogEntry) => {
    const { kind, tool } = classifyCommand(e.line);
    patchLab((p) => {
      const next: LabProgress = { ...p, commands: (p.commands ?? 0) + 1, restarts: (p.restarts ?? 0) + (kind === 'restart' ? 1 : 0) };
      if (kind === 'diagnostic' && !(p.tools ?? []).includes(tool)) next.tools = [...(p.tools ?? []), tool];
      if (p.fault && !p.fault.diagnosis?.correct) {
        next.fault = { ...p.fault, commandsBefore: (p.fault.commandsBefore ?? 0) + (kind === 'diagnostic' ? 1 : 0), restartsBefore: (p.fault.restartsBefore ?? 0) + (kind === 'restart' ? 1 : 0) };
      }
      return next;
    });
  };

  const finished = !!saved?.finishedAt;
  const ready = readyForFault(lab, saved?.completed ?? []);
  const configSteps = lab.steps.filter((s) => (s.stage ?? 'configure') === 'configure');
  const verifySteps = lab.steps.filter((s) => s.stage === 'verify');
  const stageSteps = !integrated ? lab.steps : stage === 'verify' ? verifySteps : configSteps;
  const stepsView = stage === 'configure' || stage === 'verify' || !integrated;
  const step = stepsView ? (stageSteps.includes(lab.steps[stepIdx]) ? lab.steps[stepIdx] : stageSteps[0]) : lab.steps[stepIdx];
  const r = step ? results[step.id] : undefined;

  const reviewDone = !!integrated && integrated.review.every((q) => saved?.review?.[q.id] !== undefined);
  const stageDone: Record<Stage, boolean> = {
    environment: (saved?.completed.length ?? 0) > 0,
    dependencies: (saved?.completed.length ?? 0) > 0,
    configure: configSteps.every((s) => completed.has(s.id)),
    verify: verifySteps.every((s) => completed.has(s.id)),
    troubleshoot: !!saved?.fault?.repairedAt && !!saved?.fault?.diagnosis?.correct,
    review: reviewDone,
  };

  const maybeFinish = (p: LabProgress): LabProgress => {
    if (!integrated) return p;
    const allReview = integrated.review.every((q) => p.review?.[q.id] !== undefined);
    if (p.fault?.repairedAt && p.fault?.diagnosis?.correct && allReview && readyForFault(lab, p.completed) && !p.finishedAt) {
      const m = p.mode ?? 'guided';
      return { ...p, finishedAt: Date.now(), modesCompleted: [...new Set([...(p.modesCompleted ?? []), m])] };
    }
    return p;
  };

  const header = (
    <div className="spread">
      <div>
        <button className="link" onClick={() => go('labs')}>← Guided labs</button>
        <h1 style={{ marginTop: 4 }}>{lab.title} <span className="badge">{lab.level}</span> <span className="badge">{lab.duration}</span>{running && integrated && <span className="badge accent" style={{ marginLeft: 6 }}>{MODE_INFO[mode].label} mode</span>}</h1>
      </div>
      <div className="row">
        {finished && <span className="badge ok">completed</span>}
        {running && <button onClick={() => { if (confirm('Discard the lab machines and start again from the starting configuration? Your completed steps, incident and review answers are reset (your notes are kept).')) begin(false, mode); }}>Start over</button>}
      </div>
    </div>
  );

  if (!running) {
    const nextMode = MODES.find((m) => !(saved?.modesCompleted ?? []).includes(m));
    return (
      <div className="page wide">
        {header}
        <div className="grid2" style={{ marginTop: 12 }}>
          <div className="card">
            <h3>Your assignment</h3>
            <Markdown text={lab.brief} />
            {integrated && (
              <>
                <h3>Technologies</h3>
                <p className="small">{integrated.technologies.map((t) => <span key={t} className="badge" style={{ margin: '0 4px 4px 0' }}>{t}</span>)}</p>
              </>
            )}
            <h3>You will learn to</h3>
            <ul>{lab.objectives.map((o, i) => <li key={i}>{o}</li>)}</ul>
            <h3>Before you start</h3>
            <p className="small">Helpful lessons{integrated ? ' (recommended, not required)' : ''}: {lab.prerequisites.map((p, i) => <span key={p.link}>{i > 0 && ', '}<a href={`#/${p.link}`}>{p.label}</a></span>)}.</p>
            {integrated && (
              <>
                <h3>How it is verified</h3>
                <p className="small">{integrated.verification}</p>
                <details><summary className="small">Common mistakes</summary><ul className="small">{integrated.mistakes.map((m, i) => <li key={i}>{m}</li>)}</ul></details>
                <h3>Learning mode</h3>
                {MODES.map((m) => (
                  <label key={m} className="small" style={{ display: 'flex', gap: 8, margin: '6px 0', alignItems: 'flex-start' }}>
                    <input type="radio" name="mode" checked={chosenMode === m} onChange={() => setChosenMode(m)} />
                    <span><strong>{MODE_INFO[m].label}</strong>{(saved?.modesCompleted ?? []).includes(m) && <span className="badge ok" style={{ marginLeft: 6 }}>completed</span>} · {MODE_INFO[m].text}</span>
                  </label>
                ))}
                {finished && nextMode && nextMode !== chosenMode && <p className="small">Done in {MODE_INFO[mode].label.toLowerCase()} mode: try it again in <button className="link" onClick={() => setChosenMode(nextMode)}>{MODE_INFO[nextMode].label.toLowerCase()} mode</button>.</p>}
              </>
            )}
            <h3>{integrated ? 'Configuration steps' : 'Steps'}</h3>
            <ol className="small">{lab.steps.map((s) => <li key={s.id}>{s.title}{completed.has(s.id) ? ' ✓' : ''}</li>)}</ol>
            <div className="row">
              {completed.size > 0 && !finished && <button className="primary" onClick={() => begin(true)}>Continue ({completed.size} step{completed.size === 1 ? '' : 's'} done{saved?.fault ? ', incident started' : ''})</button>}
              <button className={completed.size && !finished ? '' : 'primary'} onClick={() => { if (completed.size && !confirm('Start again from the starting configuration? Progress in this lab is reset (notes and completed modes are kept).')) return; begin(false, chosenMode); }}>{completed.size ? `Start over${integrated ? ` (${MODE_INFO[chosenMode].label.toLowerCase()})` : ''}` : 'Start the lab'}</button>
            </div>
            {completed.size > 0 && !finished && <p className="small muted">Continue rebuilds the lab and replays the reference solutions of your completed steps{integrated ? ' (and restarts the incident if you had started it)' : ''}: the machines themselves are not saved between sessions.</p>}
          </div>
          <div className="card">
            <h3>Topology</h3>
            <Topology />
            {lab.setupNote && <div className="small muted"><Markdown text={lab.setupNote} /></div>}
          </div>
        </div>
      </div>
    );
  }

  const leftSteps = (
    <>
      <div className="card">
        <h3>{integrated ? (stage === 'verify' ? 'Verification' : 'Configuration steps') : 'Steps'}</h3>
        <ol className="lab-steps" style={{ listStyle: 'none', paddingLeft: 0, margin: 0 }}>
          {stageSteps.map((s) => {
            const i = lab.steps.indexOf(s);
            return (
              <li key={s.id} style={{ margin: '3px 0' }}>
                <button type="button" className="link" style={{ display: 'flex', gap: 6, width: '100%', textAlign: 'left', fontWeight: s === step ? 700 : 400 }} onClick={() => setStepIdx(i)}>
                  <span style={{ width: 18, flex: 'none' }}>{completed.has(s.id) ? '✓' : `${i + 1}.`}</span>
                  <span>{s.title}{(saved?.assisted ?? []).includes(s.id) ? ' (assisted)' : ''}</span>
                </button>
              </li>
            );
          })}
        </ol>
      </div>
      {step && (
        <div className="card">
          <h3>{lab.steps.indexOf(step) + 1}. {step.title}</h3>
          <Markdown text={step.objective} />
          {mode !== 'independent' && (
            <details open={mode === 'guided'}>
              <summary className="small">Why and how it works</summary>
              <Markdown text={step.background} />
            </details>
          )}
          {(mode === 'guided' || showTasks[step.id]) && (
            <>
              <h4>Do this</h4>
              <ol className="small">{step.tasks.map((t, i) => <li key={i}><Markdown text={t} /></li>)}</ol>
            </>
          )}
          {mode === 'assisted' && !showTasks[step.id] && <button type="button" className="link small" onClick={() => { setShowTasks((x) => ({ ...x, [step.id]: true })); patchLab((p) => ({ ...p, hints: (p.hints ?? 0) + 1 })); }}>Show the detailed steps (counts as a hint)</button>}
          {mode === 'guided' && step.commands && step.commands.length > 0 && (
            <>
              <h4>The important commands</h4>
              {step.commands.map((c, i) => (
                <details key={i} className="small">
                  <summary><code>{c.command}</code> <span className="muted">({c.host})</span></summary>
                  <div style={{ paddingLeft: 10 }}>
                    <div><strong>What:</strong> {c.what}</div>
                    <div><strong>Why:</strong> {c.why}</div>
                    {c.where && <div><strong>Where:</strong> {c.where}</div>}
                    <div><strong>Success looks like:</strong> {c.success}</div>
                    {c.verify && <div><strong>Verify:</strong> {c.verify}</div>}
                  </div>
                </details>
              ))}
            </>
          )}
          {mode !== 'independent' && step.learn.length > 0 && <p className="small">Learn more: {step.learn.map((l, i) => <span key={l.link}>{i > 0 && ' · '}<a href={`#/${l.link}`}>{l.label}</a></span>)}</p>}
        </div>
      )}
    </>
  );

  const rightSteps = step && (
    <>
      <div className="card">
        <div className="spread">
          <h3>Check this step</h3>
          <button type="button" className="primary" disabled={busy} onClick={() => check(step)}>{busy ? 'Checking…' : 'Check step'}</button>
        </div>
        <p className="small muted">{step.afterReboot ? 'Reboots every machine on a copy of the lab and re-runs all checks.' : 'Runs these checks against the machines as they are now (on a copy: nothing is changed).'}</p>
        {r?.passed && (
          <div className="callout small" style={{ marginBottom: 8 }}>
            {step.afterReboot ? (integrated ? <><strong>Build verified.</strong> Everything still works after a reboot of every machine. <button type="button" className="link" onClick={() => setStage('troubleshoot')}>Next: troubleshooting →</button></> : <><strong>Lab complete.</strong> Everything still works after a reboot of every machine.</>) : <>Step done. {(() => { const n = lab.steps[lab.steps.indexOf(step) + 1]; return n ? <button type="button" className="link" onClick={() => { setStepIdx(lab.steps.indexOf(n)); if (integrated && n.stage === 'verify') setStage('verify'); }}>Next: {n.title} →</button> : null; })()}</>}
          </div>
        )}
        {r ? r.results.map((x, i) => <CheckLine key={i} r={x} />) : <ul className="small">{(step.afterReboot ? [...lab.steps.filter((s) => !s.afterReboot).flatMap((s) => s.checks), ...step.checks] : step.checks).map((c, i) => <li key={`${c.id}-${i}`}>{c.description}</li>)}</ul>}
      </div>
      {mode !== 'independent' && step.hints.length > 0 && (
        <div className="card">
          <div className="spread"><h3>Hints</h3><span className="muted small">{hints[step.id] ?? 0}/{step.hints.length}</span></div>
          {step.hints.slice(0, hints[step.id] ?? 0).map((h, i) => <div key={i} className="callout small"><strong>Hint {i + 1}.</strong> <Markdown text={h} /></div>)}
          {(hints[step.id] ?? 0) < step.hints.length && <button type="button" onClick={() => { setHints((x) => ({ ...x, [step.id]: (x[step.id] ?? 0) + 1 })); patchLab((p) => ({ ...p, hints: (p.hints ?? 0) + 1 })); }}>Show a hint</button>}
        </div>
      )}
      {mode !== 'independent' && (step.solution.length > 0 || step.gui) && (
        <div className="card">
          <div className="spread">
            <h3>Reference solution</h3>
            <button type="button" className="link" onClick={() => { if (!showSolution[step.id] && mode === 'assisted' && !confirm('Show the reference solution? Try first: the assisted mode is about working out the commands yourself.')) return; setShowSolution((x) => ({ ...x, [step.id]: !x[step.id] })); }}>{showSolution[step.id] ? 'Hide' : 'Show'}</button>
          </div>
          {showSolution[step.id] && (
            <>
              {step.solution.map((s, i) => (
                <div key={i}>
                  <div className="small muted">{s.user}@{s.host}{s.answers?.length ? ` (answers: ${s.answers.join(', ')})` : ''}</div>
                  <pre className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{s.commands.join('\n')}</pre>
                </div>
              ))}
              {step.gui && (
                <div>
                  <div className="small muted">In the webConfigurator</div>
                  <ol className="small">{step.gui.steps.map((g, i) => <li key={i}>{g}</li>)}</ol>
                </div>
              )}
              <button type="button" onClick={() => doItForMe(step)}>Do it for me</button>
              <p className="small muted">{step.gui ? 'Makes these changes on the lab machines' : 'Runs these commands on the lab machines'} and marks the step as assisted.</p>
            </>
          )}
        </div>
      )}
    </>
  );

  let left: JSX.Element;
  let right: JSX.Element | undefined;
  if (!integrated || stepsView) {
    left = leftSteps;
    right = rightSteps;
  } else if (stage === 'environment') {
    left = <EnvironmentPanel lab={lab} />;
    right = <><div className="card"><h3>Topology</h3><Topology /></div><ToolsCard lab={lab} /></>;
  } else if (stage === 'dependencies') {
    left = <DependencyPanel lab={lab} getWorld={getWorld} />;
    right = <ToolsCard lab={lab} />;
  } else if (stage === 'troubleshoot') {
    left = (
      <FaultPanel key={`fault-${labKey}`} lab={lab} mode={mode} saved={saved} ready={ready} getWorld={getWorld}
        onInject={() => { setWorld(injectFault(getWorld(), integrated.fault)); patchLab((p) => ({ ...p, fault: { injectedAt: Date.now(), commandsBefore: 0, restartsBefore: 0, hints: 0 } })); }}
        onDiagnose={(selected, correct) => {
          patchLab((p) => maybeFinish({ ...p, fault: { ...p.fault!, diagnosis: { selected, correct, attempts: (p.fault?.diagnosis?.attempts ?? 0) + 1 } } }));
          update((p) => recordConcepts(p, integrated.fault.concepts, correct && !saved?.fault?.diagnosis, Date.now()));
        }}
        onRepaired={() => patchLab((p) => maybeFinish({ ...p, fault: { ...p.fault!, repairedAt: p.fault?.repairedAt ?? Date.now() } }))}
        onHint={() => patchLab((p) => ({ ...p, hints: (p.hints ?? 0) + 1, fault: { ...p.fault!, hints: (p.fault?.hints ?? 0) + 1 } }))}
        onShowSolution={() => patchLab((p) => ({ ...p, fault: { ...p.fault!, hints: (p.fault?.hints ?? 0) + 3 } }))} />
    );
    right = saved?.fault ? <DependencyPanel lab={lab} getWorld={getWorld} showExplanation={false} /> : <ToolsCard lab={lab} />;
  } else {
    left = <ReviewPanel lab={lab} saved={saved} onAnswer={(qid, choice) => {
      const q = integrated.review.find((x) => x.id === qid)!;
      patchLab((p) => (p.review?.[qid] !== undefined ? p : maybeFinish({ ...p, review: { ...p.review, [qid]: choice } })));
      update((p) => recordConcepts(p, q.concepts, choice === q.answer, Date.now()));
    }} />;
    right = <FeedbackCard lab={lab} saved={saved} />;
  }

  return (
    <div className="page wide">
      {header}
      {integrated && (
        <div className="tabs" role="tablist" style={{ marginBottom: 6 }}>
          {STAGES.map((s) => (
            <button key={s.id} type="button" role="tab" aria-selected={stage === s.id} className={stage === s.id ? 'active' : ''}
              onClick={() => { setStage(s.id); if (s.id === 'verify' && verifySteps[0]) setStepIdx(lab.steps.indexOf(verifySteps[0])); if (s.id === 'configure' && step && step.stage === 'verify') setStepIdx(lab.steps.indexOf(configSteps.find((c) => !completed.has(c.id)) ?? configSteps[0])); }}>
              {s.label}{stageDone[s.id] ? ' ✓' : ''}
            </button>
          ))}
        </div>
      )}
      {finished && integrated && <div className="callout small">Lab completed in {MODE_INFO[mode].label.toLowerCase()} mode. {MODES.find((m) => !(saved?.modesCompleted ?? []).includes(m)) ? 'Try it again in a harder mode from the start page (Start over).' : 'Done in every mode.'} The review stage shows your feedback.</div>}
      <div className="ts-grid" style={{ marginTop: 10 }}>
        <div className="ts-col">{left}</div>
        <div className="ts-center">
          <LabTerminals key={labKey} getWorld={getWorld} setWorld={setWorld} height="100%" specs={lab.terminals} onCommand={onCommand} />
        </div>
        <div className="ts-col">
          {right}
          <NotesCard key={`notes-${id}`} initial={saved?.notes ?? ''} onSave={(text) => patchLab((p) => ({ ...p, notes: text }))} />
        </div>
      </div>
    </div>
  );
}

