// "Start here": how the lab works, and the study roadmap with the learner's
// position on it. Each phase explains why it comes where it does; each step
// opens where the learner stopped.

import { ROADMAP, ROADMAP_STEPS } from '../../content/roadmap';
import { roadmapCounts, currentStepIndex, viewStep, type StepStatus } from '../roadmapProgress';
import { go, useProgress } from '../state';

const HOW = [
  { title: 'Lessons', text: 'Each lesson has eight sections, from "What is it?" to an assessment. Read them in order: the overview and "How it works" explain the idea, the later sections show how to deploy, configure, operate and troubleshoot it. A lesson counts as completed when every section has been opened.' },
  { title: 'Terminals', text: 'Lessons, tickets and labs give you terminals on a simulated company network (corp.lab). Type real Linux, PowerShell and pfSense commands: the machines react like real ones, but nothing leaves your computer.' },
  { title: 'Troubleshooting tickets', text: 'Each lesson links to tickets: something is broken, and you find out why from evidence, submit a diagnosis, fix it and verify. Hints are available, but a ticket solved without revealing the answer counts most.' },
  { title: 'Guided and integrated labs', text: 'Guided labs build one service step by step, each step checked against the running machines. Integrated labs combine several subjects, end with an incident to troubleshoot, and can be done guided, assisted or independently.' },
];

const MARK: Record<StepStatus, string> = { done: '✓', started: '◐', todo: '' };

export function StartHere() {
  const { progress } = useProgress();
  const cur = currentStepIndex(progress);
  const { done, total } = roadmapCounts(progress);
  const current = ROADMAP_STEPS[cur];
  const cv = viewStep(progress, current.step);
  const fresh = done === 0 && cv.status === 'todo';
  const phaseNo = (id: string) => ROADMAP.findIndex((p) => p.id === id) + 1;

  return (
    <div className="page roadmap">
      <header className="dash-hero">
        <div>
          <h1>Start here</h1>
          <p>
            Cyber Owl Lab teaches how infrastructure services work and how to fix them when they break. You learn a subject in a lesson, practise it on
            simulated machines, then combine subjects in labs that end with a real-looking incident.
          </p>
          <p className="muted small">The roadmap below gives an order that never assumes something you have not learned yet. You can open any lesson at any time; the roadmap is the recommended path, not a lock.</p>
        </div>
        <div className="dash-next card">
          <div className="small muted">{fresh ? 'Your first step' : 'Continue the roadmap'} · Phase {phaseNo(current.phase.id)}: {current.phase.title}</div>
          <h3>{cv.title}</h3>
          {cv.fraction !== undefined && <span className="meter"><span style={{ width: `${Math.round(cv.fraction * 100)}%` }} /></span>}
          <p className="small muted">{cv.kindLabel} · {cv.detail}</p>
          <button type="button" className="primary" onClick={() => go(cv.link)}>{fresh ? 'Begin with this lesson' : cv.status === 'started' ? 'Continue' : 'Start'} →</button>
          <p className="small muted" style={{ marginTop: 10 }}>Roadmap: {done} of {total} steps done</p>
          <span className="meter ok"><span style={{ width: `${Math.round((done / total) * 100)}%` }} /></span>
        </div>
      </header>

      <h2>How the lab works</h2>
      <div className="grid2 how">
        {HOW.map((h) => (
          <div key={h.title} className="card">
            <h3>{h.title}</h3>
            <p className="small">{h.text}</p>
          </div>
        ))}
      </div>

      <h2>The roadmap</h2>
      <ol className="phase-strip" aria-label="Roadmap phases">
        {ROADMAP.map((ph, i) => {
          const tracked = ph.steps.filter((s) => s.kind !== 'practice');
          const d = tracked.filter((s) => viewStep(progress, s).status === 'done').length;
          const state = d === tracked.length ? 'done' : ph.id === current.phase.id ? 'current' : '';
          return (
            <li key={ph.id} className={state}>
              <a href={`#/start`} onClick={(e) => { e.preventDefault(); document.getElementById(`phase-${ph.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }}>
                <span className="phase-no">{i + 1}</span>
                <span className="phase-name">{ph.title}</span>
                <span className="phase-count">{d}/{tracked.length}</span>
              </a>
            </li>
          );
        })}
      </ol>

      {ROADMAP.map((ph, i) => {
        const tracked = ph.steps.filter((s) => s.kind !== 'practice');
        const d = tracked.filter((s) => viewStep(progress, s).status === 'done').length;
        const complete = d === tracked.length;
        return (
          <details key={ph.id} id={`phase-${ph.id}`} className={`card phase ${ph.id === current.phase.id ? 'current' : ''}`} open={!complete || ph.id === current.phase.id}>
            <summary>
              <span className="phase-no">{i + 1}</span>
              <span className="phase-title">{ph.title}</span>
              <span className={`badge ${complete ? 'ok' : d ? 'accent' : ''}`}>{complete ? 'done' : `${d}/${tracked.length}`}</span>
            </summary>
            <p className="small"><strong>Goal.</strong> {ph.goal}</p>
            <p className="small muted"><strong>Why here.</strong> {ph.why}</p>
            <ol className="road-steps">
              {ph.steps.map((s) => {
                const idx = ROADMAP_STEPS.findIndex((x) => x.step === s);
                const v = viewStep(progress, s);
                const isCurrent = idx === cur;
                return (
                  <li key={idx} className={`${v.status}${isCurrent ? ' current' : ''}`}>
                    <span className="road-mark" aria-label={v.status}>{MARK[v.status] || idx + 1}</span>
                    <div className="road-body">
                      <div><span className="badge">{v.kindLabel}</span> <a href={`#/${v.link}`}>{v.title}</a></div>
                      <div className="small muted">{s.why}</div>
                      {v.fraction !== undefined && v.status !== 'todo' && <div className="small muted">{v.detail}</div>}
                    </div>
                    <button type="button" className={isCurrent ? 'primary' : ''} onClick={() => go(v.link)}>{v.status === 'done' ? 'Review' : v.status === 'started' ? 'Continue' : s.kind === 'practice' ? 'Open' : 'Start'}</button>
                  </li>
                );
              })}
            </ol>
          </details>
        );
      })}
      <p className="small muted">Every lab on the roadmap comes after the lessons it relies on. The <a href="#/curriculum">curriculum</a> shows the same subjects grouped by module.</p>
    </div>
  );
}
