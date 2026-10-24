// End-to-end case studies: list and detail pages (#/cases, #/cases/<id>).

import { CASE_STUDIES, getCase } from '../../content/cases';
import { getLesson } from '../../content/lessons';
import { ALL_SCENARIOS } from '../../engine/scenarios';
import { LayeredDiagramView } from '../components/Diagrams';
import { Inline, Markdown } from '../components/Markdown';
import { go, useProgress } from '../state';
import { RefBadge } from './Reference';

export function CaseStudyList() {
  const { progress } = useProgress();
  return (
    <div className="page">
      <h1>Case studies</h1>
      <p className="muted">
        Complete incidents, from the first symptom to a verified repair: the environment and its dependencies, every command run and what its output means,
        the root cause, the repair and why it works, what must be restarted, how to verify, and how to prevent it. Cases marked
        <span className="badge accent" style={{ margin: '0 4px' }}>interactive ticket</span> can be reproduced and solved in the simulator.
      </p>
      <div className="grid3">
        {CASE_STUDIES.map((c) => {
          const solved = c.scenarioId && progress.attempts.some((a) => a.scenarioId === c.scenarioId && a.status === 'resolved');
          return (
            <div className="card" key={c.id}>
              <div className="spread"><strong>{c.letter}. {c.title}</strong><span className="badge">{c.level}</span></div>
              <p className="small muted">{c.platforms.join(' · ')}</p>
              <div className="small"><Inline text={c.symptoms.split('\n')[0]} /></div>
              <div className="spread" style={{ marginTop: 8 }}>
                <span className="row" style={{ gap: 4 }}>{c.scenarioId && <span className="badge accent">interactive ticket</span>}{solved && <span className="badge ok">ticket resolved</span>}</span>
                <button className="primary" onClick={() => go(`cases/${c.id}`)}>Read</button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Prompt({ host }: { host?: string }) {
  return host ? <span style={{ color: 'var(--accent)' }}>{host}$ </span> : <span style={{ color: 'var(--accent)' }}>$ </span>;
}

export function CaseStudyPage({ id }: { id: string }) {
  const c = getCase(id);
  if (!c) return <div className="page"><h1>Unknown case study</h1><a href="#/cases">All case studies</a></div>;
  const scenario = c.scenarioId ? ALL_SCENARIOS.find((s) => s.id === c.scenarioId) : undefined;
  return (
    <div className="page">
      <div className="muted small"><a href="#/cases">Case studies</a> · {c.level} · {c.platforms.join(' · ')}</div>
      <h1>{c.letter}. {c.title}</h1>
      <div className="callout small"><strong>About the output.</strong> <Inline text={c.outputSource} /></div>
      {scenario && (
        <div className="callout ok small spread">
          <span>Reproduce this incident yourself: <strong>{scenario.title}</strong>. Read on after you have tried, or use this page as the walkthrough.</span>
          <button className="primary" onClick={() => go(`troubleshoot/${scenario.id}`)}>Open the ticket</button>
        </div>
      )}

      <h2>1. Symptoms</h2>
      <Markdown text={c.symptoms} />
      <h2>2. Environment</h2>
      <LayeredDiagramView d={c.environment} />
      <h2>3. Expected behaviour</h2>
      <Markdown text={c.expected} />
      <h2>4. Dependencies involved</h2>
      <ul>{c.dependencies.map((d, i) => <li key={i}><Inline text={d} /></li>)}</ul>

      <h2>5–6. Investigation: commands, output and interpretation</h2>
      {c.investigation.map((s, i) => (
        <div className="card" key={i} style={{ marginBottom: 10 }}>
          <strong>{i + 1}. {s.title}</strong>
          <pre style={{ marginTop: 6 }}><Prompt host={s.host} />{s.command}{'\n'}{s.output}</pre>
          <Inline text={s.interpretation} />
        </div>
      ))}

      <h2>7. Root cause</h2>
      <div className="callout warn"><Markdown text={c.rootCause} /></div>

      <h2>8–9. Repair, and why it works</h2>
      {c.repair.map((r, i) => (
        <div className="card" key={i} style={{ marginBottom: 10 }}>
          <strong>{r.title}</strong>
          <pre style={{ marginTop: 6 }}>{r.commands.split('\n').map((l, j) => <span key={j}>{l.startsWith('#') ? <span className="muted">{l}</span> : <><Prompt host={r.host} />{l}</>}{'\n'}</span>)}</pre>
          <Inline text={r.why} />
        </div>
      ))}

      <h2>10. What must be reloaded or restarted</h2>
      <Markdown text={c.restart} />

      <h2>11. Verification</h2>
      {c.verify.map((v, i) => (
        <div className="card" key={i} style={{ marginBottom: 10 }}>
          <pre><Prompt host={v.host} />{v.command}{'\n'}{v.output}</pre>
          <Inline text={v.meaning} />
        </div>
      ))}

      <h2>12. Prevention</h2>
      <ul>{c.prevention.map((p, i) => <li key={i}><Inline text={p} /></li>)}</ul>

      <h2>Related</h2>
      <div className="row" style={{ gap: 6 }}>
        {c.lessonIds.map((l) => <a key={l} className="badge" href={`#/lesson/${l}/troubleshoot`}>Lesson: {getLesson(l)?.title.split(':')[0] ?? l}</a>)}
        {(c.refIds ?? []).map((r) => <RefBadge key={r} id={r} />)}
      </div>
    </div>
  );
}
