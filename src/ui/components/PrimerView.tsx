import { useState } from 'react';
import type { Primer } from '../../content/types';
import { Inline, Markdown } from './Markdown';

// The beginner's layer of a lesson: the short version first, one idea at a
// time with a concrete example, then a case followed step by step. The
// in-depth text of the lesson follows these blocks.

/** "What is it?": the short version, an analogy, the key ideas with examples, and common misconceptions. */
export function PrimerIntro({ p }: { p: Primer }) {
  return (
    <div className="primer">
      <div className="callout primer-oneliner"><strong>In short.</strong> <Inline text={p.oneLiner} /></div>
      <div className="card primer-analogy">
        <h3>Think of it like this</h3>
        <Markdown text={p.analogy} />
      </div>
      <h2>Key ideas</h2>
      <ol className="primer-ideas">
        {p.ideas.map((idea, i) => (
          <li key={i} className="card">
            <h3><span className="primer-num">{i + 1}</span>{idea.title}</h3>
            <Markdown text={idea.explain} />
            <div className="primer-example">
              <div className="primer-label">Example</div>
              <Markdown text={idea.example} />
            </div>
          </li>
        ))}
      </ol>
      <h2>Common misconceptions</h2>
      <div className="primer-myths">
        {p.misconceptions.map((m, i) => (
          <div key={i} className="card">
            <div className="primer-myth"><span className="badge err">Myth</span> <Inline text={m.myth} /></div>
            <div className="primer-truth"><span className="badge ok">Actually</span><Markdown text={m.truth} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}

/** "How it works": one concrete case followed step by step. */
export function PrimerWalkthrough({ p }: { p: Primer }) {
  const w = p.walkthrough;
  return (
    <div className="primer">
      <h2>Step by step: {w.title}</h2>
      {w.intro && <Markdown text={w.intro} />}
      <ol className="primer-steps">
        {w.steps.map((s, i) => (
          <li key={i}>
            <div className="primer-step-head"><span className="primer-num">{i + 1}</span><strong>{s.label}</strong></div>
            <Markdown text={s.detail} />
            {s.show && <pre className="primer-show">{s.show}</pre>}
          </li>
        ))}
      </ol>
    </div>
  );
}

/** Quick self-check: questions with answers revealed on request. */
export function PrimerChecks({ p }: { p: Primer }) {
  const [open, setOpen] = useState<Record<number, boolean>>({});
  return (
    <div className="primer">
      <h2>Check yourself</h2>
      <p className="small muted">Answer in your head first, then reveal. These are not graded; the Assessment tab is.</p>
      {p.checks.map((c, i) => (
        <div key={i} className="card primer-check">
          <div><strong>Q{i + 1}.</strong> <Inline text={c.q} /></div>
          {open[i]
            ? <div className="primer-answer"><Markdown text={c.a} /></div>
            : <button className="small" onClick={() => setOpen((o) => ({ ...o, [i]: true }))}>Show answer</button>}
        </div>
      ))}
    </div>
  );
}
