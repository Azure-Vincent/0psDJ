import { useMemo, useState } from 'react';
import type { Assessment as AssessmentT, LearnRoute, Question } from '../../content/types';
import { gradeQuestion, stableShuffle, type GradeResult } from '../../learning/grading';
import { recordConcepts } from '../../learning/progress';
import { useProgress } from '../state';
import { getLesson } from '../../content/lessons';
import { SECTIONS } from '../sections';
import { Markdown } from './Markdown';

/**
 * Unsubmitted answers by question id. "Where this is taught" sends the learner to another tab,
 * which unmounts the questions; this keeps their work for when they come back (until the app reloads).
 */
const drafts = new Map<string, unknown>();

/** "Where this is taught": links to the lesson sections that explain how to work out the answer. */
function LearnLinks({ routes, lessonId }: { routes: LearnRoute[]; lessonId?: string }) {
  return (
    <div className="small muted" style={{ margin: '4px 0 6px' }}>
      Where this is taught:{' '}
      {routes.map((r, i) => {
        const [, id, sec] = r.split('/');
        const s = SECTIONS.find((x) => x.id === sec);
        const label = s?.short ?? s?.title ?? sec;
        const title = id === lessonId ? label : `${getLesson(id)?.title ?? id} › ${label}`;
        return <span key={r}>{i > 0 && ' · '}<a href={`#/${r}`}>{title}</a></span>;
      })}
    </div>
  );
}

function QuestionView({ q, index, lessonId }: { q: Question; index: number; lessonId?: string }) {
  const { progress, update } = useProgress();
  const initial = useMemo(() => {
    // Order questions track positions in q.items, not the text: items may repeat ("ACK (client)").
    if (q.kind === 'order') return stableShuffle(q.items.map((_, i) => i), q.id);
    if (q.kind === 'multi') return [] as number[];
    if (q.kind === 'single') return -1;
    return '';
  }, [q]);
  const [answer, setAnswerState] = useState<unknown>(() => (drafts.has(q.id) ? drafts.get(q.id) : initial));
  const setAnswer = (a: unknown) => { drafts.set(q.id, a); setAnswerState(a); };
  const [result, setResult] = useState<GradeResult | null>(null);
  const prior = progress.questions[q.id];

  const submit = () => {
    const r = gradeQuestion(q, q.kind === 'order' ? (answer as number[]).map((i) => q.items[i]) : answer);
    setResult(r);
    const misconception = q.kind === 'single' && !r.correct ? `${q.id}#${answer}` : undefined;
    update((p) => {
      const prev = p.questions[q.id];
      const next = recordConcepts(p, q.concepts, r.correct, Date.now(), misconception);
      return {
        ...next,
        questions: { ...next.questions, [q.id]: { attempts: (prev?.attempts ?? 0) + 1, correct: r.correct || !!prev?.correct, firstTryCorrect: prev ? prev.firstTryCorrect : r.correct } },
      };
    });
  };

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <div className="spread">
        <strong>Question {index + 1}</strong>
        <span className="row">
          <span className="badge">{q.level}</span>
          <span className="badge">{{ single: 'single choice', multi: 'select all that apply', order: 'put in order', text: 'type the answer', 'nft-rule': 'write a firewall rule', 'sshd-config': 'write a configuration' }[q.kind]}</span>
          {prior?.correct && <span className="badge ok">answered correctly{prior.firstTryCorrect ? ' first try' : ''}</span>}
        </span>
      </div>
      <Markdown text={q.prompt} />
      {q.exhibit && <pre>{q.exhibit}</pre>}
      {q.learn && q.learn.length > 0 && <LearnLinks routes={q.learn} lessonId={lessonId} />}

      {q.kind === 'single' && q.options.map((o, i) => (
        <label key={i} className="row" style={{ alignItems: 'flex-start', margin: '4px 0' }}>
          <input type="radio" name={q.id} checked={answer === i} onChange={() => { setAnswer(i); setResult(null); }} />
          <span>{o.text}</span>
        </label>
      ))}
      {q.kind === 'multi' && q.options.map((o, i) => {
        const sel = answer as number[];
        return (
          <label key={i} className="row" style={{ alignItems: 'flex-start', margin: '4px 0' }}>
            <input type="checkbox" checked={sel.includes(i)} onChange={() => { setAnswer(sel.includes(i) ? sel.filter((x) => x !== i) : [...sel, i]); setResult(null); }} />
            <span>{o.text}</span>
          </label>
        );
      })}
      {q.kind === 'order' && (
        <ol style={{ paddingLeft: 22 }}>
          {(answer as number[]).map((item, i, arr) => (
            <li key={item} style={{ margin: '3px 0' }}>
              <span className="row" style={{ flexWrap: 'nowrap' }}>
                <button aria-label="move up" disabled={i === 0} onClick={() => { const a = arr.slice(); [a[i - 1], a[i]] = [a[i], a[i - 1]]; setAnswer(a); setResult(null); }}>↑</button>
                <button aria-label="move down" disabled={i === arr.length - 1} onClick={() => { const a = arr.slice(); [a[i + 1], a[i]] = [a[i], a[i + 1]]; setAnswer(a); setResult(null); }}>↓</button>
                <span>{q.items[item]}</span>
              </span>
            </li>
          ))}
        </ol>
      )}
      {q.kind === 'text' && (
        <input className="mono" style={{ width: '100%' }} placeholder={q.placeholder} value={answer as string} onChange={(e) => { setAnswer(e.target.value); setResult(null); }} onKeyDown={(e) => e.key === 'Enter' && submit()} />
      )}
      {q.kind === 'nft-rule' && (
        <>
          <div className="small muted">Existing chain (policy drop):</div>
          <pre>{q.context.join('\n')}{'\n'}<span className="muted"># your rule:</span></pre>
          <input className="mono" style={{ width: '100%' }} placeholder="e.g. ip saddr 10.0.10.0/24 tcp dport 22 accept" value={answer as string} onChange={(e) => { setAnswer(e.target.value); setResult(null); }} />
          <div className="small muted">Graded by loading your rule into the simulator's nftables engine and evaluating {q.tests.length} test packets.</div>
        </>
      )}
      {q.kind === 'sshd-config' && (
        <>
          <textarea rows={7} placeholder="Keyword value" value={answer as string} onChange={(e) => { setAnswer(e.target.value); setResult(null); }} />
          <div className="small muted">Graded by parsing your text with the simulator's sshd_config parser and checking the effective configuration (like sshd -T -C ...).</div>
        </>
      )}

      <div className="row" style={{ marginTop: 8 }}>
        <button className="primary" onClick={submit}>Check answer</button>
        {result && !result.correct && <button onClick={() => { setResult(null); setAnswer(initial); }}>Reset</button>}
      </div>
      {result && (
        <div style={{ marginTop: 8 }}>
          <div className={`feedback ${result.correct ? 'ok' : 'bad'}`}>{result.correct ? '✓ Correct' : '✗ Not yet'}</div>
          {result.feedback.map((f, i) => <div key={i} className="small" style={{ color: f.ok ? 'var(--ok)' : 'var(--err)', fontFamily: q.kind === 'order' || q.kind.includes('-') ? 'var(--mono)' : undefined }}>{f.text}</div>)}
          {(result.correct || (prior?.attempts ?? 0) >= 2) && (
            <div className="callout ok" style={{ marginTop: 8 }}>
              <strong>Explanation. </strong>
              {q.explanation.split('\n').length > 1 ? <pre style={{ background: 'transparent', padding: 0 }}>{q.explanation}</pre> : q.explanation}
            </div>
          )}
          {!result.correct && (prior?.attempts ?? 0) < 2 && <div className="small muted">The full explanation appears once you answer correctly or after a second attempt.</div>}
        </div>
      )}
    </div>
  );
}

export function AssessmentView({ assessment, lessonId }: { assessment: AssessmentT; lessonId?: string }) {
  const { progress } = useProgress();
  const done = assessment.questions.filter((q) => progress.questions[q.id]?.correct).length;
  return (
    <div>
      <div className="spread" style={{ marginBottom: 10 }}>
        <div className="muted">Conceptual, design and troubleshooting questions. Practical answers are graded by the simulator itself. Each question links to the lesson sections that teach how to work it out.</div>
        <span className="badge accent">{done} / {assessment.questions.length} correct</span>
      </div>
      {assessment.questions.map((q, i) => <QuestionView key={q.id} q={q} index={i} lessonId={lessonId} />)}
    </div>
  );
}
