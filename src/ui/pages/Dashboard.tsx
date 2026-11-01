import { CONCEPTS } from '../../content/concepts';
import { CURRICULUM } from '../../content/curriculum';
import { ASSESSMENTS, LESSONS } from '../../content/lessons';
import { GUIDED_LABS, INTEGRATED_LABS } from '../../engine/labs';
import { ALL_SCENARIOS } from '../../engine/scenarios';
import { CAUSES } from '../../engine/scenarios/catalog';
import type { ConceptId } from '../../engine/scenarios/types';
import type { Lesson } from '../../content/types';
import { mastery, type MasteryLevel, type Progress } from '../../learning/progress';
import { SECTIONS } from '../sections';
import { go, useProgress } from '../state';

function misconceptionText(m: string): string | null {
  const cause = /^cause:([^@]+)@/.exec(m);
  if (cause) return `Suspected "${CAUSES[cause[1]]?.title}" when the evidence pointed elsewhere`;
  if (m.startsWith('predict:')) return `Mispredicted the effect of switching off "${m.split(':')[1]}"`;
  if (m.startsWith('revealed:')) return `Needed the solution for "${ALL_SCENARIOS.find((s) => s.id === m.slice(9))?.title}"`;
  return null;
}

const pct = (n: number, d: number) => (d ? Math.round((n / d) * 100) : 0);

/** Lessons in learning-path order (module by module, as in the sidebar). */
const PATH: Lesson[] = CURRICULUM.flatMap((m) => LESSONS.filter((l) => l.moduleId === m.id));

function lessonState(p: Progress, L: Lesson) {
  const visited = p.lessons[L.id]?.visited ?? [];
  const next = SECTIONS.find((s) => !visited.includes(s.id));
  return { visited: visited.length, done: !next, next, link: `lesson/${L.id}/${next?.id ?? p.lessons[L.id]?.lastSection ?? 'what'}` };
}

function Stat({ label, value, total, tone, onClick }: { label: string; value: number; total: number; tone?: 'ok' | 'accent'; onClick: () => void }) {
  return (
    <button type="button" className="stat" onClick={onClick}>
      <span className="stat-value">{value}<span className="stat-total"> / {total}</span></span>
      <span className="stat-label">{label}</span>
      <span className={`meter ${tone ?? ''}`}><span style={{ width: `${pct(value, total)}%` }} /></span>
    </button>
  );
}

const LEVEL_ORDER: MasteryLevel[] = ['struggling', 'learning', 'proficient', 'not started'];
const LEVEL_BADGE: Record<MasteryLevel, string> = { struggling: 'err', learning: 'accent', proficient: 'ok', 'not started': '' };

export function Dashboard() {
  const { progress } = useProgress();
  const allQuestions = Object.values(ASSESSMENTS).flatMap((a) => a.questions);
  const resolved = new Set(progress.attempts.filter((a) => a.status === 'resolved').map((a) => a.scenarioId));
  const correctQ = allQuestions.filter((q) => progress.questions[q.id]?.correct).length;
  const concepts = Object.keys(CONCEPTS) as ConceptId[];
  const levels = new Map(concepts.map((c) => [c, mastery(progress.concepts[c])]));
  const struggling = concepts.filter((c) => levels.get(c)!.level === 'struggling');
  // Recommend prerequisite review when a concept is struggling and its prerequisite is not yet proficient.
  const prereqs = [...new Set(struggling.flatMap((c) => CONCEPTS[c].prerequisites).filter((p) => levels.get(p)?.level !== 'proficient'))];
  const recent = progress.attempts.slice(-5).reverse();

  const lessonsDone = PATH.filter((L) => lessonState(progress, L).done).length;
  const labsDone = GUIDED_LABS.filter((l) => progress.labs?.[l.id]?.finishedAt).length;
  const proficient = concepts.filter((c) => levels.get(c)!.level === 'proficient').length;

  // Work in progress: guided labs started and not finished (most recent first), and open tickets.
  const openLabs = GUIDED_LABS
    .map((l) => ({ l, p: progress.labs?.[l.id] }))
    .filter(({ p }) => p && !p.finishedAt && (p.completed.length > 0 || p.fault))
    .sort((a, b) => b.p!.startedAt - a.p!.startedAt);
  const openTickets = [...new Map(progress.attempts.filter((a) => a.status === 'in-progress' && !resolved.has(a.scenarioId)).map((a) => [a.scenarioId, a])).values()].reverse().slice(0, 3);
  const nextLesson = PATH.find((L) => { const s = lessonState(progress, L); return s.visited > 0 && !s.done; }) ?? PATH.find((L) => !lessonState(progress, L).done);
  const nextTicket = ALL_SCENARIOS.find((s) => !resolved.has(s.id));
  const nextIntegrated = INTEGRATED_LABS.find((l) => !progress.labs?.[l.id]?.finishedAt && !openLabs.some((o) => o.l.id === l.id));
  const fresh = lessonsDone === 0 && PATH.every((L) => lessonState(progress, L).visited === 0) && progress.attempts.length === 0;

  const conceptRows = [...concepts].sort((a, b) => LEVEL_ORDER.indexOf(levels.get(a)!.level) - LEVEL_ORDER.indexOf(levels.get(b)!.level) || CONCEPTS[a].title.localeCompare(CONCEPTS[b].title));
  const levelCount = (lv: MasteryLevel) => concepts.filter((c) => levels.get(c)!.level === lv).length;

  return (
    <div className="page dashboard">
      <header className="dash-hero">
        <div>
          <h1>Cyber Owl Lab</h1>
          <p className="muted">Learn how infrastructure services work internally, and practise diagnosing them from evidence. Everything runs locally and offline.</p>
        </div>
        {nextLesson && (
          <div className="dash-next card">
            <div className="small muted">{fresh ? 'Start here' : 'Pick up where you left off'}</div>
            <h3>{nextLesson.title}</h3>
            {(() => {
              const s = lessonState(progress, nextLesson);
              return (
                <>
                  <span className="meter"><span style={{ width: `${pct(s.visited, SECTIONS.length)}%` }} /></span>
                  <p className="small muted">{s.visited} of {SECTIONS.length} sections{s.next ? ` · next: ${s.next.title}` : ''}</p>
                  <button type="button" className="primary" onClick={() => go(s.link)}>{s.visited ? 'Continue the lesson' : 'Start the lesson'}</button>
                </>
              );
            })()}
          </div>
        )}
      </header>

      <div className="stat-row">
        <Stat label="Lessons completed" value={lessonsDone} total={PATH.length} onClick={() => go('curriculum')} />
        <Stat label="Guided labs finished" value={labsDone} total={GUIDED_LABS.length} tone="ok" onClick={() => go('labs')} />
        <Stat label="Tickets solved without revealing" value={resolved.size} total={ALL_SCENARIOS.length} tone="ok" onClick={() => go('troubleshoot')} />
        <Stat label="Assessment questions right" value={correctQ} total={allQuestions.length} onClick={() => go(nextLesson ? `lesson/${nextLesson.id}/assess` : 'curriculum')} />
        <Stat label="Concepts proficient" value={proficient} total={concepts.length} tone="accent" onClick={() => document.getElementById('dash-concepts')?.scrollIntoView({ behavior: 'smooth' })} />
      </div>

      {(struggling.length > 0 || prereqs.length > 0) && (
        <div className="callout warn" style={{ marginTop: 14 }}>
          <strong>Recommended review.</strong> Your answers show repeated difficulty with{' '}
          {struggling.map((c, i) => <span key={c}>{i > 0 ? ', ' : ''}<button className="link" onClick={() => go(CONCEPTS[c].review)}>{CONCEPTS[c].title}</button></span>)}.
          {prereqs.length > 0 && <> These build on {prereqs.map((c, i) => <span key={c}>{i > 0 ? ', ' : ''}<button className="link" onClick={() => go(CONCEPTS[c].review)}>{CONCEPTS[c].title}</button></span>)}: review that first.</>}
        </div>
      )}

      <div className="grid2" style={{ marginTop: 14 }}>
        <section className="card">
          <h3>In progress</h3>
          {openLabs.length === 0 && openTickets.length === 0 && <p className="small muted">Nothing open. Labs and tickets you start appear here so you can return to them.</p>}
          {openLabs.map(({ l, p }) => (
            <div key={l.id} className="dash-item">
              <div>
                <a href={`#/labs/${l.id}`}>{l.title}</a>
                <div className="small muted">
                  {p!.completed.length}/{l.steps.length} steps{p!.fault ? (p!.fault.repairedAt ? ' · incident repaired' : ' · incident open') : ''}{l.integrated && p!.mode ? ` · ${p!.mode} mode` : ''}
                </div>
              </div>
              <span className="meter ok" style={{ width: 90 }}><span style={{ width: `${pct(p!.completed.length, l.steps.length)}%` }} /></span>
            </div>
          ))}
          {openTickets.map((a) => {
            const s = ALL_SCENARIOS.find((x) => x.id === a.scenarioId);
            return s ? (
              <div key={a.id} className="dash-item">
                <div>
                  <a href={`#/troubleshoot/${s.id}`}>{s.title}</a>
                  <div className="small muted">Ticket · {a.commands.length} commands · {a.diagnoses.length} diagnoses · {a.hintsUsed} hints</div>
                </div>
                <span className="badge">open</span>
              </div>
            ) : null;
          })}
        </section>
        <section className="card">
          <h3>Practice next</h3>
          {nextIntegrated && (
            <div className="dash-item">
              <div><a href={`#/labs/${nextIntegrated.id}`}>{nextIntegrated.title}</a><div className="small muted">Integrated lab · {nextIntegrated.integrated!.technologies.slice(0, 4).join(', ')}</div></div>
              <button type="button" onClick={() => go(`labs/${nextIntegrated.id}`)}>Open</button>
            </div>
          )}
          {nextTicket && (
            <div className="dash-item">
              <div><a href={`#/troubleshoot/${nextTicket.id}`}>{nextTicket.title}</a><div className="small muted">Troubleshooting ticket</div></div>
              <button type="button" onClick={() => go(`troubleshoot/${nextTicket.id}`)}>Open</button>
            </div>
          )}
          <div className="dash-item">
            <div><a href="#/cases">Case studies</a><div className="small muted">Unguided investigations of real-world failures</div></div>
            <button type="button" onClick={() => go('cases')}>Open</button>
          </div>
        </section>
      </div>

      <h2>Learning path</h2>
      <p className="small muted">Modules in the order they build on each other. A lesson counts as completed when every section has been opened.</p>
      <div className="grid2">
        {CURRICULUM.map((m) => {
          const ls = LESSONS.filter((l) => l.moduleId === m.id);
          if (!ls.length) return null;
          const states = ls.map((L) => ({ L, s: lessonState(progress, L) }));
          const visited = states.reduce((n, x) => n + x.s.visited, 0);
          const done = states.filter((x) => x.s.done).length;
          return (
            <section key={m.id} className="card">
              <div className="spread">
                <h3 style={{ margin: 0 }}><span className="muted">{m.id}</span> {m.title}</h3>
                <span className={`badge ${done === ls.length ? 'ok' : done ? 'accent' : ''}`}>{done}/{ls.length}</span>
              </div>
              <span className="meter" style={{ margin: '8px 0' }}><span style={{ width: `${pct(visited, ls.length * SECTIONS.length)}%` }} /></span>
              <ul className="dash-lessons">
                {states.map(({ L, s }) => (
                  <li key={L.id}>
                    <button type="button" className="link" onClick={() => go(s.link)} title={s.next ? `Next: ${s.next.title}` : 'All sections opened'}>
                      <span className={`dot ${s.done ? 'ok' : s.visited ? 'accent' : ''}`} aria-hidden="true" />
                      {L.title.split(':')[0]}
                    </button>
                    <span className="small muted">{s.done ? 'done' : s.visited ? `${s.visited}/${SECTIONS.length}` : ''}</span>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>

      <h2 id="dash-concepts">Understanding by concept</h2>
      <p className="small muted">
        Updated by assessment answers, dependency predictions, troubleshooting diagnoses and lab work: not by page views.{' '}
        {LEVEL_ORDER.map((lv) => <span key={lv} className={`badge ${LEVEL_BADGE[lv]}`} style={{ marginRight: 4 }}>{levelCount(lv)} {lv}</span>)}
      </p>
      <details className="card" open={concepts.some((c) => levels.get(c)!.level !== 'not started')}>
        <summary className="small">All {concepts.length} concepts, those needing attention first</summary>
        <table style={{ marginTop: 8 }}>
          <thead><tr><th>Concept</th><th style={{ width: 160 }}>Mastery</th><th>Status</th><th>Observed misconceptions</th></tr></thead>
          <tbody>
            {conceptRows.map((c) => {
              const s = progress.concepts[c];
              const m = levels.get(c)!;
              const mis = (s?.misconceptions ?? []).map(misconceptionText).filter(Boolean).slice(-2);
              return (
                <tr key={c}>
                  <td><button className="link" onClick={() => go(CONCEPTS[c].review)}>{CONCEPTS[c].title}</button><div className="small muted">{CONCEPTS[c].description}</div></td>
                  <td>
                    <span className={`meter ${m.level === 'struggling' ? 'err' : m.level === 'proficient' ? 'ok' : ''}`}><span style={{ width: `${Math.round(m.score * 100)}%` }} /></span>
                    <div className="small muted">{s ? `${s.correct} right · ${s.incorrect} wrong` : ''}</div>
                  </td>
                  <td><span className={`badge ${LEVEL_BADGE[m.level]}`}>{m.level}</span></td>
                  <td className="small">{mis.length ? mis.map((x, i) => <div key={i}>{x}</div>) : <span className="muted">—</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </details>

      <h2>Recent troubleshooting</h2>
      {recent.length === 0 ? <p className="muted small">No attempts yet. <button type="button" className="link" onClick={() => go('troubleshoot')}>Open the troubleshooting lab</button>.</p> : (
        <table>
          <thead><tr><th>Ticket</th><th>Status</th><th>Hints</th><th>Diagnoses</th><th>Commands</th><th /></tr></thead>
          <tbody>
            {recent.map((a) => (
              <tr key={a.id}>
                <td>{ALL_SCENARIOS.find((s) => s.id === a.scenarioId)?.title}</td>
                <td><span className={`badge ${a.status === 'resolved' ? 'ok' : a.status === 'revealed' ? 'warn' : ''}`}>{a.status}</span></td>
                <td>{a.hintsUsed}</td>
                <td>{a.diagnoses.length}</td>
                <td>{a.commands.length}</td>
                <td><button className="link" onClick={() => go(`history/${a.id}`)}>details</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
