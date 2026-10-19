import { CONCEPTS } from '../../content/concepts';
import { SSH_ASSESSMENT } from '../../content/ssh/assessment';
import { SSH_SCENARIOS } from '../../engine/scenarios/sshScenarios';
import type { ConceptId } from '../../engine/scenarios/types';
import { CAUSES } from '../../engine/scenarios/catalog';
import { mastery } from '../../learning/progress';
import { SECTIONS } from './LessonPage';
import { go, useProgress } from '../state';

function misconceptionText(m: string): string | null {
  const cause = /^cause:([^@]+)@/.exec(m);
  if (cause) return `Suspected "${CAUSES[cause[1]]?.title}" when the evidence pointed elsewhere`;
  if (m.startsWith('predict:')) return `Mispredicted the effect of switching off "${m.split(':')[1]}"`;
  if (m.startsWith('revealed:')) return `Needed the solution for "${SSH_SCENARIOS.find((s) => s.id === m.slice(9))?.title}"`;
  return null;
}

export function Dashboard() {
  const { progress } = useProgress();
  const visited = progress.lessons.ssh?.visited ?? [];
  const resolved = new Set(progress.attempts.filter((a) => a.status === 'resolved').map((a) => a.scenarioId));
  const correctQ = SSH_ASSESSMENT.questions.filter((q) => progress.questions[q.id]?.correct).length;
  const concepts = Object.keys(CONCEPTS) as ConceptId[];
  const struggling = concepts.filter((c) => mastery(progress.concepts[c]).level === 'struggling');
  // Recommend prerequisite review when a concept is struggling and its prerequisite is not yet proficient.
  const prereqs = [...new Set(struggling.flatMap((c) => CONCEPTS[c].prerequisites).filter((p) => mastery(progress.concepts[p]).level !== 'proficient'))];
  const nextSection = SECTIONS.find((s) => !visited.includes(s.id));
  const nextScenario = SSH_SCENARIOS.find((s) => !resolved.has(s.id));
  const recent = progress.attempts.slice(-5).reverse();

  return (
    <div className="page">
      <h1>Infrastructure Lab</h1>
      <p className="muted">Learn how infrastructure services work internally, and practise diagnosing them from evidence. Everything runs locally and offline.</p>
      <div className="grid3" style={{ marginTop: 12 }}>
        <div className="card">
          <h3>SSH lesson</h3>
          <div className="meter"><div style={{ width: `${(visited.length / SECTIONS.length) * 100}%` }} /></div>
          <p className="small muted">{visited.length} of {SECTIONS.length} sections visited</p>
          <button className="primary" onClick={() => go(`lesson/ssh/${nextSection?.id ?? progress.lessons.ssh?.lastSection ?? 'what'}`)}>{visited.length ? 'Continue' : 'Start'}{nextSection ? `: ${nextSection.title}` : ''}</button>
        </div>
        <div className="card">
          <h3>Troubleshooting</h3>
          <div className="meter ok"><div style={{ width: `${(resolved.size / SSH_SCENARIOS.length) * 100}%` }} /></div>
          <p className="small muted">{resolved.size} of {SSH_SCENARIOS.length} tickets resolved without revealing</p>
          {nextScenario && <button onClick={() => go(`troubleshoot/${nextScenario.id}`)}>Next ticket: {nextScenario.title}</button>}
        </div>
        <div className="card">
          <h3>Assessment</h3>
          <div className="meter"><div style={{ width: `${(correctQ / SSH_ASSESSMENT.questions.length) * 100}%` }} /></div>
          <p className="small muted">{correctQ} of {SSH_ASSESSMENT.questions.length} questions answered correctly</p>
          <button onClick={() => go('lesson/ssh/assess')}>Open assessment</button>
        </div>
      </div>

      {(struggling.length > 0 || prereqs.length > 0) && (
        <div className="callout warn" style={{ marginTop: 14 }}>
          <strong>Recommended review.</strong> Your answers show repeated difficulty with{' '}
          {struggling.map((c, i) => <span key={c}>{i > 0 ? ', ' : ''}<button className="link" onClick={() => go(CONCEPTS[c].review)}>{CONCEPTS[c].title}</button></span>)}.
          {prereqs.length > 0 && <> These build on {prereqs.map((c, i) => <span key={c}>{i > 0 ? ', ' : ''}<button className="link" onClick={() => go(CONCEPTS[c].review)}>{CONCEPTS[c].title}</button></span>)}: review that first.</>}
        </div>
      )}

      <h2>Understanding by concept</h2>
      <p className="small muted">Updated by assessment answers, dependency predictions and troubleshooting diagnoses: not by page views.</p>
      <table>
        <thead><tr><th>Concept</th><th style={{ width: 160 }}>Mastery</th><th>Status</th><th>Observed misconceptions</th></tr></thead>
        <tbody>
          {concepts.map((c) => {
            const s = progress.concepts[c];
            const m = mastery(s);
            const mis = (s?.misconceptions ?? []).map(misconceptionText).filter(Boolean).slice(-2);
            return (
              <tr key={c}>
                <td><button className="link" onClick={() => go(CONCEPTS[c].review)}>{CONCEPTS[c].title}</button><div className="small muted">{CONCEPTS[c].description}</div></td>
                <td>
                  <div className={`meter ${m.level === 'struggling' ? 'err' : m.level === 'proficient' ? 'ok' : ''}`}><div style={{ width: `${Math.round(m.score * 100)}%` }} /></div>
                  <div className="small muted">{s ? `${s.correct} right · ${s.incorrect} wrong` : ''}</div>
                </td>
                <td><span className={`badge ${m.level === 'proficient' ? 'ok' : m.level === 'struggling' ? 'err' : m.level === 'learning' ? 'accent' : ''}`}>{m.level}</span></td>
                <td className="small">{mis.length ? mis.map((x, i) => <div key={i}>{x}</div>) : <span className="muted">—</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h2>Recent troubleshooting</h2>
      {recent.length === 0 ? <p className="muted">No attempts yet.</p> : (
        <table>
          <thead><tr><th>Ticket</th><th>Status</th><th>Hints</th><th>Diagnoses</th><th>Commands</th><th /></tr></thead>
          <tbody>
            {recent.map((a) => (
              <tr key={a.id}>
                <td>{SSH_SCENARIOS.find((s) => s.id === a.scenarioId)?.title}</td>
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
