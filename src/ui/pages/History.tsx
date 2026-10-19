import { ALL_SCENARIOS } from '../../engine/scenarios';
import { CAUSES } from '../../engine/scenarios/catalog';
import { go, useProgress } from '../state';

const fmt = (t: number) => new Date(t).toLocaleString();

export function History({ id }: { id?: string }) {
  const { progress } = useProgress();
  const attempts = progress.attempts.slice().reverse();
  const a = id ? progress.attempts.find((x) => x.id === id) : undefined;
  if (a) {
    const s = ALL_SCENARIOS.find((x) => x.id === a.scenarioId);
    return (
      <div className="page">
        <button className="link" onClick={() => go('history')}>← All attempts</button>
        <h1>{s?.title} <span className={`badge ${a.status === 'resolved' ? 'ok' : a.status === 'revealed' ? 'warn' : ''}`}>{a.status}</span></h1>
        <p className="muted">Started {fmt(a.startedAt)}{a.endedAt ? ` · ended ${fmt(a.endedAt)}` : ''} · hints used: {a.hintsUsed}</p>
        <div className="grid2">
          <div className="card"><h3>Notes</h3><p><strong>Symptoms:</strong> {a.notes.symptoms || '—'}</p><p><strong>Evidence:</strong> {a.notes.evidence || '—'}</p></div>
          <div className="card">
            <h3>Diagnoses</h3>
            {a.diagnoses.length === 0 && <p className="muted">none</p>}
            {a.diagnoses.map((d, i) => <div key={i} className={`feedback ${d.correct ? 'ok' : 'bad'}`}>{fmt(d.time)}: {d.selected.map((c) => CAUSES[c]?.title).join('; ')}</div>)}
            <h3>Verifications</h3>
            {a.verifications.length === 0 && <p className="muted">none</p>}
            {a.verifications.map((v, i) => <div key={i} className={`feedback ${v.passed ? 'ok' : 'bad'}`}>{fmt(v.time)}: {v.summary}</div>)}
          </div>
        </div>
        <h2>Commands ({a.commands.length})</h2>
        <pre>{a.commands.map((c) => `${new Date(c.time).toLocaleTimeString()}  ${c.user}@${c.host}$ ${c.line}${c.code ? `   # exit ${c.code}` : ''}`).join('\n') || '(none)'}</pre>
        <button onClick={() => go(`troubleshoot/${a.scenarioId}`)}>Open this ticket again</button>
      </div>
    );
  }
  return (
    <div className="page">
      <h1>Troubleshooting history</h1>
      {attempts.length === 0 ? <p className="muted">No attempts yet. Open a ticket in the Troubleshooting lab.</p> : (
        <table>
          <thead><tr><th>Started</th><th>Ticket</th><th>Status</th><th>Hints</th><th>Diagnoses</th><th>Verifications</th><th>Commands</th><th /></tr></thead>
          <tbody>
            {attempts.map((x) => (
              <tr key={x.id}>
                <td className="small">{fmt(x.startedAt)}</td>
                <td>{ALL_SCENARIOS.find((s) => s.id === x.scenarioId)?.title}</td>
                <td><span className={`badge ${x.status === 'resolved' ? 'ok' : x.status === 'revealed' ? 'warn' : ''}`}>{x.status}</span></td>
                <td>{x.hintsUsed}</td><td>{x.diagnoses.length}</td><td>{x.verifications.length}</td><td>{x.commands.length}</td>
                <td><button className="link" onClick={() => go(`history/${x.id}`)}>details</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
