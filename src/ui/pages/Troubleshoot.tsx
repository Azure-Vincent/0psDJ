import { useRef, useState } from 'react';
import { CONCEPTS } from '../../content/concepts';
import { buildSshLab } from '../../engine/lab/sshLab';
import { CAUSES } from '../../engine/scenarios/catalog';
import { goalLabel, gradeDiagnosis, verifyScenario, type DiagnosisGrade, type Verification } from '../../engine/scenarios/engine';
import { ALL_SCENARIOS, SCENARIO_SETS } from '../../engine/scenarios';
import type { CauseCategory, Scenario } from '../../engine/scenarios/types';
import type { CommandLogEntry } from '../../engine/shell/shell';
import type { World } from '../../engine/types';
import { mastery, recordConcepts, type TroubleshootingAttempt } from '../../learning/progress';
import { LabTerminals } from '../components/LabTerminals';
import { Topology } from '../components/Topology';
import { go, useProgress } from '../state';

const ORDER: Scenario['difficulty'][] = ['beginner', 'intermediate', 'advanced'];

export function TroubleshootList() {
  const { progress } = useProgress();
  return (
    <div className="page">
      <h1>Troubleshooting lab</h1>
      <p className="muted">
        Each ticket starts from a working network (office LAN with ws01/ws02, router rtr01 with an Internet uplink, server srv01, DNS/DHCP on ns1) with one or more realistic faults injected through the same commands an
        administrator would have run. The environment is a deterministic simulation: changing a firewall rule, route, file, permission or service changes logs,
        packets and connection results consistently. Nothing is pre-recorded.
      </p>
      <div className="callout small">
        Method: <strong>symptom</strong> (exact message) → <strong>locate</strong> the layer → <strong>evidence</strong> on both ends → <strong>hypothesis</strong> →
        <strong> test</strong> → <strong>fix persistently</strong> → <strong>verify</strong> (now, after reboot, and without weakening security).
      </div>
      {SCENARIO_SETS.map((set) => (
        <div key={set.id}>
          <h2>{set.title}</h2>
          <div className="grid3">
            {set.scenarios.slice().sort((a, b) => ORDER.indexOf(a.difficulty) - ORDER.indexOf(b.difficulty)).map((s) => {
              const attempts = progress.attempts.filter((a) => a.scenarioId === s.id);
              const best = attempts.find((a) => a.status === 'resolved') ?? attempts.find((a) => a.status === 'revealed');
              return (
                <div className="card" key={s.id}>
                  <div className="spread"><strong>{s.title}</strong>
                    <span className="row">
                      <span className="badge">{s.difficulty}</span>
                      {best ? <span className={`badge ${best.status === 'resolved' ? 'ok' : 'warn'}`}>{best.status}</span> : attempts.length ? <span className="badge">{attempts.length} attempt(s)</span> : null}
                    </span>
                  </div>
                  <p className="small">{s.ticket}</p>
                  <button className="primary" onClick={() => go(`troubleshoot/${s.id}`)}>Open ticket</button>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function newAttempt(scenarioId: string): TroubleshootingAttempt {
  return {
    id: `${scenarioId}-${Date.now().toString(36)}`, scenarioId, startedAt: Date.now(), status: 'in-progress', hintsUsed: 0,
    diagnoses: [], verifications: [], commands: [], notes: { symptoms: '', evidence: '', hypothesis: '' },
  };
}

function GoalLine({ label, ok, lines }: { label: string; ok: boolean; lines: string[] }) {
  const last = lines.filter((l) => !l.startsWith('debug')).slice(-1)[0] ?? '';
  return (
    <div className={`feedback ${ok ? 'ok' : 'bad'}`} style={{ fontSize: 12.5 }}>
      {ok ? '✓' : '✗'} {label}{!ok && last ? <div className="mono small">{last}</div> : null}
    </div>
  );
}

export function TroubleshootWorkspace({ id }: { id: string }) {
  const scenario = ALL_SCENARIOS.find((s) => s.id === id);
  const { progress, update } = useProgress();
  const worldRef = useRef<World | null>(null);
  const [labKey, setLabKey] = useState(0);
  const [attemptId, setAttemptId] = useState<string | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [grade, setGrade] = useState<DiagnosisGrade | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [hintsShown, setHintsShown] = useState(0);

  if (!scenario) return <div className="page"><h1>Unknown scenario</h1><button onClick={() => go('troubleshoot')}>Back</button></div>;
  const attempt = progress.attempts.find((a) => a.id === attemptId) ?? null;

  const patchAttempt = (fn: (a: TroubleshootingAttempt) => TroubleshootingAttempt) =>
    update((p) => ({ ...p, attempts: p.attempts.map((a) => (a.id === attemptId ? fn(a) : a)) }));

  const start = () => {
    const w = buildSshLab();
    scenario.setup(w);
    worldRef.current = w;
    const a = newAttempt(scenario.id);
    update((p) => ({
      ...p,
      attempts: [...p.attempts.map((x) => (x.scenarioId === scenario.id && x.status === 'in-progress' ? { ...x, status: 'abandoned' as const, endedAt: Date.now() } : x)), a],
    }));
    setAttemptId(a.id);
    setSelected([]);
    setGrade(null);
    setVerification(null);
    setHintsShown(0);
    setLabKey((k) => k + 1);
  };

  const onCommand = (e: CommandLogEntry) => {
    const entry = { time: Date.now(), host: e.host, user: e.user, line: e.line, code: e.code };
    setAttemptIdSafeAppend(entry);
  };
  // onCommand is captured by shells at creation; use a functional update keyed by the attempt id in a ref.
  const attemptRef = useRef<string | null>(null);
  attemptRef.current = attemptId;
  const setAttemptIdSafeAppend = (entry: TroubleshootingAttempt['commands'][number]) =>
    update((p) => ({ ...p, attempts: p.attempts.map((a) => (a.id === attemptRef.current ? { ...a, commands: [...a.commands, entry].slice(-500) } : a)) }));

  const finished = attempt?.status === 'resolved' || attempt?.status === 'revealed';
  const diagnosedOk = attempt?.diagnoses.some((d) => d.correct) ?? false;
  const lastVerification = attempt?.verifications[attempt.verifications.length - 1];

  const maybeResolve = (diagOk: boolean, verifyOk: boolean) => {
    if (diagOk && verifyOk && attempt?.status === 'in-progress') {
      patchAttempt((a) => ({ ...a, status: 'resolved', endedAt: Date.now() }));
      update((p) => recordConcepts(p, scenario.concepts, (attempt?.hintsUsed ?? 0) < 3, Date.now()));
    }
  };

  const submitDiagnosis = () => {
    const g = gradeDiagnosis(scenario, selected);
    setGrade(g);
    const firstTry = (attempt?.diagnoses.length ?? 0) === 0;
    patchAttempt((a) => ({ ...a, diagnoses: [...a.diagnoses, { time: Date.now(), selected, correct: g.correct }] }));
    update((p) => {
      let next = p;
      for (const w of g.wrong) next = recordConcepts(next, [CAUSES[w.id].concept], false, Date.now(), `cause:${w.id}@${scenario.id}`);
      if (g.correct && firstTry) next = recordConcepts(next, scenario.rootCauses.map((c) => CAUSES[c].concept), true, Date.now());
      return next;
    });
    maybeResolve(g.correct, !!lastVerification?.passed);
  };

  const verify = () => {
    setVerifying(true);
    setTimeout(() => {
      const v = verifyScenario(worldRef.current!, scenario);
      setVerification(v);
      setVerifying(false);
      const failedC = [...v.constraints, ...v.constraintsAfterReboot].filter((c) => c.required && !c.ok);
      const summary = v.passed ? 'passed' : !v.now.every((g) => g.ok) ? 'goal not met' : !v.afterReboot.every((g) => g.ok) ? 'fails after reboot' : `policy violation: ${failedC.map((c) => c.id).join(', ')}`;
      patchAttempt((a) => ({ ...a, verifications: [...a.verifications, { time: Date.now(), passed: v.passed, summary }] }));
      maybeResolve(diagnosedOk || !!grade?.correct, v.passed);
    }, 10);
  };

  const reveal = () => {
    if (!confirm('Reveal the root cause and reference solution? The attempt will be recorded as "revealed".')) return;
    patchAttempt((a) => ({ ...a, status: 'revealed', endedAt: Date.now() }));
    update((p) => recordConcepts(p, scenario.concepts, false, Date.now(), `revealed:${scenario.id}`));
  };

  const showHint = () => {
    setHintsShown((n) => n + 1);
    patchAttempt((a) => ({ ...a, hintsUsed: Math.max(a.hintsUsed, hintsShown + 1) }));
  };

  const categories = [...new Set(scenario.candidates.map((c) => CAUSES[c].category))] as CauseCategory[];
  const struggling = scenario.concepts.filter((c) => mastery(progress.concepts[c]).level === 'struggling');
  const clientUser = scenario.clientUser ?? 'alice';

  return (
    <div className="page wide">
      <div className="spread">
        <div>
          <button className="link" onClick={() => go('troubleshoot')}>← All tickets</button>
          <h1 style={{ marginTop: 4 }}>{scenario.title} <span className="badge">{scenario.difficulty}</span></h1>
        </div>
        <div className="row">
          {attempt && <span className={`badge ${attempt.status === 'resolved' ? 'ok' : attempt.status === 'revealed' ? 'warn' : 'accent'}`}>{attempt.status}</span>}
          {attempt && !finished && <button className="danger" onClick={reveal}>Reveal solution</button>}
          <button onClick={start}>{attempt ? 'Restart from scratch' : 'Start investigation'}</button>
        </div>
      </div>

      {!attempt ? (
        <div className="grid2" style={{ marginTop: 12 }}>
          <div className="card">
            <h3>Ticket</h3>
            <p>{scenario.ticket}</p>
            <h3>What you know</h3>
            <ul>{scenario.briefing.map((b, i) => <li key={i}>{b}</li>)}</ul>
            <h3>Goal</h3>
            <ul>{scenario.goals.map((g, i) => <li key={i}>{g.description}</li>)}</ul>
            <button className="primary" onClick={start}>Start investigation</button>
          </div>
          <div className="card"><h3>Topology</h3><Topology /></div>
        </div>
      ) : (
        <div className="ts-grid" style={{ marginTop: 10 }}>
          <div className="ts-col">
            <div className="card">
              <h3>Ticket</h3>
              <p className="small">{scenario.ticket}</p>
              <ul className="small">{scenario.briefing.map((b, i) => <li key={i}>{b}</li>)}</ul>
              <div className="small"><strong>Goal:</strong> {scenario.goals.map((g) => g.description).join(' ')}</div>
            </div>
            <div className="card"><Topology /></div>
            <div className="card">
              <div className="spread"><h3>Hints</h3><span className="muted small">{hintsShown}/{scenario.hints.length}</span></div>
              {scenario.hints.slice(0, hintsShown).map((h, i) => <div key={i} className="callout small"><strong>Hint {i + 1}.</strong> {h}</div>)}
              {hintsShown < scenario.hints.length && !finished && (
                <button onClick={showHint}>{hintsShown === 0 ? 'I need a nudge' : 'Next hint'}</button>
              )}
              {hintsShown === 0 && <p className="small muted">Hints become more specific each time. Try to collect evidence first.</p>}
            </div>
            {struggling.length > 0 && (
              <div className="callout warn small">
                You have struggled with {struggling.map((c) => CONCEPTS[c].title).join(', ')} before. Review:{' '}
                {struggling.map((c) => <button key={c} className="link" onClick={() => go(CONCEPTS[c].review)}>{CONCEPTS[c].title}</button>)}
              </div>
            )}
          </div>

          <div className="ts-center">
            <LabTerminals key={labKey} getWorld={() => worldRef.current!} setWorld={(w) => (worldRef.current = w)} onCommand={onCommand} height="100%"
              specs={scenario.terminals ?? [
                { hostId: 'ws01', user: clientUser, label: `ws01 (${clientUser})`, banner: `ws01 terminal as ${clientUser}. Type "help" for commands. sudo password: ws01-${clientUser}.` },
                { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Out-of-band console on srv01 (root). Works even when the network does not.' },
                { hostId: 'ns1', user: 'root', label: 'ns1 console', banner: 'Console on ns1 (root): BIND 9, zone file /etc/bind/db.corp.lab.' },
                { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on rtr01 (root): Linux router between 10.0.10.0/24, 10.0.20.0/24 and the Internet uplink 203.0.113.0/24.' },
              ]} />
          </div>

          <div className="ts-col">
            <div className="card">
              <h3>Investigation notes</h3>
              <label className="small muted">Symptoms (exact messages)</label>
              <textarea rows={2} value={attempt.notes.symptoms} onChange={(e) => patchAttempt((a) => ({ ...a, notes: { ...a.notes, symptoms: e.target.value } }))} />
              <label className="small muted">Evidence and test results</label>
              <textarea rows={3} value={attempt.notes.evidence} onChange={(e) => patchAttempt((a) => ({ ...a, notes: { ...a.notes, evidence: e.target.value } }))} />
              <details>
                <summary className="small">Commands run ({attempt.commands.length})</summary>
                <div className="evidence-list">
                  {attempt.commands.length === 0 && <span className="muted">none yet</span>}
                  {attempt.commands.map((c, i) => <div key={i}>{c.user}@{c.host}$ {c.line}{c.code ? ` (exit ${c.code})` : ''}</div>)}
                </div>
              </details>
            </div>
            <div className="card causes">
              <h3>Diagnosis</h3>
              <p className="small muted">Select the root cause(s). There may be more than one fault.</p>
              {categories.map((cat) => (
                <div key={cat}>
                  <div className="small muted" style={{ marginTop: 6 }}>{cat}</div>
                  {scenario.candidates.filter((c) => CAUSES[c].category === cat).map((c) => (
                    <label key={c}>
                      <input type="checkbox" disabled={finished} checked={selected.includes(c)} onChange={() => { setGrade(null); setSelected((s) => (s.includes(c) ? s.filter((x) => x !== c) : [...s, c])); }} />
                      <span>{CAUSES[c].title}</span>
                    </label>
                  ))}
                </div>
              ))}
              <button className="primary" style={{ marginTop: 8 }} disabled={selected.length === 0 || finished} onClick={submitDiagnosis}>Submit diagnosis</button>
              {grade && (
                <div style={{ marginTop: 8 }}>
                  {grade.correct ? (
                    <div className="feedback ok">✓ Diagnosis correct.{lastVerification?.passed ? '' : ' Now repair it and press Verify.'}</div>
                  ) : (
                    <div className="feedback bad">✗ Not yet.{grade.missing.length > 0 && grade.wrong.length === 0 ? ` You have found ${grade.matched.length} of the root causes; keep investigating.` : ''}</div>
                  )}
                  {grade.wrong.map((w) => <div key={w.id} className="callout err small"><strong>{w.title}:</strong> {w.explanation}</div>)}
                  {grade.acceptable.map((w) => <div key={w.id} className="callout small"><strong>{w.title}:</strong> {w.note}</div>)}
                </div>
              )}
            </div>
            <div className="card">
              <div className="spread"><h3>Verify the repair</h3><button className="primary" disabled={verifying} onClick={verify}>{verifying ? 'Verifying…' : 'Verify'}</button></div>
              <p className="small muted">Runs the goal connection now, reboots every host (runtime state rebuilt from files) and runs it again, then checks the security policy.</p>
              {verification && (
                <>
                  {verification.now.map((g, i) => <GoalLine key={`n${i}`} label={`Now: ${goalLabel(g.goal)}`} ok={g.ok} lines={g.lines} />)}
                  {verification.afterReboot.map((g, i) => <GoalLine key={`r${i}`} label={`After reboot: ${goalLabel(g.goal)}`} ok={g.ok} lines={g.lines} />)}
                  {verification.constraints.map((c, i) => {
                    const after = verification.constraintsAfterReboot[i];
                    const ok = c.ok && after.ok;
                    return (
                      <div key={c.id} className={`feedback ${ok ? 'ok' : c.required ? 'bad' : ''}`} style={{ fontSize: 12.5, background: !ok && !c.required ? 'var(--warn-soft)' : undefined, color: !ok && !c.required ? 'var(--warn)' : undefined }}>
                        {ok ? '✓' : c.required ? '✗' : '!'} {scenario.constraints[i].description}
                        {!ok && <div className="small">{!c.ok ? c.message : `After reboot: ${after.message}`}</div>}
                      </div>
                    );
                  })}
                  {verification.passed && !diagnosedOk && !grade?.correct && <div className="callout small">Service restored. Record a correct diagnosis to close the ticket.</div>}
                </>
              )}
            </div>
            {finished && (
              <div className="card">
                <h3>{attempt.status === 'resolved' ? 'Resolved: root cause analysis' : 'Solution (revealed)'}</h3>
                <p><strong>Root cause.</strong> {scenario.explanation.rootCause}</p>
                <p><strong>How it manifested.</strong> {scenario.explanation.manifestation}</p>
                <p><strong>Evidence that identifies it.</strong> {scenario.explanation.evidence}</p>
                <p><strong>Prevention.</strong> {scenario.explanation.prevention}</p>
                <h3>Reference repair</h3>
                {scenario.solution.map((s, i) => (
                  <div key={i}>
                    <div className="small muted">On {s.host}{s.user ? ` as ${s.user}` : ' as root'}:</div>
                    <pre>{s.commands.join('\n')}</pre>
                    {s.note && <div className="small">{s.note}</div>}
                  </div>
                ))}
                <div className="small muted">Root cause(s): {scenario.rootCauses.map((c) => CAUSES[c].title).join('; ')}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
