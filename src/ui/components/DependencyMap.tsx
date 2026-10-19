import { useState } from 'react';
import { OUTCOME_LABELS, SSH_DEPENDENCIES, runWithFault, type DependencyRun, type OutcomeClass } from '../../engine/lab/dependencies';
import { recordConcepts } from '../../learning/progress';
import type { ConceptId } from '../../engine/scenarios/types';
import { go, useProgress } from '../state';

const NODE_CONCEPT: Record<string, ConceptId> = {
  dns: 'dns.resolution', 'dns-record': 'dns.zone', 'client-route': 'net.routing', router: 'net.routing', 'server-route': 'net.routing',
  firewall: 'fw.stateful', sshd: 'tcp.handshake', algorithms: 'ssh.kex', hostkey: 'ssh.hostkeys', authz: 'ssh.authz', authkeys: 'ssh.authorized-keys', shell: 'ssh.userauth',
};

export function DependencyMap() {
  const { update, progress } = useProgress();
  const [node, setNode] = useState<string | null>(null);
  const [prediction, setPrediction] = useState<OutcomeClass | null>(null);
  const [run, setRun] = useState<DependencyRun | null>(null);
  const sel = SSH_DEPENDENCIES.find((n) => n.id === node);

  const simulate = () => {
    if (!node || !prediction) return;
    const r = runWithFault(node);
    setRun(r);
    const correct = r.outcome === prediction;
    update((p) => {
      const prev = p.predictions[node];
      const next = recordConcepts(p, [NODE_CONCEPT[node]], correct, Date.now(), correct ? undefined : `predict:${node}:${prediction}`);
      return { ...next, predictions: { ...next.predictions, [node]: { attempts: (prev?.attempts ?? 0) + 1, correct: correct || !!prev?.correct } } };
    });
  };

  const failedPhase = run ? [...run.trace].reverse().find((e) => e.kind === 'packet' || e.kind === 'internal')?.phase : undefined;

  return (
    <div className="grid2">
      <div>
        <h3>Dependency chain for "alice@ws01 → ssh srv01.corp.lab"</h3>
        <p className="muted small">Each item depends on the ones above it. Select one to switch it off, predict what the client will print, then run the simulation.</p>
        <div className="dep-graph">
          {SSH_DEPENDENCIES.map((n, i) => (
            <div key={n.id} className={`dep-node${node === n.id ? ' sel' : ''}`} onClick={() => { setNode(n.id); setPrediction(null); setRun(null); }} role="button" tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && (setNode(n.id), setPrediction(null), setRun(null))}>
              <span className="muted">{i + 1}</span>
              <span>{n.label}<div className="layer-tag">{n.layer} · {n.host}</div></span>
              {progress.predictions[n.id]?.correct ? <span className="badge ok">predicted</span> : <span />}
            </div>
          ))}
        </div>
      </div>
      <div>
        {!sel && <div className="card muted">Select a dependency on the left.</div>}
        {sel && (
          <div className="card">
            <h3>Switch off: {sel.label}</h3>
            <p><strong>Fault applied:</strong> {sel.failure}</p>
            <p>What will <code>ssh srv01.corp.lab</code> on ws01 print?</p>
            {(Object.keys(OUTCOME_LABELS) as OutcomeClass[]).map((o) => (
              <label key={o} className="row" style={{ margin: '3px 0' }}>
                <input type="radio" name="pred" checked={prediction === o} onChange={() => { setPrediction(o); setRun(null); }} disabled={!!run} />
                <span className="mono small">{OUTCOME_LABELS[o]}</span>
              </label>
            ))}
            <div className="row" style={{ marginTop: 8 }}>
              <button className="primary" disabled={!prediction || !!run} onClick={simulate}>Run simulation</button>
              {run && <button onClick={() => { setRun(null); setPrediction(null); }}>Predict again</button>}
            </div>
            {run && (
              <div style={{ marginTop: 10 }}>
                <div className={`feedback ${run.outcome === prediction ? 'ok' : 'bad'}`}>
                  {run.outcome === prediction ? '✓ Your prediction was right.' : `✗ You predicted "${OUTCOME_LABELS[prediction!]}". Actual: "${OUTCOME_LABELS[run.outcome]}".`}
                </div>
                <p className="small">Failure surfaced in phase <strong>{failedPhase}</strong> after {(run.elapsedMs / 1000).toFixed(1)} s of simulated time.</p>
                <h3>Client (ssh -v)</h3>
                <pre style={{ maxHeight: 220 }}>{run.lines.filter((l) => !/identity file|load_hostkeys|Reading configuration|ssh_config line/.test(l)).join('\n')}</pre>
                <h3>srv01 journal during the attempt</h3>
                <pre style={{ maxHeight: 160 }}>{run.serverLog.length ? run.serverLog.join('\n') : '(nothing: sshd never saw this attempt)'}</pre>
                <button onClick={() => go(`lesson/ssh/visualize?fault=${sel.id}`)}>Open this run in the sequence diagram</button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
