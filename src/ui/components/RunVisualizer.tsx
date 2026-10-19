import { useMemo, useState } from 'react';
import { runVisual, type VisualRun } from '../../engine/lab/visualRuns';
import { SequenceDiagram } from './SequenceDiagram';
import type { Lane } from './SequenceDiagram';
import { LAB_LANES, segmentOf } from './labLanes';

export function RunVisualizer({ runs, lanes = LAB_LANES }: { runs: VisualRun[]; lanes?: Lane[] }) {
  const [id, setId] = useState(runs[0].id);
  const run = runs.find((r) => r.id === id)!;
  const result = useMemo(() => runVisual(run), [run]);
  return (
    <div>
      <p className="muted">Each run builds a fresh lab, applies the listed change, and executes one command with the trace recorder on. Every arrow is a packet the engine routed; the inspector's "Path taken" shows each hook's firewall decision, including the exact rule.</p>
      <div className="row" style={{ marginBottom: 6 }}>
        <label>Run:{' '}
          <select value={id} onChange={(e) => setId(e.target.value)}>
            {runs.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
          </select>
        </label>
        <code>{run.user}@{run.host}$ {run.command}</code>
      </div>
      <div className="callout small">{run.description}</div>
      <SequenceDiagram events={result.trace} lanes={lanes} segmentOf={segmentOf} />
      <details className="card" style={{ marginTop: 12 }} open>
        <summary><strong>Command output</strong></summary>
        <pre style={{ maxHeight: 300 }}>{result.output || '(no output)'}</pre>
      </details>
    </div>
  );
}
