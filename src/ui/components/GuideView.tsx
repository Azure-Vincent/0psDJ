// A technology's ServiceGuide, rendered in parts so that each lesson tab shows
// one kind of information: architecture under "How it works", diagrams under
// "Visualize", the file catalogue under "Config", day-to-day management under
// "Operate & recover", and the diagnostic workflow and failure modes under
// "Troubleshooting".

import { useState } from 'react';
import type { GuideFile, GuideFileKind, ServiceGuide } from '../../content/types';
import { refLink, refTitle } from '../../content/reference';
import { LayeredDiagramView, StaticSequenceView } from './Diagrams';
import { Inline, Markdown } from './Markdown';

const KIND_LABEL: Record<GuideFileKind, string> = {
  config: 'Main configuration', 'config-dir': 'Configuration directory', auth: 'Authentication', log: 'Log', unit: 'Service unit',
  startup: 'Startup', cert: 'Certificates / keys', data: 'Data', runtime: 'Runtime', registry: 'Registry', eventlog: 'Event log', binary: 'Program',
};

/** How it works: the questions every service answers, its ports and its processes. */
export function GuideArchitecture({ g }: { g: ServiceGuide }) {
  return (
    <>
      <h2>Architecture at a glance</h2>
      <div className="table-scroll"><table>
        <tbody>
          {g.architecture.map((a) => (
            <tr key={a.q}><th style={{ width: '26%' }}>{a.q}</th><td><Markdown text={a.a} /></td></tr>
          ))}
        </tbody>
      </table></div>
      <div className="grid2">
        <div>
          <h3>Ports and transport</h3>
          {g.ports.length ? (
            <div className="table-scroll"><table><thead><tr><th>Port</th><th>Transport</th><th>Purpose</th></tr></thead>
              <tbody>{g.ports.map((p) => <tr key={p.port + p.proto}><td className="mono">{p.port}</td><td>{p.proto}</td><td>{p.purpose}</td></tr>)}</tbody></table></div>
          ) : <p className="small muted">No network ports of its own.</p>}
        </div>
        <div>
          <h3>Processes and OS components</h3>
          <div className="table-scroll"><table><tbody>{g.processes.map((p) => <tr key={p.name + p.platform}><td className="mono">{p.name}</td><td className="small muted">{p.platform}</td><td><Inline text={p.role} /></td></tr>)}</tbody></table></div>
        </div>
      </div>
    </>
  );
}

/** Visualize: what it depends on and the messages it exchanges. */
export function GuideDiagrams({ g }: { g: ServiceGuide }) {
  return (
    <>
      <h2>Dependencies and communication</h2>
      <LayeredDiagramView d={g.dependencies} />
      {g.sequence && <StaticSequenceView s={g.sequence} />}
    </>
  );
}

/** A file in the catalogue: the guide's full description, or only a purpose for paths listed in the configuration overview. */
export type CatalogueFile = Pick<GuideFile, 'path' | 'platform' | 'contains'> & Partial<Pick<GuideFile, 'kind' | 'accessed' | 'problems' | 'perms'>>;

/** Operating-system families a platform description belongs to ("Linux, macOS, Windows" belongs to three). */
const FAMILIES: [string, RegExp][] = [
  ['Linux', /linux|debian|ubuntu|rhel|rocky|alma|systemd|xrdp|realmd|sssd/i],
  ['Windows', /windows/i],
  ['macOS', /macos/i],
  ['pfSense', /pfsense|freebsd/i],
  ['Docker', /docker|container/i],
];
const familiesOf = (platform: string) => FAMILIES.filter(([, re]) => re.test(platform)).map(([name]) => name);

/** Config: one catalogue of files, directories and logs, filterable by operating system. */
export function FileCatalogue({ files }: { files: CatalogueFile[] }) {
  const present = FAMILIES.map(([n]) => n).filter((n) => files.some((f) => familiesOf(f.platform).includes(n)));
  const [fam, setFam] = useState<string>('all');
  // Files whose platform names no family (e.g. "client") apply everywhere.
  const shown = files.filter((f) => fam === 'all' || familiesOf(f.platform).includes(fam) || familiesOf(f.platform).length === 0);
  const dash = <span className="muted">—</span>;
  return (
    <>
      {present.length > 1 && (
        <div className="row" style={{ marginBottom: 6 }}>
          <button className={fam === 'all' ? 'primary' : ''} onClick={() => setFam('all')}>All</button>
          {present.map((n) => <button key={n} className={fam === n ? 'primary' : ''} onClick={() => setFam(n)}>{n}</button>)}
        </div>
      )}
      <div className="table-scroll"><table className="wide">
        <thead><tr><th style={{ minWidth: 190 }}>Path</th><th>Type</th><th>Contains</th><th>Read / written</th><th>Problems from bad values or permissions</th></tr></thead>
        <tbody>
          {shown.map((f) => (
            <tr key={f.path + f.platform}>
              <td className="mono small" style={{ overflowWrap: 'anywhere' }}>{f.path}{f.perms && <div className="muted">{f.perms}</div>}<div className="muted">{f.platform}</div></td>
              <td className="small">{f.kind ? <span className="badge">{KIND_LABEL[f.kind]}</span> : dash}</td>
              <td className="small"><Inline text={f.contains} /></td>
              <td className="small">{f.accessed ? <Inline text={f.accessed} /> : dash}</td>
              <td className="small">{f.problems ? <Inline text={f.problems} /> : dash}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </>
  );
}

/** Operate & recover: service management, reload vs restart, verifying it is healthy again. */
export function GuideOperate({ g, simulated }: { g: ServiceGuide; simulated: boolean }) {
  const [mgmt, setMgmt] = useState(0);
  return (
    <>
      <h2>Service management</h2>
      {g.management.length > 1 && (
        <div className="row" style={{ marginBottom: 6 }}>
          {g.management.map((m, i) => <button key={m.platform} className={mgmt === i ? 'primary' : ''} onClick={() => setMgmt(i)}>{m.platform}</button>)}
        </div>
      )}
      {g.management[mgmt] && (
        <div className="table-scroll"><table className="wide">
          <thead><tr><th>Task</th><th>Command</th><th>What it does / how to read it</th><th>Risk</th></tr></thead>
          <tbody>
            {g.management[mgmt].tasks.map((t) => (
              <tr key={t.task + t.command}>
                <td>{t.task}{t.sim && simulated && <div><span className="badge accent">in simulator</span></div>}</td>
                <td><pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{t.command}</pre></td>
                <td className="small"><Inline text={t.explain} /></td>
                <td className="small">{t.risk ? <Inline text={t.risk} /> : <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}

      <h2>Reload, restart, interface restart or reboot?</h2>
      <div className="table-scroll"><table className="wide">
        <thead><tr><th>Action</th><th>When it is appropriate</th><th>What it does</th><th>Risk</th></tr></thead>
        <tbody>{g.actions.map((a) => <tr key={a.action}><td className="mono small">{a.action}</td><td className="small"><Inline text={a.when} /></td><td className="small"><Inline text={a.effect} /></td><td className="small"><Inline text={a.risk} /></td></tr>)}</tbody>
      </table></div>

      <h2>Verify it is healthy</h2>
      <p className="small muted">After any change or recovery, check every line, not only the one you fixed.</p>
      <div className="table-scroll"><table>
        <thead><tr><th>Check</th><th>Command</th><th>Expected</th></tr></thead>
        <tbody>{g.verification.map((v) => <tr key={v.check}><td>{v.check}</td><td className="mono small">{v.command}</td><td className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{v.expect}</td></tr>)}</tbody>
      </table></div>

      {g.refIds.length > 0 && (
        <>
          <h2>Reference library</h2>
          <div className="row" style={{ gap: 6 }}>
            {g.refIds.map((id) => <a key={id} className="badge accent" href={`#/${refLink(id)}`} title={refTitle(id)}>{refTitle(id)}</a>)}
          </div>
        </>
      )}
    </>
  );
}

/** Troubleshooting: the ordered diagnostic workflow. */
export function GuideWorkflow({ g, simulated }: { g: ServiceGuide; simulated: boolean }) {
  return (
    <>
      <h2>Diagnostic workflow</h2>
      <p className="small muted">Go through the steps in order. Each one checks something that the later steps depend on, so the first step that fails is usually where the problem is. Fix that, then carry on from there.</p>
      {g.workflow.map((w, i) => (
        <div className="card" key={w.question} style={{ marginBottom: 8 }}>
          <div className="spread"><strong>{i + 1}. {w.question.replace(/^\d+\.\s*/, '')}</strong>{w.sim && simulated && <span className="badge accent">in simulator</span>}</div>
          {w.why && <div className="small" style={{ marginTop: 4 }}><Inline text={w.why} /></div>}
          <pre>{w.command}</pre>
          <div className="grid2" style={{ gap: 10 }}>
            <div><div className="small muted">Normal output</div><pre className="small" style={{ whiteSpace: 'pre-wrap' }}>{w.healthy}</pre></div>
            <div><div className="small muted">If you see something else, it means</div><Inline text={w.broken} /></div>
          </div>
          <div className="small" style={{ marginTop: 6 }}><strong>What to do next:</strong> <Inline text={w.next} /></div>
        </div>
      ))}
    </>
  );
}

/** Troubleshooting: symptoms, their likely causes and how to tell them apart. */
export function GuideFailures({ g }: { g: ServiceGuide }) {
  return (
    <>
      <h2>Common failures</h2>
      <div className="table-scroll"><table className="wide">
        <thead><tr><th>Symptom</th><th>Likely causes</th><th>Commands that tell them apart</th><th>Fix</th><th>Verify</th></tr></thead>
        <tbody>
          {g.failures.map((f) => (
            <tr key={f.symptom}>
              <td className="mono small">{f.symptom}</td>
              <td className="small"><ul style={{ margin: 0, paddingLeft: 16 }}>{f.causes.map((c, i) => <li key={i}><Inline text={c} /></li>)}</ul></td>
              <td className="mono small">{f.diagnose.map((d) => <div key={d}>{d}</div>)}</td>
              <td className="small"><Inline text={f.fix} /></td>
              <td className="mono small">{f.verify}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </>
  );
}
