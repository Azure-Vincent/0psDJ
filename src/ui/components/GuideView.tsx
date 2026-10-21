// "Operate & recover" section: renders a ServiceGuide (architecture,
// dependencies, files and logs, service management, diagnostic workflow,
// failure modes, verification) for one technology.

import { useState } from 'react';
import type { GuideFileKind, ServiceGuide } from '../../content/types';
import { refLink, refTitle } from '../../content/reference';
import { LayeredDiagramView, StaticSequenceView } from './Diagrams';
import { Inline, Markdown } from './Markdown';

const KIND_LABEL: Record<GuideFileKind, string> = {
  config: 'Main configuration', 'config-dir': 'Configuration directory', auth: 'Authentication', log: 'Log', unit: 'Service unit',
  startup: 'Startup', cert: 'Certificates / keys', data: 'Data', runtime: 'Runtime', registry: 'Registry', eventlog: 'Event log', binary: 'Program',
};

const QUESTIONS: [string, string][] = [
  ['What is it and how does it operate?', 'g-arch'],
  ['What does it depend on?', 'g-deps'],
  ['Where are its configuration files?', 'g-files'],
  ['Where are its logs?', 'g-files'],
  ['How do I check whether it is running?', 'g-mgmt'],
  ['How do I start, stop, restart or reload it?', 'g-mgmt'],
  ['How do I verify its network connections?', 'g-verify'],
  ['What are the most common reasons it fails?', 'g-fail'],
  ['Which commands identify those failures, and how do I read them?', 'g-flow'],
  ['How do I repair it safely?', 'g-actions'],
  ['How do I confirm it is fully operational again?', 'g-verify'],
];

function jump(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function GuideView({ g, simulated }: { g: ServiceGuide; simulated: boolean }) {
  const platforms = [...new Set(g.files.map((f) => f.platform))];
  const [plat, setPlat] = useState<string>('all');
  const [mgmt, setMgmt] = useState(0);
  const files = g.files.filter((f) => plat === 'all' || f.platform === plat);
  return (
    <div>
      <div className="callout small">
        <strong>Can you answer these without looking?</strong> Each links to the part of this guide that answers it.
        <div className="row" style={{ marginTop: 6, gap: 6 }}>
          {QUESTIONS.map(([q, id]) => <button key={q} className="small" onClick={() => jump(id)}>{q}</button>)}
        </div>
      </div>

      <h2 id="g-arch">Service architecture</h2>
      <Markdown text={g.purpose} />
      <table>
        <tbody>
          {g.architecture.map((a) => (
            <tr key={a.q}><th style={{ width: '26%' }}>{a.q}</th><td><Markdown text={a.a} /></td></tr>
          ))}
        </tbody>
      </table>
      <div className="grid2">
        <div>
          <h3>Ports and transport</h3>
          {g.ports.length ? (
            <table><thead><tr><th>Port</th><th>Transport</th><th>Purpose</th></tr></thead>
              <tbody>{g.ports.map((p) => <tr key={p.port + p.proto}><td className="mono">{p.port}</td><td>{p.proto}</td><td>{p.purpose}</td></tr>)}</tbody></table>
          ) : <p className="small muted">No network ports of its own.</p>}
        </div>
        <div>
          <h3>Processes and OS components</h3>
          <table><tbody>{g.processes.map((p) => <tr key={p.name + p.platform}><td className="mono">{p.name}</td><td className="small muted">{p.platform}</td><td><Inline text={p.role} /></td></tr>)}</tbody></table>
        </div>
      </div>

      <h2 id="g-deps">Dependencies and communication</h2>
      <LayeredDiagramView d={g.dependencies} />
      {g.sequence && <StaticSequenceView s={g.sequence} />}

      <h2 id="g-files">Important files, directories and logs</h2>
      {platforms.length > 1 && (
        <div className="row" style={{ marginBottom: 6 }}>
          <button className={plat === 'all' ? 'primary' : ''} onClick={() => setPlat('all')}>All platforms</button>
          {platforms.map((p) => <button key={p} className={plat === p ? 'primary' : ''} onClick={() => setPlat(p)}>{p}</button>)}
        </div>
      )}
      <table>
        <thead><tr><th>Path</th><th>Type</th><th>Contains</th><th>Read / written</th><th>Problems from bad values or permissions</th></tr></thead>
        <tbody>
          {files.map((f) => (
            <tr key={f.path + f.platform}>
              <td className="mono small" style={{ wordBreak: 'break-all' }}>{f.path}{f.perms && <div className="muted">{f.perms}</div>}{platforms.length > 1 && <div className="muted">{f.platform}</div>}</td>
              <td className="small"><span className="badge">{KIND_LABEL[f.kind]}</span></td>
              <td className="small"><Inline text={f.contains} /></td>
              <td className="small"><Inline text={f.accessed} /></td>
              <td className="small"><Inline text={f.problems} /></td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 id="g-mgmt">Service management</h2>
      <div className="row" style={{ marginBottom: 6 }}>
        {g.management.map((m, i) => <button key={m.platform} className={mgmt === i ? 'primary' : ''} onClick={() => setMgmt(i)}>{m.platform}</button>)}
      </div>
      {g.management[mgmt] && (
        <table>
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
        </table>
      )}

      <h2 id="g-actions">Reload, restart, interface restart or reboot?</h2>
      <table>
        <thead><tr><th>Action</th><th>When it is appropriate</th><th>What it does</th><th>Risk</th></tr></thead>
        <tbody>{g.actions.map((a) => <tr key={a.action}><td className="mono small">{a.action}</td><td className="small"><Inline text={a.when} /></td><td className="small"><Inline text={a.effect} /></td><td className="small"><Inline text={a.risk} /></td></tr>)}</tbody>
      </table>

      <h2 id="g-flow">Diagnostic workflow</h2>
      <p className="small muted">Work from the bottom of the stack upwards and stop at the first step that fails: everything above it depends on it.</p>
      {g.workflow.map((w, i) => (
        <div className="card" key={w.question} style={{ marginBottom: 8 }}>
          <div className="spread"><strong>{i + 1}. {w.question}</strong>{w.sim && simulated && <span className="badge accent">in simulator</span>}</div>
          <pre>{w.command}</pre>
          <div className="grid2" style={{ gap: 10 }}>
            <div><div className="small muted">Healthy</div><pre className="small" style={{ whiteSpace: 'pre-wrap' }}>{w.healthy}</pre></div>
            <div><div className="small muted">Broken, and what it means</div><Inline text={w.broken} /></div>
          </div>
          <div className="small" style={{ marginTop: 6 }}><strong>Next:</strong> <Inline text={w.next} /></div>
        </div>
      ))}

      <h2 id="g-fail">Common failures</h2>
      <table>
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
      </table>

      <h2 id="g-verify">Verify recovery</h2>
      <table>
        <thead><tr><th>Check</th><th>Command</th><th>Expected</th></tr></thead>
        <tbody>{g.verification.map((v) => <tr key={v.check}><td>{v.check}</td><td className="mono small">{v.command}</td><td className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{v.expect}</td></tr>)}</tbody>
      </table>

      {g.refIds.length > 0 && (
        <>
          <h2>Reference library</h2>
          <div className="row" style={{ gap: 6 }}>
            {g.refIds.map((id) => <a key={id} className="badge accent" href={`#/${refLink(id)}`}>{refTitle(id)}</a>)}
          </div>
        </>
      )}
    </div>
  );
}
