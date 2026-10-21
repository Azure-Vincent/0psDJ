// Reference library: commands, files & logs, and recovery procedures, faceted
// by OS, service, protocol and symptom. Deep links: #/reference?id=<id>.
// The old #/commands route opens the same page on the Commands tab.

import { useEffect, useMemo, useState } from 'react';
import { COMMAND_EXERCISES } from '../../content/commands';
import { REF_ENTRIES, getRef, type RefEntry } from '../../content/reference';
import type { CommandRef, FileRef, Procedure } from '../../content/types';
import { Exercise } from '../components/CommandExercise';
import { Inline, Markdown } from '../components/Markdown';
import { routeQuery } from '../state';

type Tab = 'command' | 'file' | 'procedure' | 'practice';
const TABS: [Tab, string][] = [['command', 'Commands'], ['file', 'Files & logs'], ['procedure', 'Recovery procedures'], ['practice', 'Practice']];

function uniq(xs: string[]): string[] {
  return [...new Set(xs)].sort((a, b) => a.localeCompare(b));
}

function CommandBody({ c }: { c: CommandRef }) {
  return (
    <div style={{ marginTop: 8 }}>
      <div className="small muted">Syntax</div><pre>{c.syntax}</pre>
      <table><tbody>{c.args.map((a) => <tr key={a.arg}><td className="mono" style={{ whiteSpace: 'nowrap' }}>{a.arg}</td><td>{a.meaning}</td></tr>)}</tbody></table>
      <div className="small muted">Example ({c.simulator ? 'output from the simulator or a real system of the stated version' : 'representative output of the stated platform'})</div>
      <pre><span style={{ color: 'var(--accent)' }}>$ {c.example.command}</span>{'\n'}{c.example.output}</pre>
      <p><strong>Interpreting it.</strong> <Inline text={c.interpretation} /></p>
      {c.errors && c.errors.length > 0 && (
        <>
          <div className="small muted">Common errors</div>
          <table><tbody>{c.errors.map((e) => <tr key={e.message}><td className="mono small">{e.message}</td><td className="small"><Inline text={e.meaning} /></td></tr>)}</tbody></table>
        </>
      )}
      <table className="small">
        <tbody>
          {c.permissions && <tr><th style={{ width: 140 }}>Permissions</th><td><Inline text={c.permissions} /></td></tr>}
          {c.risks && <tr><th>Risks</th><td><Inline text={c.risks} /></td></tr>}
          {c.compat && <tr><th>Compatibility</th><td><Inline text={c.compat} /></td></tr>}
          <tr><th>Limitations</th><td><Inline text={c.limitations} /></td></tr>
          {c.services && c.services.length > 0 && <tr><th>Related services</th><td>{c.services.join(', ')}</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function FileBody({ f }: { f: FileRef }) {
  return (
    <div style={{ marginTop: 8 }}>
      <table className="small">
        <tbody>
          <tr><th style={{ width: 140 }}>Platform</th><td>{f.platform}</td></tr>
          <tr><th>Purpose</th><td><Inline text={f.purpose} /></td></tr>
          <tr><th>Contents</th><td><Inline text={f.contents} /></td></tr>
          <tr><th>Read / written</th><td><Inline text={f.accessed} /></td></tr>
          <tr><th>Permissions</th><td className="mono">{f.permissions}</td></tr>
          <tr><th>Problems</th><td><Inline text={f.problems} /></td></tr>
          <tr><th>Related services</th><td>{f.services.join(', ')}</td></tr>
        </tbody>
      </table>
      {f.example && <><div className="small muted">Example</div><pre>{f.example}</pre></>}
      {f.relatedCommands && f.relatedCommands.length > 0 && (
        <div className="row small" style={{ gap: 4 }}><span className="muted">Commands:</span>{f.relatedCommands.map((id) => <RefBadge key={id} id={id} />)}</div>
      )}
    </div>
  );
}

function ProcedureBody({ p }: { p: Procedure }) {
  return (
    <div style={{ marginTop: 8 }}>
      <Markdown text={p.purpose} />
      {p.symptoms.length > 0 && <p className="small"><strong>Use when:</strong> {p.symptoms.join('; ')}</p>}
      <ol>
        {p.steps.map((s, i) => (
          <li key={i} style={{ marginBottom: 8 }}>
            <strong>{s.title}</strong>
            {s.command && <pre style={{ margin: '4px 0' }}>{s.command}</pre>}
            <div className="small"><Inline text={s.why} /></div>
          </li>
        ))}
      </ol>
      <p className="callout warn small"><strong>Risks.</strong> <Inline text={p.risks} /></p>
      <p className="small"><strong>Verify.</strong> <Inline text={p.verify} /></p>
    </div>
  );
}

/** Full body of one reference entry (used inline by the troubleshooting workspace). */
export function RefDetail({ id }: { id: string }) {
  const e = getRef(id);
  if (!e) return null;
  return e.kind === 'command' ? <CommandBody c={e.item} /> : e.kind === 'file' ? <FileBody f={e.item} /> : <ProcedureBody p={e.item} />;
}

export function RefBadge({ id }: { id: string }) {
  const e = getRef(id);
  return <a className="badge accent" href={`#/reference?id=${encodeURIComponent(id)}`}>{e ? (e.kind === 'command' ? e.title : e.title) : id}</a>;
}

function EntryCard({ e, open, toggle }: { e: RefEntry; open: boolean; toggle: () => void }) {
  const sub = e.kind === 'command' ? `${e.item.platform} · ${e.item.category}` : e.kind === 'file' ? `${e.item.platform} · ${e.item.kind}` : e.item.platform;
  const summary = e.kind === 'command' ? e.item.purpose : e.kind === 'file' ? e.item.purpose : e.item.purpose;
  return (
    <div className="card" id={`ref-${e.id}`} style={{ marginBottom: 8 }}>
      <div className="spread" style={{ cursor: 'pointer' }} onClick={toggle}>
        <span><strong className="mono">{e.title}</strong> <span className="muted small">· {sub}</span></span>
        <span className="row">{e.kind === 'command' && e.item.simulator && <span className="badge accent">in simulator</span>}<span className="muted">{open ? '▾' : '▸'}</span></span>
      </div>
      {!open && <div className="small" style={{ marginTop: 4 }}><Inline text={summary.split('\n')[0]} /></div>}
      {open && (e.kind === 'command' ? <CommandBody c={e.item} /> : e.kind === 'file' ? <FileBody f={e.item} /> : <ProcedureBody p={e.item} />)}
    </div>
  );
}

export function Reference({ initialTab }: { initialTab?: Tab }) {
  const q = routeQuery();
  const deep = q.get('id') ? getRef(q.get('id')!) : undefined;
  const [tab, setTab] = useState<Tab>(q.get('tab') === 'practice' ? 'practice' : deep?.kind ?? initialTab ?? 'command');
  const [filter, setFilter] = useState(q.get('q') ?? '');
  const [os, setOs] = useState('all');
  const [service, setService] = useState(q.get('service') ?? 'all');
  const [protocol, setProtocol] = useState('all');
  const [symptom, setSymptom] = useState('all');
  const [open, setOpen] = useState<string | null>(deep?.id ?? null);

  // Follow deep links (#/reference?id=...) also when the page is already open.
  useEffect(() => {
    const follow = (scroll: boolean) => {
      const id = routeQuery().get('id');
      const e = id ? getRef(id) : undefined;
      if (!e) return;
      setTab(e.kind);
      setOpen(e.id);
      if (scroll) setTimeout(() => document.getElementById(`ref-${e.id}`)?.scrollIntoView({ block: 'start' }), 0);
    };
    follow(true);
    const on = () => follow(true);
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);

  const ofKind = useMemo(() => REF_ENTRIES.filter((e) => e.kind === tab), [tab]);
  const facets = useMemo(() => ({
    os: uniq(ofKind.map((e) => e.os)),
    service: uniq(ofKind.flatMap((e) => e.services)),
    protocol: uniq(ofKind.flatMap((e) => e.protocols)),
    symptom: uniq(ofKind.flatMap((e) => e.symptoms)),
  }), [ofKind]);
  const f = filter.toLowerCase();
  const list = ofKind.filter((e) =>
    (os === 'all' || e.os === os) && (service === 'all' || e.services.includes(service)) && (protocol === 'all' || e.protocols.includes(protocol))
    && (symptom === 'all' || e.symptoms.includes(symptom)) && (!f || e.text.toLowerCase().includes(f)));
  const pick = (t: Tab) => { setTab(t); setOs('all'); setService('all'); setProtocol('all'); setSymptom('all'); };
  const select = (label: string, value: string, set: (v: string) => void, options: string[]) =>
    options.length > 0 && (
      <select value={value} onChange={(e) => set(e.target.value)} aria-label={label}>
        <option value="all">{label}: all</option>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    );

  return (
    <div className="page">
      <h1>Reference library</h1>
      <p className="muted">Commands, files and logs, and recovery procedures across Linux, Windows, Docker and pfSense. Lessons, guides and case studies link here. Filter by OS, service, protocol or symptom.</p>
      <div className="tabs">
        {TABS.map(([t, label]) => <button key={t} className={tab === t ? 'active' : ''} onClick={() => pick(t)}>{label}{t !== 'practice' && <span className="n" style={{ marginLeft: 5 }}>{REF_ENTRIES.filter((e) => e.kind === t).length}</span>}</button>)}
      </div>
      {tab === 'practice' ? (
        <>
          <p className="muted">You are not told which command to use. For "Which command?", type the full command line you would run; it is checked for the right tool and the arguments that make it answer the question.</p>
          {COMMAND_EXERCISES.map((ex) => <Exercise key={ex.id} ex={ex} />)}
        </>
      ) : (
        <>
          <div className="row" style={{ marginBottom: 10, gap: 6 }}>
            <input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
            {select('OS', os, setOs, facets.os)}
            {select('Service', service, setService, facets.service)}
            {select('Protocol', protocol, setProtocol, facets.protocol)}
            {select('Symptom', symptom, setSymptom, facets.symptom)}
            <span className="small muted">{list.length} of {ofKind.length}</span>
          </div>
          {list.length === 0 && <p className="muted">Nothing matches these filters.</p>}
          {list.map((e) => (
            <EntryCard key={e.id} e={e} open={open === e.id} toggle={() => { setOpen(open === e.id ? null : e.id); if (open !== e.id) history.replaceState(null, '', `#/reference?id=${encodeURIComponent(e.id)}`); }} />
          ))}
        </>
      )}
    </div>
  );
}
