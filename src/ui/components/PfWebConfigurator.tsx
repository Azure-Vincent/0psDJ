import { useEffect, useMemo, useState } from 'react';
import type { PfAddr, PfAlias, PfConfig, PfNatRule, PfOutboundRule, PfRule } from '../../engine/pf/config';
import { PF_VERSION, readConfig, sysLog } from '../../engine/pf/model';
import {
  addrLabel, aliasUsers, assignInterface, availablePorts, browse, deleteAlias, deleteInterface, deleteOutbound, deletePortForward, deleteRule,
  firewallLog, guiApply, guiSave, ifaceLabel, moveRule, saveAlias, saveInterface, saveOutbound, savePortForward, saveRule, setOutboundMode, toggleRule,
  type FilterAssoc, type Subsystem,
} from '../../engine/pf/webgui';
import type { World } from '../../engine/types';

// The pfSense webConfigurator, as seen from a browser on a client machine.
// Every page reads /conf/config.xml on fw01; saving a form validates it,
// writes config.xml and marks the change as pending; "Apply Changes" loads it.
// Each page load is an HTTPS request from the client, so a rule that cuts the
// admin's workstation off locks the webConfigurator too.

type Page =
  | { p: 'dashboard' } | { p: 'assign' } | { p: 'iface'; key: string } | { p: 'aliases' } | { p: 'alias'; name: string | null }
  | { p: 'rules'; iface: string } | { p: 'rule'; iface: string; tracker: string | null }
  | { p: 'nat' } | { p: 'natedit'; index: number | null } | { p: 'outbound' } | { p: 'logs' } | { p: 'states' };

const URLS: Record<Page['p'], string> = {
  dashboard: 'index.php', assign: 'interfaces_assign.php', iface: 'interfaces.php', aliases: 'firewall_aliases.php', alias: 'firewall_aliases_edit.php',
  rules: 'firewall_rules.php', rule: 'firewall_rules_edit.php', nat: 'firewall_nat.php', natedit: 'firewall_nat_edit.php', outbound: 'firewall_nat_out.php',
  logs: 'status_logs_filter.php', states: 'diag_dump_states.php',
};

const TITLES: Record<Page['p'], string> = {
  dashboard: 'Status / Dashboard', assign: 'Interfaces / Interface Assignments', iface: 'Interfaces', aliases: 'Firewall / Aliases', alias: 'Firewall / Aliases / Edit',
  rules: 'Firewall / Rules', rule: 'Firewall / Rules / Edit', nat: 'Firewall / NAT / Port Forward', natedit: 'Firewall / NAT / Port Forward / Edit',
  outbound: 'Firewall / NAT / Outbound', logs: 'Status / System Logs / Firewall', states: 'Diagnostics / States',
};

const NAV: { label: string; items: { label: string; page: Page }[] }[] = [
  { label: 'Status', items: [{ label: 'Dashboard', page: { p: 'dashboard' } }, { label: 'System Logs: Firewall', page: { p: 'logs' } }] },
  { label: 'Interfaces', items: [{ label: 'Assignments', page: { p: 'assign' } }] },
  { label: 'Firewall', items: [{ label: 'Aliases', page: { p: 'aliases' } }, { label: 'NAT', page: { p: 'nat' } }, { label: 'Rules', page: { p: 'rules', iface: 'wan' } }] },
  { label: 'Diagnostics', items: [{ label: 'States', page: { p: 'states' } }] },
];

const box: React.CSSProperties = { border: '1px solid var(--border)', borderRadius: 6, background: 'var(--panel)', marginBottom: 12 };
const boxHead: React.CSSProperties = { background: 'var(--panel-2)', padding: '6px 10px', fontWeight: 600, borderBottom: '1px solid var(--border)' };
const formRow: React.CSSProperties = { display: 'grid', gridTemplateColumns: '170px 1fr', gap: 8, alignItems: 'center', padding: '6px 10px', borderBottom: '1px solid var(--border)' };

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <div style={box}><div style={boxHead}>{title}</div><div style={{ overflowX: 'auto' }}>{children}</div></div>;
}

function Field({ label, children, help }: { label: string; children: React.ReactNode; help?: string }) {
  return (
    <div style={formRow}>
      <label className="small" style={{ fontWeight: 600, textAlign: 'right' }}>{label}</label>
      <div>{children}{help && <div className="small muted">{help}</div>}</div>
    </div>
  );
}

// ---------------------------------------------------------------- address selector

type AddrKind = string; // any | single | network | (self) | <key> | <key>ip

function kindOf(a: PfAddr): AddrKind {
  if (a.network) return a.network;
  // An address being typed may still be empty: it is still a "single host" selection.
  if (a.address !== undefined) return a.address.includes('/') ? 'network' : 'single';
  return 'any';
}

function AddrEditor({ cfg, value, onChange, ports, label }: { cfg: PfConfig; value: PfAddr; onChange: (a: PfAddr) => void; ports: boolean; label: string }) {
  const kind = kindOf(value);
  const [addr, mask] = (value.address ?? '').split('/');
  const setKind = (k: AddrKind) => {
    const base: PfAddr = { not: value.not, port: value.port };
    if (k === 'any') onChange({ ...base, any: true });
    else if (k === 'single') onChange({ ...base, address: addr || '' });
    else if (k === 'network') onChange({ ...base, address: `${addr || ''}/${mask || '24'}` });
    else onChange({ ...base, network: k });
  };
  return (
    <>
      <Field label={label}>
        <div className="row">
          <label className="small"><input type="checkbox" checked={!!value.not} onChange={(e) => onChange({ ...value, not: e.target.checked || undefined })} /> Invert match</label>
          <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label={`${label} type`}>
            <option value="any">any</option>
            <option value="single">Single host or alias</option>
            <option value="network">Network</option>
            <option value="(self)">This Firewall (self)</option>
            {cfg.interfaces.filter((i) => i.enable).flatMap((i) => [
              <option key={i.key} value={i.key}>{i.descr} net</option>,
              <option key={`${i.key}ip`} value={`${i.key}ip`}>{i.descr} address</option>,
            ])}
          </select>
          {(kind === 'single' || kind === 'network') && (
            <input value={addr ?? ''} placeholder="address or alias" size={18} list="pf-aliases" aria-label={`${label} address`}
              onChange={(e) => onChange({ ...value, any: undefined, address: kind === 'network' ? `${e.target.value}/${mask || '24'}` : e.target.value })} />
          )}
          {kind === 'network' && (
            <select value={mask || '24'} aria-label={`${label} mask`} onChange={(e) => onChange({ ...value, address: `${addr}/${e.target.value}` })}>
              {Array.from({ length: 32 }, (_, i) => 32 - i).map((m) => <option key={m} value={m}>/{m}</option>)}
            </select>
          )}
        </div>
      </Field>
      {ports && (
        <Field label={`${label} port`} help="A port, a range (1000:2000) or a port alias. Empty = any.">
          <input value={value.port ?? ''} placeholder="any" size={14} list="pf-port-aliases" aria-label={`${label} port`} onChange={(e) => onChange({ ...value, port: e.target.value.trim() || undefined })} />
        </Field>
      )}
    </>
  );
}

// ---------------------------------------------------------------- the component

export function PfWebConfigurator({ getWorld, setWorld, hostId, fromHost, fromUser, visible, banner }: {
  getWorld: () => World;
  setWorld: (w: World) => void;
  /** The pfSense host. */
  hostId: string;
  /** The machine and user whose browser is used. */
  fromHost: string;
  fromUser: string;
  visible: boolean;
  /** Shown under the login form (who is browsing, the credentials). */
  banner?: string;
}) {
  const [, setTick] = useState(0);
  const refresh = () => setTick((t) => t + 1);
  const [loggedIn, setLoggedIn] = useState(false);
  const [page, setPage] = useState<Page>({ p: 'dashboard' });
  const [errors, setErrors] = useState<string[]>([]);
  const [notice, setNotice] = useState('');
  const [loadKey, setLoadKey] = useState(0);
  // Re-read the machines when the tab is shown (terminals may have changed them).
  useEffect(() => { if (visible) refresh(); }, [visible]);

  const world = getWorld();
  const host = world.hosts[hostId];
  const ip = host.ifaces.find((i) => i.name === 'vtnet1')?.address ?? host.ifaces.find((i) => i.address && i.name !== 'lo0' && i.name !== 'lo')?.address ?? hostId;
  const base = `https://${ip}/`;
  const url = base + (loggedIn ? URLS[page.p] + (page.p === 'rules' ? `?if=${page.iface}` : page.p === 'iface' ? `?if=${page.key}` : '') : '');
  // Each navigation (loadKey) is a new request from the client.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reach = useMemo(() => browse(world, fromHost, fromUser, base), [loadKey, base, visible]);

  let cfg: PfConfig | null = null;
  let cfgError = '';
  try { cfg = readConfig(host); } catch (e) { cfgError = (e as Error).message; }

  const go = (p: Page) => { setPage(p); setErrors([]); setNotice(''); setLoadKey((k) => k + 1); };
  const save = (sub: Subsystem, what: string, edit: (c: PfConfig, clock: number) => string[], then?: Page) => {
    const r = guiSave(getWorld(), hostId, sub, edit, what);
    if (r.errors.length) { setErrors(r.errors); return false; }
    setWorld(r.world);
    setErrors([]);
    if (then) { setPage(then); setLoadKey((k) => k + 1); }
    refresh();
    return true;
  };
  const apply = () => {
    const r = guiApply(getWorld(), hostId);
    setWorld(r.world);
    setErrors(r.errors.length ? ['There were error(s) loading the rules:', ...r.errors] : []);
    setNotice(r.errors.length ? '' : 'The changes have been applied successfully. The firewall rules are now reloading in the background.');
    setLoadKey((k) => k + 1);
    refresh();
  };

  const chrome = (
    <div className="row small" style={{ background: 'var(--panel-2)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 8px', gap: 6, flexWrap: 'nowrap' }}>
      <button className="link" title="Reload" onClick={() => setLoadKey((k) => k + 1)}>⟳</button>
      <span className="badge err" title="The webConfigurator uses a self-signed certificate">Not secure</span>
      <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{url}</span>
      <span className="muted" style={{ marginLeft: 'auto', whiteSpace: 'nowrap' }}>browser on {fromHost}</span>
    </div>
  );

  const frame = (body: React.ReactNode) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, height: '100%', minHeight: 0 }}>
      {chrome}
      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', overflowX: 'hidden', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg)' }}>{body}</div>
    </div>
  );

  if (!reach.ok) {
    return frame(
      <div style={{ padding: 30 }}>
        <h2 style={{ marginTop: 0 }}>This site can't be reached</h2>
        <p>{reach.detail}</p>
        <p className="mono small muted">{reach.error}</p>
        <p className="small">The browser runs on {fromHost}: check the path from there (ping, curl -kv {base}) and fw01's rules from its console (pfctl -sr). The anti-lockout rule only covers clients on the LAN interface.</p>
        <button onClick={() => setLoadKey((k) => k + 1)}>Reload</button>
      </div>,
    );
  }

  if (!loggedIn) return frame(<Login banner={banner} onLogin={(u, p) => {
    const ok = host.users[u]?.password === p && (u === 'admin' || u === 'root');
    const w = structuredClone(getWorld());
    const client = w.hosts[fromHost].ifaces.find((i) => i.address && i.name !== 'lo')?.address ?? fromHost;
    sysLog(w, w.hosts[hostId], 'php-fpm', ok ? `/index.php: Successful login for user '${u}' from: ${client} (Local Database)` : `/index.php: webConfigurator authentication error for user '${u}' from: ${client}`);
    setWorld(w);
    if (ok) { setLoggedIn(true); go({ p: 'dashboard' }); }
    return ok;
  }} />);

  const pending = host.pf?.pending ?? [];
  const pfIfaces = cfg?.interfaces ?? [];

  const body = !cfg ? (
    <div className="callout err">The configuration file /conf/config.xml cannot be parsed: {cfgError}. Fix it from the console (viconfig) or restore a backup.</div>
  ) : (
    <>
      {pending.length > 0 && (
        <div className="callout warn row" style={{ justifyContent: 'space-between' }}>
          <span>{pending.includes('interfaces') ? 'The interface configuration has been changed.' : 'The firewall rule configuration has been changed.'} The changes must be applied for them to take effect.</span>
          <button className="primary" onClick={apply}>Apply Changes</button>
        </div>
      )}
      {notice && <div className="callout ok">{notice}</div>}
      {errors.length > 0 && (
        <div className="callout err"><strong>The following input errors were detected:</strong><ul style={{ margin: '4px 0' }}>{errors.map((e, i) => <li key={i}>{e}</li>)}</ul></div>
      )}
      <datalist id="pf-aliases">{cfg.aliases.filter((a) => a.type !== 'port').map((a) => <option key={a.name} value={a.name} />)}</datalist>
      <datalist id="pf-port-aliases">{cfg.aliases.filter((a) => a.type === 'port').map((a) => <option key={a.name} value={a.name} />)}</datalist>
      <PageBody cfg={cfg} page={page} go={go} save={save} world={world} hostId={hostId} />
    </>
  );

  return frame(
    <div>
      <div className="row" style={{ background: '#212121', color: '#eee', padding: '6px 12px', gap: 4 }}>
        <strong style={{ color: '#f0ad4e', marginRight: 10 }}>pf<span style={{ color: '#fff' }}>sense</span></strong>
        {NAV.map((n) => (
          <span key={n.label} className="row" style={{ gap: 2 }}>
            <span className="small" style={{ color: '#aaa', marginLeft: 6 }}>{n.label}:</span>
            {n.items.map((it) => (
              <button key={it.label} className="small" style={{ background: 'transparent', color: '#eee', border: '1px solid #444', padding: '2px 6px' }} onClick={() => go(it.page)}>{it.label}</button>
            ))}
            {n.label === 'Interfaces' && pfIfaces.map((i) => (
              <button key={i.key} className="small" style={{ background: 'transparent', color: '#eee', border: '1px solid #444', padding: '2px 6px' }} onClick={() => go({ p: 'iface', key: i.key })}>{i.descr}</button>
            ))}
          </span>
        ))}
        <button className="small" style={{ marginLeft: 'auto', background: 'transparent', color: '#eee', border: '1px solid #444', padding: '2px 6px' }} onClick={() => setLoggedIn(false)}>Logout (admin)</button>
      </div>
      <div style={{ padding: '10px 14px' }}>
        <h3 style={{ marginTop: 0 }}>{TITLES[page.p]}{page.p === 'iface' && cfg ? ` / ${ifaceLabel(cfg, page.key)} (${pfIfaces.find((i) => i.key === page.key)?.if ?? ''})` : ''}</h3>
        {body}
      </div>
    </div>,
  );
}

function Login({ onLogin, banner }: { onLogin: (u: string, p: string) => boolean; banner?: string }) {
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [bad, setBad] = useState(false);
  return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
      <form className="card" style={{ width: 300 }} onSubmit={(e) => { e.preventDefault(); setBad(!onLogin(u, p)); }}>
        <h3 style={{ marginTop: 0 }}><span style={{ color: '#d9822b' }}>pf</span>sense <span className="small muted">Login to pfSense</span></h3>
        {bad && <div className="feedback bad small">Username or Password incorrect</div>}
        <div style={{ display: 'grid', gap: 8 }}>
          <input placeholder="Username" aria-label="Username" value={u} onChange={(e) => setU(e.target.value)} autoCapitalize="none" />
          <input placeholder="Password" aria-label="Password" type="password" value={p} onChange={(e) => setP(e.target.value)} />
          <button className="primary" type="submit">Sign In</button>
        </div>
        {banner && <p className="small muted" style={{ marginBottom: 0 }}>{banner}</p>}
      </form>
    </div>
  );
}

// ---------------------------------------------------------------- pages

type SaveFn = (sub: Subsystem, what: string, edit: (c: PfConfig, clock: number) => string[], then?: Page) => boolean;

function PageBody({ cfg, page, go, save, world, hostId }: { cfg: PfConfig; page: Page; go: (p: Page) => void; save: SaveFn; world: World; hostId: string }) {
  const host = world.hosts[hostId];
  switch (page.p) {
    case 'dashboard': {
      const up = Math.max(0, Math.floor((world.clock - host.bootTime) / 1000));
      return (
        <div className="grid2">
          <Panel title="System Information">
            <table style={{ margin: 0 }}><tbody>
              <tr><th>Name</th><td>{cfg.hostname}.{cfg.domain}</td></tr>
              <tr><th>Version</th><td>{PF_VERSION} (amd64)</td></tr>
              <tr><th>Uptime</th><td>{Math.floor(up / 3600)} Hours {Math.floor((up % 3600) / 60)} Minutes {up % 60} Seconds</td></tr>
              <tr><th>DNS server(s)</th><td>{cfg.dnsservers.join(', ')}</td></tr>
              <tr><th>State table size</th><td>{host.conntrack.length} states</td></tr>
              <tr><th>Packet filter</th><td>{host.pf?.enabled ? 'enabled' : <span className="badge err">disabled (pfctl -d)</span>}</td></tr>
            </tbody></table>
          </Panel>
          <Panel title="Interfaces">
            <table style={{ margin: 0 }}><tbody>
              {cfg.interfaces.map((i) => {
                const hi = host.ifaces.find((x) => x.name === i.if);
                return <tr key={i.key}><td>{hi?.up ? '▲' : '▼'} {i.descr}</td><td className="mono">{i.if}</td><td className="mono">{hi?.address ? `${hi.address}/${hi.prefix}` : 'n/a'}</td></tr>;
              })}
            </tbody></table>
          </Panel>
        </div>
      );
    }
    case 'assign': return <Assignments cfg={cfg} save={save} ports={availablePorts(cfg, host.ifaces.map((i) => i.name))} go={go} />;
    case 'iface': return <InterfaceEdit key={page.key} cfg={cfg} ikey={page.key} save={save} />;
    case 'aliases': return <Aliases cfg={cfg} go={go} save={save} />;
    case 'alias': return <AliasEdit cfg={cfg} name={page.name} save={save} go={go} />;
    case 'rules': return <Rules cfg={cfg} iface={page.iface} go={go} save={save} world={world} hostId={hostId} />;
    case 'rule': return <RuleEdit key={`${page.iface}-${page.tracker}`} cfg={cfg} iface={page.iface} tracker={page.tracker} save={save} go={go} />;
    case 'nat': return <PortForwards cfg={cfg} go={go} save={save} />;
    case 'natedit': return <PortForwardEdit cfg={cfg} index={page.index} save={save} go={go} />;
    case 'outbound': return <Outbound cfg={cfg} save={save} go={go} />;
    case 'logs': {
      const entries = firewallLog(world, hostId, cfg);
      return (
        <Panel title={`Last ${Math.min(entries.length, 50)} Firewall Log Entries`}>
          {entries.length === 0 ? <p className="small muted" style={{ padding: 10 }}>No log entries. Blocked packets appear here (the default deny and rules with Log enabled).</p> : (
            <table style={{ margin: 0 }} className="small">
              <thead><tr><th>Action</th><th>Time</th><th>Interface</th><th>Rule</th><th>Source</th><th>Destination</th><th>Protocol</th></tr></thead>
              <tbody>{entries.slice(0, 50).map((e, i) => (
                <tr key={i}><td>{e.action === 'pass' ? <span className="badge ok">✓ pass</span> : <span className="badge err">✗ block</span>}</td><td className="mono">{e.time}</td><td>{e.iface}</td><td>{e.rule}</td><td className="mono">{e.src}</td><td className="mono">{e.dst}</td><td>{e.proto}</td></tr>
              ))}</tbody>
            </table>
          )}
        </Panel>
      );
    }
    case 'states': {
      const nat = host.nat;
      return (
        <Panel title={`States (${host.conntrack.length})`}>
          {host.conntrack.length === 0 ? <p className="small muted" style={{ padding: 10 }}>No states.</p> : (
            <table style={{ margin: 0 }} className="small mono">
              <thead><tr><th>Protocol</th><th>Source (Original Source) → Destination (Original Destination)</th><th>State</th></tr></thead>
              <tbody>{host.conntrack.map((c, i) => {
                const n = nat.find((x) => x.orig.src === c.src && x.orig.sport === c.sport && x.orig.dst === c.dst && x.orig.dport === c.dport);
                const dst = n && n.trans.dst !== c.dst ? `${n.trans.dst}:${n.trans.dport} (${c.dst}:${c.dport})` : `${c.dst}:${c.dport}`;
                const src = n && n.trans.src !== c.src ? `${n.trans.src}:${n.trans.sport} (${c.src}:${c.sport})` : `${c.src}:${c.sport}`;
                return <tr key={i}><td>{c.proto}</td><td>{src} → {dst}</td><td>{c.state}</td></tr>;
              })}</tbody>
            </table>
          )}
        </Panel>
      );
    }
  }
}

function Assignments({ cfg, save, ports, go }: { cfg: PfConfig; save: SaveFn; ports: string[]; go: (p: Page) => void }) {
  const [port, setPort] = useState(ports[0] ?? '');
  useEffect(() => { if (!ports.includes(port)) setPort(ports[0] ?? ''); }, [ports, port]);
  return (
    <Panel title="Interface Assignments">
      <table style={{ margin: 0 }}>
        <thead><tr><th>Interface</th><th>Network port</th><th /></tr></thead>
        <tbody>
          {cfg.interfaces.map((i) => (
            <tr key={i.key}>
              <td><button className="link" onClick={() => go({ p: 'iface', key: i.key })}>{i.descr}</button> <span className="small muted">({i.key})</span></td>
              <td className="mono">{i.if}</td>
              <td>{i.key !== 'wan' && i.key !== 'lan' && <button className="danger small" onClick={() => save('interfaces', 'interfaces_assign.php', (c) => deleteInterface(c, i.key))}>Delete</button>}</td>
            </tr>
          ))}
          <tr>
            <td>Available network ports:</td>
            <td>{ports.length ? <select value={port} aria-label="Available network ports" onChange={(e) => setPort(e.target.value)}>{ports.map((p) => <option key={p}>{p}</option>)}</select> : <span className="muted small">none</span>}</td>
            <td>{ports.length > 0 && <button className="primary small" onClick={() => save('interfaces', 'interfaces_assign.php', (c) => assignInterface(c, port))}>+ Add</button>}</td>
          </tr>
        </tbody>
      </table>
      <p className="small muted" style={{ padding: '0 10px' }}>A new interface is assigned as OPTn, disabled and without an address: open it to enable and configure it.</p>
    </Panel>
  );
}

function InterfaceEdit({ cfg, ikey, save }: { cfg: PfConfig; ikey: string; save: SaveFn }) {
  const i = cfg.interfaces.find((x) => x.key === ikey);
  const [enable, setEnable] = useState(!!i?.enable);
  const [descr, setDescr] = useState(i?.descr ?? '');
  const [ipaddr, setIp] = useState(i?.ipaddr ?? '');
  const [subnet, setSubnet] = useState(i?.subnet ?? 24);
  if (!i) return <p>The interface does not exist.</p>;
  return (
    <Panel title="General Configuration">
      <Field label="Enable"><label className="small"><input type="checkbox" checked={enable} onChange={(e) => setEnable(e.target.checked)} /> Enable interface</label></Field>
      <Field label="Description" help="Letters, digits and underscores (shown in the menus and rule tabs)."><input value={descr} aria-label="Description" onChange={(e) => setDescr(e.target.value)} /></Field>
      <Field label="IPv4 Configuration Type">{i.gateway ? 'Static IPv4 (upstream gateway ' + i.gateway + ')' : 'Static IPv4'}</Field>
      <Field label="IPv4 Address">
        <div className="row">
          <input value={ipaddr} aria-label="IPv4 Address" onChange={(e) => setIp(e.target.value.trim())} size={16} />
          <select value={subnet} aria-label="Subnet mask" onChange={(e) => setSubnet(Number(e.target.value))}>{Array.from({ length: 32 }, (_, k) => 32 - k).map((m) => <option key={m} value={m}>/{m}</option>)}</select>
        </div>
      </Field>
      <div style={{ padding: 10 }}>
        <button className="primary" onClick={() => save('interfaces', `interfaces.php?if=${ikey}`, (c) => saveInterface(c, ikey, { enable, descr, ipaddr, subnet }))}>Save</button>
      </div>
    </Panel>
  );
}

function Aliases({ cfg, go, save }: { cfg: PfConfig; go: (p: Page) => void; save: SaveFn }) {
  return (
    <Panel title="Firewall Aliases">
      <table style={{ margin: 0 }} className="small">
        <thead><tr><th>Name</th><th>Type</th><th>Values</th><th>Description</th><th /></tr></thead>
        <tbody>
          {cfg.aliases.length === 0 && <tr><td colSpan={5} className="muted">No aliases.</td></tr>}
          {cfg.aliases.map((a) => (
            <tr key={a.name}>
              <td className="mono">{a.name}</td><td>{a.type}</td><td className="mono">{a.address.join(', ')}</td><td>{a.descr}</td>
              <td className="row" style={{ gap: 4 }}>
                <button className="small" onClick={() => go({ p: 'alias', name: a.name })}>Edit</button>
                <button className="small danger" title={aliasUsers(cfg, a.name).length ? `Used by: ${aliasUsers(cfg, a.name).join(', ')}` : 'Delete'} onClick={() => save('filter', 'firewall_aliases.php', (c) => deleteAlias(c, a.name))}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ padding: 10 }}><button className="primary" onClick={() => go({ p: 'alias', name: null })}>+ Add</button></div>
    </Panel>
  );
}

function AliasEdit({ cfg, name, save, go }: { cfg: PfConfig; name: string | null; save: SaveFn; go: (p: Page) => void }) {
  const orig = name ? cfg.aliases.find((a) => a.name === name) : undefined;
  const [a, setA] = useState<PfAlias>(orig ? { ...orig, address: [...orig.address] } : { name: '', type: 'host', address: [''], descr: '' });
  const set = (patch: Partial<PfAlias>) => setA((x) => ({ ...x, ...patch }));
  return (
    <Panel title="Properties">
      <Field label="Name"><input value={a.name} aria-label="Alias name" onChange={(e) => set({ name: e.target.value })} /></Field>
      <Field label="Description"><input value={a.descr} aria-label="Alias description" size={40} onChange={(e) => set({ descr: e.target.value })} /></Field>
      <Field label="Type">
        <select value={a.type} aria-label="Alias type" onChange={(e) => set({ type: e.target.value as PfAlias['type'] })}>
          <option value="host">Host(s)</option><option value="network">Network(s)</option><option value="port">Port(s)</option>
        </select>
      </Field>
      <Field label={a.type === 'host' ? 'IP or FQDN' : a.type === 'network' ? 'Network or FQDN' : 'Port'} help={a.type === 'network' ? 'CIDR notation: 10.0.0.0/16' : a.type === 'port' ? 'A port or a range (1000:2000)' : 'One IPv4 address per entry'}>
        <div style={{ display: 'grid', gap: 4 }}>
          {a.address.map((x, i) => (
            <div key={i} className="row">
              <input value={x} aria-label={`Entry ${i + 1}`} onChange={(e) => set({ address: a.address.map((y, j) => (j === i ? e.target.value : y)) })} />
              <button className="small danger" onClick={() => set({ address: a.address.filter((_, j) => j !== i) })}>Delete</button>
            </div>
          ))}
          <div><button className="small" onClick={() => set({ address: [...a.address, ''] })}>+ Add Host</button></div>
        </div>
      </Field>
      <div className="row" style={{ padding: 10 }}>
        <button className="primary" onClick={() => save('filter', 'firewall_aliases_edit.php', (c) => saveAlias(c, a, name), { p: 'aliases' })}>Save</button>
        <button onClick={() => go({ p: 'aliases' })}>Cancel</button>
      </div>
    </Panel>
  );
}

function Rules({ cfg, iface, go, save, world, hostId }: { cfg: PfConfig; iface: string; go: (p: Page) => void; save: SaveFn; world: World; hostId: string }) {
  const rules = cfg.filter.filter((r) => r.interface === iface);
  const rt = world.hosts[hostId].pf;
  const counter = (r: PfRule) => {
    const line = rt?.lines.find((l) => l.text.endsWith(`label "USER_RULE: ${r.descr}"`));
    if (!line) return '';
    const all = rt!.ruleset.tables.flatMap((t) => t.chains.flatMap((c) => c.rules)).filter((x) => line.handles.includes(x.handle));
    const p = all.reduce((n, x) => n + (x.counter?.packets ?? 0), 0);
    return `${p} pkts`;
  };
  const i = cfg.interfaces.find((x) => x.key === iface);
  return (
    <>
      <div className="tabs" style={{ marginTop: 0 }}>
        {cfg.interfaces.map((x) => <button key={x.key} className={x.key === iface ? 'active' : ''} onClick={() => go({ p: 'rules', iface: x.key })}>{x.descr}</button>)}
      </div>
      <Panel title={`Rules (Drag to Change Order)`}>
        <table style={{ margin: 0 }} className="small">
          <thead><tr><th /><th>States</th><th>Protocol</th><th>Source</th><th>Port</th><th>Destination</th><th>Port</th><th>Description</th><th>Actions</th></tr></thead>
          <tbody>
            {iface === 'lan' && cfg.antiLockout && (
              <tr className="muted"><td>✓</td><td /><td>*</td><td>*</td><td>*</td><td>LAN Address</td><td>443, 80{cfg.sshEnabled ? ', 22' : ''}</td><td>Anti-Lockout Rule</td><td /></tr>
            )}
            {i?.blockpriv && <tr className="muted"><td>✗</td><td /><td>*</td><td>RFC 1918 networks</td><td>*</td><td>*</td><td>*</td><td>Block private networks</td><td /></tr>}
            {rules.length === 0 && <tr><td colSpan={9} className="muted">No rules are currently defined for this interface. All incoming connections on this interface will be blocked until pass rules are added.</td></tr>}
            {rules.map((r) => (
              <tr key={r.tracker} style={{ opacity: r.disabled ? 0.5 : 1 }}>
                <td title={r.type}>{r.type === 'pass' ? <span style={{ color: 'var(--ok)' }}>✓</span> : r.type === 'block' ? <span style={{ color: 'var(--err)' }}>✗</span> : <span style={{ color: 'var(--warn)' }}>✗↩</span>}{r.log ? ' 📋' : ''}</td>
                <td className="mono">{counter(r)}</td>
                <td>{r.protocol ? r.protocol.toUpperCase() : '*'}</td>
                <td>{addrLabel(cfg, r.source)}</td><td>{r.source.port ?? '*'}</td>
                <td>{addrLabel(cfg, r.destination)}</td><td>{r.destination.port ?? '*'}</td>
                <td>{r.descr}{r.associatedRuleId && <span className="badge" style={{ marginLeft: 4 }}>NAT</span>}</td>
                <td><div className="row" style={{ gap: 2, minWidth: 104 }}>
                  <button className="small" title="Move up" onClick={() => save('filter', 'firewall_rules.php', (c) => moveRule(c, r.tracker, -1))}>↑</button>
                  <button className="small" title="Move down" onClick={() => save('filter', 'firewall_rules.php', (c) => moveRule(c, r.tracker, 1))}>↓</button>
                  <button className="small" onClick={() => go({ p: 'rule', iface, tracker: r.tracker })}>Edit</button>
                  <button className="small" onClick={() => save('filter', 'firewall_rules.php', (c) => toggleRule(c, r.tracker))}>{r.disabled ? 'Enable' : 'Disable'}</button>
                  <button className="small danger" onClick={() => save('filter', 'firewall_rules.php', (c) => deleteRule(c, r.tracker))}>Delete</button>
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="row" style={{ padding: 10 }}>
          <button className="primary" onClick={() => go({ p: 'rule', iface, tracker: 'new-top' })}>↑ Add (top)</button>
          <button className="primary" onClick={() => go({ p: 'rule', iface, tracker: null })}>↓ Add (bottom)</button>
          <span className="small muted">Rules are evaluated on a first-match basis, top to bottom, on traffic entering {ifaceLabel(cfg, iface)}. Anything not passed is blocked (and logged) by the default deny.</span>
        </div>
      </Panel>
    </>
  );
}

function RuleEdit({ cfg, iface, tracker, save, go }: { cfg: PfConfig; iface: string; tracker: string | null; save: SaveFn; go: (p: Page) => void }) {
  const isNew = tracker === null || tracker === 'new-top';
  const orig = isNew ? undefined : cfg.filter.find((r) => r.tracker === tracker);
  const [r, setR] = useState<PfRule>(orig ? structuredClone(orig) : { tracker: '', type: 'pass', interface: iface, protocol: 'tcp', source: { any: true }, destination: { any: true }, descr: '', disabled: false, log: false });
  const set = (patch: Partial<PfRule>) => setR((x) => ({ ...x, ...patch }));
  const ports = r.protocol === 'tcp' || r.protocol === 'udp' || r.protocol === 'tcp/udp';
  const strip = (a: PfAddr): PfAddr => (ports ? a : { ...a, port: undefined });
  return (
    <Panel title="Edit Firewall Rule">
      <Field label="Action" help="Block silently drops; Reject answers with TCP RST or ICMP port unreachable.">
        <select value={r.type} aria-label="Action" onChange={(e) => set({ type: e.target.value as PfRule['type'] })}><option value="pass">Pass</option><option value="block">Block</option><option value="reject">Reject</option></select>
      </Field>
      <Field label="Disabled"><label className="small"><input type="checkbox" checked={r.disabled} onChange={(e) => set({ disabled: e.target.checked })} /> Disable this rule</label></Field>
      <Field label="Interface" help="The interface the traffic enters the firewall on.">
        <select value={r.interface} aria-label="Interface" onChange={(e) => set({ interface: e.target.value })}>{cfg.interfaces.map((i) => <option key={i.key} value={i.key}>{i.descr}</option>)}</select>
      </Field>
      <Field label="Protocol">
        <select value={r.protocol ?? 'any'} aria-label="Protocol" onChange={(e) => set({ protocol: e.target.value === 'any' ? undefined : e.target.value })}>
          <option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp/udp">TCP/UDP</option><option value="icmp">ICMP</option><option value="any">Any</option>
        </select>
      </Field>
      <AddrEditor cfg={cfg} label="Source" value={r.source} ports={ports} onChange={(a) => set({ source: a })} />
      <AddrEditor cfg={cfg} label="Destination" value={r.destination} ports={ports} onChange={(a) => set({ destination: a })} />
      <Field label="Log"><label className="small"><input type="checkbox" checked={r.log} onChange={(e) => set({ log: e.target.checked })} /> Log packets that are handled by this rule</label></Field>
      <Field label="Description"><input value={r.descr} size={50} aria-label="Rule description" onChange={(e) => set({ descr: e.target.value })} /></Field>
      <div className="row" style={{ padding: 10 }}>
        <button className="primary" onClick={() => save('filter', 'firewall_rules_edit.php', (c, clock) => saveRule(c, { ...r, source: strip(r.source), destination: strip(r.destination) }, isNew ? null : tracker, clock, tracker === 'new-top' ? 'top' : 'bottom'), { p: 'rules', iface: r.interface })}>Save</button>
        <button onClick={() => go({ p: 'rules', iface })}>Cancel</button>
      </div>
    </Panel>
  );
}

function PortForwards({ cfg, go, save }: { cfg: PfConfig; go: (p: Page) => void; save: SaveFn }) {
  return (
    <>
      <div className="tabs" style={{ marginTop: 0 }}>
        <button className="active">Port Forward</button>
        <button onClick={() => go({ p: 'outbound' })}>Outbound</button>
      </div>
      <Panel title="Rules">
        <table style={{ margin: 0 }} className="small">
          <thead><tr><th /><th>Interface</th><th>Protocol</th><th>Source</th><th>Dest. Address</th><th>Dest. Ports</th><th>NAT IP</th><th>NAT Ports</th><th>Description</th><th /></tr></thead>
          <tbody>
            {cfg.nat.length === 0 && <tr><td colSpan={10} className="muted">No port forwards.</td></tr>}
            {cfg.nat.map((n, i) => (
              <tr key={i} style={{ opacity: n.disabled ? 0.5 : 1 }}>
                <td title={n.associatedRuleId ? 'Has an associated filter rule' : 'No associated filter rule'}>{n.associatedRuleId ? '🔗' : ''}</td>
                <td>{ifaceLabel(cfg, n.interface)}</td><td>{n.protocol.toUpperCase()}</td><td>{addrLabel(cfg, n.source)}</td>
                <td>{addrLabel(cfg, n.destination)}</td><td>{n.destination.port}</td><td className="mono">{n.target}</td><td>{n.localPort || n.destination.port}</td><td>{n.descr}</td>
                <td className="row" style={{ gap: 2, flexWrap: 'nowrap' }}>
                  <button className="small" onClick={() => go({ p: 'natedit', index: i })}>Edit</button>
                  <button className="small danger" onClick={() => save('filter', 'firewall_nat.php', (c) => deletePortForward(c, i))}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ padding: 10 }}><button className="primary" onClick={() => go({ p: 'natedit', index: null })}>+ Add</button></div>
      </Panel>
    </>
  );
}

function PortForwardEdit({ cfg, index, save, go }: { cfg: PfConfig; index: number | null; save: SaveFn; go: (p: Page) => void }) {
  const orig = index === null ? undefined : cfg.nat[index];
  const [n, setN] = useState<PfNatRule>(orig ? structuredClone(orig) : { interface: 'wan', protocol: 'tcp', source: { any: true }, destination: { network: 'wanip' }, target: '', localPort: '', descr: '', disabled: false });
  const [assoc, setAssoc] = useState<FilterAssoc>(orig ? (orig.associatedRuleId ? 'associated' : 'none') : 'associated');
  const set = (patch: Partial<PfNatRule>) => setN((x) => ({ ...x, ...patch }));
  return (
    <Panel title="Edit Redirect Entry">
      <Field label="Disabled"><label className="small"><input type="checkbox" checked={n.disabled} onChange={(e) => set({ disabled: e.target.checked })} /> Disable this rule</label></Field>
      <Field label="Interface" help="Usually WAN: where the connections to translate arrive.">
        <select value={n.interface} aria-label="NAT interface" onChange={(e) => set({ interface: e.target.value })}>{cfg.interfaces.map((i) => <option key={i.key} value={i.key}>{i.descr}</option>)}</select>
      </Field>
      <Field label="Protocol">
        <select value={n.protocol} aria-label="NAT protocol" onChange={(e) => set({ protocol: e.target.value })}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp/udp">TCP/UDP</option></select>
      </Field>
      <AddrEditor cfg={cfg} label="Source" value={n.source} ports={false} onChange={(a) => set({ source: a })} />
      <AddrEditor cfg={cfg} label="Destination" value={n.destination} ports onChange={(a) => set({ destination: a })} />
      <Field label="Redirect target IP" help="The internal host (an address or a host alias).">
        <input value={n.target} aria-label="Redirect target IP" list="pf-aliases" onChange={(e) => set({ target: e.target.value.trim() })} />
      </Field>
      <Field label="Redirect target port" help="Empty = same as the destination port.">
        <input value={n.localPort} aria-label="Redirect target port" list="pf-port-aliases" onChange={(e) => set({ localPort: e.target.value.trim() })} />
      </Field>
      <Field label="Description"><input value={n.descr} size={50} aria-label="NAT description" onChange={(e) => set({ descr: e.target.value })} /></Field>
      <Field label="Filter rule association" help="A port forward only translates: without a pass rule the default deny drops the translated traffic.">
        <select value={assoc} aria-label="Filter rule association" onChange={(e) => setAssoc(e.target.value as FilterAssoc)}>
          <option value="associated">Add associated filter rule</option>
          {!orig && <option value="unassociated">Add unassociated filter rule</option>}
          <option value="none">None</option>
        </select>
      </Field>
      <div className="row" style={{ padding: 10 }}>
        <button className="primary" onClick={() => save('filter', 'firewall_nat_edit.php', (c, clock) => savePortForward(c, n, index, assoc, clock), { p: 'nat' })}>Save</button>
        <button onClick={() => go({ p: 'nat' })}>Cancel</button>
      </div>
    </Panel>
  );
}

function Outbound({ cfg, save, go }: { cfg: PfConfig; save: SaveFn; go: (p: Page) => void }) {
  const [mode, setMode] = useState(cfg.outbound.mode);
  const blank: PfOutboundRule = { interface: 'wan', source: '', destination: 'any', target: '', descr: '', disabled: false };
  const [draft, setDraft] = useState<PfOutboundRule>(blank);
  const modes: [PfConfig['outbound']['mode'], string, string][] = [
    ['automatic', 'Automatic outbound NAT rule generation', '(IPsec passthrough included)'],
    ['hybrid', 'Hybrid Outbound NAT rule generation', '(Automatic Outbound NAT + rules below)'],
    ['advanced', 'Manual Outbound NAT rule generation', '(AON - Advanced Outbound NAT)'],
    ['disabled', 'Disable Outbound NAT rule generation', '(No Outbound NAT rules)'],
  ];
  return (
    <>
      <div className="tabs" style={{ marginTop: 0 }}>
        <button onClick={() => go({ p: 'nat' })}>Port Forward</button>
        <button className="active">Outbound</button>
      </div>
      <Panel title="Outbound NAT Mode">
        <div style={{ padding: 10, display: 'grid', gap: 4 }}>
          {modes.map(([m, l, s]) => <label key={m} className="small"><input type="radio" name="pf-outbound-mode" checked={mode === m} onChange={() => setMode(m)} /> <strong>{l}</strong> <span className="muted">{s}</span></label>)}
          <div><button className="primary" onClick={() => save('filter', 'firewall_nat_out.php', (c) => setOutboundMode(c, mode))}>Save</button></div>
        </div>
      </Panel>
      <Panel title="Mappings">
        <table style={{ margin: 0 }} className="small">
          <thead><tr><th>Interface</th><th>Source</th><th>Destination</th><th>NAT Address</th><th>Description</th><th /></tr></thead>
          <tbody>
            {cfg.outbound.rules.length === 0 && <tr><td colSpan={6} className="muted">No mappings.</td></tr>}
            {cfg.outbound.rules.map((r, i) => (
              <tr key={i} style={{ opacity: r.disabled ? 0.5 : 1 }}>
                <td>{ifaceLabel(cfg, r.interface)}</td><td className="mono">{r.source}</td><td className="mono">{r.destination}</td><td>{r.target || `${ifaceLabel(cfg, r.interface)} address`}</td><td>{r.descr}</td>
                <td><button className="small danger" onClick={() => save('filter', 'firewall_nat_out.php', (c) => deleteOutbound(c, i))}>Delete</button></td>
              </tr>
            ))}
            <tr>
              <td><select value={draft.interface} aria-label="Outbound interface" onChange={(e) => setDraft({ ...draft, interface: e.target.value })}>{cfg.interfaces.map((x) => <option key={x.key} value={x.key}>{x.descr}</option>)}</select></td>
              <td><input value={draft.source} placeholder="172.16.50.0/24" size={15} aria-label="Outbound source" onChange={(e) => setDraft({ ...draft, source: e.target.value.trim() })} /></td>
              <td><input value={draft.destination} size={10} aria-label="Outbound destination" onChange={(e) => setDraft({ ...draft, destination: e.target.value.trim() || 'any' })} /></td>
              <td><input value={draft.target} placeholder="interface address" size={14} aria-label="Outbound NAT address" onChange={(e) => setDraft({ ...draft, target: e.target.value.trim() })} /></td>
              <td><input value={draft.descr} size={18} aria-label="Outbound description" onChange={(e) => setDraft({ ...draft, descr: e.target.value })} /></td>
              <td><button className="small primary" onClick={() => { if (save('filter', 'firewall_nat_out_edit.php', (c) => saveOutbound(c, draft, null))) setDraft(blank); }}>+ Add</button></td>
            </tr>
          </tbody>
        </table>
        <p className="small muted" style={{ padding: '0 10px' }}>{cfg.outbound.mode === 'automatic' ? 'In automatic mode the mappings are generated: every internal interface network and static route is translated to the WAN address. These rules are ignored.' : cfg.outbound.mode === 'disabled' ? 'Outbound NAT is disabled: nothing is translated.' : cfg.outbound.mode === 'hybrid' ? 'These mappings are applied before the automatic ones.' : 'Only these mappings are applied: a network without a mapping leaves with its private source address.'}</p>
      </Panel>
    </>
  );
}
