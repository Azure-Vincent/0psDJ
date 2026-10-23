import { useMemo, useRef, useState, type PointerEvent as RPointerEvent } from 'react';
import { BUILDER_PASSWORD, BUILDER_USER, buildDesignWorld, hostsFile, interfacesFile, loginUser, nftablesFile, rebootDesignWorld, segmentLabel, switchInterfacesFile, traceCommand, type TraceResult } from '../../engine/builder/build';
import { addressOf, freeIface, isSubInterface, newId, normalizeDesign, renameIfaces, validateDesign, type AllowRule, type Design, type DesignLink, type DesignNode, type ForwardRule, type NodeKind, type SwitchPort } from '../../engine/builder/design';
import { DESIGN_TEMPLATES, EMPTY_DESIGN } from '../../engine/builder/templates';
import type { World } from '../../engine/types';
import { LabTerminals } from '../components/LabTerminals';
import { SequenceDiagram, type Lane } from '../components/SequenceDiagram';

const STORE = 'infralab.builder.v1';
const W = 760, H = 460;
const KIND_LABEL: Record<NodeKind, string> = { host: 'Workstation', server: 'Server', router: 'Router', switch: 'Switch' };
const KIND_ICON: Record<NodeKind, string> = { host: '🖥', server: '🗄', router: '⇄', switch: '⋮⋮' };
const KIND_COLOR: Record<NodeKind, string> = { host: 'var(--c-blue)', server: 'var(--c-green)', router: 'var(--c-orange)', switch: 'var(--c-teal)' };

// The running network survives navigation within the session (not reloads).
let LIVE: { world: World; design: Design } | null = null;

function load(): Design {
  try {
    const s = localStorage.getItem(STORE);
    if (s) {
      return normalizeDesign(JSON.parse(s));
    }
  } catch { /* storage unavailable */ }
  return DESIGN_TEMPLATES[0].design();
}

function save(d: Design) {
  try { localStorage.setItem(STORE, JSON.stringify(d)); } catch { /* storage unavailable */ }
}

function uniqueName(d: Design, base: string): string {
  for (let k = 1; ; k++) if (!d.nodes.some((n) => n.name === `${base}${k}`)) return `${base}${k}`;
}

function newNode(d: Design, kind: NodeKind, x: number, y: number): DesignNode {
  const id = newId('n');
  switch (kind) {
    case 'host': return { id, kind, name: uniqueName(d, 'pc'), x, y, ifaces: [{ name: 'eth0' }] };
    case 'server': return { id, kind, name: uniqueName(d, 'srv'), x, y, ifaces: [{ name: 'eth0' }], services: ['ssh', 'web'] };
    case 'router': return { id, kind, name: uniqueName(d, 'r'), x, y, ifaces: [{ name: 'eth0' }, { name: 'eth1' }], services: ['ssh'] };
    case 'switch': return { id, kind, name: uniqueName(d, 'sw'), x, y, ifaces: [], ports: Array.from({ length: 8 }, (_, k) => ({ name: `swp${k + 1}`, mode: 'access' as const, vlan: 1 })) };
  }
}

function nextPhys(n: DesignNode): string {
  for (let k = 0; ; k++) if (!n.ifaces.some((i) => i.name === `eth${k}`)) return `eth${k}`;
}

function nextPort(n: DesignNode): string {
  for (let k = 1; ; k++) if (!(n.ports ?? []).some((p) => p.name === `swp${k}`)) return `swp${k}`;
}

/** Free interface of a node for a new cable; adds one when all are in use. */
function ensureFree(d: Design, n: DesignNode): { node: DesignNode; iface: string } {
  const f = freeIface(d, n);
  if (f) return { node: n, iface: f };
  if (n.kind === 'switch') {
    const name = nextPort(n);
    return { node: { ...n, ports: [...(n.ports ?? []), { name, mode: 'access', vlan: 1 }] }, iface: name };
  }
  const name = nextPhys(n);
  return { node: { ...n, ifaces: [...n.ifaces, { name }] }, iface: name };
}

function download(name: string, text: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---------------------------------------------------------------------------
// Canvas
// ---------------------------------------------------------------------------

function Canvas({ design, selected, connectFrom, problems, readOnly, onSelect, onMove, onNodeClick }: {
  design: Design;
  selected: string | null;
  connectFrom: string | null;
  problems: Set<string>;
  readOnly?: boolean;
  onSelect: (id: string | null) => void;
  onMove?: (id: string, x: number, y: number) => void;
  onNodeClick?: (id: string) => void;
}) {
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{ id: string; dx: number; dy: number; moved: boolean } | null>(null);
  const byId = new Map(design.nodes.map((n) => [n.id, n]));

  const toSvg = (e: { clientX: number; clientY: number }) => {
    const s = svg.current!;
    const pt = s.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const m = s.getScreenCTM();
    return m ? pt.matrixTransform(m.inverse()) : pt;
  };
  const down = (e: RPointerEvent, n: DesignNode) => {
    e.stopPropagation();
    if (readOnly) { onSelect(n.id); return; }
    const p = toSvg(e);
    drag.current = { id: n.id, dx: p.x - n.x, dy: p.y - n.y, moved: false };
    (e.target as Element).setPointerCapture?.(e.pointerId);
  };
  const move = (e: RPointerEvent) => {
    const d = drag.current;
    if (!d || !onMove) return;
    const p = toSvg(e);
    const x = Math.max(40, Math.min(W - 40, p.x - d.dx)), y = Math.max(30, Math.min(H - 40, p.y - d.dy));
    const n = byId.get(d.id)!;
    if (Math.abs(x - n.x) + Math.abs(y - n.y) > 2) d.moved = true;
    if (d.moved) onMove(d.id, Math.round(x), Math.round(y));
  };
  const up = () => {
    const d = drag.current;
    drag.current = null;
    if (d && !d.moved) (onNodeClick ?? onSelect)(d.id);
  };

  return (
    <svg ref={svg} viewBox={`0 0 ${W} ${H}`} className="builder-canvas" role="application" aria-label="Network design canvas"
      onPointerMove={move} onPointerUp={up} onPointerDown={() => onSelect(null)}>
      <defs>
        <pattern id="bgrid" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M 20 0 L 0 0 0 20" fill="none" stroke="var(--border)" strokeWidth="0.5" /></pattern>
      </defs>
      <rect width={W} height={H} fill="url(#bgrid)" />
      {design.links.map((l) => {
        const a = byId.get(l.a.node), b = byId.get(l.b.node);
        if (!a || !b) return null;
        const sel = selected === l.id;
        const lab = (from: DesignNode, to: DesignNode, txt: string) => {
          const t = 0.22;
          return <text x={from.x + (to.x - from.x) * t} y={from.y + (to.y - from.y) * t - 4} fontSize="10" textAnchor="middle" fill="var(--muted)">{txt}</text>;
        };
        return (
          <g key={l.id} onPointerDown={(e) => { e.stopPropagation(); onSelect(l.id); }} style={{ cursor: 'pointer' }}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="transparent" strokeWidth="12" />
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={problems.has(l.id) ? 'var(--err)' : sel ? 'var(--accent)' : 'var(--lane)'} strokeWidth={sel ? 3 : 2} />
            {lab(a, b, l.a.iface)}
            {lab(b, a, l.b.iface)}
          </g>
        );
      })}
      {design.nodes.map((n) => {
        const sel = selected === n.id || connectFrom === n.id;
        const addrs = n.ifaces.filter((i) => i.address?.trim()).map((i) => `${i.name} ${i.address}`);
        return (
          <g key={n.id} transform={`translate(${n.x},${n.y})`} onPointerDown={(e) => down(e, n)} style={{ cursor: readOnly ? 'pointer' : 'grab' }}>
            <rect x={-38} y={-22} width={76} height={44} rx={n.kind === 'router' ? 22 : 6} fill="var(--panel)" stroke={problems.has(n.id) ? 'var(--err)' : sel ? 'var(--accent)' : KIND_COLOR[n.kind]} strokeWidth={sel ? 3 : 2} strokeDasharray={connectFrom === n.id ? '4 3' : undefined} />
            <text y={-3} textAnchor="middle" fontSize="15" fill={KIND_COLOR[n.kind]}>{KIND_ICON[n.kind]}</text>
            <text y={14} textAnchor="middle" fontSize="11" fontWeight="600" fill="var(--text)">{n.name}</text>
            {addrs.slice(0, 3).map((a, i) => <text key={i} y={34 + i * 11} textAnchor="middle" fontSize="9.5" fill="var(--muted)">{a}</text>)}
            {addrs.length > 3 && <text y={34 + 33} textAnchor="middle" fontSize="9.5" fill="var(--muted)">+{addrs.length - 3} more</text>}
          </g>
        );
      })}
      {!design.nodes.length && <text x={W / 2} y={H / 2} textAnchor="middle" fill="var(--muted)" fontSize="14">Add devices with the buttons above, or start from a template.</text>}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Inspector
// ---------------------------------------------------------------------------

function numOrUndef(s: string): number | undefined {
  return s.trim() === '' ? undefined : Number(s);
}

function RuleRows<R extends AllowRule | ForwardRule>({ rules, onChange, forward }: { rules: R[]; onChange: (r: R[]) => void; forward?: boolean }) {
  const set = (i: number, patch: Partial<R>) => onChange(rules.map((r, k) => (k === i ? { ...r, ...patch } : r)));
  return (
    <div className="small">
      {rules.map((r, i) => (
        <div key={i} className="row" style={{ gap: 4, marginBottom: 4 }}>
          <select value={r.proto} onChange={(e) => set(i, { proto: e.target.value, port: e.target.value === 'tcp' || e.target.value === 'udp' ? r.port : undefined } as Partial<R>)} aria-label="Protocol">
            {forward && <option value="any">any</option>}
            <option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option>
          </select>
          <input style={{ width: 54 }} placeholder="port" value={r.port ?? ''} disabled={r.proto === 'icmp' || r.proto === 'any'} onChange={(e) => set(i, { port: numOrUndef(e.target.value) } as Partial<R>)} aria-label="Port" />
          <input style={{ width: 112 }} placeholder="from (any)" value={r.from ?? ''} onChange={(e) => set(i, { from: e.target.value } as Partial<R>)} aria-label="Source" />
          {forward && <input style={{ width: 112 }} placeholder="to (any)" value={(r as ForwardRule).to ?? ''} onChange={(e) => set(i, { to: e.target.value } as unknown as Partial<R>)} aria-label="Destination" />}
          <button className="link" onClick={() => onChange(rules.filter((_, k) => k !== i))} aria-label="Remove rule">✕</button>
        </div>
      ))}
      <button onClick={() => onChange([...rules, { proto: 'tcp', port: 22 } as R])}>+ rule</button>
    </div>
  );
}

/** Comma-separated VLAN list; keeps the text as typed ("10," while typing the next one). */
function VlanList({ value, onChange, label }: { value: number[]; onChange: (v: number[]) => void; label: string }) {
  const [text, setText] = useState(value.join(','));
  return <input style={{ width: 80 }} value={text} placeholder="10,20" aria-label={label} onChange={(e) => { setText(e.target.value); onChange(e.target.value.split(/[ ,]+/).filter(Boolean).map(Number)); }} />;
}

function NodeInspector({ design, node, onChange, onDelete }: { design: Design; node: DesignNode; onChange: (n: DesignNode) => void; onDelete: () => void }) {
  const set = (patch: Partial<DesignNode>) => onChange({ ...node, ...patch });
  const cabled = (iface: string) => design.links.some((l) => (l.a.node === node.id && l.a.iface === iface) || (l.b.node === node.id && l.b.iface === iface));
  const [preview, setPreview] = useState(false);

  if (node.kind === 'switch') {
    const ports = node.ports ?? [];
    const setPort = (i: number, p: Partial<SwitchPort>) => set({ ports: ports.map((x, k) => (k === i ? { ...x, ...p } : x)) });
    const labels = Object.fromEntries(design.links.flatMap((l) => [[l.a, l.b], [l.b, l.a]]).filter(([s]) => s.node === node.id).map(([s, o]) => [s.iface, `${design.nodes.find((n) => n.id === o.node)?.name} ${o.iface}`]));
    return (
      <div>
        <div className="spread"><h3 style={{ margin: 0 }}>Switch</h3><button className="link" onClick={onDelete}>Delete</button></div>
        <label className="small">Name <input value={node.name} onChange={(e) => set({ name: e.target.value.trim() })} /></label>
        <h4>Ports</h4>
        <p className="small muted">Access port: one VLAN, untagged (for a host). Trunk: several VLANs tagged (for a router with sub-interfaces).</p>
        <table className="small" style={{ width: '100%' }}>
          <tbody>
            {ports.map((p, i) => (
              <tr key={p.name}>
                <td className="mono">{p.name}</td>
                <td>
                  <select value={p.mode} onChange={(e) => setPort(i, e.target.value === 'trunk' ? { mode: 'trunk', vlans: p.vlans ?? [p.vlan ?? 1] } : { mode: 'access', vlan: p.vlan ?? p.vlans?.[0] ?? 1 })} aria-label={`${p.name} mode`}>
                    <option value="access">access</option><option value="trunk">trunk</option>
                  </select>
                </td>
                <td>
                  {p.mode === 'access'
                    ? <input style={{ width: 52 }} value={p.vlan || ''} placeholder="1" onChange={(e) => setPort(i, { vlan: Number(e.target.value.trim() || 0) })} aria-label={`${p.name} VLAN`} />
                    : <VlanList value={p.vlans ?? []} onChange={(vlans) => setPort(i, { vlans })} label={`${p.name} VLANs`} />}
                </td>
                <td className="muted">{labels[p.name] ?? ''}</td>
                <td>{!cabled(p.name) && <button className="link" onClick={() => set({ ports: ports.filter((_, k) => k !== i) })} aria-label={`Remove ${p.name}`}>✕</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <button onClick={() => set({ ports: [...ports, { name: nextPort(node), mode: 'access', vlan: 1 }] })}>+ port</button>
        <details style={{ marginTop: 8 }} open={preview} onToggle={(e) => setPreview((e.target as HTMLDetailsElement).open)}>
          <summary className="small">Configuration this generates</summary>
          {preview && <pre className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{'/etc/network/interfaces\n\n' + switchInterfacesFile(node, labels)}</pre>}
        </details>
      </div>
    );
  }

  const fw = node.firewall ?? { enabled: false, allow: [] };
  const setIface = (i: number, patch: Partial<DesignNode['ifaces'][number]>) => set({ ifaces: node.ifaces.map((x, k) => (k === i ? { ...x, ...patch } : x)) });
  const physNames = node.ifaces.filter((i) => !isSubInterface(i.name)).map((i) => i.name);
  return (
    <div>
      <div className="spread"><h3 style={{ margin: 0 }}>{KIND_LABEL[node.kind]}</h3><button className="link" onClick={onDelete}>Delete</button></div>
      <label className="small">Hostname <input value={node.name} onChange={(e) => set({ name: e.target.value.trim() })} /></label>

      <h4>Interfaces</h4>
      {node.ifaces.map((i, k) => (
        <div key={k} className="row small" style={{ gap: 4, marginBottom: 4 }}>
          <input className="mono" style={{ width: 70 }} value={i.name} onChange={(e) => setIface(k, { name: e.target.value.trim() })} aria-label="Interface name" />
          <input className="mono" style={{ width: 130 }} placeholder="10.0.1.10/24" value={i.address ?? ''} onChange={(e) => setIface(k, { address: e.target.value })} aria-label={`${i.name} address`} />
          {!cabled(i.name) && <button className="link" onClick={() => set({ ifaces: node.ifaces.filter((_, j) => j !== k) })} aria-label={`Remove ${i.name}`}>✕</button>}
        </div>
      ))}
      <div className="row">
        <button onClick={() => set({ ifaces: [...node.ifaces, { name: nextPhys(node) }] })}>+ interface</button>
        {node.kind === 'router' && physNames.length > 0 && <button onClick={() => set({ ifaces: [...node.ifaces, { name: `${physNames[0]}.${10 * (node.ifaces.filter((i) => isSubInterface(i.name)).length + 1)}` }] })}>+ VLAN sub-interface</button>}
      </div>
      {node.kind === 'router' && <p className="small muted">A sub-interface such as <code>eth0.20</code> sends VLAN 20 tagged over eth0: cable eth0 to a switch trunk port carrying VLAN 20.</p>}

      <h4>Routing</h4>
      <label className="small">Default gateway <input className="mono" style={{ width: 120 }} placeholder={node.kind === 'router' ? '(none)' : '10.0.1.1'} value={node.gateway ?? ''} onChange={(e) => set({ gateway: e.target.value })} /></label>
      <div className="small" style={{ marginTop: 4 }}>
        {(node.routes ?? []).map((r, k) => (
          <div key={k} className="row" style={{ gap: 4, marginBottom: 4 }}>
            <input className="mono" style={{ width: 120 }} placeholder="10.0.30.0/24" value={r.dest} onChange={(e) => set({ routes: node.routes!.map((x, j) => (j === k ? { ...x, dest: e.target.value } : x)) })} aria-label="Route destination" />
            via <input className="mono" style={{ width: 100 }} placeholder="next hop" value={r.via} onChange={(e) => set({ routes: node.routes!.map((x, j) => (j === k ? { ...x, via: e.target.value } : x)) })} aria-label="Next hop" />
            <button className="link" onClick={() => set({ routes: node.routes!.filter((_, j) => j !== k) })} aria-label="Remove route">✕</button>
          </div>
        ))}
        <button onClick={() => set({ routes: [...(node.routes ?? []), { dest: '', via: '' }] })}>+ static route</button>
      </div>

      <h4>Services</h4>
      <div className="row small">
        {(['ssh', 'web'] as const).map((s) => (
          <label key={s}><input type="checkbox" checked={!!node.services?.includes(s)} onChange={(e) => set({ services: e.target.checked ? [...(node.services ?? []), s] : (node.services ?? []).filter((x) => x !== s) })} /> {s === 'ssh' ? 'sshd (tcp 22)' : 'nginx (tcp 80)'}</label>
        ))}
      </div>

      <h4>Firewall (input)</h4>
      <label className="small"><input type="checkbox" checked={fw.enabled} onChange={(e) => set({ firewall: { ...fw, enabled: e.target.checked } })} /> Drop everything addressed to {node.name} except:</label>
      {fw.enabled && <RuleRows rules={fw.allow} onChange={(allow) => set({ firewall: { ...fw, allow } })} />}
      {fw.enabled && <p className="small muted">Replies to connections {node.name} opens itself are always allowed (ct state established,related).</p>}

      {node.kind === 'router' && (
        <>
          <h4>Forwarding (traffic routed through {node.name})</h4>
          <label className="small">Policy{' '}
            <select value={node.forward?.policy ?? 'accept'} onChange={(e) => set({ forward: { policy: e.target.value as 'accept' | 'drop', allow: node.forward?.allow ?? [] } })}>
              <option value="accept">accept everything</option><option value="drop">drop, except the rules below</option>
            </select>
          </label>
          {(node.forward?.policy === 'drop' || (node.forward?.allow.length ?? 0) > 0) && <RuleRows forward rules={node.forward?.allow ?? []} onChange={(allow) => set({ forward: { policy: node.forward?.policy ?? 'accept', allow } })} />}
          <h4>NAT</h4>
          <label className="small">Masquerade traffic leaving{' '}
            <select value={node.nat?.outIface ?? ''} onChange={(e) => set({ nat: e.target.value ? { outIface: e.target.value } : undefined })}>
              <option value="">(no NAT)</option>
              {node.ifaces.map((i) => <option key={i.name} value={i.name}>{i.name}</option>)}
            </select>
          </label>
        </>
      )}
      <details style={{ marginTop: 10 }} open={preview} onToggle={(e) => setPreview((e.target as HTMLDetailsElement).open)}>
        <summary className="small">Configuration this generates</summary>
        {preview && (
          <>
            <pre className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{'/etc/network/interfaces\n\n' + interfacesFile(node)}</pre>
            <pre className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{'/etc/nftables.conf\n\n' + nftablesFile(node)}</pre>
            <pre className="mono small" style={{ whiteSpace: 'pre-wrap' }}>{'/etc/hosts\n\n' + hostsFile(design, node)}</pre>
          </>
        )}
      </details>
    </div>
  );
}

function LinkInspector({ design, link, onChange, onDelete }: { design: Design; link: DesignLink; onChange: (l: DesignLink) => void; onDelete: () => void }) {
  const end = (side: 'a' | 'b') => {
    const e = link[side];
    const n = design.nodes.find((x) => x.id === e.node);
    if (!n) return null;
    const used = new Set(design.links.filter((l) => l.id !== link.id).flatMap((l) => [l.a, l.b]).filter((x) => x.node === n.id).map((x) => x.iface));
    const options = n.kind === 'switch' ? (n.ports ?? []).map((p) => p.name) : n.ifaces.filter((i) => !isSubInterface(i.name)).map((i) => i.name);
    return (
      <div className="row small">
        <strong>{n.name}</strong>
        <select value={e.iface} onChange={(ev) => onChange({ ...link, [side]: { ...e, iface: ev.target.value } })} aria-label={`${n.name} interface`}>
          {options.map((o) => <option key={o} value={o} disabled={used.has(o)}>{o}{used.has(o) ? ' (in use)' : ''}</option>)}
        </select>
      </div>
    );
  };
  return (
    <div>
      <div className="spread"><h3 style={{ margin: 0 }}>Cable</h3><button className="link" onClick={onDelete}>Delete</button></div>
      {end('a')}
      <div className="small muted" style={{ margin: '4px 0' }}>↕</div>
      {end('b')}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Run mode: terminals and the packet tracer
// ---------------------------------------------------------------------------

function Tracer({ design, getWorld }: { design: Design; getWorld: () => World }) {
  const machines = design.nodes.filter((n) => n.kind !== 'switch');
  const [from, setFrom] = useState(machines[0]?.name ?? '');
  const [cmd, setCmd] = useState('');
  const [result, setResult] = useState<(TraceResult & { line: string; host: string }) | null>(null);
  const presets = (t: string) => {
    const n = design.nodes.find((x) => x.name === t);
    const ip = n?.ifaces.map(addressOf).find(Boolean) ?? t;
    return [`ping -c 1 ${ip}`, `curl -s http://${t}/`, `ssh -o ConnectTimeout=3 ${BUILDER_USER}@${t} hostname`, `traceroute -n ${ip}`];
  };
  const [toSel, setTo] = useState('');
  const to = toSel && toSel !== from ? toSel : machines.find((n) => n.name !== from)?.name ?? '';
  const lanes: Lane[] = machines.map((n) => ({ id: n.name, label: n.name, sub: n.ifaces.filter((i) => i.address?.trim()).map((i) => i.address!.split('/')[0]).join(' / ') || KIND_LABEL[n.kind] }));
  const run = (line: string) => {
    if (!from || !line.trim()) return;
    const w = getWorld();
    setResult({ ...traceCommand(w, from, loginUser(w, from), line.trim()), line: line.trim(), host: from });
  };
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h3>Packet tracer</h3>
      <p className="small muted">Runs one command with the packet recorder on a copy of the network (your machines are not changed) and shows every packet, every hop and every firewall and NAT decision.</p>
      <div className="row small">
        From <select value={from} onChange={(e) => setFrom(e.target.value)} aria-label="Source machine">{machines.map((n) => <option key={n.id}>{n.name}</option>)}</select>
        to <select value={to} onChange={(e) => setTo(e.target.value)} aria-label="Target machine">{machines.filter((n) => n.name !== from).map((n) => <option key={n.id}>{n.name}</option>)}</select>
        {to && presets(to).map((p) => <button key={p} className="mono" onClick={() => { setCmd(p); run(p); }}>{p.split(' ')[0]}</button>)}
      </div>
      <form className="row" style={{ marginTop: 6 }} onSubmit={(e) => { e.preventDefault(); run(cmd); }}>
        <span className="mono small">{from}$</span>
        <input className="mono" style={{ flex: 1, minWidth: 200 }} value={cmd} placeholder="any command, e.g. curl -s http://web1/" onChange={(e) => setCmd(e.target.value)} aria-label="Command to trace" />
        <button className="primary" type="submit">Trace</button>
      </form>
      {result && (
        <div style={{ marginTop: 10 }}>
          <div className="small muted">{result.host}$ {result.line}</div>
          <pre className="mono small" style={{ whiteSpace: 'pre-wrap', maxHeight: 180, overflow: 'auto' }}>{result.output || '(no output)'}</pre>
          {result.decisions.length === 0 && result.events.length > 0 && <p className="small muted">No firewall filtered or translated these packets (every chain on the path accepts by default).</p>}
          {result.decisions.length > 0 && (
            <>
              <h4>Decisions along the path</h4>
              {result.decisions.map((d, i) => (
                <div key={i} className={`feedback ${/drop|reject|no route|disabled/i.test(d.note) ? 'bad' : 'ok'}`} style={{ fontSize: 12.5 }}><strong>{d.host}</strong>: {d.note}{d.count > 1 ? <span className="muted"> (×{d.count})</span> : null}</div>
              ))}
            </>
          )}
          {result.events.length > 0
            ? <div style={{ overflowX: 'auto' }}><SequenceDiagram events={result.events} lanes={lanes} segmentOf={(h, i) => segmentLabel(getWorld(), h, i)} /></div>
            : <p className="small muted">No packets were sent.</p>}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function Builder() {
  const [design, setDesignState] = useState<Design>(() => LIVE?.design ?? load());
  const [selected, setSelected] = useState<string | null>(null);
  const [connectMode, setConnectMode] = useState(false);
  const [connectFrom, setConnectFrom] = useState<string | null>(null);
  const [running, setRunning] = useState(!!LIVE);
  const [buildErrors, setBuildErrors] = useState(false);
  const [runKey, setRunKey] = useState(0);
  const worldRef = useRef<World | null>(LIVE?.world ?? null);
  const fileInput = useRef<HTMLInputElement>(null);

  const diagnostics = useMemo(() => validateDesign(design), [design]);
  const problems = useMemo(() => new Set(diagnostics.filter((d) => d.level === 'error' && d.target).map((d) => d.target!)), [diagnostics]);
  const errors = diagnostics.filter((d) => d.level === 'error');

  const setDesign = (d: Design) => { setDesignState(d); save(d); setBuildErrors(false); };
  const patchNode = (changed: DesignNode) => {
    let n = changed;
    // A renamed interface keeps its cable (interfaces are renamed in place, so match by position).
    const old = design.nodes.find((x) => x.id === n.id);
    const renames: Record<string, string> = {};
    if (old && old.ifaces.length === n.ifaces.length) old.ifaces.forEach((i, k) => { if (i.name !== n.ifaces[k].name) renames[i.name] = n.ifaces[k].name; });
    // Its VLAN sub-interfaces follow a renamed physical interface (eth0.10 → eth3.10).
    const subOf = (name: string, parent: string) => name.startsWith(`${parent}.`) && /^\d+$/.test(name.slice(parent.length + 1));
    for (const [from, to] of Object.entries(renames)) {
      if (from.includes('.') || to.includes('.')) continue;
      n = { ...n, ifaces: n.ifaces.map((i) => (subOf(i.name, from) ? { ...i, name: `${to}${i.name.slice(from.length)}` } : i)) };
      for (const i of old!.ifaces) if (subOf(i.name, from)) renames[i.name] = `${to}${i.name.slice(from.length)}`;
    }
    const next = { ...design, nodes: design.nodes.map((x) => (x.id === n.id ? n : x)) };
    setDesign(Object.keys(renames).length ? renameIfaces(next, n.id, renames) : next);
  };
  const selNode = design.nodes.find((n) => n.id === selected);
  const selLink = design.links.find((l) => l.id === selected);

  const add = (kind: NodeKind) => {
    const k = design.nodes.length;
    const n = newNode(design, kind, 80 + ((k * 110) % (W - 160)), 80 + Math.floor((k * 110) / (W - 160)) * 110 % (H - 140));
    setDesign({ ...design, nodes: [...design.nodes, n] });
    setSelected(n.id);
  };

  const nodeClick = (id: string) => {
    if (!connectMode) { setSelected(id); return; }
    if (!connectFrom) { setConnectFrom(id); return; }
    if (connectFrom === id) { setConnectFrom(null); return; }
    let d = design;
    const a = ensureFree(d, d.nodes.find((n) => n.id === connectFrom)!);
    d = { ...d, nodes: d.nodes.map((n) => (n.id === a.node.id ? a.node : n)) };
    const b = ensureFree(d, d.nodes.find((n) => n.id === id)!);
    d = { ...d, nodes: d.nodes.map((n) => (n.id === b.node.id ? b.node : n)) };
    const link: DesignLink = { id: newId('l'), a: { node: a.node.id, iface: a.iface }, b: { node: b.node.id, iface: b.iface } };
    setDesign({ ...d, links: [...d.links, link] });
    setConnectFrom(null);
    setSelected(link.id);
  };

  const deleteSelected = () => {
    if (selNode) setDesign({ ...design, nodes: design.nodes.filter((n) => n.id !== selNode.id), links: design.links.filter((l) => l.a.node !== selNode.id && l.b.node !== selNode.id) });
    else if (selLink) setDesign({ ...design, links: design.links.filter((l) => l.id !== selLink.id) });
    setSelected(null);
    setConnectFrom(null);
  };

  const start = () => {
    const r = buildDesignWorld(design);
    if (!r.world) { setBuildErrors(true); return; }
    worldRef.current = r.world;
    LIVE = { world: r.world, design };
    setRunning(true);
    setRunKey((k) => k + 1);
    setConnectMode(false);
    setConnectFrom(null);
  };
  const stop = () => { LIVE = null; worldRef.current = null; setRunning(false); };
  const setWorld = (w: World) => { worldRef.current = w; if (LIVE) LIVE = { ...LIVE, world: w }; };

  const importFile = (f: File) => {
    f.text().then((t) => {
      try {
        setDesign(normalizeDesign(JSON.parse(t)));
        setSelected(null);
      } catch (e) {
        alert(`Could not import: ${(e as Error).message}`);
      }
    });
  };

  if (running && worldRef.current) {
    const w = worldRef.current;
    const specs = design.nodes
      .slice()
      .sort((a, b) => ['host', 'server', 'router', 'switch'].indexOf(a.kind) - ['host', 'server', 'router', 'switch'].indexOf(b.kind))
      .filter((n) => w.hosts[n.name])
      .map((n) => ({ hostId: n.name, user: loginUser(w, n.name), label: n.name, banner: `${KIND_LABEL[n.kind]} ${n.name} (${n.ifaces.filter((i) => i.address?.trim()).map((i) => `${i.name} ${i.address}`).join(', ') || 'no addresses'})` }));
    return (
      <div className="page wide">
        <div className="spread">
          <h1 style={{ margin: 0 }}>Infrastructure Builder <span className="badge ok">running</span></h1>
          <div className="row">
            <button onClick={() => { setWorld(rebootDesignWorld(worldRef.current!)); setRunKey((k) => k + 1); }}>Reboot all machines</button>
            <button onClick={() => { if (confirm('Rebuild the network from the design? Changes made in the terminals are lost.')) start(); }}>Rebuild</button>
            <button className="primary" onClick={stop}>← Back to the design</button>
          </div>
        </div>
        <p className="small muted">Every machine is a simulated Debian system configured from the files the design generated. Log in as <code>{BUILDER_USER}</code> (password <code>{BUILDER_PASSWORD}</code>, with sudo) on workstations and servers, as root on routers and switches. Changes you make in the terminals stay until you rebuild.</p>
        <div className="builder-run">
          <div className="card" style={{ padding: 8 }}>
            <Canvas design={design} selected={null} connectFrom={null} problems={new Set()} readOnly onSelect={() => undefined} />
          </div>
          <div style={{ minHeight: 0 }}>
            <LabTerminals key={runKey} specs={specs} getWorld={() => worldRef.current!} setWorld={setWorld} height={480} />
          </div>
        </div>
        <Tracer key={runKey} design={design} getWorld={() => worldRef.current!} />
      </div>
    );
  }

  return (
    <div className="page wide">
      <div className="spread">
        <h1 style={{ margin: 0 }}>Infrastructure Builder</h1>
        <div className="row">
          <select value="" onChange={(e) => { const t = DESIGN_TEMPLATES.find((x) => x.id === e.target.value); if (t && (!design.nodes.length || confirm(`Replace the current design with "${t.title}"?`))) { setDesign(t.design()); setSelected(null); } else if (e.target.value === 'empty' && confirm('Start an empty design?')) { setDesign({ ...EMPTY_DESIGN }); setSelected(null); } }} aria-label="Templates">
            <option value="">Templates…</option>
            {DESIGN_TEMPLATES.map((t) => <option key={t.id} value={t.id}>{t.title}</option>)}
            <option value="empty">Empty design</option>
          </select>
          <button onClick={() => download(`${(design.name || 'design').replace(/[^\w-]+/g, '-')}.json`, JSON.stringify(design, null, 2))}>Export</button>
          <button onClick={() => fileInput.current?.click()}>Import</button>
          <input ref={fileInput} type="file" accept="application/json,.json" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) importFile(f); e.target.value = ''; }} />
          <button className="primary" disabled={errors.length > 0} onClick={start} title={errors.length ? 'Fix the errors first' : 'Build the network and open terminals'}>Build &amp; run ▶</button>
        </div>
      </div>
      <p className="small muted">Draw a network, give the machines addresses, VLANs and firewall rules, then build it: every device becomes a simulated Debian machine configured from real files (<code>/etc/network/interfaces</code>, <code>/etc/nftables.conf</code>, a VLAN-aware bridge on the switches), with terminals and a packet tracer.</p>

      <div className="builder-grid">
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <input value={design.name} onChange={(e) => setDesign({ ...design, name: e.target.value })} aria-label="Design name" style={{ fontWeight: 600 }} />
            {(['host', 'server', 'router', 'switch'] as NodeKind[]).map((k) => <button key={k} onClick={() => add(k)}>+ {KIND_LABEL[k]}</button>)}
            <button className={connectMode ? 'primary' : ''} onClick={() => { setConnectMode(!connectMode); setConnectFrom(null); }} aria-pressed={connectMode}>{connectMode ? 'Connecting… (click two devices)' : '⟷ Connect'}</button>
            {(selNode || selLink) && <button onClick={deleteSelected}>Delete selected</button>}
          </div>
          <div className="card" style={{ padding: 6 }}>
            <Canvas design={design} selected={selected} connectFrom={connectFrom} problems={problems} onSelect={(id) => { if (!connectMode) setSelected(id); }}
              onMove={(id, x, y) => setDesignState((d) => { const nd = { ...d, nodes: d.nodes.map((n) => (n.id === id ? { ...n, x, y } : n)) }; save(nd); return nd; })}
              onNodeClick={nodeClick} />
          </div>
          <div className="card" style={{ marginTop: 10 }}>
            <div className="spread"><h3 style={{ margin: 0 }}>Checks</h3><span className={`badge ${errors.length ? 'err' : diagnostics.length ? 'warn' : 'ok'}`}>{errors.length} error{errors.length === 1 ? '' : 's'}, {diagnostics.length - errors.length} warning{diagnostics.length - errors.length === 1 ? '' : 's'}</span></div>
            {buildErrors && <div className="callout err small">Fix the errors before building.</div>}
            {diagnostics.length === 0 && <p className="small">No problems found. Build the network to try it.</p>}
            {diagnostics.map((d, i) => (
              <div key={i} className={`feedback ${d.level === 'error' ? 'bad' : ''}`} style={{ fontSize: 12.5, cursor: d.target ? 'pointer' : undefined, background: d.level === 'warning' ? 'var(--warn-soft)' : undefined, color: d.level === 'warning' ? 'var(--warn)' : undefined }} onClick={() => d.target && setSelected(d.target)}>
                {d.level === 'error' ? '✗' : '!'} {d.message}
              </div>
            ))}
          </div>
        </div>
        <div className="card builder-inspector">
          {selNode ? <NodeInspector key={selNode.id} design={design} node={selNode} onChange={patchNode} onDelete={deleteSelected} />
            : selLink ? <LinkInspector design={design} link={selLink} onChange={(l) => setDesign({ ...design, links: design.links.map((x) => (x.id === l.id ? l : x)) })} onDelete={deleteSelected} />
            : (
              <div className="small">
                <h3>How to use</h3>
                <ol>
                  <li>Add devices and drag them into place.</li>
                  <li>Press <strong>Connect</strong>, then click two devices to cable them (the next free interface or switch port is used; change it by clicking the cable).</li>
                  <li>Click a device to set its addresses (<code>10.0.1.10/24</code>), gateway, VLANs, services and firewall rules.</li>
                  <li>Fix what the checks report, then <strong>Build &amp; run</strong>.</li>
                </ol>
                <p className="muted">Switches are VLAN-aware Linux bridges; machines cabled directly to each other share a point-to-point link. Cables between switches are not simulated yet.</p>
                <p className="muted">Your design is saved in this browser automatically. Use Export to keep a copy or share it.</p>
              </div>
            )}
        </div>
      </div>
    </div>
  );
}
