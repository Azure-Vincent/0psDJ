import { useMemo, useState } from 'react';
import { freshLab } from '../../engine/lab/dependencies';
import { classify6, eui64, expandIp6, formatIp6, linkLocalFromMac, multicastMac, parseCidr6, parseIp6, slaacAddress, solicitedNode } from '../../engine/net/ip6';
import { formatBridgeVlans, parseVids, recomputeL2 } from '../../engine/sim/l2';
import type { World } from '../../engine/types';

// ---------------------------------------------------------------------------
// VLAN explorer: edit sw01's port table, recompute broadcast domains with the
// simulator's own layer-2 code.
// ---------------------------------------------------------------------------

interface PortCfg { mode: 'access' | 'trunk'; access: string; vids: string; pvid: string }

function portsOf(w: World): Record<string, PortCfg> {
  const out: Record<string, PortCfg> = {};
  for (const [name, p] of Object.entries(w.hosts.sw01.bridge!.ports)) {
    const access = p.vids.length === 1 && p.pvid === p.vids[0] && p.untagged.includes(p.vids[0]);
    out[name] = access
      ? { mode: 'access', access: String(p.vids[0]), vids: '', pvid: '' }
      : { mode: 'trunk', access: '', vids: p.vids.filter((v) => !p.untagged.includes(v)).join(' '), pvid: p.pvid === null ? '' : String(p.pvid) };
  }
  return out;
}

function stanza(name: string, c: PortCfg): string {
  if (c.mode === 'access') return `auto ${name}\niface ${name}\n    bridge-access ${c.access}`;
  return `auto ${name}\niface ${name}\n    bridge-vids ${c.vids || '(none)'}${c.pvid ? `\n    bridge-pvid ${c.pvid}` : '\n    bridge-allow-untagged no'}`;
}

export function VlanExplorer() {
  const base = useMemo(() => freshLab(), []);
  const initial = useMemo(() => portsOf(base), [base]);
  const [ports, setPorts] = useState<Record<string, PortCfg>>(initial);
  const result = useMemo(() => {
    const w = structuredClone(base);
    const b = w.hosts.sw01.bridge!;
    for (const [name, c] of Object.entries(ports)) {
      if (c.mode === 'access') {
        const v = Number(c.access);
        b.ports[name] = Number.isInteger(v) && v >= 1 && v <= 4094 ? { vids: [v], pvid: v, untagged: [v] } : { vids: [], pvid: null, untagged: [] };
      } else {
        const vids = parseVids(c.vids);
        const pvid = c.pvid ? Number(c.pvid) : null;
        if (pvid && !vids.includes(pvid)) vids.unshift(pvid);
        b.ports[name] = { vids, pvid, untagged: pvid ? [pvid] : [] };
      }
    }
    recomputeL2(w);
    const members: { label: string; segment: string | null; how: string }[] = [];
    for (const l of w.links ?? []) {
      const h = w.hosts[l.a.host];
      for (const i of h.ifaces.filter((x) => x.name === l.a.iface || x.vlan?.parent === l.a.iface)) {
        const addr = i.address ? ` ${i.address}/${i.prefix}` : '';
        members.push({ label: `${h.hostname} ${i.name}${addr}`, segment: i.segment, how: `${l.b.iface}, ${i.vlan ? `tagged ${i.vlan.id}` : 'untagged'}` });
      }
    }
    const groups = new Map<string, typeof members>();
    for (const m of members) {
      const k = m.segment ?? '(not connected: frames dropped)';
      groups.set(k, [...(groups.get(k) ?? []), m]);
    }
    return { groups: [...groups.entries()].sort(), vlanShow: formatBridgeVlans(w.hosts.sw01) };
  }, [base, ports]);
  const label = (port: string) => {
    const l = base.links?.find((x) => x.b.iface === port);
    return l ? `${l.a.host} ${l.a.iface}` : '';
  };
  const set = (name: string, patch: Partial<PortCfg>) => setPorts((p) => ({ ...p, [name]: { ...p[name], ...patch } }));
  return (
    <div className="card">
      <p className="muted small">Change a port of sw01 and see which hosts end up in the same broadcast domain (they can ARP each other; anything else must be routed). The grouping is computed by the simulator's layer-2 code: an interface is in VLAN v when the switch accepts its frames into v and sends v back in the form the interface expects (untagged for a plain NIC, tagged for a sub-interface like eth3.30).</p>
      <table>
        <thead><tr><th>Port</th><th>Connected to</th><th>Mode</th><th>VLAN(s)</th><th>ifupdown2</th></tr></thead>
        <tbody>
          {Object.entries(ports).map(([name, c]) => (
            <tr key={name}>
              <td><code>{name}</code></td>
              <td>{label(name)}</td>
              <td>
                <select value={c.mode} onChange={(e) => set(name, e.target.value === 'access' ? { mode: 'access', access: c.access || '10' } : { mode: 'trunk', vids: c.vids || c.access || '30', pvid: c.pvid || '1' })}>
                  <option value="access">access</option>
                  <option value="trunk">trunk</option>
                </select>
              </td>
              <td>
                {c.mode === 'access'
                  ? <label className="small">VLAN <input style={{ width: 60 }} value={c.access} onChange={(e) => set(name, { access: e.target.value })} /></label>
                  : <><label className="small">tagged <input style={{ width: 90 }} value={c.vids} onChange={(e) => set(name, { vids: e.target.value })} /></label>{' '}<label className="small">PVID <input style={{ width: 50 }} value={c.pvid} onChange={(e) => set(name, { pvid: e.target.value })} /></label></>}
              </td>
              <td><pre className="small" style={{ margin: 0 }}>{stanza(name, c)}</pre></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row"><button onClick={() => setPorts(initial)}>Reset to the lab configuration</button></div>
      <h3>Broadcast domains</h3>
      {result.groups.map(([seg, ms]) => (
        <div key={seg} className={seg.startsWith('(') ? 'callout small' : 'card small'} style={{ marginBottom: 6 }}>
          <strong>{seg}</strong>: {ms.map((m) => `${m.label} (${m.how})`).join(' · ')}
        </div>
      ))}
      <details><summary className="small">sw01# bridge vlan show</summary><pre className="small">{result.vlanShow}</pre></details>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IPv6 address explorer
// ---------------------------------------------------------------------------

const KIND_TEXT: Record<string, string> = {
  unspecified: 'unspecified (::, "no address yet")', loopback: 'loopback (::1)', 'link-local': 'link-local (fe80::/10): valid only on one link, never routed',
  'unique-local': 'unique local (fc00::/7): private, like RFC 1918', multicast: 'multicast (ff00::/8)', documentation: 'documentation (2001:db8::/32): examples only, never routed',
  'ipv4-mapped': 'IPv4-mapped (::ffff:0:0/96)', global: 'global unicast',
};

export function Ipv6Explorer() {
  const [addr, setAddr] = useState('2001:0db8:0020:0000:0000:0000:0000:0010');
  const [mac, setMac] = useState('52:54:00:e7:00:1e');
  const [prefix, setPrefix] = useState('2001:db8:30::/64');
  const a = useMemo(() => {
    const n = parseIp6(addr);
    if (n === null) return null;
    const s = formatIp6(n);
    return { canonical: s, expanded: expandIp6(n), kind: KIND_TEXT[classify6(s)], sn: solicitedNode(s), snMac: multicastMac(solicitedNode(s)) };
  }, [addr]);
  const m = useMemo(() => {
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac)) return null;
    const bytes = mac.toLowerCase().split(':');
    const first = parseInt(bytes[0], 16);
    const id = eui64(mac.toLowerCase());
    const c = parseCidr6(prefix);
    return {
      steps: [
        `MAC                       ${bytes.join(':')}`,
        `split and insert ff:fe    ${bytes.slice(0, 3).join(':')}:ff:fe:${bytes.slice(3).join(':')}`,
        `flip bit 7 (U/L) of byte 1 ${bytes[0]} → ${(first ^ 2).toString(16).padStart(2, '0')}`,
        `interface identifier      ${expandIp6(id).split(':').slice(4).join(':')}`,
      ],
      ll: linkLocalFromMac(mac.toLowerCase()),
      slaac: c && c.prefix === 64 ? slaacAddress(prefix, mac.toLowerCase()) : null,
      prefixOk: !!c,
      prefix64: c?.prefix === 64,
    };
  }, [mac, prefix]);
  return (
    <div className="card">
      <h3>Notation and type</h3>
      <label>Address <input style={{ width: 360 }} value={addr} onChange={(e) => setAddr(e.target.value)} spellCheck={false} /></label>
      {a ? (
        <table className="small">
          <tbody>
            <tr><td>Canonical (RFC 5952)</td><td><code>{a.canonical}</code></td></tr>
            <tr><td>Fully expanded</td><td><code>{a.expanded}</code></td></tr>
            <tr><td>Type</td><td>{a.kind}</td></tr>
            <tr><td>Solicited-node group (NDP)</td><td><code>{a.sn}</code> → Ethernet <code>{a.snMac}</code></td></tr>
          </tbody>
        </table>
      ) : <p className="bad small">Not a valid IPv6 address.</p>}
      <h3>SLAAC from a MAC address (modified EUI-64)</h3>
      <div className="row">
        <label>MAC <input value={mac} onChange={(e) => setMac(e.target.value)} spellCheck={false} /></label>
        <label>Advertised prefix <input value={prefix} onChange={(e) => setPrefix(e.target.value)} spellCheck={false} /></label>
      </div>
      {m ? (
        <>
          <pre className="small">{m.steps.join('\n')}</pre>
          <table className="small">
            <tbody>
              <tr><td>Link-local</td><td><code>{m.ll}</code></td></tr>
              <tr><td>SLAAC address</td><td>{m.slaac ? <code>{m.slaac}</code> : m.prefixOk ? 'SLAAC needs a /64 prefix' : 'invalid prefix'}</td></tr>
            </tbody>
          </table>
          <p className="muted small">In the lab: dev01 has MAC 52:54:00:e7:00:1e; rtr01 advertises 2001:db8:30::/64 on VLAN 30. Real desktops usually also create random temporary (privacy) addresses for outgoing connections; the simulator uses EUI-64 only.</p>
        </>
      ) : <p className="bad small">MAC must look like aa:bb:cc:dd:ee:ff.</p>}
    </div>
  );
}
