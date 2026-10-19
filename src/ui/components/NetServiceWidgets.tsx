import { useMemo, useState } from 'react';
import { DhcpConfigError, parseDhcpdConf, parseLeases } from '../../engine/config/dhcpd';
import { DHCPD_CONF } from '../../engine/lab/sshLab';
import { freshLab } from '../../engine/lab/dependencies';
import { inCidr, parseCidr } from '../../engine/net/ip';
import { Shell } from '../../engine/shell/shell';
import { chooseAddress } from '../../engine/sim/dhcp';
import type { World } from '../../engine/types';

// ---------------------------------------------------------------------------
// DHCP allocation simulator: the engine's dhcpd.conf parser and allocation
// function applied to a sequence of clients, as ns1 (10.0.10.53 on eth0) would.
// ---------------------------------------------------------------------------

const SERVER_ADDR = '10.0.10.53';
const DEFAULT_CLIENTS = 'ws02 52:54:00:d4:00:42\nprinter01 52:54:00:e5:00:21\nvisitor-1 52:54:00:77:00:01\nvisitor-2 52:54:00:77:00:02\nws02 52:54:00:d4:00:42';

export function DhcpAllocator() {
  const [conf, setConf] = useState(DHCPD_CONF);
  const [clients, setClients] = useState(DEFAULT_CLIENTS);
  const result = useMemo(() => {
    let config;
    try {
      config = parseDhcpdConf(conf);
    } catch (e) {
      return { error: e instanceof DhcpConfigError ? e.message : String(e) };
    }
    const subnet = config.subnets.find((s) => inCidr(SERVER_ADDR, parseCidr(`${s.network}/${s.prefix}`)!));
    if (!subnet) return { error: `No subnet declaration for eth0 (${SERVER_ADDR}).\n** Ignoring requests on eth0. If this is not what you want, please write a subnet declaration in your dhcpd.conf file for the network segment to which interface eth0 is attached. **` };
    const opts = { ...config.options, ...subnet.options };
    const warnings: string[] = [];
    const net = parseCidr(`${subnet.network}/${subnet.prefix}`)!;
    for (const r of opts.routers ?? []) if (!inCidr(r, net)) warnings.push(`option routers ${r} is not inside ${subnet.network}/${subnet.prefix}: clients cannot reach their gateway.`);
    if (!opts.routers?.length) warnings.push('No option routers: clients get no default route.');
    if (!opts.domainNameServers?.length) warnings.push('No option domain-name-servers: clients get no DNS servers.');
    if (subnet.range && subnet.range.some((a) => !inCidr(a, net))) warnings.push('The range is not inside the subnet.');
    for (const h of config.hosts) if (h.fixedAddress && subnet.range && inCidr(h.fixedAddress, net)) {
      const [a, b] = subnet.range;
      const n = (x: string) => x.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);
      if (n(h.fixedAddress) >= n(a) && n(h.fixedAddress) <= n(b)) warnings.push(`Reservation ${h.name} (${h.fixedAddress}) lies inside the dynamic range.`);
    }
    // Allocate in order, appending each lease as dhcpd does.
    const now = Date.UTC(2026, 9, 19, 9, 0, 0);
    let leases = parseLeases('');
    const rows = clients.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
      const [name, macRaw] = line.split(/\s+/);
      const mac = (macRaw ?? '').toLowerCase();
      if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) return { name, mac: macRaw ?? '', outcome: 'invalid MAC address (expected aa:bb:cc:dd:ee:ff)', ip: '' };
      const pick = chooseAddress(config, subnet, leases, mac, now);
      if (!pick) return { name, mac, outcome: `no free leases (dhcpd logs "network ${subnet.network}/${subnet.prefix}: no free leases" and does not answer)`, ip: '' };
      if (pick.reason !== 'fixed-address') leases = [...leases.filter((x) => x.ip !== pick.ip), { ip: pick.ip, mac, hostname: name, starts: now, ends: now + config.defaultLeaseTime * 1000, state: 'active' as const }];
      return { name, mac, outcome: pick.reason, ip: pick.ip };
    });
    return { rows, opts, subnet, leaseTime: config.defaultLeaseTime, warnings };
  }, [conf, clients]);

  return (
    <div className="card">
      <p className="muted small">Edit the configuration or the list of clients (one "name MAC" per line, in request order). The engine's dhcpd.conf parser and allocation function compute what ns1 would offer on eth0 ({SERVER_ADDR}): reservation first, then this MAC's previous lease, then the first free address in the range.</p>
      <div className="row" style={{ alignItems: 'stretch' }}>
        <label style={{ flex: 2, minWidth: 280 }}>/etc/dhcp/dhcpd.conf
          <textarea spellCheck={false} value={conf} onChange={(e) => setConf(e.target.value)} rows={18} style={{ width: '100%', fontFamily: 'var(--mono, monospace)' }} />
        </label>
        <label style={{ flex: 1, minWidth: 220 }}>Clients (name MAC)
          <textarea spellCheck={false} value={clients} onChange={(e) => setClients(e.target.value)} rows={18} style={{ width: '100%', fontFamily: 'var(--mono, monospace)' }} />
        </label>
      </div>
      <div className="row"><button onClick={() => { setConf(DHCPD_CONF); setClients(DEFAULT_CLIENTS); }}>Reset to the lab configuration</button></div>
      {'error' in result ? (
        <pre className="bad">{result.error}</pre>
      ) : (
        <>
          <p className="small">Offered to every client: mask /{result.subnet!.prefix}; router {result.opts!.routers?.join(', ') ?? '(none)'}; DNS {result.opts!.domainNameServers?.join(', ') ?? '(none)'}; domain {result.opts!.domainName ?? '(none)'}; lease {result.leaseTime} s (renew at {Math.floor(result.leaseTime! / 2)} s).</p>
          {result.warnings!.map((w) => <div key={w} className="callout small">⚠ {w}</div>)}
          <table>
            <thead><tr><th>#</th><th>Client</th><th>MAC</th><th>Address</th><th>Why</th></tr></thead>
            <tbody>
              {result.rows!.map((r, i) => (
                <tr key={i}><td>{i + 1}</td><td>{r.name}</td><td><code>{r.mac}</code></td><td>{r.ip ? <code>{r.ip}</code> : '—'}</td><td className={r.ip ? '' : 'bad'}>{r.outcome}</td></tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// NAT inspector: one connection through a fresh lab, captured on both sides of
// rtr01, plus rtr01's conntrack table.
// ---------------------------------------------------------------------------

interface NatFlow {
  id: string;
  label: string;
  host: string;
  user: string;
  command: string;
  inside: string;
  outside: string;
  filter: string;
}

const NAT_FLOWS: NatFlow[] = [
  { id: 'out', label: 'Outbound: ws01 → Internet web server (masquerade)', host: 'ws01', user: 'alice', command: 'curl -I http://203.0.113.80/', inside: 'eth0', outside: 'eth2', filter: 'tcp port 80' },
  { id: 'in', label: 'Inbound: Internet → published web server (DNAT)', host: 'ext01', user: 'guest', command: 'curl -I http://203.0.113.2/', inside: 'eth1', outside: 'eth2', filter: 'tcp port 80' },
  { id: 'ping', label: 'Outbound ping from ws01 (ICMP is translated too)', host: 'ws01', user: 'alice', command: 'ping -c 1 203.0.113.80', inside: 'eth0', outside: 'eth2', filter: 'icmp' },
];

function sh(w: { v: World }, host: string, user: string, cmd: string): string {
  const s = new Shell(() => w.v, (n) => (w.v = n), { hostId: host, user, cwd: '/' });
  return s.execute(cmd).output;
}

/** The first frames of the flow from tcpdump output, without banner lines and timestamps. */
function frames(out: string): string {
  return out.split('\n').filter((l) => /^\d\d:\d\d:\d\d\./.test(l)).slice(0, 4).map((l) => l.replace(/^\S+ /, '')).join('\n') || '(no frames)';
}

export function NatInspector() {
  const [id, setId] = useState(NAT_FLOWS[0].id);
  const [noMasq, setNoMasq] = useState(false);
  const flow = NAT_FLOWS.find((f) => f.id === id)!;
  const res = useMemo(() => {
    const w = { v: freshLab() };
    if (noMasq) {
      sh(w, 'rtr01', 'root', "sed -i '/oifname \"eth2\" masquerade/d' /etc/nftables.conf");
      sh(w, 'rtr01', 'root', 'systemctl reload nftables');
    }
    for (const h of Object.values(w.v.hosts)) h.capture = [];
    const client = sh(w, flow.host, flow.user, flow.command.replace('curl -I', 'curl -I -m 5'));
    const c = (i: string) => frames(sh(w, 'rtr01', 'root', `tcpdump -n -i ${i} ${flow.filter}`));
    return { client, inside: c(flow.inside), outside: c(flow.outside), ct: sh(w, 'rtr01', 'root', 'conntrack -L'), nat: sh(w, 'rtr01', 'root', 'nft list table ip nat') };
  }, [flow, noMasq]);
  const insideFirst = flow.id !== 'in';
  const panes = [
    { title: `rtr01 ${flow.inside} (inside)`, text: res.inside },
    { title: `rtr01 ${flow.outside} (Internet side)`, text: res.outside },
  ];
  if (!insideFirst) panes.reverse();
  return (
    <div className="card">
      <div className="row">
        <label>Flow:{' '}
          <select value={id} onChange={(e) => setId(e.target.value)}>
            {NAT_FLOWS.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
          </select>
        </label>
        <label><input type="checkbox" checked={noMasq} onChange={(e) => setNoMasq(e.target.checked)} /> remove the masquerade rule first</label>
      </div>
      <p className="small"><code>{flow.user}@{flow.host}$ {flow.command}</code></p>
      <pre style={{ maxHeight: 120 }}>{res.client}</pre>
      <p className="muted small">The first frames of the flow as captured on each side of rtr01 (direction of travel: left → right). Compare the addresses and ports.</p>
      <div className="row" style={{ alignItems: 'stretch' }}>
        {panes.map((p) => (
          <div key={p.title} style={{ flex: 1, minWidth: 280 }}>
            <strong className="small">{p.title}</strong>
            <pre style={{ fontSize: 12 }}>{p.text}</pre>
          </div>
        ))}
      </div>
      <strong className="small">rtr01# conntrack -L</strong>
      <pre style={{ fontSize: 12 }}>{res.ct}</pre>
      <details><summary className="small">rtr01# nft list table ip nat</summary><pre style={{ fontSize: 12 }}>{res.nat}</pre></details>
    </div>
  );
}
