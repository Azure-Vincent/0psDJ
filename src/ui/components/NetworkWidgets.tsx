import { useMemo, useState } from 'react';
import { runCapture } from '../../engine/lab/captures';
import { freshLab } from '../../engine/lab/dependencies';
import { broadcastOf, formatIp, inCidr, parseCidr, parseIp, prefixMask } from '../../engine/net/ip';
import { frameBytes } from '../../engine/pcap';
import { dnsQuery, lookupHostsFile, resolve } from '../../engine/sim/dns';
import { writeFile, readFile } from '../../engine/fs';
import { seededInt } from '../../engine/util/sha256';
import { recordConcepts } from '../../learning/progress';
import { useProgress } from '../state';

// ---------------------------------------------------------------------------
// Subnetting practice
// ---------------------------------------------------------------------------

function makeProblem(seed: number) {
  const prefix = seededInt(`p${seed}`, 17, 30);
  const ip = [seededInt(`a${seed}`, 0, 2) === 0 ? 10 : seededInt(`a${seed}`, 0, 1) ? 172 : 192, 0, 0, 0];
  if (ip[0] === 172) ip[1] = seededInt(`b${seed}`, 16, 31);
  else if (ip[0] === 192) ip[1] = 168;
  else ip[1] = seededInt(`b${seed}`, 0, 255);
  ip[2] = seededInt(`c${seed}`, 0, 255);
  ip[3] = seededInt(`d${seed}`, 1, 254);
  const addr = ip.join('.');
  const net = formatIp((parseIp(addr)! & prefixMask(prefix)) >>> 0);
  const bc = broadcastOf(addr, prefix);
  const hosts = 2 ** (32 - prefix) - 2;
  const first = formatIp((parseIp(net)! + 1) >>> 0);
  const last = formatIp((parseIp(bc)! - 1) >>> 0);
  return { addr, prefix, answers: { network: net, broadcast: bc, first, last, hosts: String(hosts) } };
}

const FIELDS: [keyof ReturnType<typeof makeProblem>['answers'], string][] = [
  ['network', 'Network address'], ['broadcast', 'Broadcast address'], ['first', 'First usable host'], ['last', 'Last usable host'], ['hosts', 'Usable hosts'],
];

export function SubnetPractice() {
  const { update } = useProgress();
  const [seed, setSeed] = useState(1);
  const [vals, setVals] = useState<Record<string, string>>({});
  const [checked, setChecked] = useState(false);
  const p = useMemo(() => makeProblem(seed), [seed]);
  const ok = (k: string) => (vals[k] ?? '').trim() === p.answers[k as keyof typeof p.answers];
  const allOk = FIELDS.every(([k]) => ok(k));
  const block = 2 ** (32 - p.prefix);
  return (
    <div className="card" style={{ margin: '10px 0' }}>
      <div className="spread"><h3 style={{ margin: 0 }}>Subnetting practice</h3><span className="muted small">problem #{seed}</span></div>
      <p>Host address <code>{p.addr}/{p.prefix}</code> (mask {formatIp(prefixMask(p.prefix))}). Work out:</p>
      <table style={{ maxWidth: 520 }}>
        <tbody>
          {FIELDS.map(([k, label]) => (
            <tr key={k}>
              <th>{label}</th>
              <td>
                <input className="mono" value={vals[k] ?? ''} onChange={(e) => { setVals({ ...vals, [k]: e.target.value }); setChecked(false); }} />
                {checked && <span style={{ marginLeft: 8, color: ok(k) ? 'var(--ok)' : 'var(--err)' }}>{ok(k) ? '✓' : `✗ ${p.answers[k]}`}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row">
        <button className="primary" onClick={() => { setChecked(true); update((pr) => recordConcepts(pr, ['net.cidr'], allOk, Date.now(), allOk ? undefined : `subnet:/${p.prefix}`)); }}>Check</button>
        <button onClick={() => { setSeed((s) => s + 1); setVals({}); setChecked(false); }}>New problem</button>
      </div>
      {checked && (
        <div className="callout small">
          Method: a /{p.prefix} leaves {32 - p.prefix} host bits, so blocks of {block.toLocaleString()} addresses.
          {p.prefix >= 24 ? ` In the last octet, blocks start at multiples of ${block}.` : p.prefix >= 16 ? ` In the third octet, blocks start at multiples of ${block / 256}.` : ''}
          {' '}The block containing {p.addr} starts at {p.answers.network}; the broadcast is the last address of the block; usable hosts exclude both: {block} − 2 = {p.answers.hosts}.
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Longest-prefix-match route lookup
// ---------------------------------------------------------------------------

const DEFAULT_ROUTES = `default via 10.0.10.1 dev eth0
10.0.10.0/24 dev eth0 proto kernel scope link src 10.0.10.25
10.0.0.0/16 via 10.0.10.2 dev eth0
10.0.20.0/24 via 10.0.10.3 dev eth0
192.168.50.0/24 via 10.0.10.4 dev eth0`;

export function RouteLookup() {
  const [text, setText] = useState(DEFAULT_ROUTES);
  const [dst, setDst] = useState('10.0.20.77');
  const rows = text.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const t = line.split(/\s+/);
    const cidr = parseCidr(t[0] === 'default' ? 'default' : t[0].includes('/') ? t[0] : `${t[0]}/32`);
    const via = t.includes('via') ? t[t.indexOf('via') + 1] : undefined;
    const dev = t.includes('dev') ? t[t.indexOf('dev') + 1] : undefined;
    return { line, cidr, via, dev, match: cidr && parseIp(dst) !== null ? inCidr(dst, cidr) : false };
  });
  const best = rows.filter((r) => r.match).sort((a, b) => b.cidr!.prefix - a.cidr!.prefix)[0];
  return (
    <div className="card" style={{ margin: '10px 0' }}>
      <h3>Route lookup (longest prefix match)</h3>
      <div className="grid2">
        <div>
          <div className="small muted">Routing table (ip route format)</div>
          <textarea rows={7} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
          <label className="row" style={{ marginTop: 6 }}>Destination <input className="mono" value={dst} onChange={(e) => setDst(e.target.value)} /></label>
        </div>
        <div>
          {parseIp(dst) === null ? <div className="feedback bad small">Enter an IPv4 address.</div> : (
            <>
              <table className="small">
                <thead><tr><th>Route</th><th>/len</th><th>Contains {dst}?</th></tr></thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={i} style={r === best ? { background: 'var(--accent-soft)', fontWeight: 600 } : !r.match ? { color: 'var(--muted)' } : undefined}>
                      <td className="mono">{r.line}</td><td>{r.cidr ? r.cidr.prefix : '?'}</td><td>{!r.cidr ? 'unparsed' : r.match ? (r === best ? 'yes: longest match' : 'yes') : 'no'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {best ? (
                <div className="feedback ok small">{dst} {best.via ? `via ${best.via} ` : '(on-link, ARP for the destination itself) '}dev {best.dev ?? '?'}</div>
              ) : <div className="feedback bad small">No route matches: "Network is unreachable".</div>}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Encapsulation explorer
// ---------------------------------------------------------------------------

interface Field { layer: 'eth' | 'arp' | 'ip' | 'l4' | 'payload' | 'pad'; name: string; start: number; end: number }

const LAYER_COLOR: Record<Field['layer'], string> = {
  eth: 'var(--c-yellow)', arp: 'var(--c-violet)', ip: 'var(--c-blue)', l4: 'var(--c-green)', payload: 'var(--c-red)', pad: 'var(--c-gray)',
};

function dissect(b: Uint8Array): Field[] {
  const f: Field[] = [
    { layer: 'eth', name: 'Destination MAC', start: 0, end: 6 },
    { layer: 'eth', name: 'Source MAC', start: 6, end: 12 },
    { layer: 'eth', name: 'EtherType', start: 12, end: 14 },
  ];
  const type = (b[12] << 8) | b[13];
  if (type === 0x0806) {
    f.push(
      { layer: 'arp', name: 'Hardware / protocol type', start: 14, end: 18 }, { layer: 'arp', name: 'Address lengths', start: 18, end: 20 },
      { layer: 'arp', name: 'Opcode', start: 20, end: 22 }, { layer: 'arp', name: 'Sender MAC', start: 22, end: 28 }, { layer: 'arp', name: 'Sender IP', start: 28, end: 32 },
      { layer: 'arp', name: 'Target MAC', start: 32, end: 38 }, { layer: 'arp', name: 'Target IP', start: 38, end: 42 }, { layer: 'pad', name: 'Ethernet padding (min. 60 bytes)', start: 42, end: b.length },
    );
    return f;
  }
  const ihl = (b[14] & 15) * 4;
  const total = (b[16] << 8) | b[17];
  f.push(
    { layer: 'ip', name: 'Version + header length', start: 14, end: 15 }, { layer: 'ip', name: 'DSCP/ECN', start: 15, end: 16 },
    { layer: 'ip', name: 'Total length', start: 16, end: 18 }, { layer: 'ip', name: 'Identification', start: 18, end: 20 },
    { layer: 'ip', name: 'Flags + fragment offset', start: 20, end: 22 }, { layer: 'ip', name: 'TTL', start: 22, end: 23 },
    { layer: 'ip', name: 'Protocol', start: 23, end: 24 }, { layer: 'ip', name: 'Header checksum', start: 24, end: 26 },
    { layer: 'ip', name: 'Source address', start: 26, end: 30 }, { layer: 'ip', name: 'Destination address', start: 30, end: 34 },
  );
  const s = 14 + ihl;
  const proto = b[23];
  let hdr = 8;
  if (proto === 6) {
    hdr = (b[s + 12] >> 4) * 4;
    f.push(
      { layer: 'l4', name: 'TCP source port', start: s, end: s + 2 }, { layer: 'l4', name: 'TCP destination port', start: s + 2, end: s + 4 },
      { layer: 'l4', name: 'Sequence number', start: s + 4, end: s + 8 }, { layer: 'l4', name: 'Acknowledgment number', start: s + 8, end: s + 12 },
      { layer: 'l4', name: 'Data offset + flags', start: s + 12, end: s + 14 }, { layer: 'l4', name: 'Window', start: s + 14, end: s + 16 },
      { layer: 'l4', name: 'TCP checksum', start: s + 16, end: s + 18 }, { layer: 'l4', name: 'Urgent pointer', start: s + 18, end: s + 20 },
    );
    if (hdr > 20) f.push({ layer: 'l4', name: 'TCP options', start: s + 20, end: s + hdr });
  } else if (proto === 17) {
    f.push(
      { layer: 'l4', name: 'UDP source port', start: s, end: s + 2 }, { layer: 'l4', name: 'UDP destination port', start: s + 2, end: s + 4 },
      { layer: 'l4', name: 'UDP length', start: s + 4, end: s + 6 }, { layer: 'l4', name: 'UDP checksum', start: s + 6, end: s + 8 },
    );
  } else {
    f.push({ layer: 'l4', name: 'ICMP type', start: s, end: s + 1 }, { layer: 'l4', name: 'ICMP code', start: s + 1, end: s + 2 }, { layer: 'l4', name: 'ICMP checksum', start: s + 2, end: s + 4 }, { layer: 'l4', name: 'ICMP rest of header', start: s + 4, end: s + 8 });
  }
  if (14 + total > s + hdr) f.push({ layer: 'payload', name: proto === 17 ? 'Application data (DNS)' : proto === 6 ? 'Application data' : 'ICMP data', start: s + hdr, end: 14 + total });
  if (b.length > 14 + total) f.push({ layer: 'pad', name: 'Ethernet padding (min. 60 bytes)', start: 14 + total, end: b.length });
  return f;
}

function fieldValue(b: Uint8Array, fl: Field): string {
  const bytes = [...b.slice(fl.start, fl.end)];
  if (fl.name.includes('MAC')) return bytes.map((x) => x.toString(16).padStart(2, '0')).join(':');
  if (/address|IP$/.test(fl.name) && bytes.length === 4) return bytes.join('.');
  if (bytes.length <= 4 && !/(Application|ICMP) data|options|padding/i.test(fl.name)) {
    const n = bytes.reduce((a, x) => a * 256 + x, 0);
    if (fl.name === 'EtherType') return `0x${n.toString(16).padStart(4, '0')} (${n === 0x0800 ? 'IPv4' : n === 0x0806 ? 'ARP' : '?'})`;
    if (fl.name === 'Protocol') return `${n} (${n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : '?'})`;
    if (fl.name === 'Data offset + flags') {
      const names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG'].filter((_, k) => n & (1 << k));
      return `header ${(bytes[0] >> 4) * 4} bytes, flags 0x${(n & 0x3f).toString(16).padStart(2, '0')} (${names.join(', ')})`;
    }
    if (fl.name === 'Flags + fragment offset') return `0x${n.toString(16).padStart(4, '0')}${n & 0x4000 ? ' (DF: don\'t fragment)' : ''}${n & 0x2000 ? ' (MF)' : ''}, offset ${n & 0x1fff}`;
    if (fl.name === 'Version + header length') return `IPv${bytes[0] >> 4}, ${(bytes[0] & 15) * 4} bytes`;
    return /checksum/i.test(fl.name) ? `0x${n.toString(16).padStart(4, '0')}` : String(n);
  }
  return `${bytes.length} bytes`;
}

export function EncapsulationExplorer() {
  const frames = useMemo(() => runCapture('ssh-login').frames, []);
  const options = useMemo(() => {
    const pick = (pred: (i: number) => boolean, label: string) => { const i = frames.findIndex((_, k) => pred(k)); return i >= 0 ? [{ i, label }] : []; };
    return [
      ...pick((k) => frames[k].arp?.op === 'request', 'ARP request (broadcast)'),
      ...pick((k) => frames[k].ip?.app?.protocol === 'DNS', 'DNS query over UDP'),
      ...pick((k) => !!frames[k].ip?.tcp?.flags.includes('SYN') && !frames[k].ip!.tcp!.flags.includes('ACK'), 'TCP SYN'),
      ...pick((k) => frames[k].ip?.app?.info?.startsWith('Client: Protocol') ?? false, 'SSH identification string (TCP payload)'),
    ];
  }, [frames]);
  const [sel, setSel] = useState(options[0]?.i ?? 0);
  const [hover, setHover] = useState<string | null>(null);
  const bytes = frameBytes(frames[sel]);
  const fields = dissect(bytes);
  const fieldAt = (i: number) => fields.find((f) => i >= f.start && i < f.end);
  return (
    <div className="card" style={{ margin: '10px 0' }}>
      <h3>Encapsulation explorer</h3>
      <div className="row small" style={{ marginBottom: 8 }}>
        {options.map((o) => <button key={o.i} className={o.i === sel ? 'primary' : ''} onClick={() => setSel(o.i)}>{o.label}</button>)}
        <span className="muted">Frames captured on ws01:eth0 by the simulator ({bytes.length} bytes).</span>
      </div>
      <div className="row small" style={{ marginBottom: 6 }}>
        {(['eth', 'arp', 'ip', 'l4', 'payload', 'pad'] as const).filter((l) => fields.some((f) => f.layer === l)).map((l) => (
          <span key={l} className="badge" style={{ color: LAYER_COLOR[l], borderColor: LAYER_COLOR[l] }}>{{ eth: 'Ethernet (L2)', arp: 'ARP', ip: 'IPv4 (L3)', l4: 'TCP/UDP/ICMP (L4)', payload: 'Payload', pad: 'Padding' }[l]}</span>
        ))}
      </div>
      <div className="hex" style={{ display: 'flex', flexWrap: 'wrap', gap: 2, maxWidth: 16 * 26 }}>
        {[...bytes].map((x, i) => {
          const f = fieldAt(i);
          return (
            <span key={i} title={f?.name} onMouseEnter={() => setHover(f?.name ?? null)} onMouseLeave={() => setHover(null)}
              style={{ width: 24, textAlign: 'center', borderBottom: `3px solid ${f ? LAYER_COLOR[f.layer] : 'transparent'}`, background: hover && f?.name === hover ? 'var(--accent-soft)' : undefined }}>
              {x.toString(16).padStart(2, '0')}
            </span>
          );
        })}
      </div>
      <table className="small" style={{ marginTop: 10 }}>
        <thead><tr><th>Bytes</th><th>Field</th><th>Value</th></tr></thead>
        <tbody>
          {fields.map((f) => (
            <tr key={f.name + f.start} onMouseEnter={() => setHover(f.name)} onMouseLeave={() => setHover(null)} style={hover === f.name ? { background: 'var(--accent-soft)' } : undefined}>
              <td className="mono">{f.start}–{f.end - 1}</td>
              <td><span style={{ color: LAYER_COLOR[f.layer] }}>■</span> {f.name}</td>
              <td className="mono">{fieldValue(bytes, f)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Resolver tracer
// ---------------------------------------------------------------------------

export function ResolverTracer() {
  const [host, setHost] = useState('ws01');
  const [name, setName] = useState('www');
  const [hostsEntry, setHostsEntry] = useState(false);
  const [badServer, setBadServer] = useState(false);
  const result = useMemo(() => {
    const w = freshLab();
    const h = w.hosts[host];
    if (hostsEntry) writeFile(h, '/etc/hosts', (readFile(h, '/etc/hosts') ?? '') + '10.0.20.99\tsrv01.corp.lab srv01\n', w.clock);
    if (badServer) writeFile(h, '/etc/resolv.conf', (readFile(h, '/etc/resolv.conf') ?? '').replace('10.0.10.53', '10.0.10.35'), w.clock);
    const filesHit = lookupHostsFile(h, name);
    const start = w.clock;
    const r = resolve(w, h, name);
    const elapsed = w.clock - start;
    const dw = freshLabWith(host, badServer);
    const dig = dnsQuery(dw, dw.hosts[host], badServer ? '10.0.10.35' : '10.0.10.53', name.endsWith('.') ? name : name + '.', 5);
    return { r, filesHit, elapsed, dig, resolv: readFile(h, '/etc/resolv.conf') ?? '' };
  }, [host, name, hostsEntry, badServer]);
  return (
    <div className="card" style={{ margin: '10px 0' }}>
      <h3>Resolver tracer (getaddrinfo step by step)</h3>
      <div className="row small">
        <label>Host <select value={host} onChange={(e) => setHost(e.target.value)}><option>ws01</option><option>srv01</option></select></label>
        <label>Name <input className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} /></label>
        <label className="row"><input type="checkbox" checked={hostsEntry} onChange={(e) => setHostsEntry(e.target.checked)} /> add stale /etc/hosts entry for srv01</label>
        <label className="row"><input type="checkbox" checked={badServer} onChange={(e) => setBadServer(e.target.checked)} /> typo in resolv.conf (10.0.10.35)</label>
      </div>
      <div className="grid2" style={{ marginTop: 8 }}>
        <div>
          <ol className="small">
            <li><strong>/etc/hosts</strong>: {result.filesHit ? <>match → <code>{result.filesHit}</code> (DNS is not asked)</> : 'no match'}</li>
            {!result.filesHit && (
              <>
                {result.r.exchanges.map((x, i) => (
                  <li key={i}>
                    DNS query <code>{x.qname}</code> to {x.server}: <strong>{x.outcome}</strong>
                    {x.answer && x.answer.answers.length ? ` (${x.answer.answers.map((a) => `${a.type} ${a.data}`).join(', ')})` : ''}
                    {' '}<span className="muted">{Math.round(x.rttMs)} ms</span>
                  </li>
                ))}
              </>
            )}
          </ol>
          <div className={`feedback ${result.r.ok ? 'ok' : 'bad'} small`}>
            getent hosts {name}: {result.r.ok ? `${result.r.ip} (${result.r.source === 'hosts' ? '/etc/hosts' : result.r.source === 'dns' ? `DNS, as ${result.r.fqdn}` : 'literal'})` : result.r.message}
            <span className="muted"> · {(result.elapsed / 1000).toFixed(2)} s simulated</span>
          </div>
        </div>
        <div>
          <div className="small muted">{host}:/etc/resolv.conf</div>
          <pre>{result.resolv}</pre>
          <div className="small">For comparison, <code>dig {name}</code> (no /etc/hosts, no search list) gets: <strong>{result.dig.outcome}</strong>{result.dig.answer?.answers.length ? ` ${result.dig.answer.answers.map((a) => a.data).join(', ')}` : ''}</div>
        </div>
      </div>
    </div>
  );
}

function freshLabWith(host: string, badServer: boolean) {
  const w = freshLab();
  if (badServer) { const h = w.hosts[host]; writeFile(h, '/etc/resolv.conf', (readFile(h, '/etc/resolv.conf') ?? '').replace('10.0.10.53', '10.0.10.35'), w.clock); }
  return w;
}
