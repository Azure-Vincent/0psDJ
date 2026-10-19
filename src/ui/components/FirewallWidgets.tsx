import { useMemo, useState } from 'react';
import { explainPacket, NftError, parseRulesetFile, type Hook } from '../../engine/config/nft';
import { SRV01_NFT } from '../../engine/lab/sshLab';
import { broadcastOf, formatIp, inCidr, parseCidr, parseIp, prefixMask } from '../../engine/net/ip';

/** Static diagram of the IPv4 netfilter hooks. */
export function HookDiagram() {
  const box = (x: number, y: number, w: number, label: string, accent = false) => (
    <g>
      <rect x={x} y={y} width={w} height={34} rx={6} fill={accent ? 'var(--accent-soft)' : 'var(--panel-2)'} stroke={accent ? 'var(--accent)' : 'var(--border)'} />
      <text x={x + w / 2} y={y + 21} textAnchor="middle" fontSize={12} fontWeight={accent ? 700 : 400} style={{ fill: 'var(--text)' }}>{label}</text>
    </g>
  );
  const arrow = (x1: number, y1: number, x2: number, y2: number) => <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--muted)" markerEnd="url(#h-arrow)" />;
  return (
    <div className="card" style={{ margin: '10px 0' }}>
      <svg viewBox="0 0 760 200" width="100%" role="img" aria-label="Netfilter hooks">
        <defs><marker id="h-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="var(--muted)" /></marker></defs>
        <text x={10} y={95} fontSize={11} style={{ fill: 'var(--muted)' }}>NIC in</text>
        {arrow(55, 91, 80, 91)}
        {box(80, 74, 110, 'prerouting')}
        {arrow(190, 91, 215, 91)}
        <polygon points="215,91 270,66 325,91 270,116" fill="var(--panel)" stroke="var(--border)" />
        <text x={270} y={88} textAnchor="middle" fontSize={10.5} style={{ fill: 'var(--text)' }}>routing</text>
        <text x={270} y={101} textAnchor="middle" fontSize={10.5} style={{ fill: 'var(--text)' }}>decision</text>
        {arrow(270, 66, 270, 40)}
        {box(215, 6, 110, 'input', true)}
        {arrow(325, 23, 380, 23)}
        <text x={385} y={27} fontSize={11} style={{ fill: 'var(--muted)' }}>local process (sshd, nginx…)</text>
        {arrow(325, 91, 380, 91)}
        {box(380, 74, 110, 'forward', true)}
        <text x={435} y={128} textAnchor="middle" fontSize={10} style={{ fill: 'var(--muted)' }}>only if ip_forward=1</text>
        {arrow(490, 91, 560, 91)}
        {box(560, 74, 120, 'postrouting')}
        {arrow(680, 91, 705, 91)}
        <text x={708} y={95} fontSize={11} style={{ fill: 'var(--muted)' }}>NIC out</text>
        <text x={385} y={170} fontSize={11} style={{ fill: 'var(--muted)' }}>local process sends</text>
        {arrow(480, 166, 500, 166)}
        {box(500, 149, 90, 'output', true)}
        {arrow(590, 166, 620, 108)}
      </svg>
      <div className="small muted">Filter chains on the highlighted hooks decide accept/drop/reject. Server firewalls live in <strong>input</strong> (and output); router firewalls in <strong>forward</strong>.</div>
    </div>
  );
}

export function CidrCalculator() {
  const [prefix, setPrefix] = useState('10.0.10.0/23');
  const [probe, setProbe] = useState('10.0.11.20');
  const c = parseCidr(prefix);
  const addr = parseIp(prefix.split('/')[0]);
  const valid = c && addr !== null && prefix.includes('/');
  const size = valid ? 2 ** (32 - c!.prefix) : 0;
  return (
    <div className="card" style={{ margin: '10px 0' }}>
      <h3>CIDR calculator</h3>
      <div className="row">
        <label>Prefix <input className="mono" value={prefix} onChange={(e) => setPrefix(e.target.value)} /></label>
        <label>Is this address inside? <input className="mono" value={probe} onChange={(e) => setProbe(e.target.value)} /></label>
      </div>
      {!valid ? <div className="feedback bad small">Enter a prefix like 10.0.10.0/23.</div> : (
        <table style={{ maxWidth: 560 }}>
          <tbody>
            <tr><th>Network</th><td className="mono">{formatIp(c!.network)}/{c!.prefix}{c!.network !== addr ? ` (you wrote ${prefix.split('/')[0]}: host bits are ignored)` : ''}</td></tr>
            <tr><th>Mask</th><td className="mono">{formatIp(prefixMask(c!.prefix))}</td></tr>
            <tr><th>Range</th><td className="mono">{formatIp(c!.network)} – {broadcastOf(formatIp(c!.network), c!.prefix)}</td></tr>
            <tr><th>Addresses</th><td className="mono">{size.toLocaleString()}{c!.prefix < 24 ? ` (= ${size / 256} × /24)` : ''}</td></tr>
            <tr><th>{probe}</th><td>{parseIp(probe) === null ? <span className="muted">not an IPv4 address</span> : inCidr(probe, c!) ? <span className="badge err">inside: a rule on this prefix matches it</span> : <span className="badge ok">outside</span>}</td></tr>
          </tbody>
        </table>
      )}
    </div>
  );
}

export function PacketTester() {
  const [text, setText] = useState(SRV01_NFT);
  const [hook, setHook] = useState<Hook>('input');
  const [src, setSrc] = useState('10.0.10.25');
  const [dst, setDst] = useState('10.0.20.10');
  const [proto, setProto] = useState<'tcp' | 'udp' | 'icmp'>('tcp');
  const [sport, setSport] = useState('51514');
  const [dport, setDport] = useState('22');
  const [ct, setCt] = useState<'new' | 'established' | 'related'>('new');
  const [iif, setIif] = useState('eth0');
  const result = useMemo(() => {
    try {
      const rs = parseRulesetFile(text);
      return { ok: true as const, ...explainPacket(rs, hook, {
        src, dst, proto, ctState: ct, len: 60,
        sport: proto === 'icmp' ? undefined : Number(sport), dport: proto === 'icmp' ? undefined : Number(dport),
        icmpType: proto === 'icmp' ? 'echo-request' : undefined,
        iif: hook === 'output' ? undefined : iif, oif: hook === 'input' ? undefined : 'eth1',
      }) };
    } catch (e) {
      return { ok: false as const, error: e instanceof NftError ? e.message : String(e) };
    }
  }, [text, hook, src, dst, proto, sport, dport, ct, iif]);
  return (
    <div className="grid2">
      <div>
        <div className="small muted">Ruleset (nft -f format)</div>
        <textarea rows={20} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
      </div>
      <div>
        <div className="small muted">Packet</div>
        <div className="row small" style={{ marginBottom: 8 }}>
          <label>hook <select value={hook} onChange={(e) => setHook(e.target.value as Hook)}><option>input</option><option>forward</option><option>output</option></select></label>
          <label>src <input className="mono" style={{ width: 110 }} value={src} onChange={(e) => setSrc(e.target.value)} /></label>
          <label>dst <input className="mono" style={{ width: 110 }} value={dst} onChange={(e) => setDst(e.target.value)} /></label>
          <label>proto <select value={proto} onChange={(e) => setProto(e.target.value as typeof proto)}><option>tcp</option><option>udp</option><option>icmp</option></select></label>
          {proto !== 'icmp' && <label>sport <input className="mono" style={{ width: 64 }} value={sport} onChange={(e) => setSport(e.target.value)} /></label>}
          {proto !== 'icmp' && <label>dport <input className="mono" style={{ width: 64 }} value={dport} onChange={(e) => setDport(e.target.value)} /></label>}
          <label>ct state <select value={ct} onChange={(e) => setCt(e.target.value as typeof ct)}><option>new</option><option>established</option><option>related</option></select></label>
          {hook !== 'output' && <label>iif <input className="mono" style={{ width: 52 }} value={iif} onChange={(e) => setIif(e.target.value)} /></label>}
        </div>
        {!result.ok ? <pre style={{ color: 'var(--err)' }}>{result.error}</pre> : (
          <>
            <div className={`feedback ${result.result.verdict === 'accept' ? 'ok' : 'bad'}`}>
              Verdict: <strong>{result.result.verdict}</strong>{result.result.rejectWith ? ` (${result.result.rejectWith})` : ''}
            </div>
            <table className="small">
              <thead><tr><th>#</th><th>Chain</th><th>Rule</th><th>Result</th></tr></thead>
              <tbody>
                {result.steps.length === 0 && <tr><td colSpan={4} className="muted">No base chain on the {hook} hook: the packet is not filtered.</td></tr>}
                {result.steps.map((s, i) => (
                  <tr key={i} style={s.matched && s.outcome.includes('→') ? { background: 'var(--accent-soft)' } : s.matched ? undefined : { color: 'var(--muted)' }}>
                    <td>{s.handle ?? '—'}</td><td className="mono">{s.chain}</td><td className="mono">{s.text}</td><td>{s.outcome}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="small muted">Uses the simulator's evaluator on a copy of the ruleset (counters are not changed). "ct state" is what conntrack would have classified.</div>
          </>
        )}
      </div>
    </div>
  );
}
