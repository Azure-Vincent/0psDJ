import { useMemo, useState } from 'react';
import { fullchain, SRV01_ONLY_CERT, WWW_CERT, WWW_CERT_2025 } from '../../engine/lab/pkiLab';
import { asn1Time, type Cert, cn, CORP_ISSUING, CORP_ROOT, dnOpenssl, matchesHost, parseCerts, PUBLIC_ROOTS, VERIFY_TEXT, verifyChain } from '../../engine/sim/pki';

// ---------------------------------------------------------------------------
// Certificate chain inspector: verify the lab's certificates with the
// simulator's OpenSSL-style chain builder under different server/client setups.
// ---------------------------------------------------------------------------

const LEAVES: Record<string, { label: string; cert: Cert }> = {
  current: { label: 'www.corp.lab (2026, valid)', cert: WWW_CERT.cert },
  expired: { label: 'www.corp.lab (2025, expired 17 Oct 2026)', cert: WWW_CERT_2025.cert },
  srv01: { label: 'srv01.corp.lab only', cert: SRV01_ONLY_CERT.cert },
};

const CLOCKS: Record<string, { label: string; ms: number }> = {
  now: { label: 'correct (19 Oct 2026)', ms: Date.parse('2026-10-19T08:30:00Z') },
  past: { label: 'wrong: 1 Jan 2024 (dead CMOS battery)', ms: Date.parse('2024-01-01T00:00:00Z') },
};

export function ChainInspector() {
  const [leaf, setLeaf] = useState('current');
  const [sends, setSends] = useState<'full' | 'leaf'>('full');
  const [store, setStore] = useState<'corp' | 'public'>('corp');
  const [name, setName] = useState('www.corp.lab');
  const [clock, setClock] = useState('now');
  const r = useMemo(() => {
    const presented = sends === 'full' ? [LEAVES[leaf].cert, CORP_ISSUING.cert] : [LEAVES[leaf].cert];
    const trusted = [...PUBLIC_ROOTS.map((x) => x.cert), ...(store === 'corp' ? [CORP_ROOT.cert] : [])];
    const v = verifyChain(presented[0], presented.slice(1), trusted, CLOCKS[clock].ms);
    const match = matchesHost(presented[0], name.trim());
    const first = v.errors[0];
    const curl = first ? `curl: (60) SSL certificate problem: ${VERIFY_TEXT[first.code]}` : !match ? `curl: (60) SSL: no alternative certificate subject name matches target host name '${name.trim()}'` : 'HTTP/1.1 200 OK  (SSL certificate verify ok)';
    // sanity: the PEM round trip used by the real files
    const roundTrip = parseCerts(fullchain(presented[0], ...presented.slice(1))).length === presented.length;
    return { presented, v, match, curl, roundTrip };
  }, [leaf, sends, store, name, clock]);
  const rows = [...r.v.chain].map((c, depth) => ({ c, depth, errs: r.v.errors.filter((e) => e.depth === depth) }));
  return (
    <div className="card">
      <p className="muted small">The same chain building and checks the lab's curl and openssl use (simulated cryptography, OpenSSL 3.0 error codes). Change what the server presents and what the client trusts, and see which check fails first.</p>
      <div className="row" style={{ flexWrap: 'wrap', gap: 12 }}>
        <label className="small">Server certificate<br />
          <select value={leaf} onChange={(e) => setLeaf(e.target.value)}>{Object.entries(LEAVES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select>
        </label>
        <label className="small">nginx ssl_certificate file contains<br />
          <select value={sends} onChange={(e) => setSends(e.target.value as 'full' | 'leaf')}><option value="full">leaf + intermediate (full chain)</option><option value="leaf">leaf only</option></select>
        </label>
        <label className="small">Client trust store<br />
          <select value={store} onChange={(e) => setStore(e.target.value as 'corp' | 'public')}><option value="corp">public roots + Corp Lab Root CA</option><option value="public">public roots only (fresh install)</option></select>
        </label>
        <label className="small">Client clock<br />
          <select value={clock} onChange={(e) => setClock(e.target.value)}>{Object.entries(CLOCKS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select>
        </label>
        <label className="small">Name in the URL<br />
          <input value={name} onChange={(e) => setName(e.target.value)} style={{ width: 160 }} />
        </label>
      </div>
      <h3>Chain built by the client</h3>
      <table>
        <thead><tr><th>Depth</th><th>Subject</th><th>Issuer</th><th>Valid</th><th>From</th><th>Result</th></tr></thead>
        <tbody>
          {rows.slice().reverse().map(({ c, depth, errs }) => (
            <tr key={depth}>
              <td>{depth}</td>
              <td><code>{dnOpenssl(c.subject)}</code>{c.ca ? ' (CA)' : ''}</td>
              <td><code>{cn(c.issuer)}</code></td>
              <td className="small">{asn1Time(c.notBefore)} –<br />{asn1Time(c.notAfter)}</td>
              <td className="small">{c === CORP_ROOT.cert || PUBLIC_ROOTS.some((x) => x.cert === c) ? 'client trust store' : 'sent by server'}</td>
              <td className="small">{errs.length ? errs.map((e) => <div key={e.code} style={{ color: 'var(--bad, #c0392b)' }}>error {e.code}: {VERIFY_TEXT[e.code]}</div>) : <span style={{ color: 'var(--good, #1e8449)' }}>ok</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="small">Name check: {r.match ? <>“{name.trim()}” matches <code>{r.match}</code> in the subjectAltName.</> : <>“{name.trim()}” is not in <code>{r.presented[0].san.join(', ')}</code>.</>}</p>
      <pre className="small">{r.curl}{r.v.errors.length ? `\n(openssl s_client: Verify return code: ${r.v.errors[r.v.errors.length - 1].code} (${VERIFY_TEXT[r.v.errors[r.v.errors.length - 1].code]}))` : ''}</pre>
      {!r.roundTrip && <p className="small muted">PEM round trip failed.</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MTU calculator: IP MTU, MSS and test sizes for common encapsulations.
// ---------------------------------------------------------------------------

const ENCAPS: { id: string; label: string; overhead: number; note: string }[] = [
  { id: 'none', label: 'None (plain Ethernet)', overhead: 0, note: 'Ethernet frame on the wire: MTU + 14 header + 4 FCS.' },
  { id: 'vlan', label: '802.1Q VLAN tag', overhead: 0, note: 'The 4-byte tag enlarges the frame (1522), not the IP packet: the IP MTU stays the same if switches accept "baby giant" frames (all modern ones do).' },
  { id: 'pppoe', label: 'PPPoE (DSL/fibre)', overhead: 8, note: 'PPPoE header 6 + PPP 2 bytes. Classic home/office uplinks: 1492.' },
  { id: 'gre', label: 'GRE over IPv4', overhead: 24, note: 'Outer IPv4 20 + GRE 4.' },
  { id: 'vxlan', label: 'VXLAN over IPv4', overhead: 50, note: 'Outer Ethernet 14 + IPv4 20 + UDP 8 + VXLAN 8: overlays need 1550+ underlay MTU or 1450 inside.' },
  { id: 'wg4', label: 'WireGuard over IPv4', overhead: 60, note: 'IPv4 20 + UDP 8 + WireGuard 32. wg-quick uses 1420 to also fit IPv6 transport.' },
  { id: 'wg6', label: 'WireGuard over IPv6', overhead: 80, note: 'IPv6 40 + UDP 8 + WireGuard 32: 1420 inside a 1500 link.' },
  { id: 'ipsec', label: 'IPsec ESP tunnel (AES-GCM, IPv4)', overhead: 73, note: 'Outer IPv4 20 + ESP header 8 + IV 8 + padding/trailer up to 21 + ICV 16: worst case ~73; many gateways clamp MSS to 1360.' },
];

export function MtuCalculator() {
  const [link, setLink] = useState(1500);
  const [enc, setEnc] = useState('pppoe');
  const e = ENCAPS.find((x) => x.id === enc)!;
  const mtu = link - e.overhead;
  const valid = Number.isInteger(link) && link >= 576 && link <= 9216 && mtu >= 576;
  const rows: [string, string, string][] = valid ? [
    ['IP MTU inside the encapsulation', String(mtu), 'Largest IP packet the endpoints may send through this link.'],
    ['TCP MSS (IPv4)', String(mtu - 40), 'MTU − 20 IP − 20 TCP. With timestamps a full segment carries 12 bytes less data.'],
    ['TCP MSS (IPv6)', String(mtu - 60), 'MTU − 40 IPv6 − 20 TCP.'],
    ['ping -M do -s (IPv4)', String(mtu - 28), 'Largest echo data that fits: MTU − 20 IP − 8 ICMP.'],
    ['ping -6 -M do -s', String(mtu - 48), 'MTU − 40 IPv6 − 8 ICMPv6.'],
    ['Ethernet frame on the underlying link', String(link + 18 + (enc === 'vlan' ? 4 : 0)), 'Including the 14-byte header and 4-byte FCS (+4 for an 802.1Q tag).'],
  ] : [];
  return (
    <div className="card">
      <p className="muted small">Work out the sizes for a link and the encapsulation it carries. Both ends of a link must use the same MTU; routers in front of a smaller link should clamp the TCP MSS.</p>
      <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
        <label className="small">Underlying link MTU<br /><input type="number" value={link} min={576} max={9216} onChange={(ev) => setLink(Number(ev.target.value))} style={{ width: 90 }} /></label>
        <label className="small">Encapsulation<br />
          <select value={enc} onChange={(ev) => setEnc(ev.target.value)}>{ENCAPS.map((x) => <option key={x.id} value={x.id}>{x.label}{x.overhead ? ` (−${x.overhead})` : ''}</option>)}</select>
        </label>
      </div>
      {!valid ? <p className="small">Enter a link MTU between 576 and 9216 that leaves at least 576 bytes inside the encapsulation.</p> : (
        <>
          <table>
            <thead><tr><th>Value</th><th>Bytes</th><th>Why</th></tr></thead>
            <tbody>{rows.map(([k, v, why]) => <tr key={k}><td>{k}</td><td><strong>{v}</strong></td><td className="small">{why}</td></tr>)}</tbody>
          </table>
          <p className="small">{e.note}</p>
          <pre className="small">{`# test the path (DF set)\nping -c 1 -M do -s ${mtu - 28} DESTINATION\n\n# interface MTU (persistent: "mtu ${mtu}" in /etc/network/interfaces)\nip link set dev IFACE mtu ${mtu}\n\n# MSS clamping on the router in front of this link (nftables)\noifname "IFACE" tcp flags syn tcp option maxseg size set ${mtu - 40}\n# or follow the route MTU automatically:\noifname "IFACE" tcp flags syn tcp option maxseg size set rt mtu`}</pre>
        </>
      )}
    </div>
  );
}
