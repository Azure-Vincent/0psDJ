// Static topology of the lab (addresses and roles only: it never reveals
// runtime state, so it cannot give away a troubleshooting answer).

export function Topology() {
  const box = (x: number, y: number, title: string, lines: string[], w = 150) => (
    <g>
      <rect x={x} y={y} width={w} height={22 + lines.length * 14} rx={6} fill="var(--panel-2)" stroke="var(--border)" />
      <text x={x + 8} y={y + 16} fontWeight={700} fontSize={12} style={{ fill: 'var(--text)' }}>{title}</text>
      {lines.map((l, i) => <text key={i} x={x + 8} y={y + 31 + i * 14} className="mono" style={{ fill: 'var(--muted)', fontSize: 9.5 }}>{l}</text>)}
    </g>
  );
  return (
    <svg viewBox="0 0 340 372" width="100%" style={{ maxWidth: 480 }} role="img" aria-label="Lab topology">
      <text x={8} y={14} fontSize={11} style={{ fill: 'var(--muted)' }}>VLAN 10 office · 10.0.10.0/24</text>
      <line x1={10} y1={22} x2={330} y2={22} stroke="var(--accent)" strokeWidth={3} />
      {box(4, 34, 'ws01', ['10.0.10.25', 'static (alice)'], 98)}
      {box(118, 34, 'ws02', ['DHCP client', 'laptop (dana)'], 98)}
      {box(222, 34, 'ns1', ['10.0.10.53', 'BIND + dhcpd'], 114)}
      <line x1={53} y1={22} x2={53} y2={34} stroke="var(--accent)" />
      <line x1={167} y1={22} x2={167} y2={34} stroke="var(--accent)" />
      <line x1={279} y1={22} x2={279} y2={34} stroke="var(--accent)" />
      <line x1={110} y1={22} x2={110} y2={110} stroke="var(--accent)" />
      {box(40, 110, 'rtr01', ['eth0 10.0.10.1', 'eth1 10.0.20.1', 'eth2 203.0.113.2', 'eth3.30 10.0.30.1', 'NAT, nftables, radvd'], 150)}
      <text x={236} y={112} fontSize={11} style={{ fill: 'var(--muted)' }}>Internet</text>
      <text x={236} y={124} className="mono" style={{ fill: 'var(--muted)', fontSize: 9.5 }}>203.0.113.0/24</text>
      <line x1={190} y1={150} x2={240} y2={150} stroke="var(--warn)" strokeWidth={2} />
      {box(240, 132, 'ext01', ['203.0.113.80', 'nginx :80'], 96)}
      <line x1={115} y1={212} x2={115} y2={250} stroke="var(--ok)" />
      <path d="M190 192 H322 V250" fill="none" stroke="var(--lane)" strokeDasharray="5 3" />
      <text x={196} y={206} style={{ fill: 'var(--muted)', fontSize: 9.5 }}>trunk, tagged 30</text>
      <text x={8} y={244} fontSize={11} style={{ fill: 'var(--muted)' }}>VLAN 20 servers</text>
      <line x1={10} y1={250} x2={190} y2={250} stroke="var(--ok)" strokeWidth={3} />
      <text x={214} y={244} fontSize={11} style={{ fill: 'var(--muted)' }}>VLAN 30 dev</text>
      <line x1={205} y1={250} x2={330} y2={250} stroke="var(--lane)" strokeWidth={3} />
      <line x1={115} y1={250} x2={115} y2={262} stroke="var(--ok)" />
      <line x1={270} y1={250} x2={270} y2={262} stroke="var(--lane)" />
      {box(40, 262, 'srv01', ['10.0.20.10', '2001:db8:20::10', 'sshd :22, nginx :80'], 150)}
      {box(208, 262, 'dev01', ['10.0.30.25', 'IPv6 SLAAC', '2001:db8:30::/64'], 128)}
      <text x={8} y={356} style={{ fill: 'var(--muted)', fontSize: 9.5 }}>All LAN ports are on sw01 (VLAN-aware Linux bridge): access ports for</text>
      <text x={8} y={368} style={{ fill: 'var(--muted)', fontSize: 9.5 }}>VLAN 10/20/30, trunk swp7 to rtr01 eth3. Console: sw01.</text>
    </svg>
  );
}
