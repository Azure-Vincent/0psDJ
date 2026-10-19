// Static topology of the SSH lab (addresses and roles only: it never reveals
// runtime state, so it cannot give away a troubleshooting answer).

export function Topology() {
  const box = (x: number, y: number, title: string, lines: string[], w = 150) => (
    <g>
      <rect x={x} y={y} width={w} height={22 + lines.length * 14} rx={6} fill="var(--panel-2)" stroke="var(--border)" />
      <text x={x + 8} y={y + 16} fontWeight={700} fontSize={12} style={{ fill: 'var(--text)' }}>{title}</text>
      {lines.map((l, i) => <text key={i} x={x + 8} y={y + 31 + i * 14} fontSize={10.5} className="mono" style={{ fill: 'var(--muted)' }}>{l}</text>)}
    </g>
  );
  return (
    <svg viewBox="0 0 300 330" width="100%" role="img" aria-label="Lab topology">
      <text x={8} y={14} fontSize={11} style={{ fill: 'var(--muted)' }}>lan10 · 10.0.10.0/24 · VLAN 10</text>
      <line x1={20} y1={22} x2={280} y2={22} stroke="var(--accent)" strokeWidth={3} />
      {box(6, 34, 'ws01', ['10.0.10.25', 'client (alice)'], 135)}
      {box(158, 34, 'ns1', ['10.0.10.53', 'BIND (corp.lab)'], 135)}
      <line x1={73} y1={22} x2={73} y2={34} stroke="var(--accent)" />
      <line x1={225} y1={22} x2={225} y2={34} stroke="var(--accent)" />
      <line x1={150} y1={22} x2={150} y2={130} stroke="var(--accent)" />
      {box(80, 130, 'rtr01', ['eth0 10.0.10.1', 'eth1 10.0.20.1', 'ip_forward, nftables'], 140)}
      <line x1={150} y1={194} x2={150} y2={232} stroke="var(--ok)" />
      <text x={8} y={226} fontSize={11} style={{ fill: 'var(--muted)' }}>srv20 · 10.0.20.0/24 · VLAN 20</text>
      <line x1={20} y1={232} x2={280} y2={232} stroke="var(--ok)" strokeWidth={3} />
      <line x1={150} y1={232} x2={150} y2={246} stroke="var(--ok)" />
      {box(80, 246, 'srv01', ['10.0.20.10', 'sshd :22, nginx :80', 'nftables (default drop)'], 140)}
    </svg>
  );
}
