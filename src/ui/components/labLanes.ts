import type { Lane } from './SequenceDiagram';

export const LAB_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'client 10.0.10.25' },
  { id: 'ns1', label: 'ns1', sub: 'DNS 10.0.10.53' },
  { id: 'rtr01', label: 'rtr01', sub: 'router .10.1 / .20.1' },
  { id: 'srv01', label: 'srv01', sub: 'server 10.0.20.10' },
];

export const DHCP_LANES: Lane[] = [
  { id: 'ws02', label: 'ws02', sub: 'DHCP client (office)' },
  { id: 'ns1', label: 'ns1', sub: 'dhcpd 10.0.10.53' },
  { id: 'rtr01', label: 'rtr01', sub: 'gateway, dhcrelay' },
  { id: 'dev02', label: 'dev02', sub: 'DHCP client (VLAN 30)' },
  { id: 'srv01', label: 'srv01', sub: 'server 10.0.20.10' },
];

export const NAT_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'office 10.0.10.25' },
  { id: 'rtr01', label: 'rtr01', sub: 'NAT 203.0.113.2' },
  { id: 'srv01', label: 'srv01', sub: 'web 10.0.20.10' },
  { id: 'ext01', label: 'ext01', sub: 'Internet 203.0.113.80' },
];

export const VLAN_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'VLAN 10 · 10.0.10.25' },
  { id: 'ns1', label: 'ns1', sub: 'VLAN 10 · 10.0.10.53' },
  { id: 'dev01', label: 'dev01', sub: 'VLAN 30 · 10.0.30.25' },
  { id: 'rtr01', label: 'rtr01', sub: 'gateway (eth3.30 on trunk)' },
  { id: 'srv01', label: 'srv01', sub: 'VLAN 20 · 10.0.20.10' },
];

export const IPV6_LANES: Lane[] = [
  { id: 'dev01', label: 'dev01', sub: 'SLAAC 2001:db8:30::/64' },
  { id: 'dev02', label: 'dev02', sub: 'DHCPv6 client' },
  { id: 'rtr01', label: 'rtr01', sub: 'radvd, dhcpd -6 · ::1 on both sides' },
  { id: 'srv01', label: 'srv01', sub: '2001:db8:20::10' },
  { id: 'ns1', label: 'ns1', sub: 'DNS (A + AAAA)' },
];

export const TLS_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'curl / openssl' },
  { id: 'ns1', label: 'ns1', sub: 'DNS www → srv01' },
  { id: 'rtr01', label: 'rtr01', sub: 'router' },
  { id: 'srv01', label: 'srv01', sub: 'nginx :443' },
];

export const MTU_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'office · mtu 1500' },
  { id: 'rtr01', label: 'rtr01', sub: 'eth2 uplink' },
  { id: 'ext01', label: 'ext01', sub: 'Internet 203.0.113.80' },
];

export const KRB_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'kinit / ssh (alice)' },
  { id: 'ns1', label: 'ns1', sub: 'DNS + KDC CORP.LAB' },
  { id: 'rtr01', label: 'rtr01', sub: 'router' },
  { id: 'srv01', label: 'srv01', sub: 'sshd + keytab' },
];

export function segmentOf(host: string, iface?: string): string {
  if (host === 'rtr01') return iface === 'eth1' ? 'srv20' : iface === 'eth2' ? 'wan' : iface?.startsWith('eth3') ? 'dev30 (VLAN 30)' : 'lan10';
  if (host === 'srv01') return 'srv20';
  if (host === 'ext01') return 'wan';
  if (host === 'dev01' || host === 'dev02') return 'dev30 (VLAN 30)';
  return 'lan10';
}
