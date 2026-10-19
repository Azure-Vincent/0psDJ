import type { Lane } from './SequenceDiagram';

export const LAB_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'client 10.0.10.25' },
  { id: 'ns1', label: 'ns1', sub: 'DNS 10.0.10.53' },
  { id: 'rtr01', label: 'rtr01', sub: 'router .10.1 / .20.1' },
  { id: 'srv01', label: 'srv01', sub: 'server 10.0.20.10' },
];

export const DHCP_LANES: Lane[] = [
  { id: 'ws02', label: 'ws02', sub: 'DHCP client (eth0)' },
  { id: 'ns1', label: 'ns1', sub: 'dhcpd 10.0.10.53' },
  { id: 'rtr01', label: 'rtr01', sub: 'gateway 10.0.10.1' },
  { id: 'srv01', label: 'srv01', sub: 'server 10.0.20.10' },
];

export const NAT_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'office 10.0.10.25' },
  { id: 'rtr01', label: 'rtr01', sub: 'NAT 203.0.113.2' },
  { id: 'srv01', label: 'srv01', sub: 'web 10.0.20.10' },
  { id: 'ext01', label: 'ext01', sub: 'Internet 203.0.113.80' },
];

export function segmentOf(host: string, iface?: string): string {
  if (host === 'rtr01') return iface === 'eth1' ? 'srv20' : iface === 'eth2' ? 'wan' : 'lan10';
  if (host === 'srv01') return 'srv20';
  if (host === 'ext01') return 'wan';
  return 'lan10';
}
