import type { Lane } from './SequenceDiagram';

export const LAB_LANES: Lane[] = [
  { id: 'ws01', label: 'ws01', sub: 'client 10.0.10.25' },
  { id: 'ns1', label: 'ns1', sub: 'DNS 10.0.10.53' },
  { id: 'rtr01', label: 'rtr01', sub: 'router .10.1 / .20.1' },
  { id: 'srv01', label: 'srv01', sub: 'server 10.0.20.10' },
];

export function segmentOf(host: string, iface?: string): string {
  if (host === 'rtr01') return iface === 'eth1' ? 'srv20' : 'lan10';
  if (host === 'srv01') return 'srv20';
  return 'lan10';
}
