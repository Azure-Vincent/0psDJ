// Starter designs for the Infrastructure Builder.

import type { Design, DesignNode, SwitchPort } from './design';

const ports = (n: number, vlan = 1): SwitchPort[] => Array.from({ length: n }, (_, k) => ({ name: `swp${k + 1}`, mode: 'access', vlan }));
const ssh = { proto: 'tcp' as const, port: 22 };
const web = { proto: 'tcp' as const, port: 80 };
const icmp = { proto: 'icmp' as const };

export interface DesignTemplate {
  id: string;
  title: string;
  description: string;
  design(): Design;
}

export const EMPTY_DESIGN: Design = { version: 1, name: 'My network', nodes: [], links: [] };

function twoNetworks(): Design {
  const nodes: DesignNode[] = [
    { id: 'sw1', kind: 'switch', name: 'sw-office', x: 160, y: 120, ifaces: [], ports: ports(4) },
    { id: 'sw2', kind: 'switch', name: 'sw-servers', x: 560, y: 120, ifaces: [], ports: ports(4) },
    { id: 'r1', kind: 'router', name: 'gw', x: 360, y: 120, ifaces: [{ name: 'eth0', address: '10.0.1.1/24' }, { name: 'eth1', address: '10.0.2.1/24' }], services: ['ssh'], firewall: { enabled: true, allow: [{ ...ssh, from: '10.0.1.0/24' }, icmp] } },
    { id: 'h1', kind: 'host', name: 'pc1', x: 80, y: 300, ifaces: [{ name: 'eth0', address: '10.0.1.10/24' }], gateway: '10.0.1.1' },
    { id: 'h2', kind: 'host', name: 'pc2', x: 240, y: 300, ifaces: [{ name: 'eth0', address: '10.0.1.11/24' }], gateway: '10.0.1.1' },
    { id: 's1', kind: 'server', name: 'web1', x: 560, y: 300, ifaces: [{ name: 'eth0', address: '10.0.2.10/24' }], gateway: '10.0.2.1', services: ['ssh', 'web'], firewall: { enabled: true, allow: [{ ...ssh, from: '10.0.1.0/24' }, web, icmp] } },
  ];
  return {
    version: 1, name: 'Two networks and a router', nodes,
    links: [
      { id: 'l1', a: { node: 'h1', iface: 'eth0' }, b: { node: 'sw1', iface: 'swp1' } },
      { id: 'l2', a: { node: 'h2', iface: 'eth0' }, b: { node: 'sw1', iface: 'swp2' } },
      { id: 'l3', a: { node: 'r1', iface: 'eth0' }, b: { node: 'sw1', iface: 'swp4' } },
      { id: 'l4', a: { node: 'r1', iface: 'eth1' }, b: { node: 'sw2', iface: 'swp4' } },
      { id: 'l5', a: { node: 's1', iface: 'eth0' }, b: { node: 'sw2', iface: 'swp1' } },
    ],
  };
}

function routerOnAStick(): Design {
  const swPorts: SwitchPort[] = [
    { name: 'swp1', mode: 'access', vlan: 10 },
    { name: 'swp2', mode: 'access', vlan: 10 },
    { name: 'swp3', mode: 'access', vlan: 20 },
    { name: 'swp4', mode: 'access', vlan: 20 },
    { name: 'swp8', mode: 'trunk', vlans: [10, 20] },
  ];
  return {
    version: 1, name: 'VLANs with router-on-a-stick',
    nodes: [
      { id: 'sw', kind: 'switch', name: 'sw1', x: 360, y: 200, ifaces: [], ports: swPorts },
      { id: 'r', kind: 'router', name: 'rtr', x: 360, y: 50, ifaces: [{ name: 'eth0' }, { name: 'eth0.10', address: '192.168.10.1/24' }, { name: 'eth0.20', address: '192.168.20.1/24' }], forward: { policy: 'drop', allow: [{ proto: 'tcp', port: 80, from: '192.168.10.0/24', to: '192.168.20.0/24' }, { proto: 'icmp' }] } },
      { id: 'a', kind: 'host', name: 'staff1', x: 120, y: 360, ifaces: [{ name: 'eth0', address: '192.168.10.21/24' }], gateway: '192.168.10.1' },
      { id: 'b', kind: 'host', name: 'staff2', x: 260, y: 360, ifaces: [{ name: 'eth0', address: '192.168.10.22/24' }], gateway: '192.168.10.1' },
      { id: 'c', kind: 'server', name: 'app1', x: 460, y: 360, ifaces: [{ name: 'eth0', address: '192.168.20.10/24' }], gateway: '192.168.20.1', services: ['ssh', 'web'] },
      { id: 'd', kind: 'server', name: 'db1', x: 600, y: 360, ifaces: [{ name: 'eth0', address: '192.168.20.20/24' }], gateway: '192.168.20.1', services: ['ssh'] },
    ],
    links: [
      { id: 'l1', a: { node: 'a', iface: 'eth0' }, b: { node: 'sw', iface: 'swp1' } },
      { id: 'l2', a: { node: 'b', iface: 'eth0' }, b: { node: 'sw', iface: 'swp2' } },
      { id: 'l3', a: { node: 'c', iface: 'eth0' }, b: { node: 'sw', iface: 'swp3' } },
      { id: 'l4', a: { node: 'd', iface: 'eth0' }, b: { node: 'sw', iface: 'swp4' } },
      { id: 'l5', a: { node: 'r', iface: 'eth0' }, b: { node: 'sw', iface: 'swp8' } },
    ],
  };
}

function dmzNat(): Design {
  return {
    version: 1, name: 'Office, DMZ and the Internet (NAT)',
    nodes: [
      { id: 'inet', kind: 'server', name: 'internet', x: 620, y: 60, ifaces: [{ name: 'eth0', address: '198.51.100.1/24' }], services: ['web'] },
      { id: 'fw', kind: 'router', name: 'fw', x: 380, y: 60, ifaces: [{ name: 'eth0', address: '198.51.100.2/24' }, { name: 'eth1', address: '10.1.0.1/24' }, { name: 'eth2', address: '172.16.0.1/24' }], gateway: '198.51.100.1', services: ['ssh'],
        firewall: { enabled: true, allow: [{ ...ssh, from: '10.1.0.0/24' }, icmp] },
        forward: { policy: 'drop', allow: [{ proto: 'any', from: '10.1.0.0/24' }, { proto: 'tcp', port: 80, to: '172.16.0.10' }] },
        nat: { outIface: 'eth0' } },
      { id: 'swl', kind: 'switch', name: 'sw-lan', x: 160, y: 200, ifaces: [], ports: ports(4) },
      { id: 'swd', kind: 'switch', name: 'sw-dmz', x: 560, y: 220, ifaces: [], ports: ports(4) },
      { id: 'pc', kind: 'host', name: 'laptop', x: 80, y: 360, ifaces: [{ name: 'eth0', address: '10.1.0.50/24' }], gateway: '10.1.0.1' },
      { id: 'adm', kind: 'host', name: 'admin-pc', x: 240, y: 360, ifaces: [{ name: 'eth0', address: '10.1.0.51/24' }], gateway: '10.1.0.1' },
      { id: 'www', kind: 'server', name: 'www', x: 560, y: 380, ifaces: [{ name: 'eth0', address: '172.16.0.10/24' }], gateway: '172.16.0.1', services: ['ssh', 'web'], firewall: { enabled: true, allow: [web, { ...ssh, from: '10.1.0.0/24' }, icmp] } },
    ],
    links: [
      { id: 'l1', a: { node: 'fw', iface: 'eth0' }, b: { node: 'inet', iface: 'eth0' } },
      { id: 'l2', a: { node: 'fw', iface: 'eth1' }, b: { node: 'swl', iface: 'swp4' } },
      { id: 'l3', a: { node: 'fw', iface: 'eth2' }, b: { node: 'swd', iface: 'swp4' } },
      { id: 'l4', a: { node: 'pc', iface: 'eth0' }, b: { node: 'swl', iface: 'swp1' } },
      { id: 'l5', a: { node: 'adm', iface: 'eth0' }, b: { node: 'swl', iface: 'swp2' } },
      { id: 'l6', a: { node: 'www', iface: 'eth0' }, b: { node: 'swd', iface: 'swp1' } },
    ],
  };
}

export const DESIGN_TEMPLATES: DesignTemplate[] = [
  { id: 'two-networks', title: 'Two networks and a router', description: 'An office LAN and a server LAN on separate switches, routed by a Linux router. The server firewall allows SSH only from the office.', design: twoNetworks },
  { id: 'vlans', title: 'VLANs with router-on-a-stick', description: 'One switch with a staff VLAN and a server VLAN; the router reaches both over one trunk with tagged sub-interfaces and only forwards HTTP and ping from staff to servers.', design: routerOnAStick },
  { id: 'dmz', title: 'Office, DMZ and the Internet', description: 'A firewall with three legs: the office is masqueraded to the Internet, the DMZ web server is reachable on port 80, everything else is dropped.', design: dmzNat },
];
