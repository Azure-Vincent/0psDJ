// Infrastructure Builder: a network design the learner draws (devices, cables,
// addresses, VLANs, firewall rules) and its validation. buildDesignWorld turns a
// valid design into a simulated World of Debian machines configured through
// the same files an administrator would write.

import { familyOf, inPrefix, isIpAddress } from '../net/addr';
import { broadcastOf, networkOf, parseCidr, parseIp } from '../net/ip';

export type NodeKind = 'host' | 'server' | 'router' | 'switch';
export type ServiceKind = 'ssh' | 'web';
export type Proto = 'tcp' | 'udp' | 'icmp';

export interface DesignIface {
  /** eth0, eth1… (physical) or eth0.20 (802.1Q sub-interface, routers only). */
  name: string;
  /** IPv4 address with prefix length, e.g. 10.0.10.10/24. Empty = no address. */
  address?: string;
}

export interface SwitchPort {
  name: string;
  mode: 'access' | 'trunk';
  /** Access VLAN (untagged). */
  vlan?: number;
  /** Tagged VLANs on a trunk port. */
  vlans?: number[];
}

/** Input firewall: what the machine itself accepts (everything else is dropped). */
export interface AllowRule {
  proto: Proto;
  port?: number;
  /** Source address or CIDR; empty = any. */
  from?: string;
}

/** Forward firewall on a router: traffic it routes between networks. */
export interface ForwardRule {
  proto: Proto | 'any';
  port?: number;
  from?: string;
  to?: string;
}

export interface DesignNode {
  id: string;
  kind: NodeKind;
  /** Hostname, also the machine id in the simulator. */
  name: string;
  x: number;
  y: number;
  /** NICs (hosts, servers, routers). */
  ifaces: DesignIface[];
  /** Switch ports. */
  ports?: SwitchPort[];
  /** Default gateway (IPv4). */
  gateway?: string;
  routes?: { dest: string; via: string }[];
  services?: ServiceKind[];
  firewall?: { enabled: boolean; allow: AllowRule[] };
  /** Routers: forward chain policy and its exceptions. */
  forward?: { policy: 'accept' | 'drop'; allow: ForwardRule[] };
  /** Routers: masquerade traffic leaving this interface (source NAT). */
  nat?: { outIface: string };
}

export interface DesignLink {
  id: string;
  a: { node: string; iface: string };
  b: { node: string; iface: string };
}

export interface Design {
  version: 1;
  name: string;
  nodes: DesignNode[];
  links: DesignLink[];
}

export interface Diagnostic {
  level: 'error' | 'warning';
  /** Node or link id the problem belongs to (for highlighting), if any. */
  target?: string;
  message: string;
}

const NAME_RE = /^[a-z][a-z0-9-]{0,30}$/;
const PHYS_RE = /^eth\d{1,2}$/;
const SUB_RE = /^(eth\d{1,2})\.(\d{1,4})$/;
const PORT_RE = /^swp\d{1,2}$/;

export function physicalOf(iface: string): string {
  return SUB_RE.exec(iface)?.[1] ?? iface;
}

export function subnetOf(cidr: string): string | null {
  const [ip, p] = cidr.trim().split('/');
  if (p === undefined || parseIp(ip) === null || !/^\d+$/.test(p) || Number(p) > 32) return null;
  return networkOf(ip, Number(p));
}

export function validCidrAddress(s: string): boolean {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(s.trim());
  if (!m || parseIp(m[1]) === null) return false;
  const p = Number(m[2]);
  if (p < 8 || p > 30) return false;
  // Not the network or broadcast address.
  return m[1] !== networkOf(m[1], p).split('/')[0] && m[1] !== broadcastOf(m[1], p);
}

function validSource(s: string): boolean {
  const t = s.trim();
  if (isIpAddress(t)) return familyOf(t) === 4;
  return !!/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(t) && !!parseCidr(t);
}

export function addressOf(i: DesignIface): string | null {
  return i.address?.trim() ? i.address.trim().split('/')[0] : null;
}

/** All IPv4 subnets a node is directly attached to. */
export function nodeSubnets(n: DesignNode): { iface: string; subnet: string; ip: string }[] {
  return n.ifaces.filter((i) => i.address?.trim() && validCidrAddress(i.address)).map((i) => ({ iface: i.name, subnet: subnetOf(i.address!.trim())!, ip: addressOf(i)! }));
}

/** The interface of a node whose subnet contains ip. */
export function ifaceFor(n: DesignNode, ip: string): string | null {
  return nodeSubnets(n).find((s) => inPrefix(ip, s.subnet))?.iface ?? null;
}

/** The node and switch-port VLAN configuration a cable endpoint reaches, if any. */
export function linkOf(design: Design, node: string, iface: string): { link: DesignLink; peer: { node: string; iface: string } } | null {
  for (const l of design.links) {
    if (l.a.node === node && l.a.iface === iface) return { link: l, peer: l.b };
    if (l.b.node === node && l.b.iface === iface) return { link: l, peer: l.a };
  }
  return null;
}

export function validateDesign(design: Design): Diagnostic[] {
  const out: Diagnostic[] = [];
  const err = (message: string, target?: string) => out.push({ level: 'error', target, message });
  const warn = (message: string, target?: string) => out.push({ level: 'warning', target, message });
  const byId = new Map(design.nodes.map((n) => [n.id, n]));

  if (!design.nodes.length) err('The design is empty: add some devices.');
  const names = new Map<string, number>();
  for (const n of design.nodes) names.set(n.name, (names.get(n.name) ?? 0) + 1);

  const ipOwners = new Map<string, string[]>();
  for (const n of design.nodes) {
    if (!NAME_RE.test(n.name)) err(`"${n.name}" is not a valid hostname (lower-case letters, digits and "-", starting with a letter).`, n.id);
    if ((names.get(n.name) ?? 0) > 1) err(`Two devices are named "${n.name}".`, n.id);

    if (n.kind === 'switch') {
      const seen = new Set<string>();
      for (const p of n.ports ?? []) {
        if (!PORT_RE.test(p.name)) err(`${n.name}: "${p.name}" is not a switch port name (swp1, swp2, …).`, n.id);
        if (seen.has(p.name)) err(`${n.name}: port ${p.name} is listed twice.`, n.id);
        seen.add(p.name);
        const vids = p.mode === 'access' ? [p.vlan ?? 1] : p.vlans ?? [];
        for (const v of vids) if (!Number.isInteger(v) || v < 1 || v > 4094) err(`${n.name} ${p.name}: VLAN ${v} is outside 1–4094.`, n.id);
        if (p.mode === 'trunk' && !(p.vlans ?? []).length) warn(`${n.name} ${p.name}: trunk port without tagged VLANs (only VLAN 1 untagged).`, n.id);
      }
      continue;
    }

    const ifn = new Set<string>();
    for (const i of n.ifaces) {
      const sub = SUB_RE.exec(i.name);
      if (!PHYS_RE.test(i.name) && !sub) err(`${n.name}: "${i.name}" is not an interface name (eth0, or eth0.20 for a VLAN sub-interface).`, n.id);
      if (sub) {
        if (n.kind !== 'router') err(`${n.name}: VLAN sub-interfaces (${i.name}) are only offered on routers.`, n.id);
        const vid = Number(sub[2]);
        if (vid < 1 || vid > 4094) err(`${n.name} ${i.name}: VLAN ${vid} is outside 1–4094.`, n.id);
        if (!n.ifaces.some((p) => p.name === sub[1])) err(`${n.name}: ${i.name} needs its parent interface ${sub[1]}.`, n.id);
      }
      if (ifn.has(i.name)) err(`${n.name}: interface ${i.name} is listed twice.`, n.id);
      ifn.add(i.name);
      if (i.address?.trim()) {
        if (!validCidrAddress(i.address)) err(`${n.name} ${i.name}: "${i.address}" is not a usable IPv4 address with prefix (e.g. 10.0.1.10/24; prefix 8–30, not the network or broadcast address).`, n.id);
        else {
          const ip = addressOf(i)!;
          ipOwners.set(ip, [...(ipOwners.get(ip) ?? []), `${n.name} ${i.name}`]);
        }
      }
    }
    // Two interfaces of one machine in the same subnet confuse routing.
    const subs = nodeSubnets(n);
    for (let a = 0; a < subs.length; a++) for (let b = a + 1; b < subs.length; b++) {
      if (subs[a].subnet === subs[b].subnet) warn(`${n.name}: ${subs[a].iface} and ${subs[b].iface} are both in ${subs[a].subnet}; replies may leave through the other interface.`, n.id);
    }

    if (n.gateway?.trim()) {
      const g = n.gateway.trim();
      if (!isIpAddress(g) || familyOf(g) !== 4) err(`${n.name}: gateway "${g}" is not an IPv4 address.`, n.id);
      else if (!ifaceFor(n, g)) err(`${n.name}: gateway ${g} is not in the subnet of any of its interfaces, so it cannot be reached directly.`, n.id);
      else if (subs.some((s) => s.ip === g)) err(`${n.name}: the gateway ${g} is the machine's own address.`, n.id);
    } else if (n.kind !== 'router' && subs.length) {
      warn(`${n.name} has no default gateway: it can only reach its own subnet${subs.length > 1 ? 's' : ''}.`, n.id);
    }
    for (const r of n.routes ?? []) {
      if (!subnetOf(r.dest) || subnetOf(r.dest) !== r.dest.trim()) err(`${n.name}: route destination "${r.dest}" must be a network in CIDR form (e.g. 10.0.30.0/24).`, n.id);
      if (!isIpAddress(r.via.trim()) || familyOf(r.via.trim()) !== 4) err(`${n.name}: route via "${r.via}" is not an IPv4 address.`, n.id);
      else if (!ifaceFor(n, r.via.trim())) err(`${n.name}: next hop ${r.via} for ${r.dest} is not on any directly attached subnet.`, n.id);
    }
    for (const rule of n.firewall?.allow ?? []) {
      if (rule.port !== undefined && (rule.proto === 'icmp' || !Number.isInteger(rule.port) || rule.port < 1 || rule.port > 65535)) err(`${n.name}: firewall rule ${rule.proto}${rule.port !== undefined ? ' ' + rule.port : ''} has an invalid port.`, n.id);
      if (rule.from?.trim() && !validSource(rule.from)) err(`${n.name}: firewall source "${rule.from}" is not an IPv4 address or network.`, n.id);
    }
    if (n.kind === 'router') {
      for (const rule of n.forward?.allow ?? []) {
        if (rule.port !== undefined && (rule.proto === 'icmp' || rule.proto === 'any' || !Number.isInteger(rule.port) || rule.port < 1 || rule.port > 65535)) err(`${n.name}: forward rule has an invalid port (ports need tcp or udp).`, n.id);
        for (const a of [rule.from, rule.to]) if (a?.trim() && !validSource(a)) err(`${n.name}: forward rule address "${a}" is not an IPv4 address or network.`, n.id);
      }
      if (n.nat?.outIface && !n.ifaces.some((i) => i.name === n.nat!.outIface)) err(`${n.name}: NAT interface ${n.nat.outIface} does not exist.`, n.id);
    }
    const fw = n.firewall;
    if (fw?.enabled) {
      const allows = (proto: Proto, port: number) => fw.allow.some((r) => r.proto === proto && (r.port === undefined || r.port === port));
      if (n.services?.includes('web') && !allows('tcp', 80)) warn(`${n.name} runs a web server but its firewall does not allow tcp 80.`, n.id);
      if (n.services?.includes('ssh') && !allows('tcp', 22)) warn(`${n.name} runs sshd but its firewall does not allow tcp 22.`, n.id);
    }
  }
  for (const [ip, owners] of ipOwners) if (owners.length > 1) err(`Duplicate address ${ip}: ${owners.join(' and ')}.`);

  // Cables.
  const used = new Map<string, string>();
  for (const l of design.links) {
    const ends = [l.a, l.b].map((e) => ({ e, n: byId.get(e.node) }));
    if (ends.some((x) => !x.n)) { err('A cable is attached to a device that no longer exists.', l.id); continue; }
    const [a, b] = ends as { e: DesignLink['a']; n: DesignNode }[];
    if (a.n.id === b.n.id) err(`${a.n.name}: a cable from the machine to itself.`, l.id);
    if (a.n.kind === 'switch' && b.n.kind === 'switch') err(`${a.n.name}–${b.n.name}: cables between switches are not simulated yet; use one switch with more ports.`, l.id);
    for (const x of [a, b]) {
      const key = `${x.n.id}/${x.e.iface}`;
      if (used.has(key)) err(`${x.n.name} ${x.e.iface} has two cables.`, l.id);
      used.set(key, l.id);
      const exists = x.n.kind === 'switch' ? (x.n.ports ?? []).some((p) => p.name === x.e.iface) : x.n.ifaces.some((i) => i.name === x.e.iface && PHYS_RE.test(i.name));
      if (!exists) err(`${x.n.name} has no ${x.n.kind === 'switch' ? 'port' : 'physical interface'} ${x.e.iface} for this cable.`, l.id);
    }
    // Point-to-point between two machines: their addresses should share a subnet.
    if (a.n.kind !== 'switch' && b.n.kind !== 'switch') {
      const sa = subnetsOn(a.n, a.e.iface), sb = subnetsOn(b.n, b.e.iface);
      if (sa.length && sb.length && !sa.some((s) => sb.includes(s))) warn(`${a.n.name} ${a.e.iface} (${sa.join(', ')}) and ${b.n.name} ${b.e.iface} (${sb.join(', ')}) are cabled together but in different subnets.`, l.id);
    }
    // Machine to switch: tagged sub-interfaces need a trunk carrying the VLAN.
    const sw = a.n.kind === 'switch' ? a : b.n.kind === 'switch' ? b : null;
    const other = sw === a ? b : a;
    if (sw && other.n.kind !== 'switch') {
      const port = (sw.n.ports ?? []).find((p) => p.name === sw.e.iface);
      if (port) {
        for (const i of other.n.ifaces) {
          const sub = SUB_RE.exec(i.name);
          if (!sub || sub[1] !== other.e.iface) continue;
          const vid = Number(sub[2]);
          if (port.mode !== 'trunk' || !(port.vlans ?? []).includes(vid)) warn(`${other.n.name} ${i.name} sends VLAN ${vid} tagged, but ${sw.n.name} ${port.name} is not a trunk carrying VLAN ${vid}.`, l.id);
        }
        const untaggedAddr = other.n.ifaces.find((i) => i.name === other.e.iface)?.address?.trim();
        if (port.mode === 'trunk' && untaggedAddr) warn(`${other.n.name} ${other.e.iface} sends untagged frames into trunk port ${sw.n.name} ${port.name}: they land in VLAN 1.`, l.id);
      }
    }
  }
  for (const n of design.nodes) {
    if (n.kind === 'switch') continue;
    for (const i of n.ifaces) {
      if (!i.address?.trim() || !PHYS_RE.test(physicalOf(i.name))) continue;
      if (!used.has(`${n.id}/${physicalOf(i.name)}`)) warn(`${n.name} ${i.name} has an address but no cable.`, n.id);
    }
  }
  // Same subnet in two different broadcast domains is legal, but usually a mistake.
  return out;
}

function subnetsOn(n: DesignNode, phys: string): string[] {
  return nodeSubnets(n).filter((s) => physicalOf(s.iface) === phys && !SUB_RE.test(s.iface)).map((s) => s.subnet);
}

export function isSubInterface(name: string): boolean {
  return SUB_RE.test(name);
}

export function vlanOfIface(name: string): number | null {
  const m = SUB_RE.exec(name);
  return m ? Number(m[2]) : null;
}

let seq = 0;
export function newId(prefix: string): string {
  seq += 1;
  return `${prefix}${Date.now().toString(36)}${seq.toString(36)}`;
}

/** Next free physical interface or switch port of a node. */
export function freeIface(design: Design, n: DesignNode): string | null {
  const used = new Set(design.links.flatMap((l) => [l.a, l.b]).filter((e) => e.node === n.id).map((e) => e.iface));
  if (n.kind === 'switch') return (n.ports ?? []).find((p) => !used.has(p.name))?.name ?? null;
  return n.ifaces.find((i) => PHYS_RE.test(i.name) && !used.has(i.name))?.name ?? null;
}
