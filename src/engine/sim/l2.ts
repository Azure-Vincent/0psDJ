// Layer 2: the VLAN-aware Linux bridge on the switch (sw01) and the broadcast
// domains it creates.
//
// The switch is configured like a Debian/Cumulus box with ifupdown2:
//
//   auto br0
//   iface br0
//       bridge-vlan-aware yes
//       bridge-ports swp1 swp2 ...
//       bridge-vids 10 20 30        # VLANs a port carries unless it says otherwise
//       bridge-pvid 1               # VLAN for untagged frames (sent untagged)
//   auto swp1
//   iface swp1
//       bridge-access 10            # access port: VLAN 10 only, untagged
//   auto swp7
//   iface swp7
//       bridge-vids 30              # trunk: VLAN 30 tagged (plus the untagged PVID)
//
// Every host interface cabled to the switch is placed in a broadcast domain
// (Interface.segment) derived from the port's VLAN membership and from whether
// the host sends untagged frames (a plain NIC) or tagged ones (a VLAN
// sub-interface such as eth3.30). The simulator treats membership as
// symmetric: a host interface is in VLAN v when the switch both accepts its
// frames into v and sends v's frames back in the form the interface expects.

import type { IfaceConfig } from '../config/netconf';
import type { BridgeState, Host, Interface, World } from '../types';

/** The interface at the other end of the cable plugged into host:iface, if any. */
export function linkPeer(world: World, hostId: string, iface: string): { host: string; iface: string } | null {
  for (const l of world.links ?? []) {
    if (l.a.host === hostId && l.a.iface === iface) return l.b;
    if (l.b.host === hostId && l.b.iface === iface) return l.a;
  }
  return null;
}

/** How the switch carried a frame between two cabled interfaces (for hop notes). */
export function switchPath(world: World, aHost: Host, aIf: Interface, bHost: Host, bIf: Interface): string | null {
  const ma = vlanMembership(world, aHost, aIf);
  const mb = vlanMembership(world, bHost, bIf);
  if (!ma || !mb) return null;
  const how = (i: Interface) => (i.vlan ? `tagged ${i.vlan.id}` : 'untagged');
  return `switched by ${ma.switchId}: in ${ma.port} (${how(aIf)}) → VLAN ${ma.vid} → out ${mb.port} (${how(bIf)})`;
}

export function parseVids(s: string | undefined): number[] {
  if (!s) return [];
  const out: number[] = [];
  for (const part of s.split(/[\s,]+/).filter(Boolean)) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!m) continue;
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    for (let v = a; v <= b && v <= 4094; v++) if (v >= 1 && !out.includes(v)) out.push(v);
  }
  return out;
}

/** Build the bridge state from ifupdown2 stanzas. Returns null when no bridge is configured. */
export function bridgeFromConfig(ifaces: IfaceConfig[], errors: string[]): BridgeState | null {
  const br = ifaces.find((i) => i.options['bridge-ports'] !== undefined);
  if (!br) return null;
  const vlanAware = /^(yes|on|1)$/i.test(br.options['bridge-vlan-aware'] ?? 'no');
  const defVids = parseVids(br.options['bridge-vids']);
  const defPvid = br.options['bridge-pvid'] ? Number(br.options['bridge-pvid']) : 1;
  const ports: BridgeState['ports'] = {};
  for (const name of br.options['bridge-ports'].split(/\s+/).filter(Boolean)) {
    const st = ifaces.find((i) => i.name === name);
    const access = st?.options['bridge-access'];
    if (access !== undefined) {
      const v = Number(access);
      if (!Number.isInteger(v) || v < 1 || v > 4094) { errors.push(`${name}: invalid bridge-access value "${access}"`); continue; }
      ports[name] = { vids: [v], pvid: v, untagged: [v] };
      continue;
    }
    const vids = st?.options['bridge-vids'] !== undefined ? parseVids(st.options['bridge-vids']) : [...defVids];
    const pvidRaw = st?.options['bridge-pvid'];
    const pvid = pvidRaw !== undefined ? Number(pvidRaw) : defPvid;
    const allowUntagged = !/^(no|off|0)$/i.test(st?.options['bridge-allow-untagged'] ?? 'yes');
    if (allowUntagged && pvid && !vids.includes(pvid)) vids.unshift(pvid);
    ports[name] = { vids, pvid: allowUntagged ? pvid : null, untagged: allowUntagged && pvid ? [pvid] : [] };
  }
  return { name: br.name, vlanAware, ports };
}

/** Broadcast-domain id for a VLAN: the lab segment that declares this VLAN, or a generic name. */
export function segmentForVlan(world: World, vid: number): string {
  return Object.values(world.segments).find((s) => s.vlan === vid)?.id ?? `vlan${vid}`;
}

/** VLAN a host interface's frames belong to on the switch, or null if they are dropped / not delivered back. */
export function vlanMembership(world: World, host: Host, iface: Interface): { switchId: string; port: string; vid: number } | null | undefined {
  const phys = iface.vlan ? iface.vlan.parent : iface.name;
  const peer = linkPeer(world, host.id, phys);
  if (!peer) return undefined; // not cabled to a switch
  const sw = world.hosts[peer.host];
  if (!sw?.bridge) return null;
  const portIf = sw.ifaces.find((i) => i.name === peer.iface);
  const parent = iface.vlan ? host.ifaces.find((i) => i.name === iface.vlan!.parent) : iface;
  if (!portIf?.up || !parent?.up || !iface.up) return null;
  const bp = sw.bridge.ports[peer.iface];
  if (!bp) return null; // port not enslaved to the bridge
  if (!sw.bridge.vlanAware) return { switchId: sw.id, port: peer.iface, vid: iface.vlan ? iface.vlan.id : 1 };
  if (iface.vlan) {
    const v = iface.vlan.id;
    return bp.vids.includes(v) && !bp.untagged.includes(v) ? { switchId: sw.id, port: peer.iface, vid: v } : null;
  }
  const v = bp.pvid;
  return v !== null && bp.vids.includes(v) && bp.untagged.includes(v) ? { switchId: sw.id, port: peer.iface, vid: v } : null;
}

/** Recompute Interface.segment for every interface (call after any switch or interface change). */
export function recomputeL2(world: World): void {
  for (const h of Object.values(world.hosts)) {
    for (const i of h.ifaces) {
      if (i.name === 'lo') continue;
      if (h.bridge !== undefined && h.bridge !== null && h.bridge.ports[i.name]) { i.segment = null; continue; }
      const m = vlanMembership(world, h, i);
      if (m === undefined) {
        i.segment = i.vlan ? null : i.staticSegment ?? i.segment;
        continue;
      }
      i.segment = m ? (world.hosts[m.switchId].bridge!.vlanAware ? segmentForVlan(world, m.vid) : `${m.switchId}-flat`) : null;
    }
  }
}

/** `bridge vlan show` output (iproute2 6.1 format). */
export function formatBridgeVlans(host: Host): string {
  const b = host.bridge;
  if (!b) return '';
  const rows: string[] = ['port              vlan-id  '];
  const entry = (name: string, vids: number[], pvid: number | null, untagged: number[]) => {
    vids.forEach((v, idx) => {
      const flags = `${v === pvid ? ' PVID' : ''}${untagged.includes(v) ? ' Egress Untagged' : ''}`;
      rows.push(`${(idx === 0 ? name : '').padEnd(18)}${v}${flags}`);
    });
  };
  for (const [name, p] of Object.entries(b.ports)) {
    const up = host.ifaces.find((i) => i.name === name)?.up;
    if (!up) continue;
    entry(name, [...p.vids].sort((x, y) => x - y), p.pvid, p.untagged);
  }
  if (b.vlanAware) entry(b.name, [1], 1, [1]);
  return rows.join('\n');
}

/** Physical link state (carrier): cabled NICs need the switch port up; uncabled ones need a segment. */
export function hasCarrier(world: World, host: Host, iface: Interface): boolean {
  if (iface.name === 'lo') return true;
  if (iface.vlan) {
    const parent = host.ifaces.find((i) => i.name === iface.vlan!.parent);
    return !!parent && parent.up && hasCarrier(world, host, parent);
  }
  const peer = linkPeer(world, host.id, iface.name);
  if (peer) return !!world.hosts[peer.host]?.ifaces.find((i) => i.name === peer.iface)?.up;
  return iface.segment !== null || !!host.bridge?.ports[iface.name];
}
