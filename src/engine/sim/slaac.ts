// IPv6 router discovery and stateless address autoconfiguration (RFC 4861 §6,
// RFC 4862): radvd on the router answers Router Solicitations and sends
// unsolicited Router Advertisements; hosts that accept RAs (accept_ra, i.e.
// not forwarding) form an address from each autonomous /64 prefix plus their
// EUI-64 interface identifier and install a default route via the router's
// link-local address.

import { evaluate } from '../config/nft';
import { canonicalIp6, inCidr6, multicastMac, parseCidr6, slaacAddress } from '../net/ip6';
import type { Host, Interface, Packet, World } from '../types';
import { log } from './journal';
import { capture, clonePacket, describeDecision, nextId } from './network';
import { activeRecorder } from './trace';

export interface RadvdIface {
  name: string;
  sendAdvert: boolean;
  prefixes: { prefix: string; onLink: boolean; autonomous: boolean }[];
  rdnss: string[];
  routerLifetime: number;
  /** AdvManagedFlag (M): addresses are available from DHCPv6. */
  managed: boolean;
  /** AdvOtherConfigFlag (O): other configuration (DNS) is available from DHCPv6. */
  other: boolean;
}

export class RadvdConfigError extends Error {}

/** Parse /etc/radvd.conf (interface { … prefix … { … }; RDNSS … { }; }; blocks). */
export function parseRadvdConf(text: string): RadvdIface[] {
  const toks: { t: string; line: number }[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '');
    const re = /[{};]|[^\s{};]+/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line))) toks.push({ t: m[0], line: i + 1 });
  });
  let i = 0;
  const err = (line: number, msg: string): never => {
    throw new RadvdConfigError(`syntax error in /etc/radvd.conf, line ${line}: ${msg}`);
  };
  const next = () => toks[i++] ?? err(toks[toks.length - 1]?.line ?? 1, 'unexpected end of file');
  const expect = (v: string) => {
    const t = next();
    if (t.t !== v) err(t.line, `expected "${v}" near "${t.t}"`);
  };
  const onOff = (t: { t: string; line: number }) => (t.t === 'on' ? true : t.t === 'off' ? false : err(t.line, `expected on/off near "${t.t}"`));
  const out: RadvdIface[] = [];
  while (i < toks.length) {
    const kw = next();
    if (kw.t !== 'interface') err(kw.line, `unexpected "${kw.t}"`);
    const name = next().t;
    expect('{');
    const ifc: RadvdIface = { name, sendAdvert: false, prefixes: [], rdnss: [], routerLifetime: 1800, managed: false, other: false };
    for (;;) {
      const t = next();
      if (t.t === '}') { expect(';'); break; }
      if (t.t === 'AdvSendAdvert') { ifc.sendAdvert = onOff(next()); expect(';'); continue; }
      if (t.t === 'AdvDefaultLifetime') { ifc.routerLifetime = Number(next().t); expect(';'); continue; }
      if (t.t === 'AdvManagedFlag') { ifc.managed = onOff(next()); expect(';'); continue; }
      if (t.t === 'AdvOtherConfigFlag') { ifc.other = onOff(next()); expect(';'); continue; }
      if (t.t === 'prefix') {
        const pt = next();
        const c = parseCidr6(pt.t);
        if (!c || !pt.t.includes('/')) err(pt.line, `invalid prefix "${pt.t}"`);
        const pre = { prefix: `${canonicalIp6(pt.t.split('/')[0])}/${pt.t.split('/')[1]}`, onLink: true, autonomous: true };
        expect('{');
        for (;;) {
          const o = next();
          if (o.t === '}') { expect(';'); break; }
          if (o.t === 'AdvOnLink') pre.onLink = onOff(next());
          else if (o.t === 'AdvAutonomous') pre.autonomous = onOff(next());
          else next();
          expect(';');
        }
        ifc.prefixes.push(pre);
        continue;
      }
      if (t.t === 'RDNSS') {
        for (;;) {
          const a = next();
          if (a.t === '{') break;
          const c = canonicalIp6(a.t);
          if (!c) err(a.line, `invalid RDNSS address "${a.t}"`);
          ifc.rdnss.push(c!);
        }
        for (;;) { const o = next(); if (o.t === '}') { expect(';'); break; } }
        continue;
      }
      // Other interface options (MinRtrAdvInterval, AdvManagedFlag, ...): "Name value;"
      next();
      expect(';');
    }
    out.push(ifc);
  }
  return out;
}

export interface RadvdLoaded {
  ifaces: RadvdIface[];
}

function linkLocal(i: Interface): string | undefined {
  return (i.addrs6 ?? []).find((a) => a.scope === 'link')?.address;
}

/** Accepts router advertisements: IPv6 enabled on the interface and the host is not a router. */
function acceptsRa(h: Host): boolean {
  return !h.ip6Forward;
}

function applyRa(world: World, host: Host, iface: Interface, ra: Packet): string[] {
  const nd = ra.icmp!.nd!;
  const changes: string[] = [];
  for (const p of nd.prefixes ?? []) {
    // An address from another source (DHCPv6 /128) needs the on-link prefix route from the RA.
    host.routes6 = (host.routes6 ?? []).filter((r) => !(r.dest === p.prefix && r.dev === iface.name && r.proto === 'ra'));
    const own = (iface.addrs6 ?? []).some((a) => a.scope === 'global' && a.prefix <= 64 && inCidr6(a.address, parseCidr6(p.prefix)!));
    if (p.onLink !== false && !own && (iface.autoconf6 === false || !p.autonomous)) host.routes6.push({ dest: p.prefix, dev: iface.name, proto: 'ra' });
    // net.ipv6.conf.IF.autoconf=0 (ifupdown "autoconf 0"): no SLAAC address, but the route and default router still apply.
    if (!p.autonomous || !p.prefix.endsWith('/64') || iface.autoconf6 === false) continue;
    const addr = slaacAddress(p.prefix, iface.mac);
    iface.addrs6 = iface.addrs6 ?? [];
    const existing = iface.addrs6.find((a) => a.address === addr);
    if (existing) existing.validLft = p.valid;
    else {
      iface.addrs6.unshift({ address: addr, prefix: 64, scope: 'global', origin: 'ra', validLft: p.valid });
      changes.push(`${addr}/64`);
    }
  }
  host.routes6 = (host.routes6 ?? []).filter((r) => !(r.dest === 'default' && r.dev === iface.name && r.proto === 'ra'));
  if ((nd.routerLifetime ?? 0) > 0) host.routes6.push({ dest: 'default', via: ra.src, dev: iface.name, proto: 'ra' });
  void world;
  return changes;
}

/** Send a Router Advertisement from `router` on `iface` to all nodes (or to one soliciting host). */
export function sendRa(world: World, router: Host, iface: Interface, cfg: RadvdIface, solicitedBy?: { host: Host; iface: Interface }): { host: Host; addresses: string[] }[] {
  const src = linkLocal(iface);
  if (!src || !iface.segment || !cfg.sendAdvert) return [];
  const ra: Packet = {
    id: nextId(world), src, dst: 'ff02::1', ttl: 255, proto: 'icmp',
    icmp: {
      type: 134, code: 0, description: 'Router Advertisement',
      nd: { lladdr: iface.mac, routerLifetime: cfg.routerLifetime, prefixes: cfg.prefixes.map((p) => ({ prefix: p.prefix, autonomous: p.autonomous, onLink: p.onLink, valid: 86400 })), rdnss: cfg.rdnss, managed: cfg.managed, other: cfg.other, flags: `hop limit 64, managed ${cfg.managed ? 'on' : 'off'}, other ${cfg.other ? 'on' : 'off'}` },
    },
  };
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, router.id, clonePacket(ra));
  capture(world, router, iface, 'out', iface.mac, multicastMac('ff02::1'), ra);
  const configured: { host: Host; addresses: string[] }[] = [];
  const notes: string[] = [];
  for (const h of Object.values(world.hosts)) {
    if (h === router) continue;
    for (const i of h.ifaces) {
      if (!i.up || i.segment !== iface.segment || !linkLocal(i)) continue;
      capture(world, h, i, 'in', iface.mac, multicastMac('ff02::1'), ra);
      const fw = evaluate(h.nft, 'input', { family: 6, src: ra.src, dst: ra.dst, proto: 'icmp', icmpType: 'nd-router-advert', iif: i.name, ctState: 'untracked', len: 96 });
      if (fw.verdict !== 'accept') { notes.push(`${h.hostname}: dropped by its firewall (${describeDecision('input', fw)})`); continue; }
      if (!acceptsRa(h)) { notes.push(`${h.hostname}: ignored (it forwards IPv6, so accept_ra does not apply)`); continue; }
      const added = applyRa(world, h, i, ra);
      configured.push({ host: h, addresses: added });
      notes.push(`${h.hostname}: ${added.length ? `configured ${added.join(', ')} and a default route via ${src}` : 'refreshed its address and default route'}`);
      log(world, h, 'kernel', `IPv6: ${i.name}: ${added.length ? `autoconfigured ${added.join(', ')}` : 'router advertisement refreshed'} from ${src}`);
    }
  }
  if (rec && ev) {
    rec.endPacket(ev, solicitedBy?.host.id ?? configured[0]?.host.id ?? router.id, [], [{ host: router.id, egress: iface.name, srcMac: iface.mac, dstMac: multicastMac('ff02::1'), ttl: 255, note: `multicast to all nodes (ff02::1) on ${iface.segment}; ${notes.join('; ') || 'no other host on the link'}` }], configured.length > 0, configured.length ? `processed by ${configured.map((c) => c.host.id).join(', ')}` : 'no host configured itself');
    rec.describe(ra.id, `ICMPv6 Router Advertisement: prefix ${cfg.prefixes.map((p) => p.prefix).join(', ') || '(none)'}`, `${router.hostname} (radvd) announces itself as a default router (lifetime ${cfg.routerLifetime} s) from its link-local address ${src}, and advertises ${cfg.prefixes.length ? cfg.prefixes.map((p) => `${p.prefix} (${p.autonomous ? 'autonomous: hosts may build addresses from it' : 'not autonomous'})`).join(', ') : 'no prefix'}${cfg.rdnss.length ? `, plus DNS server(s) ${cfg.rdnss.join(', ')} (RDNSS, used only by clients with an RDNSS-aware resolver such as rdnssd, NetworkManager or systemd-networkd)` : ''}${cfg.managed || cfg.other ? `. Flags: M (managed) ${cfg.managed ? 'on: addresses are available from DHCPv6' : 'off'}, O (other) ${cfg.other ? 'on: DNS and other options are available from DHCPv6' : 'off'}` : ''}. Each host appends its 64-bit interface identifier (EUI-64 from its MAC) to the /64 prefix. The default route points at the router's link-local address, not a global one.`);
  }
  world.clock += 0.3;
  return configured;
}

/** A host asks for router advertisements on `iface` (at interface up, or `rdisc6`). */
export function routerSolicit(world: World, host: Host, iface: Interface): { routers: { address: string; mac: string; cfg: RadvdIface }[] } {
  const src = linkLocal(iface);
  if (!src || !iface.segment) return { routers: [] };
  const rs: Packet = {
    id: nextId(world), src, dst: 'ff02::2', ttl: 255, proto: 'icmp',
    icmp: { type: 133, code: 0, description: 'Router Solicitation', nd: { lladdr: iface.mac } },
  };
  const rec = activeRecorder();
  const ev = rec?.beginPacket(world.clock, host.id, clonePacket(rs));
  capture(world, host, iface, 'out', iface.mac, multicastMac('ff02::2'), rs);
  const routers: { host: Host; iface: Interface; cfg: RadvdIface }[] = [];
  const notes: string[] = [];
  for (const h of Object.values(world.hosts)) {
    if (h === host) continue;
    for (const i of h.ifaces) {
      if (!i.up || i.segment !== iface.segment || !linkLocal(i)) continue;
      capture(world, h, i, 'in', iface.mac, multicastMac('ff02::2'), rs);
      const rt = h.services.radvd;
      const loaded = rt?.state === 'active' ? (rt.loaded as RadvdLoaded | null) : null;
      const cfg = loaded?.ifaces.find((c) => c.name === i.name && c.sendAdvert);
      if (!cfg) continue;
      const fw = evaluate(h.nft, 'input', { family: 6, src: rs.src, dst: rs.dst, proto: 'icmp', icmpType: 'nd-router-solicit', iif: i.name, ctState: 'untracked', len: 56 });
      if (fw.verdict !== 'accept') { notes.push(`${h.hostname} runs radvd but its firewall dropped it (${describeDecision('input', fw)})`); continue; }
      routers.push({ host: h, iface: i, cfg });
    }
  }
  if (rec && ev) {
    rec.endPacket(ev, routers[0]?.host.id ?? host.id, [], [{ host: host.id, egress: iface.name, srcMac: iface.mac, dstMac: multicastMac('ff02::2'), ttl: 255, note: `multicast to all routers (ff02::2) on ${iface.segment}; ${routers.length ? `answered by ${routers.map((r) => r.host.hostname).join(', ')}` : notes.join('; ') || 'no router advertisement daemon on this link'}` }], routers.length > 0, routers.length ? `received by ${routers.map((r) => r.host.id).join(', ')}` : 'no router answered');
    rec.describe(rs.id, 'ICMPv6 Router Solicitation', `${host.hostname} brings ${iface.name} up with only a link-local address (${src}, built from its MAC) and asks all routers on the link (ff02::2) to advertise themselves now instead of waiting for the next periodic advertisement.`);
  }
  world.clock += 0.3;
  for (const r of routers) sendRa(world, r.host, r.iface, r.cfg, { host, iface });
  return { routers: routers.map((r) => ({ address: linkLocal(r.iface)!, mac: r.iface.mac, cfg: r.cfg })) };
}
