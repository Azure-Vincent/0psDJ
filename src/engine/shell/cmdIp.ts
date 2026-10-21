// iproute2 `ip`: addresses (IPv4 and IPv6), routes, neighbours and links,
// including 802.1Q VLAN links (ip link add link eth3 name eth3.30 type vlan id 30).

import { normAddr } from '../net/addr';
import { broadcastOf, parseCidr, parseIp } from '../net/ip';
import { canonicalIp6, linkLocalFromMac, parseCidr6, parseIp6 } from '../net/ip6';
import { hasCarrier, recomputeL2 } from '../sim/l2';
import { ifaceMtu, LOOPBACK, lookupRoute, routeTable, routeTable6 } from '../sim/network';
import type { Host, Interface, Route, World } from '../types';
import { type CmdCtx, type CommandDef, err, ok } from './types';

const needRoot = (ctx: CmdCtx) => (ctx.user.uid !== 0 ? err('RTNETLINK answers: Operation not permitted', 2) : null);

function renderRoute(r: Route): string {
  if (r.dest === 'default') return `default via ${r.via} dev ${r.dev} onlink `;
  if (r.proto === 'kernel') return `${r.dest} dev ${r.dev} proto kernel scope link src ${r.src} `;
  return `${r.dest}${r.via ? ` via ${r.via}` : ''} dev ${r.dev} ${r.proto === 'static' ? 'proto static ' : ''}`;
}

function renderRoute6(r: Route): string {
  const dest = r.dest;
  if (r.proto === 'kernel') return `${dest} dev ${r.dev} proto kernel metric 256 pref medium`;
  if (r.proto === 'ra') return dest === 'default'
    ? `default via ${r.via} dev ${r.dev} proto ra metric 1024 expires 1791sec hoplimit 64 pref medium`
    : `${dest} dev ${r.dev} proto ra metric 1024 expires 86391sec pref medium`;
  return `${dest}${r.via ? ` via ${r.via}` : ''} dev ${r.dev}${r.proto === 'static' ? ' proto static' : ''} metric 1024 pref medium`;
}

function ifName(i: Interface): string {
  return i.vlan ? `${i.name}@${i.vlan.parent}` : i.name;
}

let W: World;

function flagsOf(h: Host, i: Interface): string {
  if (i.name === LOOPBACK) return 'LOOPBACK,UP,LOWER_UP';
  if (!i.up) return 'BROADCAST,MULTICAST';
  return hasCarrier(W, h, i) ? 'BROADCAST,MULTICAST,UP,LOWER_UP' : i.vlan ? 'BROADCAST,MULTICAST,UP' : 'NO-CARRIER,BROADCAST,MULTICAST,UP';
}

function state(h: Host, i: Interface): string {
  if (i.name === LOOPBACK) return 'UNKNOWN';
  if (!i.up) return 'DOWN';
  if (hasCarrier(W, h, i)) return 'UP';
  return i.vlan ? 'LOWERLAYERDOWN' : 'DOWN';
}

function linkLines(h: Host, i: Interface, idx: number, detail: boolean): string[] {
  const lo = i.name === LOOPBACK;
  const master = h.bridge?.ports[i.name] ? ` master ${h.bridge.name}` : '';
  const out = [`${idx + 1}: ${ifName(i)}: <${flagsOf(h, i)}> mtu ${ifaceMtu(i)} qdisc ${lo ? 'noqueue' : i.vlan ? 'noqueue' : 'fq_codel'}${master} state ${state(h, i)} group default qlen 1000`];
  out.push(`    link/${lo ? 'loopback' : 'ether'} ${i.mac} brd ${lo ? '00:00:00:00:00:00' : 'ff:ff:ff:ff:ff:ff'}`);
  if (detail && i.vlan) out.push(`    vlan protocol 802.1Q id ${i.vlan.id} <REORDER_HDR> `);
  if (detail && master) out.push(`    bridge_slave state ${i.up ? 'forwarding' : 'disabled'} priority 32 cost 100 `);
  if (!lo && !i.vlan && !h.bridge?.ports[i.name] && !detail) out.push(`    altname enp${idx}s0`);
  return out;
}

function addrLines(i: Interface, fam: 0 | 4 | 6): string[] {
  const lo = i.name === LOOPBACK;
  const out: string[] = [];
  if (fam !== 6 && i.address && (i.up || lo)) {
    out.push(`    inet ${i.address}/${i.prefix}${lo ? '' : ` brd ${broadcastOf(i.address, i.prefix!)}`} scope ${lo ? 'host' : 'global'} ${i.name}`);
    out.push('       valid_lft forever preferred_lft forever');
  }
  if (fam !== 4 && (i.up || lo)) {
    for (const a of i.addrs6 ?? []) {
      const extra = a.origin === 'ra' ? ' dynamic mngtmpaddr' : '';
      out.push(`    inet6 ${a.address}/${a.prefix} scope ${a.scope}${extra} `);
      out.push(a.origin === 'ra' ? `       valid_lft ${a.validLft ?? 86400}sec preferred_lft 14400sec` : '       valid_lft forever preferred_lft forever');
    }
  }
  return out;
}

function devArg(rest: string[]): string | undefined {
  const k = rest.indexOf('dev');
  if (k >= 0) return rest[k + 1];
  // "ip addr show eth0" / "ip link show eth0"
  const cand = rest.find((r, j) => j > 0 && !['show', 'list', 'ls', 'up', 'down', 'dev'].includes(r) && rest[j - 1] !== 'dev');
  return rest[0] === 'show' || rest[0] === 'list' || rest[0] === 'ls' ? cand : undefined;
}

export const ip: CommandDef = {
  name: 'ip',
  summary: 'show / manipulate addresses, routes, neighbours and links (iproute2; IPv4 and IPv6, VLAN links)',
  usage: 'ip [-4|-6] [-br] [-d] addr [show [dev DEV] | add|del ADDR/PREFIX dev DEV | flush dev DEV] | ip [-6] route [get ADDR | add PREFIX via GW | del PREFIX] | ip [-6] neigh [flush] | ip [-d] link [show | set DEV up|down | add link DEV name DEV.ID type vlan id ID | del DEV]',
  run(args, ctx) {
    W = ctx.world;
    let fam: 0 | 4 | 6 = 0;
    let brief = false;
    let detail = false;
    const words: string[] = [];
    for (const a of args) {
      if (a === '-4') fam = 4;
      else if (a === '-6') fam = 6;
      else if (a === '-br' || a === '-brief') brief = true;
      else if (a === '-d' || a === '-details') detail = true;
      else if (a === '-s' || a === '-c' || a === '-color') continue;
      else words.push(a);
    }
    const [objRaw, ...rest] = words;
    const obj = objRaw ?? 'help';
    const host = ctx.host;
    const isAddr = obj.length >= 1 && 'address'.startsWith(obj);
    const isRoute = obj.length >= 1 && 'route'.startsWith(obj) && obj[0] === 'r';
    const isNeigh = ['n', 'ne', 'nei', 'neigh', 'neighbor', 'neighbour'].includes(obj);
    const isLink = obj.length >= 1 && 'link'.startsWith(obj);

    if (isAddr && ['add', 'del', 'delete', 'flush'].includes(rest[0])) {
      const deny = needRoot(ctx);
      if (deny) return deny;
      const dev = rest.indexOf('dev') >= 0 ? rest[rest.indexOf('dev') + 1] : undefined;
      const iface = host.ifaces.find((i) => i.name === dev);
      if (!iface) return err(`Cannot find device "${dev ?? ''}"`, 1);
      if (rest[0] === 'flush') {
        if (fam !== 6) { iface.address = null; iface.prefix = null; host.routes = host.routes.filter((r) => r.dev !== iface.name); }
        if (fam !== 4) iface.addrs6 = (iface.addrs6 ?? []).filter((a) => a.scope === 'link' && fam !== 6);
        return ok('');
      }
      const spec = rest[1] ?? '';
      if (spec.includes(':')) {
        const c = parseCidr6(spec);
        if (!c) return err(`Error: inet6 prefix is expected rather than "${spec}".`, 1);
        const addr = canonicalIp6(spec.split('/')[0])!;
        const prefix = spec.includes('/') ? c.prefix : 128;
        iface.addrs6 = iface.addrs6 ?? [];
        const existing = iface.addrs6.find((a) => a.address === addr);
        if (rest[0] === 'add') {
          if (existing) return err('RTNETLINK answers: File exists', 2);
          iface.addrs6.unshift({ address: addr, prefix, scope: /^fe[89ab]/.test(addr) ? 'link' : 'global', origin: 'static' });
          return ok('');
        }
        if (!existing) return err('RTNETLINK answers: Cannot assign requested address', 2);
        iface.addrs6 = iface.addrs6.filter((a) => a !== existing);
        return ok('');
      }
      const c = parseCidr(spec);
      if (!c || !spec.includes('/')) return err(`Error: any valid prefix is expected rather than "${spec}".`, 1);
      const addr = spec.split('/')[0];
      if (rest[0] === 'add') {
        if (iface.address) return err('RTNETLINK answers: File exists (this simulator models one IPv4 address per interface: delete the old one first)', 2);
        iface.address = addr;
        iface.prefix = c.prefix;
        return ok('');
      }
      if (iface.address !== addr) return err('RTNETLINK answers: Cannot assign requested address', 2);
      iface.address = null;
      iface.prefix = null;
      host.routes = host.routes.filter((r) => r.dev !== iface.name || !r.via);
      return ok('');
    }

    if (isAddr) {
      const dev = devArg(rest);
      const list = host.ifaces.map((i, idx) => ({ i, idx })).filter(({ i }) => !dev || i.name === dev);
      if (dev && list.length === 0) return err(`Device "${dev}" does not exist.`, 1);
      if (brief) {
        return ok(list.map(({ i }) => {
          const addrs = [...(fam !== 6 && i.address && i.up ? [`${i.address}/${i.prefix}`] : []), ...(fam !== 4 && (i.up || i.name === LOOPBACK) ? (i.addrs6 ?? []).map((a) => `${a.address}/${a.prefix}`) : [])];
          return `${ifName(i).padEnd(16)} ${state(host, i).padEnd(14)} ${addrs.join(' ')} `;
        }).join('\n'));
      }
      const out: string[] = [];
      for (const { i, idx } of list) {
        const a = addrLines(i, fam);
        if (fam && a.length === 0) continue;
        out.push(...linkLines(host, i, idx, detail), ...a);
      }
      return ok(out.join('\n'));
    }

    if (isRoute) {
      const sub = rest[0] ?? 'show';
      const target = rest[1];
      const v6 = fam === 6 || (!!target && target.includes(':')) || (rest.includes('via') && (rest[rest.indexOf('via') + 1] ?? '').includes(':'));
      if (sub === 'show' || sub === 'list' || sub === 'ls') return ok((v6 ? routeTable6(host).map(renderRoute6) : routeTable(host).map(renderRoute)).join('\n'));
      if (sub === 'get') {
        const dst = target ? normAddr(target) : undefined;
        if (!dst || (v6 ? parseIp6(dst) === null : parseIp(dst) === null)) return err('Error: any valid prefix is expected rather than "' + (target ?? '') + '".');
        const locals = v6 ? host.ifaces.flatMap((i) => (i.addrs6 ?? []).map((a) => a.address)) : host.ifaces.filter((i) => i.address).map((i) => i.address!);
        if (locals.includes(dst) || dst.startsWith('127.') || dst === '::1') return ok(`local ${dst} dev lo ${v6 ? 'table local proto kernel ' : ''}src ${dst.startsWith('127.') ? '127.0.0.1' : dst} uid ${ctx.user.uid} \n    cache <local> `);
        const rd = lookupRoute(host, dst);
        if (!rd) return err('RTNETLINK answers: Network is unreachable', 2);
        if (v6) return ok(`${dst} from :: ${rd.route.via ? `via ${rd.route.via} ` : ''}dev ${rd.dev} ${rd.route.proto === 'ra' ? 'proto ra ' : rd.route.proto === 'kernel' ? 'proto kernel ' : ''}src ${rd.src} metric ${rd.route.proto === 'kernel' ? 256 : 1024} pref medium`);
        const pm = host.pmtu?.[dst];
        return ok(`${dst} ${rd.route.via ? `via ${rd.route.via} ` : ''}dev ${rd.dev} src ${rd.src} uid ${ctx.user.uid} \n    cache ${pm ? `expires 599sec mtu ${pm} ` : ''}`);
      }
      if (sub === 'add' || sub === 'del' || sub === 'delete' || sub === 'replace') {
        const deny = needRoot(ctx);
        if (deny) return deny;
        const prefix = target;
        const viaRaw = rest.indexOf('via') >= 0 ? rest[rest.indexOf('via') + 1] : undefined;
        const via = viaRaw ? normAddr(viaRaw) : undefined;
        let dev = rest.indexOf('dev') >= 0 ? rest[rest.indexOf('dev') + 1] : undefined;
        const validPrefix = prefix === 'default' || (v6 ? parseCidr6(prefix ?? '') !== null : parseCidr(prefix ?? '') !== null);
        if (!prefix || !validPrefix) return err(`Error: ${v6 ? 'inet6 prefix' : 'any valid prefix'} is expected rather than "${prefix ?? ''}".`);
        const table = v6 ? (host.routes6 = host.routes6 ?? []) : host.routes;
        const dest = prefix === 'default' || prefix === '0.0.0.0/0' || prefix === '::/0' ? 'default'
          : v6 ? `${canonicalIp6(prefix.split('/')[0])}/${prefix.includes('/') ? prefix.split('/')[1] : 128}` : prefix.includes('/') ? prefix : `${prefix}/32`;
        if (sub === 'del' || sub === 'delete') {
          const idx = table.findIndex((r) => r.dest === dest && (!via || r.via === via));
          if (idx < 0) return err('RTNETLINK answers: No such process', 2);
          table.splice(idx, 1);
          return ok('');
        }
        if (via) {
          if (v6) {
            const rd = /^fe[89ab]/.test(via) ? null : lookupRoute(host, via);
            if (!dev && !rd) return err('Error: Nexthop has invalid gateway.', 2);
            dev = dev ?? (rd!.route.via ? undefined : rd!.dev);
            if (!dev) return err('Error: Nexthop has invalid gateway.', 2);
          } else {
            const onlink = host.ifaces.find((i) => i.up && i.address && i.prefix !== null && parseCidr(`${i.address}/${i.prefix}`) && parseCidr(`${i.address}/${i.prefix}`)!.network === (parseCidr(`${via}/${i.prefix}`)!.network));
            if (!onlink) return err('Error: Nexthop has invalid gateway.', 2);
            dev = dev ?? onlink.name;
          }
        }
        if (!dev) return err('Error: Device for nexthop is not up.', 2);
        if (sub === 'add' && table.some((r) => r.dest === dest && r.proto !== 'ra')) return err('RTNETLINK answers: File exists', 2);
        const kept = table.filter((r) => r.dest !== dest || r.proto === 'ra');
        table.length = 0;
        table.push(...kept, { dest, via, dev, proto: 'static' });
        return ok('');
      }
      return err(`Command "${sub}" is unknown, try "ip route help".`, 255);
    }

    if (isNeigh) {
      if (rest[0] === 'flush') {
        host.neighbors = host.neighbors.filter((n) => (fam === 6 ? !n.ip.includes(':') : fam === 4 ? n.ip.includes(':') : false));
        return ok('');
      }
      return ok(host.neighbors
        .filter((n) => (fam === 6 ? n.ip.includes(':') : fam === 4 ? !n.ip.includes(':') : true))
        .map((n) => {
          const router = n.ip.includes(':') && n.mac && Object.values(ctx.world.hosts).some((h) => h.ip6Forward && h.ifaces.some((i) => i.mac === n.mac && i.addrs6?.some((a) => a.address === n.ip)));
          return `${n.ip} dev ${n.dev} ${n.mac ? `lladdr ${n.mac} ` : ''}${router ? 'router ' : ''}${n.state}`;
        }).join('\n'));
    }

    if (isLink) {
      if (rest[0] === 'add') {
        const deny = needRoot(ctx);
        if (deny) return deny;
        const parentName = rest[rest.indexOf('link') + 1];
        const name = rest[rest.indexOf('name') + 1];
        const type = rest[rest.indexOf('type') + 1];
        const id = Number(rest[rest.indexOf('id') + 1]);
        if (rest.indexOf('link') < 0 || rest.indexOf('name') < 0 || type !== 'vlan' || rest.indexOf('id') < 0) return err('Usage: ip link add link DEV name NAME type vlan id ID (only VLAN links are simulated)', 255);
        const parent = host.ifaces.find((i) => i.name === parentName);
        if (!parent) return err(`Cannot find device "${parentName}"`, 1);
        if (!Number.isInteger(id) || id < 1 || id > 4094) return err('Error: argument "' + rest[rest.indexOf('id') + 1] + '" is wrong: id is invalid', 255);
        if (host.ifaces.some((i) => i.name === name)) return err('RTNETLINK answers: File exists', 2);
        host.ifaces.push({ name, mac: parent.mac, segment: null, address: null, prefix: null, up: false, addrs6: [], vlan: { parent: parent.name, id } });
        recomputeL2(ctx.world);
        return ok('');
      }
      if (rest[0] === 'del' || rest[0] === 'delete') {
        const deny = needRoot(ctx);
        if (deny) return deny;
        const name = rest[1] === 'dev' ? rest[2] : rest[1];
        const iface = host.ifaces.find((i) => i.name === name);
        if (!iface) return err(`Cannot find device "${name}"`, 1);
        if (!iface.vlan) return err('RTNETLINK answers: Operation not supported (physical interfaces cannot be deleted)', 2);
        host.ifaces = host.ifaces.filter((i) => i !== iface);
        host.routes = host.routes.filter((r) => r.dev !== name);
        host.routes6 = (host.routes6 ?? []).filter((r) => r.dev !== name);
        recomputeL2(ctx.world);
        return ok('');
      }
      if (rest[0] === 'set') {
        const deny = needRoot(ctx);
        if (deny) return deny;
        const name = rest[1] === 'dev' ? rest[2] : rest[1];
        const iface = host.ifaces.find((i) => i.name === name);
        if (!iface) return err(`Cannot find device "${name}"`);
        if (rest.includes('up')) {
          iface.up = true;
          if (iface.name !== LOOPBACK && !host.bridge?.ports[iface.name] && !(iface.addrs6 ?? []).some((a) => a.scope === 'link')) {
            iface.addrs6 = [...(iface.addrs6 ?? []), { address: linkLocalFromMac(iface.mac), prefix: 64, scope: 'link', origin: 'kernel' }];
          }
        }
        const mtuIdx = rest.indexOf('mtu');
        if (mtuIdx >= 0) {
          const mtu = Number(rest[mtuIdx + 1]);
          if (!Number.isInteger(mtu)) return err(`Error: argument "${rest[mtuIdx + 1] ?? ''}" is wrong: Invalid "mtu" value`, 255);
          if (mtu < 68) return err('Error: mtu less than device minimum.', 2);
          if (mtu > 9216) return err('Error: mtu greater than device maximum.', 2);
          const parent = iface.vlan ? host.ifaces.find((x) => x.name === iface.vlan!.parent) : undefined;
          if (parent && mtu > ifaceMtu(parent)) return err('Error: mtu greater than device maximum.', 2);
          iface.mtu = mtu;
          host.pmtu = {};
        }
        if (rest.includes('down')) {
          iface.up = false;
          host.routes = host.routes.filter((r) => r.dev !== name);
          host.routes6 = (host.routes6 ?? []).filter((r) => r.dev !== name);
        }
        recomputeL2(ctx.world);
        return ok('');
      }
      const dev = devArg(rest);
      const list = host.ifaces.map((i, idx) => ({ i, idx })).filter(({ i }) => !dev || i.name === dev);
      if (dev && list.length === 0) return err(`Device "${dev}" does not exist.`, 1);
      if (brief) return ok(list.map(({ i }) => `${ifName(i).padEnd(16)} ${state(host, i).padEnd(14)} ${i.mac} <${flagsOf(host, i)}> `).join('\n'));
      return ok(list.flatMap(({ i, idx }) => linkLines(host, i, idx, detail)).join('\n'));
    }
    return err('Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\nwhere  OBJECT := { address | route | neigh | link }\n       OPTIONS := { -4 | -6 | -br[ief] | -d[etails] }', 255);
  },
};
