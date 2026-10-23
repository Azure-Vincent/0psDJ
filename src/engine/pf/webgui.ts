// What the pfSense webConfigurator does behind its pages: validate the form,
// change config.xml, mark the subsystem dirty ("The changes must be applied
// for them to take effect") and, on "Apply Changes", reconfigure interfaces
// and reload the filter. The React pages and the guided lab's reference
// solutions both go through these functions, so they edit config.xml exactly
// as the shell tools (viconfig, easyrule) and the boot process read it.

import { isIp as isIPv4, networkOf, parseCidr } from '../net/ip';
import { Shell } from '../shell/shell';
import type { World } from '../types';
import { ifaceOf, newTracker, type PfAddr, type PfAlias, type PfConfig, type PfIface, type PfNatRule, type PfOutboundRule, type PfRule } from './config';
import { applyInterfaces, FILTER_LOG, filterConfigure, readConfig, sysLog, writeConfig } from './model';

export type Subsystem = 'interfaces' | 'filter';

// ---------------------------------------------------------------------------
// The browser
// ---------------------------------------------------------------------------

/**
 * Load a page of the webConfigurator from a client machine (on a copy of the
 * world): the request crosses the network like any other, so a rule that
 * blocks the admin's workstation locks the webConfigurator too.
 */
export function browse(world: World, fromHost: string, user: string, url: string): { ok: boolean; error?: string; detail?: string } {
  let w = structuredClone(world);
  const home = w.hosts[fromHost]?.users[user]?.home ?? '/';
  const sh = new Shell(() => w, (n) => (w = n), { hostId: fromHost, user, cwd: home });
  const r = sh.execute(`curl -sk -m 10 -o /dev/null -w '%{http_code}' ${url}`);
  if (r.code === 0 && /^[23]\d\d$/.test(r.output.trim())) return { ok: true };
  const host = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const errors: Record<number, [string, string]> = {
    6: ['ERR_NAME_NOT_RESOLVED', `${host}'s server IP address could not be found.`],
    7: ['ERR_CONNECTION_REFUSED', `${host} refused to connect.`],
    28: ['ERR_CONNECTION_TIMED_OUT', `${host} took too long to respond.`],
    35: ['ERR_SSL_PROTOCOL_ERROR', `${host} sent an invalid response.`],
  };
  const [error, detail] = errors[r.code] ?? ['ERR_CONNECTION_FAILED', `The connection to ${host} failed.`];
  return { ok: false, error, detail };
}

// ---------------------------------------------------------------------------
// Saving and applying
// ---------------------------------------------------------------------------

/**
 * Save a page: run the edit on the current config.xml; when it reports no
 * input errors, write the file and mark the subsystem as pending. Returns a
 * new world (the caller's world is not modified).
 */
export function guiSave(world: World, hostId: string, subsystem: Subsystem, edit: (cfg: PfConfig, clock: number) => string[], what: string): { world: World; errors: string[] } {
  const w = structuredClone(world);
  const host = w.hosts[hostId];
  let cfg: PfConfig;
  try {
    cfg = readConfig(host);
  } catch (e) {
    return { world, errors: [`The configuration file could not be read: ${(e as Error).message}`] };
  }
  const errors = edit(cfg, w.clock);
  if (errors.length) return { world, errors };
  writeConfig(w, host, cfg);
  const rt = host.pf!;
  rt.pending = [...new Set([...(rt.pending ?? []), subsystem])];
  w.clock += 1000;
  sysLog(w, host, 'php-fpm', `/${what}: Configuration Change: admin@10.0.10.25 (Local Database): ${what}`);
  return { world: w, errors: [] };
}

/** "Apply Changes": reconfigure the interfaces when they changed, then reload the filter. */
export function guiApply(world: World, hostId: string): { world: World; errors: string[] } {
  const w = structuredClone(world);
  const host = w.hosts[hostId];
  const rt = host.pf!;
  if ((rt.pending ?? []).includes('interfaces')) {
    try {
      applyInterfaces(w, host, readConfig(host));
    } catch (e) {
      return { world, errors: [(e as Error).message] };
    }
  }
  const r = filterConfigure(w, host);
  rt.pending = r.ok ? [] : rt.pending;
  w.clock += 1000;
  return { world: w, errors: r.errors };
}

// ---------------------------------------------------------------------------
// Validation helpers (pfSense's input error messages)
// ---------------------------------------------------------------------------

const RESERVED = new Set(['any', 'self', 'lan', 'wan', 'pass', 'block', 'reject', 'in', 'out', 'on', 'from', 'to', 'port', 'proto', 'all', 'inet', 'inet6', 'tcp', 'udp', 'icmp']);

const isPort = (p: string) => /^\d{1,5}([:-]\d{1,5})?$/.test(p) && p.split(/[:-]/).every((n) => Number(n) >= 1 && Number(n) <= 65535);

/** An address field: an IP, a CIDR (when allowed) or the name of a host/network alias. */
function addrError(cfg: PfConfig, value: string, field: string, allowCidr: boolean): string | null {
  if (cfg.aliases.some((a) => a.name === value && a.type !== 'port')) return null;
  if (isIPv4(value)) return null;
  if (allowCidr && value.includes('/') && parseCidr(value)) return null;
  return `A valid ${field} IP address or alias must be specified.`;
}

function portError(cfg: PfConfig, value: string | undefined, field: string): string | null {
  if (!value) return null;
  if (cfg.aliases.some((a) => a.name === value && a.type === 'port')) return null;
  return isPort(value) ? null : `${value} is not a valid ${field} port. It must be a port alias or integer between 1 and 65535.`;
}

function addrFieldErrors(cfg: PfConfig, a: PfAddr, field: 'source' | 'destination'): string[] {
  const e: string[] = [];
  if (a.address !== undefined) {
    const x = addrError(cfg, a.address, field, true);
    if (x) e.push(x);
  }
  if (a.network && a.network !== '(self)') {
    const key = a.network.replace(/ip$/, '');
    const i = cfg.interfaces.find((x) => x.key === key);
    if (!i) e.push(`The ${field} network ${a.network} does not exist.`);
  }
  const p = portError(cfg, a.port, field);
  if (p) e.push(p);
  return e;
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/** Interfaces > Assignments: the network ports not assigned yet. */
export function availablePorts(cfg: PfConfig, hostIfaces: string[]): string[] {
  return hostIfaces.filter((n) => n !== 'lo' && n !== 'lo0' && !cfg.interfaces.some((i) => i.if === n));
}

/** "+ Add": assign a port as the next OPTn interface (disabled, no address). */
export function assignInterface(cfg: PfConfig, port: string): string[] {
  if (cfg.interfaces.some((i) => i.if === port)) return [`${port} is already assigned.`];
  let n = 1;
  while (cfg.interfaces.some((i) => i.key === `opt${n}`)) n++;
  cfg.interfaces.push({ key: `opt${n}`, if: port, descr: `OPT${n}`, enable: false, ipaddr: null, subnet: null });
  return [];
}

export function deleteInterface(cfg: PfConfig, key: string): string[] {
  if (key === 'wan' || key === 'lan') return ['The WAN and LAN interfaces cannot be deleted.'];
  const i = cfg.interfaces.find((x) => x.key === key);
  if (!i) return ['The interface does not exist.'];
  const users = [...cfg.filter.filter((r) => r.interface === key).map((r) => r.descr), ...cfg.nat.filter((r) => r.interface === key).map((r) => r.descr)];
  if (users.length) return [`The interface is part of a group or has rules or NAT entries (${users.slice(0, 3).join(', ')}). Remove them first.`];
  cfg.interfaces = cfg.interfaces.filter((x) => x !== i);
  return [];
}

/** Interfaces > OPTn: enable, description, static IPv4 address. */
export function saveInterface(cfg: PfConfig, key: string, f: { enable: boolean; descr: string; ipaddr: string; subnet: number }): string[] {
  const i = cfg.interfaces.find((x) => x.key === key);
  if (!i) return ['The interface does not exist.'];
  const e: string[] = [];
  const descr = f.descr.trim();
  if (!/^[A-Za-z0-9_]+$/.test(descr)) e.push('The interface description may only contain letters, digits and underscores.');
  else if (cfg.interfaces.some((x) => x !== i && x.descr.toLowerCase() === descr.toLowerCase())) e.push(`An interface with the description ${descr} already exists.`);
  else if (cfg.aliases.some((a) => a.name.toLowerCase() === descr.toLowerCase())) e.push(`An alias with the name ${descr} already exists.`);
  if (f.enable) {
    if (!isIPv4(f.ipaddr)) e.push('A valid IPv4 address must be specified.');
    else if (!(f.subnet >= 1 && f.subnet <= 32)) e.push('A valid subnet bit count must be specified.');
    else {
      const net = networkOf(f.ipaddr, f.subnet);
      if (f.subnet < 31 && (f.ipaddr === net.split('/')[0])) e.push('This IPv4 address is the network address and cannot be used');
      for (const o of cfg.interfaces) {
        if (o === i || !o.enable || !o.ipaddr || o.subnet === null) continue;
        const a = parseCidr(net)!;
        const b = parseCidr(networkOf(o.ipaddr, o.subnet))!;
        const p = Math.min(a.prefix, b.prefix);
        if (networkOf(f.ipaddr, p) === networkOf(o.ipaddr, p)) e.push(`IPv4 address ${f.ipaddr}/${f.subnet} is being used by or overlaps with: ${o.descr} (${o.ipaddr}/${o.subnet})`);
      }
    }
  }
  if (e.length) return e;
  i.enable = f.enable;
  i.descr = descr;
  i.ipaddr = f.enable ? f.ipaddr : i.ipaddr;
  i.subnet = f.enable ? f.subnet : i.subnet;
  return [];
}

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

export function saveAlias(cfg: PfConfig, a: PfAlias, original: string | null): string[] {
  const e: string[] = [];
  const name = a.name.trim();
  if (!/^[A-Za-z0-9_]{1,31}$/.test(name) || /^\d+$/.test(name) || /^_+$/.test(name)) e.push('The alias name must be less than 32 characters long, may not consist of only numbers, may not consist of only underscores, and may only contain the following characters: a-z, A-Z, 0-9, _');
  else if (RESERVED.has(name.toLowerCase())) e.push(`Cannot use a reserved keyword as an alias name: ${name}`);
  else if (cfg.aliases.some((x) => x.name === name && x.name !== original)) e.push('An alias with this name already exists.');
  else if (cfg.interfaces.some((i) => i.descr.toLowerCase() === name.toLowerCase())) e.push('An interface description with this name already exists.');
  const addrs = a.address.map((x) => x.trim()).filter(Boolean);
  if (!addrs.length) e.push('At least one entry must be specified.');
  for (const x of addrs) {
    if (cfg.aliases.some((y) => y.name === x && y.name !== original && (a.type === 'port') === (y.type === 'port'))) continue; // nested alias
    if (a.type === 'port' && !isPort(x)) e.push(`${x} is not a valid port or alias.`);
    if (a.type === 'host' && !isIPv4(x)) e.push(`${x} is not a valid host alias.`);
    if (a.type === 'network' && !(x.includes('/') && parseCidr(x))) e.push(`${x} is not a valid network or alias.`);
  }
  if (e.length) return e;
  const next: PfAlias = { name, type: a.type, address: addrs, descr: a.descr.trim() };
  if (original === null) cfg.aliases.push(next);
  else {
    const idx = cfg.aliases.findIndex((x) => x.name === original);
    if (idx < 0) return ['The alias does not exist.'];
    cfg.aliases[idx] = next;
    // Renaming an alias updates the rules that use it.
    if (original !== name) {
      const ren = (p: PfAddr) => {
        if (p.address === original) p.address = name;
        if (p.port === original) p.port = name;
      };
      for (const r of cfg.filter) { ren(r.source); ren(r.destination); }
      for (const r of cfg.nat) {
        ren(r.source); ren(r.destination);
        if (r.target === original) r.target = name;
        if (r.localPort === original) r.localPort = name;
      }
    }
  }
  return [];
}

/** Where an alias is used (pfSense refuses to delete aliases in use). */
export function aliasUsers(cfg: PfConfig, name: string): string[] {
  const uses = (p: PfAddr) => p.address === name || p.port === name;
  return [
    ...cfg.filter.filter((r) => uses(r.source) || uses(r.destination)).map((r) => r.descr || `rule ${r.tracker}`),
    ...cfg.nat.filter((r) => uses(r.source) || uses(r.destination) || r.target === name || r.localPort === name).map((r) => r.descr || 'port forward'),
    ...cfg.aliases.filter((a) => a.name !== name && a.address.includes(name)).map((a) => a.name),
  ];
}

export function deleteAlias(cfg: PfConfig, name: string): string[] {
  const users = aliasUsers(cfg, name);
  if (users.length) return [`Cannot delete alias. Currently in use by ${users[0]}`];
  cfg.aliases = cfg.aliases.filter((a) => a.name !== name);
  return [];
}

// ---------------------------------------------------------------------------
// Firewall rules
// ---------------------------------------------------------------------------

export function ruleErrors(cfg: PfConfig, r: PfRule): string[] {
  const e: string[] = [];
  if (!ifaceOf(cfg, r.interface)) e.push('The interface does not exist.');
  const ports = r.protocol === 'tcp' || r.protocol === 'udp' || r.protocol === 'tcp/udp';
  if (!ports && (r.source.port || r.destination.port)) e.push('Source and destination ports can only be specified with the TCP and UDP protocols.');
  e.push(...addrFieldErrors(cfg, r.source, 'source'), ...addrFieldErrors(cfg, r.destination, 'destination'));
  if (r.descr.length > 52) e.push('The description must be 52 characters or less.');
  return e;
}

/** Save a rule. New rules go to the bottom of the interface's list, or the top ("Add rule to the top of the list"). */
export function saveRule(cfg: PfConfig, r: PfRule, tracker: string | null, clock: number, position: 'top' | 'bottom' = 'bottom'): string[] {
  const e = ruleErrors(cfg, r);
  if (e.length) return e;
  if (tracker) {
    const idx = cfg.filter.findIndex((x) => x.tracker === tracker);
    if (idx < 0) return ['The rule does not exist.'];
    cfg.filter[idx] = { ...r, tracker, associatedRuleId: cfg.filter[idx].associatedRuleId };
    return [];
  }
  const rule = { ...r, tracker: newTracker(cfg, clock) };
  const same = cfg.filter.map((x, i) => (x.interface === r.interface ? i : -1)).filter((i) => i >= 0);
  if (position === 'top' && same.length) cfg.filter.splice(same[0], 0, rule);
  else if (same.length) cfg.filter.splice(same[same.length - 1] + 1, 0, rule);
  else cfg.filter.push(rule);
  return [];
}

export function deleteRule(cfg: PfConfig, tracker: string): string[] {
  const r = cfg.filter.find((x) => x.tracker === tracker);
  if (!r) return ['The rule does not exist.'];
  cfg.filter = cfg.filter.filter((x) => x !== r);
  // A port forward that loses its associated rule keeps working as an unassociated forward.
  for (const n of cfg.nat) if (r.associatedRuleId && n.associatedRuleId === r.associatedRuleId) n.associatedRuleId = undefined;
  return [];
}

export function toggleRule(cfg: PfConfig, tracker: string): string[] {
  const r = cfg.filter.find((x) => x.tracker === tracker);
  if (!r) return ['The rule does not exist.'];
  r.disabled = !r.disabled;
  return [];
}

/** Move a rule up or down among the rules of its interface (drag and drop in the real page). */
export function moveRule(cfg: PfConfig, tracker: string, dir: -1 | 1): string[] {
  const idx = cfg.filter.findIndex((x) => x.tracker === tracker);
  if (idx < 0) return ['The rule does not exist.'];
  const iface = cfg.filter[idx].interface;
  let j = idx + dir;
  while (j >= 0 && j < cfg.filter.length && cfg.filter[j].interface !== iface) j += dir;
  if (j < 0 || j >= cfg.filter.length) return [];
  [cfg.filter[idx], cfg.filter[j]] = [cfg.filter[j], cfg.filter[idx]];
  return [];
}

// ---------------------------------------------------------------------------
// NAT
// ---------------------------------------------------------------------------

export type FilterAssoc = 'associated' | 'unassociated' | 'none';

/**
 * Save a port forward. "Add associated filter rule" creates a pass rule on the
 * same interface to the translated address and port, linked to the forward
 * (descr "NAT <descr>"); "unassociated" adds the same rule without the link;
 * "None" adds no rule (traffic is then translated and blocked by the default deny).
 */
export function savePortForward(cfg: PfConfig, r: PfNatRule, index: number | null, assoc: FilterAssoc, clock: number): string[] {
  const e: string[] = [];
  if (!ifaceOf(cfg, r.interface)) e.push('The interface does not exist.');
  if (!['tcp', 'udp', 'tcp/udp'].includes(r.protocol)) e.push('A port forward needs the TCP, UDP or TCP/UDP protocol.');
  if (!r.destination.port) e.push('A valid destination port range must be specified.');
  e.push(...addrFieldErrors(cfg, r.source, 'source'), ...addrFieldErrors(cfg, r.destination, 'destination'));
  const t = addrError(cfg, r.target, 'redirect target', false);
  if (t) e.push(t);
  const lp = portError(cfg, r.localPort || undefined, 'redirect target');
  if (lp) e.push(lp);
  if (e.length) return e;
  const old = index === null ? undefined : cfg.nat[index];
  const id = old?.associatedRuleId ?? (assoc === 'associated' ? `nat_${Math.floor(clock / 1000).toString(16)}${String(cfg.nat.length).padStart(2, '0')}.${(clock % 100000000).toString().padStart(8, '0')}` : undefined);
  const next: PfNatRule = { ...r, associatedRuleId: assoc === 'associated' || (old?.associatedRuleId && assoc !== 'none') ? id : undefined };
  const filterRule = (): PfRule => ({
    tracker: '', type: 'pass', interface: r.interface, protocol: r.protocol, source: { ...r.source },
    destination: { address: r.target, port: r.localPort || r.destination.port }, descr: `NAT ${r.descr}`.slice(0, 52), disabled: r.disabled, log: false, associatedRuleId: id,
  });
  if (old) cfg.nat[index!] = next;
  else cfg.nat.push(next);
  if (next.associatedRuleId) {
    const existing = cfg.filter.find((x) => x.associatedRuleId === next.associatedRuleId);
    if (existing) Object.assign(existing, { ...filterRule(), tracker: existing.tracker });
    else saveRule(cfg, filterRule(), null, clock);
  }
  if (assoc === 'unassociated' && !old) saveRule(cfg, { ...filterRule(), associatedRuleId: undefined }, null, clock);
  return [];
}

/** Deleting a port forward also deletes its associated filter rule. */
export function deletePortForward(cfg: PfConfig, index: number): string[] {
  const r = cfg.nat[index];
  if (!r) return ['The port forward does not exist.'];
  cfg.nat.splice(index, 1);
  if (r.associatedRuleId) cfg.filter = cfg.filter.filter((x) => x.associatedRuleId !== r.associatedRuleId);
  return [];
}

export function setOutboundMode(cfg: PfConfig, mode: PfConfig['outbound']['mode']): string[] {
  // Switching from automatic to manual copies the automatic rules, so nothing changes until they are edited.
  if (mode === 'advanced' && cfg.outbound.mode === 'automatic' && !cfg.outbound.rules.length) {
    for (const w of cfg.interfaces.filter((i) => i.enable && i.gateway)) {
      const nets = [
        ...cfg.interfaces.filter((i) => i.enable && !i.gateway && i.ipaddr && i.subnet !== null).map((i) => networkOf(i.ipaddr!, i.subnet!)),
        ...cfg.routes.map((r) => r.network), '127.0.0.0/8',
      ];
      for (const n of nets) cfg.outbound.rules.push({ interface: w.key, source: n, destination: 'any', target: '', descr: `Auto created rule - ${w.descr} to ${n}`, disabled: false });
    }
  }
  cfg.outbound.mode = mode;
  return [];
}

export function saveOutbound(cfg: PfConfig, r: PfOutboundRule, index: number | null): string[] {
  const e: string[] = [];
  if (!ifaceOf(cfg, r.interface)) e.push('The interface does not exist.');
  if (r.source !== 'any' && !(r.source.includes('/') && parseCidr(r.source)) && !cfg.aliases.some((a) => a.name === r.source && a.type !== 'port')) e.push('A valid source network must be specified (network/mask or alias).');
  if (r.destination !== 'any' && !(r.destination.includes('/') && parseCidr(r.destination))) e.push('A valid destination network must be specified.');
  if (r.target && !isIPv4(r.target)) e.push('The translation address must be an IPv4 address (empty = interface address).');
  if (e.length) return e;
  if (index === null) cfg.outbound.rules.push(r);
  else cfg.outbound.rules[index] = r;
  return [];
}

export function deleteOutbound(cfg: PfConfig, index: number): string[] {
  if (!cfg.outbound.rules[index]) return ['The mapping does not exist.'];
  cfg.outbound.rules.splice(index, 1);
  return [];
}

// ---------------------------------------------------------------------------
// Status pages
// ---------------------------------------------------------------------------

export interface FilterLogEntry {
  time: string;
  action: 'pass' | 'block';
  iface: string;
  rule: string;
  src: string;
  dst: string;
  proto: string;
}

/** Status > System Logs > Firewall: filter.log, newest first, with the rule's description from its tracker. */
export function firewallLog(world: World, hostId: string, cfg: PfConfig | null): FilterLogEntry[] {
  const host = world.hosts[hostId];
  const lines = (host.fs[FILTER_LOG]?.content ?? '').split('\n').filter(Boolean);
  const out: FilterLogEntry[] = [];
  for (const l of lines) {
    const m = /^(\w{3} [ \d]\d \d\d:\d\d:\d\d) \S+ filterlog\[\d+\]: (.*)$/.exec(l);
    if (!m) continue;
    const f = m[2].split(',');
    const tracker = f[3];
    const ifname = f[4];
    const proto = f[16];
    const [src, dst] = [f[18], f[19]];
    const ports = proto === 'tcp' || proto === 'udp' ? [f[20], f[21]] : [];
    const rule = tracker === '1000000103' ? 'Default deny rule IPv4' : tracker === '12000' ? 'Block private networks' : cfg?.filter.find((r) => r.tracker === tracker)?.descr ?? `tracker ${tracker}`;
    const iface = cfg?.interfaces.find((i) => i.if === ifname)?.descr ?? ifname;
    out.push({ time: m[1], action: f[6] === 'pass' ? 'pass' : 'block', iface, rule, src: ports.length ? `${src}:${ports[0]}` : src, dst: ports.length ? `${dst}:${ports[1]}` : dst, proto: proto.toUpperCase() });
  }
  return out.reverse();
}

/** Labels for the source/destination selector ("LAN net", "WAN address", "This Firewall"). */
export function addrLabel(cfg: PfConfig, a: PfAddr): string {
  const not = a.not ? '! ' : '';
  if (a.network) {
    if (a.network === '(self)') return `${not}This Firewall`;
    const ip = a.network.endsWith('ip');
    const i = cfg.interfaces.find((x) => x.key === (ip ? a.network!.slice(0, -2) : a.network));
    return `${not}${i?.descr ?? a.network} ${ip ? 'address' : 'net'}`;
  }
  if (a.address) return `${not}${a.address}`;
  return `${not}*`;
}

export const ifaceLabel = (cfg: PfConfig, key: string): string => cfg.interfaces.find((i) => i.key === key)?.descr ?? key.toUpperCase();

export type { PfIface };
