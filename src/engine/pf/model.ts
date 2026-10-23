// pfSense hosts. The configuration is /conf/config.xml; "applying" it does
// what pfSense's PHP does: interfaces and routes come from <interfaces>,
// <gateways> and <staticroutes>, and the filter (rules, port forwards,
// outbound NAT) is generated as a pf ruleset (/tmp/rules.debug) and loaded.
// Here the pf ruleset is compiled into the simulator's packet filter, with
// pf's semantics: rules apply to traffic entering an interface, the first
// matching rule wins ("quick"), passed connections keep state, port forwards
// (rdr) are translated before filtering, and the default deny is logged.

import type { Chain, MatchExpr, Rule, Ruleset } from '../config/nft';
import { networkOf, parseCidr } from '../net/ip';
import { recomputeL2 } from '../sim/l2';
import type { Host, World } from '../types';
import { fromXml, ifaceOf, PF_CONFIG, toXml, type PfAddr, type PfConfig, type PfRule } from './config';
import { XmlError } from './xml';

export const PF_TABLE = 'pf';
export const PF_VERSION = '2.7.2-RELEASE';
export const FILTER_LOG = '/var/log/filter.log';
export const RULES_DEBUG = '/tmp/rules.debug';

/** One line of the generated pf ruleset and the compiled rules that implement it (for counters). */
export interface PfLine {
  text: string;
  /** Handles of the compiled rules (filter or NAT). */
  handles: number[];
  section: 'filter' | 'nat';
}

export interface PfRuntime {
  /** pf is enabled (pfctl -d disables filtering and NAT). */
  enabled: boolean;
  /** The ruleset compiled at the last successful load. */
  ruleset: Ruleset;
  lines: PfLine[];
  /** config.xml text of the last successful load (pfSense restores from backup if the file breaks). */
  lastGood: string;
  loadedAt: number;
  /** Errors of the last load attempt. */
  errors: string[];
  /** Saved in the webConfigurator but not applied yet ("You must apply the changes"). */
  pending?: ('interfaces' | 'filter')[];
}

export function isPfsense(host: Host | undefined): boolean {
  return host?.kind === 'pfsense';
}

const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'];
const ICMP_NAMES: Record<string, string> = { echoreq: 'echo-request', echorep: 'echo-reply', unreach: 'destination-unreachable', timex: 'time-exceeded' };
const PORT_NAMES: Record<string, string> = { 22: 'ssh', 53: 'domain', 80: 'http', 443: 'https', 3389: 'ms-wbt-server' };

export function readConfig(host: Host): PfConfig {
  return fromXml(host.fs[PF_CONFIG]?.content ?? '');
}

/** Write the configuration back to config.xml (what saving a page in the webConfigurator does). */
export function writeConfig(world: World, host: Host, cfg: PfConfig): void {
  const node = host.fs[PF_CONFIG];
  host.fs[PF_CONFIG] = { type: 'file', mode: 0o644, owner: 'root', group: 'wheel', content: toXml(cfg), mtime: world.clock, ...(node ? { mode: node.mode } : {}) };
}

// ---------------------------------------------------------------------------
// Address and port resolution
// ---------------------------------------------------------------------------

class CompileError extends Error {}

function ifaceAddrs(cfg: PfConfig): string[] {
  return cfg.interfaces.filter((i) => i.enable && i.ipaddr).map((i) => i.ipaddr!);
}

/** Addresses for a <source>/<destination>; null = any. Interface macros: lan (subnet), lanip (address), (self). */
export function resolveAddr(cfg: PfConfig, a: PfAddr): { values: string[] | null; text: string } {
  if (a.network) {
    const n = a.network.toLowerCase();
    if (n === '(self)') return { values: [...ifaceAddrs(cfg), '127.0.0.1'], text: '(self)' };
    const isIp = n.endsWith('ip');
    const i = ifaceOf(cfg, isIp ? n.slice(0, -2) : n);
    if (!i) throw new CompileError(`unknown interface network "${a.network}"`);
    if (!i.ipaddr || i.subnet === null) return { values: [], text: `(${i.if}${isIp ? '' : ':network'})` };
    return isIp ? { values: [`${i.ipaddr}/32`], text: i.ipaddr } : { values: [networkOf(i.ipaddr, i.subnet)], text: networkOf(i.ipaddr, i.subnet) };
  }
  if (a.address) {
    const alias = cfg.aliases.find((x) => x.name === a.address);
    if (alias) {
      if (alias.type === 'port') throw new CompileError(`port alias "${alias.name}" used as an address`);
      return { values: alias.address.map((x) => (x.includes('/') ? x : `${x}/32`)), text: `<${alias.name}>` };
    }
    const v = a.address.includes('/') ? a.address : `${a.address}/32`;
    if (!parseCidr(v)) throw new CompileError(`syntax error near "${a.address}"`);
    return { values: [v], text: a.address };
  }
  return { values: null, text: 'any' };
}

/** Ports for a <port>: "80", "80-443" / "80:443", or a port alias. */
export function resolvePorts(cfg: PfConfig, p: string | undefined): { values: string[] | null; text: string } {
  if (!p) return { values: null, text: '' };
  const alias = cfg.aliases.find((x) => x.name === p);
  const raw = alias ? (alias.type === 'port' ? alias.address : null) : [p];
  if (!raw) throw new CompileError(`host alias "${p}" used as a port`);
  const values = raw.map((x) => x.replace(':', '-'));
  for (const v of values) if (!/^\d{1,5}(-\d{1,5})?$/.test(v) || v.split('-').some((n) => Number(n) > 65535)) throw new CompileError(alias ? `invalid port "${v}" in alias "${alias.name}"` : `syntax error near "${p}"`);
  const one = (v: string) => (v.includes('-') ? v.replace('-', ':') : `= ${PORT_NAMES[v] ?? v}`);
  return { values, text: alias ? `$${alias.name}` : values.length === 1 ? one(values[0]) : `{ ${values.join(' ')} }` };
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

export interface Compiled {
  ruleset: Ruleset;
  lines: PfLine[];
  rulesDebug: string;
  errors: string[];
}

export function compilePf(cfg: PfConfig): Compiled {
  let handle = 1;
  const errors: string[] = [];
  const lines: PfLine[] = [];
  const input: Rule[] = [];
  const forward: Rule[] = [];
  const pre: Rule[] = [];
  const post: Rule[] = [];
  const mk = (matches: MatchExpr[], verdict: Rule['verdict'], comment: string, log?: string): Rule => ({ handle: handle++, matches, counter: { packets: 0, bytes: 0 }, log: log ? { prefix: log } : null, verdict, comment });
  const iif = (name: string): MatchExpr => ({ kind: 'iface', field: 'iifname', negate: false, values: [name] });
  const oif = (name: string): MatchExpr => ({ kind: 'iface', field: 'oifname', negate: false, values: [name] });
  const addr = (field: 'saddr' | 'daddr', values: string[], negate = false): MatchExpr => ({ kind: 'addr', family: 4, field, negate, values });
  /** A filter rule goes into both input (to the firewall) and forward (through it): the destination decides which applies. */
  const both = (make: () => Rule): number[] => { const a = make(); const b = { ...make(), handle: handle++ }; input.push(a); forward.push(b); return [a.handle, b.handle]; };

  const wanIfs = cfg.interfaces.filter((i) => i.enable && i.if && i.gateway);
  const active = (key: string) => { const i = ifaceOf(cfg, key); return i && i.enable && i.if ? i : undefined; };

  // State: replies and related packets of passed connections.
  const est = (): Rule => mk([{ kind: 'ctstate', values: ['established', 'related'] }], { kind: 'accept' }, 'pass: keep state');
  input.push(est());
  forward.push(est());
  input.push(mk([iif('lo')], { kind: 'accept' }, 'pass quick on lo0'));
  lines.push({ section: 'filter', text: 'block drop in log inet all label "Default deny rule IPv4"', handles: [] });
  lines.push({ section: 'filter', text: 'pass out inet all flags S/SA keep state allow-opts label "let out anything IPv4 from firewall host itself"', handles: [] });

  for (const w of cfg.interfaces.filter((i) => i.enable && i.if && i.blockpriv)) {
    const h = both(() => mk([iif(w.if), addr('saddr', PRIVATE)], { kind: 'drop' }, `Block private networks from ${w.descr}`, `pf|12000|block|Block private networks from ${w.descr}`));
    lines.push({ section: 'filter', text: `block drop in log quick on ${w.if} inet from { ${PRIVATE.join(' ')} } to any label "Block private networks from ${w.descr}"`, handles: h });
  }

  const lan = active('lan');
  if (cfg.antiLockout && lan?.ipaddr) {
    const ports = ['443', '80', ...(cfg.sshEnabled ? ['22'] : [])];
    const h = both(() => mk([iif(lan.if), addr('daddr', [`${lan.ipaddr}/32`]), { kind: 'port', proto: 'tcp', field: 'dport', negate: false, values: ports }], { kind: 'accept' }, 'anti-lockout rule'));
    lines.push({ section: 'filter', text: `pass in quick on ${lan.if} inet proto tcp from any to (${lan.if}) port { ${ports.join(' ')} } flags S/SA keep state label "anti-lockout rule"`, handles: h });
  }

  cfg.filter.forEach((r, idx) => {
    if (r.disabled) return;
    const i = active(r.interface);
    if (!i) return; // rules of unassigned or disabled interfaces are not loaded
    try {
      lines.push({ section: 'filter', ...userRule(r, i.if, idx) });
    } catch (e) {
      if (!(e instanceof CompileError)) throw e;
      errors.push(`${RULES_DEBUG}:${lines.length + 20}: ${e.message} - The line in question reads [${lines.length + 20}]: ${r.type} in quick on $${i.descr} ... label "USER_RULE: ${r.descr}"`);
    }
  });

  function userRule(r: PfRule, ifname: string, idx: number): Omit<PfLine, 'section'> {
    const src = resolveAddr(cfg, r.source);
    const dst = resolveAddr(cfg, r.destination);
    const sp = resolvePorts(cfg, r.source.port);
    const dp = resolvePorts(cfg, r.destination.port);
    const protos = r.protocol === 'tcp/udp' ? ['tcp', 'udp'] : r.protocol ? [r.protocol] : [null];
    const verdict: Rule['verdict'] = r.type === 'pass' ? { kind: 'accept' } : r.type === 'block' ? { kind: 'drop' } : { kind: 'reject', with: 'default' };
    const label = `USER_RULE: ${r.descr}`;
    const handles: number[] = [];
    for (const proto of protos) {
      const m: MatchExpr[] = [iif(ifname)];
      if (src.values) m.push(addr('saddr', src.values, !!r.source.not));
      if (dst.values) m.push(addr('daddr', dst.values, !!r.destination.not));
      if (proto === 'tcp' || proto === 'udp') {
        if (sp.values) m.push({ kind: 'port', proto, field: 'sport', negate: false, values: sp.values });
        if (dp.values) m.push({ kind: 'port', proto, field: 'dport', negate: false, values: dp.values });
        if (!sp.values && !dp.values) m.push({ kind: 'l4proto', via: 'meta l4proto', negate: false, values: [proto] });
      } else if (proto === 'icmp') {
        m.push({ kind: 'l4proto', via: 'meta l4proto', negate: false, values: ['icmp'] });
        if (r.icmptype && ICMP_NAMES[r.icmptype]) m.push({ kind: 'icmptype', values: [ICMP_NAMES[r.icmptype]] });
      } else if (proto) throw new CompileError(`unknown protocol ${proto}`);
      handles.push(...both(() => mk(m, verdict, label, r.log ? `pf|${r.tracker || 1000 + idx}|${r.type === 'pass' ? 'pass' : 'block'}|${label}` : undefined)));
    }
    const action = r.type === 'pass' ? 'pass in quick' : r.type === 'block' ? `block drop in${r.log ? ' log' : ''} quick` : `block return in${r.log ? ' log' : ''} quick`;
    const passLog = r.type === 'pass' && r.log ? 'pass in log quick' : action;
    const protoText = r.protocol ? ` proto ${r.protocol === 'tcp/udp' ? '{ tcp udp }' : r.protocol}` : '';
    const not = (a: PfAddr) => (a.not ? '! ' : '');
    const text = `${passLog} on ${ifname} inet${protoText} from ${not(r.source)}${src.text}${sp.text ? ` port ${sp.text}` : ''} to ${not(r.destination)}${dst.text}${dp.text ? ` port ${dp.text}` : ''}${r.protocol === 'icmp' && r.icmptype ? ` icmp-type ${r.icmptype}` : ''}${r.type === 'pass' ? `${r.protocol === 'tcp' || !r.protocol || r.protocol === 'tcp/udp' ? ' flags S/SA' : ''} keep state` : ''} label "${label}"`;
    return { text, handles };
  }

  const deny = (): Rule => mk([], { kind: 'drop' }, 'Default deny rule IPv4', 'pf|1000000103|block|Default deny rule IPv4');
  const d1 = deny();
  const d2 = deny();
  input.push(d1);
  forward.push(d2);
  lines[0].handles.push(d1.handle, d2.handle);

  // ---- NAT: port forwards (rdr) and outbound NAT --------------------------
  for (const r of cfg.nat) {
    if (r.disabled) continue;
    const i = active(r.interface);
    if (!i) continue;
    try {
      const dst = resolveAddr(cfg, r.destination);
      const src = resolveAddr(cfg, r.source);
      const dp = resolvePorts(cfg, r.destination.port);
      const target = resolveAddr(cfg, { address: r.target });
      if (!target.values || target.values.length !== 1) throw new CompileError(`invalid redirect target "${r.target}"`);
      const tip = target.values[0].replace(/\/32$/, '');
      const lp = r.localPort ? Number(r.localPort.split(/[-:]/)[0]) : undefined;
      const protos = r.protocol === 'tcp/udp' ? ['tcp', 'udp'] as const : [r.protocol as 'tcp' | 'udp'];
      const handles: number[] = [];
      for (const proto of protos) {
        const m: MatchExpr[] = [iif(i.if)];
        if (src.values) m.push(addr('saddr', src.values));
        if (dst.values) m.push(addr('daddr', dst.values));
        if (dp.values) m.push({ kind: 'port', proto, field: 'dport', negate: false, values: dp.values });
        else m.push({ kind: 'l4proto', via: 'meta l4proto', negate: false, values: [proto] });
        const rule = mk(m, { kind: 'dnat', addr: tip, port: lp }, `rdr: ${r.descr}`);
        pre.push(rule);
        handles.push(rule.handle);
      }
      lines.push({ section: 'nat', handles, text: `rdr on ${i.if} inet proto ${r.protocol === 'tcp/udp' ? '{ tcp udp }' : r.protocol} from ${src.text} to ${dst.text}${dp.text ? ` port ${dp.text.replace(/^= /, '')}` : ''} -> ${tip}${r.localPort ? ` port ${r.localPort}` : ''}` });
    } catch (e) {
      if (!(e instanceof CompileError)) throw e;
      errors.push(`${RULES_DEBUG}:${lines.length + 20}: ${e.message} - The line in question reads [${lines.length + 20}]: rdr on $${i.descr} ... # ${r.descr}`);
    }
  }

  const internal = [
    ...cfg.interfaces.filter((i) => i.enable && i.if && !i.gateway && i.ipaddr && i.subnet !== null).map((i) => networkOf(i.ipaddr!, i.subnet!)),
    ...cfg.routes.map((r) => r.network),
    '127.0.0.0/8',
  ];
  const outRule = (ifname: string, ifaddr: string, sources: string[], dest: string | null, target: string, descr: string) => {
    const m: MatchExpr[] = [oif(ifname), addr('saddr', sources)];
    if (dest) m.push(addr('daddr', [dest]));
    const rule = mk(m, target ? { kind: 'snat', addr: target } : { kind: 'masquerade' }, descr);
    post.push(rule);
    lines.push({ section: 'nat', handles: [rule.handle], text: `nat on ${ifname} inet from { ${sources.join(' ')} } to ${dest ?? 'any'} -> ${target || ifaddr} port 1024:65535` });
  };
  const mode = cfg.outbound.mode;
  if (mode === 'hybrid' || mode === 'advanced') {
    for (const r of cfg.outbound.rules) {
      if (r.disabled) continue;
      const i = active(r.interface);
      if (!i?.ipaddr) continue;
      try {
        const src = r.source === 'any' ? null : resolveAddr(cfg, /^[a-z]+\d*$/i.test(r.source) && !cfg.aliases.some((a) => a.name === r.source) ? { network: r.source } : { address: r.source }).values;
        outRule(i.if, i.ipaddr, src ?? ['0.0.0.0/0'], r.destination === 'any' ? null : r.destination, r.target, `nat: ${r.descr}`);
      } catch (e) {
        if (!(e instanceof CompileError)) throw e;
        errors.push(`${RULES_DEBUG}:${lines.length + 20}: ${e.message} - The line in question reads [${lines.length + 20}]: nat on $${i.descr} ... # ${r.descr}`);
      }
    }
  }
  if (mode === 'automatic' || mode === 'hybrid') {
    for (const w of wanIfs) if (w.ipaddr) outRule(w.if, w.ipaddr, internal, null, '', `Auto created rule - ${w.descr}`);
  }

  const chain = (name: string, hook: 'input' | 'forward' | 'output' | 'prerouting' | 'postrouting', type: string, rules: Rule[]): Chain => ({ name, base: { type, hook, priority: type === 'nat' ? (hook === 'prerouting' ? -100 : 100) : 0, policy: hook === 'output' || type === 'nat' ? 'accept' : 'drop' }, rules, handle: handle++ });
  const ruleset: Ruleset = {
    tables: [
      { family: 'inet', name: PF_TABLE, chains: [chain('in', 'input', 'filter', input), chain('forward', 'forward', 'filter', forward), chain('out', 'output', 'filter', [])], handle: handle++ },
      { family: 'ip', name: 'pfnat', chains: [chain('rdr', 'prerouting', 'nat', pre), chain('nat', 'postrouting', 'nat', post)], handle: handle++ },
    ],
    nextHandle: handle,
  };
  const macros = cfg.interfaces.filter((i) => i.if).map((i) => `${i.descr.toUpperCase()} = "{ ${i.if} }"`);
  const tables = cfg.aliases.filter((a) => a.type !== 'port').map((a) => `table <${a.name}> { ${a.address.join(' ')} }`);
  const portMacros = cfg.aliases.filter((a) => a.type === 'port').map((a) => `${a.name} = "{ ${a.address.join(' ')} }"`);
  const rulesDebug = [
    '#System aliases', '', 'loopback = "{ lo0 }"', ...macros, '', '#SSH Lockout Table', 'table <sshguard> persist', '', ...tables, ...portMacros, '', '# Gateways', ...cfg.gateways.map((g) => `GW${g.name} = " route-to ( ${ifaceOf(cfg, g.interface)?.if ?? g.interface} ${g.gateway} ) "`), '',
    'set loginterface vtnet0', 'set skip on pfsync0', '', '',
    ...lines.filter((l) => l.section === 'nat').map((l) => l.text), '',
    '#---------------------------------------------------------------------------', '# default deny rules', '#---------------------------------------------------------------------------',
    ...lines.filter((l) => l.section === 'filter').map((l) => l.text), '',
  ].join('\n');
  return { ruleset, lines, rulesDebug, errors };
}

// ---------------------------------------------------------------------------
// Loading, booting, logging
// ---------------------------------------------------------------------------

/** /etc/rc.filter_configure: generate and load the ruleset; on errors pf keeps the previous rules. */
export function filterConfigure(world: World, host: Host): { ok: boolean; errors: string[] } {
  const rt = host.pf!;
  let cfg: PfConfig;
  try {
    cfg = readConfig(host);
  } catch (e) {
    const msg = e instanceof XmlError ? `XML error: ${e.message} at line ${e.line} in ${PF_CONFIG}` : (e as Error).message;
    rt.errors = [msg];
    sysLog(world, host, 'php-fpm', `/rc.filter_configure: ${msg}`);
    return { ok: false, errors: [msg] };
  }
  const c = compilePf(cfg);
  host.fs[RULES_DEBUG] = { type: 'file', mode: 0o644, owner: 'root', group: 'wheel', content: c.rulesDebug, mtime: world.clock };
  if (c.errors.length) {
    rt.errors = c.errors;
    sysLog(world, host, 'php-fpm', `/rc.filter_configure: New alert found: There were error(s) loading the rules: ${c.errors[0]}`);
    return { ok: false, errors: c.errors };
  }
  rt.ruleset = c.ruleset;
  rt.lines = c.lines;
  rt.errors = [];
  rt.loadedAt = world.clock;
  rt.lastGood = host.fs[PF_CONFIG].content;
  rt.pending = (rt.pending ?? []).filter((x) => x !== 'filter');
  host.nft = rt.enabled ? rt.ruleset : { tables: [], nextHandle: 1 };
  // Changing rules does not drop existing states (pf keeps them until they expire or are killed).
  return { ok: true, errors: [] };
}

/** Interfaces, gateways and static routes from config.xml (rc.reload_interfaces / boot). */
export function applyInterfaces(world: World, host: Host, cfg: PfConfig): void {
  host.routes = [];
  for (const i of host.ifaces) {
    if (i.name === 'lo0' || i.name === 'lo') continue;
    const c = cfg.interfaces.find((x) => x.if === i.name);
    i.up = !!c?.enable;
    i.address = c?.enable && c.ipaddr ? c.ipaddr : null;
    i.prefix = c?.enable && c.ipaddr ? c.subnet : null;
    if (i.address && i.prefix !== null) host.routes.push({ dest: networkOf(i.address, i.prefix), dev: i.name, proto: 'kernel', src: i.address });
  }
  const gw = (name: string) => cfg.gateways.find((g) => g.name === name);
  const dev = (ifKey: string) => ifaceOf(cfg, ifKey)?.if;
  const def = cfg.gateways.find((g) => g.defaultgw) ?? cfg.gateways[0];
  if (def && dev(def.interface)) host.routes.push({ dest: 'default', via: def.gateway, dev: dev(def.interface)!, proto: 'static' });
  for (const r of cfg.routes) {
    const g = gw(r.gateway);
    if (g && dev(g.interface)) host.routes.push({ dest: r.network, via: g.gateway, dev: dev(g.interface)!, proto: 'static' });
  }
  recomputeL2(world);
}

export function sysLog(world: World, host: Host, ident: string, message: string): void {
  appendLog(world, host, '/var/log/system.log', `${bsdTime(world.clock)} ${host.hostname} ${ident}[${(world.counter % 90000) + 1000}]: ${message}`);
}

function bsdTime(ms: number): string {
  const d = new Date(ms);
  const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()];
  return `${mon} ${String(d.getUTCDate()).padStart(2, ' ')} ${d.toISOString().slice(11, 19)}`;
}

export function appendLog(world: World, host: Host, path: string, line: string): void {
  const f = host.fs[path];
  const lines = (f?.content ?? '').split('\n').filter(Boolean);
  lines.push(line);
  host.fs[path] = { type: 'file', mode: 0o600, owner: 'root', group: 'wheel', content: lines.slice(-400).join('\n') + '\n', mtime: world.clock };
}

/** filterlog: one CSV line per logged packet in /var/log/filter.log (pfSense 2.7 format). */
export function filterLog(world: World, host: Host, prefix: string, p: { src: string; dst: string; ttl: number; id: number; proto: string; tcp?: { sport: number; dport: number; flags: string[]; seq: number; ack: number; window: number; len: number }; udp?: { sport: number; dport: number; len: number }; icmp?: { type: number; code: number } }, len: number, iif: string | undefined, oif: string | undefined): void {
  const [, tracker, action] = prefix.split('|');
  const dir = iif ? 'in' : 'out';
  const ifname = iif ?? oif ?? '';
  const protoId = p.tcp ? 6 : p.udp ? 17 : 1;
  const base = [tracker === '1000000103' ? '4' : '', '', '', tracker, ifname, 'match', action, dir, '4', '0x0', '', String(p.ttl), String(p.id & 0xffff), '0', 'DF', String(protoId), p.tcp ? 'tcp' : p.udp ? 'udp' : 'icmp', String(len), p.src, p.dst];
  const l4 = p.tcp
    ? [String(p.tcp.sport), String(p.tcp.dport), String(p.tcp.len), p.tcp.flags.map((f) => f[0]).join(''), String(p.tcp.seq), p.tcp.flags.includes('ACK') ? String(p.tcp.ack) : '', String(p.tcp.window), '', 'mss']
    : p.udp ? [String(p.udp.sport), String(p.udp.dport), String(p.udp.len)]
      : [p.icmp?.type === 8 ? 'request' : p.icmp?.type === 0 ? 'reply' : 'unreach', String(p.icmp?.code ?? 0)];
  appendLog(world, host, FILTER_LOG, `${bsdTime(world.clock)} ${host.hostname} filterlog[${(host.nextPid % 9000) + 40000}]: ${[...base, ...l4].join(',')}`);
}

/** Boot: interfaces, routes, services and the filter from config.xml. */
export function bootPfsense(world: World, host: Host, startSsh: (on: boolean) => void): void {
  host.conntrack = [];
  host.nat = [];
  host.neighbors = [];
  host.pmtu = {};
  host.routes6 = [];
  host.ipForward = true;
  host.ip6Forward = false;
  world.clock += 1000;
  host.bootTime = world.clock;
  host.nextPid = 300;
  const rt = (host.pf ??= { enabled: true, ruleset: { tables: [], nextHandle: 1 }, lines: [], lastGood: host.fs[PF_CONFIG]?.content ?? '', loadedAt: 0, errors: [] });
  rt.enabled = true;
  rt.pending = [];
  for (const i of host.ifaces) if (i.name === 'lo0' || i.name === 'lo') { i.up = true; i.address = '127.0.0.1'; i.prefix = 8; }
  let cfg: PfConfig;
  try {
    cfg = readConfig(host);
  } catch (e) {
    // pfSense restores the most recent backup when config.xml cannot be parsed.
    sysLog(world, host, 'php', `XML configuration file could not be parsed (${(e as Error).message}); restoring the last good configuration from /cf/conf/backup.`);
    host.fs[PF_CONFIG] = { ...host.fs[PF_CONFIG], content: rt.lastGood, mtime: world.clock };
    cfg = readConfig(host);
  }
  sysLog(world, host, 'kernel', `FreeBSD 14.0-CURRENT amd64 (pfSense ${PF_VERSION})`);
  applyInterfaces(world, host, cfg);
  startSsh(cfg.sshEnabled);
  filterConfigure(world, host);
  sysLog(world, host, 'php-fpm', '/rc.start_packages: Restarting/Starting all packages.');
}

/** Listening sockets of a pfSense host's own daemons (webConfigurator nginx; sshd comes from the ssh service). */
export function pfListeners(host: Host): { proto: 'tcp' | 'udp'; addr: string; port: number; process: string; pid: number; service: string }[] {
  if (!isPfsense(host)) return [];
  return [80, 443].map((port) => ({ proto: 'tcp' as const, addr: '0.0.0.0', port, process: 'nginx', pid: 375, service: 'webConfigurator' }));
}
