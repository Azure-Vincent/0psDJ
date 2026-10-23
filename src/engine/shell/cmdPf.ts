// The pfSense console (menu option 8, "Shell"): FreeBSD tools and pfSense's
// own scripts. pfctl shows and controls pf (rules with counters, NAT, states,
// tables), easyrule adds rules from the command line, viconfig edits
// config.xml, and /etc/rc.filter_configure regenerates and loads the ruleset
// from it. ifconfig, netstat, sockstat and ping print FreeBSD's formats.
// Linux tools do not exist here ("Command not found.").

import { networkOf } from '../net/ip';
import { ifaceOf, newTracker, PF_CONFIG, type PfConfig } from '../pf/config';
import { applyInterfaces, filterConfigure, PF_VERSION, readConfig, RULES_DEBUG, writeConfig } from '../pf/model';
import { allListeners, serviceDef, startService, stopService } from '../sim/services';
import { echo } from '../win/ps/netops';
import { resolve } from '../sim/dns';
import { type CmdCtx, type CmdResult, type CommandDef, err, ok } from './types';

/** Linux tools that a FreeBSD/pfSense shell does not have. */
export const LINUX_ONLY = new Set([
  'ip', 'ss', 'systemctl', 'journalctl', 'nft', 'apt', 'apt-get', 'ifup', 'ifdown', 'ifreload', 'ifquery', 'bridge', 'dhclient', 'timedatectl', 'hostnamectl',
  'ethtool', 'conntrack', 'iptables', 'nmcli', 'resolvectl', 'networkctl', 'tracepath', 'rdisc6', 'update-ca-certificates', 'named-checkzone', 'named-checkconf', 'rndc', 'dhcpd', 'useradd', 'usermod',
]);

const root = (ctx: CmdCtx) => ctx.user.uid === 0;
const freebsdName = (n: string) => (n === 'lo' ? 'lo0' : n);
const prefixToHex = (p: number) => `0x${(p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0).toString(16).padStart(8, '0')}`;

function cfgOrError(ctx: CmdCtx): { cfg?: PfConfig; error?: CmdResult } {
  try {
    return { cfg: readConfig(ctx.host) };
  } catch (e) {
    return { error: err(`${(e as Error).message}`, 1) };
  }
}

function applySsh(ctx: CmdCtx, on: boolean): void {
  const def = serviceDef('ssh')!;
  const rt = ctx.host.services.ssh;
  if (!rt) return;
  rt.enabled = on;
  if (on && rt.state !== 'active') startService(ctx.world, ctx.host, def);
  if (!on && rt.state === 'active') stopService(ctx.world, ctx.host, def);
}

function loadFilter(ctx: CmdCtx): CmdResult {
  const r = filterConfigure(ctx.world, ctx.host);
  if (r.ok) return ok('');
  return err(r.errors[0].startsWith('XML error') ? r.errors[0] : `There were error(s) loading the rules: ${r.errors.join('\n')}`, 1);
}

// ---------------------------------------------------------------------------
// pfctl
// ---------------------------------------------------------------------------

function stateLines(ctx: CmdCtx): string[] {
  const h = ctx.host;
  const out: string[] = [];
  for (const c of h.conntrack) {
    const nat = h.nat.find((n) => n.proto === c.proto && ((n.orig.src === c.src && n.orig.sport === c.sport) || (n.trans.src === c.src && n.trans.sport === c.sport)));
    const st = c.proto === 'tcp' ? (c.state === 'ESTABLISHED' ? 'ESTABLISHED:ESTABLISHED' : c.state === 'SYN_SENT' ? 'SYN_SENT:CLOSED' : 'FIN_WAIT_2:FIN_WAIT_2') : c.proto === 'udp' ? 'MULTIPLE:SINGLE' : '0:0';
    if (nat && nat.kind.includes('dnat')) out.push(`all ${c.proto} ${nat.trans.dst}:${nat.trans.dport} (${nat.orig.dst}:${nat.orig.dport}) <- ${c.src}:${c.sport}       ${st}`);
    else if (nat) out.push(`all ${c.proto} ${nat.orig.src}:${nat.orig.sport} (${nat.trans.src}:${nat.trans.sport}) -> ${c.dst}:${c.dport}       ${st}`);
    else out.push(`all ${c.proto} ${c.dst}:${c.dport} <- ${c.src}:${c.sport}       ${st}`);
  }
  return out;
}

const pfctl: CommandDef = {
  name: 'pfctl',
  summary: 'control pf: -sr rules, -sn NAT, -ss states, -si info, -vvsr counters, -d/-e, -F states, -k host, -t TABLE -T show',
  usage: 'pfctl [-vv] -s rules|nat|states|info|all | -d | -e | -F states | -k HOST | -t TABLE -T show | -f /tmp/rules.debug',
  run(args, ctx) {
    if (!root(ctx)) return err('pfctl: /dev/pf: Permission denied', 1);
    const rt = ctx.host.pf!;
    const joined = args.join(' ');
    const verbose = /-v/.test(joined.replace(/-vv?s/, (m) => m.replace('s', ''))) || args.some((a) => /^-v+/.test(a));
    const showArg = (() => {
      for (let i = 0; i < args.length; i++) {
        const m = /^-v*s(\w*)$/.exec(args[i]);
        if (m) return m[1] || args[i + 1] || '';
      }
      return null;
    })();
    if (args.includes('-d')) {
      if (!rt.enabled) return err('pfctl: pf not enabled', 1);
      rt.enabled = false;
      ctx.host.nft = { tables: [], nextHandle: 1 };
      return ok('pf disabled');
    }
    if (args.includes('-e')) {
      if (rt.enabled) return err('pfctl: pf already enabled', 1);
      rt.enabled = true;
      ctx.host.nft = rt.ruleset;
      return ok('pf enabled');
    }
    if (args.includes('-f')) return loadFilter(ctx);
    const fi = args.indexOf('-F');
    if (fi >= 0) {
      const what = args[fi + 1] ?? '';
      if (what === 'states' || what === 'all') {
        const n = ctx.host.conntrack.length;
        ctx.host.conntrack = [];
        ctx.host.nat = [];
        return ok(`${n} states cleared`);
      }
      return err(`pfctl: Unknown flush modifier '${what}'`, 1);
    }
    const ki = args.indexOf('-k');
    if (ki >= 0) {
      const target = args[ki + 1] ?? '';
      const before = ctx.host.conntrack.length;
      ctx.host.conntrack = ctx.host.conntrack.filter((c) => c.src !== target);
      ctx.host.nat = ctx.host.nat.filter((n) => n.orig.src !== target);
      return ok(`killed ${before - ctx.host.conntrack.length} states from 1 sources and 0 destinations`);
    }
    const ti = args.indexOf('-t');
    if (ti >= 0) {
      const name = args[ti + 1] ?? '';
      const { cfg, error } = cfgOrError(ctx);
      if (error) return error;
      const a = cfg!.aliases.find((x) => x.name === name && x.type !== 'port');
      if (!a) return err('pfctl: Table does not exist.', 1);
      return ok(a.address.map((x) => `   ${x}`).join('\n'));
    }
    if (showArg === null) return err('usage: pfctl [-AdeghMmNnOPqRrvz] [-a anchor] [-D macro=value] [-F modifier]\n\t[-f file] [-i interface] [-K host | network]\n\t[-k host | network | gateway | label | id] [-o level] [-p device]\n\t[-s modifier] [-t table -T command [address ...]] [-x level]', 64);
    const what = showArg.toLowerCase();
    const counters = (handles: number[]) => {
      const rules = rt.ruleset.tables.flatMap((t) => t.chains.flatMap((c) => c.rules)).filter((r) => handles.includes(r.handle));
      const p = rules.reduce((n, r) => n + (r.counter?.packets ?? 0), 0);
      const b = rules.reduce((n, r) => n + (r.counter?.bytes ?? 0), 0);
      return `  [ Evaluations: ${p * 2 + 3}  Packets: ${p}  Bytes: ${b}  States: ${Math.min(p, ctx.host.conntrack.length)} ]\n  [ Inserted: uid 0 pid ${ctx.host.nextPid % 90000} State Creations: ${p} ]`;
    };
    const lines = (section: 'filter' | 'nat') => rt.lines.filter((l) => l.section === section).flatMap((l) => (verbose ? [`@${rt.lines.indexOf(l)} ${l.text}`, counters(l.handles)] : [l.text]));
    if (what === 'rules' || what === 'r') return ok(['scrub on vtnet0 all fragment reassemble', ...lines('filter')].join('\n'));
    if (what === 'nat' || what === 'n') return ok(lines('nat').join('\n'));
    if (what === 'states' || what === 's') return ok(stateLines(ctx).join('\n'));
    const info = () => {
      const up = Math.floor((ctx.world.clock - (rt.loadedAt || ctx.host.bootTime)) / 1000);
      const t = `${Math.floor(up / 86400)} days ${new Date(up * 1000).toISOString().slice(11, 19)}`;
      const total = rt.ruleset.tables.flatMap((x) => x.chains.flatMap((c) => c.rules)).reduce((n, r) => n + (r.counter?.packets ?? 0), 0);
      return [`Status: ${rt.enabled ? 'Enabled' : 'Disabled'} for ${t}           Debug: Urgent`, '', 'State Table                          Total             Rate', `  current entries                     ${String(ctx.host.conntrack.length).padStart(4)}`, `  searches                          ${String(total * 3).padStart(6)}            0.1/s`, `  inserts                           ${String(ctx.host.conntrack.length).padStart(6)}            0.0/s`, 'Counters', `  match                             ${String(total).padStart(6)}            0.0/s`, '  bad-offset                             0            0.0/s', '  fragment                               0            0.0/s', '  short                                  0            0.0/s', '  normalize                              0            0.0/s', '  memory                                 0            0.0/s'].join('\n');
    };
    if (what === 'info' || what === 'i') return ok(info());
    if (what === 'all' || what === 'a') return ok(['FILTER RULES:', 'scrub on vtnet0 all fragment reassemble', ...lines('filter'), '', 'TRANSLATION RULES:', ...lines('nat'), '', 'STATES:', ...stateLines(ctx), '', 'INFO:', info()].join('\n'));
    if (what === 'tables' || what === 't') {
      const { cfg } = cfgOrError(ctx);
      return ok(['sshguard', ...(cfg?.aliases.filter((a) => a.type !== 'port').map((a) => a.name) ?? [])].sort().join('\n'));
    }
    return err(`pfctl: Unknown show modifier '${showArg}'`, 1);
  },
};

// ---------------------------------------------------------------------------
// pfSense scripts
// ---------------------------------------------------------------------------

const filterConfigureCmd: CommandDef = {
  name: '/etc/rc.filter_configure',
  summary: 'regenerate the pf ruleset from config.xml and load it (rules, aliases, NAT)',
  usage: '/etc/rc.filter_configure',
  run(_args, ctx) {
    if (!root(ctx)) return err('/etc/rc.filter_configure: Permission denied.', 1);
    return loadFilter(ctx);
  },
};

const reloadAll: CommandDef = {
  name: '/etc/rc.reload_all',
  summary: 'reapply everything in config.xml: interfaces, routes, services and the filter',
  usage: '/etc/rc.reload_all',
  run(_args, ctx) {
    if (!root(ctx)) return err('/etc/rc.reload_all: Permission denied.', 1);
    const { cfg, error } = cfgOrError(ctx);
    if (error) return error;
    applyInterfaces(ctx.world, ctx.host, cfg!);
    applySsh(ctx, cfg!.sshEnabled);
    return loadFilter(ctx);
  },
};

const viconfig: CommandDef = {
  name: 'viconfig',
  summary: 'edit /conf/config.xml (then apply with /etc/rc.filter_configure or /etc/rc.reload_all)',
  usage: 'viconfig',
  run(_args, ctx) {
    if (!root(ctx)) return err('viconfig: Permission denied.', 1);
    const n = ctx.host.fs[PF_CONFIG];
    return { out: '', code: 0, editor: { hostId: ctx.host.id, user: ctx.user.name, path: PF_CONFIG, content: n?.content ?? '', readOnly: false, isNew: !n } };
  },
};

const EASY_USAGE = 'Usage: easyrule <action> [options]\n\n  block <interface> <source IP>\n  pass <interface> <protocol> <source IP> <destination ip> [destination port]\n  unblock <interface> <source IP>\n  showblock <interface>';

const easyrule: CommandDef = {
  name: 'easyrule',
  summary: 'add a block or pass rule from the shell: easyrule block wan 198.51.100.7, easyrule pass wan tcp any 172.16.50.10 80',
  usage: 'easyrule block|unblock|showblock|pass ...',
  run(args, ctx) {
    if (!root(ctx)) return err('easyrule: Permission denied.', 1);
    const [action, ifArg, ...rest] = args;
    if (!action || !ifArg) return err(EASY_USAGE, 1);
    const { cfg, error } = cfgOrError(ctx);
    if (error) return error;
    const c = cfg!;
    const iface = ifaceOf(c, ifArg);
    if (!iface) return err(`Invalid interface for ${action} rule: ${ifArg}`, 1);
    const aliasName = `EasyRuleBlockHosts${iface.descr.toUpperCase()}`;
    const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s);
    if (action === 'block' || action === 'unblock' || action === 'showblock') {
      let alias = c.aliases.find((a) => a.name === aliasName);
      if (action === 'showblock') return ok(alias?.address.join('\n') ?? '');
      const ip = rest[0];
      if (!ip || !isIp(ip)) return err(`Tried to ${action} invalid IP: ${ip ?? ''}`, 1);
      const entry = ip.includes('/') ? ip : `${ip}/32`;
      if (action === 'unblock') {
        if (!alias?.address.includes(entry)) return err(`Host is not on the block list: ${ip}`, 1);
        alias.address = alias.address.filter((a) => a !== entry);
        writeConfig(ctx.world, ctx.host, c);
        loadFilter(ctx);
        return ok(`Host unblocked successfully`);
      }
      if (!alias) {
        alias = { name: aliasName, type: 'network', address: [], descr: 'Hosts blocked from Firewall Log view' };
        c.aliases.push(alias);
      }
      if (!alias.address.includes(entry)) alias.address.push(entry);
      if (!c.filter.some((r) => r.interface === iface.key && r.source.address === aliasName)) {
        const first = c.filter.findIndex((r) => r.interface === iface.key);
        const rule = { tracker: newTracker(c, ctx.world.clock), type: 'block' as const, interface: iface.key, source: { address: aliasName }, destination: { any: true }, descr: `Easy Rule: Blocked from Firewall Log View`, disabled: false, log: false };
        c.filter.splice(first < 0 ? c.filter.length : first, 0, rule);
      }
      writeConfig(ctx.world, ctx.host, c);
      const r = loadFilter(ctx);
      return r.code ? r : ok('Block added successfully');
    }
    if (action === 'pass') {
      const [proto, src, dst, port] = rest;
      if (!proto || !src || !dst) return err(EASY_USAGE, 1);
      if (!['tcp', 'udp', 'icmp', 'tcp/udp', 'any'].includes(proto)) return err(`Invalid protocol for pass rule: ${proto}`, 1);
      if (src !== 'any' && !isIp(src)) return err(`Tried to pass invalid source IP: ${src}`, 1);
      if (dst !== 'any' && !isIp(dst)) return err(`Tried to pass invalid destination IP: ${dst}`, 1);
      if (port && !/^\d+(-\d+)?$/.test(port)) return err(`Tried to pass invalid destination port: ${port}`, 1);
      const rule = {
        tracker: newTracker(c, ctx.world.clock), type: 'pass' as const, interface: iface.key, protocol: proto === 'any' ? undefined : proto,
        source: src === 'any' ? { any: true } : { address: src }, destination: dst === 'any' ? { any: true, ...(port ? { port } : {}) } : { address: dst, ...(port ? { port } : {}) },
        descr: 'Easy Rule: Passed from Firewall Log View', disabled: false, log: false,
      };
      const first = c.filter.findIndex((r) => r.interface === iface.key);
      c.filter.splice(first < 0 ? c.filter.length : first, 0, rule);
      writeConfig(ctx.world, ctx.host, c);
      const r = loadFilter(ctx);
      return r.code ? r : ok('Successfully added pass rule!');
    }
    return err(EASY_USAGE, 1);
  },
};

// ---------------------------------------------------------------------------
// FreeBSD networking tools
// ---------------------------------------------------------------------------

const ifconfig: CommandDef = {
  name: 'ifconfig',
  summary: 'show network interfaces (FreeBSD format)',
  usage: 'ifconfig [INTERFACE]',
  run(args, ctx) {
    const h = ctx.host;
    const { cfg } = cfgOrError(ctx);
    const want = args.find((a) => !a.startsWith('-'));
    const list = h.ifaces.filter((i) => !want || freebsdName(i.name) === want);
    if (want && !list.length) return err(`ifconfig: interface ${want} does not exist`, 1);
    const out: string[] = [];
    for (const i of list) {
      const lo = i.name === 'lo';
      const descr = cfg?.interfaces.find((x) => x.if === i.name)?.descr;
      const flags = lo ? '1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP>' : i.up ? '1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP>' : '8802<BROADCAST,SIMPLEX,MULTICAST>';
      out.push(`${freebsdName(i.name)}: flags=${flags} metric 0 mtu ${lo ? 16384 : i.mtu ?? 1500}`);
      if (descr) out.push(`\tdescription: ${descr}`);
      if (!lo) out.push('\toptions=4c079b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM,TSO4,TSO6,LRO,VLAN_HWTSO,LINKSTATE,TXCSUM_IPV6>', `\tether ${i.mac}`);
      if (i.address && i.prefix !== null) {
        const bcast = i.prefix < 32 && !lo ? ` broadcast ${networkOf(i.address, i.prefix).split('/')[0].split('.').map((o, k) => (k === 3 ? String(Number(o) + 2 ** (32 - i.prefix!) - 1) : o)).join('.')}` : '';
        out.push(`\tinet ${i.address} netmask ${prefixToHex(i.prefix)}${bcast}`);
      }
      if (lo) out.push('\tinet6 ::1 prefixlen 128', '\tgroups: lo');
      else out.push('\tmedia: Ethernet autoselect (10Gbase-T <full-duplex>)', `\tstatus: ${i.up && i.segment ? 'active' : 'no carrier'}`, '\tnd6 options=21<PERFORMNUD,AUTO_LINKLOCAL>');
    }
    return ok(out.join('\n'));
  },
};

const netstat: CommandDef = {
  name: 'netstat',
  summary: 'routing table (-rn) and sockets (-an), FreeBSD format',
  usage: 'netstat -rn | -an',
  run(args, ctx) {
    const f = args.join('');
    const h = ctx.host;
    if (f.includes('r')) {
      const out = ['Routing tables', '', 'Internet:', 'Destination        Gateway            Flags     Netif Expire'];
      const idx = (dev: string) => h.ifaces.findIndex((i) => i.name === dev) + 1;
      for (const r of h.routes.filter((x) => x.dest === 'default')) out.push(`${'default'.padEnd(19)}${(r.via ?? '').padEnd(19)}${'UGS'.padEnd(10)}${r.dev.padStart(5)}`);
      for (const r of h.routes.filter((x) => x.dest !== 'default')) {
        out.push(`${r.dest.padEnd(19)}${(r.via ?? `link#${idx(r.dev)}`).padEnd(19)}${(r.via ? 'UGS' : 'U').padEnd(10)}${r.dev.padStart(5)}`);
        if (!r.via && r.src) out.push(`${r.src.padEnd(19)}${`link#${idx(r.dev)}`.padEnd(19)}${'UHS'.padEnd(10)}${'lo0'.padStart(5)}`);
      }
      out.push(`${'127.0.0.1'.padEnd(19)}${'link#1'.padEnd(19)}${'UH'.padEnd(10)}${'lo0'.padStart(5)}`);
      return ok(out.join('\n'));
    }
    if (f.includes('a')) {
      const out = ['Active Internet connections (including servers)', 'Proto Recv-Q Send-Q Local Address          Foreign Address        (state)'];
      for (const l of allListeners(h)) out.push(`${(l.proto + '4').padEnd(6)}${'0'.padStart(6)} ${'0'.padStart(6)} ${`*.${l.port}`.padEnd(23)}${'*.*'.padEnd(23)}${l.proto === 'tcp' ? 'LISTEN' : ''}`);
      return ok(out.join('\n'));
    }
    return err('usage: netstat [-46AaLnRSTWx] [-f protocol_family | -p protocol]\n               [-M core] [-N system]\n       netstat -i | -I interface [-46abdhnW] [-f address_family]\n       netstat -r [-46AnW] [-F fibnum] [-f address_family]', 64);
  },
};

const sockstat: CommandDef = {
  name: 'sockstat',
  summary: 'listening sockets with their processes (-4l)',
  usage: 'sockstat -4l',
  run(_args, ctx) {
    const out = ['USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS'];
    for (const l of allListeners(ctx.host).filter((x) => !x.addr.includes(':'))) out.push(`root     ${l.process.slice(0, 10).padEnd(11)}${String(l.pid).padEnd(6)}${'6'.padEnd(4)}${(l.proto + '4').padEnd(7)}${`*:${l.port}`.padEnd(22)}*:*`);
    return ok(out.join('\n'));
  },
};

const ping: CommandDef = {
  name: 'ping',
  summary: 'send ICMP echo requests (FreeBSD: -c COUNT, -S SOURCE)',
  usage: 'ping [-c COUNT] HOST',
  run(args, ctx) {
    let count = 0;
    let target: string | undefined;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '-c') count = Number(args[++i]);
      else if (args[i] === '-S' || args[i] === '-t' || args[i] === '-W' || args[i] === '-i') i++;
      else if (!args[i].startsWith('-')) target = args[i];
    }
    if (!target) return err('usage: ping [-4AaDdfHnoQqRrv] [-C pcp] [-c count] [-G sweepmaxsize]\n            [-g sweepminsize] [-h sweepincrsize] [-i wait] [-l preload]\n            [-M mask | time] [-m ttl] [-p pattern] [-S src_addr]\n            [-s packetsize] [-t timeout] [-W waittime] [-z tos]\n            IPv4-host', 64);
    const r = resolve(ctx.world, ctx.host, target, { family: 4 });
    if (!r.ok) return err(`ping: cannot resolve ${target}: Unknown host`, 68);
    const n = count > 0 ? Math.min(count, 10) : 4;
    const out = [`PING ${target} (${r.ip}): 56 data bytes`];
    let got = 0;
    const times: number[] = [];
    for (let seq = 0; seq < n; seq++) {
      const start = ctx.world.clock;
      const e = echo(ctx.world, ctx.host, r.ip, 56, seq + 1, undefined, 10_000);
      if (e.kind === 'reply') { got++; const t = e.ms + 0.312; times.push(t); out.push(`64 bytes from ${r.ip}: icmp_seq=${seq} ttl=${e.ttl} time=${t.toFixed(3)} ms`); }
      else if (e.kind === 'unreachable') out.push(`92 bytes from ${e.from}: ${e.text.replace(/\.$/, '')}`);
      else if (e.kind === 'local') { return err(`ping: sendto: ${/unreach/.test(e.text) ? 'No route to host' : 'Network is unreachable'}`, 2); }
      else out.push(`Request timeout for icmp_seq ${seq}`);
      ctx.world.clock = Math.max(ctx.world.clock, start + 1000);
    }
    if (!count) out.push('^C');
    out.push('', `--- ${target} ping statistics ---`, `${n} packets transmitted, ${got} packets received, ${(((n - got) / n) * 100).toFixed(1)}% packet loss`);
    if (times.length) {
      const min = Math.min(...times), max = Math.max(...times), avg = times.reduce((a, b) => a + b, 0) / times.length;
      out.push(`round-trip min/avg/max/stddev = ${min.toFixed(3)}/${avg.toFixed(3)}/${max.toFixed(3)}/${((max - min) / 2).toFixed(3)} ms`);
    }
    return { out: out.join('\n'), code: got ? 0 : 2 };
  },
};

const uname: CommandDef = {
  name: 'uname', summary: 'system name', usage: 'uname [-a]',
  run(args, ctx) {
    return ok(args.includes('-a') ? `FreeBSD ${ctx.host.hostname}.${ctx.host.domain} 14.0-CURRENT FreeBSD 14.0-CURRENT amd64 1400094 #1 RELENG_2_7_2-n255948-8d2b56da39c: Wed Dec  6 20:45:47 UTC 2023     root@freebsd:/var/jenkins/workspace/pfSense-CE-snapshots-2_7_2-main/obj/amd64/StdASW5b/var/jenkins/workspace/pfSense-CE-snapshots-2_7_2-main/sources/FreeBSD-src-RELENG_2_7_2/amd64.amd64/sys/pfSense amd64` : 'FreeBSD');
  },
};

const hostname: CommandDef = { name: 'hostname', summary: 'host name', usage: 'hostname', run: (_a, ctx) => ok(`${ctx.host.hostname}.${ctx.host.domain}`) };

/** Commands that differ on a pfSense host (looked up before the Linux ones). */
export const PF_COMMANDS: Record<string, CommandDef> = Object.fromEntries(
  [pfctl, filterConfigureCmd, reloadAll, viconfig, easyrule, ifconfig, netstat, sockstat, ping, uname, hostname].flatMap((c) => [[c.name, c], ...(c.name.startsWith('/etc/') ? [[c.name.slice(5), c]] : [])]),
);

export { RULES_DEBUG, PF_VERSION };
