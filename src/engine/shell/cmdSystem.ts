// Service management, logs, firewall, SSH tooling and DNS server tooling.

import {
  emptyRuleset, findChain, NftError, parseRuleExpr, parseRulesetFile, renderChain, renderRuleset,
} from '../config/nft';
import { effectiveConfig, renderSshdT } from '../config/sshdConfig';
import { parseZone, ZoneError } from '../config/zone';
import { readFile, writeFile } from '../fs';
import { formatEntry, isoTime } from '../sim/journal';
import { fingerprintOfBlob, KEY_LABEL, parsePublicKey } from '../sim/keys';
import {
  bootHost, dhcpdTest, findService, parseNginxListens, reloadService, restartService, SERVICE_DEFS, sshdTest, startService, stopService, type SshdLoaded,
} from '../sim/services';
import { dropIns, unitDirectives, unitPath, unitWantedBy } from '../sim/units';
import { knownHostName, knownHostsEntries, runSsh } from '../sim/ssh';
import { resolve } from '../sim/dns';
import { dhcpAcquire, dhcpRelease } from '../sim/dhcp';
import { tcpConnect, ERRNO_TEXT } from '../sim/tcp';
import { base64Decode } from '../util/sha256';
import { resolvePath } from './cmdFiles';
import { type CmdCtx, type CommandDef, err, ok, parseFlags } from './types';
import type { Host, ServiceRuntime } from '../types';

const PERM = (ctx: CmdCtx, msg: string) => (ctx.user.uid !== 0 ? err(msg, 1) : null);

function ago(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}min ago`;
  return `${Math.floor(m / 60)}h ${m % 60}min ago`;
}

function dayTime(ms: number): string {
  const d = new Date(Math.floor(ms));
  return `${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][d.getUTCDay()]} ${isoTime(ms)}`;
}

/** `systemctl list-dependencies`: Requires/Wants of the unit (from its file), plus the implicit default dependencies. */
function dependencyTree(host: Host, name: string, unit: string, reverse: boolean): string[] {
  const dot = (u: string) => {
    const def = SERVICE_DEFS.find((d) => d.unit === u);
    const rt = def && host.services[def.name];
    if (!rt) return '\u25cf';
    return rt.state === 'active' ? '\u25cf' : rt.state === 'failed' ? '\u00d7' : '\u25cb';
  };
  if (reverse) {
    const target = unitWantedBy(name);
    const lines = [unit, `\u25cf \u2514\u2500${target}`];
    if (target === 'multi-user.target') lines.push('\u25cf   \u2514\u2500graphical.target');
    else lines.push('\u25cf   \u2514\u2500basic.target', '\u25cf     \u2514\u2500multi-user.target');
    return lines;
  }
  const dir = unitDirectives(host, name, unit);
  const deps = [...(dir.Requires ?? []), ...(dir.Wants ?? [])];
  const defaultDeps = (dir.DefaultDependencies ?? ['yes'])[0] !== 'no';
  if (defaultDeps) deps.unshift('-.mount', 'system.slice', 'sysinit.target');
  const uniq = [...new Set(deps)].sort((a, b) => a.localeCompare(b));
  const lines = [unit];
  uniq.forEach((d, i) => {
    const last = i === uniq.length - 1;
    lines.push(`${dot(d)} ${last ? '\u2514' : '\u251c'}\u2500${d}`);
    if (d === 'sysinit.target') {
      // Targets are expanded recursively. Only the units the simulator models are listed under sysinit.target.
      const kids = ['systemd-journald.service', 'systemd-sysctl.service', 'systemd-tmpfiles-setup.service', ...(host.services.nftables ? ['nftables.service'] : [])].sort();
      kids.forEach((k, j) => lines.push(`${dot(k)} ${last ? ' ' : '\u2502'} ${j === kids.length - 1 ? '\u2514' : '\u251c'}\u2500${k}`));
    }
  });
  return lines;
}

/** `systemctl show`: a subset of real properties, all derived from the simulated state. */
function showProps(clock: number, host: Host, name: string, unit: string, description: string, rt: ServiceRuntime, prop: string | true | undefined, valueOnly: boolean): string[] {
  const dir = unitDirectives(host, name, unit);
  const def = SERVICE_DEFS.find((d) => d.name === name)!;
  const sub = rt.state === 'active' ? (def.oneshot ? 'exited' : 'running') : rt.state === 'failed' ? 'failed' : 'dead';
  const props: [string, string][] = [
    ['Id', unit],
    ['Names', [unit, ...def.aliases.filter((a) => a.endsWith('.service') && a !== unit)].join(' ')],
    ['Description', description],
    ['LoadState', 'loaded'],
    ['ActiveState', rt.state],
    ['SubState', sub],
    ['Result', rt.result || 'success'],
    ['MainPID', String(rt.state === 'active' && !def.oneshot ? rt.pid ?? 0 : 0)],
    ['ExecMainStatus', rt.state === 'failed' ? '255' : '0'],
    ['Type', (dir.Type ?? ['simple'])[0]],
    ['Restart', (dir.Restart ?? ['no'])[0]],
    ['NRestarts', '0'],
    ['FragmentPath', unitPath(name) ?? ''],
    ['DropInPaths', dropIns(host, unit).join(' ')],
    ['UnitFileState', rt.enabled ? 'enabled' : 'disabled'],
    ['Requires', (dir.Requires ?? []).join(' ')],
    ['Wants', (dir.Wants ?? []).join(' ')],
    ['WantedBy', unitWantedBy(name)],
    ['After', (dir.After ?? []).join(' ')],
    ['Before', (dir.Before ?? []).join(' ')],
    ['StateChangeTimestamp', rt.since ? dayTime(rt.since) + ' UTC' : ''],
    ['ActiveEnterTimestampMonotonic', String(Math.max(0, rt.since - host.bootTime) * 1000)],
  ];
  void clock;
  const wanted = typeof prop === 'string' ? prop.split(',') : null;
  return props.filter(([k]) => !wanted || wanted.includes(k)).map(([k, v]) => (valueOnly ? v : `${k}=${v}`));
}

const systemctl: CommandDef = {
  name: 'systemctl',
  summary: 'control systemd services',
  usage: 'systemctl status|start|stop|restart|reload|enable|disable|is-active|is-enabled|is-failed|cat|show|list-dependencies UNIT | systemctl list-units [--failed] | systemctl --failed',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-p', '--property', '--state']);
    const [verb, ...units] = rest;
    const host = ctx.host;
    const failedOnly = flags.has('--failed') || flags.get('--state') === 'failed';
    if (!verb || verb === 'list-units') {
      const rows: string[][] = [];
      for (const d of SERVICE_DEFS) {
        const rt = host.services[d.name];
        if (!rt) continue;
        if (failedOnly ? rt.state !== 'failed' : rt.state === 'inactive' && !flags.has('--all') && !flags.has('-a')) continue;
        const sub = rt.state === 'active' ? (d.oneshot ? 'exited' : 'running') : rt.state === 'failed' ? 'failed' : 'dead';
        rows.push([rt.state === 'failed' ? '●' : ' ', d.unit, 'loaded', rt.state, sub, d.description]);
      }
      const w = Math.max(4, ...rows.map((r) => r[1].length));
      const lines = [`  ${'UNIT'.padEnd(w)} LOAD   ACTIVE   SUB     DESCRIPTION`];
      for (const r of rows) lines.push(`${r[0]} ${r[1].padEnd(w)} ${r[2]} ${r[3].padEnd(8)} ${r[4].padEnd(7)} ${r[5]}`);
      lines.push('', 'LOAD   = Reflects whether the unit definition was properly loaded.', 'ACTIVE = The high-level unit activation state, i.e. generalization of SUB.', 'SUB    = The low-level unit activation state, values depend on unit type.');
      lines.push(`${rows.length} loaded units listed.${failedOnly ? '' : ' Pass --all to see loaded but inactive units, too.'}`);
      if (!failedOnly) lines.push('To show all installed unit files use \'systemctl list-unit-files\'.');
      lines.push('(The simulator lists the lab\'s modelled services only, not every unit a real system has.)');
      return ok(lines.join('\n'));
    }
    if (verb === 'daemon-reload') return PERM(ctx, 'Failed to reload daemon: Access denied') ?? ok('');
    if (verb === 'reboot') return reboot.run([], ctx);
    if (units.length === 0) return err(`Too few arguments.`, 1);
    const out: string[] = [];
    let code = 0;
    for (const u of units) {
      const def = findService(host, u);
      if (!def) {
        if (verb === 'status') { out.push(`Unit ${u.endsWith('.service') ? u : u + '.service'} could not be found.`); code = 4; continue; }
        if (verb === 'is-active') { out.push('inactive'); code = 3; continue; }
        if (verb === 'is-failed') { out.push('inactive'); code = 1; continue; }
        if (verb === 'cat') { out.push(`No files found for ${u.endsWith('.service') ? u : u + '.service'}.`); code = 1; continue; }
        if (verb === 'list-dependencies') { out.push(`${u.endsWith('.service') ? u : u + '.service'}`); continue; }
        out.push(`Failed to ${verb} ${u}.service: Unit ${u}.service not found.`);
        code = 5;
        continue;
      }
      const rt = host.services[def.name];
      const needRoot = ['start', 'stop', 'restart', 'reload', 'enable', 'disable', 'reload-or-restart', 'try-restart'].includes(verb);
      if (needRoot && ctx.user.uid !== 0) {
        out.push(`Failed to ${verb} ${def.unit}: Access denied`, 'See system logs and \'systemctl status ' + def.unit + '\' for details.');
        code = 1;
        continue;
      }
      switch (verb) {
        case 'status': {
          const icon = rt.state === 'active' ? '●' : rt.state === 'failed' ? '×' : '○';
          const active = rt.state === 'active'
            ? `active (${def.oneshot ? 'exited' : 'running'}) since ${dayTime(rt.since)}; ${ago(ctx.world.clock - rt.since)}`
            : rt.state === 'failed'
              ? `failed (Result: ${rt.result}) since ${dayTime(rt.since)}; ${ago(ctx.world.clock - rt.since)}`
              : rt.since ? `inactive (dead) since ${dayTime(rt.since)}; ${ago(ctx.world.clock - rt.since)}` : 'inactive (dead)';
          out.push(`${icon} ${def.unit} - ${def.description}`);
          const frag = unitPath(def.name) ?? `/lib/systemd/system/${def.unit}`;
          out.push(frag.startsWith('/run/systemd/generator')
            ? `     Loaded: loaded (/etc/init.d/${def.unit.replace(/\.service$/, '')}; generated)`
            : `     Loaded: loaded (${frag}; ${rt.enabled ? 'enabled' : 'disabled'}; preset: enabled)`);
          const drop = dropIns(host, def.unit);
          if (drop.length) out.push(`    Drop-In: /etc/systemd/system/${def.unit}.d`, `             └─${drop.map((d) => d.split('/').pop()).join(', ')}`);
          out.push(`     Active: ${active}`);
          if (def.name === 'ssh') {
            out.push('       Docs: man:sshd(8)', '             man:sshd_config(5)');
            if (rt.state !== 'inactive' || rt.since) out.push(`    Process: ${(rt.pid ?? 500) - 2} ExecStartPre=/usr/sbin/sshd -t (code=exited, status=${rt.state === 'failed' ? '255/EXCEPTION' : '0/SUCCESS'})`);
          }
          if (rt.state === 'active' && !def.oneshot) {
            out.push(`   Main PID: ${rt.pid} (${def.name === 'ssh' ? 'sshd' : def.name})`, '      Tasks: 1 (limit: 2307)', '     Memory: 2.3M', '        CPU: 41ms', `     CGroup: /system.slice/${def.unit}`);
            if (def.statusLines) out.push(...def.statusLines(host, rt));
            else out.push(`             └─${rt.pid} ${def.name}`);
          }
          if (ctx.user.uid === 0 || ctx.user.groups.includes('adm')) {
            const logs = host.journal.filter((e) => e.unit === def.unit).slice(-10);
            if (logs.length) out.push('', ...logs.map(formatEntry));
          } else out.push('', 'Hint: You are currently not seeing messages from other users and the system.', '      Users in groups \'adm\', \'systemd-journal\' can see all messages.');
          if (rt.state !== 'active') code = 3;
          break;
        }
        case 'start':
          if (!startService(ctx.world, host, def)) {
            out.push(`Job for ${def.unit} failed because the control process exited with error code.`, `See "systemctl status ${def.unit}" and "journalctl -xeu ${def.unit}" for details.`);
            code = 1;
          }
          break;
        case 'stop':
          stopService(ctx.world, host, def);
          break;
        case 'restart':
        case 'reload-or-restart':
          if (!restartService(ctx.world, host, def)) {
            out.push(`Job for ${def.unit} failed because the control process exited with error code.`, `See "systemctl status ${def.unit}" and "journalctl -xeu ${def.unit}" for details.`);
            code = 1;
          }
          break;
        case 'reload': {
          const r = reloadService(ctx.world, host, def);
          if (!r.ok) {
            out.push(r.message ?? `Job for ${def.unit} failed.`);
            code = 1;
          }
          break;
        }
        case 'enable':
          if (!rt.enabled) {
            out.push(`Synchronizing state of ${def.unit} with SysV service script with /lib/systemd/systemd-sysv-install.`, `Executing: /lib/systemd/systemd-sysv-install enable ${def.name}`, `Created symlink /etc/systemd/system/multi-user.target.wants/${def.unit} → /lib/systemd/system/${def.unit}.`);
          }
          rt.enabled = true;
          if (flags.has('--now')) startService(ctx.world, host, def);
          break;
        case 'disable':
          if (rt.enabled) out.push(`Removed "/etc/systemd/system/multi-user.target.wants/${def.unit}".`);
          rt.enabled = false;
          if (flags.has('--now')) stopService(ctx.world, host, def);
          break;
        case 'is-active':
          out.push(rt.state === 'active' ? 'active' : rt.state);
          if (rt.state !== 'active') code = 3;
          break;
        case 'is-enabled':
          out.push(rt.enabled ? 'enabled' : 'disabled');
          if (!rt.enabled) code = 1;
          break;
        case 'is-failed':
          out.push(rt.state);
          if (rt.state !== 'failed') code = 1;
          break;
        case 'cat': {
          const files = [unitPath(def.name), ...dropIns(host, def.unit)].filter((p): p is string => !!p && readFile(host, p) !== undefined);
          if (files.length === 0) { out.push(`No files found for ${def.unit}.`); code = 1; break; }
          files.forEach((f, i) => out.push(`${i ? '\n' : ''}# ${f}`, readFile(host, f)!.replace(/\n$/, '')));
          break;
        }
        case 'list-dependencies':
          out.push(...dependencyTree(host, def.name, def.unit, flags.has('--reverse')));
          break;
        case 'show':
          out.push(...showProps(ctx.world.clock, host, def.name, def.unit, def.description, rt, flags.get('-p') ?? flags.get('--property'), flags.has('--value')));
          break;
        default:
          return err(`Unknown command verb ${verb}.`, 1);
      }
    }
    return { out: out.join('\n'), code };
  },
};

const journalctl: CommandDef = {
  name: 'journalctl',
  summary: 'query the systemd journal',
  usage: 'journalctl [-u UNIT] [-t IDENT] [-k] [-b] [-p PRIORITY] [-n N] [-e] [-f] [-x] [-g PATTERN] [--since "N min ago"]',
  run(args, ctx) {
    const { flags } = parseFlags(args, ['-u', '-n', '-p', '-t', '-g', '--since', '--grep', '--unit', '--lines', '--priority', '--identifier']);
    if (ctx.user.uid !== 0 && !ctx.user.groups.includes('adm')) {
      return ok('Hint: You are currently not seeing messages from other users and the system.\n      Users in groups \'adm\', \'systemd-journal\' can see all messages.\n      Pass -q to turn off this notice.\n-- No entries --');
    }
    let entries = ctx.host.journal;
    const unit = (flags.get('-u') ?? flags.get('--unit')) as string | undefined;
    if (unit) {
      const def = findService(ctx.host, unit);
      const name = def?.unit ?? (unit.endsWith('.service') ? unit : unit + '.service');
      entries = entries.filter((e) => e.unit === name);
    }
    const ident = (flags.get('-t') ?? flags.get('--identifier')) as string | undefined;
    if (ident) entries = entries.filter((e) => e.ident === ident);
    if (flags.has('-k') || flags.has('--dmesg')) entries = entries.filter((e) => e.ident === 'kernel');
    if (flags.has('-b')) entries = entries.filter((e) => e.time >= ctx.host.bootTime - 1);
    const prio = (flags.get('-p') ?? flags.get('--priority')) as string | undefined;
    if (prio) {
      const order = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];
      const max = /^\d$/.test(prio) ? Number(prio) : order.indexOf(prio);
      entries = entries.filter((e) => order.indexOf(e.priority) <= max);
    }
    const since = flags.get('--since') as string | undefined;
    if (since) {
      const m = /(\d+)\s*(min|minute|minutes|h|hour|hours|sec|s)\s*ago/.exec(since);
      if (m) {
        const mult = m[2].startsWith('h') ? 3600_000 : m[2].startsWith('s') ? 1000 : 60_000;
        const cutoff = ctx.world.clock - Number(m[1]) * mult;
        entries = entries.filter((e) => e.time >= cutoff);
      }
    }
    const g = (flags.get('-g') ?? flags.get('--grep')) as string | undefined;
    if (g) {
      let re: RegExp;
      try { re = new RegExp(g, 'i'); } catch { return err(`Failed to compile pattern "${g}"`); }
      entries = entries.filter((e) => re.test(e.message));
    }
    const n = flags.get('-n') ?? flags.get('--lines');
    const follow = flags.has('-f') || flags.has('--follow');
    const limit = n !== undefined ? Number(n === true ? 10 : n) : follow ? 10 : flags.has('-e') ? 1000 : 300;
    const shown = entries.slice(-limit);
    const note = follow ? '\n(simulator: -f shows the last entries and returns instead of waiting; run it again after reproducing the problem to see new lines)' : '';
    if (shown.length === 0) return ok('-- No entries --' + note);
    return ok(shown.map(formatEntry).join('\n') + note);
  },
};

// ---------------------------------------------------------------------------
// nftables / iptables
// ---------------------------------------------------------------------------

const nft: CommandDef = {
  name: 'nft',
  summary: 'nftables firewall administration',
  usage: 'nft [-a] list ruleset | nft add|insert rule FAMILY TABLE CHAIN EXPR | nft delete rule FAMILY TABLE CHAIN handle N | nft -f FILE | nft flush ruleset',
  run(args, ctx) {
    const deny = PERM(ctx, 'Operation not permitted (you must be root)');
    if (deny) return deny;
    let a = [...args];
    let withHandle = false;
    let file: string | undefined;
    while (a[0]?.startsWith('-')) {
      const f = a.shift()!;
      if (f === '-a' || f === '--handle') withHandle = true;
      else if (f === '-f' || f === '--file') file = a.shift();
      else if (f === '-c' || f === '--check') { /* syntax check handled with -f */ }
    }
    const host = ctx.host;
    try {
      if (file) {
        const path = resolvePath(ctx, file);
        const text = readFile(host, path);
        if (text === undefined) return err(`Error: Could not process rule: No such file or directory\ninclude "${file}"`, 1);
        const rs = parseRulesetFile(text, path);
        if (!args.includes('-c')) host.nft = rs;
        return ok('');
      }
      const [verb, what, ...rest] = a;
      if (verb === 'list') {
        if (what === 'ruleset') return ok(renderRuleset(host.nft, withHandle));
        if (what === 'chain') {
          const [fam, table, chain] = rest;
          const c = findChain(host.nft, fam, table, chain);
          if (!c) return err(`Error: No such file or directory\nlist chain ${fam} ${table} ${chain}\n${' '.repeat(11)}^^^^^`, 1);
          return ok(`table ${fam} ${table} {\n${renderChain(c, withHandle)}\n}`);
        }
        if (what === 'tables') return ok(host.nft.tables.map((t) => `table ${t.family} ${t.name}`).join('\n'));
        if (what === 'table') {
          const t = host.nft.tables.find((x) => x.family === rest[0] && x.name === rest[1]);
          if (!t) return err('Error: No such file or directory', 1);
          return ok(renderRuleset({ tables: [t], nextHandle: 0 }, withHandle));
        }
      }
      if (verb === 'flush') {
        if (what === 'ruleset') {
          host.nft = emptyRuleset();
          return ok('');
        }
        if (what === 'chain') {
          const c = findChain(host.nft, rest[0], rest[1], rest[2]);
          if (!c) return err('Error: No such file or directory', 1);
          c.rules = [];
          return ok('');
        }
      }
      if ((verb === 'add' || verb === 'insert') && what === 'rule') {
        const [fam, table, chain, ...expr] = rest;
        const c = findChain(host.nft, fam, table, chain);
        if (!c) return err(`Error: No such file or directory; did you mean table 'filter' in family inet?\n${verb} rule ${fam} ${table} ${chain} ${expr.join(' ')}`, 1);
        let pos: number | null = null;
        if (expr[0] === 'position' || expr[0] === 'handle') {
          pos = Number(expr[1]);
          expr.splice(0, 2);
        }
        const rule = parseRuleExpr(expr.join(' '), host.nft.nextHandle++);
        if (pos !== null) {
          const idx = c.rules.findIndex((r) => r.handle === pos);
          if (idx < 0) return err(`Error: Could not process rule: No such file or directory`, 1);
          c.rules.splice(verb === 'add' ? idx + 1 : idx, 0, rule);
        } else if (verb === 'insert') c.rules.unshift(rule);
        else c.rules.push(rule);
        return ok('');
      }
      if (verb === 'delete' && what === 'rule') {
        const [fam, table, chain, h, n] = rest;
        const c = findChain(host.nft, fam, table, chain);
        if (!c) return err('Error: No such file or directory', 1);
        if (h !== 'handle' || !n) return err('Error: syntax error, unexpected newline, expecting handle', 1);
        const idx = c.rules.findIndex((r) => r.handle === Number(n));
        if (idx < 0) return err(`Error: Could not process rule: No such file or directory\ndelete rule ${fam} ${table} ${chain} handle ${n}`, 1);
        c.rules.splice(idx, 1);
        return ok('');
      }
      if (verb === 'chain' || (verb === 'add' && what === 'chain')) {
        // nft chain inet filter input '{ policy accept; }'
        const r = verb === 'chain' ? [what, ...rest] : rest;
        const [fam, table, chain, ...spec] = r;
        const c = findChain(host.nft, fam, table, chain);
        const m = /policy\s+(accept|drop)/.exec(spec.join(' '));
        if (!c || !c.base || !m) return err('Error: Could not process rule: No such file or directory', 1);
        c.base.policy = m[1] as 'accept' | 'drop';
        return ok('');
      }
      return err(`Error: syntax error, unexpected ${verb ?? 'end of file'}`, 1);
    } catch (e) {
      if (e instanceof NftError) return err(`Error: ${e.message.replace(/^.*Error: /, '')}`, 1);
      throw e;
    }
  },
};

const iptables: CommandDef = {
  name: 'iptables',
  summary: 'legacy firewall front-end (iptables-nft on Debian 12)',
  usage: 'iptables -L -n -v',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('iptables v1.8.9 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)', 4);
    if (!args.some((a) => a.startsWith('-L') || a === '-S' || a.includes('L'))) {
      return err('iptables v1.8.9 (nf_tables): this simulator only supports listing (-L / -S). Use nft to change rules.', 2);
    }
    const ipFilter = ctx.host.nft.tables.find((t) => t.family === 'ip' && t.name === 'filter');
    const note = ctx.host.nft.tables.some((t) => t.family === 'inet')
      ? '\n# Note (Infrastructure Lab): this host\'s rules live in the nftables "inet filter" table.\n# iptables-nft only shows tables it created ("ip filter"), so the chains above look empty\n# even though traffic IS being filtered. Use "nft list ruleset".'
      : '';
    if (args.includes('-S')) return ok(`-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT${note}`);
    if (ipFilter) return ok(renderRuleset({ tables: [ipFilter], nextHandle: 0 }));
    const v = args.some((a) => a.includes('v'));
    const hdr = v ? ' pkts bytes target     prot opt in     out     source               destination' : 'target     prot opt source               destination';
    return ok(['Chain INPUT (policy ACCEPT' + (v ? ' 0 packets, 0 bytes' : '') + ')', hdr, '', 'Chain FORWARD (policy ACCEPT' + (v ? ' 0 packets, 0 bytes' : '') + ')', hdr, '', 'Chain OUTPUT (policy ACCEPT' + (v ? ' 0 packets, 0 bytes' : '') + ')', hdr].join('\n') + note);
  },
};

// ---------------------------------------------------------------------------
// SSH tooling
// ---------------------------------------------------------------------------

function parseSshArgs(args: string[]): { opts: Record<string, string>; user?: string; target?: string; port?: number; identity: string[]; verbose: number; command?: string; error?: string } {
  const opts: Record<string, string> = {};
  const identity: string[] = [];
  let verbose = 0;
  let user: string | undefined;
  let port: number | undefined;
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('-')) break;
    if (/^-v+$/.test(a)) { verbose += a.length - 1; continue; }
    const take = () => (a.length > 2 ? a.slice(2) : args[++i]);
    switch (a.slice(0, 2)) {
      case '-p': port = Number(take()); break;
      case '-l': user = take(); break;
      case '-i': identity.push(take()); break;
      case '-o': {
        const [k, v] = take().split('=');
        opts[k.toLowerCase()] = v;
        break;
      }
      case '-4': opts.addressfamily = 'inet'; break;
      case '-6': opts.addressfamily = 'inet6'; break;
      case '-q': case '-t': case '-T': case '-A': case '-X': case '-C': break;
      default: return { opts, identity, verbose, error: `unknown option -- ${a.slice(1)}` };
    }
  }
  let target = args[i];
  const command = args.slice(i + 1).join(' ') || undefined;
  if (target?.includes('@')) {
    const [u, h] = target.split('@');
    user = u;
    target = h;
  }
  if (opts.port) port = Number(opts.port);
  if (opts.user) user = opts.user;
  return { opts, user, target, port, identity, verbose, command };
}

const ssh: CommandDef = {
  name: 'ssh',
  summary: 'OpenSSH client',
  usage: 'ssh [-v] [-p PORT] [-i KEY] [-o Option=value] [user@]host [command]',
  run(args, ctx) {
    const p = parseSshArgs(args);
    if (p.error || !p.target) {
      return err(`${p.error ? p.error + '\n' : ''}usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]\n           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n           destination [command [argument ...]]`, 255);
    }
    const yesno = (v?: string) => (v === undefined ? undefined : v.toLowerCase() === 'yes');
    const answers: string[] = [];
    // Collect answers interactively: runSsh is deterministic, so we re-run it with the
    // answers gathered so far until it either completes or asks the next question.
    for (let guard = 0; guard < 8; guard++) {
      const snapshot = structuredClone(ctx.world);
      const res = runSsh(snapshot, {
        clientHostId: ctx.host.id,
        localUser: ctx.user.name,
        target: p.target,
        user: p.user,
        port: p.port,
        identityFiles: p.identity.map((i) => resolvePath(ctx, i)),
        verbose: p.verbose,
        strictHostKeyChecking: (p.opts.stricthostkeychecking?.toLowerCase() as 'yes' | 'no' | 'ask' | 'accept-new') ?? 'ask',
        batchMode: yesno(p.opts.batchmode),
        connectTimeoutS: p.opts.connecttimeout ? Number(p.opts.connecttimeout) : undefined,
        family: p.opts.addressfamily === 'inet6' ? 6 : p.opts.addressfamily === 'inet' ? 4 : 0,
        pubkeyAuthentication: yesno(p.opts.pubkeyauthentication),
        passwordAuthentication: yesno(p.opts.passwordauthentication),
        answers,
        remoteCommand: p.command,
      });
      if (res.outcome === 'need-input') {
        // Ask the learner; ctx.ask throws NeedInput on the first unanswered question,
        // which the shell turns into a prompt and replays the whole command later.
        answers.push(ctx.ask(res.prompt!.text, res.prompt!.secret, res.lines.join('\n')));
        continue;
      }
      // Commit the simulated world.
      Object.assign(ctx.world, snapshot);
      if (res.outcome === 'session' && res.session) {
        const s = res.session;
        if (p.command) {
          const remote = ctx.run(p.command, `${s.hostId}:${s.user}`, ctx.stdin);
          return { out: [...res.lines, remote.out].filter(Boolean).join('\n'), code: remote.code };
        }
        return {
          out: res.lines.join('\n'),
          code: 0,
          enterSession: {
            hostId: s.hostId,
            user: s.user,
            cwd: ctx.world.hosts[s.hostId].fs[ctx.world.hosts[s.hostId].users[s.user].home] ? ctx.world.hosts[s.hostId].users[s.user].home : '/',
            ssh: { ...s, clientHostId: ctx.host.id, target: p.target },
          },
        };
      }
      return { out: res.lines.join('\n'), code: res.exitCode };
    }
    return err('ssh: too many prompts', 255);
  },
};

const sshKeygen: CommandDef = {
  name: 'ssh-keygen',
  summary: 'inspect keys and manage known_hosts',
  usage: 'ssh-keygen -lf FILE | ssh-keygen -R HOST [-f known_hosts] | ssh-keygen -F HOST',
  run(args, ctx) {
    const { flags } = parseFlags(args, ['-f', '-R', '-F', '-t', '-C', '-N']);
    const file = flags.get('-f') as string | undefined;
    if (flags.has('-l')) {
      if (!file) return err('ssh-keygen: -l requires -f FILE in this simulator', 1);
      const path = resolvePath(ctx, file);
      const node = ctx.host.fs[path] ?? ctx.host.fs[path + '.pub'];
      if (!node) return err(`${file}: No such file or directory`, 255);
      const out: string[] = [];
      for (const line of node.content.split('\n')) {
        const k = parsePublicKey(line.includes('sim-public:') ? line.replace(/^.*sim-public: /, '') : line.replace(/^\S+\s+(?=ssh-|ecdsa-)/, ''));
        if (k) out.push(`${k.bits} ${k.fingerprint} ${k.comment || 'no comment'} (${KEY_LABEL[k.type]})`);
      }
      if (!out.length) return err(`${file} is not a public key file.`, 255);
      return ok(out.join('\n'));
    }
    const khFile = file ? resolvePath(ctx, file) : `${ctx.user.home}/.ssh/known_hosts`;
    if (flags.has('-R')) {
      const hostArg = flags.get('-R') as string;
      const node = ctx.host.fs[khFile];
      if (!node) return err(`do_known_hosts: hostkeys_foreach failed for ${khFile}: No such file or directory`, 255);
      if (node.owner !== ctx.user.name && ctx.user.uid !== 0) return err(`${khFile}: Permission denied`, 255);
      const lines = node.content.split('\n');
      const out: string[] = [];
      const keep = lines.filter((l, i) => {
        const pats = l.split(/\s+/)[0]?.split(',') ?? [];
        const hit = pats.includes(hostArg);
        if (hit) out.push(`# Host ${hostArg} found: line ${i + 1}`);
        return !hit;
      });
      if (!out.length) return ok('');
      writeFile(ctx.host, khFile + '.old', node.content, ctx.world.clock, { mode: 0o600, owner: node.owner, group: node.group });
      writeFile(ctx.host, khFile, keep.join('\n'), ctx.world.clock);
      out.push(`${khFile} updated.`, `Original contents retained as ${khFile}.old`);
      return ok(out.join('\n'));
    }
    if (flags.has('-F')) {
      const hostArg = flags.get('-F') as string;
      const hits = knownHostsEntries(ctx.host, khFile).filter((e) => e.patterns.includes(hostArg));
      if (!hits.length) return err('', 1);
      return ok(hits.map((h) => `# Host ${hostArg} found: line ${h.line} \n${h.patterns.join(',')} ${h.key.alg} ${h.key.blobB64}`).join('\n'));
    }
    return err('ssh-keygen: key generation is not modelled; the lab already provides keys. Supported: -lf, -R, -F', 1);
  },
};

const sshKeyscan: CommandDef = {
  name: 'ssh-keyscan',
  summary: 'fetch a server\'s public host keys over the network',
  usage: 'ssh-keyscan [-p PORT] [-t TYPE] HOST',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-p', '-t']);
    const target = rest[0];
    if (!target) return err('usage: ssh-keyscan [-46cDHv] [-f file] [-p port] [-T timeout] [-t type] [host | addrlist namelist]', 1);
    const port = Number(flags.get('-p') ?? 22);
    const r = resolve(ctx.world, ctx.host, target);
    if (!r.ok) return err(`getaddrinfo ${target}: ${r.message}`, 1);
    const c = tcpConnect(ctx.world, ctx.host, r.ip, port, { timeoutMs: 5000 });
    if (!c.ok) return err(`${target}: ${ERRNO_TEXT[c.errno]}`, 1);
    const loaded = c.conn.server.services.ssh?.loaded as SshdLoaded | null;
    c.conn.close('client');
    if (!loaded) return err(`${target}: Connection closed by remote host`, 1);
    const types = flags.has('-t') ? String(flags.get('-t')).split(',') : ['rsa', 'ecdsa', 'ed25519'];
    const name = knownHostName(target, port);
    const out = [`# ${target}:${port} SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`];
    for (const k of loaded.hostKeys) if (types.includes(k.key.type)) out.push(`${name} ${k.key.alg} ${k.key.blobB64}`);
    return ok(out.join('\n'));
  },
};

const sshCopyId: CommandDef = {
  name: 'ssh-copy-id',
  summary: 'install your public key on a server (needs a working login method, normally a password)',
  usage: 'ssh-copy-id [-i KEY.pub] [user@]host',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-i', '-p']);
    const pubPath = resolvePath(ctx, (flags.get('-i') as string) ?? `${ctx.user.home}/.ssh/id_ed25519.pub`);
    const pubNode = ctx.host.fs[pubPath.endsWith('.pub') ? pubPath : pubPath + '.pub'];
    if (!pubNode) return err(`/usr/bin/ssh-copy-id: ERROR: failed to open ID file '${pubPath}': No such file`, 1);
    const target = rest[0];
    if (!target) return err('Usage: /usr/bin/ssh-copy-id [-h|-?|-f|-n|-s|-x] [-i [identity_file]] [-p port] [-F alternative ssh_config file] [-t target_path] [[-o <ssh -o options>] ...] [user@]hostname', 1);
    const out = [`/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "${pubPath}"`, '/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed'];
    const res = ssh.run(['-o', 'PubkeyAuthentication=no', ...(flags.has('-p') ? ['-p', String(flags.get('-p'))] : []), target, 'mkdir -p .ssh && chmod 700 .ssh && cat >> .ssh/authorized_keys'], { ...ctx, stdin: pubNode.content });
    if (res.code !== 0) return { out: [...out, '/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys', res.out].join('\n'), code: 1 };
    return ok([...out, '/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys', res.out, '', 'Number of key(s) added: 1', '', `Now try logging into the machine, with:   "ssh '${target}'"`, 'and check to make sure that only the key(s) you wanted were added.'].filter((l) => l !== undefined).join('\n'));
  },
};

const sshd: CommandDef = {
  name: 'sshd',
  summary: 'OpenSSH daemon: -t tests the config file, -T prints the effective configuration',
  usage: 'sshd -t | sshd -T [-C user=NAME,addr=IP]',
  run(args, ctx) {
    const deny = PERM(ctx, 'sshd: no hostkeys available -- exiting.');
    if (deny) return deny;
    const { flags } = parseFlags(args, ['-C', '-f']);
    if (flags.has('-t') || flags.has('-T')) {
      const t = sshdTest(ctx.host);
      if (t.errors.length) return err(t.errors.join('\n'), 255);
      if (flags.has('-t')) return ok('');
      const cspec = flags.get('-C') as string | undefined;
      let mctx;
      if (cspec) {
        const kv = Object.fromEntries(cspec.split(',').map((x) => x.split('=')));
        const u = ctx.host.users[kv.user];
        mctx = { user: kv.user ?? '', groups: u ? [u.primaryGroup, ...u.groups] : [], address: kv.addr ?? '0.0.0.0' };
      }
      return ok(renderSshdT(effectiveConfig(t.parsed, mctx)));
    }
    return err('sshd: running the daemon by hand is not supported here; use systemctl. Supported: sshd -t, sshd -T', 1);
  },
};

// ---------------------------------------------------------------------------
// BIND tooling
// ---------------------------------------------------------------------------

const rndc: CommandDef = {
  name: 'rndc',
  summary: 'control the BIND name server (reload zones)',
  usage: 'rndc reload [ZONE] | rndc status',
  run(args, ctx) {
    const deny = PERM(ctx, 'rndc: neither /etc/bind/rndc.conf nor /etc/bind/rndc.key was found');
    if (deny) return deny;
    const def = findService(ctx.host, 'named');
    if (!def) return err('rndc: connect failed: 127.0.0.1#953: connection refused', 1);
    const rt = ctx.host.services.named;
    if (rt.state !== 'active') return err('rndc: connect failed: 127.0.0.1#953: connection refused', 1);
    if (args[0] === 'reload') {
      reloadService(ctx.world, ctx.host, def);
      return ok(args[1] ? 'zone reload queued' : 'server reload successful');
    }
    if (args[0] === 'status') return ok(`version: BIND 9.18.28-1~deb12u2-Debian (Extended Support Version) <id:>\nrunning on ${ctx.host.hostname}: Linux x86_64 6.1.0-26-amd64\nboot time: ${new Date(Math.floor(rt.since)).toUTCString()}\nnumber of zones: ${(rt.loaded as { zones: unknown[] }).zones.length + 101}\nserver is up and running`);
    return err('rndc: unknown command', 1);
  },
};

const namedCheckzone: CommandDef = {
  name: 'named-checkzone',
  summary: 'validate a zone file before loading it',
  usage: 'named-checkzone ZONE FILE',
  run(args, ctx) {
    const [zone, file] = args;
    if (!zone || !file) return err('usage: named-checkzone [-djqvD] [-c class] [-f inputformat] [-F outputformat] [-J filename] [-s (full|relative)] [-t directory] [-w directory] [-k (ignore|warn|fail)] [-m (ignore|warn|fail)] [-n (ignore|warn|fail)] [-r (ignore|warn|fail)] [-i (full|full-sibling|local|local-sibling|none)] [-M (ignore|warn|fail)] [-S (ignore|warn|fail)] [-W (ignore|warn)] [-o filename] zonename [ (filename|-) ]', 1);
    const path = resolvePath(ctx, file);
    const text = readFile(ctx.host, path);
    if (text === undefined) return err(`zone ${zone}/IN: loading from master file ${file} failed: file not found\nzone ${zone}/IN: not loaded due to errors.`, 1);
    try {
      const z = parseZone(text, zone, file);
      return ok(`zone ${zone}/IN: loaded serial ${z.serial}\nOK`);
    } catch (e) {
      const msg = e instanceof ZoneError ? e.message : String(e);
      return err(`dns_master_load: ${msg}\nzone ${zone}/IN: loading from master file ${file} failed: ${msg.split(': ').pop()}\nzone ${zone}/IN: not loaded due to errors.`, 1);
    }
  },
};

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

const nginxCmd: CommandDef = {
  name: 'nginx',
  summary: 'nginx control: -t tests the configuration, -s reload re-reads it',
  usage: 'nginx -t | nginx -s reload',
  run(args, ctx) {
    const deny = PERM(ctx, 'nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" failed (13: Permission denied)');
    if (deny) return deny;
    const def = findService(ctx.host, 'nginx');
    if (!def) return err('-bash: nginx: command not found', 127);
    if (args[0] === '-t') {
      const r = parseNginxListens(readFile(ctx.host, '/etc/nginx/nginx.conf') ?? '');
      if (r.errors.length) return err([...r.errors, 'nginx: configuration file /etc/nginx/nginx.conf test failed'].join('\n'), 1);
      return ok('nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful');
    }
    if (args[0] === '-s' && args[1] === 'reload') {
      if (ctx.host.services.nginx.state !== 'active') return err('nginx: [error] invalid PID number "" in "/run/nginx.pid"', 1);
      const r = reloadService(ctx.world, ctx.host, def);
      return r.ok ? ok('') : err('nginx: [emerg] reload failed, see journalctl -u nginx', 1);
    }
    return err('nginx: this simulator supports -t and -s reload', 1);
  },
};

const dhclient: CommandDef = {
  name: 'dhclient',
  summary: 'DHCP client: obtain (or with -r release) a lease',
  usage: 'dhclient [-v] [-r] [IFACE]',
  run(args, ctx) {
    if (ctx.user.uid !== 0) return err('dhclient: Permission denied (you must be root)', 1);
    const { flags, rest } = parseFlags(args);
    const name = rest[0] ?? ctx.host.ifaces.find((i) => i.name !== 'lo')?.name;
    const iface = ctx.host.ifaces.find((i) => i.name === name);
    if (!iface || iface.name === 'lo') return err(`Cannot find device "${name}"`, 1);
    if (flags.has('-r')) {
      const msg = dhcpRelease(ctx.world, ctx.host, iface);
      return ok(flags.has('-v') ? (msg ?? 'dhclient: no active lease on ' + iface.name) : '');
    }
    iface.up = true;
    const before = ctx.host.journal.length;
    const lease = dhcpAcquire(ctx.world, ctx.host, iface);
    const lines = ctx.host.journal.slice(before).filter((e) => e.ident === 'dhclient').map((e) => e.message);
    if (!lease) return { out: flags.has('-v') ? lines.join('\n') : '', code: 2 };
    return ok(flags.has('-v') ? lines.join('\n') : '');
  },
};

const dhcpdCmd: CommandDef = {
  name: 'dhcpd',
  summary: 'ISC DHCP server: -t tests /etc/dhcp/dhcpd.conf',
  usage: 'dhcpd -t [-cf FILE]',
  run(args, ctx) {
    if (!ctx.host.services.dhcpd) return err('-bash: dhcpd: command not found', 127);
    if (!args.includes('-t')) return err('dhcpd: run the server with systemctl (isc-dhcp-server); this simulator supports dhcpd -t', 1);
    const e = dhcpdTest(ctx.host);
    const head = 'Internet Systems Consortium DHCP Server 4.4.3-P1\nCopyright 2004-2022 Internet Systems Consortium.\nAll rights reserved.';
    return e.length ? err(`${head}\n${e.join('\n')}`, 1) : ok(head);
  },
};

const reboot: CommandDef = {
  name: 'reboot',
  summary: 'reboot the machine (runtime state is rebuilt from configuration files)',
  usage: 'reboot',
  run(_args, ctx) {
    const deny = PERM(ctx, 'Call to Reboot failed: Access denied');
    if (deny) return deny;
    ctx.world.sessions = (ctx.world.sessions ?? []).filter((s) => s.serverHostId !== ctx.host.id && s.clientHostId !== ctx.host.id);
    bootHost(ctx.world, ctx.host);
    ctx.world.clock += 25_000;
    const failed = Object.entries(ctx.host.services).filter(([, rt]) => rt.state === 'failed').map(([n]) => n);
    return ok([
      `[ simulated reboot of ${ctx.host.hostname} ]`,
      'Runtime state (addresses, routes, loaded firewall rules, running services, ARP and conntrack tables) was discarded and rebuilt from the persistent configuration files and enabled services.',
      failed.length ? `Units that failed during boot: ${failed.join(', ')}` : 'All enabled units started.',
    ].join('\n'));
  },
};

export const SYSTEM_COMMANDS: CommandDef[] = [systemctl, journalctl, nft, iptables, ssh, sshKeygen, sshKeyscan, sshCopyId, sshd, rndc, namedCheckzone, nginxCmd, dhclient, dhcpdCmd, reboot];
export { fingerprintOfBlob, base64Decode };
