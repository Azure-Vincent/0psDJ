// MIT Kerberos client tools (krb5-user) and the KDC's kadmin.local, plus the
// clock tools (date, timedatectl) that Kerberos depends on.

import { cachePath, formatKeytab, parseKdcConf, parseKeytab, qualify, realmOf, type KeytabEntry } from '../config/krb5';
import { readFile } from '../fs';
import {
  clientConf, defaultRealm, getInitialCreds, getServiceTicket, hostTime, kadminRemote, kadminRequest, KrbError, readCache, writeCache, type KadminResult,
} from '../sim/kerberos';
import { log } from '../sim/journal';
import { serviceDef, startService, stopService } from '../sim/services';
import { getFile, writeChecked } from './cmdFiles';
import { tokenizeLine } from './tokenize';
import { type CmdCtx, type CommandDef, err, ok } from './types';

const KEYTAB = '/etc/krb5.keytab';

function fqdn(ctx: CmdCtx): string {
  return `${ctx.host.hostname}.${ctx.host.domain}`.toLowerCase();
}

/** "10/19/2026 08:30:12" (klist uses the locale's short date and time). */
function klistTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())}/${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function krbFail(cmd: string, e: unknown, while_: string): ReturnType<CommandDef['run']> {
  if (e instanceof KrbError) return err(`${cmd}: ${e.message} ${while_}`, 1);
  throw e;
}

function readKeytab(ctx: CmdCtx, path: string): { entries?: KeytabEntry[]; error?: string } {
  const f = getFile(ctx, path);
  if (f.error === 'Permission denied') return { error: 'Permission denied' };
  if (f.error || f.content === undefined) return { error: `Key table file '${path}' not found` };
  return { entries: parseKeytab(f.content) ?? [] };
}

const kinit: CommandDef = {
  name: 'kinit',
  summary: 'obtain a Kerberos ticket-granting ticket (password or keytab)',
  usage: 'kinit [-k [-t KEYTAB]] [PRINCIPAL]',
  run(args, ctx) {
    const useKeytab = args.includes('-k');
    const tIdx = args.indexOf('-t');
    const keytabPath = tIdx >= 0 ? (args[tIdx + 1] ?? '').replace(/^FILE:/, '') : KEYTAB;
    const name = args.filter((a, i) => !a.startsWith('-') && args[i - 1] !== '-t')[0];
    let principal: string;
    try {
      const conf = clientConf(ctx.host);
      const dflt = useKeytab && !name ? `host/${fqdn(ctx)}` : name ?? ctx.user.name;
      if (!dflt.includes('@') && !conf.defaultRealm) return err(`kinit: Configuration file does not specify default realm when parsing name ${dflt}`, 1);
      principal = dflt.includes('@') ? dflt : qualify(dflt, defaultRealm(conf));
    } catch (e) {
      return krbFail('kinit', e, 'while initializing Kerberos 5 library');
    }
    let keytabEntry: KeytabEntry | undefined;
    if (useKeytab) {
      const kt = readKeytab(ctx, keytabPath);
      if (kt.error) return err(`kinit: ${kt.error} while getting initial credentials`, 1);
      keytabEntry = kt.entries!.filter((e) => e.principal === principal).sort((a, b) => b.kvno - a.kvno)[0];
      if (!keytabEntry) return err(`kinit: Keytab contains no suitable keys for ${principal} while getting initial credentials`, 1);
    }
    try {
      const tgt = getInitialCreds(ctx.world, ctx.host, principal, keytabEntry ? { keytab: keytabEntry } : { password: () => ctx.ask(`Password for ${principal}: `, true) });
      writeCache(ctx.world, ctx.host, ctx.user.uid, ctx.user.name, ctx.user.primaryGroup, { principal, tickets: [tgt] });
      return ok('');
    } catch (e) {
      return krbFail('kinit', e, 'while getting initial credentials');
    }
  },
};

const klist: CommandDef = {
  name: 'klist',
  summary: 'list Kerberos tickets in the credential cache, or keys in a keytab (-k)',
  usage: 'klist [-k [-t] [-e] [KEYTAB]]',
  run(args, ctx) {
    if (args.includes('-k') || args.some((a) => /^-k[te]+$/.test(a))) {
      const flags = args.filter((a) => a.startsWith('-')).join('');
      const path = (args.find((a) => !a.startsWith('-')) ?? KEYTAB).replace(/^FILE:/, '');
      const kt = readKeytab(ctx, path);
      if (kt.error) return err(`klist: ${kt.error} while starting keytab scan`, 1);
      const withTime = flags.includes('t');
      const withEnc = flags.includes('e');
      const out = [`Keytab name: FILE:${path}`, withTime ? 'KVNO Timestamp           Principal' : 'KVNO Principal', withTime ? '---- ------------------- ------------------------------------------------------' : '---- --------------------------------------------------------------------------'];
      for (const e of kt.entries!) out.push(`${String(e.kvno).padStart(4)} ${withTime ? klistTime(e.timestamp) + ' ' : ''}${e.principal}${withEnc ? ` (${e.enctype}) ` : ''}`);
      return ok(out.join('\n'));
    }
    const path = cachePath(ctx.user.uid);
    const f = getFile(ctx, path);
    const cache = f.content !== undefined ? readCache(ctx.host, ctx.user.uid) : null;
    if (!cache) return err(`klist: No credentials cache found (filename: ${path})`, 1);
    const out = [`Ticket cache: FILE:${path}`, `Default principal: ${cache.principal}`, '', 'Valid starting       Expires              Service principal'];
    for (const t of cache.tickets) {
      out.push(`${klistTime(t.start)}  ${klistTime(t.end)}  ${t.server}`);
      if (t.renewTill) out.push(`\trenew until ${klistTime(t.renewTill)}`);
    }
    return ok(out.join('\n'));
  },
};

const kdestroy: CommandDef = {
  name: 'kdestroy',
  summary: 'destroy the Kerberos credential cache',
  usage: 'kdestroy',
  run(_args, ctx) {
    const path = cachePath(ctx.user.uid);
    if (!ctx.host.fs[path]) return err('kdestroy: No credentials cache found while destroying cache', 1);
    delete ctx.host.fs[path];
    return ok('');
  },
};

const kvno: CommandDef = {
  name: 'kvno',
  summary: 'get a service ticket and print the key version number of the service',
  usage: 'kvno SERVICE_PRINCIPAL...',
  run(args, ctx) {
    const names = args.filter((a) => !a.startsWith('-'));
    if (!names.length) return err('Usage: kvno [-c ccache] [-e etype] [-k keytab] [-q] [-u | -S sname] service1 service2 ...', 1);
    const cache = readCache(ctx.host, ctx.user.uid);
    if (!cache) return err(`kvno: No credentials cache found (filename: ${cachePath(ctx.user.uid)}) while getting client principal name`, 1);
    const out: string[] = [];
    let code = 0;
    for (const n of names) {
      const server = qualify(n, realmOf(cache.principal));
      try {
        const { ticket, cached } = getServiceTicket(ctx.world, ctx.host, cache, server);
        if (!cached) cache.tickets.push(ticket);
        out.push(`${server}: kvno = ${ticket.kvno}`);
      } catch (e) {
        if (!(e instanceof KrbError)) throw e;
        out.push(`kvno: ${e.message} while getting credentials for ${server}`);
        code = 1;
      }
    }
    writeCache(ctx.world, ctx.host, ctx.user.uid, ctx.user.name, ctx.user.primaryGroup, cache);
    return { out: out.join('\n'), code };
  },
};

/** Apply what kadmin asked for on the calling host (keytab entries). */
function applyKeytab(ctx: CmdCtx, res: KadminResult, who: string): string[] {
  const out = [...res.lines];
  if (res.keytab) {
    const cur = readKeytab(ctx, res.keytab.path);
    const existing = cur.entries ?? [];
    const e = writeChecked(ctx, res.keytab.path, formatKeytab([...existing, ...res.keytab.entries]));
    if (e) return [`${who}: ${e === 'Permission denied' ? 'Permission denied' : e} while adding key to keytab`];
    ctx.host.fs[res.keytab.path].mode = 0o600;
  }
  if (res.ktremove) {
    const cur = readKeytab(ctx, res.ktremove.path);
    if (cur.error) return [`ktremove: ${cur.error} while removing entries from keytab`];
    const entries = cur.entries!;
    const mine = entries.filter((x) => x.principal === res.ktremove!.principal);
    const maxKvno = Math.max(0, ...mine.map((x) => x.kvno));
    const drop = (x: KeytabEntry) => x.principal === res.ktremove!.principal && (res.ktremove!.which === 'all' || (res.ktremove!.which === 'old' ? x.kvno < maxKvno : x.kvno === Number(res.ktremove!.which)));
    const removed = entries.filter(drop);
    const e = writeChecked(ctx, res.ktremove.path, formatKeytab(entries.filter((x) => !drop(x))));
    if (e) return [`ktremove: ${e} while removing entries from keytab`];
    for (const r of removed) out.push(`Entry for principal ${r.principal} with kvno ${r.kvno} removed from keytab FILE:${res.ktremove.path}.`);
  }
  return out;
}

function queryArgv(args: string[]): string[] | null {
  const i = args.indexOf('-q');
  if (i < 0 || args[i + 1] === undefined) return null;
  return tokenizeLine(args[i + 1]).filter((t) => !t.startsWith('\u0000'));
}

const kadminLocal: CommandDef = {
  name: 'kadmin.local',
  summary: 'administer the Kerberos database directly on the KDC (root)',
  usage: 'kadmin.local -q "addprinc|delprinc|cpw|listprincs|getprinc|ktadd|ktremove …"',
  run(args, ctx) {
    const argv = queryArgv(args);
    if (!argv) return err('kadmin.local: interactive mode is not supported in this simulator; use kadmin.local -q "REQUEST"', 1);
    const confText = readFile(ctx.host, '/etc/krb5kdc/kdc.conf');
    if (confText === undefined) return err('kadmin.local: No such file or directory while initializing kadmin.local interface', 1);
    const conf = parseKdcConf(confText);
    let realm: string;
    try {
      realm = defaultRealm(clientConf(ctx.host));
    } catch (e) {
      return krbFail('kadmin.local', e, 'while initializing kadmin.local interface');
    }
    if (!conf.realms[realm]) return err(`kadmin.local: Cannot open DB2 database '/var/lib/krb5kdc/principal': No such file or directory while initializing kadmin.local interface`, 1);
    const db = getFile(ctx, conf.realms[realm].databaseName);
    if (db.error === 'Permission denied') return err('kadmin.local: Permission denied while initializing kadmin.local interface', 1);
    const actor = `${ctx.user.name}/admin@${realm}`;
    const res = kadminRequest({ world: ctx.world, kdc: ctx.host, conf, realm, actor, local: true, ask: (t, s) => ctx.ask(t, s) }, argv);
    return ok([`Authenticating as principal ${actor} with password.`, ...applyKeytab(ctx, res, 'kadmin.local')].join('\n'));
  },
};

const kadmin: CommandDef = {
  name: 'kadmin',
  summary: 'administer the Kerberos database over the network (kadmind, TCP 749)',
  usage: 'kadmin [-p PRINCIPAL] [-w PASSWORD] -q "REQUEST"',
  run(args, ctx) {
    const argv = queryArgv(args);
    if (!argv) return err('kadmin: interactive mode is not supported in this simulator; use kadmin -q "REQUEST"', 1);
    const pIdx = args.indexOf('-p');
    const wIdx = args.indexOf('-w');
    let principal: string;
    try {
      const conf = clientConf(ctx.host);
      const realm = defaultRealm(conf);
      const cache = readCache(ctx.host, ctx.user.uid);
      const base = pIdx >= 0 ? args[pIdx + 1] : cache ? `${cache.principal.split('@')[0]}/admin` : `${ctx.user.name}/admin`;
      principal = qualify(base, realm);
    } catch (e) {
      return krbFail('kadmin', e, 'while initializing kadmin interface');
    }
    const head = `Authenticating as principal ${principal} with password.`;
    try {
      const res = kadminRemote(ctx.world, ctx.host, principal, () => (wIdx >= 0 ? args[wIdx + 1] : ctx.ask(`Password for ${principal}: `, true, head)), argv, (t, s) => ctx.ask(t, s));
      return ok([head, ...applyKeytab(ctx, res, 'kadmin')].join('\n'));
    } catch (e) {
      if (e instanceof KrbError) return err(`${head}\nkadmin: ${e.message} while initializing kadmin interface`, 1);
      throw e;
    }
  },
};

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/** GNU date's default format: "Mon Oct 19 08:31:12 UTC 2026". */
export function gnuDate(ms: number): string {
  const s = new Date(ms).toUTCString(); // "Mon, 19 Oct 2026 08:31:12 GMT"
  const [, wd, dd, mon, yyyy, time] = /^(\w+), (\d+) (\w+) (\d+) (\S+)/.exec(s)!;
  return `${wd} ${mon} ${String(Number(dd)).padStart(2, ' ')} ${time} UTC ${yyyy}`;
}

function parseDateString(s: string, base: number): number | null {
  const t = s.trim();
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)$/.exec(t);
  if (m) return Date.parse(`${m[1]}T${m[2].length === 5 ? m[2] + ':00' : m[2]}Z`);
  const hm = /^(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(t);
  if (hm) {
    const d = new Date(base);
    d.setUTCHours(Number(hm[1]), Number(hm[2]), Number(hm[3] ?? 0), 0);
    return d.getTime();
  }
  const p = Date.parse(t);
  return Number.isNaN(p) ? null : p;
}

const date: CommandDef = {
  name: 'date',
  summary: 'print or set the system date and time (this host\'s clock)',
  usage: 'date [-u] [+FORMAT] | date -s "YYYY-MM-DD HH:MM:SS"',
  run(args, ctx) {
    const now = hostTime(ctx.world, ctx.host);
    const sIdx = args.findIndex((a) => a === '-s' || a === '--set' || a.startsWith('--set='));
    if (sIdx >= 0) {
      const val = args[sIdx].startsWith('--set=') ? args[sIdx].slice(6) : args.slice(sIdx + 1).join(' ');
      const t = parseDateString(val, now);
      if (t === null) return err(`date: invalid date '${val}'`, 1);
      if (ctx.user.uid !== 0) return err(`date: cannot set date: Operation not permitted\n${gnuDate(t)}`, 1);
      ctx.host.clockOffset = Math.round(t - ctx.world.clock);
      return ok(gnuDate(t));
    }
    const fmt = args.find((a) => a.startsWith('+'));
    if (fmt === '+%s') return ok(String(Math.floor(now / 1000)));
    if (fmt) {
      const d = new Date(now).toISOString();
      return ok(fmt.slice(1).replace(/%F/g, d.slice(0, 10)).replace(/%T/g, d.slice(11, 19)).replace(/%Y/g, d.slice(0, 4)).replace(/%m/g, d.slice(5, 7)).replace(/%d/g, d.slice(8, 10)).replace(/%H/g, d.slice(11, 13)).replace(/%M/g, d.slice(14, 16)).replace(/%S/g, d.slice(17, 19)).replace(/%Z/g, 'UTC').replace(/%s/g, String(Math.floor(now / 1000))));
    }
    return ok(gnuDate(now));
  },
};

function tdcTime(ms: number): string {
  const d = new Date(ms);
  return `${d.toUTCString().slice(0, 3)} ${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)}`;
}

const timedatectl: CommandDef = {
  name: 'timedatectl',
  summary: 'show the clock and NTP synchronization state; set-ntp, set-time',
  usage: 'timedatectl [status] | timedatectl set-ntp true|false | timedatectl set-time "YYYY-MM-DD HH:MM:SS"',
  run(args, ctx) {
    const svc = ctx.host.services['systemd-timesyncd'];
    const ntpActive = svc?.state === 'active';
    const now = hostTime(ctx.world, ctx.host);
    const sub = args[0] ?? 'status';
    if (sub === 'status') {
      return ok([
        `               Local time: ${tdcTime(now)} UTC`,
        `           Universal time: ${tdcTime(now)} UTC`,
        `                 RTC time: ${tdcTime(now)}`,
        '                Time zone: Etc/UTC (UTC, +0000)',
        `System clock synchronized: ${ntpActive && !ctx.host.clockOffset ? 'yes' : 'no'}`,
        `              NTP service: ${!svc ? 'n/a' : ntpActive ? 'active' : 'inactive'}`,
        '          RTC in local TZ: no',
      ].join('\n'));
    }
    if (ctx.user.uid !== 0) return err('Failed to ' + (sub === 'set-ntp' ? 'set ntp' : 'set time') + ': Access denied', 1);
    if (sub === 'set-ntp') {
      if (!svc) return err('Failed to set ntp: NTP not supported', 1);
      const on = /^(true|yes|1|on)$/i.test(args[1] ?? '');
      if (on) {
        svc.enabled = true;
        if (svc.state !== 'active') startService(ctx.world, ctx.host, serviceDef('systemd-timesyncd')!);
      } else {
        svc.enabled = false;
        if (svc.state === 'active') stopService(ctx.world, ctx.host, serviceDef('systemd-timesyncd')!);
      }
      return ok('');
    }
    if (sub === 'set-time') {
      if (ntpActive) return err('Failed to set time: Automatic time synchronization is enabled', 1);
      const t = parseDateString(args.slice(1).join(' '), now);
      if (t === null) return err(`Failed to parse time specification '${args.slice(1).join(' ')}': Invalid argument`, 1);
      ctx.host.clockOffset = Math.round(t - ctx.world.clock);
      log(ctx.world, ctx.host, 'systemd-timedated', `Changed local time to ${gnuDate(t)}`, { pid: null, unit: 'systemd-timedated.service' });
      return ok('');
    }
    return err(`Unknown command verb ${sub}.`, 1);
  },
};

export const KRB_COMMANDS: CommandDef[] = [kinit, klist, kdestroy, kvno, kadminLocal, kadmin, date, timedatectl];
