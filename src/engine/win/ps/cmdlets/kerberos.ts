// Kerberos and time tools on Windows: klist (the ticket caches of the logon
// sessions), setspn (service principal names in the directory) and w32tm (the
// Windows Time service). They print what their real counterparts print.

import { realmOf, type CachedTicket } from '../../../config/krb5';
import { resolve } from '../../../sim/dns';
import { hostTime } from '../../../sim/kerberos';
import { ntpExchange } from '../../../sim/ntp';
import { domainDn } from '../../ad';
import {
  computerSpns, krbAccounts, krbSession, krbStatus, logonIdFor, MACHINE_LOGON, machineSession, sessionTicket, sourceName, spnOwners, timeSource, timeSync, type KrbAccount, type TimeSource,
} from '../../kerberos';
import type { AdState, WinKrbSession } from '../../model';
import { native, type PsCtx } from '../runtime';
import { admin as isAdmin, has } from './native';

const ok = (out: string, code = 0) => ({ out, code });

const pad2 = (n: number) => String(n).padStart(2, '0');
/** klist's time format: 10/26/2026 18:40:10 (local). */
function klistTime(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()} ${d.getUTCHours()}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())} (local)`;
}

const splitPrincipal = (p: string) => `${p.slice(0, p.lastIndexOf('@'))} @ ${realmOf(p)}`;

function ticketLines(s: WinKrbSession, t: CachedTicket & { kdc: string }, i: number): string[] {
  const tgt = /^krbtgt\//i.test(t.server);
  return [
    `#${i}>\tClient: ${splitPrincipal(s.client)}`,
    `\tServer: ${splitPrincipal(t.server)}`,
    '\tKerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96',
    tgt ? '\tTicket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize' : '\tTicket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize',
    `\tStart Time: ${klistTime(t.start)}`,
    `\tEnd Time:   ${klistTime(t.end)}`,
    `\tRenew Time: ${klistTime(t.renewTill ?? t.end)}`,
    '\tSession Key Type: AES-256-CTS-HMAC-SHA1-96',
    tgt ? '\tCache Flags: 0x1 -> PRIMARY ' : '\tCache Flags: 0 ',
    `\tKdc Called: ${t.kdc}`,
    '',
  ];
}

/**
 * The logon session klist works on: the console's own (a domain account on a
 * DC, a local account elsewhere, which has no Kerberos credentials), the
 * computer's (0x3e7), or another session by its logon id (only its tickets:
 * LSA does not hand out other sessions' passwords).
 */
function targetSession(ctx: PsCtx, logonId?: string): { session?: WinKrbSession; password: string | null; logonId: string; missing?: boolean } {
  const w = ctx.host.win!;
  if (logonId && Number(logonId) === 0x3e7) {
    if (!w.domain) return { logonId: MACHINE_LOGON, password: null };
    return { session: machineSession(ctx.host), password: w.domain.machinePassword, logonId: MACHINE_LOGON };
  }
  if (logonId) {
    const s = Object.values(w.krb ?? {}).find((x) => Number(x.logonId) === Number(logonId));
    return s ? { session: s, password: null, logonId: s.logonId } : { logonId, password: null, missing: true };
  }
  const ad = w.ad;
  const u = ad?.users[ctx.user.name.toLowerCase()];
  const id = logonIdFor(ctx.host, `${w.domain?.netbios ?? ctx.host.hostname}\\${ctx.user.name}`);
  if (!ad || !u) return { logonId: id, password: null };
  return { session: krbSession(ctx.host, id, `${u.sam}@${ad.domain.toUpperCase()}`), password: u.password, logonId: id };
}

native({
  name: 'klist', synopsis: 'Lists and manages Kerberos tickets: klist [-li 0x3e7] [tickets | purge | get <SPN>].',
  run(args, ctx) {
    const li = args.findIndex((a) => /^[-/]li$/i.test(a));
    const logonArg = li >= 0 ? args[li + 1] : undefined;
    const rest = args.filter((_, i) => li < 0 || (i !== li && i !== li + 1)).filter((a) => !/^[-/]lh$/i.test(a) && a !== '0');
    const verb = (rest[0] ?? 'tickets').toLowerCase();
    const head = ['', `Current LogonId is 0:${logonIdFor(ctx.host, `${ctx.host.win!.domain?.netbios ?? ctx.host.hostname}\\${ctx.user.name}`)}`];
    // Other logon sessions (the computer's included) need an elevated administrator.
    if (logonArg && !isAdmin(ctx)) return ok([...head, 'Error calling API LsaCallAuthenticationPackage (QueryTicketCache Ex2 substatus): 0x5', '', 'klist failed with 0xc0000022/-1073741790: {Access Denied}'].join('\n'), 1);
    const c = targetSession(ctx, logonArg);
    if (logonArg) head.push(`Targeted LogonId is 0:${c.logonId}`);
    if (c.missing) return ok([...head, 'Error calling API LsaCallAuthenticationPackage (QueryTicketCache Ex2 substatus): 0x520', '', 'klist failed with 0xc000005f/-1073741729: A specified logon session does not exist. It may already have been terminated.'].join('\n'), 1);
    const now = hostTime(ctx.world, ctx.host);
    const list = () => {
      const tickets = (c.session?.tickets ?? []).filter((t) => t.end > now);
      return ['', `Cached Tickets: (${tickets.length})`, '', ...tickets.flatMap((t, i) => ticketLines(c.session!, t, i))];
    };
    if (verb === 'purge') {
      if (c.session) c.session.tickets = [];
      return ok([...head, '\tDeleting all tickets:', '\tTicket(s) purged!'].join('\n'));
    }
    if (verb === 'get') {
      const spn = rest[1];
      if (!spn) return ok('Usage: klist [-lh <LogonId.HighPart>] [-li <LogonId.LowPart>] get <ServicePrincipalName>', 87);
      const r = c.session ? sessionTicket(ctx.world, ctx.host, c.session, c.password, spn) : { ok: false as const, noCreds: true as const };
      if (!r.ok) {
        const s = krbStatus(r);
        const sub = 'noKdc' in r ? '0x51f' : 'noCreds' in r ? '0x8009030e' : r.code === 37 ? '0x52f' : r.code === 7 || r.code === 8 ? '0x6fb' : '0x52e';
        const n = Number(s.status) | 0;
        return ok([...head, `Error calling API LsaCallAuthenticationPackage (GetTicket substatus): ${sub}`, '', `klist failed with ${s.status}/${n}: ${s.text}`].join('\n'), 1);
      }
      return ok([...head, `A ticket to ${spn} has been retrieved successfully.`, ...list()].join('\n'));
    }
    if (verb === 'tickets' || verb === 'tgt') return ok([...head, ...list()].join('\n'));
    return ok('Usage: klist [-lh <LogonId.HighPart>] [-li <LogonId.LowPart>] [tickets | tgt | purge | sessions | kcd_cache | get <ServicePrincipalName> | add_bind <DomainName> <DcName> | query_bind | purge_bind]', 87);
  },
});

// ---------------------------------------------------------------------------
// setspn
// ---------------------------------------------------------------------------

const USAGE_SETSPN = `Usage: setspn [modifiers switch] [accountname]
  Where "accountname" can be the name or domain\\name
  of the target computer or user account

  Edit Mode Switches:
   -R = reset HOST ServicePrincipalName
    Usage:   setspn -R accountname
   -S = add arbitrary SPN after verifying no duplicates exist
    Usage:   setspn -S SPN accountname
   -D = delete arbitrary SPN
    Usage:   setspn -D SPN accountname

  Query Mode Switches:
   -Q = query for existence of SPN
    Usage:   setspn -Q SPN
   -X = search for duplicate SPNs
    Usage:   setspn -X
   -L = list SPNs registered to target account
    Usage:   setspn [-L] accountname`;

function findAccount(ad: AdState, name: string): KrbAccount | undefined {
  const n = name.replace(/^[^\\]+\\/, '').toLowerCase();
  const all = krbAccounts(ad);
  return all.find((a) => a.kind === 'computer' && (a.sam.toLowerCase() === n || a.sam.toLowerCase() === `${n}$`)) ?? all.find((a) => a.sam.toLowerCase() === n);
}

/** Make the account's SPN list explicit before changing it. */
function spnList(ad: AdState, a: KrbAccount): string[] {
  if (a.kind === 'computer') return (ad.computers[a.key].spns ??= [...computerSpns(ad, a.key)]);
  return (ad.users[a.key].spns ??= []);
}

native({
  name: 'setspn', synopsis: 'Reads and changes service principal names: setspn -L account, -Q SPN, -S SPN account, -D SPN account, -X.',
  run(args, ctx) {
    const ad = ctx.host.win!.ad;
    const flag = (args[0] ?? '').toLowerCase().replace(/^\//, '-');
    if (!args.length || flag === '-?' || flag === '-h') return ok(USAGE_SETSPN, args.length ? 0 : 1);
    if (!ad) return ok(`FindDomainForAccount: Call to DsGetDcNameWithAccountW failed with return value 0x00000525\nUnable to locate account ${args[args.length - 1]}`, 1);
    const dom = domainDn(ad.domain);
    const notFound = (n: string) => ok(`FindDomainForAccount: Call to DsGetDcNameWithAccountW failed with return value 0x00000525\nUnable to locate account ${n}`, 1);
    if (flag === '-x') {
      const groups = new Map<string, KrbAccount[]>();
      for (const a of krbAccounts(ad)) for (const s of a.spns) groups.set(s.toLowerCase(), [...(groups.get(s.toLowerCase()) ?? []), a]);
      const dup = [...groups.entries()].filter(([, v]) => v.length > 1);
      return ok([`Checking domain ${dom}`, 'Processing entry 0', ...dup.flatMap(([spn, v]) => [`${v[0].spns.find((s) => s.toLowerCase() === spn)} is registered on these accounts:`, ...v.map((a) => `\t${a.dn}`), '']), `found ${dup.length} group of duplicate SPNs.`].join('\n'));
    }
    if (flag === '-q') {
      const spn = args[1] ?? '';
      const owners = spnOwners(ad, spn).filter((a) => a.spns.some((s) => s.toLowerCase() === spn.toLowerCase()));
      if (!owners.length) return ok(`Checking domain ${dom}\n\nNo such SPN found.`, 1);
      return ok([`Checking domain ${dom}`, ...owners.flatMap((a) => [a.dn, ...a.spns.map((s) => `\t${s}`)]), '', 'Existing SPN found!'].join('\n'));
    }
    if (flag === '-s' || flag === '-a' || flag === '-d') {
      const spn = args[1];
      const name = args[2];
      if (!spn || !name) return ok(USAGE_SETSPN, 1);
      const a = findAccount(ad, name);
      if (!a) return notFound(name);
      if (!isAdmin(ctx)) return ok(`Registering ServicePrincipalNames for ${a.dn}\n\t${spn}\nFailed to assign SPN on account '${a.dn}', error 0x2098/8344 -> Insufficient access rights to perform the operation.`, 1);
      const list = spnList(ad, a);
      if (flag === '-d') {
        const i = list.findIndex((s) => s.toLowerCase() === spn.toLowerCase());
        if (i < 0) return ok(`Unregistering ServicePrincipalNames for ${a.dn}\n\t${spn}\nFailed to remove SPN on account '${a.dn}', error 0x2116/8470 -> The attribute value is not valid.`, 1);
        list.splice(i, 1);
        return ok(`Unregistering ServicePrincipalNames for ${a.dn}\n\t${spn}\nUpdated object`);
      }
      const others = krbAccounts(ad).filter((x) => x.dn !== a.dn && x.spns.some((s) => s.toLowerCase() === spn.toLowerCase()));
      if (list.some((s) => s.toLowerCase() === spn.toLowerCase())) return ok(`Checking domain ${dom}\n\nRegistering ServicePrincipalNames for ${a.dn}\n\t${spn}\nDuplicate SPN found, aborting operation!`, 1);
      if (others.length) {
        // Since Windows Server 2012 R2 the directory itself refuses an SPN that another account holds.
        if (flag === '-a') return ok(`Registering ServicePrincipalNames for ${a.dn}\n\t${spn}\nFailed to assign SPN on account '${a.dn}', error 0x21c7/8647 -> The operation failed because SPN value provided for addition/modification is not unique forest-wide.`, 1);
        return ok([`Checking domain ${dom}`, ...others.flatMap((x) => [x.dn, ...x.spns.map((s) => `\t${s}`)]), '', 'Duplicate SPN found, aborting operation!'].join('\n'), 1);
      }
      list.push(spn);
      return ok(`${flag === '-s' ? `Checking domain ${dom}\n\n` : ''}Registering ServicePrincipalNames for ${a.dn}\n\t${spn}\nUpdated object`);
    }
    if (flag === '-r') {
      const a = findAccount(ad, args[1] ?? '');
      if (!a || a.kind !== 'computer') return notFound(args[1] ?? '');
      delete ad.computers[a.key].spns;
      return ok(`Registering ServicePrincipalNames for ${a.dn}\n${computerSpns(ad, a.key).filter((s) => /^host\//i.test(s)).map((s) => `\t${s}`).join('\n')}\nUpdated object`);
    }
    const name = flag === '-l' ? args[1] : args[0];
    if (!name) return ok(USAGE_SETSPN, 1);
    const a = findAccount(ad, name);
    if (!a) return notFound(name);
    return ok([`Registered ServicePrincipalNames for ${a.dn}:`, ...a.spns.map((s) => `\t${s}`)].join('\n'));
  },
});

// ---------------------------------------------------------------------------
// w32tm
// ---------------------------------------------------------------------------

native({
  name: 'w32tm', synopsis: 'Windows Time service tool (/query /status|/source|/configuration, /resync, /stripchart /computer:X).',
  run(args, ctx) {
    const host = ctx.host;
    const w = host.win!;
    const running = w.services.W32Time?.status === 'Running';
    const usage = 'w32tm [/? | /register | /unregister ]\n  /query [/computer:<target>] {/source | /configuration | /peers | /status}\n  /resync [/computer:<computer>] [/nowait] [/rediscover] [/soft]\n  /stripchart /computer:<target> [/period:<refresh>] [/dataonly] [/samples:<count>]';
    if (has(args, '/stripchart')) {
      const target = args.find((a) => /^\/computer:/i.test(a))?.slice(10);
      if (!target) return ok(usage, 1);
      const r = resolveHost(ctx, target);
      const t = new Date(hostTime(ctx.world, host));
      const stamp = `${pad2(t.getUTCHours())}:${pad2(t.getUTCMinutes())}:${pad2(t.getUTCSeconds())}`;
      const out = [`Tracking ${target} [${r?.ip ?? target}:123].`, 'Collecting 1 samples.', `The current time is ${klistTime(hostTime(ctx.world, host)).replace(' (local)', '')}.`];
      if (!r) return ok([...out, `${stamp}, error: 0x80072AF9`].join('\n'), 0);
      const x = ntpQuery(ctx, r.ip);
      if (x === null) return ok([...out, `${stamp}, error: 0x800705B4`].join('\n'), 0);
      const off = (x - hostTime(ctx.world, host)) / 1000;
      return ok([...out, `${stamp}, ${off >= 0 ? '+' : '-'}${Math.abs(off).toFixed(7).padStart(10, '0')}s`].join('\n'));
    }
    if (!running) return ok('The following error occurred: The service has not been started. (0x80070426)', 1);
    if (has(args, '/resync')) {
      if (!isAdmin(ctx)) return ok('The following error occurred: Access is denied. (0x80070005)', 1);
      return timeSync(ctx.world, host)
        ? ok('Sending resync command to local computer\nThe command completed successfully.')
        : ok('Sending resync command to local computer\nThe computer did not resync because no time data was available.', 1);
    }
    if (has(args, '/query')) {
      // The source W32Time last used (discovering a DC again only when it never synchronised).
      const last = w.timeSync;
      const src: TimeSource = w.ad ? { kind: 'cmos' } : !w.domain ? { kind: 'ntp', name: 'time.windows.com,0x8' } : last?.ok ? { kind: 'domain', dc: last.source, ip: findIp(ctx, last.source) } : timeSource(ctx.world, host);
      const name = sourceName(src);
      if (has(args, '/source')) return ok(name);
      const synced = src.kind !== 'domain' || (last?.ok ?? false);
      if (has(args, '/configuration')) return ok(['[TimeProviders]', '', 'NtpClient (Local)', 'DllName: C:\\Windows\\system32\\w32time.dll (Local)', 'Enabled: 1 (Local)', `Type: ${src.kind === 'ntp' ? 'NTP' : 'NT5DS'} (Local)`, '', 'NtpServer (Local)', `Enabled: ${w.ad ? 1 : 0} (Local)`].join('\n'));
      return ok([
        'Leap Indicator: ' + (synced ? '0(no warning)' : '3(not synchronized)'),
        `Stratum: ${src.kind === 'cmos' ? '1 (primary reference - syncd by radio clock)' : synced ? '2 (secondary reference - syncd by (S)NTP)' : '0 (unspecified)'}`,
        'Precision: -23 (119.209ns per tick)',
        'Root Delay: 0.0010000s',
        'Root Dispersion: 10.0000000s',
        `ReferenceId: ${src.kind === 'cmos' ? '0x4C4F434C (source name:  "LOCL")' : synced && src.kind === 'domain' ? `0x${src.ip.split('.').map((o) => Number(o).toString(16).padStart(2, '0')).join('').toUpperCase()} (source IP:  ${src.ip})` : '0x00000000 (unspecified)'}`,
        `Last Successful Sync Time: ${last?.ok ? klistTime(last.at + (host.clockOffset ?? 0)).replace(' (local)', '') : 'unspecified'}`,
        `Source: ${synced ? name : 'Free-running System Clock'}`,
        'Poll Interval: 10 (1024s)',
      ].join('\n'));
    }
    return ok(usage, 1);
  },
});

function resolveHost(ctx: PsCtx, name: string): { ip: string } | null {
  const r = resolve(ctx.world, ctx.host, name, { family: 4 });
  return r.ok ? { ip: r.ip } : null;
}

/** The DC's address as the member knows it (its DNS cache: resolve without traffic to the DC itself). */
function findIp(ctx: PsCtx, name: string): string {
  return Object.values(ctx.world.hosts).find((h) => h.win?.ad && `${h.hostname.toLowerCase()}.${h.win.ad.domain}` === name.toLowerCase())?.ifaces.find((i) => i.name !== 'lo' && i.address)?.address ?? '';
}

/** The server's time from one NTP exchange, or null without an answer. */
function ntpQuery(ctx: PsCtx, ip: string): number | null {
  const x = ntpExchange(ctx.world, ctx.host, ip);
  return x.kind === 'reply' ? x.reply.serverTime : null;
}
