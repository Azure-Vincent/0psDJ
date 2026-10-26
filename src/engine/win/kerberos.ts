// Kerberos in Active Directory. Every domain controller runs a KDC (the Kdc
// service inside lsass, TCP/UDP 88) that answers from the directory: user and
// computer accounts are the principals, their passwords the keys, and service
// principal names (SPNs) say which account a service ticket is encrypted for.
// On the client side, LSA's Kerberos package keeps a ticket cache per logon
// session (the machine's own session is 0x3e7) and Negotiate picks Kerberos
// first; it falls back to NTLM only when no KDC answers or no account holds the
// SPN. Any other Kerberos error (a clock more than 5 minutes off, a revoked
// account) is final. The Windows Time service keeps members within that limit
// by synchronising from a domain controller (NT5DS).

import { deriveKey, realmOf, type CachedTicket } from '../config/krb5';
import { hostTime, sendToKdcs, type KdcReply, type KdcRequest, type KdcTarget, type KrbCode } from '../sim/kerberos';
import { ntpExchange, ntpSynced } from '../sim/ntp';
import type { Host, World } from '../types';
import { seededInt } from '../util/sha256';
import { domainDn, locateDc } from './ad';
import { computerDn } from './gpo';
import { winEvent, type AdState, type AdUser, type WinKrbSession } from './model';

/** The KDC's tolerance (Kerberos policy "Maximum tolerance for computer clock synchronization"). */
export const MAX_SKEW_MS = 5 * 60_000;
const TGT_LIFE_MS = 10 * 3600_000;
const RENEW_MS = 7 * 86400_000;
export const MACHINE_LOGON = '0x3e7';

/** Services that the HOST/ SPN stands for (sPNMappings in the directory). */
const HOST_ALIASES = ['cifs', 'http', 'rpcss', 'eventlog', 'netlogon', 'w32time', 'spooler', 'schedule', 'dnscache', 'www'];

export const realmOfDomain = (ad: AdState) => ad.domain.toUpperCase();

/** A computer's servicePrincipalName: as set, or what Windows registers at join (and, on a DC, at promotion). */
export function computerSpns(ad: AdState, key: string): string[] {
  const c = ad.computers[key];
  if (c.spns) return c.spns;
  const short = c.name.toUpperCase();
  const fq = c.dnsHostName.toLowerCase();
  const dc = c.dc ? [`ldap/${fq}/${ad.domain}`, `ldap/${fq}`, `ldap/${short}`, `ldap/${fq}/${ad.netbios}`, `GC/${fq}/${ad.domain}`, `DNS/${fq}`, `Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/${fq}`] : [];
  return [...dc, `TERMSRV/${short}`, `TERMSRV/${fq}`, `WSMAN/${short}`, `WSMAN/${fq}`, `RestrictedKrbHost/${short}`, `HOST/${short}`, `RestrictedKrbHost/${fq}`, `HOST/${fq}`];
}

export interface KrbAccount { kind: 'user' | 'computer'; key: string; sam: string; dn: string; password: string; enabled: boolean; spns: string[]; user?: AdUser }

export function krbAccounts(ad: AdState): KrbAccount[] {
  const dn = domainDn(ad.domain);
  return [
    ...Object.entries(ad.users).map(([key, u]) => ({ kind: 'user' as const, key, sam: u.sam, dn: `CN=${u.name},CN=Users,${dn}`, password: u.password, enabled: u.enabled && !u.lockedOut, spns: u.sam === 'krbtgt' ? ['kadmin/changepw'] : u.spns ?? [], user: u })),
    ...Object.entries(ad.computers).map(([key, c]) => ({ kind: 'computer' as const, key, sam: `${c.name.toUpperCase()}$`, dn: computerDn(ad, key), password: c.password, enabled: c.enabled, spns: computerSpns(ad, key) })),
  ];
}

/**
 * The accounts that hold an SPN: exact matches first; only when there are none
 * does a HOST/ SPN stand in for cifs/, http/ ... on the same host (sPNMappings).
 */
export function spnOwners(ad: AdState, spn: string): KrbAccount[] {
  const want = spn.toLowerCase();
  const all = krbAccounts(ad);
  const exact = all.filter((a) => a.spns.some((s) => s.toLowerCase() === want));
  const [svc, ...rest] = want.split('/');
  if (exact.length || !HOST_ALIASES.includes(svc)) return exact;
  const asHost = `host/${rest.join('/')}`;
  return all.filter((a) => a.spns.some((s) => s.toLowerCase() === asHost));
}

/** An account by the name part of a principal: "alice", "WIN01$". */
function principalAccount(ad: AdState, name: string): KrbAccount | undefined {
  const n = name.toLowerCase();
  const u = ad.users[n];
  if (u) return { kind: 'user', key: n, sam: u.sam, dn: '', password: u.password, enabled: u.enabled && !u.lockedOut, spns: u.spns ?? [], user: u };
  const key = n.endsWith('$') ? n.slice(0, -1) : '';
  const c = key ? ad.computers[key] : undefined;
  return c ? { kind: 'computer', key, sam: `${c.name.toUpperCase()}$`, dn: '', password: c.password, enabled: c.enabled, spns: [] } : undefined;
}

export const accountKey = (ad: AdState, a: Pick<KrbAccount, 'sam' | 'password'>) => deriveKey(`${a.sam}@${realmOfDomain(ad)}`, a.password);
const krbtgtKey = (ad: AdState) => accountKey(ad, { sam: 'krbtgt', password: ad.users.krbtgt?.password ?? `krbtgt-${ad.domainSid}` });

// ---------------------------------------------------------------------------
// The KDC on a domain controller
// ---------------------------------------------------------------------------

const AUDIT = 'Microsoft-Windows-Security-Auditing';
const clientAddr = (ip: string) => (ip.includes(':') ? ip : `::ffff:${ip}`);

/** AS and TGS requests to a Windows DC, answered from the directory; events 4768/4769/4771 on the DC. */
export function adKdcProcess(world: World, kdc: Host, req: KdcRequest, from: string): KdcReply {
  const ad = kdc.win!.ad!;
  const realm = realmOfDomain(ad);
  const now = hostTime(world, kdc);
  const name = req.client.slice(0, req.client.lastIndexOf('@'));
  const service = req.server.replace(/@[^@]*$/, '');
  const fail = (code: KrbCode): KdcReply => ({ ok: false, code });
  if (req.realm.toUpperCase() !== realm) return fail(6);

  if (req.type === 'AS') {
    const tgt4768 = (code: string, ok: boolean) => winEvent(world, kdc, 'Security', 4768, AUDIT, `A Kerberos authentication ticket (TGT) was requested.\n\nAccount Information:\n\tAccount Name:\t\t${name}\n\tSupplied Realm Name:\t${req.realm}\n\nService Information:\n\tService Name:\t\tkrbtgt\n\nNetwork Information:\n\tClient Address:\t\t${clientAddr(from)}\n\nAdditional Information:\n\tResult Code:\t\t${code}\n\tPre-Authentication Type:\t${ok ? '2' : '-'}`, ok ? 'Information' : 'Information');
    const preauth4771 = (code: string) => winEvent(world, kdc, 'Security', 4771, AUDIT, `Kerberos pre-authentication failed.\n\nAccount Information:\n\tAccount Name:\t\t${name}\n\nService Information:\n\tService Name:\t\tkrbtgt/${realm}\n\nNetwork Information:\n\tClient Address:\t\t${clientAddr(from)}\n\nAdditional Information:\n\tFailure Code:\t\t${code}\n\tPre-Authentication Type:\t2`);
    const acct = principalAccount(ad, name);
    if (!acct) { tgt4768('0x6', false); return fail(6); }
    if (!acct.enabled) { tgt4768('0x12', false); return fail(18); }
    if (!req.preauth) return fail(25);
    if (req.preauth.key !== deriveKey(req.client, acct.password)) {
      const u = acct.user;
      if (u) {
        u.badCount++;
        if (ad.lockoutThreshold > 0 && u.badCount >= ad.lockoutThreshold) {
          u.lockedOut = true;
          winEvent(world, kdc, 'Security', 4740, AUDIT, `A user account was locked out.\n\nAccount That Was Locked Out:\n\tAccount Name:\t\t${u.sam}\n\nAdditional Information:\n\tCaller Computer Name:\t${from}`);
        }
      }
      preauth4771('0x18');
      return fail(24);
    }
    if (Math.abs(req.preauth.time - now) > MAX_SKEW_MS) { preauth4771('0x25'); return fail(37); }
    if (acct.user) { acct.user.badCount = 0; acct.user.lastLogon = world.clock; }
    tgt4768('0x0', true);
    const ticket: CachedTicket = { server: `krbtgt/${realm}@${realm}`, start: now, end: now + TGT_LIFE_MS, renewTill: now + RENEW_MS, kvno: 2, serviceKey: krbtgtKey(ad) };
    return { ok: true, ticket };
  }

  const svc4769 = (svcName: string, code: string) => winEvent(world, kdc, 'Security', 4769, AUDIT, `A Kerberos service ticket was requested.\n\nAccount Information:\n\tAccount Name:\t\t${req.client}\n\nService Information:\n\tService Name:\t\t${svcName}\n\nNetwork Information:\n\tClient Address:\t\t${clientAddr(from)}\n\nAdditional Information:\n\tFailure Code:\t\t${code}`);
  if (req.tgt.serviceKey !== krbtgtKey(ad)) return fail(31);
  if (req.tgt.end < now) return fail(32);
  if (Math.abs(req.authTime - now) > MAX_SKEW_MS) { svc4769(service, '0x25'); return fail(37); }
  if (/^krbtgt\//i.test(service)) return { ok: true, ticket: { ...req.tgt, server: req.server } };
  const owners = spnOwners(ad, service);
  if (owners.length > 1) {
    winEvent(world, kdc, 'System', 11, 'Microsoft-Windows-Kerberos-Key-Distribution-Center', `The KDC encountered duplicate names while processing a Kerberos authentication request. The duplicate name is ${service} (of type DS_SERVICE_PRINCIPAL_NAME). This may result in authentication failures or downgrades to NTLM. In order to prevent this from occuring remove the duplicate entries for ${service} in Active Directory.`, 'Error');
    svc4769(service, '0x8');
    return fail(8);
  }
  if (!owners.length) { svc4769(service, '0x7'); return fail(7); }
  const owner = owners[0];
  svc4769(owner.sam, '0x0');
  return { ok: true, ticket: { server: req.server, start: now, end: Math.min(req.tgt.end, now + TGT_LIFE_MS), renewTill: req.tgt.renewTill, kvno: 2, serviceKey: accountKey(ad, owner) } };
}

// ---------------------------------------------------------------------------
// The client: LSA's Kerberos package
// ---------------------------------------------------------------------------

export type KrbOutcome =
  | { ok: true; ticket: CachedTicket & { kdc: string } }
  | { ok: false; noKdc: true }
  | { ok: false; noCreds: true }
  | { ok: false; code: KrbCode };

/** Windows finds a KDC with the DC locator and talks to it over TCP (MaxPacketSize 0). */
function kdcTargets(world: World, host: Host): { targets: KdcTarget[]; name: string } {
  const m = host.win!.domain!;
  const loc = locateDc(world, host, m.domain);
  if (!loc.ok) return { targets: [], name: '' };
  return { targets: [{ name: loc.name, ip: loc.ip, port: 88, transport: 'tcp', via: 'DNS SRV' }], name: loc.name };
}

function asRequest(world: World, host: Host, client: string, password: string): KrbOutcome {
  const realm = realmOf(client);
  const { targets, name } = kdcTargets(world, host);
  if (!targets.length) return { ok: false, noKdc: true };
  const base = { type: 'AS' as const, client, server: `krbtgt/${realm}@${realm}`, realm, lifetime: TGT_LIFE_MS / 1000, renewable: RENEW_MS / 1000 };
  let r = sendToKdcs(world, host, targets, base);
  if (r && !r.ok && r.code === 25) r = sendToKdcs(world, host, targets, { ...base, preauth: { key: deriveKey(client, password), time: hostTime(world, host) } });
  if (!r) return { ok: false, noKdc: true };
  return r.ok ? { ok: true, ticket: { ...r.ticket, kdc: name } } : { ok: false, code: r.code };
}

function tgsRequest(world: World, host: Host, client: string, tgt: CachedTicket, spn: string): KrbOutcome {
  const realm = realmOf(client);
  const { targets, name } = kdcTargets(world, host);
  if (!targets.length) return { ok: false, noKdc: true };
  const r = sendToKdcs(world, host, targets, { type: 'TGS', client, server: `${spn}@${realm}`, realm, tgt, authTime: hostTime(world, host) });
  if (!r) return { ok: false, noKdc: true };
  return r.ok ? { ok: true, ticket: { ...r.ticket, kdc: name } } : { ok: false, code: r.code };
}

/** The logon id Windows gives a session (stable per host and account in the simulator). */
export function logonIdFor(host: Host, account: string): string {
  return account === MACHINE_LOGON ? MACHINE_LOGON : `0x${seededInt(`logon:${host.id}:${account.toLowerCase()}`, 0x30000, 0xfffff).toString(16)}`;
}

export function krbSession(host: Host, logonId: string, client: string): WinKrbSession {
  const w = host.win!;
  w.krb ??= {};
  const s = w.krb[logonId];
  if (s && s.client.toLowerCase() === client.toLowerCase()) return s;
  return (w.krb[logonId] = { logonId, client, tickets: [] });
}

/**
 * A ticket for `spn` in a logon session: from the cache when still valid,
 * else from the KDC (first a TGT with the session's password, then TGS).
 */
export function sessionTicket(world: World, host: Host, s: WinKrbSession, password: string | null, name: string): KrbOutcome {
  const now = hostTime(world, host);
  const realm = realmOf(s.client);
  const spn = /^krbtgt$/i.test(name) ? `krbtgt/${realm}` : name;
  const want = `${spn}@${realm}`.toLowerCase();
  const cached = s.tickets.find((t) => t.server.toLowerCase() === want && t.end > now);
  if (cached) return { ok: true, ticket: cached };
  let tgt = s.tickets.find((t) => t.server.toLowerCase() === `krbtgt/${realm}@${realm}`.toLowerCase() && t.end > now);
  if (!tgt) {
    if (password === null) return { ok: false, noCreds: true };
    const a = asRequest(world, host, s.client, password);
    if (!a.ok) return a;
    s.tickets = [a.ticket, ...s.tickets.filter((t) => !t.server.toLowerCase().startsWith('krbtgt/'))];
    tgt = a.ticket;
  }
  if (/^krbtgt\//i.test(spn)) return { ok: true, ticket: tgt };
  let t = tgsRequest(world, host, s.client, tgt, spn);
  // The KDC no longer accepts the cached TGT (expired by its clock, or a new krbtgt key): get a new one once.
  if (!t.ok && 'code' in t && (t.code === 31 || t.code === 32) && password !== null) {
    s.tickets = s.tickets.filter((x) => x !== tgt);
    const a = asRequest(world, host, s.client, password);
    if (!a.ok) return a;
    s.tickets.unshift(a.ticket);
    t = tgsRequest(world, host, s.client, a.ticket, spn);
  }
  if (t.ok) s.tickets.push(t.ticket);
  return t;
}

/** The computer's own session (0x3e7): WIN01$@AD.CORP.LAB with the machine password. */
export function machineSession(host: Host): WinKrbSession {
  const m = host.win!.domain!;
  return krbSession(host, MACHINE_LOGON, `${host.hostname.toUpperCase()}$@${m.domain.toUpperCase()}`);
}

/** Does the computer hold a valid TGT? (Its groups, the token Group Policy filters with, come from the TGT.) */
export function hasMachineTgt(world: World, host: Host): boolean {
  const s = host.win!.krb?.[MACHINE_LOGON];
  const now = hostTime(world, host);
  return !!s?.tickets.some((t) => /^krbtgt\//i.test(t.server) && t.end > now);
}

export function machineTicket(world: World, host: Host, spn: string): KrbOutcome {
  return sessionTicket(world, host, machineSession(host), host.win!.domain!.machinePassword, spn);
}

/** NTSTATUS and message for a Kerberos failure, as Windows reports it. */
export function krbStatus(r: Exclude<KrbOutcome, { ok: true }>): { status: string; text: string; logon: string } {
  if ('noKdc' in r) return { status: '0xc000005e', text: 'There are currently no logon servers available to service the logon request.', logon: 'There are currently no logon servers available to service the logon request.' };
  if ('noCreds' in r) return { status: '0x8009030e', text: 'No credentials are available in the security package', logon: 'No credentials are available in the security package' };
  const m: Partial<Record<KrbCode, [string, string, string]>> = {
    6: ['0xc0000064', 'The specified account does not exist.', 'The user name or password is incorrect.'],
    7: ['0xc000018b', 'The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.', 'The security database on the server does not have a computer account for this workstation trust relationship.'],
    8: ['0xc000018b', 'The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.', 'The security database on the server does not have a computer account for this workstation trust relationship.'],
    18: ['0xc0000072', 'The referenced account is currently disabled and may not be logged on to.', 'Your account has been disabled. Please see your system administrator.'],
    31: ['0xc000006d', 'The attempted logon is invalid. This is either due to a bad username or authentication information.', 'The user name or password is incorrect.'],
    32: ['0xc000006d', 'The attempted logon is invalid. This is either due to a bad username or authentication information.', 'The user name or password is incorrect.'],
    24: ['0xc000006a', 'When trying to update a password, this return status indicates that the value provided as the current password is not correct.', 'The user name or password is incorrect.'],
    37: ['0xc0000133', 'The time at the Primary Domain Controller is different than the time at the Backup Domain Controller or member server by too large an amount.', 'There is a time and/or date difference between the client and server.'],
    41: ['0xc000018b', 'The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.', 'The security database on the server does not have a computer account for this workstation trust relationship.'],
  };
  const [status, text, logon] = m[r.code] ?? ['0xc000005e', 'There are currently no logon servers available to service the logon request.', 'There are currently no logon servers available to service the logon request.'];
  return { status, text, logon };
}

/** Does Negotiate fall back to NTLM after this Kerberos result? Only when Kerberos was not available (no KDC, no unique SPN owner). */
export const ntlmFallback = (r: KrbOutcome) => !r.ok && ('noKdc' in r || ('code' in r && (r.code === 7 || r.code === 8)));

function lsaWarning(world: World, host: Host, spn: string, r: Exclude<KrbOutcome, { ok: true }>): void {
  const s = krbStatus(r);
  winEvent(world, host, 'System', 40960, 'LsaSrv', `The Security System detected an authentication error for the server ${spn}. The failure code from authentication protocol Kerberos was "${s.logon}\n (${s.status})".`, 'Warning');
}

export type LogonResult = { ok: true; pkg: 'Kerberos' | 'NTLM' } | { ok: false; status: string; message: string };

/**
 * The interactive part of a domain logon on `server` (console or Remote
 * Desktop, after NLA): LSA gets a TGT for the user and a ticket to the
 * computer itself (host/<fqdn>), which the computer decrypts with its own
 * password. Without a KDC the logon goes ahead with NTLM.
 */
export function interactiveLogon(world: World, server: Host, sam: string, password: string): LogonResult {
  const m = server.win!.domain!;
  const client = `${sam}@${m.domain.toUpperCase()}`;
  const logonId = logonIdFor(server, `${m.netbios}\\${sam}`);
  delete server.win!.krb?.[logonId];
  const spn = `host/${server.hostname.toLowerCase()}.${m.domain}`;
  const r = sessionTicket(world, server, krbSession(server, logonId, client), password, spn);
  if (r.ok) {
    if (r.ticket.serviceKey !== deriveKey(`${server.hostname.toUpperCase()}$@${m.domain.toUpperCase()}`, m.machinePassword)) {
      winEvent(world, server, 'System', 4, 'Microsoft-Windows-Security-Kerberos', `The Kerberos client received a KRB_AP_ERR_MODIFIED error from the server ${server.hostname.toUpperCase()}$. The target name used was ${spn}. This indicates that the target server failed to decrypt the ticket provided by the client. This can occur when the target server principal name (SPN) is registered on an account other than the account the target service is using. Ensure that the target SPN is only registered on the account used by the server.`, 'Error');
      const s = krbStatus({ ok: false, code: 41 });
      return { ok: false, status: s.status, message: s.logon };
    }
    return { ok: true, pkg: 'Kerberos' };
  }
  if (ntlmFallback(r)) return { ok: true, pkg: 'NTLM' };
  lsaWarning(world, server, spn, r);
  const s = krbStatus(r);
  return { ok: false, status: s.status, message: s.logon };
}

/**
 * Group Policy authenticates the computer to LDAP on the DC with Kerberos
 * (ldap/<dc>); it does not fall back to NTLM.
 */
export function gpKerberos(world: World, host: Host, dcName: string): KrbOutcome {
  const spn = `ldap/${dcName}`;
  const r = machineTicket(world, host, spn);
  if (!r.ok && 'code' in r) lsaWarning(world, host, spn, r);
  return r;
}

// ---------------------------------------------------------------------------
// Windows Time (W32Time): domain members follow the domain hierarchy (NT5DS)
// ---------------------------------------------------------------------------

export type TimeSource = { kind: 'cmos' } | { kind: 'domain'; dc: string; ip: string } | { kind: 'ntp'; name: string };

/** Where W32Time takes the time from: a DC (members), the local clock (the forest root PDC), or time.windows.com. */
export function timeSource(world: World, host: Host): TimeSource {
  const w = host.win!;
  if (w.ad) return { kind: 'cmos' };
  if (!w.domain) return { kind: 'ntp', name: 'time.windows.com,0x8' };
  const loc = locateDc(world, host, w.domain.domain);
  return loc.ok ? { kind: 'domain', dc: loc.name, ip: loc.ip } : { kind: 'domain', dc: '', ip: '' };
}

const TIME = 'Microsoft-Windows-Time-Service';

/** One synchronisation (service start, w32tm /resync): true when the clock now follows its source. */
export function timeSync(world: World, host: Host): boolean {
  const src = timeSource(world, host);
  const ok = sync(world, host, src);
  host.win!.timeSync = { ok, at: world.clock, source: sourceName(src) };
  return ok;
}

export const sourceName = (s: TimeSource) => (s.kind === 'cmos' ? 'Local CMOS Clock' : s.kind === 'ntp' ? s.name : s.dc || 'Free-running System Clock');

function sync(world: World, host: Host, src: TimeSource): boolean {
  if (src.kind === 'cmos') return true;
  if (src.kind === 'ntp') { host.clockOffset = 0; return true; }
  if (!src.dc) {
    winEvent(world, host, 'System', 129, TIME, 'NtpClient was unable to set a domain peer to use as a time source because of discovery error. NtpClient will try again in 15 minutes and double the reattempt interval thereafter. The error was: The entry is not found. (0x800706E1)', 'Warning');
    return false;
  }
  const x = ntpExchange(world, host, src.ip);
  if (x.kind !== 'reply' || !ntpSynced(x.reply)) {
    winEvent(world, host, 'System', 47, TIME, `Time Provider NtpClient: No valid response has been received from domain controller ${src.dc} after 8 attempts to contact it. This domain controller will be discarded as a time source and NtpClient will attempt to discover a new domain controller from which to synchronize. The error was: The peer is unreachable.`, 'Warning');
    return false;
  }
  host.clockOffset = Math.round(x.reply.serverTime - world.clock);
  winEvent(world, host, 'System', 37, TIME, `The time provider NtpClient is currently receiving valid time data from ${src.dc} (ntp.d|0.0.0.0:123->${src.ip}:123).`);
  return true;
}
