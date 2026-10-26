// Active Directory: the domain controller's database, AD-integrated DNS, and
// what members do with it. Everything a member does goes over the simulated
// network: it finds a DC with the DNS SRV record _ldap._tcp.dc._msdcs.<domain>
// asked of its own DNS servers, contacts it on LDAP (389), and proves its
// identity with the machine account password (the "secure channel"). Domain
// logons are NTLM pass-through: the member forwards the credentials to the DC,
// which checks the password, the account state and the lockout counter.

import type { ZoneRecord } from '../config/zone';
import { dnsQuery } from '../sim/dns';
import { findHostByIp } from '../sim/network';
import { tcpConnect } from '../sim/tcp';
import type { Host, World } from '../types';
import { seededInt } from '../util/sha256';
import { clearGroupPolicy, gpData, normDn, startupGroupPolicy } from './gpo';
import { timeSync } from './kerberos';
import {
  applyFirewall, startWinService, winEvent, winResolver,
  type AdState, type DomainMembership, type WinFwRule, type WinService,
} from './model';

export const AD_DOMAIN = 'ad.corp.lab';
export const AD_NETBIOS = 'CORP';

export function domainDn(domain: string): string {
  return domain.split('.').map((p) => `DC=${p}`).join(',');
}

export function isDc(host: Host | undefined): boolean {
  return !!host?.win?.ad;
}

/** sAMAccountName lookup (case-insensitive). */
export function adUser(ad: AdState, sam: string) {
  return ad.users[sam.toLowerCase()];
}

/** Every group a principal belongs to, directly or through nesting (users are in Domain Users). */
export function principalGroups(ad: AdState, sam: string): string[] {
  const out = new Set<string>();
  const isUser = !!adUser(ad, sam);
  if (isUser) out.add('Domain Users');
  const queue = [sam.toLowerCase(), ...(isUser ? ['domain users'] : [])];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const g of Object.values(ad.groups)) {
      if (g.members.some((m) => m.toLowerCase() === cur) && !out.has(g.name)) {
        out.add(g.name);
        queue.push(g.name.toLowerCase());
      }
    }
  }
  return [...out];
}

// ---------------------------------------------------------------------------
// Locating a domain controller
// ---------------------------------------------------------------------------

export type DcLocation =
  | { ok: true; dc: Host; ip: string; name: string }
  | { ok: false; error: 'dns' | 'ldap'; detail: string };

export function locateDc(world: World, from: Host, domain: string): DcLocation {
  const self = from.win?.ad;
  if (self && self.domain === domain && from.win!.services.NTDS?.status === 'Running') {
    const ip = from.ifaces.find((i) => i.name !== 'lo' && i.address)?.address ?? '127.0.0.1';
    return { ok: true, dc: from, ip, name: `${from.hostname.toLowerCase()}.${domain}` };
  }
  const servers = winResolver(from).nameservers;
  if (!servers.length) return { ok: false, error: 'dns', detail: 'no DNS servers configured' };
  const q = `_ldap._tcp.dc._msdcs.${domain}.`;
  let target: string | null = null;
  let server: string | null = null;
  let detail = 'DNS name does not exist';
  for (const ns of servers) {
    const ex = dnsQuery(world, from, ns, q, 2, 'SRV');
    if (ex.outcome === 'answer') {
      const srv = ex.answer!.answers.find((r) => r.type === 'SRV');
      if (srv) { target = srv.data.split(/\s+/)[3]; server = ns; break; }
    }
    if (ex.outcome === 'timeout' || ex.outcome === 'unreachable' || ex.outcome === 'port-unreachable') { detail = 'timeout'; continue; }
    detail = ex.outcome === 'refused' ? 'refused' : 'DNS name does not exist';
    break;
  }
  if (!target || !server) return { ok: false, error: 'dns', detail };
  const a = dnsQuery(world, from, server, target, 2, 'A');
  const ip = a.outcome === 'answer' ? a.answer!.answers.find((r) => r.type === 'A')?.data : undefined;
  if (!ip) return { ok: false, error: 'dns', detail: `no address for ${target}` };
  const c = tcpConnect(world, from, ip, 389, { timeoutMs: 3000 });
  if (!c.ok) return { ok: false, error: 'ldap', detail: `LDAP to ${ip}:389 failed (${c.errno})` };
  c.conn.send('c2s', 120, { protocol: 'DATA', info: 'LDAP searchRequest (netlogon ping)', fields: [] });
  c.conn.close('client');
  const dc = findHostByIp(world, ip);
  if (!dc?.win?.ad || dc.win.ad.domain !== domain) return { ok: false, error: 'ldap', detail: `${ip} is not a domain controller for ${domain}` };
  return { ok: true, dc, ip, name: target.replace(/\.$/, '') };
}

// ---------------------------------------------------------------------------
// Secure channel and authentication
// ---------------------------------------------------------------------------

export type ChannelState = 'ok' | 'no-dc' | 'denied' | 'not-joined';

export function secureChannel(world: World, member: Host): { state: ChannelState; dc?: DcLocation } {
  const m = member.win?.domain;
  if (!m) return { state: 'not-joined' };
  const loc = locateDc(world, member, m.domain);
  if (!loc.ok) return { state: 'no-dc', dc: loc };
  if (loc.dc === member) return { state: 'ok', dc: loc };
  const comp = loc.dc.win!.ad!.computers[member.hostname.toLowerCase()];
  return { state: comp && comp.enabled && comp.password === m.machinePassword ? 'ok' : 'denied', dc: loc };
}

export interface DomainAuth {
  ok: boolean;
  /** NTSTATUS for event 4625 / the client. */
  status?: string;
  kind?: 'bad-password' | 'locked' | 'disabled' | 'no-logon-servers' | 'trust' | 'no-domain';
  reason?: string;
  sam?: string;
  groups?: string[];
}

function trustFailed(world: World, member: Host, dcName: string): void {
  winEvent(world, member, 'System', 3210, 'NETLOGON', `This computer could not authenticate with \\\\${dcName}, a Windows domain controller for domain ${member.win!.domain!.netbios}, and therefore this computer might deny logon requests. This inability to authenticate might be caused by another computer on the same network using the same name or the password for this computer account is not recognized. If this message appears again, contact your system administrator.`, 'Error');
}

export function noLogonServers(world: World, member: Host): void {
  winEvent(world, member, 'System', 5719, 'NETLOGON', `This computer was not able to set up a secure session with a domain controller in domain ${member.win!.domain!.netbios} due to the following: \nThere are currently no logon servers available to service the logon request. \nThis may lead to authentication problems. Make sure that this computer is connected to the network. If the problem persists, please contact your domain administrator.`, 'Error');
}

/** NTLM pass-through: `server` (a member or the DC itself) validates domain credentials with a DC. */
export function domainAuth(world: World, server: Host, sam: string, password: string): DomainAuth {
  const w = server.win!;
  const mem = w.domain;
  if (!mem) return { ok: false, kind: 'no-domain', status: '0xC000006D', reason: 'Unknown user name or bad password.' };
  const ch = secureChannel(world, server);
  if (ch.state === 'no-dc') {
    noLogonServers(world, server);
    return { ok: false, kind: 'no-logon-servers', status: '0xC000005E', reason: 'There are currently no logon servers available to service the logon request.' };
  }
  const loc = ch.dc as Extract<DcLocation, { ok: true }>;
  if (ch.state === 'denied') {
    trustFailed(world, server, loc.name);
    return { ok: false, kind: 'trust', status: '0xC000018D', reason: 'The trust relationship between this workstation and the primary domain failed.' };
  }
  const dc = loc.dc;
  const ad = dc.win!.ad!;
  const u = adUser(ad, sam);
  const audit = (ok: boolean, code: string) => winEvent(world, dc, 'Security', 4776, 'Microsoft-Windows-Security-Auditing', `The computer attempted to validate the credentials for an account.\n\nAuthentication Package:\tMICROSOFT_AUTHENTICATION_PACKAGE_V1_0\nLogon Account:\t${sam}\nSource Workstation:\t${server.hostname.toUpperCase()}\nError Code:\t${ok ? '0x0' : code}`, ok ? 'Information' : 'Information');
  if (!u) { audit(false, '0xC0000064'); return { ok: false, kind: 'bad-password', status: '0xC000006D', reason: 'Unknown user name or bad password.' }; }
  if (u.lockedOut) { audit(false, '0xC0000234'); return { ok: false, kind: 'locked', status: '0xC0000234', reason: 'Account locked out.' }; }
  if (u.password !== password) {
    u.badCount++;
    audit(false, '0xC000006A');
    if (ad.lockoutThreshold > 0 && u.badCount >= ad.lockoutThreshold) {
      u.lockedOut = true;
      winEvent(world, dc, 'Security', 4740, 'Microsoft-Windows-Security-Auditing', `A user account was locked out.\n\nAccount That Was Locked Out:\n\tAccount Name:\t\t${u.sam}\n\nAdditional Information:\n\tCaller Computer Name:\t${server.hostname.toUpperCase()}`);
    }
    return { ok: false, kind: 'bad-password', status: '0xC000006D', reason: 'Unknown user name or bad password.' };
  }
  if (!u.enabled) { audit(false, '0xC0000072'); return { ok: false, kind: 'disabled', status: '0xC0000072', reason: 'Account currently disabled.' }; }
  u.badCount = 0;
  u.lastLogon = world.clock;
  audit(true, '');
  return { ok: true, sam: u.sam, groups: principalGroups(ad, u.sam) };
}

/** Does a domain principal hold the right to log on through Remote Desktop on `server`? */
export function domainRdpAllowed(server: Host, sam: string, groups: string[]): boolean {
  const w = server.win!;
  if (w.ad) return groups.includes('Domain Admins') || groups.includes('Administrators');
  const nb = w.domain!.netbios.toLowerCase();
  const names = new Set([sam, ...groups].map((x) => `${nb}\\${x.toLowerCase()}`));
  return ['Administrators', 'Remote Desktop Users'].some((g) => (w.localDomainMembers?.[g] ?? []).some((m) => names.has(m.toLowerCase())));
}

// ---------------------------------------------------------------------------
// Promotion, join, boot
// ---------------------------------------------------------------------------

function svc(name: string, displayName: string, process: string, dependsOn: string[] = []): WinService {
  return { name, displayName, startType: 'Automatic', status: 'Stopped', process, pid: null, dependsOn, protected: true };
}

function fwRule(name: string, displayName: string, group: string, protocol: 'TCP' | 'UDP', port: string): WinFwRule {
  return { name, displayName, group, direction: 'Inbound', action: 'Allow', enabled: true, profiles: 'Any', protocol, localPort: [port], remoteAddress: 'Any', builtIn: true };
}

function rec(name: string, type: ZoneRecord['type'], data: string, ttl = 600): ZoneRecord {
  return { name, type, data, ttl };
}

/** The records Netlogon and the DNS server register for a DC. */
function dcRecords(domain: string, dcName: string, ip: string): ZoneRecord[] {
  const z = `${domain}.`;
  const fq = `${dcName}.${z}`;
  return [
    rec(z, 'SOA', `${fq} hostmaster.${z} 1 900 600 86400 3600`, 3600),
    rec(z, 'NS', fq, 3600),
    rec(z, 'A', ip),
    rec(fq, 'A', ip, 3600),
    rec(`_ldap._tcp.${z}`, 'SRV', `0 100 389 ${fq}`),
    rec(`_kerberos._tcp.${z}`, 'SRV', `0 100 88 ${fq}`),
    rec(`_kerberos._udp.${z}`, 'SRV', `0 100 88 ${fq}`),
    rec(`_kpasswd._tcp.${z}`, 'SRV', `0 100 464 ${fq}`),
    rec(`_gc._tcp.${z}`, 'SRV', `0 100 3268 ${fq}`),
    rec(`_ldap._tcp.dc._msdcs.${z}`, 'SRV', `0 100 389 ${fq}`),
    rec(`_kerberos._tcp.dc._msdcs.${z}`, 'SRV', `0 100 88 ${fq}`),
    rec(`_ldap._tcp.pdc._msdcs.${z}`, 'SRV', `0 100 389 ${fq}`),
    rec(`gc._msdcs.${z}`, 'A', ip),
  ];
}

/**
 * Install-ADDSForest: the server becomes the first DC of a new forest. Its local
 * Administrator becomes the domain Administrator (same password), the DNS role
 * hosts the AD-integrated zone, the previous DNS servers become forwarders and
 * the server's own DNS client points at itself. Takes effect at the restart.
 */
export function promoteForest(world: World, host: Host, domain: string, netbios: string): void {
  const w = host.win!;
  const ip = w.adapters[0]?.address ?? '127.0.0.1';
  const dcName = host.hostname.toLowerCase();
  const sid = `S-1-5-21-${seededInt(`${domain}:a`, 1000000000, 3999999999)}-${seededInt(`${domain}:b`, 1000000000, 3999999999)}-${seededInt(`${domain}:c`, 100000000, 999999999)}`;
  const admin = host.users.Administrator;
  w.ad = {
    domain, netbios, domainSid: sid, lockoutThreshold: 5, nextRid: 1103,
    users: {
      administrator: { sam: 'Administrator', name: 'Administrator', enabled: true, password: admin?.password ?? '', lockedOut: false, badCount: 0, description: 'Built-in account for administering the computer/domain', rid: 500 },
      guest: { sam: 'Guest', name: 'Guest', enabled: false, password: '', lockedOut: false, badCount: 0, description: 'Built-in account for guest access to the computer/domain', rid: 501 },
      krbtgt: { sam: 'krbtgt', name: 'krbtgt', enabled: false, password: `krbtgt-${sid}`, lockedOut: false, badCount: 0, description: 'Key Distribution Center Service Account', rid: 502 },
    },
    groups: {
      'domain admins': { name: 'Domain Admins', scope: 'Global', category: 'Security', description: 'Designated administrators of the domain', members: ['Administrator'], rid: 512 },
      'domain users': { name: 'Domain Users', scope: 'Global', category: 'Security', description: 'All domain users', members: [], rid: 513 },
      'domain computers': { name: 'Domain Computers', scope: 'Global', category: 'Security', description: 'All workstations and servers joined to the domain', members: [], rid: 515 },
      'domain controllers': { name: 'Domain Controllers', scope: 'Global', category: 'Security', description: 'All domain controllers in the domain', members: [`${host.hostname.toUpperCase()}$`], rid: 516 },
      'enterprise admins': { name: 'Enterprise Admins', scope: 'Universal', category: 'Security', description: 'Designated administrators of the enterprise', members: ['Administrator'], rid: 519 },
      administrators: { name: 'Administrators', scope: 'DomainLocal', category: 'Security', description: 'Administrators have complete and unrestricted access to the computer/domain', members: ['Administrator', 'Domain Admins', 'Enterprise Admins'], rid: 544 },
    },
    computers: {
      [dcName]: { name: host.hostname.toUpperCase(), dnsHostName: `${dcName}.${domain}`, password: 'dc', enabled: true, os: w.productName, dc: true, rid: 1000 },
    },
  };
  gpData(w.ad);
  const forwarders = w.adapters.flatMap((a) => a.dns).filter((d) => d !== ip && !d.startsWith('127.'));
  w.dnsServer = { zones: [{ origin: `${domain}.`, records: dcRecords(domain, dcName, ip), serial: 1, dsIntegrated: true }], forwarders };
  for (const a of w.adapters) a.dns = ['127.0.0.1'];
  // Restartable AD DS (Windows Server 2008+): NTDS and the KDC can be stopped like other services.
  w.services.NTDS = { ...svc('NTDS', 'Active Directory Domain Services', 'lsass', ['RpcSs']), protected: false };
  w.services.Kdc = { ...svc('Kdc', 'Kerberos Key Distribution Center', 'lsass', ['NTDS']), protected: false };
  w.services.DNS = { ...svc('DNS', 'DNS Server', 'dns', ['RpcSs']), protected: false };
  w.services.ADWS = { ...svc('ADWS', 'Active Directory Web Services', 'Microsoft.ActiveDirectory.WebServices'), protected: false };
  if (w.services.Netlogon) w.services.Netlogon.startType = 'Automatic';
  w.features = [...new Set([...(w.features ?? []), 'AD-Domain-Services', 'DNS', 'RSAT-AD-PowerShell', 'RSAT-DNS-Server', 'GPMC'])];
  w.firewall.rules.push(
    fwRule('ADDS-LDAP-TCP-In', 'Active Directory Domain Controller - LDAP (TCP-In)', 'Active Directory Domain Services', 'TCP', '389'),
    fwRule('ADDS-LDAP-UDP-In', 'Active Directory Domain Controller - LDAP (UDP-In)', 'Active Directory Domain Services', 'UDP', '389'),
    fwRule('ADDS-LDAPS-TCP-In', 'Active Directory Domain Controller - Secure LDAP (TCP-In)', 'Active Directory Domain Services', 'TCP', '636'),
    fwRule('ADDS-LDAPGC-TCP-In', 'Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)', 'Active Directory Domain Services', 'TCP', '3268'),
    fwRule('KDC-TCP-In', 'Kerberos Key Distribution Center (TCP-In)', 'Kerberos Key Distribution Center', 'TCP', '88'),
    fwRule('KDC-UDP-In', 'Kerberos Key Distribution Center (UDP-In)', 'Kerberos Key Distribution Center', 'UDP', '88'),
    fwRule('KPWD-TCP-In', 'Kerberos Key Distribution Center - PCR (TCP-In)', 'Kerberos Key Distribution Center', 'TCP', '464'),
    fwRule('ADDS-W32Time-NTP-UDP-In', 'Active Directory Domain Controller - W32Time (NTP-UDP-In)', 'Active Directory Domain Services', 'UDP', '123'),
    fwRule('DNSSrv-TCP-In', 'DNS (TCP, Incoming)', 'DNS Service', 'TCP', '53'),
    fwRule('DNSSrv-UDP-In', 'DNS (UDP, Incoming)', 'DNS Service', 'UDP', '53'),
    fwRule('ADWS-TCP-In', 'Active Directory Web Services (TCP-In)', 'Active Directory Web Services', 'TCP', '9389'),
  );
  w.pendingDomain = { domain, netbios, machinePassword: 'dc' };
  w.workgroup = netbios;
  winEvent(world, host, 'Directory Service', 1000, 'NTDS General', `Microsoft Active Directory Domain Services startup complete, version 10.0.${w.build}.1`);
}

/** Create (or reset) the computer account and record the join for the next restart. */
export function joinDomain(world: World, member: Host, dc: Host, ouPath?: string): DomainMembership {
  const ad = dc.win!.ad!;
  const key = member.hostname.toLowerCase();
  const password = `mpw-${seededInt(`${member.id}:${world.counter}:${world.clock}`, 100000, 999999)}`;
  const existed = !!ad.computers[key];
  const ou = ouPath ? gpData(ad).ous[normDn(ouPath)]?.dn : ad.computers[key]?.ou;
  ad.computers[key] = { name: member.hostname.toUpperCase(), dnsHostName: `${key}.${ad.domain}`, password, enabled: true, os: member.win!.productName, rid: ad.computers[key]?.rid ?? ad.nextRid++, ...(ou ? { ou } : {}) };
  const dcomp = ad.groups['domain computers'];
  if (!dcomp.members.includes(`${member.hostname.toUpperCase()}$`)) dcomp.members.push(`${member.hostname.toUpperCase()}$`);
  if (!existed) winEvent(world, dc, 'Security', 4741, 'Microsoft-Windows-Security-Auditing', `A computer account was created.\n\nNew Computer Account:\n\tAccount Name:\t\t${member.hostname.toUpperCase()}$\n\tAccount Domain:\t\t${ad.netbios}`);
  const m = { domain: ad.domain, netbios: ad.netbios, machinePassword: password };
  member.win!.pendingDomain = m;
  return m;
}

/** Set a new machine password on both sides (Reset-ComputerMachinePassword, Test-ComputerSecureChannel -Repair). */
export function resetMachinePassword(world: World, member: Host, dc: Host): void {
  const comp = dc.win!.ad!.computers[member.hostname.toLowerCase()];
  const pw = `mpw-${seededInt(`${member.id}:reset:${world.counter}:${world.clock}`, 100000, 999999)}`;
  if (comp) { comp.password = pw; comp.enabled = true; }
  member.win!.domain!.machinePassword = pw;
}

function registerDns(world: World, host: Host, dc: Host): void {
  const zone = dc.win!.dnsServer?.zones.find((z) => z.origin === `${host.win!.domain!.domain}.`);
  const ip = host.win!.adapters[0]?.address;
  if (!zone || !ip || dc.win!.services.DNS?.status !== 'Running') return;
  // The DNS client registers with its primary DNS server: only when that is an AD DNS server for the zone.
  const primary = host.win!.adapters[0]?.dns[0];
  const dcIps = dc.ifaces.map((i) => i.address).filter(Boolean);
  if (!primary || !(dcIps.includes(primary) || (dc === host && primary.startsWith('127.')))) return;
  const name = `${host.hostname.toLowerCase()}.${zone.origin}`;
  zone.records = zone.records.filter((r) => !(r.name === name && r.type === 'A'));
  zone.records.push({ name, type: 'A', data: ip, ttl: 1200 });
  zone.serial++;
  void world;
}

/** Boot-time domain work: apply a pending join, start Netlogon, locate a DC. */
export function domainBoot(world: World, host: Host): void {
  const w = host.win!;
  // Ticket caches live in LSA's memory.
  delete w.krb;
  if (w.pendingDomain !== undefined) {
    if (w.pendingDomain === null) {
      delete w.domain;
      delete w.localDomainMembers;
      clearGroupPolicy(host);
      if (w.services.Netlogon) w.services.Netlogon.startType = 'Manual';
    } else {
      w.domain = w.pendingDomain;
      w.workgroup = w.pendingDomain.netbios;
      if (!w.ad) w.localDomainMembers ??= { Administrators: [`${w.domain.netbios}\\Domain Admins`], Users: [`${w.domain.netbios}\\Domain Users`] };
      if (w.services.Netlogon) w.services.Netlogon.startType = 'Automatic';
    }
    delete w.pendingDomain;
  }
  if (!w.domain) return;
  if (w.services.Netlogon?.startType === 'Automatic') startWinService(world, host, 'Netlogon');
  const ch = secureChannel(world, host);
  if (ch.state === 'no-dc') {
    noLogonServers(world, host);
    return;
  }
  const loc = ch.dc as Extract<DcLocation, { ok: true }>;
  if (ch.state === 'denied') trustFailed(world, host, loc.name);
  w.domainNetwork = true;
  applyFirewall(host);
  registerDns(world, host, loc.dc);
  // W32Time tried the DC when it started; if the DC was not reachable yet, it tries again now.
  if (w.services.W32Time?.status === 'Running' && !w.timeSync?.ok) timeSync(world, host);
  // Computer startup policy (the trust must work: the computer binds with its account).
  if (ch.state === 'ok') startupGroupPolicy(world, host);
}
