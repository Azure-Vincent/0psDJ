// LDAP against Active Directory: dc01 answers LDAP (389), LDAPS (636) and the
// global catalog (3268) from its AD database. The directory is built from the
// AD model (domain, containers, OUs, users, groups, computers) with the
// attributes clients read (sAMAccountName, userPrincipalName, memberOf, member,
// userAccountControl …). Binds follow AD's rules and error codes (data 52e,
// 533, 775 …), searches without a bind are refused, the LDAP server signing
// policy (LDAPServerIntegrity = 2) refuses simple binds without TLS, and LDAPS
// needs a server certificate in the DC's computer store.

import { readFile } from '../fs';
import type { Host, World } from '../types';
import { domainDn, NTDS_PARAMS } from '../win/ad';
import type { AdState, AdUser } from '../win/model';
import { winEvent } from '../win/model';
import { resolve } from './dns';
import { type Cert, matchesHost, trustStore, VERIFY_TEXT, verifyChain } from './pki';
import { allListeners } from './services';
import { tcpConnect } from './tcp';

export { NTDS_PARAMS };

export interface LdapEntry { dn: string; attrs: Record<string, string[]> }

const UPPER_DC = (domain: string) => domainDn(domain);

/** Where a user object lives: its OU (from New-ADUser -Path), or CN=Users. */
export const userContainer = (ad: AdState, u: AdUser) => u.ou ?? `CN=Users,${UPPER_DC(ad.domain)}`;
export const userDnOf = (ad: AdState, u: AdUser) => `CN=${u.name},${userContainer(ad, u)}`;
const groupDnOf = (ad: AdState, g: AdState['groups'][string]) => `CN=${g.name},${g.rid < 1000 && g.scope === 'DomainLocal' ? 'CN=Builtin' : 'CN=Users'},${UPPER_DC(ad.domain)}`;

/** AD's 18-digit FILETIME (100 ns since 1601) for a timestamp. */
const filetime = (ms: number) => String(Math.floor(ms * 10_000 + 116_444_736_000_000_000));
const generalized = (ms: number) => new Date(Math.floor(ms)).toISOString().replace(/[-:T]/g, '').replace(/\.\d+Z$/, '.0Z');

const GROUP_TYPE: Record<string, number> = { 'Global/Security': -2147483646, 'DomainLocal/Security': -2147483644, 'Universal/Security': -2147483640, 'Global/Distribution': 2, 'DomainLocal/Distribution': 4, 'Universal/Distribution': 8 };

/** Every object of the directory, built from the AD database. */
export function directory(dc: Host): LdapEntry[] {
  const ad = dc.win!.ad!;
  const base = UPPER_DC(ad.domain);
  const created = Date.parse('2026-09-01T09:12:44Z');
  const out: LdapEntry[] = [];
  const add = (dn: string, attrs: Record<string, string | string[] | undefined>) => {
    const a: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(attrs)) if (v !== undefined && !(Array.isArray(v) && !v.length)) a[k] = Array.isArray(v) ? v : [v];
    a.distinguishedName = [dn];
    out.push({ dn, attrs: a });
  };
  add(base, { objectClass: ['top', 'domain', 'domainDNS'], dc: ad.domain.split('.')[0], name: ad.domain.split('.')[0], whenCreated: generalized(created) });
  for (const [cn, desc] of [['Users', 'Default container for upgraded user accounts'], ['Computers', 'Default container for upgraded computer accounts'], ['Builtin', '']] as const) {
    add(`CN=${cn},${base}`, { objectClass: cn === 'Builtin' ? ['top', 'builtinDomain'] : ['top', 'container'], cn, name: cn, description: desc || undefined });
  }
  add(`OU=Domain Controllers,${base}`, { objectClass: ['top', 'organizationalUnit'], ou: 'Domain Controllers', name: 'Domain Controllers', description: 'Default container for domain controllers' });
  for (const o of Object.values(ad.ous ?? {})) add(o.dn, { objectClass: ['top', 'organizationalUnit'], ou: o.name, name: o.name, description: o.description || undefined });
  const memberOf = (sam: string) => Object.values(ad.groups).filter((g) => g.members.some((m) => m.toLowerCase() === sam.toLowerCase())).map((g) => groupDnOf(ad, g));
  for (const u of Object.values(ad.users)) {
    const dn = userDnOf(ad, u);
    const [given, ...rest] = u.name.split(' ');
    add(dn, {
      objectClass: ['top', 'person', 'organizationalPerson', 'user'], cn: u.name, name: u.name, displayName: u.name,
      givenName: rest.length ? given : undefined, sn: rest.length ? rest.join(' ') : undefined,
      sAMAccountName: u.sam, userPrincipalName: `${u.sam}@${ad.domain}`, description: u.description || undefined,
      mail: u.rid >= 1000 ? `${u.sam.toLowerCase()}@corp.lab` : undefined,
      memberOf: memberOf(u.sam), primaryGroupID: '513',
      userAccountControl: String(512 | (u.enabled ? 0 : 2)), lockoutTime: u.lockedOut ? filetime(created + 86_400_000) : '0',
      badPwdCount: String(u.badCount), lastLogonTimestamp: u.lastLogon ? filetime(u.lastLogon) : undefined,
      sAMAccountType: '805306368', objectCategory: `CN=Person,CN=Schema,CN=Configuration,${base}`, whenCreated: generalized(created),
      servicePrincipalName: u.spns,
    });
  }
  for (const g of Object.values(ad.groups)) {
    const members = g.members.map((m) => {
      const u = Object.values(ad.users).find((x) => x.sam.toLowerCase() === m.toLowerCase());
      if (u) return userDnOf(ad, u);
      const gg = Object.values(ad.groups).find((x) => x.name.toLowerCase() === m.toLowerCase());
      if (gg) return groupDnOf(ad, gg);
      const c = Object.values(ad.computers).find((x) => `${x.name}$`.toLowerCase() === m.toLowerCase());
      return c ? `CN=${c.name},${c.ou ?? (c.dc ? `OU=Domain Controllers,${base}` : `CN=Computers,${base}`)}` : undefined;
    }).filter((x): x is string => !!x);
    add(groupDnOf(ad, g), {
      objectClass: ['top', 'group'], cn: g.name, name: g.name, sAMAccountName: g.name, description: g.description || undefined,
      member: members, memberOf: memberOf(g.name), groupType: String(GROUP_TYPE[`${g.scope}/${g.category}`] ?? -2147483646),
      objectCategory: `CN=Group,CN=Schema,CN=Configuration,${base}`, whenCreated: generalized(created),
    });
  }
  for (const c of Object.values(ad.computers)) {
    const dn = `CN=${c.name},${c.ou ?? (c.dc ? `OU=Domain Controllers,${base}` : `CN=Computers,${base}`)}`;
    add(dn, {
      objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'], cn: c.name, name: c.name, sAMAccountName: `${c.name}$`,
      dNSHostName: c.dnsHostName, operatingSystem: c.os, userAccountControl: String(c.dc ? 532480 : 4096 | (c.enabled ? 0 : 2)),
      memberOf: memberOf(`${c.name}$`), objectCategory: `CN=Computer,CN=Schema,CN=Configuration,${base}`, servicePrincipalName: c.spns,
    });
  }
  return out;
}

/** The RootDSE: readable without a bind. */
export function rootDse(dc: Host): LdapEntry {
  const ad = dc.win!.ad!;
  const base = UPPER_DC(ad.domain);
  const fq = `${dc.hostname}.${ad.domain}`;
  return {
    dn: '',
    attrs: {
      defaultNamingContext: [base], rootDomainNamingContext: [base],
      namingContexts: [base, `CN=Configuration,${base}`, `CN=Schema,CN=Configuration,${base}`, `DC=DomainDnsZones,${base}`, `DC=ForestDnsZones,${base}`],
      dnsHostName: [fq], ldapServiceName: [`${ad.domain}:${dc.hostname}$@${ad.domain.toUpperCase()}`],
      serverName: [`CN=${dc.hostname.toUpperCase()},CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,${base}`],
      supportedLDAPVersion: ['3', '2'], supportedSASLMechanisms: ['GSSAPI', 'GSS-SPNEGO', 'EXTERNAL', 'DIGEST-MD5'],
      isGlobalCatalogReady: ['TRUE'], isSynchronized: ['TRUE'], domainFunctionality: ['7'], forestFunctionality: ['7'], domainControllerFunctionality: ['7'],
    },
  };
}

// ---------------------------------------------------------------------------
// Filters (RFC 4515)
// ---------------------------------------------------------------------------

export type Filter =
  | { t: 'and' | 'or'; f: Filter[] }
  | { t: 'not'; f: Filter }
  | { t: 'eq' | 'ge' | 'le' | 'approx'; attr: string; value: string }
  | { t: 'present'; attr: string }
  | { t: 'sub'; attr: string; parts: (string | null)[] };

export function parseFilter(text: string): Filter | null {
  let s = text.trim();
  if (!s.startsWith('(')) s = `(${s})`;
  let i = 0;
  const unescape = (v: string) => v.replace(/\\([0-9a-fA-F]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)));
  const one = (): Filter | null => {
    if (s[i] !== '(') return null;
    i++;
    const c = s[i];
    if (c === '&' || c === '|') {
      i++;
      const f: Filter[] = [];
      while (s[i] === '(') { const x = one(); if (!x) return null; f.push(x); }
      if (s[i] !== ')' || !f.length) return null;
      i++;
      return { t: c === '&' ? 'and' : 'or', f };
    }
    if (c === '!') {
      i++;
      const x = one();
      if (!x || s[i] !== ')') return null;
      i++;
      return { t: 'not', f: x };
    }
    let depth = 0;
    let j = i;
    for (; j < s.length; j++) { if (s[j] === '(') depth++; if (s[j] === ')') { if (depth === 0) break; depth--; } }
    if (j >= s.length) return null;
    const body = s.slice(i, j);
    i = j + 1;
    const m = /^([a-zA-Z][\w-]*(?:;[\w-]+)*|\d+(?:\.\d+)+)(?::[\d.]+:)?(>=|<=|~=|=)(.*)$/.exec(body);
    if (!m) return null;
    const [, attr, op, value] = m;
    if (op === '>=') return { t: 'ge', attr, value: unescape(value) };
    if (op === '<=') return { t: 'le', attr, value: unescape(value) };
    if (op === '~=') return { t: 'approx', attr, value: unescape(value) };
    if (value === '*') return { t: 'present', attr };
    if (value.includes('*')) return { t: 'sub', attr, parts: value.split('*').map((p) => (p === '' ? null : unescape(p))) };
    return { t: 'eq', attr, value: unescape(value) };
  };
  const f = one();
  return f && i === s.length ? f : null;
}

const attrValues = (e: LdapEntry, attr: string): string[] => {
  const k = Object.keys(e.attrs).find((x) => x.toLowerCase() === attr.toLowerCase());
  return k ? e.attrs[k] : [];
};

export function matchFilter(e: LdapEntry, f: Filter): boolean {
  switch (f.t) {
    case 'and': return f.f.every((x) => matchFilter(e, x));
    case 'or': return f.f.some((x) => matchFilter(e, x));
    case 'not': return !matchFilter(e, f.f);
    case 'present': return f.attr.toLowerCase() === 'objectclass' || attrValues(e, f.attr).length > 0;
    case 'eq': case 'approx': {
      const v = f.value.toLowerCase();
      // objectCategory=person is shorthand for the category's DN.
      if (f.attr.toLowerCase() === 'objectcategory' && !v.includes('=')) return attrValues(e, 'objectCategory').some((x) => x.toLowerCase().startsWith(`cn=${v},`));
      return attrValues(e, f.attr).some((x) => x.toLowerCase() === v);
    }
    case 'ge': return attrValues(e, f.attr).some((x) => (/^-?\d+$/.test(x) ? Number(x) >= Number(f.value) : x.toLowerCase() >= f.value.toLowerCase()));
    case 'le': return attrValues(e, f.attr).some((x) => (/^-?\d+$/.test(x) ? Number(x) <= Number(f.value) : x.toLowerCase() <= f.value.toLowerCase()));
    case 'sub': {
      const rx = new RegExp(`^${f.parts.map((p) => (p === null ? '' : p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('.*')}$`, 'i');
      return attrValues(e, f.attr).some((x) => rx.test(x));
    }
  }
}

// ---------------------------------------------------------------------------
// The protocol: connect, TLS, bind, search
// ---------------------------------------------------------------------------

export interface LdapUri { scheme: 'ldap' | 'ldaps'; host: string; port: number }
export function parseLdapUri(uri: string): LdapUri | null {
  const m = /^(ldaps?):\/\/(\[[^\]]+\]|[^/:]*)(?::(\d+))?\/?$/i.exec(uri.trim());
  if (!m) return null;
  const scheme = m[1].toLowerCase() as 'ldap' | 'ldaps';
  return { scheme, host: m[2].replace(/^\[|\]$/g, '') || 'localhost', port: Number(m[3] ?? (scheme === 'ldaps' ? 636 : 389)) };
}

export interface LdapClientConf { caFile: string; reqcert: 'never' | 'allow' | 'try' | 'demand' | 'hard'; base?: string; uri?: string; binddn?: string }

/** /etc/ldap/ldap.conf (and ~/.ldaprc) as libldap reads them. */
export function clientConf(host: Host, home?: string): LdapClientConf {
  const conf: LdapClientConf = { caFile: '/etc/ssl/certs/ca-certificates.crt', reqcert: 'demand' };
  for (const f of ['/etc/ldap/ldap.conf', ...(home ? [`${home}/.ldaprc`, `${home}/ldaprc`] : [])]) {
    for (const raw of (readFile(host, f) ?? '').split('\n')) {
      const m = /^\s*([A-Za-z_]+)\s+(.+?)\s*$/.exec(raw.replace(/#.*$/, ''));
      if (!m) continue;
      const k = m[1].toUpperCase();
      if (k === 'TLS_CACERT') conf.caFile = m[2];
      else if (k === 'TLS_REQCERT') conf.reqcert = m[2].toLowerCase() as LdapClientConf['reqcert'];
      else if (k === 'BASE') conf.base = m[2];
      else if (k === 'URI') conf.uri = m[2].split(/\s+/)[0];
      else if (k === 'BINDDN') conf.binddn = m[2];
    }
  }
  return conf;
}

/** An open LDAP session on a domain controller. */
export interface LdapSession {
  dc: Host;
  tls: boolean;
  /** The bound principal (sAMAccountName), or null when anonymous. */
  bound: string | null;
}

export type LdapError = { code: number; name: string; info?: string; matched?: string };

const ERR = (code: number, name: string, info?: string, matched?: string): LdapError => ({ code, name, info, matched });
export const CANT_CONTACT = (info?: string): LdapError => ERR(-1, "Can't contact LDAP server", info);

/** Does the DC have a usable certificate for LDAPS / StartTLS? */
function dcCertificate(dc: Host): { cert: Cert; chain: Cert[] } | null {
  const certs = dc.win!.certificates ?? [];
  return certs.find((c) => c.hasKey !== false && c.cert.san.some((s) => s.toLowerCase() === `dns:${dc.hostname}.${dc.win!.ad!.domain}`.toLowerCase())) ?? null;
}

/** TLS from the client's point of view: certificate verification and host-name check, as libldap with OpenSSL reports them. */
function tlsCheck(world: World, client: Host, dc: Host, name: string, conf: LdapClientConf): LdapError | null {
  const c = dcCertificate(dc);
  if (!c) return CANT_CONTACT('error:0A000126:SSL routines::unexpected eof while reading');
  if (conf.reqcert === 'never' || conf.reqcert === 'allow') return null;
  const trusted = trustStore(client, conf.caFile);
  if (!client.fs[conf.caFile]) return CANT_CONTACT(`could not load CA certificate file ${conf.caFile}`);
  const v = verifyChain(c.cert, c.chain, trusted, world.clock);
  // 'try' and 'demand'/'hard' all end the session on a bad certificate; only 'allow' goes on.
  if (!v.ok) return CANT_CONTACT(`error:0A000086:SSL routines::certificate verify failed (${VERIFY_TEXT[v.errors[0]?.code ?? 20]})`);
  if (!matchesHost(c.cert, name)) return CANT_CONTACT('TLS: hostname does not match CN in peer certificate');
  return null;
}

/** Open a connection to an LDAP URI from `client` (TCP, then TLS for ldaps://). */
export function ldapConnect(world: World, client: Host, uri: LdapUri, conf: LdapClientConf, startTls = false): { session: LdapSession } | { error: LdapError } {
  const r = resolve(world, client, uri.host === 'localhost' ? '127.0.0.1' : uri.host, { family: 4 });
  if (!r.ok) return { error: CANT_CONTACT() };
  const c = tcpConnect(world, client, r.ip, uri.port, { timeoutMs: 30_000 });
  if (!c.ok) return { error: CANT_CONTACT() };
  const server = c.conn.server;
  const l = allListeners(server).find((x) => x.proto === 'tcp' && x.port === c.conn.sv.localPort);
  c.conn.send('c2s', 60, { protocol: 'LDAP', info: uri.scheme === 'ldaps' ? 'TLS Client Hello' : 'bindRequest', fields: [] });
  if (!server.win?.ad || l?.service !== 'NTDS') { c.conn.close('server'); return { error: CANT_CONTACT() }; }
  if (uri.scheme === 'ldaps' || startTls) {
    const e = tlsCheck(world, client, server, uri.host, conf);
    if (e) {
      c.conn.close('client');
      return { error: startTls ? { ...e, code: -11, name: 'Connect error' } : e };
    }
  }
  c.conn.close('client');
  return { session: { dc: server, tls: uri.scheme === 'ldaps' || startTls, bound: null } };
}

/** The server signing policy in force: 2 = "Require signing" (simple binds need TLS). */
export function signingRequired(dc: Host): boolean {
  return Number(dc.win!.registry[NTDS_PARAMS]?.LDAPServerIntegrity ?? 1) >= 2;
}

const BIND_FAIL = (data: string) => ERR(49, 'Invalid credentials', `80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data ${data}, v4563`);

/** A simple bind (DN, UPN or DOMAIN\user and a password), as AD answers it. */
export function ldapBind(world: World, s: LdapSession, client: Host, who: string, password: string): LdapError | null {
  const ad = s.dc.win!.ad!;
  if (!who) { s.bound = null; return null; } // anonymous
  if (!password) { s.bound = null; return null; } // unauthenticated bind = anonymous in AD
  if (!s.tls && signingRequired(s.dc)) return ERR(8, 'Strong(er) authentication required', '00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking if SSL\\TLS are not already active on the connection, data 0, v4563');
  const lw = who.toLowerCase();
  const u = Object.values(ad.users).find((x) => userDnOf(ad, x).toLowerCase() === lw || `${x.sam}@${ad.domain}`.toLowerCase() === lw || `${ad.netbios}\\${x.sam}`.toLowerCase() === lw);
  const audit = (ok: boolean, status: string) => winEvent(world, s.dc, 'Security', ok ? 4624 : 4625, 'Microsoft-Windows-Security-Auditing',
    ok ? `An account was successfully logged on.\n\nLogon Type:\t\t3\n\nNew Logon:\n\tAccount Name:\t\t${u?.sam}\n\tAccount Domain:\t\t${ad.netbios}\n\nNetwork Information:\n\tSource Network Address:\t${client.ifaces.find((i) => i.name === 'eth0')?.address ?? ''}\n\nDetailed Authentication Information:\n\tLogon Process:\t\tAdvapi\n\tAuthentication Package:\tMICROSOFT_AUTHENTICATION_PACKAGE_V1_0`
      : `An account failed to log on.\n\nLogon Type:\t\t3\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\t${u?.sam ?? who}\n\nFailure Information:\n\tStatus:\t\t\t${status}\n\nNetwork Information:\n\tSource Network Address:\t${client.ifaces.find((i) => i.name === 'eth0')?.address ?? ''}`);
  if (!u) { audit(false, '0xC000006D'); return BIND_FAIL('52e'); }
  if (u.lockedOut) { audit(false, '0xC0000234'); return BIND_FAIL('775'); }
  if (u.password !== password) {
    u.badCount++;
    audit(false, '0xC000006D');
    if (ad.lockoutThreshold > 0 && u.badCount >= ad.lockoutThreshold) {
      u.lockedOut = true;
      winEvent(world, s.dc, 'Security', 4740, 'Microsoft-Windows-Security-Auditing', `A user account was locked out.\n\nAccount That Was Locked Out:\n\tAccount Name:\t\t${u.sam}\n\nAdditional Information:\n\tCaller Computer Name:\t${client.hostname.toUpperCase()}`);
    }
    return BIND_FAIL('52e');
  }
  if (!u.enabled) { audit(false, '0xC0000072'); return BIND_FAIL('533'); }
  u.badCount = 0;
  u.lastLogon = world.clock;
  audit(true, '');
  s.bound = u.sam;
  return null;
}

export type Scope = 'base' | 'one' | 'sub' | 'children';

export interface SearchResult { entries: LdapEntry[]; refs: string[]; error?: LdapError }

/** A search as AD answers it: RootDSE for everyone, the rest only after a bind. */
export function ldapSearch(s: LdapSession, base: string, scope: Scope, filter: Filter, attrs: string[], gc = false): SearchResult {
  if (base === '' && scope === 'base') {
    const r = rootDse(s.dc);
    return { entries: matchFilter(r, filter) ? [project(r, attrs)] : [], refs: [] };
  }
  if (!s.bound) return { entries: [], refs: [], error: ERR(1, 'Operations error', '000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563') };
  const all = directory(s.dc);
  const b = base.toLowerCase().replace(/\s*,\s*/g, ',');
  const baseEntry = all.find((e) => e.dn.toLowerCase() === b);
  const domain = UPPER_DC(s.dc.win!.ad!.domain);
  if (!baseEntry) {
    const matched = all.filter((e) => b.endsWith(',' + e.dn.toLowerCase())).sort((x, y) => y.dn.length - x.dn.length)[0]?.dn ?? '';
    return { entries: [], refs: [], error: ERR(32, 'No such object', `0000208D: NameErr: DSID-0310028B, problem 2001 (NO_OBJECT), data 0, best match of:\n\t'${matched}'`, matched) };
  }
  const inScope = (e: LdapEntry) => {
    const dn = e.dn.toLowerCase();
    if (scope === 'base') return dn === b;
    const parent = dn.slice(dn.indexOf(',') + 1);
    if (scope === 'one') return parent === b;
    if (scope === 'children') return dn.endsWith(',' + b);
    return dn === b || dn.endsWith(',' + b);
  };
  const entries = all.filter((e) => inScope(e) && matchFilter(e, filter)).map((e) => project(e, attrs));
  // A subtree search from the domain root is referred to the application partitions (not on the global catalog).
  const refs = !gc && (scope === 'sub') && b === domain.toLowerCase()
    ? [`ldap://ForestDnsZones.${s.dc.win!.ad!.domain}/DC=ForestDnsZones,${domain}`, `ldap://DomainDnsZones.${s.dc.win!.ad!.domain}/DC=DomainDnsZones,${domain}`, `ldap://${s.dc.win!.ad!.domain}/CN=Configuration,${domain}`]
    : [];
  return { entries, refs };
}

/** Only the requested attributes ("*" or none: all user attributes; "+": none here; "1.1": no attributes). */
function project(e: LdapEntry, attrs: string[]): LdapEntry {
  if (!attrs.length || attrs.includes('*')) return e;
  if (attrs.length === 1 && attrs[0] === '1.1') return { dn: e.dn, attrs: {} };
  const out: Record<string, string[]> = {};
  for (const a of attrs) {
    const k = Object.keys(e.attrs).find((x) => x.toLowerCase() === a.toLowerCase());
    if (k) out[k] = e.attrs[k];
  }
  return { dn: e.dn, attrs: out };
}

/** LDIF value: plain, or base64 ("::") when it is not safe as-is. */
export function ldifLine(attr: string, v: string): string {
  const safe = /^[\x01-\x09\x0b\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f][\x01-\x09\x0b\x0c\x0e-\x7f]*$/.test(v) && !/ $/.test(v);
  if (v === '') return `${attr}:`;
  return safe ? `${attr}: ${v}` : `${attr}:: ${btoa(String.fromCharCode(...new TextEncoder().encode(v)))}`;
}
