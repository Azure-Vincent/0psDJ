// MIT Kerberos 5 configuration and data files: krb5.conf (clients), kdc.conf
// and kadm5.acl (KDC), the principal database, keytabs and credential caches.
//
// The principal database, keytabs and credential caches are binary files in real
// MIT krb5; the simulator stores them as text with the same information so the
// tools (kadmin.local, klist -k, klist) can show it. Keys are synthetic: a
// SHA-256 digest of the principal (the salt) and the password or a random seed.

import { sha256Hex } from '../util/sha256';

// ---------------------------------------------------------------------------
// profile format (krb5.conf, kdc.conf): [sections], "tag = value", "TAG = { … }"
// ---------------------------------------------------------------------------

export type Profile = Record<string, Record<string, string[] | Record<string, string[]>>>;

export class ProfileError extends Error {}

export function parseProfile(text: string): Profile {
  const out: Profile = {};
  let section: string | null = null;
  const stack: { name: string; body: Record<string, string[]> }[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/^\s*[#;].*$/, '').trim();
    if (!line) return;
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) {
      if (stack.length) throw new ProfileError(`line ${i + 1}: missing "}"`);
      section = sec[1].trim();
      out[section] ??= {};
      return;
    }
    if (line === '}') {
      if (!stack.length) throw new ProfileError(`line ${i + 1}: unexpected "}"`);
      const done = stack.pop()!;
      if (section) out[section][done.name] = done.body;
      return;
    }
    const m = /^([^=\s]+)\s*=\s*(.*)$/.exec(line);
    if (!m || !section) throw new ProfileError(`line ${i + 1}: syntax error`);
    const [, tag, value] = m;
    if (value === '{') {
      if (stack.length) throw new ProfileError(`line ${i + 1}: nested relations are not supported`);
      stack.push({ name: tag, body: {} });
      return;
    }
    if (stack.length) (stack[stack.length - 1].body[tag] ??= []).push(value.trim());
    else {
      const cur = out[section][tag];
      out[section][tag] = Array.isArray(cur) ? [...cur, value.trim()] : [value.trim()];
    }
  });
  if (stack.length) throw new ProfileError('missing "}" at end of file');
  return out;
}

function flat(p: Profile, section: string, tag: string): string | undefined {
  const v = p[section]?.[tag];
  return Array.isArray(v) ? v[0] : undefined;
}

function bool(v: string | undefined, dflt: boolean): boolean {
  if (v === undefined) return dflt;
  return /^(true|yes|on|1)$/i.test(v);
}

/** krb5 duration: "10h", "7d", "10h 0m 0s", "1d 2h", "36000" (seconds). Returns seconds. */
export function parseDuration(v: string | undefined, dflt: number): number {
  if (!v) return dflt;
  if (/^\d+$/.test(v.trim())) return Number(v.trim());
  let total = 0;
  let matched = false;
  for (const m of v.matchAll(/(\d+)\s*([dhms])/g)) {
    matched = true;
    total += Number(m[1]) * { d: 86400, h: 3600, m: 60, s: 1 }[m[2] as 'd' | 'h' | 'm' | 's'];
  }
  return matched ? total : dflt;
}

export interface Krb5Conf {
  defaultRealm?: string;
  dnsLookupKdc: boolean;
  ticketLifetime: number;
  renewLifetime: number;
  clockskew: number;
  rdns: boolean;
  realms: Record<string, { kdc: string[]; adminServer?: string }>;
  domainRealm: Record<string, string>;
}

/** /etc/krb5.conf. Throws ProfileError on syntax errors (the library refuses to initialise). */
export function parseKrb5Conf(text: string | undefined): Krb5Conf {
  const p = parseProfile(text ?? '');
  const realms: Krb5Conf['realms'] = {};
  for (const [name, body] of Object.entries(p.realms ?? {})) {
    if (Array.isArray(body)) continue;
    realms[name] = { kdc: body.kdc ?? [], adminServer: body.admin_server?.[0] };
  }
  const domainRealm: Record<string, string> = {};
  for (const [k, v] of Object.entries(p.domain_realm ?? {})) if (Array.isArray(v)) domainRealm[k.toLowerCase()] = v[0];
  return {
    defaultRealm: flat(p, 'libdefaults', 'default_realm'),
    dnsLookupKdc: bool(flat(p, 'libdefaults', 'dns_lookup_kdc'), true),
    ticketLifetime: parseDuration(flat(p, 'libdefaults', 'ticket_lifetime'), 86400),
    renewLifetime: parseDuration(flat(p, 'libdefaults', 'renew_lifetime'), 0),
    clockskew: parseDuration(flat(p, 'libdefaults', 'clockskew'), 300),
    rdns: bool(flat(p, 'libdefaults', 'rdns'), true),
    realms,
    domainRealm,
  };
}

export interface KdcConf {
  realms: Record<string, { databaseName: string; aclFile: string; maxLife: number; maxRenewableLife: number; kdcPorts: number[]; kdcTcpPorts: number[] }>;
}

function ports(v: string | undefined, dflt: number[]): number[] {
  if (v === undefined) return dflt;
  return v.split(/[\s,]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n) && n > 0 && n < 65536);
}

export function parseKdcConf(text: string | undefined): KdcConf {
  const p = parseProfile(text ?? '');
  const defPorts = ports(flat(p, 'kdcdefaults', 'kdc_ports'), [88, 750]);
  const defTcp = ports(flat(p, 'kdcdefaults', 'kdc_tcp_ports'), [88]);
  const realms: KdcConf['realms'] = {};
  for (const [name, body] of Object.entries(p.realms ?? {})) {
    if (Array.isArray(body)) continue;
    realms[name] = {
      databaseName: body.database_name?.[0] ?? '/var/lib/krb5kdc/principal',
      aclFile: body.acl_file?.[0] ?? '/etc/krb5kdc/kadm5.acl',
      maxLife: parseDuration(body.max_life?.[0], 86400),
      maxRenewableLife: parseDuration(body.max_renewable_life?.[0], 0),
      kdcPorts: ports(body.kdc_ports?.[0], defPorts),
      kdcTcpPorts: ports(body.kdc_tcp_ports?.[0], defTcp),
    };
  }
  return { realms };
}

// ---------------------------------------------------------------------------
// Principals and keys
// ---------------------------------------------------------------------------

export const ENCTYPES = ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96'] as const;

/** Long-term key of a principal: string-to-key(password, salt = principal name). */
export function deriveKey(principal: string, secret: string): string {
  return sha256Hex(`krb5-key:${principal}:${secret}`).slice(0, 32);
}

/** "alice" → "alice@CORP.LAB"; keeps an explicit realm. */
export function qualify(name: string, realm: string): string {
  return name.includes('@') ? name : `${name}@${realm}`;
}

export function realmOf(principal: string): string {
  return principal.slice(principal.lastIndexOf('@') + 1);
}

export interface PrincipalEntry {
  name: string;
  kvno: number;
  key: string;
  attributes: string[];
  created: number;
  modified: number;
  modifiedBy: string;
  lastPwChange: number;
  lastSuccess?: number;
  lastFailed?: number;
  failedCount: number;
}

const DB_HEADER = `# Kerberos principal database (simulated as text; on a real KDC this is a
# binary database: read and change it only with kadmin.local or kadmin)
# name	kvno	key	attributes	created	modified	modified-by	last-pwchange	last-success	last-failed	failed-count
`;

export function parsePrincipalDb(text: string | undefined): PrincipalEntry[] | null {
  if (text === undefined) return null;
  const out: PrincipalEntry[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    const f = line.split('\t');
    if (f.length < 11) continue;
    out.push({
      name: f[0], kvno: Number(f[1]), key: f[2], attributes: f[3] ? f[3].split(',') : [],
      created: Number(f[4]), modified: Number(f[5]), modifiedBy: f[6], lastPwChange: Number(f[7]),
      lastSuccess: f[8] ? Number(f[8]) : undefined, lastFailed: f[9] ? Number(f[9]) : undefined, failedCount: Number(f[10]) || 0,
    });
  }
  return out;
}

export function formatPrincipalDb(entries: PrincipalEntry[]): string {
  return DB_HEADER + entries.map((e) => [e.name, e.kvno, e.key, e.attributes.join(','), e.created, e.modified, e.modifiedBy, e.lastPwChange, e.lastSuccess ?? '', e.lastFailed ?? '', e.failedCount].join('\t')).join('\n') + '\n';
}

export function newPrincipal(name: string, secret: string, time: number, by: string, attributes = ['REQUIRES_PRE_AUTH']): PrincipalEntry {
  return { name, kvno: 1, key: deriveKey(name, secret), attributes, created: time, modified: time, modifiedBy: by, lastPwChange: time, failedCount: 0 };
}

// ---------------------------------------------------------------------------
// kadm5.acl: "principal-pattern  permissions"
// ---------------------------------------------------------------------------

export interface AclEntry { pattern: string; perms: string }

export function parseKadmAcl(text: string | undefined): AclEntry[] {
  return (text ?? '').split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean).map((l) => {
    const [pattern, perms = ''] = l.split(/\s+/);
    return { pattern, perms };
  });
}

function globMatch(pattern: string, s: string): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^@]*')}$`);
  return re.test(s);
}

/** Does `principal` have permission letter `p` (a add, d delete, m modify, c change password, i inquire, l list, x/* all)? */
export function aclAllows(acl: AclEntry[], principal: string, p: string): boolean {
  const e = acl.find((x) => globMatch(x.pattern, principal));
  if (!e) return false;
  return e.perms.includes('*') || e.perms.includes('x') || e.perms.includes(p);
}

// ---------------------------------------------------------------------------
// Keytabs and credential caches
// ---------------------------------------------------------------------------

export interface KeytabEntry { kvno: number; principal: string; enctype: string; key: string; timestamp: number }

const KEYTAB_HEADER = '# Kerberos keytab (simulated as text; real keytabs are binary: list them with klist -k)\n';

export function parseKeytab(text: string | undefined): KeytabEntry[] | null {
  if (text === undefined) return null;
  return text.split('\n').filter((l) => l.trim() && !l.startsWith('#')).map((l) => {
    const [kvno, principal, enctype, key, ts] = l.split('\t');
    return { kvno: Number(kvno), principal, enctype, key, timestamp: Number(ts) || 0 };
  });
}

export function formatKeytab(entries: KeytabEntry[]): string {
  return KEYTAB_HEADER + entries.map((e) => [e.kvno, e.principal, e.enctype, e.key, e.timestamp].join('\t')).join('\n') + (entries.length ? '\n' : '');
}

export interface CachedTicket {
  server: string;
  /** Times are the KDC's clock when issued (ms). */
  start: number;
  end: number;
  renewTill?: number;
  /** Key version of the service key that encrypted the ticket, and a digest of that key. */
  kvno: number;
  serviceKey: string;
}

export interface CredCache { principal: string; tickets: CachedTicket[] }

export function parseCache(text: string | undefined): CredCache | null {
  if (text === undefined) return null;
  let principal = '';
  const tickets: CachedTicket[] = [];
  for (const l of text.split('\n')) {
    if (!l.trim() || l.startsWith('#')) continue;
    const f = l.split('\t');
    if (f[0] === 'principal') principal = f[1];
    else if (f[0] === 'ticket') tickets.push({ server: f[1], start: Number(f[2]), end: Number(f[3]), renewTill: f[4] ? Number(f[4]) : undefined, kvno: Number(f[5]), serviceKey: f[6] });
  }
  return principal ? { principal, tickets } : null;
}

export function formatCache(c: CredCache): string {
  return '# Kerberos credential cache (simulated as text; real caches are binary: list them with klist)\n'
    + `principal\t${c.principal}\n`
    + c.tickets.map((t) => ['ticket', t.server, t.start, t.end, t.renewTill ?? '', t.kvno, t.serviceKey].join('\t')).join('\n') + (c.tickets.length ? '\n' : '');
}

export function cachePath(uid: number): string {
  return `/tmp/krb5cc_${uid}`;
}
