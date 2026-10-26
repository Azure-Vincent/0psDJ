// Group Policy. A GPO lives in two places: its container in Active Directory
// (name, status, permissions, and where it is linked: gPLink on the domain or
// on an OU) and its files in SYSVOL on every DC (the settings). A computer
// processes its policy at startup and every ~90 minutes (gpupdate forces it):
//
//   1. find a DC (DNS SRV, LDAP) and bind with the computer account,
//   2. read its own DN, then the gPLinks of the domain and of each OU above it,
//      in LSDOU order, honouring Block Inheritance and Enforced links,
//   3. drop GPOs it may not read or apply (security filtering, evaluated with
//      the groups in its Kerberos ticket: those of its last start),
//   4. read each GPO's gpt.ini and settings from \\domain\SYSVOL over SMB (445),
//   5. apply: policy registry values, firewall rules; undo what GPOs that no
//      longer apply had set.
//
// Only Computer Configuration is modelled (registry policies and firewall
// rules); user policy, WMI filters, loopback and sites are not.

import { tcpConnect } from '../sim/tcp';
import type { Host, World } from '../types';
import { domainDn, isDc, principalGroups, secureChannel, type DcLocation } from './ad';
import { applyFirewall, rdpEnabled, startWinService, stopWinService, winEvent, type AdState, type Gpo, type GpLink, type GpState } from './model';

export const DEFAULT_DOMAIN_POLICY = '31B2F340-016D-11D2-945F-00C04FB984F9';
export const DEFAULT_DC_POLICY = '6AC1786C-016F-11D2-945F-00C04FB984F9';

const GP = 'Microsoft-Windows-GroupPolicy';

export const defaultGpoPermissions = (): Gpo['permissions'] => ({
  'Authenticated Users': 'GpoApply',
  'Domain Admins': 'GpoEditDeleteModifySecurity',
  'Enterprise Admins': 'GpoEditDeleteModifySecurity',
  SYSTEM: 'GpoEditDeleteModifySecurity',
  'ENTERPRISE DOMAIN CONTROLLERS': 'GpoRead',
});

/** The OUs, GPOs and links of a domain (created with the forest; filled in for older saved state). */
export function gpData(ad: AdState): { ous: NonNullable<AdState['ous']>; gpos: NonNullable<AdState['gpos']>; links: NonNullable<AdState['gpLinks']> } {
  const dn = domainDn(ad.domain);
  if (!ad.gpos) {
    const mk = (id: string, name: string): Gpo => ({ id, name, status: 'AllSettingsEnabled', description: '', registry: [], firewallRules: [], securitySettings: true, permissions: defaultGpoPermissions(), computerVersion: 3, created: 0, modified: 0 });
    ad.gpos = { [DEFAULT_DOMAIN_POLICY]: mk(DEFAULT_DOMAIN_POLICY, 'Default Domain Policy'), [DEFAULT_DC_POLICY]: mk(DEFAULT_DC_POLICY, 'Default Domain Controllers Policy') };
  }
  ad.ous ??= { [`ou=domain controllers,${dn}`.toLowerCase()]: { dn: `OU=Domain Controllers,${dn}`, name: 'Domain Controllers', description: 'Default container for domain controllers', blockInheritance: false, protected: true } };
  ad.gpLinks ??= {
    [dn.toLowerCase()]: [{ gpoId: DEFAULT_DOMAIN_POLICY, enabled: true, enforced: false }],
    [`ou=domain controllers,${dn}`.toLowerCase()]: [{ gpoId: DEFAULT_DC_POLICY, enabled: true, enforced: false }],
  };
  return { ous: ad.ous, gpos: ad.gpos, links: ad.gpLinks };
}

export const normDn = (dn: string) => dn.split(',').map((p) => p.trim()).join(',').toLowerCase();

/** The DN of a computer object. */
export function computerDn(ad: AdState, key: string): string {
  const c = ad.computers[key.toLowerCase()];
  const container = c?.ou ?? (c?.dc ? `OU=Domain Controllers,${domainDn(ad.domain)}` : `CN=Computers,${domainDn(ad.domain)}`);
  return `CN=${c?.name ?? key.toUpperCase()},${container}`;
}

export const findGpo = (ad: AdState, name: string) => Object.values(gpData(ad).gpos).find((g) => g.name.toLowerCase() === name.toLowerCase() || g.id.toLowerCase() === name.replace(/[{}]/g, '').toLowerCase());

/** A GPO's settings as Group Policy sees them: empty GPOs are "Not Applied (Empty)". */
export const gpoHasComputerSettings = (g: Gpo) => !!g.securitySettings || g.registry.length > 0 || g.firewallRules.length > 0;

export interface ScopedGpo { gpo: Gpo; link: GpLink; container: string }

/**
 * The GPOs linked above an object, in processing order (lowest precedence
 * first): domain, then each OU from the top down; Block Inheritance at an OU
 * drops the non-enforced links above it; enforced links are processed last,
 * the highest container's last of all (so it wins).
 */
export function linkedGpos(ad: AdState, objectDn: string): { normal: ScopedGpo[]; enforced: ScopedGpo[]; disabledLinks: ScopedGpo[] } {
  const { gpos, links, ous } = gpData(ad);
  const root = normDn(domainDn(ad.domain));
  const parts = objectDn.split(',').map((p) => p.trim());
  // Containers from the domain down to the object's parent (OUs only carry links).
  const containers: string[] = [];
  for (let i = parts.length - 1; i >= 1; i--) {
    const dn = parts.slice(i).join(',');
    const n = normDn(dn);
    if (n === root || (/^ou=/i.test(parts[i]) && n.endsWith(root))) containers.push(dn);
  }
  let normal: ScopedGpo[] = [];
  const enforced: ScopedGpo[] = [];
  const disabledLinks: ScopedGpo[] = [];
  for (const c of containers) {
    const n = normDn(c);
    if (ous[n]?.blockInheritance) normal = [];
    // Within a container the link with order 1 has the highest precedence: process from the last.
    const here: ScopedGpo[] = [];
    for (const l of [...(links[n] ?? [])].reverse()) {
      const g = gpos[l.gpoId];
      if (!g) continue;
      const s = { gpo: g, link: l, container: c };
      if (!l.enabled) disabledLinks.push(s);
      else if (l.enforced) here.push(s);
      else normal.push(s);
    }
    // A higher container's enforced links are processed after (and so win over) a lower one's.
    enforced.unshift(...here);
  }
  return { normal, enforced, disabledLinks };
}

/** Groups in a computer's token: its groups in AD (with nesting) and the well-known ones. */
export function computerToken(ad: AdState, host: Host): string[] {
  const sam = `${host.hostname.toUpperCase()}$`;
  const groups = principalGroups(ad, sam).filter((g) => g !== 'Domain Users');
  return [...new Set([...groups, 'Authenticated Users', 'Everyone', ...(isDc(host) ? ['ENTERPRISE DOMAIN CONTROLLERS'] : []), sam])];
}

/** A policy key without its hive: "HKLM\\Software\\X", "HKLM:\\Software\\X" and "HKEY_LOCAL_MACHINE\\Software\\X" are one key. */
export const hivePath = (k: string) => k.replace(/^HKLM:?\\?|^HKEY_LOCAL_MACHINE\\?/i, '');

const READ: Gpo['permissions'][string][] = ['GpoRead', 'GpoApply', 'GpoEdit', 'GpoEditDeleteModifySecurity'];

function permissionFor(g: Gpo, token: string[]): { read: boolean; apply: boolean } {
  const lower = new Set(token.map((t) => t.toLowerCase()));
  const perms = Object.entries(g.permissions).filter(([t]) => lower.has(t.toLowerCase()) || lower.has(t.replace(/^[^\\]+\\/, '').toLowerCase())).map(([, p]) => p);
  return { read: perms.some((p) => READ.includes(p)), apply: perms.includes('GpoApply') };
}

export interface GpResult {
  ok: boolean;
  /** gpupdate's error text for Computer policy. */
  error?: string;
  applied: Gpo[];
  filtered: { name: string; reason: string }[];
  dc?: string;
}

const SYSVOL_ERROR = (domain: string, id: string) => `The processing of Group Policy failed. Windows attempted to read the file \\\\${domain}\\sysvol\\${domain}\\Policies\\{${id}}\\gpt.ini from a domain controller and was not successful. Group Policy settings may not be applied until this event is resolved. This issue may be transient and could be caused by one or more of the following: \na) Name Resolution/Network Connectivity to the current domain controller. \nb) File Replication Service Latency (a file created on another domain controller has not replicated to the current domain controller). \nc) The Distributed File System (DFS) client has been disabled.`;
const NO_DC_ERROR = 'The processing of Group Policy failed. Windows could not resolve the computer name. This could be caused by one of more of the following: \na) Name Resolution failure on the current domain controller. \nb) Active Directory Replication Latency (an account created on another domain controller has not replicated to the current domain controller).';
const BIND_ERROR = 'The processing of Group Policy failed. Windows could not authenticate to the Active Directory service on a domain controller. (LDAP Bind function call failed). Look in the details tab for error code and description.';

/**
 * Process Computer Configuration on `host` (startup or gpupdate). On failure
 * the settings of the last successful processing stay in place.
 */
export function processGroupPolicy(world: World, host: Host, refreshToken = false): GpResult {
  const w = host.win!;
  const m = w.domain;
  if (!m) {
    clearGroupPolicy(host);
    return { ok: true, applied: [], filtered: [] };
  }
  const prev: GpState = { ...(w.gp ?? { applied: [], filtered: [], registry: [], rules: [] }) };
  const fail = (error: string, id: number): GpResult => {
    w.gp = { ...prev, lastError: error };
    winEvent(world, host, 'System', id, GP, error, 'Error');
    return { ok: false, error, applied: [], filtered: [] };
  };
  const ch = secureChannel(world, host);
  if (ch.state === 'no-dc') return fail(NO_DC_ERROR, 1129);
  if (ch.state === 'denied') return fail(BIND_ERROR, 1006);
  const loc = ch.dc as Extract<DcLocation, { ok: true }>;
  const ad = loc.dc.win!.ad!;
  const self = ad.computers[host.hostname.toLowerCase()];
  if (!self) return fail(NO_DC_ERROR, 1129);
  const token = (refreshToken ? undefined : prev.token) ?? computerToken(ad, host);
  prev.token = token;
  const { normal, enforced } = linkedGpos(ad, computerDn(ad, host.hostname));
  const applied: Gpo[] = [];
  const filtered: { name: string; reason: string }[] = [];
  const order = [...normal, ...enforced].map((s) => s.gpo);
  // A GPO linked twice is processed once, at its highest-precedence (last) position.
  for (const [i, g] of order.entries()) {
    if (order.indexOf(g, i + 1) !== -1) continue;
    const perm = permissionFor(g, token);
    if (!perm.read) { filtered.push({ name: g.name, reason: 'Inaccessible' }); continue; }
    if (!perm.apply) { filtered.push({ name: g.name, reason: 'Denied (Security)' }); continue; }
    if (g.status === 'ComputerSettingsDisabled' || g.status === 'AllSettingsDisabled') { filtered.push({ name: g.name, reason: 'Disabled (GPO)' }); continue; }
    if (!gpoHasComputerSettings(g)) { filtered.push({ name: g.name, reason: 'Not Applied (Empty)' }); continue; }
    applied.push(g);
  }
  // SYSVOL: the GPT of every applicable GPO is read over SMB from the DC.
  if (loc.dc !== host && applied.length) {
    const c = tcpConnect(world, host, loc.ip, 445, { timeoutMs: 3000 });
    if (!c.ok) return fail(SYSVOL_ERROR(ad.domain, applied[0].id), 1058);
    c.conn.send('c2s', 180, { protocol: 'SMB2', info: `Create Request File: ${ad.domain}\\Policies\\{${applied[0].id}}\\gpt.ini`, fields: [] });
    c.conn.close('client');
  }

  // Undo what the previous processing set, then apply in order (later GPOs win).
  undoRegistry(host, prev.registry);
  const registry: GpState['registry'] = [];
  const rules: GpState['rules'] = [];
  for (const g of applied) {
    for (const v of g.registry) {
      const key = `HKLM:\\${hivePath(v.key)}`;
      const existing = Object.keys(w.registry).find((k) => k.toLowerCase() === key.toLowerCase()) ?? key;
      (w.registry[existing] ??= {})[v.valueName] = v.value;
      registry.push({ key: existing, valueName: v.valueName });
    }
    for (const r of g.firewallRules) rules.push({ ...r, gpo: `${ad.domain}\\${g.name}` });
  }
  const before = prev.applied.join('|');
  w.gp = { appliedAt: world.clock, fromDc: loc.name, applied: applied.map((g) => g.name), filtered, registry, rules, token };
  applyFirewall(host);
  // Remote Desktop follows its policy: the listener comes and goes with fDenyTSConnections.
  if (rdpEnabled(host)) { for (const n of ['TermService', 'SessionEnv', 'UmRdpService']) if (w.services[n] && w.services[n].startType !== 'Disabled') startWinService(world, host, n); }
  else if (w.services.TermService?.status === 'Running') stopWinService(world, host, 'TermService');
  const changed = before !== w.gp.applied.join('|') || registry.length > 0 || rules.length > 0;
  winEvent(world, host, 'System', changed ? 1502 : 1500, GP, changed
    ? `The Group Policy settings for the computer were processed successfully. New settings from ${applied.length} Group Policy objects were detected and applied.`
    : 'The Group Policy settings for the computer were processed successfully. There were no changes detected since the last successful processing of Group Policy.');
  return { ok: true, applied, filtered, dc: loc.name };
}

/** At startup: the computer gets a fresh ticket (its groups as of now), then processes policy. */
export function startupGroupPolicy(world: World, host: Host): void {
  if (host.win!.domain) processGroupPolicy(world, host, true);
}

function undoRegistry(host: Host, values: GpState['registry']): void {
  const w = host.win!;
  for (const r of values) {
    const key = Object.keys(w.registry).find((k) => k.toLowerCase() === r.key.toLowerCase());
    if (!key) continue;
    delete w.registry[key][r.valueName];
    if (!Object.keys(w.registry[key]).length) delete w.registry[key];
  }
}

/** Out of the domain: the settings Group Policy wrote are removed. */
export function clearGroupPolicy(host: Host): void {
  const w = host.win!;
  if (!w.gp) return;
  undoRegistry(host, w.gp.registry);
  delete w.gp;
  applyFirewall(host);
}
