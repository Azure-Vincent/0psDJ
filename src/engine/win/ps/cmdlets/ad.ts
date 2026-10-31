// Active Directory on Windows PowerShell: the ActiveDirectory module (users,
// groups, computers, lockout), DnsServer, ServerManager (features),
// ADDSDeployment (Install-ADDSForest), domain membership (Add-Computer,
// Test-ComputerSecureChannel) and credentials (Get-Credential, New-Object).

import { tcpConnect } from '../../../sim/tcp';
import type { Host } from '../../../types';
import { adUser, domainDn, isDc, joinDomain, locateDc, principalGroups, promoteForest, resetMachinePassword, secureChannel } from '../../ad';
import { computerDn, gpData, normDn } from '../../gpo';
import { winEvent, type AdGroup, type AdState, type AdUser } from '../../model';
import { registerView } from '../format';
import { cmdlet, type Call, type ParamDef, type PsCtx } from '../runtime';
import { date, flatten, getProp, isBlock, isObj, obj, toBool, toStr, wildcard, type PSObject, type PSSecure, type PSValue } from '../values';
import { isAdmin } from './files';
import { complexEnough } from './system';

const AD = 'ActiveDirectory';
const DNSSRV = 'DnsServer';
const SM = 'ServerManager';
const MGMT = 'Microsoft.PowerShell.Management';

const hasFeature = (ctx: PsCtx, f: string) => !!ctx.host.win?.features?.includes(f);

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

function credObj(user: string, password: string): PSObject {
  return obj('System.Management.Automation.PSCredential', { UserName: user, Password: { __t: 'System.Security.SecureString', plain: password } as PSSecure });
}

/** A -Credential value: a PSCredential, or a user name (PowerShell then asks for the password). */
function credential(c: Call, param = 'Credential'): { user: string; password: string } | null {
  const v = c.p[param];
  if (isObj(v) && v.__t === 'System.Management.Automation.PSCredential') return { user: toStr(v.UserName), password: toStr((v.Password as unknown as PSSecure).plain) };
  const user = v === undefined ? '' : toStr(v);
  if (!user) return null;
  const password = c.ctx.ask(`\nWindows PowerShell credential request.\nEnter your credentials.\nPassword for user ${user}: `, true);
  return { user, password };
}

/** "CORP\\alice", "alice@ad.corp.lab" → domain part and sAMAccountName. */
function splitUser(u: string): { domain: string; sam: string } {
  if (u.includes('\\')) { const [d, s] = u.split('\\'); return { domain: d, sam: s }; }
  if (u.includes('@')) { const [s, d] = u.split('@'); return { domain: d, sam: s }; }
  return { domain: '', sam: u };
}

cmdlet({
  name: 'Get-Credential', module: 'Microsoft.PowerShell.Security', synopsis: 'Gets a credential object based on a user name and password.',
  params: [{ name: 'UserName', aliases: ['Credential'], type: 'string', position: 0 }, { name: 'Message', type: 'string' }],
  run(c) {
    const user = c.str('UserName') ?? c.ctx.ask('\ncmdlet Get-Credential at command pipeline position 1\nSupply values for the following parameters:\nUser: ', false);
    const password = c.ctx.ask(`\nWindows PowerShell credential request.\n${c.str('Message') ?? 'Enter your credentials.'}\nPassword for user ${user}: `, true);
    return [credObj(user, password)];
  },
});

cmdlet({
  name: 'New-Object', module: 'Microsoft.PowerShell.Utility', synopsis: 'Creates an instance of a .NET Framework object (PSCredential, PSObject).',
  params: [{ name: 'TypeName', type: 'string', position: 0, mandatory: true }, { name: 'ArgumentList', aliases: ['Args'], type: 'any', position: 1 }, { name: 'Property', type: 'any' }],
  run(c) {
    const t = (c.str('TypeName') ?? '').toLowerCase().replace(/^system\.management\.automation\./, '');
    const args = flatten(c.p.ArgumentList ?? []);
    if (t === 'pscredential') {
      const pw = args[1];
      if (args.length !== 2 || !(isObj(pw) && pw.__t === 'System.Security.SecureString')) {
        c.error(`Cannot find an overload for "PSCredential" and the argument count: "${args.length}".`, { category: 'InvalidOperation', target: '', exception: 'MethodException', id: 'ConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectCommand' });
        return [];
      }
      return [credObj(toStr(args[0]), toStr((pw as unknown as PSSecure).plain))];
    }
    if (t === 'psobject' || t === 'pscustomobject') {
      const p = c.p.Property;
      const entries = p && typeof p === 'object' && 'entries' in (p as object) ? (p as { entries: Record<string, PSValue>; keys: string[] }) : null;
      return [obj('System.Management.Automation.PSCustomObject', entries ? Object.fromEntries(entries.keys.map((k) => [k, entries.entries[k]])) : {})];
    }
    c.error(`Cannot find type [${c.str('TypeName')}]: verify that the assembly containing this type is loaded.`, { category: 'InvalidType', target: '', exception: 'PSArgumentException', id: 'TypeNotFound,Microsoft.PowerShell.Commands.NewObjectCommand' });
    return [];
  },
});

// ---------------------------------------------------------------------------
// The directory a cmdlet talks to
// ---------------------------------------------------------------------------

/** The DC this console reaches: itself on a DC, otherwise one located through DNS. */
export function directory(c: Call): { dc: Host; ad: AdState } | null {
  const host = c.ctx.host;
  if (isDc(host)) return { dc: host, ad: host.win!.ad! };
  const m = host.win?.domain;
  const loc = m ? locateDc(c.ctx.world, host, m.domain) : null;
  if (loc?.ok) return { dc: loc.dc, ad: loc.dc.win!.ad! };
  c.error('Unable to find a default server with Active Directory Web Services running.', { category: 'ResourceUnavailable', target: '', exception: 'ADServerDownException', id: `ActiveDirectoryServer:1355,Microsoft.ActiveDirectory.Management.Commands.${c.name.replace('-', '')}` });
  return null;
}

export function guid(seed: string): string {
  let h = 2166136261;
  for (const ch of seed) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
  const hex = (n: number, l: number) => ((n * 2654435761) >>> 0).toString(16).padStart(8, '0').slice(0, l);
  return `${hex(h, 8)}-${hex(h + 1, 4)}-${hex(h + 2, 4)}-${hex(h + 3, 4)}-${hex(h + 4, 8)}${hex(h + 5, 4)}`;
}

function userDn(ad: AdState, u: AdUser): string {
  return `CN=${u.name},${u.ou ?? `CN=Users,${domainDn(ad.domain)}`}`;
}

function groupDn(ad: AdState, g: AdGroup): string {
  return `CN=${g.name},${g.rid < 1000 && g.scope === 'DomainLocal' ? 'CN=Builtin' : 'CN=Users'},${domainDn(ad.domain)}`;
}

const USER_EXTRA: Record<string, (ad: AdState, u: AdUser) => PSValue> = {
  Description: (_a, u) => u.description,
  LockedOut: (_a, u) => u.lockedOut,
  BadLogonCount: (_a, u) => u.badCount,
  LastLogonDate: (_a, u) => (u.lastLogon ? date(u.lastLogon) : null),
  MemberOf: (ad, u) => Object.values(ad.groups).filter((g) => g.members.some((m) => m.toLowerCase() === u.sam.toLowerCase())).map((g) => groupDn(ad, g)),
  DisplayName: (_a, u) => u.name,
  PasswordNeverExpires: () => false,
};

function userObj(ad: AdState, u: AdUser, props: string[] = []): PSObject {
  const [given, ...sur] = u.name.split(' ');
  const base: Record<string, PSValue> = {
    DistinguishedName: userDn(ad, u), Enabled: u.enabled, GivenName: sur.length ? given : '', Name: u.name, ObjectClass: 'user', ObjectGUID: guid(`${ad.domain}:${u.sam}`),
    SamAccountName: u.sam, SID: `${ad.domainSid}-${u.rid}`, Surname: sur.join(' '), UserPrincipalName: `${u.sam}@${ad.domain}`,
  };
  const want = props.some((p) => p === '*') ? Object.keys(USER_EXTRA) : props.map((p) => Object.keys(USER_EXTRA).find((k) => k.toLowerCase() === p.toLowerCase())).filter((x): x is string => !!x);
  for (const k of want) base[k] = USER_EXTRA[k](ad, u);
  return obj('Microsoft.ActiveDirectory.Management.ADUser', { ...Object.fromEntries(Object.entries(base).sort(([a], [b]) => a.localeCompare(b))), __str: base.DistinguishedName as string });
}

function groupObj(ad: AdState, g: AdGroup): PSObject {
  return obj('Microsoft.ActiveDirectory.Management.ADGroup', { DistinguishedName: groupDn(ad, g), GroupCategory: g.category, GroupScope: g.scope, Name: g.name, ObjectClass: 'group', ObjectGUID: guid(`${ad.domain}:g:${g.name}`), SamAccountName: g.name, SID: `${ad.domainSid}-${g.rid}`, __str: groupDn(ad, g) });
}

function computerObj(ad: AdState, key: string, props: string[] = []): PSObject {
  const cpt = ad.computers[key];
  const o: Record<string, PSValue> = { DistinguishedName: computerDn(ad, key), DNSHostName: cpt.dnsHostName, Enabled: cpt.enabled, Name: cpt.name, ObjectClass: 'computer', ObjectGUID: guid(`${ad.domain}:c:${cpt.name}`), SamAccountName: `${cpt.name}$`, SID: `${ad.domainSid}-${cpt.rid}`, UserPrincipalName: null };
  if (props.length) o.OperatingSystem = cpt.os;
  return obj('Microsoft.ActiveDirectory.Management.ADComputer', o);
}

function notFound(c: Call, ad: AdState, id: string, cls: string): void {
  c.error(`Cannot find an object with identity: '${id}' under: '${domainDn(ad.domain)}'.`, { category: 'ObjectNotFound', target: id, exception: 'ADIdentityNotFoundException', id: `ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.${c.name.replace('-', '')}` });
  void cls;
}

/** Resolve -Identity (sAMAccountName, name, DN, UPN, or a piped object). */
function identity(c: Call): string | null {
  if (c.has('Identity')) {
    const v = c.p.Identity;
    if (isObj(v)) return toStr(getProp(v, 'SamAccountName') ?? getProp(v, 'Name'));
    return c.str('Identity')!;
  }
  const i = c.input.find(isObj);
  if (i) return toStr(getProp(i, 'SamAccountName') ?? getProp(i, 'Name'));
  return null;
}

function findUser(ad: AdState, id: string): AdUser | undefined {
  const n = id.toLowerCase();
  return adUser(ad, id) ?? Object.values(ad.users).find((u) => u.name.toLowerCase() === n || userDn(ad, u).toLowerCase() === n || `${u.sam}@${ad.domain}`.toLowerCase() === n);
}

function findGroup(ad: AdState, id: string): AdGroup | undefined {
  const n = id.toLowerCase();
  return ad.groups[n] ?? Object.values(ad.groups).find((g) => g.name.toLowerCase() === n || groupDn(ad, g).toLowerCase() === n);
}

/** -Filter: "*", or "<Property> -eq|-ne|-like|-notlike <value>". */
function filterFn(c: Call): ((o: PSObject) => boolean) | null {
  const raw = c.p.Filter;
  const f = (isBlock(raw) ? raw.text : toStr(raw)).trim();
  if (f === '*') return () => true;
  const m = /^(\w+)\s+-(eq|ne|like|notlike)\s+(.+)$/i.exec(f);
  if (!m) {
    c.error(`Error parsing query: '${f}' Error Message: 'syntax error' at position: '1'.`, { category: 'ParserError', target: '', exception: 'ADFilterParsingException', id: `ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADFilterParsingException,Microsoft.ActiveDirectory.Management.Commands.${c.name.replace('-', '')}` });
    return null;
  }
  const [, prop, op, rawVal] = m;
  const val = rawVal.trim().replace(/^["'](.*)["']$/, '$1');
  const want: PSValue = /^\$true$/i.test(val) ? true : /^\$false$/i.test(val) ? false : val;
  return (o) => {
    const v = getProp(o, prop);
    const s = toStr(v);
    const hit = op.toLowerCase().endsWith('like') ? wildcard(toStr(want)).test(s) : typeof want === 'boolean' ? toBool(v) === want : s.toLowerCase() === toStr(want).toLowerCase();
    return op.toLowerCase().startsWith('n') ? !hit : hit;
  };
}

export function adCmdlet(name: string, synopsis: string, params: ParamDef[], run: (c: Call) => PSValue[] | void): void {
  cmdlet({ name, module: AD, synopsis, params, run, cls: `Microsoft.ActiveDirectory.Management.Commands.${name.replace('-', '')}`, available: (ctx) => hasFeature(ctx, 'RSAT-AD-PowerShell') });
}

export const ID: ParamDef = { name: 'Identity', type: 'any', position: 0 };

function plain(v: PSValue): string | null {
  return isObj(v) && v.__t === 'System.Security.SecureString' ? toStr((v as unknown as PSSecure).plain) : null;
}

function badPassword(c: Call): void {
  c.error('The password does not meet the length, complexity, or history requirement of the domain.', { category: 'InvalidData', target: '', exception: 'ADPasswordComplexityException', id: `ActiveDirectoryServer:1325,Microsoft.ActiveDirectory.Management.Commands.${c.name.replace('-', '')}` });
}

// ---- users ------------------------------------------------------------------

adCmdlet('Get-ADUser', 'Gets one or more Active Directory users.', [ID, { name: 'Filter', type: 'any' }, { name: 'Properties', aliases: ['Property'], type: 'strings' }, { name: 'Server', type: 'string' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const props = c.strs('Properties') ?? [];
  if (c.has('Filter')) {
    const f = filterFn(c);
    return f ? Object.values(d.ad.users).map((u) => userObj(d.ad, u, [...props, 'LockedOut', 'Description'])).filter(f).map((o) => userObj(d.ad, findUser(d.ad, toStr(o.SamAccountName))!, props)) : [];
  }
  const id = identity(c);
  if (!id) { c.error("Cannot process command because of one or more missing mandatory parameters: Filter.", { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'MissingMandatoryParameter,Microsoft.ActiveDirectory.Management.Commands.GetADUser' }); return []; }
  const u = findUser(d.ad, id);
  if (!u) { notFound(c, d.ad, id, 'ADUser'); return []; }
  return [userObj(d.ad, u, props)];
});

adCmdlet('New-ADUser', 'Creates an Active Directory user.', [
  { name: 'Name', type: 'string', position: 0 }, { name: 'SamAccountName', type: 'string' }, { name: 'GivenName', type: 'string' }, { name: 'Surname', type: 'string' }, { name: 'DisplayName', type: 'string' },
  { name: 'UserPrincipalName', type: 'string' }, { name: 'Path', type: 'string' }, { name: 'Description', type: 'string' }, { name: 'AccountPassword', type: 'any' }, { name: 'Enabled', type: 'bool' },
  { name: 'ChangePasswordAtLogon', type: 'bool' }, { name: 'PassThru', type: 'switch' },
], (c) => {
  const d = directory(c);
  if (!d) return [];
  const name = c.str('Name') ?? '';
  const sam = c.str('SamAccountName') ?? name;
  if (findUser(d.ad, sam) || Object.values(d.ad.users).some((u) => u.name.toLowerCase() === name.toLowerCase())) {
    c.error('The specified account already exists', { category: 'NotSpecified', target: `CN=${name},CN=Users,${domainDn(d.ad.domain)}`, exception: 'ADIdentityAlreadyExistsException', id: 'ActiveDirectoryServer:1316,Microsoft.ActiveDirectory.Management.Commands.NewADUser' });
    return [];
  }
  const pw = c.has('AccountPassword') ? plain(c.p.AccountPassword) : null;
  if (c.has('AccountPassword') && (pw === null || !complexEnough(pw, sam))) { badPassword(c); return []; }
  const enabled = c.has('Enabled') ? toBool(c.p.Enabled) : false;
  if (enabled && pw === null) {
    c.error('Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.', { category: 'InvalidOperation', target: '', exception: 'ADPasswordComplexityException', id: 'ActiveDirectoryServer:1325,Microsoft.ActiveDirectory.Management.Commands.NewADUser' });
    return [];
  }
  if (c.whatIf('New', `CN=${name},CN=Users,${domainDn(d.ad.domain)}`)) return [];
  const u: AdUser = { sam, name, enabled, password: pw ?? '', lockedOut: false, badCount: 0, description: c.str('Description') ?? '', rid: d.ad.nextRid++ };
  d.ad.users[sam.toLowerCase()] = u;
  winEvent(c.ctx.world, d.dc, 'Security', 4720, 'Microsoft-Windows-Security-Auditing', `A user account was created.\n\nNew Account:\n\tAccount Name:\t\t${sam}\n\tAccount Domain:\t\t${d.ad.netbios}`);
  return c.has('PassThru') ? [userObj(d.ad, u)] : [];
});

adCmdlet('Set-ADUser', 'Modifies an Active Directory user.', [ID, { name: 'Description', type: 'string' }, { name: 'Enabled', type: 'bool' }, { name: 'DisplayName', type: 'string' }], (c) => {
  const d = directory(c);
  const id = identity(c);
  if (!d || !id) return;
  const u = findUser(d.ad, id);
  if (!u) { notFound(c, d.ad, id, 'ADUser'); return; }
  if (c.has('Description')) u.description = c.str('Description')!;
  if (c.has('Enabled')) u.enabled = toBool(c.p.Enabled);
  if (c.has('DisplayName')) u.name = c.str('DisplayName')!;
});

adCmdlet('Remove-ADUser', 'Removes an Active Directory user.', [ID], (c) => {
  const d = directory(c);
  const id = identity(c);
  if (!d || !id) return;
  const u = findUser(d.ad, id);
  if (!u) { notFound(c, d.ad, id, 'ADUser'); return; }
  if (c.whatIf('Remove', userDn(d.ad, u))) return;
  if (c.p.confirm !== false && toStr(c.ctx.session.vars.ConfirmPreference ?? '') !== 'None') {
    const ans = c.ctx.ask(`\nConfirm\nAre you sure you want to perform this action?\nPerforming the operation "Remove" on target "${userDn(d.ad, u)}".\n[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): `, false);
    if (/^[nl]/i.test(ans.trim())) return;
  }
  delete d.ad.users[u.sam.toLowerCase()];
  for (const g of Object.values(d.ad.groups)) g.members = g.members.filter((m) => m.toLowerCase() !== u.sam.toLowerCase());
  winEvent(c.ctx.world, d.dc, 'Security', 4726, 'Microsoft-Windows-Security-Auditing', `A user account was deleted.\n\nTarget Account:\n\tAccount Name:\t\t${u.sam}\n\tAccount Domain:\t\t${d.ad.netbios}`);
});

adCmdlet('Set-ADAccountPassword', 'Modifies the password of an Active Directory account.', [ID, { name: 'NewPassword', type: 'any' }, { name: 'OldPassword', type: 'any' }, { name: 'Reset', type: 'switch' }, { name: 'PassThru', type: 'switch' }], (c) => {
  const d = directory(c);
  const id = identity(c);
  if (!d || !id) return;
  const u = findUser(d.ad, id);
  const comp = !u ? d.ad.computers[id.replace(/\$$/, '').toLowerCase()] : undefined;
  if (comp) {
    // A computer account: the member's copy of the password no longer matches (broken secure channel).
    const np = plain(c.p.NewPassword ?? null);
    if (!c.has('Reset') || np === null) { badPassword(c); return; }
    comp.password = `reset:${np}`;
    winEvent(c.ctx.world, d.dc, 'Security', 4724, 'Microsoft-Windows-Security-Auditing', `An attempt was made to reset an account's password.\n\nTarget Account:\n\tAccount Name:\t\t${comp.name}$\n\tAccount Domain:\t\t${d.ad.netbios}`);
    return;
  }
  if (!u) { notFound(c, d.ad, id, 'ADAccount'); return; }
  const pw = c.has('NewPassword') ? plain(c.p.NewPassword) : c.ctx.ask('Please enter the desired password for \'' + userDn(d.ad, u) + '\'\nPassword: ', true);
  if (!pw || !complexEnough(pw, u.sam)) { badPassword(c); return; }
  if (!c.has('Reset') && plain(c.p.OldPassword ?? null) !== u.password) {
    c.error('The specified network password is not correct.', { category: 'NotSpecified', target: u.sam, exception: 'ADInvalidPasswordException', id: 'ActiveDirectoryServer:86,Microsoft.ActiveDirectory.Management.Commands.SetADAccountPassword' });
    return;
  }
  u.password = pw;
  winEvent(c.ctx.world, d.dc, 'Security', 4724, 'Microsoft-Windows-Security-Auditing', `An attempt was made to reset an account's password.\n\nTarget Account:\n\tAccount Name:\t\t${u.sam}\n\tAccount Domain:\t\t${d.ad.netbios}`);
});

for (const [verb, enable] of [['Enable', true], ['Disable', false]] as const) {
  adCmdlet(`${verb}-ADAccount`, `${verb}s an Active Directory account.`, [ID, { name: 'PassThru', type: 'switch' }], (c) => {
    const d = directory(c);
    const id = identity(c);
    if (!d || !id) return;
    const u = findUser(d.ad, id);
    const comp = !u ? d.ad.computers[id.replace(/\$$/, '').toLowerCase()] : undefined;
    if (!u && !comp) { notFound(c, d.ad, id, 'ADAccount'); return; }
    if (c.whatIf('Set', u ? userDn(d.ad, u) : id)) return;
    if (u) u.enabled = enable;
    if (comp) comp.enabled = enable;
    winEvent(c.ctx.world, d.dc, 'Security', enable ? 4722 : 4725, 'Microsoft-Windows-Security-Auditing', `A user account was ${enable ? 'enabled' : 'disabled'}.\n\nTarget Account:\n\tAccount Name:\t\t${u?.sam ?? id}\n\tAccount Domain:\t\t${d.ad.netbios}`);
  });
}

adCmdlet('Unlock-ADAccount', 'Unlocks an Active Directory account.', [ID, { name: 'PassThru', type: 'switch' }], (c) => {
  const d = directory(c);
  const id = identity(c);
  if (!d || !id) return;
  const u = findUser(d.ad, id);
  if (!u) { notFound(c, d.ad, id, 'ADAccount'); return; }
  if (c.whatIf('Set', userDn(d.ad, u))) return;
  u.lockedOut = false;
  u.badCount = 0;
  winEvent(c.ctx.world, d.dc, 'Security', 4767, 'Microsoft-Windows-Security-Auditing', `A user account was unlocked.\n\nTarget Account:\n\tAccount Name:\t\t${u.sam}\n\tAccount Domain:\t\t${d.ad.netbios}`);
});

adCmdlet('Search-ADAccount', 'Gets Active Directory user, computer, or service accounts (-LockedOut, -AccountDisabled).', [{ name: 'LockedOut', type: 'switch' }, { name: 'AccountDisabled', type: 'switch' }, { name: 'UsersOnly', type: 'switch' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  return Object.values(d.ad.users).filter((u) => (c.has('LockedOut') ? u.lockedOut : true) && (c.has('AccountDisabled') ? !u.enabled : true) && (c.has('LockedOut') || c.has('AccountDisabled')))
    .map((u) => obj('Microsoft.ActiveDirectory.Management.ADUser', { AccountExpirationDate: null, DistinguishedName: userDn(d.ad, u), Enabled: u.enabled, LastLogonDate: u.lastLogon ? date(u.lastLogon) : null, LockedOut: u.lockedOut, Name: u.name, ObjectClass: 'user', ObjectGUID: guid(`${d.ad.domain}:${u.sam}`), PasswordExpired: false, PasswordNeverExpires: false, SamAccountName: u.sam, SID: `${d.ad.domainSid}-${u.rid}`, UserPrincipalName: `${u.sam}@${d.ad.domain}` }));
});

// ---- groups -----------------------------------------------------------------

adCmdlet('Get-ADGroup', 'Gets one or more Active Directory groups.', [ID, { name: 'Filter', type: 'any' }, { name: 'Properties', type: 'strings' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  if (c.has('Filter')) {
    const f = filterFn(c);
    return f ? Object.values(d.ad.groups).map((g) => groupObj(d.ad, g)).filter(f) : [];
  }
  const id = identity(c);
  if (!id) return [];
  const g = findGroup(d.ad, id);
  if (!g) { notFound(c, d.ad, id, 'ADGroup'); return []; }
  return [groupObj(d.ad, g)];
});

adCmdlet('New-ADGroup', 'Creates an Active Directory group.', [{ name: 'Name', type: 'string', position: 0 }, { name: 'GroupScope', type: 'string', position: 1 }, { name: 'GroupCategory', type: 'string' }, { name: 'Description', type: 'string' }, { name: 'Path', type: 'string' }, { name: 'SamAccountName', type: 'string' }, { name: 'PassThru', type: 'switch' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const name = c.str('Name') ?? '';
  const scope = ['Global', 'DomainLocal', 'Universal'].find((x) => x.toLowerCase() === (c.str('GroupScope') ?? '').toLowerCase());
  if (!scope) {
    c.error(`Cannot bind parameter 'GroupScope'. Cannot convert value "${c.str('GroupScope') ?? ''}" to type "Microsoft.ActiveDirectory.Management.ADGroupScope". Error: "Unable to match the identifier name ${c.str('GroupScope') ?? ''} to a valid enumerator name. Specify one of the following enumerator names and try again:\nDomainLocal, Global, Universal"`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage,Microsoft.ActiveDirectory.Management.Commands.NewADGroup' });
    return [];
  }
  if (findGroup(d.ad, name) || findUser(d.ad, name)) {
    c.error('The specified group already exists', { category: 'NotSpecified', target: `CN=${name},CN=Users,${domainDn(d.ad.domain)}`, exception: 'ADException', id: 'ActiveDirectoryServer:1318,Microsoft.ActiveDirectory.Management.Commands.NewADGroup' });
    return [];
  }
  const g: AdGroup = { name, scope: scope as AdGroup['scope'], category: (c.str('GroupCategory') ?? 'Security').toLowerCase().startsWith('d') ? 'Distribution' : 'Security', description: c.str('Description') ?? '', members: [], rid: d.ad.nextRid++ };
  d.ad.groups[name.toLowerCase()] = g;
  winEvent(c.ctx.world, d.dc, 'Security', 4727, 'Microsoft-Windows-Security-Auditing', `A security-enabled global group was created.\n\nNew Group:\n\tGroup Name:\t\t${name}\n\tGroup Domain:\t\t${d.ad.netbios}`);
  return c.has('PassThru') ? [groupObj(d.ad, g)] : [];
});

function memberObj(ad: AdState, m: string): PSObject {
  const u = findUser(ad, m);
  const g = !u ? findGroup(ad, m) : undefined;
  const cKey = m.replace(/\$$/, '').toLowerCase();
  const cpt = !u && !g ? ad.computers[cKey] : undefined;
  const dn = u ? userDn(ad, u) : g ? groupDn(ad, g) : cpt ? computerDn(ad, cKey) : `CN=${m},CN=Computers,${domainDn(ad.domain)}`;
  return obj('Microsoft.ActiveDirectory.Management.ADPrincipal', { distinguishedName: dn, name: u?.name ?? g?.name ?? cpt?.name ?? m, objectClass: u ? 'user' : g ? 'group' : 'computer', objectGUID: guid(`${ad.domain}:${m}`), SamAccountName: u?.sam ?? g?.name ?? m, SID: `${ad.domainSid}-${u?.rid ?? g?.rid ?? cpt?.rid ?? 0}` });
}

adCmdlet('Get-ADGroupMember', 'Gets the members of an Active Directory group.', [ID, { name: 'Recursive', type: 'switch' }], (c) => {
  const d = directory(c);
  const id = identity(c);
  if (!d || !id) return [];
  const g = findGroup(d.ad, id);
  if (!g) { notFound(c, d.ad, id, 'ADGroup'); return []; }
  const out: string[] = [];
  const walk = (grp: AdGroup) => {
    for (const m of grp.members) {
      const sub = c.has('Recursive') ? findGroup(d.ad, m) : undefined;
      if (sub) walk(sub);
      else if (!out.includes(m)) out.push(m);
    }
    if (grp.name === 'Domain Users') for (const u of Object.values(d.ad.users)) if (!out.includes(u.sam)) out.push(u.sam);
  };
  walk(g);
  return out.map((m) => memberObj(d.ad, m));
});

for (const [verb, add] of [['Add', true], ['Remove', false]] as const) {
  adCmdlet(`${verb}-ADGroupMember`, `${add ? 'Adds' : 'Removes'} one or more members ${add ? 'to' : 'from'} an Active Directory group.`, [ID, { name: 'Members', aliases: ['Member'], type: 'any', position: 1 }, { name: 'PassThru', type: 'switch' }], (c) => {
    const d = directory(c);
    const id = identity(c);
    if (!d || !id) return;
    const g = findGroup(d.ad, id);
    if (!g) { notFound(c, d.ad, id, 'ADGroup'); return; }
    const members = flatten(c.p.Members ?? []).map((m) => (isObj(m) ? toStr(getProp(m, 'SamAccountName') ?? getProp(m, 'Name')) : toStr(m)));
    const resolved: string[] = [];
    for (const m of members) {
      const u = findUser(d.ad, m);
      const sub = !u ? findGroup(d.ad, m) : undefined;
      const cpt = !u && !sub ? d.ad.computers[m.replace(/\$$/, '').toLowerCase()] : undefined;
      if (!u && !sub && !cpt) { notFound(c, d.ad, m, 'ADPrincipal'); return; }
      resolved.push(u?.sam ?? sub?.name ?? `${cpt!.name}$`);
    }
    if (!add && !c.noConfirm) {
      const ans = c.ctx.ask(`\nConfirm\nAre you sure you want to perform this action?\nPerforming the operation "Set" on target "${groupDn(d.ad, g)}".\n[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): `, false);
      if (/^[nl]/i.test(ans.trim())) return;
    }
    if (c.whatIf('Set', groupDn(d.ad, g))) return;
    for (const r of resolved) {
      const has = g.members.some((m) => m.toLowerCase() === r.toLowerCase());
      if (add && !has) g.members.push(r);
      if (!add) g.members = g.members.filter((m) => m.toLowerCase() !== r.toLowerCase());
      winEvent(c.ctx.world, d.dc, 'Security', add ? 4728 : 4729, 'Microsoft-Windows-Security-Auditing', `A member was ${add ? 'added to' : 'removed from'} a security-enabled global group.\n\nMember:\n\tAccount Name:\t\t${r}\n\nGroup:\n\tGroup Name:\t\t${g.name}\n\tGroup Domain:\t\t${d.ad.netbios}`);
    }
  });
}

adCmdlet('Get-ADPrincipalGroupMembership', 'Gets the Active Directory groups that have a specified user, computer, group, or service account.', [ID], (c) => {
  const d = directory(c);
  const id = identity(c);
  if (!d || !id) return [];
  const u = findUser(d.ad, id);
  if (!u) { notFound(c, d.ad, id, 'ADPrincipal'); return []; }
  const direct = Object.values(d.ad.groups).filter((g) => g.name === 'Domain Users' || g.members.some((m) => m.toLowerCase() === u.sam.toLowerCase()));
  return direct.map((g) => groupObj(d.ad, g));
});

// ---- computers, domain --------------------------------------------------------

adCmdlet('Get-ADComputer', 'Gets one or more Active Directory computers.', [ID, { name: 'Filter', type: 'any' }, { name: 'Properties', type: 'strings' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const props = c.strs('Properties') ?? [];
  if (c.has('Filter')) {
    const f = filterFn(c);
    return f ? Object.keys(d.ad.computers).map((k) => computerObj(d.ad, k, props)).filter(f) : [];
  }
  const id = identity(c);
  if (!id) return [];
  const key = id.replace(/\$$/, '').toLowerCase();
  if (!d.ad.computers[key]) { notFound(c, d.ad, id, 'ADComputer'); return []; }
  return [computerObj(d.ad, key, props)];
});

adCmdlet('Get-ADDomain', 'Gets an Active Directory domain.', [{ name: 'Identity', type: 'string', position: 0 }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const dn = domainDn(d.ad.domain);
  const dcName = `${d.dc.hostname.toLowerCase()}.${d.ad.domain}`;
  return [obj('Microsoft.ActiveDirectory.Management.ADDomain', {
    ComputersContainer: `CN=Computers,${dn}`, DistinguishedName: dn, DNSRoot: d.ad.domain, DomainControllersContainer: `OU=Domain Controllers,${dn}`, DomainMode: 'Windows2016Domain', DomainSID: d.ad.domainSid,
    Forest: d.ad.domain, InfrastructureMaster: dcName, Name: d.ad.domain.split('.')[0], NetBIOSName: d.ad.netbios, PDCEmulator: dcName, RIDMaster: dcName, UsersContainer: `CN=Users,${dn}`,
  })];
});

adCmdlet('Get-ADDomainController', 'Gets one or more Active Directory domain controllers.', [{ name: 'Identity', type: 'string', position: 0 }, { name: 'Discover', type: 'switch' }, { name: 'DomainName', type: 'string' }, { name: 'Filter', type: 'any' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const ip = d.dc.win!.adapters[0]?.address ?? '';
  return [obj('Microsoft.ActiveDirectory.Management.ADDomainController', {
    ComputerObjectDN: `CN=${d.dc.hostname.toUpperCase()},OU=Domain Controllers,${domainDn(d.ad.domain)}`, Domain: d.ad.domain, Enabled: true, Forest: d.ad.domain, HostName: `${d.dc.hostname.toLowerCase()}.${d.ad.domain}`,
    IPv4Address: ip, IsGlobalCatalog: true, IsReadOnly: false, LdapPort: 389, Name: d.dc.hostname.toUpperCase(), OperatingSystem: d.dc.win!.productName, Site: 'Default-First-Site-Name', SslPort: 636,
  })];
});

adCmdlet('Get-ADDefaultDomainPasswordPolicy', 'Gets the default password policy for an Active Directory domain.', [{ name: 'Identity', type: 'string', position: 0 }], (c) => {
  const d = directory(c);
  if (!d) return [];
  return [obj('Microsoft.ActiveDirectory.Management.ADDefaultDomainPasswordPolicy', {
    ComplexityEnabled: true, DistinguishedName: domainDn(d.ad.domain), LockoutDuration: d.ad.lockoutThreshold ? '00:10:00' : '00:00:00', LockoutObservationWindow: '00:10:00', LockoutThreshold: d.ad.lockoutThreshold,
    MaxPasswordAge: '42.00:00:00', MinPasswordAge: '1.00:00:00', MinPasswordLength: 7, PasswordHistoryCount: 24, ReversibleEncryptionEnabled: false,
  })];
});

adCmdlet('Set-ADDefaultDomainPasswordPolicy', 'Modifies the default password policy for an Active Directory domain.', [{ name: 'Identity', type: 'string', position: 0 }, { name: 'LockoutThreshold', type: 'int' }], (c) => {
  const d = directory(c);
  if (!d) return;
  if (c.has('LockoutThreshold')) d.ad.lockoutThreshold = Number(c.p.LockoutThreshold);
});

// ---------------------------------------------------------------------------
// DNS Server
// ---------------------------------------------------------------------------

function dnsCmdlet(name: string, synopsis: string, params: ParamDef[], run: (c: Call) => PSValue[] | void): void {
  cmdlet({ name, module: DNSSRV, synopsis, params, run, cls: name, available: (ctx) => hasFeature(ctx, 'RSAT-DNS-Server') || hasFeature(ctx, 'DNS') });
}

registerView('CimInstance#DnsServerResourceRecord', {
  kind: 'table', columns: [
    { label: 'HostName', value: 'HostName', width: 25 }, { label: 'RecordType', value: 'RecordType', width: 10 }, { label: 'Type', value: 'Type', width: 10 }, { label: 'Timestamp', value: 'Timestamp', width: 22 },
    { label: 'TimeToLive', value: 'TimeToLive', width: 15 }, { label: 'RecordData', value: 'RecordData' },
  ],
});
registerView('CimInstance#DnsServerZone', {
  kind: 'table', columns: [
    { label: 'ZoneName', value: 'ZoneName', width: 33 }, { label: 'ZoneType', value: 'ZoneType', width: 15 }, { label: 'IsAutoCreated', value: 'IsAutoCreated', width: 13 }, { label: 'IsDsIntegrated', value: 'IsDsIntegrated', width: 14 },
    { label: 'IsReverseLookupZone', value: 'IsReverseLookupZone', width: 19 }, { label: 'IsSigned', value: 'IsSigned' },
  ],
});
registerView('CimInstance#DnsServerForwarder', { kind: 'list', props: ['UseRootHint', 'Timeout(s)', 'EnableReordering', 'IPAddress', 'ReorderedIPAddress'] });

const RR_NUM: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33 };

function dnsServer(c: Call) {
  const ds = c.ctx.host.win?.dnsServer;
  if (!ds || c.ctx.host.win!.services.DNS?.status !== 'Running') {
    c.error(`Failed to enumerate zones from the server ${c.ctx.host.hostname.toUpperCase()}.`, { category: 'ObjectNotFound', target: c.ctx.host.hostname.toUpperCase(), exception: 'CimException', id: `WIN32 1722,${c.name}` });
    return null;
  }
  return ds;
}

function zoneOf(c: Call) {
  const ds = dnsServer(c);
  if (!ds) return null;
  const name = (c.str('ZoneName') ?? '').toLowerCase().replace(/\.$/, '');
  const z = ds.zones.find((x) => x.origin.replace(/\.$/, '') === name);
  if (!z) c.error(`Failed to get the zone information for ${c.str('ZoneName')} on server ${c.ctx.host.hostname.toUpperCase()}.`, { category: 'ObjectNotFound', target: c.str('ZoneName'), exception: 'CimException', id: `WIN32 9601,${c.name}` });
  return z ?? null;
}

function ttlText(s: number): string {
  return `${String(Math.floor(s / 3600)).padStart(2, '0')}:${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
}

dnsCmdlet('Get-DnsServerZone', 'Gets details of DNS zones on a DNS server.', [{ name: 'Name', aliases: ['ZoneName'], type: 'strings', position: 0 }], (c) => {
  const ds = dnsServer(c);
  if (!ds) return [];
  return ds.zones.filter((z) => !c.has('Name') || c.strs('Name')!.some((n) => n.toLowerCase().replace(/\.$/, '') === z.origin.replace(/\.$/, ''))).map((z) => obj('CimInstance#DnsServerZone', {
    ZoneName: z.origin.replace(/\.$/, ''), ZoneType: 'Primary', IsAutoCreated: false, IsDsIntegrated: z.dsIntegrated, IsReverseLookupZone: false, IsSigned: false,
  }));
});

dnsCmdlet('Get-DnsServerResourceRecord', 'Gets resource records from a specified DNS zone.', [{ name: 'ZoneName', type: 'string', position: 0, mandatory: true }, { name: 'Name', type: 'string', position: 1 }, { name: 'RRType', type: 'string' }], (c) => {
  const z = zoneOf(c);
  if (!z) return [];
  const rel = (n: string) => (n === z.origin ? '@' : n.endsWith(`.${z.origin}`) ? n.slice(0, -(z.origin.length + 1)) : n);
  let recs = z.records;
  if (c.has('Name')) {
    const want = c.str('Name')!.toLowerCase();
    recs = recs.filter((r) => rel(r.name) === want || r.name === want || r.name === `${want}.`);
    if (!recs.length) { c.error(`Failed to get ${c.str('Name')} record in ${z.origin.replace(/\.$/, '')} zone on ${c.ctx.host.hostname.toUpperCase()} server.`, { category: 'ObjectNotFound', target: c.str('Name'), exception: 'CimException', id: 'WIN32 9714,Get-DnsServerResourceRecord' }); return []; }
  }
  if (c.has('RRType')) recs = recs.filter((r) => r.type === c.str('RRType')!.toUpperCase());
  return recs.map((r) => obj('CimInstance#DnsServerResourceRecord', {
    HostName: rel(r.name), RecordType: r.type, Type: RR_NUM[r.type] ?? 0, Timestamp: r.type === 'A' && r.ttl === 1200 ? date(c.ctx.host.bootTime) : '0', TimeToLive: ttlText(r.ttl),
    RecordData: r.type === 'SRV' ? `[${r.data.split(' ')[0]}][${r.data.split(' ')[1]}][${r.data.split(' ')[2]}][${r.data.split(' ')[3]}]` : r.type === 'SOA' ? `[${z.serial}][${r.data.split(' ')[0]}][${r.data.split(' ')[1]}]` : r.data,
  }));
});

dnsCmdlet('Add-DnsServerResourceRecordA', 'Adds a type A resource record to a DNS zone.', [{ name: 'ZoneName', type: 'string', mandatory: true }, { name: 'Name', type: 'string', position: 0, mandatory: true }, { name: 'IPv4Address', type: 'strings', position: 1, mandatory: true }, { name: 'TimeToLive', type: 'string' }, { name: 'PassThru', type: 'switch' }], (c) => {
  if (!isAdmin(c)) return;
  const z = zoneOf(c);
  if (!z) return;
  const name = c.str('Name') === '@' ? z.origin : `${c.str('Name')!.toLowerCase()}.${z.origin}`;
  for (const ip of c.strs('IPv4Address') ?? []) {
    if (z.records.some((r) => r.name === name && r.type === 'A' && r.data === ip)) {
      c.error(`Failed to create resource record ${c.str('Name')} in ${z.origin.replace(/\.$/, '')} zone on ${c.ctx.host.hostname.toUpperCase()} server.`, { category: 'ResourceExists', target: c.str('Name'), exception: 'CimException', id: 'WIN32 9711,Add-DnsServerResourceRecordA' });
      continue;
    }
    z.records.push({ name, type: 'A', data: ip, ttl: 3600 });
    z.serial++;
  }
});

dnsCmdlet('Remove-DnsServerResourceRecord', 'Removes specified DNS server resource records from a zone.', [{ name: 'ZoneName', type: 'string', mandatory: true }, { name: 'Name', type: 'string', position: 0, mandatory: true }, { name: 'RRType', type: 'string', position: 1, mandatory: true }, { name: 'RecordData', type: 'string' }, { name: 'Force', type: 'switch' }], (c) => {
  const z = zoneOf(c);
  if (!z) return;
  const name = c.str('Name') === '@' ? z.origin : `${(c.str('Name') ?? '').toLowerCase()}.${z.origin}`;
  const type = (c.str('RRType') ?? '').toUpperCase();
  const hit = z.records.filter((r) => r.name === name && r.type === type && (!c.has('RecordData') || r.data === c.str('RecordData')));
  if (!hit.length) { c.error(`Failed to get ${c.str('Name')} record in ${z.origin.replace(/\.$/, '')} zone on ${c.ctx.host.hostname.toUpperCase()} server.`, { category: 'ObjectNotFound', target: c.str('Name'), exception: 'CimException', id: 'WIN32 9714,Remove-DnsServerResourceRecord' }); return; }
  if (!c.has('Force')) {
    const ans = c.ctx.ask(`\nConfirm\nRemoving DNS resource record set by name ${c.str('Name')} of type ${type} from zone ${z.origin.replace(/\.$/, '')} on ${c.ctx.host.hostname.toUpperCase()} server. Do you want to continue?\n[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): `, false);
    if (/^n/i.test(ans.trim())) return;
  }
  z.records = z.records.filter((r) => !hit.includes(r));
  z.serial++;
});

function forwarderObj(f: string[]): PSObject {
  return obj('CimInstance#DnsServerForwarder', { UseRootHint: true, 'Timeout(s)': 3, EnableReordering: true, IPAddress: f, ReorderedIPAddress: f });
}

dnsCmdlet('Get-DnsServerForwarder', 'Gets forwarder configuration settings on a DNS server.', [], (c) => {
  const ds = dnsServer(c);
  return ds ? [forwarderObj(ds.forwarders)] : [];
});

for (const [verb, mode] of [['Add', 'add'], ['Set', 'set'], ['Remove', 'remove']] as const) {
  dnsCmdlet(`${verb}-DnsServerForwarder`, `${verb === 'Set' ? 'Changes' : verb === 'Add' ? 'Adds' : 'Removes'} server-level forwarders.`, [{ name: 'IPAddress', type: 'strings', position: 0 }, { name: 'Force', type: 'switch' }, { name: 'PassThru', type: 'switch' }], (c) => {
    const ds = dnsServer(c);
    if (!ds) return [];
    const ips = c.strs('IPAddress') ?? [];
    if (mode === 'set') ds.forwarders = [...ips];
    else if (mode === 'add') for (const ip of ips) { if (!ds.forwarders.includes(ip)) ds.forwarders.push(ip); }
    else ds.forwarders = ds.forwarders.filter((f) => !ips.includes(f));
    return c.has('PassThru') ? [forwarderObj(ds.forwarders)] : [];
  });
}

dnsCmdlet('Clear-DnsServerCache', 'Clears resource records from a DNS server cache.', [{ name: 'Force', type: 'switch' }], () => []);

// ---------------------------------------------------------------------------
// Roles and features, promotion
// ---------------------------------------------------------------------------

const FEATURES: [string, string, string?][] = [
  ['AD-Domain-Services', 'Active Directory Domain Services'],
  ['DHCP', 'DHCP Server'],
  ['DNS', 'DNS Server'],
  ['FileAndStorage-Services', 'File and Storage Services'],
  ['Storage-Services', 'Storage Services', 'FileAndStorage-Services'],
  ['Web-Server', 'Web Server (IIS)'],
  ['Web-WebServer', 'Web Server', 'Web-Server'],
  ['NET-Framework-45-Core', '.NET Framework 4.8'],
  ['GPMC', 'Group Policy Management'],
  ['RSAT-AD-PowerShell', 'Active Directory module for Windows PowerShell'],
  ['RSAT-DNS-Server', 'DNS Server Tools'],
  ['Telnet-Client', 'Telnet Client'],
  ['Windows-Defender', 'Microsoft Defender Antivirus'],
  ['PowerShell', 'Windows PowerShell 5.1'],
];

registerView('Microsoft.Windows.ServerManager.Commands.Feature', {
  kind: 'table', columns: [
    { label: 'Display Name', value: (o) => `${o.__sub ? '    ' : ''}[${o.Installed ? 'X' : ' '}] ${toStr(o.DisplayName)}`, width: 52 }, { label: 'Name', value: 'Name', width: 24 }, { label: 'Install State', value: 'InstallState' },
  ],
});
registerView('Microsoft.Windows.ServerManager.Commands.FeatureOperationResult', {
  kind: 'table', columns: [{ label: 'Success', value: 'Success', width: 7 }, { label: 'Restart Needed', value: 'RestartNeeded', width: 14 }, { label: 'Exit Code', value: 'ExitCode', width: 14 }, { label: 'Feature Result', value: 'FeatureResult' }],
});

cmdlet({
  name: 'Get-WindowsFeature', module: SM, synopsis: 'Gets information about Windows Server roles, role services, and features.',
  params: [{ name: 'Name', type: 'strings', position: 0 }],
  run(c) {
    const inst = c.ctx.host.win?.features ?? [];
    return FEATURES.filter(([n]) => !c.has('Name') || c.strs('Name')!.some((x) => wildcard(x).test(n))).map(([n, dn, parent]) => obj('Microsoft.Windows.ServerManager.Commands.Feature', { DisplayName: dn, Name: n, InstallState: inst.includes(n) ? 'Installed' : 'Available', Installed: inst.includes(n), __sub: !!parent }));
  },
});

cmdlet({
  name: 'Install-WindowsFeature', module: SM, synopsis: 'Installs one or more roles, role services, or features.', cls: 'Microsoft.Windows.ServerManager.Commands.AddWindowsFeatureCommand',
  params: [{ name: 'Name', type: 'strings', position: 0 }, { name: 'IncludeManagementTools', type: 'switch' }, { name: 'IncludeAllSubFeature', type: 'switch' }, { name: 'Restart', type: 'switch' }],
  run(c) {
    const w = c.ctx.host.win!;
    if (!isAdmin(c)) { c.error('The requested operation requires elevation.', { category: 'PermissionDenied', target: '', exception: 'UnauthorizedAccessException', id: 'NotSupported,Microsoft.Windows.ServerManager.Commands.AddWindowsFeatureCommand' }); return []; }
    const names = c.strs('Name') ?? [];
    const added: string[] = [];
    for (const n of names) {
      const f = FEATURES.find(([x]) => x.toLowerCase() === n.toLowerCase());
      if (!f) { c.error(`ArgumentNotValid: The role, role service, or feature name is not valid: '${n}'. The name was not found.`, { category: 'InvalidArgument', target: n, exception: 'Exception', id: 'NameDoesNotExist,Microsoft.Windows.ServerManager.Commands.AddWindowsFeatureCommand' }); return []; }
      const tools = c.has('IncludeManagementTools') ? (f[0] === 'AD-Domain-Services' ? ['RSAT-AD-PowerShell', 'GPMC'] : f[0] === 'DNS' ? ['RSAT-DNS-Server'] : []) : [];
      for (const x of [f[0], ...tools]) if (!w.features!.includes(x)) { w.features!.push(x); added.push(FEATURES.find(([y]) => y === x)![1]); }
      if (f[0] === 'DNS' && !w.dnsServer) {
        w.dnsServer = { zones: [], forwarders: [] };
        w.services.DNS = { name: 'DNS', displayName: 'DNS Server', startType: 'Automatic', status: 'Stopped', process: 'dns', pid: null, dependsOn: ['RpcSs'] };
      }
    }
    if (!added.length) c.warn('No changes were made.');
    if (names.some((n) => n.toLowerCase() === 'ad-domain-services') && !c.has('IncludeManagementTools')) c.warn('Windows automatic updating is not enabled. To ensure that your newly-installed role or feature is automatically updated, turn on Windows Update.');
    winEvent(c.ctx.world, c.ctx.host, 'Setup', 2, 'Microsoft-Windows-Servicing', `Package ${names.join(', ')} was successfully changed to the Installed state.`);
    return [obj('Microsoft.Windows.ServerManager.Commands.FeatureOperationResult', { Success: true, RestartNeeded: 'No', ExitCode: added.length ? 'Success' : 'NoChangeNeeded', FeatureResult: added.length ? added : [] })];
  },
});

cmdlet({
  name: 'Install-ADDSForest', module: 'ADDSDeployment', synopsis: 'Creates a new Active Directory forest configuration.', cls: 'Microsoft.DirectoryServices.Deployment.PowerShell.Commands.InstallADDSForestCommand',
  available: (ctx) => hasFeature(ctx, 'AD-Domain-Services'),
  params: [
    { name: 'DomainName', type: 'string', position: 0 }, { name: 'DomainNetbiosName', type: 'string' }, { name: 'InstallDns', type: 'switch' }, { name: 'SafeModeAdministratorPassword', type: 'any' },
    { name: 'Force', type: 'switch' }, { name: 'NoRebootOnCompletion', type: 'switch' }, { name: 'DomainMode', type: 'string' }, { name: 'ForestMode', type: 'string' }, { name: 'CreateDnsDelegation', type: 'switch' },
  ],
  run(c) {
    const host = c.ctx.host;
    const w = host.win!;
    const fail = (msg: string) => c.error(`Verification of prerequisites for Domain Controller promotion failed. ${msg}`, { category: 'NotSpecified', target: '', exception: 'TestFailedException', id: 'Test.VerifyDcPromoCore.DCPromo.General.77,Microsoft.DirectoryServices.Deployment.PowerShell.Commands.InstallADDSForestCommand' });
    if (!isAdmin(c)) { fail('Access is denied.'); return []; }
    if (w.ad) { fail('The server is already a domain controller.'); return []; }
    if (w.domain) { fail('The server is a member of a domain. Use Install-ADDSDomainController to add a domain controller to an existing domain.'); return []; }
    const domain = (c.str('DomainName') ?? c.ctx.ask('\ncmdlet Install-ADDSForest at command pipeline position 1\nSupply values for the following parameters:\nDomainName: ', false)).toLowerCase().replace(/\.$/, '');
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) { fail(`The specified argument 'DomainName' was not recognized as a valid DNS name: ${domain}`); return []; }
    const netbios = (c.str('DomainNetbiosName') ?? domain.split('.')[0]).toUpperCase().slice(0, 15);
    let dsrm = plain(c.p.SafeModeAdministratorPassword ?? null);
    if (dsrm === null) {
      dsrm = c.ctx.ask('SafeModeAdministratorPassword: ', true);
      const again = c.ctx.ask('Confirm SafeModeAdministratorPassword: ', true);
      if (again !== dsrm) { c.error('The passwords do not match.', { category: 'InvalidArgument', target: '', exception: 'ArgumentException', id: 'PasswordMismatch' }); return []; }
    }
    if (!complexEnough(dsrm, 'Administrator')) { fail('The Directory Services Restore Mode password does not meet the complexity requirements.'); return []; }
    if (!c.has('Force')) {
      const ans = c.ctx.ask('The target server will be configured as a domain controller and restarted when this operation is complete.\nDo you want to continue with this operation?\n[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): ', false);
      if (/^[nl]/i.test(ans.trim())) return [];
    }
    if (w.adapters.some((a) => a.dhcp)) c.warn('This computer has at least one physical network adapter that does not have static IP address(es) assigned to its IP Properties. If both IPv4 and IPv6 are enabled for a network adapter, both IPv4 and IPv6 static IP addresses should be assigned to both IPv4 and IPv6 Properties of the physical network adapter. Such static IP address(es) assignment should be done to all the physical network adapters for reliable Domain Name System (DNS) operation.');
    c.warn('Windows Server 2022 domain controllers have a default for the security setting named "Allow cryptography algorithms compatible with Windows NT 4.0" that prevents weaker cryptography algorithms when establishing security channel sessions.\n\nFor more information about this setting, see Knowledge Base article 942564 (http://go.microsoft.com/fwlink/?LinkId=104751).');
    c.warn(`A delegation for this DNS server cannot be created because the authoritative parent zone cannot be found or it does not run Windows DNS server. If you are integrating with an existing DNS infrastructure, you should manually create a delegation to this DNS server in the parent zone to ensure reliable name resolution from outside the domain "${domain}". Otherwise, no action is required.`);
    if (!w.services.DNS && !c.has('InstallDns')) c.warn('The DNS Server role is not installed: install it (-InstallDns) or point members at another DNS server that hosts the domain\'s zone.');
    promoteForest(c.ctx.world, host, domain, netbios);
    if (!c.has('NoRebootOnCompletion')) c.ctx.reboot = true;
    return [obj('Microsoft.DirectoryServices.Deployment.Types.DeploymentResult', { Message: 'Operation completed successfully', Context: 'DCPromo.General.3', RebootRequired: c.has('NoRebootOnCompletion'), Status: 'Success' })];
  },
});

// ---------------------------------------------------------------------------
// Domain membership
// ---------------------------------------------------------------------------

function joinError(c: Call, domain: string, message: string): void {
  const h = c.ctx.host.hostname.toUpperCase();
  c.error(`Computer '${h}' failed to join domain '${domain}' from its current workgroup '${c.ctx.host.win!.workgroup}' with following error message: ${message}`, { category: 'OperationStopped', target: h, exception: 'InvalidOperationException', id: 'FailToJoinDomainFromWorkgroup,Microsoft.PowerShell.Commands.AddComputerCommand' });
}

/** Check domain credentials against the DC (Kerberos AS exchange from this computer). */
function checkDomainCred(c: Call, dc: Host, cred: { user: string; password: string }): string | null {
  const ad = dc.win!.ad!;
  const kdc = tcpConnect(c.ctx.world, c.ctx.host, dc.win!.adapters[0].address!, 88, { timeoutMs: 3000 });
  if (!kdc.ok) return 'The specified domain either does not exist or could not be contacted.';
  kdc.conn.close('client');
  const { sam } = splitUser(cred.user);
  const u = adUser(ad, sam);
  if (!u || u.password !== cred.password) {
    if (u) u.badCount++;
    return 'The user name or password is incorrect.';
  }
  if (u.lockedOut) return 'The referenced account is currently locked out and may not be logged on to.';
  if (!u.enabled) return 'The referenced account is currently disabled and may not be logged on to.';
  return null;
}

cmdlet({
  name: 'Add-Computer', module: MGMT, synopsis: 'Adds the local computer to a domain or workgroup.',
  params: [{ name: 'DomainName', type: 'string', position: 0 }, { name: 'Credential', type: 'any', position: 1 }, { name: 'Restart', type: 'switch' }, { name: 'OUPath', type: 'string' }, { name: 'Server', type: 'string' }, { name: 'Force', type: 'switch' }, { name: 'PassThru', type: 'switch' }],
  run(c) {
    const host = c.ctx.host;
    const w = host.win!;
    const domain = (c.str('DomainName') ?? '').toLowerCase().replace(/\.$/, '');
    if (!domain) { c.error('Cannot process command because of one or more missing mandatory parameters: DomainName.', { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'MissingMandatoryParameter,Microsoft.PowerShell.Commands.AddComputerCommand' }); return []; }
    if (w.domain?.domain === domain || w.pendingDomain?.domain === domain) {
      c.error(`Cannot add computer '${host.hostname.toUpperCase()}' to domain '${domain}' because it is already in that domain.`, { category: 'InvalidOperation', target: host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'AddComputerToSameDomain,Microsoft.PowerShell.Commands.AddComputerCommand' });
      return [];
    }
    if (!isAdmin(c)) { joinError(c, domain, 'Access is denied.'); return []; }
    const cred = credential(c) ?? { user: c.ctx.ask('\ncmdlet Add-Computer at command pipeline position 1\nSupply values for the following parameters:\nUser: ', false), password: '' };
    if (!cred.password) cred.password = c.ctx.ask(`\nWindows PowerShell credential request.\nEnter your credentials.\nPassword for user ${cred.user}: `, true);
    const loc = locateDc(c.ctx.world, host, domain);
    if (!loc.ok) { joinError(c, domain, 'The specified domain either does not exist or could not be contacted.'); return []; }
    const bad = checkDomainCred(c, loc.dc, cred);
    if (bad) { joinError(c, domain, bad); return []; }
    const ouPath = c.str('OUPath');
    if (ouPath && !gpData(loc.dc.win!.ad!).ous[normDn(ouPath)]) { joinError(c, domain, 'The system cannot find the file specified.'); return []; }
    if (c.whatIf('Add-Computer', host.hostname.toUpperCase())) return [];
    joinDomain(c.ctx.world, host, loc.dc, ouPath);
    winEvent(c.ctx.world, host, 'System', 4097, 'NetSetup', `The machine ${host.hostname.toUpperCase()} attempted to join the domain ${domain} and succeeded.`);
    if (c.has('Restart')) { c.ctx.reboot = true; return []; }
    c.warn(`The changes will take effect after you restart the computer ${host.hostname.toUpperCase()}.`);
    return c.has('PassThru') ? [obj('Microsoft.PowerShell.Commands.ComputerChangeInfo', { HasSucceeded: true, ComputerName: host.hostname.toUpperCase() })] : [];
  },
});

cmdlet({
  name: 'Remove-Computer', module: MGMT, synopsis: 'Removes the local computer from its domain.',
  params: [{ name: 'UnjoinDomainCredential', aliases: ['Credential'], type: 'any' }, { name: 'WorkgroupName', type: 'string' }, { name: 'Restart', type: 'switch' }, { name: 'Force', type: 'switch' }, { name: 'PassThru', type: 'switch' }],
  run(c) {
    const host = c.ctx.host;
    const w = host.win!;
    if (!w.domain || w.ad) { c.error(`Computer '${host.hostname.toUpperCase()}' is not in a domain.`, { category: 'InvalidOperation', target: host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'ComputerNotInDomain,Microsoft.PowerShell.Commands.RemoveComputerCommand' }); return []; }
    if (!c.has('Force')) {
      const ans = c.ctx.ask(`\nConfirm\nAfter you leave the domain, you will need to know the password of the local Administrator account to log onto this computer. Do you wish to continue?\n[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): `, false);
      if (/^n/i.test(ans.trim())) return [];
    }
    const loc = locateDc(c.ctx.world, host, w.domain.domain);
    if (loc.ok) { const comp = loc.dc.win!.ad!.computers[host.hostname.toLowerCase()]; if (comp) comp.enabled = false; }
    w.pendingDomain = null;
    w.workgroup = c.str('WorkgroupName') ?? 'WORKGROUP';
    if (c.has('Restart')) { c.ctx.reboot = true; return []; }
    c.warn(`The changes will take effect after you restart the computer ${host.hostname.toUpperCase()}.`);
    return [];
  },
});

function repairAuth(c: Call, dc: Host): boolean {
  const cred = credential(c);
  if (!cred) {
    // The console runs as the local Administrator: it has no rights in the domain.
    c.error('Cannot reset the secure channel password for the computer account in the domain. Operation failed with the following exception: Access is denied.', { category: 'OperationStopped', target: c.ctx.host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'FailToResetComputerAccountPassword,Microsoft.PowerShell.Commands.TestComputerSecureChannelCommand' });
    return false;
  }
  const bad = checkDomainCred(c, dc, cred);
  const groups = principalGroups(dc.win!.ad!, splitUser(cred.user).sam);
  if (bad || !groups.includes('Domain Admins')) {
    c.error(`Cannot reset the secure channel password for the computer account in the domain. Operation failed with the following exception: ${bad ?? 'Access is denied.'}`, { category: 'OperationStopped', target: c.ctx.host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'FailToResetComputerAccountPassword,Microsoft.PowerShell.Commands.TestComputerSecureChannelCommand' });
    return false;
  }
  return true;
}

cmdlet({
  name: 'Test-ComputerSecureChannel', module: MGMT, synopsis: 'Tests and repairs the secure channel between the local computer and its domain.',
  params: [{ name: 'Repair', type: 'switch' }, { name: 'Credential', type: 'any' }, { name: 'Server', type: 'string' }],
  run(c) {
    const host = c.ctx.host;
    if (!host.win!.domain) { c.error('Cannot verify the secure channel password for the local computer. Local computer is not joined to a domain.', { category: 'InvalidOperation', target: host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'ComputerNotInDomain,Microsoft.PowerShell.Commands.TestComputerSecureChannelCommand' }); return []; }
    const ch = secureChannel(c.ctx.world, host);
    if (!c.has('Repair') || ch.state === 'ok') return [ch.state === 'ok'];
    if (ch.state === 'no-dc' || !ch.dc?.ok) {
      c.error('Cannot reset the secure channel password for the computer account in the domain. Operation failed with the following exception: The specified domain either does not exist or could not be contacted.', { category: 'OperationStopped', target: host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'FailToResetComputerAccountPassword,Microsoft.PowerShell.Commands.TestComputerSecureChannelCommand' });
      return [false];
    }
    if (!repairAuth(c, ch.dc.dc)) return [false];
    resetMachinePassword(c.ctx.world, host, ch.dc.dc);
    winEvent(c.ctx.world, host, 'System', 5823, 'NETLOGON', `The system successfully changed its password on the domain controller ${ch.dc.name}. This event is logged when the password for the computer account is changed by the system.`);
    return [true];
  },
});

cmdlet({
  name: 'Reset-ComputerMachinePassword', module: MGMT, synopsis: 'Resets the machine account password for the computer.',
  params: [{ name: 'Credential', type: 'any' }, { name: 'Server', type: 'string' }],
  run(c) {
    const host = c.ctx.host;
    if (!host.win!.domain) { c.error('Cannot reset the machine account password for the local computer. Local computer is not joined to a domain.', { category: 'InvalidOperation', target: host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'ComputerNotInDomain,Microsoft.PowerShell.Commands.ResetComputerMachinePasswordCommand' }); return; }
    const loc = locateDc(c.ctx.world, host, host.win!.domain.domain);
    if (!loc.ok) { c.error('The specified domain either does not exist or could not be contacted.', { category: 'OperationStopped', target: host.hostname.toUpperCase(), exception: 'InvalidOperationException', id: 'FailToResetPasswordOnLocalMachine,Microsoft.PowerShell.Commands.ResetComputerMachinePasswordCommand' }); return; }
    if (!repairAuth(c, loc.dc)) return;
    resetMachinePassword(c.ctx.world, host, loc.dc);
  },
});
