// Group Policy management in PowerShell: the GroupPolicy module (GPMC feature:
// New-GPO, Get-GPO, New-GPLink, Set-GPLink, Remove-GPLink, Get-GPInheritance,
// Set-GPInheritance, Set-/Get-/Remove-GPRegistryValue, Set-/Get-GPPermission)
// and the ActiveDirectory cmdlets for organizational units
// (New-ADOrganizationalUnit, Get-ADOrganizationalUnit, Move-ADObject).

import { domainDn } from '../../ad';
import { computerDn, findGpo, gpData, hivePath, linkedGpos, normDn, defaultGpoPermissions } from '../../gpo';
import { winEvent, type AdState, type Gpo, type GpPermission } from '../../model';
import { registerView } from '../format';
import { cmdlet, type Call, type ParamDef } from '../runtime';
import { date, flatten, getProp, isObj, obj, toStr, wildcard, type PSObject, type PSValue } from '../values';
import { adCmdlet, directory, guid, ID } from './ad';

const GPMOD = 'GroupPolicy';

registerView('Microsoft.GroupPolicy.Gpo', { kind: 'list', props: ['DisplayName', 'DomainName', 'Owner', 'Id', 'GpoStatus', 'Description', 'CreationTime', 'ModificationTime', 'UserVersion', 'ComputerVersion', 'WmiFilter'] });
registerView('Microsoft.GroupPolicy.GpoLink', { kind: 'list', props: ['GpoId', 'DisplayName', 'Enabled', 'Enforced', 'Target', 'Order'] });
registerView('Microsoft.GroupPolicy.Som', { kind: 'list', props: ['Name', 'ContainerType', 'Path', 'GpoInheritanceBlocked', 'GpoLinks', 'InheritedGpoLinks'] });
registerView('Microsoft.GroupPolicy.GpPermission', { kind: 'list', props: ['Trustee', 'TrusteeType', 'Permission', 'Inherited'] });
registerView('Microsoft.GroupPolicy.PolicyRegistrySetting', { kind: 'list', props: ['KeyPath', 'FullKeyPath', 'Hive', 'PolicyState', 'Value', 'Type', 'ValueName', 'HasValue'] });
registerView('Microsoft.ActiveDirectory.Management.ADOrganizationalUnit', { kind: 'list', props: ['City', 'Country', 'DistinguishedName', 'LinkedGroupPolicyObjects', 'ManagedBy', 'Name', 'ObjectClass', 'ObjectGUID', 'PostalCode', 'State', 'StreetAddress'] });

function gpCmdlet(name: string, synopsis: string, params: ParamDef[], run: (c: Call) => PSValue[] | void): void {
  cmdlet({ name, module: GPMOD, synopsis, params, run, cls: `Microsoft.GroupPolicy.Commands.${name.replace('-', '')}Command`, available: (ctx) => !!ctx.host.win?.features?.includes('GPMC') });
}

const gpoPath = (ad: AdState, g: Gpo) => `cn={${g.id}},cn=policies,cn=system,${domainDn(ad.domain).toLowerCase()}`;

function gpoObj(ad: AdState, g: Gpo): PSObject {
  return obj('Microsoft.GroupPolicy.Gpo', {
    DisplayName: g.name, DomainName: ad.domain, Owner: `${ad.netbios}\\Domain Admins`, Id: g.id.toLowerCase(), GpoStatus: g.status, Description: g.description,
    CreationTime: date(g.created), ModificationTime: date(g.modified), UserVersion: 'AD Version: 0, SysVol Version: 0',
    ComputerVersion: `AD Version: ${g.computerVersion}, SysVol Version: ${g.computerVersion}`, WmiFilter: null, Path: gpoPath(ad, g), __str: 'Microsoft.GroupPolicy.Gpo',
  });
}

function noGpo(c: Call, ad: AdState, name: string): void {
  c.error(`The GPO named '${name}' was not found in the ${ad.domain} domain.`, { category: 'ObjectNotFound', target: name, exception: 'ArgumentException', id: `GpoWithNameNotFound,Microsoft.GroupPolicy.Commands.${c.name.replace('-', '')}Command` });
}

/** -Name / -Guid / a piped GPO. */
function targetGpo(c: Call, ad: AdState): Gpo | null {
  const piped = c.input.find(isObj);
  const name = c.str('Name') ?? c.str('Guid') ?? (piped ? toStr(getProp(piped, 'DisplayName')) : undefined);
  if (!name) { c.error('Cannot process command because of one or more missing mandatory parameters: Name.', { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: `MissingMandatoryParameter,Microsoft.GroupPolicy.Commands.${c.name.replace('-', '')}Command` }); return null; }
  const g = findGpo(ad, name);
  if (!g) { noGpo(c, ad, name); return null; }
  return g;
}

/** A changed GPO gets a new version (members see new settings at their next processing). */
export function touchGpo(c: Call, g: Gpo): void {
  g.computerVersion++;
  g.modified = c.ctx.world.clock;
}

/** A link target: the domain or an existing OU. */
function container(c: Call, ad: AdState, target: string): { dn: string; kind: 'Domain' | 'OU' } | null {
  const n = normDn(target);
  if (n === normDn(domainDn(ad.domain))) return { dn: domainDn(ad.domain), kind: 'Domain' };
  const ou = gpData(ad).ous[n];
  if (ou) return { dn: ou.dn, kind: 'OU' };
  c.error(`The "${target}" path was not found in the Active Directory domain.`, { category: 'ObjectNotFound', target, exception: 'ArgumentException', id: `SomNotFound,Microsoft.GroupPolicy.Commands.${c.name.replace('-', '')}Command` });
  return null;
}

function linkObj(g: Gpo, target: string, i: number, l: { enabled: boolean; enforced: boolean }): PSObject {
  return obj('Microsoft.GroupPolicy.GpoLink', { GpoId: g.id.toLowerCase(), DisplayName: g.name, Enabled: l.enabled, Enforced: l.enforced, Target: target, Order: i + 1 });
}

const yesNo = (c: Call, p: string): boolean | undefined => (c.has(p) ? /^(yes|true|1)$/i.test(c.str(p) ?? '') : undefined);

// ---- GPOs ---------------------------------------------------------------------

gpCmdlet('New-GPO', 'Creates a GPO.', [{ name: 'Name', type: 'string', position: 0, mandatory: true }, { name: 'Comment', type: 'string' }, { name: 'Domain', type: 'string' }, { name: 'Server', type: 'string' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const name = c.str('Name') ?? '';
  if (findGpo(d.ad, name)) {
    c.error(`A GPO with the name "${name}" already exists in the ${d.ad.domain} domain.`, { category: 'InvalidArgument', target: name, exception: 'ArgumentException', id: 'GpoWithNameAlreadyExists,Microsoft.GroupPolicy.Commands.NewGpoCommand' });
    return [];
  }
  const id = guid(`${d.ad.domain}:gpo:${name}:${c.ctx.world.counter}`).toUpperCase();
  const g: Gpo = { id, name, status: 'AllSettingsEnabled', description: c.str('Comment') ?? '', registry: [], firewallRules: [], permissions: defaultGpoPermissions(), computerVersion: 0, created: c.ctx.world.clock, modified: c.ctx.world.clock };
  gpData(d.ad).gpos[id] = g;
  winEvent(c.ctx.world, d.dc, 'Security', 5137, 'Microsoft-Windows-Security-Auditing', `A directory service object was created.\n\nObject:\n\tDN:\t${gpoPath(d.ad, g).toUpperCase()}\n\tClass:\tgroupPolicyContainer`);
  return [gpoObj(d.ad, g)];
});

gpCmdlet('Get-GPO', 'Gets one GPO or all the GPOs in a domain.', [{ name: 'Name', aliases: ['DisplayName'], type: 'string', position: 0 }, { name: 'Guid', aliases: ['Id'], type: 'string' }, { name: 'All', type: 'switch' }, { name: 'Domain', type: 'string' }, { name: 'Server', type: 'string' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  if (c.has('All')) return Object.values(gpData(d.ad).gpos).sort((a, b) => a.name.localeCompare(b.name)).map((g) => gpoObj(d.ad, g));
  const g = targetGpo(c, d.ad);
  return g ? [gpoObj(d.ad, g)] : [];
});

gpCmdlet('Remove-GPO', 'Removes a GPO.', [{ name: 'Name', aliases: ['DisplayName'], type: 'string', position: 0 }, { name: 'Guid', type: 'string' }, { name: 'KeepLinks', type: 'switch' }], (c) => {
  const d = directory(c);
  if (!d) return;
  const g = targetGpo(c, d.ad);
  if (!g || c.whatIf('Remove-GPO', g.name)) return;
  const data = gpData(d.ad);
  delete data.gpos[g.id];
  for (const k of Object.keys(data.links)) data.links[k] = data.links[k].filter((l) => l.gpoId !== g.id);
});

// ---- links and inheritance -------------------------------------------------

gpCmdlet('New-GPLink', 'Links a GPO to a site, domain, or organizational unit.', [{ name: 'Name', type: 'string', position: 0 }, { name: 'Guid', type: 'string' }, { name: 'Target', type: 'string', position: 1 }, { name: 'LinkEnabled', type: 'string' }, { name: 'Enforced', type: 'string' }, { name: 'Order', type: 'int' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  const t = g && container(c, d.ad, c.str('Target') ?? '');
  if (!g || !t) return [];
  const links = (gpData(d.ad).links[normDn(t.dn)] ??= []);
  if (links.some((l) => l.gpoId === g.id)) {
    c.error(`The GPO named '${g.name}' is already linked to a Scope of Management with Path '${t.dn}'.`, { category: 'InvalidArgument', target: g.name, exception: 'ArgumentException', id: 'GpoLinkAlreadyExists,Microsoft.GroupPolicy.Commands.NewGPLinkCommand' });
    return [];
  }
  const l = { gpoId: g.id, enabled: yesNo(c, 'LinkEnabled') ?? true, enforced: yesNo(c, 'Enforced') ?? false };
  const at = c.has('Order') ? Math.max(0, Math.min(links.length, Number(c.p.Order) - 1)) : links.length;
  links.splice(at, 0, l);
  return [linkObj(g, t.dn, at, l)];
});

gpCmdlet('Set-GPLink', 'Sets the properties of the specified GPO link.', [{ name: 'Name', type: 'string', position: 0 }, { name: 'Guid', type: 'string' }, { name: 'Target', type: 'string', position: 1 }, { name: 'LinkEnabled', type: 'string' }, { name: 'Enforced', type: 'string' }, { name: 'Order', type: 'int' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  const t = g && container(c, d.ad, c.str('Target') ?? '');
  if (!g || !t) return [];
  const links = gpData(d.ad).links[normDn(t.dn)] ?? [];
  const i = links.findIndex((l) => l.gpoId === g.id);
  if (i < 0) {
    c.error(`The GPO named '${g.name}' is not linked to a Scope of Management with Path '${t.dn}'.`, { category: 'InvalidArgument', target: g.name, exception: 'ArgumentException', id: 'GpoLinkNotFound,Microsoft.GroupPolicy.Commands.SetGPLinkCommand' });
    return [];
  }
  const l = links[i];
  l.enabled = yesNo(c, 'LinkEnabled') ?? l.enabled;
  l.enforced = yesNo(c, 'Enforced') ?? l.enforced;
  let at = i;
  if (c.has('Order')) { links.splice(i, 1); at = Math.max(0, Math.min(links.length, Number(c.p.Order) - 1)); links.splice(at, 0, l); }
  return [linkObj(g, t.dn, at, l)];
});

gpCmdlet('Remove-GPLink', 'Removes a GPO link from a site, domain or organizational unit.', [{ name: 'Name', type: 'string', position: 0 }, { name: 'Guid', type: 'string' }, { name: 'Target', type: 'string', position: 1 }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  const t = g && container(c, d.ad, c.str('Target') ?? '');
  if (!g || !t) return [];
  const data = gpData(d.ad);
  const links = data.links[normDn(t.dn)] ?? [];
  const i = links.findIndex((l) => l.gpoId === g.id);
  if (i < 0) {
    c.error(`The GPO named '${g.name}' is not linked to a Scope of Management with Path '${t.dn}'.`, { category: 'InvalidArgument', target: g.name, exception: 'ArgumentException', id: 'GpoLinkNotFound,Microsoft.GroupPolicy.Commands.RemoveGPLinkCommand' });
    return [];
  }
  const [l] = links.splice(i, 1);
  return [linkObj(g, t.dn, i, l)];
});

function somObj(ad: AdState, dn: string, kind: 'Domain' | 'OU'): PSObject {
  const data = gpData(ad);
  const own = (data.links[normDn(dn)] ?? []).map((l) => data.gpos[l.gpoId]?.name).filter(Boolean);
  // Inherited links as they would apply to an object in this container, highest precedence first.
  const scoped = linkedGpos(ad, `CN=probe,${dn}`);
  const inherited = [...scoped.enforced].reverse().concat([...scoped.normal].reverse()).map((s) => s.gpo.name);
  return obj('Microsoft.GroupPolicy.Som', {
    Name: kind === 'Domain' ? ad.domain : (data.ous[normDn(dn)]?.name ?? dn).toLowerCase(), ContainerType: kind, Path: dn.toLowerCase(),
    GpoInheritanceBlocked: data.ous[normDn(dn)]?.blockInheritance ? 'Yes' : 'No', GpoLinks: own, InheritedGpoLinks: [...new Set(inherited)],
  });
}

gpCmdlet('Get-GPInheritance', 'Retrieves Group Policy inheritance information for a domain or OU.', [{ name: 'Target', type: 'string', position: 0 }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const t = container(c, d.ad, c.str('Target') ?? '');
  return t ? [somObj(d.ad, t.dn, t.kind)] : [];
});

gpCmdlet('Set-GPInheritance', 'Blocks or unblocks inheritance for a domain or OU.', [{ name: 'Target', type: 'string', position: 0 }, { name: 'IsBlocked', type: 'string', position: 1 }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const t = container(c, d.ad, c.str('Target') ?? '');
  if (!t) return [];
  const ou = gpData(d.ad).ous[normDn(t.dn)];
  if (ou) ou.blockInheritance = yesNo(c, 'IsBlocked') ?? ou.blockInheritance;
  return [somObj(d.ad, t.dn, t.kind)];
});

// ---- settings: registry-based policy -------------------------------------------

const REG_PARAMS: ParamDef[] = [{ name: 'Name', aliases: ['DisplayName'], type: 'string', position: 0 }, { name: 'Guid', type: 'string' }, { name: 'Key', type: 'string' }, { name: 'ValueName', type: 'strings' }];

function regObj(v: Gpo['registry'][number]): PSObject {
  const path = hivePath(v.key);
  return obj('Microsoft.GroupPolicy.PolicyRegistrySetting', { KeyPath: path, FullKeyPath: `HKEY_LOCAL_MACHINE\\${path}`, Hive: 'LocalMachine', PolicyState: 'Set', Value: v.value, Type: v.type, ValueName: v.valueName, HasValue: true });
}

function checkKey(c: Call): string | null {
  const key = c.str('Key') ?? '';
  if (/^HK(LM:?|EY_LOCAL_MACHINE)\\/i.test(key)) return key;
  c.error(/^HK(CU|EY_CURRENT_USER)/i.test(key) ? 'User Configuration (HKCU) policy is not modelled in this simulator: use HKLM\\... keys (Computer Configuration).' : `The key "${key}" is not valid. The key must start with HKLM\\ or HKCU\\.`, { category: 'InvalidArgument', target: key, exception: 'ArgumentException', id: `InvalidKey,Microsoft.GroupPolicy.Commands.${c.name.replace('-', '')}Command` });
  return null;
}

gpCmdlet('Set-GPRegistryValue', 'Configures one or more registry-based policy settings under Computer Configuration in a GPO.', [...REG_PARAMS, { name: 'Type', type: 'string' }, { name: 'Value', type: 'any' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  const key = g && checkKey(c);
  if (!g || !key) return [];
  const type = (['DWord', 'String', 'ExpandString', 'QWord'] as const).find((t) => t.toLowerCase() === (c.str('Type') ?? 'String').toLowerCase()) ?? 'String';
  const raw = flatten(c.p.Value ?? '')[0];
  const value = type === 'DWord' || type === 'QWord' ? Number(raw) : toStr(raw);
  for (const name of c.strs('ValueName') ?? []) {
    g.registry = g.registry.filter((v) => !(normDn(hivePath(v.key)) === normDn(hivePath(key)) && v.valueName.toLowerCase() === name.toLowerCase()));
    g.registry.push({ key, valueName: name, type, value });
  }
  touchGpo(c, g);
  return [gpoObj(d.ad, g)];
});

gpCmdlet('Get-GPRegistryValue', 'Retrieves one or more registry-based policy settings under Computer Configuration in a GPO.', REG_PARAMS, (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  if (!g) return [];
  const key = c.str('Key') ?? '';
  const names = c.strs('ValueName');
  const hits = g.registry.filter((v) => normDn(hivePath(v.key)).startsWith(normDn(hivePath(key))) && (!names || names.some((n) => n.toLowerCase() === v.valueName.toLowerCase())));
  if (!hits.length) c.error(`The following key or value was not found in the GPO: ${key}`, { category: 'ObjectNotFound', target: key, exception: 'ArgumentException', id: 'UnableToRetrievePolicySetting,Microsoft.GroupPolicy.Commands.GetGPRegistryValueCommand' });
  return hits.map(regObj);
});

gpCmdlet('Remove-GPRegistryValue', 'Removes one or more registry-based policy settings from Computer Configuration in a GPO.', REG_PARAMS, (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  if (!g) return [];
  const key = c.str('Key') ?? '';
  const names = c.strs('ValueName');
  const before = g.registry.length;
  g.registry = g.registry.filter((v) => !(normDn(hivePath(v.key)) === normDn(hivePath(key)) && (!names || names.some((n) => n.toLowerCase() === v.valueName.toLowerCase()))));
  if (g.registry.length !== before) touchGpo(c, g);
  return [gpoObj(d.ad, g)];
});

// ---- security filtering --------------------------------------------------------

const LEVELS: Record<string, GpPermission | 'None'> = { gporead: 'GpoRead', gpoapply: 'GpoApply', gpoedit: 'GpoEdit', gpoeditdeletemodifysecurity: 'GpoEditDeleteModifySecurity', none: 'None' };
const WELL_KNOWN = ['authenticated users', 'everyone', 'system', 'enterprise domain controllers'];

function trusteeType(ad: AdState, t: string): string {
  if (WELL_KNOWN.includes(t.toLowerCase())) return 'WellKnownGroup';
  if (t.endsWith('$')) return 'Computer';
  return ad.groups[t.toLowerCase()] ? 'Group' : ad.users[t.toLowerCase()] ? 'User' : 'Unknown';
}

function permObj(ad: AdState, trustee: string, p: GpPermission): PSObject {
  const t = trusteeType(ad, trustee);
  return obj('Microsoft.GroupPolicy.GpPermission', { Trustee: t === 'WellKnownGroup' ? (trustee.toUpperCase() === 'SYSTEM' ? 'SYSTEM' : trustee) : `${ad.netbios}\\${trustee}`, TrusteeType: t, Permission: p, Inherited: false });
}

gpCmdlet('Get-GPPermission', 'Gets the permission level for one or more security principals on a GPO.', [{ name: 'Name', aliases: ['DisplayName'], type: 'string', position: 0 }, { name: 'Guid', type: 'string' }, { name: 'TargetName', type: 'string' }, { name: 'TargetType', type: 'string' }, { name: 'All', type: 'switch' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  if (!g) return [];
  const want = c.str('TargetName');
  return Object.entries(g.permissions).filter(([t]) => c.has('All') || !want || t.toLowerCase() === want.replace(/^[^\\]+\\/, '').toLowerCase()).map(([t, p]) => permObj(d.ad, t, p));
});

gpCmdlet('Set-GPPermission', 'Grants a level of permissions to a security principal for a GPO (security filtering and delegation).', [{ name: 'Name', aliases: ['DisplayName'], type: 'string', position: 0 }, { name: 'Guid', type: 'string' }, { name: 'TargetName', type: 'string' }, { name: 'TargetType', type: 'string' }, { name: 'PermissionLevel', type: 'string' }, { name: 'Replace', type: 'switch' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const g = targetGpo(c, d.ad);
  if (!g) return [];
  const raw = (c.str('TargetName') ?? '').replace(/^[^\\]+\\/, '');
  const level = LEVELS[(c.str('PermissionLevel') ?? '').toLowerCase()];
  if (!level) {
    c.error(`Cannot bind parameter 'PermissionLevel'. Cannot convert value "${c.str('PermissionLevel') ?? ''}" to type "Microsoft.GroupPolicy.GPPermissionType". Error: "Unable to match the identifier name ${c.str('PermissionLevel') ?? ''} to a valid enumerator name. Specify one of the following enumerator names and try again:\nNone, GpoRead, GpoApply, GpoEdit, GpoEditDeleteModifySecurity, GpoCustom, WmiFilterEdit, WmiFilterEditPermissions, WmiFilterCustom, StarterGpoRead, StarterGpoEdit, StarterGpoEditPermissions, StarterGpoCustom, SomCreateWmiFilter, SomWmiFilterFullControl, SomCreateGpo, SomCreateStarterGpo, SomLogging, SomPlanning, SomLink"`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage,Microsoft.GroupPolicy.Commands.SetGPPermissionCommand' });
    return [];
  }
  const known = WELL_KNOWN.includes(raw.toLowerCase()) || !!d.ad.groups[raw.toLowerCase()] || !!d.ad.users[raw.toLowerCase()] || (raw.endsWith('$') && !!d.ad.computers[raw.slice(0, -1).toLowerCase()]);
  if (!known) {
    c.error(`Trustee "${raw}" could not be found.`, { category: 'ObjectNotFound', target: raw, exception: 'ArgumentException', id: 'TrusteeNotFound,Microsoft.GroupPolicy.Commands.SetGPPermissionCommand' });
    return [];
  }
  const existing = Object.keys(g.permissions).find((t) => t.toLowerCase() === raw.toLowerCase());
  const name = existing ?? (WELL_KNOWN.includes(raw.toLowerCase()) ? raw.split(' ').map((w) => (w.length > 3 ? w[0].toUpperCase() + w.slice(1).toLowerCase() : w)).join(' ') : d.ad.groups[raw.toLowerCase()]?.name ?? raw);
  if (existing && !c.has('Replace') && level !== 'None') {
    const order = ['GpoRead', 'GpoApply', 'GpoEdit', 'GpoEditDeleteModifySecurity'];
    if (order.indexOf(level) < order.indexOf(g.permissions[existing])) {
      c.error(`The permission level "${g.permissions[existing]}" of trustee "${name}" is higher than "${level}". Use -Replace to lower it.`, { category: 'InvalidOperation', target: name, exception: 'InvalidOperationException', id: 'PermissionLowerThanExisting,Microsoft.GroupPolicy.Commands.SetGPPermissionCommand' });
      return [];
    }
  }
  if (existing) delete g.permissions[existing];
  if (level !== 'None') g.permissions[name] = level;
  g.modified = c.ctx.world.clock;
  return [gpoObj(d.ad, g)];
});

// ---- organizational units ----------------------------------------------------------

function ouObj(ad: AdState, dn: string): PSObject {
  const data = gpData(ad);
  const ou = data.ous[normDn(dn)];
  const linked = (data.links[normDn(dn)] ?? []).map((l) => `cn={${l.gpoId}},cn=policies,cn=system,${domainDn(ad.domain)}`);
  return obj('Microsoft.ActiveDirectory.Management.ADOrganizationalUnit', {
    City: null, Country: null, DistinguishedName: ou.dn, LinkedGroupPolicyObjects: linked, ManagedBy: null, Name: ou.name, ObjectClass: 'organizationalUnit',
    ObjectGUID: guid(`${ad.domain}:ou:${normDn(dn)}`), PostalCode: null, State: null, StreetAddress: null, __str: ou.dn,
  });
}

adCmdlet('New-ADOrganizationalUnit', 'Creates an Active Directory organizational unit.', [{ name: 'Name', type: 'string', position: 0, mandatory: true }, { name: 'Path', type: 'string' }, { name: 'Description', type: 'string' }, { name: 'ProtectedFromAccidentalDeletion', type: 'any' }, { name: 'PassThru', type: 'switch' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const data = gpData(d.ad);
  const parent = c.str('Path') ?? domainDn(d.ad.domain);
  if (normDn(parent) !== normDn(domainDn(d.ad.domain)) && !data.ous[normDn(parent)]) {
    c.error('Directory object not found', { category: 'ObjectNotFound', target: `OU=${c.str('Name')},${parent}`, exception: 'ADIdentityNotFoundException', id: 'ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.NewADOrganizationalUnit' });
    return [];
  }
  const dn = `OU=${c.str('Name')},${data.ous[normDn(parent)]?.dn ?? domainDn(d.ad.domain)}`;
  if (data.ous[normDn(dn)]) {
    c.error('An attempt was made to add an object to the directory with a name that is already in use', { category: 'NotSpecified', target: dn, exception: 'ADException', id: 'ActiveDirectoryServer:8305,Microsoft.ActiveDirectory.Management.Commands.NewADOrganizationalUnit' });
    return [];
  }
  data.ous[normDn(dn)] = { dn, name: c.str('Name') ?? '', description: c.str('Description') ?? '', blockInheritance: false, protected: !/^\$?false$/i.test(toStr(c.p.ProtectedFromAccidentalDeletion ?? true)) };
  return c.has('PassThru') ? [ouObj(d.ad, dn)] : [];
});

adCmdlet('Get-ADOrganizationalUnit', 'Gets one or more Active Directory organizational units.', [ID, { name: 'Filter', type: 'any' }, { name: 'SearchBase', type: 'string' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const data = gpData(d.ad);
  if (c.has('Filter')) {
    const f = toStr(c.p.Filter).trim();
    const m = /^name\s+-(eq|like)\s+["']?([^"']+)["']?$/i.exec(f);
    return Object.values(data.ous).filter((o) => f === '*' || (m && wildcard(m[2]).test(o.name))).map((o) => ouObj(d.ad, o.dn));
  }
  const id = c.str('Identity') ?? '';
  const ou = data.ous[normDn(id)] ?? Object.values(data.ous).find((o) => o.name.toLowerCase() === id.toLowerCase());
  if (!ou) {
    c.error(`Cannot find an object with identity: '${id}' under: '${domainDn(d.ad.domain)}'.`, { category: 'ObjectNotFound', target: id, exception: 'ADIdentityNotFoundException', id: 'ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.GetADOrganizationalUnit' });
    return [];
  }
  return [ouObj(d.ad, ou.dn)];
});

adCmdlet('Move-ADObject', 'Moves an Active Directory object (here: a computer) to a different container.', [ID, { name: 'TargetPath', type: 'string', position: 1 }, { name: 'PassThru', type: 'switch' }], (c) => {
  const d = directory(c);
  if (!d) return [];
  const piped = c.input.find(isObj);
  const id = c.has('Identity') ? (isObj(c.p.Identity) ? toStr(getProp(c.p.Identity as PSObject, 'DistinguishedName')) : c.str('Identity')!) : piped ? toStr(getProp(piped, 'DistinguishedName')) : '';
  const key = Object.keys(d.ad.computers).find((k) => normDn(computerDn(d.ad, k)) === normDn(id) || k === id.replace(/\$$/, '').toLowerCase());
  if (!key) {
    c.error(`Cannot find an object with identity: '${id}' under: '${domainDn(d.ad.domain)}'.`, { category: 'ObjectNotFound', target: id, exception: 'ADIdentityNotFoundException', id: 'ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.MoveADObject' });
    return [];
  }
  const target = c.str('TargetPath') ?? '';
  const data = gpData(d.ad);
  const ou = data.ous[normDn(target)];
  const toComputers = normDn(target) === normDn(`CN=Computers,${domainDn(d.ad.domain)}`);
  if (!ou && !toComputers) {
    c.error('Directory object not found', { category: 'ObjectNotFound', target, exception: 'ADIdentityNotFoundException', id: 'ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,Microsoft.ActiveDirectory.Management.Commands.MoveADObject' });
    return [];
  }
  if (toComputers) delete d.ad.computers[key].ou;
  else d.ad.computers[key].ou = ou!.dn;
  return [];
});

// Firewall rules stored in a GPO (New-NetFirewallRule -PolicyStore "domain\GPO") are handled in firewall.ts.
export function gpoForStore(c: Call, store: string): { ad: AdState; gpo: Gpo } | null {
  const m = /^([^\\]+)\\(.+)$/.exec(store);
  if (!m) return null;
  const d = directory(c);
  if (!d) return null;
  if (m[1].toLowerCase() !== d.ad.domain && m[1].toLowerCase() !== d.ad.netbios.toLowerCase()) {
    c.error('The specified domain either does not exist or could not be contacted.', { category: 'ObjectNotFound', target: store, exception: 'CimException', id: `Windows System Error 1355,${c.name}` });
    return null;
  }
  const g = findGpo(d.ad, m[2]);
  if (!g) {
    c.error('The system cannot find the file specified.', { category: 'ObjectNotFound', target: store, exception: 'CimException', id: `Windows System Error 2,${c.name}` });
    return null;
  }
  return { ad: d.ad, gpo: g };
}

