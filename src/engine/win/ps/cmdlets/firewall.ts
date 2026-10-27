// NetSecurity: Windows Defender Firewall profiles and rules. Every change is
// recompiled into the host's packet filter, so it takes effect at once.

import { gpoForStore, touchGpo } from './gpo';
import type { Host, World } from '../../../types';
import { applyFirewall, effectiveProfile, FW_PROFILES, winEvent, type FwProfile, type FwProfileSettings, type Gpo, type WinFwRule } from '../../model';
import { registerView } from '../format';
import { cmdlet, type Call, type ParamDef } from '../runtime';
import { flatten, getProp, hasWildcard, isObj, obj, toStr, wildcard, type PSObject, type PSValue } from '../values';
import { isAdmin } from './files';

const MOD = 'NetSecurity';
const FW_LOG = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';
const FW_PROVIDER = 'Microsoft-Windows-Windows Firewall With Advanced Security';

registerView('MSFT_NetFirewallRule', {
  kind: 'list', props: ['Name', 'DisplayName', 'Description', 'DisplayGroup', 'Group', 'Enabled', 'Profile', 'Platform', 'Direction', 'Action', 'EdgeTraversalPolicy', 'LooseSourceMapping', 'LocalOnlyMapping', 'Owner', 'PrimaryStatus', 'Status', 'EnforcementStatus', 'PolicyStoreSource', 'PolicyStoreSourceType'],
});
registerView('MSFT_NetFirewallProfile', {
  kind: 'list', props: ['Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'AllowInboundRules', 'AllowLocalFirewallRules', 'AllowLocalIPsecRules', 'AllowUserApps', 'AllowUserPorts', 'AllowUnicastResponseToMulticast', 'NotifyOnListen', 'EnableStealthModeForIPsec', 'LogFileName', 'LogMaxSizeKilobytes', 'LogAllowed', 'LogBlocked', 'LogIgnored', 'DisabledInterfaceAliases'],
});
registerView('MSFT_NetProtocolPortFilter', { kind: 'list', props: ['Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTarget'] });
registerView('MSFT_NetAddressFilter', { kind: 'list', props: ['LocalAddress', 'RemoteAddress'] });
registerView('MSFT_NetApplicationFilter', { kind: 'list', props: ['Program', 'Package'] });

export function profileText(r: WinFwRule): string {
  return r.profiles === 'Any' ? 'Any' : r.profiles.join(', ');
}

function ruleObj(r: WinFwRule, store = ''): PSObject {
  return obj('MSFT_NetFirewallRule', {
    Name: r.name, DisplayName: r.displayName, Description: r.description ?? '', DisplayGroup: r.group, Group: r.group, Enabled: r.enabled ? 'True' : 'False', Profile: profileText(r), Platform: '{}',
    Direction: r.direction, Action: r.action, EdgeTraversalPolicy: 'Block', LooseSourceMapping: false, LocalOnlyMapping: false, Owner: '', PrimaryStatus: 'OK', Status: 'The rule was parsed successfully from the store. (65536)',
    EnforcementStatus: 'NotApplicable', PolicyStoreSource: r.gpo ?? 'PersistentStore', PolicyStoreSourceType: r.gpo ? 'GroupPolicy' : 'Local', __rule: r.name, __store: store, __str: r.name,
  });
}

const listValue = (v: 'Any' | string[] | undefined): PSValue => (!v || v === 'Any' ? 'Any' : v.length === 1 ? v[0] : v);

function portFilterObj(r: WinFwRule): PSObject {
  return obj('MSFT_NetProtocolPortFilter', { Protocol: r.protocol, LocalPort: listValue(r.localPort), RemotePort: listValue(r.remotePort), IcmpType: r.icmpType ?? 'Any', DynamicTarget: 'Any', __rule: r.name });
}

function addressFilterObj(r: WinFwRule): PSObject {
  return obj('MSFT_NetAddressFilter', { LocalAddress: listValue(r.localAddress), RemoteAddress: listValue(r.remoteAddress), __rule: r.name });
}

function appFilterObj(r: WinFwRule): PSObject {
  return obj('MSFT_NetApplicationFilter', { Program: r.program ?? 'Any', Package: '', __rule: r.name });
}

function notFound(c: Call, prop: string, value: string): void {
  c.error(`No MSFT_NetFirewallRule objects found with property '${prop}' equal to '${value}'.  Verify the value of the property and retry.`, { category: 'ObjectNotFound', target: value, exception: 'CimJobException', id: `CmdletizationQuery_NotFound_${prop},${c.name}` });
}

function denied(c: Call, cls = 'MSFT_NetFirewallRule'): boolean {
  if (isAdmin(c)) return false;
  c.error('Access is denied.', { category: 'PermissionDenied', target: `${cls}:root/standardcimv2/${cls}`, exception: 'CimException', id: `Windows System Error 5,${c.name}` });
  return true;
}

const SELECT_PARAMS: ParamDef[] = [
  { name: 'Name', aliases: ['ID'], type: 'strings', position: 0 }, { name: 'DisplayName', type: 'strings' }, { name: 'DisplayGroup', type: 'strings' }, { name: 'Group', type: 'strings' },
  { name: 'InputObject', type: 'any' }, { name: 'All', type: 'switch' }, { name: 'PolicyStore', type: 'string' },
];

interface Store { rules: WinFwRule[]; gpo?: Gpo; name?: string; readOnly?: boolean }

/**
 * The rules a -PolicyStore names: PersistentStore (local, the default for
 * changes), ActiveStore (local plus Group Policy, the default for Get; changes
 * go to the local rules), RSOP (from Group Policy only, read-only), or
 * "DOMAIN\\GPO name" (the rules in that GPO).
 */
function storeRules(c: Call, forChange: boolean, name = c.str('PolicyStore')): Store | null {
  const w = c.ctx.host.win!;
  if (name && name.includes('\\')) {
    const r = gpoForStore(c, name);
    return r ? { rules: r.gpo.firewallRules, gpo: r.gpo, name } : null;
  }
  const s = (name ?? (forChange ? 'PersistentStore' : 'ActiveStore')).toLowerCase();
  if (s === 'rsop') return { rules: w.gp?.rules ?? [], readOnly: true };
  if (s === 'activestore' && !forChange) return { rules: [...w.firewall.rules, ...(w.gp?.rules ?? [])] };
  return { rules: w.firewall.rules };
}

/** Changes cannot be written to RSOP: Group Policy rules change in their GPO. */
function readOnly(c: Call, store: Store): boolean {
  if (!store.readOnly) return false;
  c.error('The request is not supported.', { category: 'NotImplemented', target: 'MSFT_NetFirewallRule:root/standardcimv2/MSFT_NetFirewallRule', exception: 'CimException', id: `Windows System Error 50,${c.name}` });
  return true;
}

/**
 * Rules selected by -Name / -DisplayName / -DisplayGroup / -Group / pipeline
 * input (rules or their filters), from -PolicyStore or, for piped rules, the
 * GPO store they were read from.
 */
function selectRules(c: Call, forChange = true): { rules: WinFwRule[]; store: Store | null } {
  const piped = [...flatten(c.p.InputObject ?? null), ...c.input].filter(isObj);
  const fromPipe = piped.map((o) => toStr(o.__store ?? '')).find(Boolean);
  const store = storeRules(c, forChange, c.str('PolicyStore') ?? (fromPipe || undefined));
  if (!store || (forChange && readOnly(c, store))) return { rules: [], store: null };
  const rules = store.rules;
  const byProp = (prop: 'Name' | 'DisplayName' | 'DisplayGroup' | 'Group', get: (r: WinFwRule) => string): WinFwRule[] => {
    const out: WinFwRule[] = [];
    for (const v of c.strs(prop)!) {
      const hit = rules.filter((r) => wildcard(v).test(get(r)));
      if (!hit.length) notFound(c, prop, v);
      for (const h of hit) if (!out.includes(h)) out.push(h);
    }
    return out;
  };
  const pick = (): WinFwRule[] => {
    if (c.has('Name')) return byProp('Name', (r) => r.name);
    if (c.has('DisplayName')) return byProp('DisplayName', (r) => r.displayName);
    if (c.has('DisplayGroup')) return byProp('DisplayGroup', (r) => r.group);
    if (c.has('Group')) return byProp('Group', (r) => r.group);
    if (piped.length) {
      const names = piped.map((o) => toStr(o.__rule ?? getProp(o, 'Name')));
      return rules.filter((r) => names.includes(r.name));
    }
    return rules;
  };
  return { rules: pick(), store };
}

function changed(world: World, host: Host, id: number, verb: string, r: WinFwRule): void {
  winEvent(world, host, FW_LOG, id, FW_PROVIDER, `A rule has been ${verb} in the Windows Defender Firewall exception list.\n\nRule Information:\n\tRule ID:\t${r.name}\n\tRule Name:\t${r.displayName}\n\tDirection:\t${r.direction}\n\tProfiles:\t${profileText(r)}\n\tAction:\t${r.action}\n\tProtocol:\t${r.protocol}\n\tLocal Port:\t${r.localPort === 'Any' ? '*' : r.localPort.join(',')}`);
}

function fwCmdlet(name: string, synopsis: string, params: ParamDef[], run: (c: Call) => PSValue[] | void): void {
  cmdlet({ name, module: MOD, synopsis, params, run, cls: name });
}

fwCmdlet('Get-NetFirewallRule', 'Retrieves firewall rules from the target computer.', [...SELECT_PARAMS, { name: 'Enabled', type: 'string' }, { name: 'Direction', type: 'string' }, { name: 'Action', type: 'string' }], (c) => {
  const sel = selectRules(c, false);
  let out = sel.rules;
  if (c.has('Enabled')) out = out.filter((r) => String(r.enabled).toLowerCase() === c.str('Enabled')!.toLowerCase());
  if (c.has('Direction')) out = out.filter((r) => r.direction.toLowerCase() === c.str('Direction')!.toLowerCase());
  if (c.has('Action')) out = out.filter((r) => r.action.toLowerCase() === c.str('Action')!.toLowerCase());
  return out.map((r) => ruleObj(r, sel.store?.name));
});

for (const [verb, enable] of [['Enable', true], ['Disable', false]] as const) {
  fwCmdlet(`${verb}-NetFirewallRule`, `${verb}s a previously ${enable ? 'disabled' : 'enabled'} firewall rule.`, [...SELECT_PARAMS, { name: 'PassThru', type: 'switch' }], (c) => {
    const { rules, store } = selectRules(c);
    if (!rules.length || denied(c)) return;
    const out: PSValue[] = [];
    let did = false;
    for (const r of rules) {
      if (c.whatIf(`${verb}`, `${r.name}: ${r.displayName}`)) continue;
      if (r.enabled !== enable) {
        r.enabled = enable;
        did = true;
        if (!store?.gpo) changed(c.ctx.world, c.ctx.host, 2005, 'modified', r);
      }
      if (c.has('PassThru')) out.push(ruleObj(r, store?.name));
    }
    if (did && store?.gpo) touchGpo(c, store.gpo);
    applyFirewall(c.ctx.host);
    return out;
  });
}

function parseProfiles(c: Call, v: PSValue): WinFwRule['profiles'] | null {
  const parts = flatten(v).flatMap((x) => toStr(x).split(',')).map((x) => x.trim()).filter(Boolean);
  if (parts.some((p) => p.toLowerCase() === 'any')) return 'Any';
  const out: FwProfile[] = [];
  for (const p of parts) {
    const hit = FW_PROFILES.find((x) => x.toLowerCase() === p.toLowerCase());
    if (!hit) {
      c.error(`Cannot bind parameter 'Profile'. Cannot convert value "${p}" to type "Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile". Error: "Unable to match the identifier name ${p} to a valid enumerator name. Specify one of the following enumerator names and try again:\nAny, Domain, Private, Public, NotApplicable"`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: `CannotConvertArgumentNoMessage,${c.name}` });
      return null;
    }
    out.push(hit);
  }
  return out.length === 3 ? 'Any' : out;
}

function enumValue(c: Call, param: string, allowed: string[], type: string): string | null | undefined {
  if (!c.has(param)) return undefined;
  const v = c.str(param)!;
  const hit = allowed.find((a) => a.toLowerCase() === v.toLowerCase());
  if (hit) return hit;
  c.error(`Cannot bind parameter '${param}'. Cannot convert value "${v}" to type "Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.${type}". Error: "Unable to match the identifier name ${v} to a valid enumerator name. Specify one of the following enumerator names and try again:\n${allowed.join(', ')}"`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: `CannotConvertArgumentNoMessage,${c.name}` });
  return null;
}

function portList(v: PSValue): 'Any' | string[] {
  const parts = flatten(v).flatMap((x) => toStr(x).split(',')).map((x) => x.trim()).filter(Boolean);
  return parts.some((p) => p.toLowerCase() === 'any') ? 'Any' : parts;
}

function validPorts(ports: 'Any' | string[]): boolean {
  return ports === 'Any' || ports.every((p) => /^\d+(-\d+)?$/.test(p) && p.split('-').every((n) => Number(n) >= 0 && Number(n) <= 65535));
}

const RULE_PARAMS: ParamDef[] = [
  { name: 'Direction', aliases: ['dir'], type: 'string' }, { name: 'Action', type: 'string' }, { name: 'Protocol', type: 'string' }, { name: 'LocalPort', type: 'strings' },
  { name: 'RemoteAddress', type: 'strings' }, { name: 'Profile', type: 'any' }, { name: 'Enabled', type: 'string' }, { name: 'Program', type: 'string' }, { name: 'IcmpType', type: 'strings' },
  { name: 'Description', type: 'string' }, { name: 'RemotePort', type: 'strings' }, { name: 'LocalAddress', type: 'strings' },
];

/** Apply rule settings from the parameters; returns false (after reporting) when a value is invalid. */
function applySettings(c: Call, r: WinFwRule): boolean {
  const dir = enumValue(c, 'Direction', ['Inbound', 'Outbound'], 'Direction');
  const act = enumValue(c, 'Action', ['NotConfigured', 'Allow', 'Block'], 'Action');
  const en = enumValue(c, 'Enabled', ['True', 'False'], 'Enabled');
  if (dir === null || act === null || en === null) return false;
  let proto = r.protocol;
  if (c.has('Protocol')) {
    const p = c.str('Protocol')!.toUpperCase();
    const map: Record<string, WinFwRule['protocol']> = { TCP: 'TCP', 6: 'TCP', UDP: 'UDP', 17: 'UDP', ICMPV4: 'ICMPv4', 1: 'ICMPv4', ICMPV6: 'ICMPv6', 58: 'ICMPv6', ANY: 'Any' };
    if (!map[p]) {
      c.error('The protocol is invalid. Specify a protocol number from 0 to 255, or one of the following keywords: TCP, UDP, ICMPv4, ICMPv6, Any.', { category: 'InvalidArgument', target: 'MSFT_NetFirewallRule', exception: 'CimException', id: `HRESULT 0x80070057,${c.name}` });
      return false;
    }
    proto = map[p];
  }
  const ports = c.has('LocalPort') ? portList(c.p.LocalPort) : r.localPort;
  if (!validPorts(ports)) {
    c.error('The port is invalid. When Protocol is TCP or UDP, individual ports or ranges are allowed. Also, the following keywords are allowed: RPC, RPCEPMap, Any, IPHTTPSIn, PlayToDiscovery.', { category: 'InvalidArgument', target: 'MSFT_NetFirewallRule', exception: 'CimException', id: `HRESULT 0x80070057,${c.name}` });
    return false;
  }
  const rports = c.has('RemotePort') ? portList(c.p.RemotePort) : r.remotePort ?? 'Any';
  if (!validPorts(rports)) {
    c.error('The port is invalid. When Protocol is TCP or UDP, individual ports or ranges are allowed. Also, the following keywords are allowed: RPC, RPCEPMap, Any, IPHTTPSIn, PlayToDiscovery.', { category: 'InvalidArgument', target: 'MSFT_NetFirewallRule', exception: 'CimException', id: `HRESULT 0x80070057,${c.name}` });
    return false;
  }
  if ((ports !== 'Any' || rports !== 'Any') && proto !== 'TCP' && proto !== 'UDP') {
    c.error('The port is invalid. When Protocol is TCP or UDP, individual ports or ranges are allowed. Also, the following keywords are allowed: RPC, RPCEPMap, Any, IPHTTPSIn, PlayToDiscovery.', { category: 'InvalidArgument', target: 'MSFT_NetFirewallRule', exception: 'CimException', id: `HRESULT 0x80070057,${c.name}` });
    return false;
  }
  let profiles = r.profiles;
  if (c.has('Profile')) {
    const p = parseProfiles(c, c.p.Profile);
    if (!p) return false;
    profiles = p;
  }
  if (dir) r.direction = dir as WinFwRule['direction'];
  if (act) r.action = act === 'Block' ? 'Block' : 'Allow';
  if (en) r.enabled = en === 'True';
  r.protocol = proto;
  r.localPort = ports;
  r.profiles = profiles;
  r.remotePort = rports;
  if (c.has('RemoteAddress')) r.remoteAddress = portList(c.p.RemoteAddress);
  if (c.has('LocalAddress')) r.localAddress = portList(c.p.LocalAddress);
  if (c.has('Program')) r.program = /^any$/i.test(c.str('Program')!) ? undefined : c.str('Program');
  if (c.has('IcmpType')) r.icmpType = c.str('IcmpType');
  if (c.has('Description')) r.description = c.str('Description');
  return true;
}

function guid(world: World): string {
  const h = (n: number, len: number) => ((n * 2654435761) >>> 0).toString(16).padStart(8, '0').slice(0, len);
  const n = world.counter + world.clock;
  return `{${h(n, 8)}-${h(n + 1, 4)}-${h(n + 2, 4)}-${h(n + 3, 4)}-${h(n + 4, 8)}${h(n + 5, 4)}}`;
}

fwCmdlet('New-NetFirewallRule', 'Creates a new inbound or outbound firewall rule and adds the rule to the target computer.', [
  { name: 'DisplayName', type: 'string', position: 0 }, { name: 'Name', aliases: ['ID'], type: 'string' }, { name: 'Group', type: 'string' }, { name: 'PolicyStore', type: 'string' }, ...RULE_PARAMS,
], (c) => {
  if (!c.has('DisplayName')) {
    c.error('Cannot process command because of one or more missing mandatory parameters: DisplayName.', { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'MissingMandatoryParameter,New-NetFirewallRule' });
    return;
  }
  if (denied(c)) return;
  const w = c.ctx.host.win!;
  const store = storeRules(c, true);
  if (!store || readOnly(c, store)) return;
  const name = c.str('Name') ?? guid(c.ctx.world);
  if (store.rules.some((r) => r.name.toLowerCase() === name.toLowerCase())) {
    c.error('Cannot create a file when that file already exists.', { category: 'ResourceExists', target: 'MSFT_NetFirewallRule:root/standardcimv2/MSFT_NetFirewallRule', exception: 'CimException', id: 'Windows System Error 183,New-NetFirewallRule' });
    return;
  }
  const r: WinFwRule = { name, displayName: c.str('DisplayName')!, group: c.str('Group') ?? '', direction: 'Inbound', action: 'Allow', enabled: true, profiles: 'Any', protocol: 'Any', localPort: 'Any', remoteAddress: 'Any' };
  if (!applySettings(c, r)) return;
  if (c.whatIf('New-NetFirewallRule', r.displayName)) return;
  if (store.gpo) {
    // Stored in the GPO (SYSVOL); members receive it at their next policy processing.
    store.gpo.firewallRules.push(r);
    touchGpo(c, store.gpo);
    return [ruleObj({ ...r, gpo: c.str('PolicyStore') })];
  }
  w.firewall.rules.push(r);
  winEvent(c.ctx.world, c.ctx.host, FW_LOG, 2004, FW_PROVIDER, `A rule has been added to the Windows Defender Firewall exception list.\n\nAdded Rule:\n\tRule ID:\t${r.name}\n\tRule Name:\t${r.displayName}\n\tDirection:\t${r.direction}\n\tProfiles:\t${profileText(r)}\n\tAction:\t${r.action}\n\tProtocol:\t${r.protocol}\n\tLocal Port:\t${r.localPort === 'Any' ? '*' : r.localPort.join(',')}`);
  applyFirewall(c.ctx.host);
  return [ruleObj(r)];
});

fwCmdlet('Set-NetFirewallRule', 'Modifies existing firewall rules.', [...SELECT_PARAMS, ...RULE_PARAMS, { name: 'NewDisplayName', type: 'string' }, { name: 'PassThru', type: 'switch' }], (c) => {
  const { rules, store } = selectRules(c);
  if (!rules.length || denied(c)) return;
  const out: PSValue[] = [];
  let did = false;
  for (const r of rules) {
    if (c.whatIf('Set', `${r.name}: ${r.displayName}`)) continue;
    const copy = { ...r };
    if (!applySettings(c, copy)) break;
    if (c.has('NewDisplayName')) copy.displayName = c.str('NewDisplayName')!;
    Object.assign(r, copy);
    did = true;
    if (!store?.gpo) changed(c.ctx.world, c.ctx.host, 2005, 'modified', r);
    if (c.has('PassThru')) out.push(ruleObj(r, store?.name));
  }
  if (did && store?.gpo) touchGpo(c, store.gpo);
  applyFirewall(c.ctx.host);
  return out;
});

fwCmdlet('Remove-NetFirewallRule', 'Deletes one or more firewall rules that match the specified criteria.', SELECT_PARAMS, (c) => {
  if (!c.has('Name') && !c.has('DisplayName') && !c.has('DisplayGroup') && !c.has('Group') && !c.has('InputObject') && !c.input.length && !c.has('All')) {
    c.error('Cannot process command because of one or more missing mandatory parameters: Name.', { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'MissingMandatoryParameter,Remove-NetFirewallRule' });
    return;
  }
  const { rules, store } = selectRules(c);
  if (!rules.length || denied(c)) return;
  const w = c.ctx.host.win!;
  for (const r of rules) {
    if (c.whatIf('Delete', `${r.name}: ${r.displayName}`)) continue;
    if (store?.gpo) {
      store.gpo.firewallRules = store.gpo.firewallRules.filter((x) => x !== r);
      touchGpo(c, store.gpo);
      continue;
    }
    w.firewall.rules = w.firewall.rules.filter((x) => x !== r);
    winEvent(c.ctx.world, c.ctx.host, FW_LOG, 2006, FW_PROVIDER, `A rule has been deleted in the Windows Defender Firewall exception list.\n\nDeleted Rule:\n\tRule ID:\t${r.name}\n\tRule Name:\t${r.displayName}`);
  }
  applyFirewall(c.ctx.host);
});

/** Rules whose filters a Get-NetFirewall*Filter call returns: the piped rules, or all rules in the store. */
function filterRules(c: Call): WinFwRule[] {
  const piped = [...flatten(c.p.AssociatedNetFirewallRule ?? null), ...c.input].filter(isObj);
  const store = storeRules(c, false, c.str('PolicyStore') ?? (piped.map((o) => toStr(o.__store ?? '')).find(Boolean) || undefined));
  if (!store) return [];
  const names = piped.map((o) => toStr(o.__rule ?? getProp(o, 'Name')));
  return store.rules.filter((r) => !piped.length || names.includes(r.name));
}

const FILTER_PARAMS: ParamDef[] = [{ name: 'All', type: 'switch' }, { name: 'AssociatedNetFirewallRule', type: 'any' }, { name: 'PolicyStore', type: 'string' }];

fwCmdlet('Get-NetFirewallPortFilter', 'Retrieves port filter objects associated with the input firewall rules.', [{ name: 'Protocol', type: 'string' }, ...FILTER_PARAMS], (c) => {
  return filterRules(c).filter((r) => !c.has('Protocol') || r.protocol.toLowerCase() === c.str('Protocol')!.toLowerCase()).map(portFilterObj);
});

fwCmdlet('Get-NetFirewallAddressFilter', 'Retrieves address filter objects associated with the input firewall rules.', FILTER_PARAMS, (c) => filterRules(c).map(addressFilterObj));

fwCmdlet('Get-NetFirewallApplicationFilter', 'Retrieves application filter objects associated with the input firewall rules.', [{ name: 'Program', type: 'string' }, ...FILTER_PARAMS], (c) => {
  const want = c.str('Program');
  return filterRules(c).filter((r) => !want || wildcard(want).test(r.program ?? 'Any')).map(appFilterObj);
});

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

type ProfileView = Partial<FwProfileSettings>;

const gpoBool = (v: boolean | undefined) => (v === undefined ? 'NotConfigured' : v ? 'True' : 'False');

function profileObj(name: FwProfile, p: ProfileView, gpoStore: boolean): PSObject {
  return obj('MSFT_NetFirewallProfile', {
    Name: name, Enabled: gpoBool(p.enabled), DefaultInboundAction: p.defaultInbound ?? 'NotConfigured', DefaultOutboundAction: p.defaultOutbound ?? 'NotConfigured', AllowInboundRules: 'NotConfigured',
    // Local rule merging is a Group Policy setting: the local store always reports NotConfigured.
    AllowLocalFirewallRules: gpoStore ? gpoBool(p.allowLocalRules) : 'NotConfigured',
    AllowLocalIPsecRules: 'NotConfigured', AllowUserApps: 'NotConfigured', AllowUserPorts: 'NotConfigured', AllowUnicastResponseToMulticast: 'NotConfigured', NotifyOnListen: 'False', EnableStealthModeForIPsec: 'NotConfigured',
    LogFileName: '%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log', LogMaxSizeKilobytes: p.logMaxKb ?? (gpoStore ? 'NotConfigured' : 4096), LogAllowed: gpoBool(p.logAllowed ?? (gpoStore ? undefined : false)), LogBlocked: gpoBool(p.logBlocked), LogIgnored: 'NotConfigured', DisabledInterfaceAliases: '{NotConfigured}', __str: name,
  });
}

/**
 * Profile settings in a -PolicyStore: PersistentStore (local, the default),
 * ActiveStore (in force: local overridden by Group Policy), RSOP (what policy
 * set, read-only) or "DOMAIN\\GPO name".
 */
function profileStore(c: Call): { view: (p: FwProfile) => ProfileView; gpo?: Gpo; gpoStore: boolean; readOnly?: boolean; local?: boolean } | null {
  const host = c.ctx.host;
  const name = c.str('PolicyStore');
  if (name && name.includes('\\')) {
    const r = gpoForStore(c, name);
    if (!r) return null;
    return { view: (p) => r.gpo.firewallProfiles?.[p] ?? {}, gpo: r.gpo, gpoStore: true };
  }
  const s = (name ?? 'PersistentStore').toLowerCase();
  if (s === 'rsop') return { view: (p) => host.win!.gp?.profiles?.[p] ?? {}, gpoStore: true, readOnly: true };
  if (s === 'activestore') return { view: (p) => { const e = effectiveProfile(host, p); return { ...e, logAllowed: e.logAllowed ?? false, logMaxKb: e.logMaxKb ?? 4096 }; }, gpoStore: true, local: true };
  return { view: (p) => host.win!.firewall.profiles[p], gpoStore: false, local: true };
}

function pickProfiles(c: Call): FwProfile[] | null {
  const names = c.strs('Name') ?? c.strs('Profile');
  if (!names) {
    const piped = c.input.filter(isObj).map((o) => toStr(getProp(o, 'Name')));
    return piped.length ? FW_PROFILES.filter((p) => piped.includes(p)) : FW_PROFILES;
  }
  const out: FwProfile[] = [];
  for (const n of names.flatMap((x) => x.split(','))) {
    const hit = FW_PROFILES.filter((p) => wildcard(n.trim()).test(p));
    if (!hit.length && !hasWildcard(n)) {
      c.error(`No MSFT_NetFirewallProfile objects found with property 'Name' equal to '${n}'.  Verify the value of the property and retry.`, { category: 'ObjectNotFound', target: n, exception: 'CimJobException', id: `CmdletizationQuery_NotFound_Name,${c.name}` });
      return null;
    }
    out.push(...hit.filter((h) => !out.includes(h)));
  }
  return out;
}

fwCmdlet('Get-NetFirewallProfile', 'Displays settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.', [{ name: 'Name', aliases: ['Profile'], type: 'strings', position: 0 }, { name: 'All', type: 'switch' }, { name: 'PolicyStore', type: 'string' }], (c) => {
  const store = profileStore(c);
  if (!store) return;
  return (pickProfiles(c) ?? []).map((p) => profileObj(p, store.view(p), store.gpoStore));
});

fwCmdlet('Set-NetFirewallProfile', 'Configures settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.', [
  { name: 'Name', aliases: ['Profile'], type: 'strings', position: 0 }, { name: 'All', type: 'switch' }, { name: 'Enabled', type: 'string' }, { name: 'DefaultInboundAction', type: 'string' }, { name: 'DefaultOutboundAction', type: 'string' },
  { name: 'LogBlocked', type: 'string' }, { name: 'LogAllowed', type: 'string' }, { name: 'LogMaxSizeKilobytes', type: 'int' }, { name: 'AllowLocalFirewallRules', type: 'string' }, { name: 'PolicyStore', type: 'string' }, { name: 'PassThru', type: 'switch' },
], (c) => {
  const list = pickProfiles(c);
  if (!list || denied(c, 'MSFT_NetFirewallProfile')) return;
  const store = profileStore(c);
  if (!store) return;
  if (store.readOnly) {
    c.error('The request is not supported.', { category: 'NotImplemented', target: 'MSFT_NetFirewallProfile:root/standardcimv2/MSFT_NetFirewallProfile', exception: 'CimException', id: `Windows System Error 50,${c.name}` });
    return;
  }
  const bool = ['True', 'False', 'NotConfigured'];
  const en = enumValue(c, 'Enabled', bool, 'GpoBoolean');
  const inA = enumValue(c, 'DefaultInboundAction', ['NotConfigured', 'Allow', 'Block'], 'Action');
  const outA = enumValue(c, 'DefaultOutboundAction', ['NotConfigured', 'Allow', 'Block'], 'Action');
  const log = enumValue(c, 'LogBlocked', bool, 'GpoBoolean');
  const logA = enumValue(c, 'LogAllowed', bool, 'GpoBoolean');
  const merge = enumValue(c, 'AllowLocalFirewallRules', bool, 'GpoBoolean');
  if (en === null || inA === null || outA === null || log === null || logA === null || merge === null) return;
  const maxKb = c.has('LogMaxSizeKilobytes') ? Number(c.p.LogMaxSizeKilobytes) : undefined;
  if (maxKb !== undefined && !(Number.isInteger(maxKb) && maxKb >= 1 && maxKb <= 32767)) {
    c.error(`Cannot validate argument on parameter 'LogMaxSizeKilobytes'. The ${maxKb} argument is greater than the maximum allowed range of 32767. Supply an argument that is less than or equal to 32767 and then try the command again.`, { category: 'InvalidData', target: '', exception: 'ParameterBindingValidationException', id: `ParameterArgumentValidationError,${c.name}` });
    return;
  }
  const host = c.ctx.host;
  const out: PSValue[] = [];
  for (const name of list) {
    if (c.whatIf('Set', name)) continue;
    if (store.gpo) {
      // In a GPO, NotConfigured removes the setting: the member keeps its own value.
      const g = ((store.gpo.firewallProfiles ??= {})[name] ??= {});
      const set = <K extends keyof FwProfileSettings>(k: K, v: string | undefined, conv: (x: string) => FwProfileSettings[K]) => {
        if (v === undefined) return;
        if (v === 'NotConfigured') delete g[k];
        else g[k] = conv(v);
      };
      set('enabled', en, (x) => x === 'True');
      set('defaultInbound', inA, (x) => (x === 'Allow' ? 'Allow' : 'Block'));
      set('defaultOutbound', outA, (x) => (x === 'Block' ? 'Block' : 'Allow'));
      set('logBlocked', log, (x) => x === 'True');
      set('logAllowed', logA, (x) => x === 'True');
      set('allowLocalRules', merge, (x) => x === 'True');
      if (maxKb !== undefined) g.logMaxKb = maxKb;
      touchGpo(c, store.gpo);
    } else {
      const p = host.win!.firewall.profiles[name];
      if (en) p.enabled = en !== 'False';
      if (inA) p.defaultInbound = inA === 'Allow' ? 'Allow' : 'Block';
      if (outA) p.defaultOutbound = outA === 'Block' ? 'Block' : 'Allow';
      if (log) p.logBlocked = log === 'True';
      if (logA) p.logAllowed = logA === 'True';
      if (maxKb !== undefined) p.logMaxKb = maxKb;
      // AllowLocalFirewallRules is only read from Group Policy; the local store accepts it and ignores it.
      winEvent(c.ctx.world, host, FW_LOG, 2003, FW_PROVIDER, `A Windows Defender Firewall setting in the ${name} profile has changed.\n\nNew Setting:\n\tType:\t${en ? 'Enable Windows Defender Firewall' : inA || outA ? 'Default action' : 'Logging'}\n\tValue:\t${en ? (p.enabled ? 'Yes' : 'No') : inA ?? outA ?? log ?? logA ?? ''}`);
    }
    if (c.has('PassThru')) out.push(profileObj(name, store.view(name), store.gpoStore));
  }
  applyFirewall(host);
  return out;
});
