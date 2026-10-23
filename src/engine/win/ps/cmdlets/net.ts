// NetTCPIP, DnsClient and NetConnection cmdlets, Test-Connection and
// Invoke-WebRequest: the network side of a Windows server.

import { isIp } from '../../../net/ip';
import { HTTP_COMMANDS } from '../../../shell/cmdHttp';
import type { CmdCtx } from '../../../shell/types';
import { dnsQuery, type QType, QTYPES } from '../../../sim/dns';
import { lookupRoute, sourceAddress } from '../../../sim/network';
import { tcpConnect } from '../../../sim/tcp';
import type { Host } from '../../../types';
import { applyAdapters, applyFirewall, winEvent, winListeners, winResolver, type FwProfile, type WinAdapter } from '../../model';
import { registerView } from '../format';
import { echo, resolve4, winMac } from '../netops';
import { cmdlet, type Call, type PsCtx } from '../runtime';
import { writeFile } from '../../../fs';
import { getProp, hasWildcard, isObj, obj, toStr, wildcard, type PSObject, type PSValue } from '../values';
import { absPath, isAdmin } from './files';

const TCPIP = 'NetTCPIP';
const DNS = 'DnsClient';

registerView('MSFT_NetAdapter', {
  kind: 'table', columns: [
    { label: 'Name', value: 'Name', width: 25 }, { label: 'InterfaceDescription', value: 'InterfaceDescription', width: 39 }, { label: 'ifIndex', value: 'ifIndex', width: 7, align: 'right' },
    { label: 'Status', value: 'Status', width: 12 }, { label: 'MacAddress', value: 'MacAddress', width: 22 }, { label: 'LinkSpeed', value: 'LinkSpeed', width: 12, align: 'right' },
  ],
});
registerView('MSFT_NetIPAddress', { kind: 'list', props: ['IPAddress', 'InterfaceIndex', 'InterfaceAlias', 'AddressFamily', 'Type', 'PrefixLength', 'PrefixOrigin', 'SuffixOrigin', 'AddressState', 'ValidLifetime', 'PreferredLifetime', 'SkipAsSource', 'PolicyStore'] });
registerView('MSFT_NetRoute', {
  kind: 'table', columns: [
    { label: 'ifIndex', value: 'ifIndex', width: 7, align: 'right' }, { label: 'DestinationPrefix', value: 'DestinationPrefix', width: 32 }, { label: 'NextHop', value: 'NextHop', width: 24 },
    { label: 'RouteMetric', value: 'RouteMetric', width: 11, align: 'right' }, { label: 'ifMetric', value: 'ifMetric', width: 8, align: 'right' }, { label: 'PolicyStore', value: 'PolicyStore' },
  ],
});
registerView('MSFT_DNSClientServerAddress', {
  kind: 'table', columns: [
    { label: 'InterfaceAlias', value: 'InterfaceAlias', width: 30 }, { label: 'Interface', value: 'InterfaceIndex', width: 9, align: 'right' }, { label: 'Address', value: 'AddressFamilyName', width: 7 },
    { label: 'ServerAddresses', value: 'ServerAddresses' },
  ],
});
registerView('NetIPConfiguration', { kind: 'list', props: ['InterfaceAlias', 'InterfaceIndex', 'InterfaceDescription', 'NetProfile.Name', 'IPv4Address', 'IPv4DefaultGateway', 'DNSServer'] });
registerView('MSFT_NetConnectionProfile', { kind: 'list', props: ['Name', 'InterfaceAlias', 'InterfaceIndex', 'NetworkCategory', 'IPv4Connectivity', 'IPv6Connectivity'] });
registerView('MSFT_NetTCPConnection', {
  kind: 'table', columns: [
    { label: 'LocalAddress', value: 'LocalAddress' }, { label: 'LocalPort', value: 'LocalPort', width: 9, align: 'right' }, { label: 'RemoteAddress', value: 'RemoteAddress' },
    { label: 'RemotePort', value: 'RemotePort', width: 10, align: 'right' }, { label: 'State', value: 'State', width: 11 }, { label: 'AppliedSetting', value: 'AppliedSetting', width: 14 }, { label: 'OwningProcess', value: 'OwningProcess', align: 'right' },
  ],
});
registerView('MSFT_NetNeighbor', {
  kind: 'table', columns: [
    { label: 'ifIndex', value: 'ifIndex', width: 7, align: 'right' }, { label: 'IPAddress', value: 'IPAddress', width: 39 }, { label: 'LinkLayerAddress', value: 'LinkLayerAddress', width: 19 },
    { label: 'State', value: 'State', width: 11 }, { label: 'PolicyStore', value: 'PolicyStore' },
  ],
});
registerView('Microsoft.DnsClient.Commands.DnsRecord', {
  kind: 'table', columns: [
    { label: 'Name', value: 'Name', width: 46 }, { label: 'Type', value: 'Type', width: 6 }, { label: 'TTL', value: 'TTL', width: 5, align: 'left' }, { label: 'Section', value: 'Section', width: 10 }, { label: 'IPAddress', value: 'Data' },
  ],
});
registerView('System.Management.ManagementObject#root\\cimv2\\Win32_PingStatus', {
  kind: 'table', columns: [
    { label: 'Source', value: 'PSComputerName', width: 13 }, { label: 'Destination', value: 'Address', width: 15 }, { label: 'IPV4Address', value: 'IPV4Address', width: 16 },
    { label: 'IPV6Address', value: 'IPV6Address', width: 40 }, { label: 'Bytes', value: 'BufferSize', width: 8, align: 'left' }, { label: 'Time(ms)', value: 'ResponseTime', align: 'left' },
  ],
});

function netCmdlet(name: string, module: string, synopsis: string, params: Parameters<typeof cmdlet>[0]['params'], run: (c: Call) => PSValue[] | void): void {
  cmdlet({ name, module, synopsis, params, run, cls: name });
}

function adapters(c: Call): WinAdapter[] {
  return c.ctx.host.win!.adapters;
}

/** Adapters chosen by -InterfaceAlias / -InterfaceIndex (all when neither is given); reports unknown ones. */
function pickAdapters(c: Call, cls: string): WinAdapter[] {
  const all = adapters(c);
  if (c.has('InterfaceAlias')) {
    const out = all.filter((a) => c.strs('InterfaceAlias')!.some((n) => wildcard(n).test(a.alias)));
    if (!out.length) notFound(c, cls, 'InterfaceAlias', c.str('InterfaceAlias')!);
    return out;
  }
  if (c.has('InterfaceIndex')) {
    const out = all.filter((a) => c.strs('InterfaceIndex')!.includes(String(a.ifIndex)));
    if (!out.length) notFound(c, cls, 'InterfaceIndex', c.str('InterfaceIndex')!);
    return out;
  }
  return all;
}

function notFound(c: Call, cls: string, prop: string, value: string): void {
  c.error(`No ${cls} objects found with property '${prop}' equal to '${value}'.  Verify the value of the property and retry.`, { category: 'ObjectNotFound', target: value, exception: 'CimJobException', id: `CmdletizationQuery_NotFound_${prop},${c.name}` });
}

function accessDenied(c: Call, cls: string): boolean {
  if (isAdmin(c)) return false;
  c.error('Access is denied.', { category: 'PermissionDenied', target: `${cls}:root/StandardCimv2/${cls}`, exception: 'CimException', id: `Windows System Error 5,${c.name}` });
  return true;
}

const IF_PARAMS = [{ name: 'InterfaceAlias', aliases: ['ifAlias'], type: 'strings' as const }, { name: 'InterfaceIndex', aliases: ['ifIndex'], type: 'strings' as const }];

// ---------------------------------------------------------------------------
// Adapters, addresses, routes
// ---------------------------------------------------------------------------

function iface(host: Host, a: WinAdapter) {
  return host.ifaces.find((i) => i.name === a.alias);
}

netCmdlet('Get-NetAdapter', 'NetAdapter', 'Gets the basic network adapter properties.', [{ name: 'Name', aliases: ['ifAlias', 'InterfaceAlias'], type: 'strings', position: 0 }, { name: 'InterfaceIndex', aliases: ['ifIndex'], type: 'strings' }], (c) => {
  const host = c.ctx.host;
  let list = adapters(c);
  if (c.has('Name')) {
    list = list.filter((a) => c.strs('Name')!.some((n) => wildcard(n).test(a.alias)));
    if (!list.length && !c.strs('Name')!.some(hasWildcard)) notFound(c, 'MSFT_NetAdapter', 'Name', c.str('Name')!);
  }
  if (c.has('InterfaceIndex')) list = list.filter((a) => c.strs('InterfaceIndex')!.includes(String(a.ifIndex)));
  return list.map((a) => {
    const i = iface(host, a);
    const up = !!i?.up && !!i.segment;
    return obj('MSFT_NetAdapter', { Name: a.alias, InterfaceDescription: a.description, ifIndex: a.ifIndex, Status: i?.up ? (up ? 'Up' : 'Disconnected') : 'Disabled', MacAddress: winMac(i?.mac ?? ''), LinkSpeed: up ? '10 Gbps' : '0 bps', MediaConnectionState: up ? 'Connected' : 'Disconnected', MtuSize: 1500, __str: a.alias });
  });
});

function ipObjs(host: Host, a: WinAdapter): PSObject[] {
  const out: PSObject[] = [];
  const i = iface(host, a);
  const ll = i?.addrs6?.find((x) => x.scope === 'link');
  const base = { InterfaceIndex: a.ifIndex, InterfaceAlias: a.alias, Type: 'Unicast', AddressState: 'Preferred', ValidLifetime: 'Infinite ([TimeSpan]::MaxValue)', PreferredLifetime: 'Infinite ([TimeSpan]::MaxValue)', SkipAsSource: false, PolicyStore: 'ActiveStore' };
  if (ll) out.push(obj('MSFT_NetIPAddress', { IPAddress: `${ll.address}%${a.ifIndex}`, ...base, AddressFamily: 'IPv6', PrefixLength: 64, PrefixOrigin: 'WellKnown', SuffixOrigin: 'Link', __str: `MSFT_NetIPAddress (Name = "${ll.address}...")` }));
  if (a.address && a.prefix !== null) out.push(obj('MSFT_NetIPAddress', { IPAddress: a.address, ...base, AddressFamily: 'IPv4', PrefixLength: a.prefix, PrefixOrigin: a.dhcp ? 'Dhcp' : 'Manual', SuffixOrigin: a.dhcp ? 'Dhcp' : 'Manual', __str: `MSFT_NetIPAddress (Name = "${a.address}...")` }));
  return out;
}

function loopbackIps(): PSObject[] {
  const base = { InterfaceIndex: 1, InterfaceAlias: 'Loopback Pseudo-Interface 1', Type: 'Unicast', PrefixOrigin: 'WellKnown', SuffixOrigin: 'WellKnown', AddressState: 'Preferred', ValidLifetime: 'Infinite ([TimeSpan]::MaxValue)', PreferredLifetime: 'Infinite ([TimeSpan]::MaxValue)', SkipAsSource: false, PolicyStore: 'ActiveStore' };
  return [obj('MSFT_NetIPAddress', { IPAddress: '::1', ...base, AddressFamily: 'IPv6', PrefixLength: 128 }), obj('MSFT_NetIPAddress', { IPAddress: '127.0.0.1', ...base, AddressFamily: 'IPv4', PrefixLength: 8 })];
}

netCmdlet('Get-NetIPAddress', TCPIP, 'Gets the IP address configuration.', [{ name: 'IPAddress', type: 'strings', position: 0 }, ...IF_PARAMS, { name: 'AddressFamily', type: 'string' }], (c) => {
  const host = c.ctx.host;
  let out = pickAdapters(c, 'MSFT_NetIPAddress').flatMap((a) => ipObjs(host, a));
  if (!c.has('InterfaceAlias') && !c.has('InterfaceIndex')) out.push(...loopbackIps());
  if (c.has('AddressFamily')) out = out.filter((o) => toStr(o.AddressFamily).toLowerCase() === c.str('AddressFamily')!.toLowerCase());
  if (c.has('IPAddress')) {
    out = out.filter((o) => c.strs('IPAddress')!.some((n) => wildcard(n).test(toStr(o.IPAddress))));
    if (!out.length) notFound(c, 'MSFT_NetIPAddress', 'IPAddress', c.str('IPAddress')!);
  }
  return out;
});

function validAddr(s: string): boolean {
  return isIp(s) && !/^0\.|^255\./.test(s);
}

netCmdlet('New-NetIPAddress', TCPIP, 'Creates and configures an IP address.', [{ name: 'IPAddress', type: 'string', position: 0 }, ...IF_PARAMS, { name: 'PrefixLength', type: 'int' }, { name: 'DefaultGateway', type: 'string' }, { name: 'AddressFamily', type: 'string' }], (c) => {
  if (accessDenied(c, 'MSFT_NetIPAddress')) return;
  const ip = c.str('IPAddress') ?? '';
  if (!validAddr(ip)) { c.error(`Cannot process argument transformation on parameter 'IPAddress'. "${ip}" is not a valid IP address.`, { category: 'InvalidData', target: '', exception: 'ParameterBindingArgumentTransformationException', id: 'ParameterArgumentTransformationError,New-NetIPAddress' }); return; }
  if (!c.has('InterfaceAlias') && !c.has('InterfaceIndex')) { c.error('The parameter InterfaceAlias or InterfaceIndex is required.', { category: 'InvalidArgument', target: '', exception: 'ArgumentException', id: 'InvalidArgument,New-NetIPAddress' }); return; }
  const [a] = pickAdapters(c, 'MSFT_NetIPAdapter');
  if (!a) return;
  if (a.address) { c.error('Instance MSFT_NetIPAddress already exists', { category: 'ResourceExists', target: 'MSFT_NetIPAddress:ROOT/StandardCimv2/MSFT_NetIPAddress', exception: 'CimException', id: 'Windows System Error 87,New-NetIPAddress' }); return; }
  if (c.has('DefaultGateway') && a.gateway) { c.error('Instance DefaultGateway already exists', { category: 'ResourceExists', target: 'MSFT_NetRoute:ROOT/StandardCimv2/MSFT_NetRoute', exception: 'CimException', id: 'Windows System Error 87,New-NetIPAddress' }); return; }
  if (c.whatIf('New-NetIPAddress', `${ip}/${c.p.PrefixLength ?? 8}`)) return;
  a.address = ip;
  a.prefix = Number(c.p.PrefixLength ?? 8);
  a.dhcp = false;
  if (c.has('DefaultGateway')) a.gateway = c.str('DefaultGateway')!;
  applyAdapters(c.ctx.world, c.ctx.host);
  applyFirewall(c.ctx.host);
  return ipObjs(c.ctx.host, a).filter((o) => o.AddressFamily === 'IPv4');
});

netCmdlet('Remove-NetIPAddress', TCPIP, 'Removes an IP address and its configuration.', [{ name: 'IPAddress', type: 'strings', position: 0 }, ...IF_PARAMS, { name: 'Confirm', type: 'any' }, { name: 'AddressFamily', type: 'string' }], (c) => {
  if (accessDenied(c, 'MSFT_NetIPAddress')) return;
  const ips = c.strs('IPAddress') ?? c.input.map((i) => toStr(getProp(i, 'IPAddress')));
  const targets = pickAdapters(c, 'MSFT_NetIPAddress').filter((a) => a.address && (ips.length === 0 || ips.includes(a.address)));
  if (!targets.length) { notFound(c, 'MSFT_NetIPAddress', 'IPAddress', ips[0] ?? ''); return; }
  for (const a of targets) {
    if (c.whatIf('Remove-NetIPAddress', `${a.address}/${a.prefix}`)) continue;
    if (c.p.Confirm !== false && toStr(c.p.Confirm).toLowerCase() !== 'false') {
      const ans = c.ctx.ask(`\nConfirm\nAre you sure you want to perform this action?\nPerforming operation "Remove" on Target "IPAddress: ${a.address} DefaultGateway: ${a.gateway ?? ''}".\n[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): `, false);
      if (/^[nl]/i.test(ans.trim())) continue;
    }
    a.address = null;
    a.prefix = null;
  }
  applyAdapters(c.ctx.world, c.ctx.host);
  applyFirewall(c.ctx.host);
});

netCmdlet('Get-NetRoute', TCPIP, 'Gets the IP route information from the IP routing table.', [{ name: 'DestinationPrefix', type: 'strings', position: 0 }, ...IF_PARAMS, { name: 'AddressFamily', type: 'string' }], (c) => {
  const host = c.ctx.host;
  const out: PSObject[] = [];
  for (const r of host.routes) {
    const a = host.win!.adapters.find((x) => x.alias === r.dev);
    if (!a) continue;
    const prefix = r.dest === 'default' ? '0.0.0.0/0' : r.dest;
    out.push(obj('MSFT_NetRoute', { ifIndex: a.ifIndex, InterfaceAlias: a.alias, DestinationPrefix: prefix, NextHop: r.via ?? '0.0.0.0', RouteMetric: r.dest === 'default' ? 0 : 256, ifMetric: 15, PolicyStore: 'ActiveStore' }));
  }
  out.push(obj('MSFT_NetRoute', { ifIndex: 1, InterfaceAlias: 'Loopback Pseudo-Interface 1', DestinationPrefix: '127.0.0.0/8', NextHop: '0.0.0.0', RouteMetric: 256, ifMetric: 75, PolicyStore: 'ActiveStore' }));
  let res = out;
  if (c.has('InterfaceAlias')) res = res.filter((o) => c.strs('InterfaceAlias')!.some((n) => wildcard(n).test(toStr(o.InterfaceAlias))));
  if (c.has('DestinationPrefix')) res = res.filter((o) => c.strs('DestinationPrefix')!.includes(toStr(o.DestinationPrefix)));
  if (!res.length && c.has('DestinationPrefix')) notFound(c, 'MSFT_NetRoute', 'DestinationPrefix', c.str('DestinationPrefix')!);
  return res.sort((x, y) => (y.DestinationPrefix as string).localeCompare(x.DestinationPrefix as string));
});

netCmdlet('Get-NetIPConfiguration', TCPIP, 'Gets IP network configuration.', [...IF_PARAMS, { name: 'Detailed', type: 'switch' }, { name: 'All', type: 'switch' }], (c) => {
  return pickAdapters(c, 'NetIPConfiguration').map((a) => obj('NetIPConfiguration', {
    InterfaceAlias: a.alias, InterfaceIndex: a.ifIndex, InterfaceDescription: a.description, 'NetProfile.Name': a.dnsSuffix || 'Network',
    IPv4Address: a.address ?? '', IPv4DefaultGateway: a.gateway ?? '', DNSServer: a.dns.length ? a.dns : '',
  }));
});

// ---------------------------------------------------------------------------
// DNS client
// ---------------------------------------------------------------------------

netCmdlet('Get-DnsClientServerAddress', DNS, 'Gets DNS server IP addresses from the TCP/IP properties on an interface.', [...IF_PARAMS, { name: 'AddressFamily', type: 'string' }], (c) => {
  const fam = c.str('AddressFamily')?.toLowerCase();
  const out: PSObject[] = [];
  for (const a of pickAdapters(c, 'MSFT_DNSClientServerAddress')) {
    if (fam !== 'ipv6') out.push(obj('MSFT_DNSClientServerAddress', { InterfaceAlias: a.alias, InterfaceIndex: a.ifIndex, AddressFamilyName: 'IPv4', AddressFamily: 2, ServerAddresses: a.dns }));
    if (fam !== 'ipv4') out.push(obj('MSFT_DNSClientServerAddress', { InterfaceAlias: a.alias, InterfaceIndex: a.ifIndex, AddressFamilyName: 'IPv6', AddressFamily: 23, ServerAddresses: [] }));
  }
  if (!c.has('InterfaceAlias') && !c.has('InterfaceIndex')) {
    if (fam !== 'ipv6') out.push(obj('MSFT_DNSClientServerAddress', { InterfaceAlias: 'Loopback Pseudo-Interface 1', InterfaceIndex: 1, AddressFamilyName: 'IPv4', AddressFamily: 2, ServerAddresses: [] }));
    if (fam !== 'ipv4') out.push(obj('MSFT_DNSClientServerAddress', { InterfaceAlias: 'Loopback Pseudo-Interface 1', InterfaceIndex: 1, AddressFamilyName: 'IPv6', AddressFamily: 23, ServerAddresses: ['fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3'] }));
  }
  return out;
});

netCmdlet('Set-DnsClientServerAddress', DNS, 'Sets DNS server addresses associated with the TCP/IP properties on an interface.', [{ name: 'InterfaceAlias', aliases: ['ifAlias'], type: 'strings', position: 0 }, { name: 'InterfaceIndex', aliases: ['ifIndex'], type: 'strings' }, { name: 'ServerAddresses', aliases: ['Addresses'], type: 'strings' }, { name: 'ResetServerAddresses', aliases: ['ResetAddresses'], type: 'switch' }], (c) => {
  if (accessDenied(c, 'MSFT_DNSClientServerAddress')) return;
  const list = pickAdapters(c, 'MSFT_DNSClientServerAddress');
  const servers = c.strs('ServerAddresses') ?? [];
  for (const s of servers) if (!isIp(s)) { c.error(`The address ${s} is not a valid IP address.`, { category: 'InvalidArgument', target: 'MSFT_DNSClientServerAddress', exception: 'CimException', id: 'Windows System Error 87,Set-DnsClientServerAddress' }); return; }
  for (const a of list) {
    if (c.whatIf('Set-DnsClientServerAddress', a.alias)) continue;
    a.dns = c.has('ResetServerAddresses') ? [] : servers;
  }
});

netCmdlet('Clear-DnsClientCache', DNS, 'Clears the contents of the DNS client cache.', [], (c) => {
  if (accessDenied(c, 'MSFT_DNSClientCache')) return;
});

netCmdlet('Get-DnsClientCache', DNS, 'Retrieves the contents of the DNS client cache.', [], () => []);

netCmdlet('Resolve-DnsName', DNS, 'Performs a DNS name query resolution for the specified name.', [{ name: 'Name', type: 'string', position: 0 }, { name: 'Type', type: 'string', position: 1 }, { name: 'Server', type: 'strings' }, { name: 'DnsOnly', type: 'switch' }, { name: 'NoHostsFile', type: 'switch' }, { name: 'QuickTimeout', type: 'switch' }], (c) => {
  const name = c.str('Name') ?? '';
  const type = (c.str('Type') ?? 'A_AAAA').toUpperCase();
  const qtypes: QType[] = type === 'A_AAAA' ? ['A', 'AAAA'] : QTYPES.includes(type as QType) ? [type as QType] : [];
  if (!qtypes.length) { c.error(`Cannot bind parameter 'Type'. Cannot convert value "${c.str('Type')}" to type "Microsoft.DnsClient.Commands.RecordType".`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage,Microsoft.DnsClient.Commands.ResolveDnsName' }); return; }
  const host = c.ctx.host;
  const servers = c.strs('Server') ?? winResolver(host).nameservers;
  const err = (msg: string, id: string) => c.error(`${name} : ${msg}`, { category: id === 'ERROR_TIMEOUT' ? 'OperationTimeout' : 'ResourceUnavailable', target: name, exception: 'Win32Exception', id: `${id},Microsoft.DnsClient.Commands.ResolveDnsName` });
  const ptr = isIp(name);
  const qname = ptr ? `${name.split('.').reverse().join('.')}.in-addr.arpa.` : name.endsWith('.') ? name : name.includes('.') ? `${name}.` : `${name}.${winResolver(host).search[0] ?? ''}.`.replace(/\.\.$/, '.');
  if (ptr) qtypes.splice(0, qtypes.length, 'PTR');
  const out: PSObject[] = [];
  let anyAnswer = false;
  for (const qt of qtypes) {
    let ex: ReturnType<typeof dnsQuery> | null = null;
    for (const s of servers) {
      ex = dnsQuery(c.ctx.world, host, s, qname, 2, qt);
      if (['answer', 'nxdomain', 'nodata', 'refused', 'servfail'].includes(ex.outcome)) break;
    }
    if (!ex || ['timeout', 'unreachable', 'port-unreachable'].includes(ex.outcome)) { err('This operation returned because the timeout period expired', 'ERROR_TIMEOUT'); return out; }
    if (ex.outcome === 'nxdomain') { err('DNS name does not exist', 'DNS_ERROR_RCODE_NAME_ERROR'); return out; }
    if (ex.outcome === 'refused') { err('DNS server failure', 'DNS_ERROR_RCODE_REFUSED'); return out; }
    if (ex.outcome === 'servfail') { err('DNS server failure', 'DNS_ERROR_RCODE_SERVER_FAILURE'); return out; }
    if (ex.outcome === 'answer') {
      anyAnswer = true;
      for (const r of ex.answer!.answers) {
        out.push(obj('Microsoft.DnsClient.Commands.DnsRecord', { Name: r.name.replace(/\.$/, ''), Type: r.type, TTL: r.ttl, Section: 'Answer', Data: r.data.replace(/\.$/, ''), IPAddress: r.data, NameHost: r.type === 'PTR' || r.type === 'CNAME' ? r.data.replace(/\.$/, '') : undefined }));
      }
    }
  }
  if (!anyAnswer && qtypes.length === 1) err('No records found', 'DNS_INFO_NO_RECORDS');
  return out;
});

// ---------------------------------------------------------------------------
// Connectivity
// ---------------------------------------------------------------------------

function adapterFor(host: Host, dst: string): WinAdapter | undefined {
  const r = lookupRoute(host, dst);
  return host.win!.adapters.find((a) => a.alias === r?.route.dev) ?? host.win!.adapters[0];
}

const WELL_KNOWN: Record<string, number> = { http: 80, rdp: 3389, smb: 445, winrm: 5985 };

netCmdlet('Test-NetConnection', 'NetTCPIP', 'Displays diagnostic information for a connection.', [{ name: 'ComputerName', aliases: ['RemoteAddress', 'cn'], type: 'string', position: 0 }, { name: 'Port', aliases: ['RemotePort'], type: 'int' }, { name: 'CommonTCPPort', type: 'string' }, { name: 'InformationLevel', type: 'string' }, { name: 'TraceRoute', type: 'switch' }], (c) => {
  const ctx = c.ctx;
  const name = c.str('ComputerName') ?? 'internetbeacon.msedge.net';
  const port = c.has('Port') ? Number(c.p.Port) : c.has('CommonTCPPort') ? WELL_KNOWN[c.str('CommonTCPPort')!.toLowerCase()] : undefined;
  const quiet = c.str('InformationLevel')?.toLowerCase() === 'quiet';
  const r = resolve4(ctx.world, ctx.host, name);
  if (!r.ok) {
    c.warn(`Name resolution of ${name} failed`);
    if (quiet) return [false];
    return [obj('TestNetConnectionResult', { ComputerName: name, RemoteAddress: '', InterfaceAlias: '', SourceAddress: '', PingSucceeded: false, 'PingReplyDetails (RTT)': '0 ms' })];
  }
  const ip = r.ip;
  const a = adapterFor(ctx.host, ip);
  const base = { ComputerName: name, RemoteAddress: ip } as Record<string, PSValue>;
  const tail = { InterfaceAlias: a?.alias ?? '', SourceAddress: sourceAddress(ctx.host, ip) };
  if (port !== undefined) {
    const conn = tcpConnect(ctx.world, ctx.host, ip, port, { timeoutMs: 21000 });
    if (conn.ok) {
      conn.conn.close('client');
      if (quiet) return [true];
      return [obj('TestNetConnectionResult', { ...base, RemotePort: port, ...tail, TcpTestSucceeded: true })];
    }
    c.warn(`TCP connect to (${ip} : ${port}) failed`);
    const e = echo(ctx.world, ctx.host, ip);
    if (e.kind !== 'reply') c.warn(`Ping to ${ip} failed with status: ${e.kind === 'timeout' ? 'TimedOut' : 'DestinationHostUnreachable'}`);
    if (quiet) return [false];
    return [obj('TestNetConnectionResult', { ...base, RemotePort: port, ...tail, PingSucceeded: e.kind === 'reply', 'PingReplyDetails (RTT)': `${e.kind === 'reply' ? e.ms : 0} ms`, TcpTestSucceeded: false })];
  }
  const e = echo(ctx.world, ctx.host, ip);
  if (e.kind !== 'reply') c.warn(`Ping to ${ip} failed with status: ${e.kind === 'timeout' ? 'TimedOut' : 'DestinationHostUnreachable'}`);
  if (quiet) return [e.kind === 'reply'];
  return [obj('TestNetConnectionResult', { ...base, ...tail, PingSucceeded: e.kind === 'reply', 'PingReplyDetails (RTT)': `${e.kind === 'reply' ? e.ms : 0} ms` })];
});

netCmdlet('Test-Connection', 'Microsoft.PowerShell.Management', 'Sends ICMP echo request packets, or pings, to one or more computers.', [{ name: 'ComputerName', aliases: ['CN', 'IPAddress', '__SERVER', 'Server', 'Destination'], type: 'strings', position: 0 }, { name: 'Count', type: 'int' }, { name: 'Quiet', type: 'switch' }, { name: 'BufferSize', aliases: ['Size', 'Bytes', 'BS'], type: 'int' }], (c) => {
  const ctx = c.ctx;
  const count = Number(c.p.Count ?? 4);
  const size = Number(c.p.BufferSize ?? 32);
  const out: PSValue[] = [];
  for (const name of c.strs('ComputerName') ?? []) {
    const r = resolve4(ctx.world, ctx.host, name);
    let okCount = 0;
    if (!r.ok) {
      if (c.has('Quiet')) { out.push(false); continue; }
      c.error(`Testing connection to computer '${name}' failed: No such host is known`, { category: 'ResourceUnavailable', target: name, exception: 'PingException', id: 'TestConnectionException,Microsoft.PowerShell.Commands.TestConnectionCommand' });
      continue;
    }
    for (let i = 1; i <= count; i++) {
      const start = ctx.world.clock;
      const e = echo(ctx.world, ctx.host, r.ip, size, i);
      if (e.kind === 'reply') {
        okCount++;
        if (!c.has('Quiet')) out.push(obj('System.Management.ManagementObject#root\\cimv2\\Win32_PingStatus', { PSComputerName: ctx.host.hostname.toUpperCase(), Address: name, IPV4Address: r.ip, IPV6Address: '', BufferSize: size, ResponseTime: e.ms, StatusCode: 0, ResponseTimeToLive: e.ttl }));
      }
      ctx.world.clock = Math.max(ctx.world.clock, start + 1000);
    }
    if (c.has('Quiet')) out.push(okCount > 0);
    else if (okCount === 0) c.error(`Testing connection to computer '${name}' failed: Error due to lack of resources`, { category: 'ResourceUnavailable', target: name, exception: 'PingException', id: 'TestConnectionException,Microsoft.PowerShell.Commands.TestConnectionCommand' });
  }
  return out;
});

netCmdlet('Get-NetTCPConnection', TCPIP, 'Gets TCP connections.', [{ name: 'LocalAddress', type: 'strings', position: 0 }, { name: 'LocalPort', type: 'strings', position: 1 }, { name: 'State', type: 'strings' }, { name: 'OwningProcess', type: 'strings' }], (c) => {
  let out = winListeners(c.ctx.host).filter((l) => l.proto === 'tcp').sort((a, b) => (a.addr === b.addr ? a.port - b.port : b.addr.length - a.addr.length)).map((l) => obj('MSFT_NetTCPConnection', {
    LocalAddress: l.addr, LocalPort: l.port, RemoteAddress: l.addr === '::' ? '::' : '0.0.0.0', RemotePort: 0, State: 'Listen', AppliedSetting: '', OwningProcess: l.pid,
  }));
  if (c.has('LocalPort')) out = out.filter((o) => c.strs('LocalPort')!.includes(String(o.LocalPort)));
  if (c.has('LocalAddress')) out = out.filter((o) => c.strs('LocalAddress')!.includes(toStr(o.LocalAddress)));
  if (c.has('State')) out = out.filter((o) => c.strs('State')!.some((s) => s.toLowerCase() === toStr(o.State).toLowerCase()));
  if (c.has('OwningProcess')) out = out.filter((o) => c.strs('OwningProcess')!.includes(String(o.OwningProcess)));
  if (!out.length && (c.has('LocalPort') || c.has('State'))) notFound(c, 'MSFT_NetTCPConnection', c.has('LocalPort') ? 'LocalPort' : 'State', c.str('LocalPort') ?? c.str('State')!);
  return out;
});

netCmdlet('Get-NetUDPEndpoint', TCPIP, 'Gets statistics for UDP endpoints.', [{ name: 'LocalPort', type: 'strings', position: 0 }], (c) => {
  return winListeners(c.ctx.host).filter((l) => l.proto === 'udp' && (!c.has('LocalPort') || c.strs('LocalPort')!.includes(String(l.port)))).map((l) => obj('MSFT_NetUDPEndpoint', { LocalAddress: l.addr, LocalPort: l.port, OwningProcess: l.pid }));
});

netCmdlet('Get-NetNeighbor', TCPIP, 'Gets neighbor cache entries.', [{ name: 'IPAddress', type: 'strings', position: 0 }, ...IF_PARAMS], (c) => {
  const host = c.ctx.host;
  return host.neighbors.filter((n) => !c.has('IPAddress') || c.strs('IPAddress')!.includes(n.ip)).map((n) => {
    const a = host.win!.adapters.find((x) => x.alias === n.dev);
    return obj('MSFT_NetNeighbor', { ifIndex: a?.ifIndex ?? 0, IPAddress: n.ip, LinkLayerAddress: n.mac ? winMac(n.mac) : '00-00-00-00-00-00', State: n.state === 'REACHABLE' ? 'Reachable' : n.state === 'STALE' ? 'Stale' : 'Unreachable', PolicyStore: 'ActiveStore' });
  });
});

// ---------------------------------------------------------------------------
// Network location (firewall profile)
// ---------------------------------------------------------------------------

function profileObj(host: Host, a: WinAdapter): PSObject {
  // A domain member that reached a DC at boot is on its domain network (Network Location Awareness).
  const dom = host.win!.domainNetwork ? host.win!.domain?.domain : undefined;
  return obj('MSFT_NetConnectionProfile', { Name: dom ?? (a.dnsSuffix || 'Network'), InterfaceAlias: a.alias, InterfaceIndex: a.ifIndex, NetworkCategory: dom ? 'DomainAuthenticated' : a.category === 'Domain' ? 'DomainAuthenticated' : a.category, IPv4Connectivity: a.gateway ? 'Internet' : 'LocalNetwork', IPv6Connectivity: 'NoTraffic' });
}

netCmdlet('Get-NetConnectionProfile', 'NetConnection', 'Gets a connection profile.', [...IF_PARAMS, { name: 'NetworkCategory', type: 'string' }], (c) => pickAdapters(c, 'MSFT_NetConnectionProfile').map((a) => profileObj(c.ctx.host, a)));

netCmdlet('Set-NetConnectionProfile', 'NetConnection', 'Changes the network category of a connection profile.', [...IF_PARAMS, { name: 'NetworkCategory', type: 'string' }, { name: 'Name', type: 'string' }, { name: 'InputObject', type: 'any' }], (c) => {
  if (accessDenied(c, 'MSFT_NetConnectionProfile')) return;
  const cat = (c.str('NetworkCategory') ?? '').toLowerCase();
  const map: Record<string, FwProfile> = { private: 'Private', public: 'Public' };
  if (!map[cat]) {
    if (cat === 'domainauthenticated') c.error('Unable to set NetworkCategory to \'DomainAuthenticated\'. This NetworkCategory type will be set automatically when authenticated to a domain network.', { category: 'PermissionDenied', target: 'MSFT_NetConnectionProfile', exception: 'CimException', id: 'Windows System Error 5,Set-NetConnectionProfile' });
    else c.error(`Cannot bind parameter 'NetworkCategory'. Cannot convert value "${c.str('NetworkCategory') ?? ''}" to type "Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetConnectionProfile.NetworkCategory". Error: "Unable to match the identifier name ${c.str('NetworkCategory') ?? ''} to a valid enumerator name. Specify one of the following enumerator names and try again:\nPublic, Private, DomainAuthenticated"`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage,Set-NetConnectionProfile' });
    return;
  }
  const fromPipe = c.input.filter(isObj).map((o) => toStr(getProp(o, 'InterfaceAlias')));
  const list = fromPipe.length ? adapters(c).filter((a) => fromPipe.includes(a.alias)) : pickAdapters(c, 'MSFT_NetConnectionProfile');
  for (const a of list) {
    if (c.whatIf('Set-NetConnectionProfile', a.alias)) continue;
    a.category = map[cat];
    winEvent(c.ctx.world, c.ctx.host, 'Microsoft-Windows-NetworkProfile/Operational', 10000, 'Microsoft-Windows-NetworkProfile', `Network Connected\n Name: ${a.dnsSuffix || 'Network'}\n Desc: ${a.description}\n Type: Managed\n State: Connected,IPV4 (Internet)\n Category: ${map[cat]}`);
  }
  applyFirewall(c.ctx.host);
});

// ---------------------------------------------------------------------------
// Invoke-WebRequest (System.Net.HttpWebRequest over the simulated network)
// ---------------------------------------------------------------------------

function curlCtx(ctx: PsCtx): CmdCtx {
  return { world: ctx.world, host: ctx.host, user: ctx.user, frame: { hostId: ctx.host.id, user: ctx.user.name, cwd: ctx.session.cwd }, ask: ctx.ask, run: () => ({ out: '', code: 1 }) };
}

const curl = HTTP_COMMANDS.find((x) => x.name === 'curl')!;

cmdlet({
  name: 'Invoke-WebRequest', module: 'Microsoft.PowerShell.Utility', synopsis: 'Gets content from a web page on the internet.', cls: 'Microsoft.PowerShell.Commands.InvokeWebRequestCommand',
  params: [{ name: 'Uri', type: 'string', position: 0 }, { name: 'UseBasicParsing', type: 'switch' }, { name: 'Method', type: 'string' }, { name: 'TimeoutSec', type: 'int' }, { name: 'OutFile', type: 'string' }, { name: 'MaximumRedirection', type: 'int' }],
  run(c) {
    const uri = c.str('Uri') ?? '';
    const head = (c.str('Method') ?? 'GET').toUpperCase() === 'HEAD';
    const full = /^[a-z]+:\/\//i.test(uri) ? uri : `http://${uri}`;
    const args = ['-s', '-S', '-v', ...(head ? ['-I'] : []), '-m', String(c.p.TimeoutSec ?? 100), ...(c.p.MaximumRedirection === 0 ? [] : ['-L']), full];
    const r = curl.run(args, curlCtx(c.ctx));
    const fail = (msg: string, id = 'WebCmdletWebResponseException') => c.error(msg, { category: 'InvalidOperation', target: 'System.Net.HttpWebRequest', exception: id === 'WebCmdletWebResponseException' ? 'WebException' : 'NotSupportedException', id });
    if (r.code !== 0) {
      const code = /curl: \((\d+)\)/.exec(r.out)?.[1];
      if (code === '6') fail('The remote name could not be resolved: \'' + full.replace(/^[a-z]+:\/\//i, '').split(/[/:]/)[0] + '\'');
      else if (code === '28') fail('The operation has timed out.');
      else if (code === '60') fail('The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel.');
      else if (code === '1' && /Protocol/.test(r.out)) fail(`The URI prefix is not recognized.`, 'WebCmdletIEDomNotSupportedException');
      else if (code === '7' || code === '35') fail('Unable to connect to the remote server');
      else fail('The underlying connection was closed: The connection was closed unexpectedly.');
      return [];
    }
    const lines = r.out.split('\n');
    const statusIdx = lines.map((l, i) => (/^< HTTP\/1\.1 /.test(l) ? i : -1)).filter((i) => i >= 0).pop() ?? -1;
    const status = statusIdx >= 0 ? /^< HTTP\/1\.1 (\d+) (.*)$/.exec(lines[statusIdx]) : null;
    const headers: string[] = [];
    for (let i = statusIdx + 1; i < lines.length && lines[i].startsWith('< ') && lines[i] !== '<'; i++) headers.push(lines[i].slice(2));
    const endIdx = lines.findIndex((l) => /^\* Connection #0 to host .* left intact$/.test(l));
    const body = head ? '' : lines.slice(endIdx + 1).join('\n');
    const code = Number(status?.[1] ?? 0);
    if (code >= 400) {
      fail(body.replace(/<[^>]+>/g, '').replace(/\n\s*\n+/g, '\n').trim() || `The remote server returned an error: (${code}) ${status?.[2] ?? ''}.`);
      return [];
    }
    if (c.has('OutFile')) {
      const path = c.str('OutFile')!;
      const host = c.ctx.host;
      writeFile(host, absPath(c.ctx, path), body, c.ctx.world.clock, { owner: c.ctx.user.name, group: c.ctx.user.name });
      return [];
    }
    const hdrMap = Object.fromEntries(headers.map((h) => [h.split(':')[0], h.split(':').slice(1).join(':').trim()]));
    return [obj('Microsoft.PowerShell.Commands.HtmlWebResponseObject', {
      StatusCode: code, StatusDescription: status?.[2] ?? '', Content: body, RawContent: [`HTTP/1.1 ${code} ${status?.[2] ?? ''}`, ...headers, '', body].join('\n').slice(0, 400),
      Headers: `{${Object.keys(hdrMap).map((k) => `[${k}, ${hdrMap[k]}]`).join(', ')}}`, RawContentLength: Number(hdrMap['Content-Length'] ?? body.length),
    })];
  },
});
registerView('Microsoft.PowerShell.Commands.HtmlWebResponseObject', { kind: 'list', props: ['StatusCode', 'StatusDescription', 'Content', 'RawContent', 'Headers', 'RawContentLength'] });
