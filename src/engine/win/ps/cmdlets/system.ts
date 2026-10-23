// Services, processes, event logs, local accounts and computer information.

import type { Host } from '../../../types';
import { seededInt } from '../../../util/sha256';
import { startWinService, stopWinService, winEvent, type WinEvent, type WinService } from '../../model';
import { registerView } from '../format';
import { cmdlet, type Call } from '../runtime';
import { date, flatten, getProp, hashGet, hasWildcard, isHash, isObj, obj, toNum, toStr, wildcard, type PSObject, type PSValue } from '../values';
import { isAdmin } from './files';

const MGMT = 'Microsoft.PowerShell.Management';
const ACCOUNTS = 'Microsoft.PowerShell.LocalAccounts';

registerView('System.ServiceProcess.ServiceController', { kind: 'table', columns: [{ label: 'Status', value: 'Status', width: 8 }, { label: 'Name', value: 'Name', width: 18 }, { label: 'DisplayName', value: 'DisplayName' }] });
registerView('System.Diagnostics.Process', {
  kind: 'table', columns: [
    { label: 'Handles', value: 'Handles', width: 7, align: 'right' }, { label: 'NPM(K)', value: 'NPM', width: 7, align: 'right' }, { label: 'PM(K)', value: 'PM', width: 8, align: 'right' },
    { label: 'WS(K)', value: 'WS', width: 10, align: 'right' }, { label: 'CPU(s)', value: (o) => (o.CPU === null ? '' : (o.CPU as number).toFixed(2)), width: 10, align: 'right' },
    { label: 'Id', value: 'Id', width: 6, align: 'right' }, { label: 'SI', value: 'SI', width: 3, align: 'right' }, { label: 'ProcessName', value: 'ProcessName' },
  ],
});
registerView('System.Diagnostics.Eventing.Reader.EventLogRecord', {
  kind: 'table', groupBy: { prop: 'ProviderName', label: 'ProviderName', indent: '   ' },
  columns: [{ label: 'TimeCreated', value: 'TimeCreated', width: 26 }, { label: 'Id', value: 'Id', width: 7, align: 'right' }, { label: 'LevelDisplayName', value: 'LevelDisplayName', width: 16 }, { label: 'Message', value: (o) => toStr(o.Message).split('\n')[0] }],
});
registerView('System.Diagnostics.EventLogEntry', {
  kind: 'table', columns: [{ label: 'Index', value: 'Index', width: 8, align: 'right' }, { label: 'Time', value: (o) => fmtShort(o.TimeGenerated as { ms: number }), width: 12 }, { label: 'EntryType', value: 'EntryType', width: 11 }, { label: 'Source', value: 'Source', width: 22 }, { label: 'InstanceID', value: 'InstanceID', width: 11, align: 'right' }, { label: 'Message', value: (o) => toStr(o.Message).split('\n')[0] }],
});
registerView('Microsoft.PowerShell.Commands.LocalUser', { kind: 'table', columns: [{ label: 'Name', value: 'Name', width: 18 }, { label: 'Enabled', value: 'Enabled', width: 7 }, { label: 'Description', value: 'Description' }] });
registerView('Microsoft.PowerShell.Commands.LocalGroup', { kind: 'table', columns: [{ label: 'Name', value: 'Name', width: 35 }, { label: 'Description', value: 'Description' }] });
registerView('Microsoft.PowerShell.Commands.LocalPrincipal', { kind: 'table', columns: [{ label: 'ObjectClass', value: 'ObjectClass', width: 11 }, { label: 'Name', value: 'Name', width: 30 }, { label: 'PrincipalSource', value: 'PrincipalSource' }] });

function fmtShort(d: { ms: number }): string {
  const x = new Date(d.ms);
  const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][x.getUTCMonth()];
  return `${mon} ${String(x.getUTCDate()).padStart(2, '0')} ${String(x.getUTCHours()).padStart(2, '0')}:${String(x.getUTCMinutes()).padStart(2, '0')}`;
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

function svcObj(host: Host, s: WinService): PSObject {
  const all = Object.values(host.win!.services);
  return obj('System.ServiceProcess.ServiceController', {
    Status: s.status, Name: s.name, DisplayName: s.displayName, StartType: s.startType === 'AutomaticDelayedStart' ? 'Automatic' : s.startType,
    ServiceName: s.name, CanStop: s.status === 'Running' && !s.protected, ServiceType: s.process === 'svchost' ? 'Win32ShareProcess' : 'Win32OwnProcess',
    DependentServices: all.filter((x) => x.dependsOn.includes(s.name)).map((x) => x.name), ServicesDependedOn: s.dependsOn, MachineName: '.', __str: 'System.ServiceProcess.ServiceController',
  });
}

/** Services selected by -Name / -DisplayName / pipeline input, reporting unknown names. */
function selectServices(c: Call, verb: string): WinService[] {
  const w = c.ctx.host.win!;
  const all = Object.values(w.services).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  const names = c.strs('Name') ?? c.strs('InputObject') ?? (c.input.length ? c.input.map((i) => (isObj(i) ? toStr(getProp(i, 'Name')) : toStr(i))) : undefined);
  if (c.has('DisplayName')) {
    const out = all.filter((s) => c.strs('DisplayName')!.some((n) => wildcard(n).test(s.displayName)));
    for (const n of c.strs('DisplayName')!) if (!hasWildcard(n) && !out.some((s) => wildcard(n).test(s.displayName))) c.error(`Cannot find any service with display name '${n}'.`, { category: 'ObjectNotFound', target: n, exception: 'ServiceCommandException', id: `NoServiceFoundForGivenDisplayName` });
    return out;
  }
  if (!names) return all;
  const out: WinService[] = [];
  for (const n of names) {
    const re = wildcard(n);
    const hit = all.filter((s) => re.test(s.name) || (!hasWildcard(n) && s.displayName.toLowerCase() === n.toLowerCase()));
    if (!hit.length && !hasWildcard(n)) c.error(`Cannot find any service with service name '${n}'.`, { category: 'ObjectNotFound', target: n, exception: 'ServiceCommandException', id: 'NoServiceFoundForGivenName' });
    for (const h of hit) if (!out.includes(h)) out.push(h);
  }
  void verb;
  return out;
}

registerSvc('Get-Service', 'Gets the services on the computer.', (c) => {
  const out = selectServices(c, 'get');
  if (c.has('DependentServices')) return out.flatMap((s) => Object.values(c.ctx.host.win!.services).filter((x) => x.dependsOn.includes(s.name))).map((s) => svcObj(c.ctx.host, s));
  if (c.has('RequiredServices')) return out.flatMap((s) => s.dependsOn.map((d) => c.ctx.host.win!.services[d]).filter(Boolean)).map((s) => svcObj(c.ctx.host, s));
  return out.map((s) => svcObj(c.ctx.host, s));
}, [{ name: 'DependentServices', aliases: ['DS'], type: 'switch' }, { name: 'RequiredServices', aliases: ['SDO', 'ServicesDependedOn'], type: 'switch' }]);

function label(s: WinService): string {
  return `${s.displayName} (${s.name})`;
}

function denyNonAdmin(c: Call, s: WinService, op: 'start' | 'stop'): boolean {
  if (isAdmin(c)) return false;
  c.error(`Service '${label(s)}' cannot be ${op === 'start' ? 'started' : 'stopped'} due to the following error: Cannot open ${s.name} service on computer '.'.`, { category: op === 'start' ? 'OpenError' : 'CloseError', target: 'System.ServiceProcess.ServiceController:ServiceController', exception: 'ServiceCommandException', id: op === 'start' ? 'CouldNotStartService' : 'CouldNotStopService' });
  return true;
}

function doStart(c: Call, s: WinService): boolean {
  if (denyNonAdmin(c, s, 'start')) return false;
  if (c.whatIf('Start-Service', label(s))) return false;
  const r = startWinService(c.ctx.world, c.ctx.host, s.name);
  if (!r.ok) {
    c.error(`Service '${label(s)}' cannot be started due to the following error: Cannot start service ${s.name} on computer '.'.`, { category: 'OpenError', target: 'System.ServiceProcess.ServiceController:ServiceController', exception: 'ServiceCommandException', id: 'CouldNotStartService' });
    return false;
  }
  return true;
}

function doStop(c: Call, s: WinService): boolean {
  if (denyNonAdmin(c, s, 'stop')) return false;
  const w = c.ctx.host.win!;
  const deps = Object.values(w.services).filter((x) => x.dependsOn.includes(s.name) && x.status === 'Running');
  if (deps.length && !c.has('Force')) {
    c.error(`Cannot stop service '${label(s)}' because it has dependent services. It can only be stopped if the Force flag is set.`, { category: 'InvalidOperation', target: 'System.ServiceProcess.ServiceController:ServiceController', exception: 'ServiceCommandException', id: 'ServiceHasDependentServices' });
    return false;
  }
  if (c.whatIf('Stop-Service', label(s))) return false;
  if (s.protected) {
    c.error(`Service '${label(s)}' cannot be stopped due to the following error: Cannot stop ${s.name} service on computer '.'.`, { category: 'CloseError', target: 'System.ServiceProcess.ServiceController:ServiceController', exception: 'ServiceCommandException', id: 'CouldNotStopService' });
    return false;
  }
  for (const d of deps) stopWinService(c.ctx.world, c.ctx.host, d.name);
  stopWinService(c.ctx.world, c.ctx.host, s.name);
  return true;
}

registerSvc('Start-Service', 'Starts one or more stopped services.', (c) => {
  const out: PSValue[] = [];
  for (const s of selectServices(c, 'start')) if (doStart(c, s) && c.has('PassThru')) out.push(svcObj(c.ctx.host, s));
  return out;
});

registerSvc('Stop-Service', 'Stops one or more running services.', (c) => {
  const out: PSValue[] = [];
  for (const s of selectServices(c, 'stop')) if (doStop(c, s) && c.has('PassThru')) out.push(svcObj(c.ctx.host, s));
  return out;
}, [{ name: 'Force', type: 'switch' }, { name: 'NoWait', type: 'switch' }]);

registerSvc('Restart-Service', 'Stops and then starts one or more services.', (c) => {
  const out: PSValue[] = [];
  for (const s of selectServices(c, 'restart')) {
    if (s.status === 'Running') { if (!doStop(c, s)) continue; }
    if (doStart(c, s) && c.has('PassThru')) out.push(svcObj(c.ctx.host, s));
  }
  return out;
}, [{ name: 'Force', type: 'switch' }]);

registerSvc('Set-Service', 'Starts, stops, and suspends a service, and changes its properties.', (c) => {
  for (const s of selectServices(c, 'set')) {
    if (!isAdmin(c)) { c.error(`Service '${label(s)}' cannot be configured due to the following error: Access is denied`, { category: 'PermissionDenied', target: 'System.ServiceProcess.ServiceController:ServiceController', exception: 'ServiceCommandException', id: 'CouldNotSetService' }); continue; }
    if (c.whatIf('Set-Service', label(s))) continue;
    if (c.has('StartupType')) {
      const t = c.str('StartupType')!.toLowerCase();
      const map: Record<string, WinService['startType']> = { automatic: 'Automatic', manual: 'Manual', disabled: 'Disabled', automaticdelayedstart: 'AutomaticDelayedStart', boot: 'Automatic', system: 'Automatic' };
      if (!map[t]) { c.error(`Cannot bind parameter 'StartupType'. Cannot convert value "${c.str('StartupType')}" to type "System.ServiceProcess.ServiceStartMode". Error: "Unable to match the identifier name ${c.str('StartupType')} to a valid enumerator name. Specify one of the following enumerator names and try again:\nBoot, System, Automatic, Manual, Disabled"`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage' }); continue; }
      s.startType = map[t];
      winEvent(c.ctx.world, c.ctx.host, 'System', 7040, 'Service Control Manager', `The start type of the ${s.displayName} service was changed from ${s.startType === map[t] ? 'demand start' : ''} to ${map[t] === 'Disabled' ? 'disabled' : map[t] === 'Manual' ? 'demand start' : 'auto start'}.`);
    }
    if (c.has('Status')) {
      const st = c.str('Status')!.toLowerCase();
      if (st === 'running') doStart(c, s);
      else if (st === 'stopped') doStop(c, s);
    }
  }
}, [{ name: 'StartupType', aliases: ['StartMode', 'SM', 'ST'], type: 'string' }, { name: 'Status', type: 'string' }, { name: 'Force', type: 'switch' }]);

function registerSvc(name: string, synopsis: string, run: (c: Call) => PSValue[] | void, extra: { name: string; aliases?: string[]; type?: 'switch' | 'string' }[] = []): void {
  cmdlet({
    name, module: MGMT, synopsis, run,
    cls: `Microsoft.PowerShell.Commands.${name.replace('-', '')}Command`,
    params: [{ name: 'Name', aliases: ['ServiceName'], type: 'strings', position: 0 }, { name: 'DisplayName', type: 'strings' }, { name: 'InputObject', type: 'any' }, { name: 'PassThru', type: 'switch' }, { name: 'ComputerName', aliases: ['cn'], type: 'strings' }, ...extra],
  });
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

interface Proc { name: string; id: number; si: number; svc?: string }

function processes(host: Host, me: string): Proc[] {
  const w = host.win!;
  const base: Proc[] = [
    { name: 'Idle', id: 0, si: 0 }, { name: 'System', id: 4, si: 0 }, { name: 'Registry', id: 92, si: 0 }, { name: 'smss', id: 316, si: 0 }, { name: 'csrss', id: 428, si: 0 }, { name: 'wininit', id: 504, si: 0 },
    { name: 'services', id: 624, si: 0 }, { name: 'lsass', id: 640, si: 0 }, { name: 'csrss', id: 516, si: 1 }, { name: 'winlogon', id: 572, si: 1 }, { name: 'dwm', id: 912, si: 1 }, { name: 'explorer', id: 3304, si: 1 },
    { name: 'powershell', id: 4128, si: 1 }, { name: 'conhost', id: 4136, si: 1 },
  ];
  for (const s of Object.values(w.services)) {
    if (s.status !== 'Running' || s.pid === null || ['System', 'lsass'].includes(s.process)) continue;
    base.push({ name: s.process, id: s.pid, si: 0, svc: s.name });
  }
  void me;
  return base.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || a.id - b.id);
}

function procObj(host: Host, p: Proc): PSObject {
  const seed = `${host.id}:${p.name}:${p.id}`;
  const ws = p.id === 0 ? 8 : seededInt(seed + 'ws', 4000, p.name === 'MsMpEng' ? 220000 : 60000);
  return obj('System.Diagnostics.Process', {
    Handles: p.id === 0 ? 0 : seededInt(seed + 'h', 80, 1800), NPM: seededInt(seed + 'n', 5, 40), PM: seededInt(seed + 'p', 1200, 90000), WS: ws,
    CPU: p.id === 0 ? null : seededInt(seed + 'c', 1, 900) / 100, Id: p.id, SI: p.si, ProcessName: p.name, Name: p.name,
    Path: p.id <= 4 ? null : p.name === 'explorer' ? 'C:\\Windows\\explorer.exe' : p.name === 'powershell' ? 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' : `C:\\Windows\\system32\\${p.name}.exe`,
    __svc: p.svc ?? null, __str: `System.Diagnostics.Process (${p.name})`,
  });
}

cmdlet({
  name: 'Get-Process', module: MGMT, synopsis: 'Gets the processes that are running on the local computer.',
  params: [{ name: 'Name', aliases: ['ProcessName'], type: 'strings', position: 0 }, { name: 'Id', aliases: ['PID'], type: 'any' }, { name: 'IncludeUserName', type: 'switch' }],
  run(c) {
    let ps = processes(c.ctx.host, c.ctx.user.name);
    if (c.has('Id')) {
      const ids = flatten(c.p.Id).map((x) => toNum(x));
      for (const id of ids) if (!ps.some((p) => p.id === id)) c.error(`Cannot find a process with the process identifier ${id}.`, { category: 'ObjectNotFound', target: String(id), exception: 'ProcessCommandException', id: 'NoProcessFoundForGivenId' });
      ps = ps.filter((p) => ids.includes(p.id));
    }
    if (c.has('Name')) {
      const out: Proc[] = [];
      for (const n of c.strs('Name')!) {
        const hit = ps.filter((p) => wildcard(n).test(p.name));
        if (!hit.length && !hasWildcard(n)) c.error(`Cannot find a process with the name "${n}". Verify the process name and call the cmdlet again.`, { category: 'ObjectNotFound', target: n, exception: 'ProcessCommandException', id: 'NoProcessFoundForGivenName' });
        out.push(...hit);
      }
      ps = out;
    }
    return ps.map((p) => procObj(c.ctx.host, p));
  },
});

cmdlet({
  name: 'Stop-Process', module: MGMT, synopsis: 'Stops one or more running processes.',
  params: [{ name: 'Id', type: 'any', position: 0 }, { name: 'Name', aliases: ['ProcessName'], type: 'strings' }, { name: 'Force', type: 'switch' }, { name: 'InputObject', type: 'any' }, { name: 'PassThru', type: 'switch' }],
  run(c) {
    const all = processes(c.ctx.host, c.ctx.user.name);
    let targets: Proc[] = [];
    if (c.has('Id')) targets = flatten(c.p.Id).map((x) => all.find((p) => p.id === toNum(x))).filter((p): p is Proc => !!p);
    else if (c.has('Name')) targets = all.filter((p) => c.strs('Name')!.some((n) => wildcard(n).test(p.name)));
    else targets = c.input.map((i) => all.find((p) => p.id === toNum(getProp(i, 'Id')))).filter((p): p is Proc => !!p);
    for (const p of targets) {
      if (p.id <= 4 || ['csrss', 'wininit', 'smss', 'services', 'lsass', 'winlogon'].includes(p.name)) {
        c.error(`Cannot stop process "${p.name} (${p.id})" because of the following error: Access is denied`, { category: 'CloseError', target: `System.Diagnostics.Process (${p.name}):Process`, exception: 'ProcessCommandException', id: 'CouldNotStopProcess' });
        continue;
      }
      if (c.whatIf('Stop-Process', `${p.name} (${p.id})`)) continue;
      const w = c.ctx.host.win!;
      for (const s of Object.values(w.services)) {
        if (s.pid !== p.id || s.status !== 'Running') continue;
        s.status = 'Stopped';
        s.pid = null;
        winEvent(c.ctx.world, c.ctx.host, 'System', 7034, 'Service Control Manager', `The ${s.displayName} service terminated unexpectedly.  It has done this 1 time(s).`, 'Error');
      }
    }
  },
});

// ---------------------------------------------------------------------------
// Event logs
// ---------------------------------------------------------------------------

const LEVELS: Record<string, number> = { Error: 2, Warning: 3, Information: 4 };

function eventObj(e: WinEvent, machine: string): PSObject {
  return obj('System.Diagnostics.Eventing.Reader.EventLogRecord', { TimeCreated: date(e.time), Id: e.id, LevelDisplayName: e.level, Message: e.message, ProviderName: e.provider, LogName: e.log, RecordId: e.recordId, Level: LEVELS[e.level], MachineName: machine });
}

cmdlet({
  name: 'Get-WinEvent', module: 'Microsoft.PowerShell.Diagnostics', synopsis: 'Gets events from event logs and event tracing log files on local and remote computers.',
  params: [{ name: 'LogName', type: 'strings', position: 0 }, { name: 'MaxEvents', type: 'int' }, { name: 'FilterHashtable', type: 'any' }, { name: 'ListLog', type: 'strings' }, { name: 'ProviderName', type: 'strings' }, { name: 'Oldest', type: 'switch' }],
  run(c) {
    const w = c.ctx.host.win!;
    const machine = `${c.ctx.host.hostname}.corp.lab`;
    if (c.has('ListLog')) {
      const logs = ['Application', 'Security', 'System', 'Windows PowerShell', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'];
      return logs.filter((l) => c.strs('ListLog')!.some((p) => wildcard(p).test(l))).map((l) => obj('System.Diagnostics.Eventing.Reader.EventLogConfiguration', { LogMode: 'Circular', MaximumSizeInBytes: 20971520, RecordCount: w.events.filter((e) => e.log === l).length, LogName: l }));
    }
    let ev = [...w.events];
    let logs = c.strs('LogName');
    let ids: number[] | undefined;
    let level: number[] | undefined;
    let start: number | undefined;
    if (c.has('FilterHashtable')) {
      const h = c.p.FilterHashtable;
      if (!isHash(h)) { c.error('Cannot bind parameter \'FilterHashtable\'.', { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage' }); return []; }
      const ln = hashGet(h, 'LogName');
      if (ln !== null) logs = flatten(ln).map(toStr);
      const id = hashGet(h, 'Id') ?? hashGet(h, 'EventID');
      if (id !== null) ids = flatten(id).map((x) => toNum(x) ?? -1);
      const lv = hashGet(h, 'Level');
      if (lv !== null) level = flatten(lv).map((x) => toNum(x) ?? -1);
      const st = hashGet(h, 'StartTime');
      if (st !== null && isObj(st) && st.__t === 'System.DateTime') start = (st as unknown as { ms: number }).ms;
      const pn = hashGet(h, 'ProviderName');
      if (pn !== null) ev = ev.filter((e) => flatten(pn).some((p) => wildcard(toStr(p)).test(e.provider)));
    }
    if (!logs && !c.has('ProviderName')) { c.error('Cannot bind parameter. Specify -LogName or -FilterHashtable.', { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'AmbiguousParameterSet' }); return []; }
    if (logs) {
      const known = ['application', 'security', 'system', 'windows powershell', 'setup', 'microsoft-windows-terminalservices-localsessionmanager/operational', 'microsoft-windows-windows firewall with advanced security/firewall'];
      for (const l of logs) if (!hasWildcard(l) && !known.includes(l.toLowerCase())) c.error(`There is not an event log on the localhost computer that matches "${l}".`, { category: 'ObjectNotFound', target: l, exception: 'Exception', id: 'NoMatchingLogsFound' });
      ev = ev.filter((e) => logs!.some((l) => wildcard(l).test(e.log)));
    }
    if (c.has('ProviderName')) ev = ev.filter((e) => c.strs('ProviderName')!.some((p) => wildcard(p).test(e.provider)));
    if (ids) ev = ev.filter((e) => ids!.includes(e.id));
    if (level) ev = ev.filter((e) => level!.includes(LEVELS[e.level]));
    if (start !== undefined) ev = ev.filter((e) => e.time >= start!);
    ev.sort((a, b) => b.time - a.time || b.recordId - a.recordId);
    if (c.has('Oldest')) ev.reverse();
    if (c.has('MaxEvents')) ev = ev.slice(0, toNum(c.p.MaxEvents) ?? 0);
    if (!ev.length) c.error('No events were found that match the specified selection criteria.', { category: 'ObjectNotFound', target: '', exception: 'Exception', id: 'NoMatchingEventsFound' });
    return ev.map((e) => eventObj(e, machine));
  },
});

cmdlet({
  name: 'Get-EventLog', module: MGMT, synopsis: 'Gets the events in an event log, or a list of the event logs, on the local computer or remote computers.',
  params: [{ name: 'LogName', type: 'string', position: 0 }, { name: 'Newest', type: 'int' }, { name: 'EntryType', type: 'strings' }, { name: 'Source', type: 'strings' }, { name: 'InstanceId', type: 'any', position: 1 }, { name: 'List', type: 'switch' }],
  run(c) {
    const w = c.ctx.host.win!;
    if (c.has('List') || !c.has('LogName')) {
      if (!c.has('List')) { c.ctx.ask('cmdlet Get-EventLog at command pipeline position 1\nSupply values for the following parameters:\nLogName: ', false); }
      return ['Application', 'Security', 'System', 'Windows PowerShell'].map((l) => obj('System.Diagnostics.EventLog', { Max: '20,480', Retain: 0, OverflowAction: 'OverwriteAsNeeded', Entries: w.events.filter((e) => e.log === l).length.toLocaleString('en-US'), Log: l }));
    }
    const log = c.str('LogName')!;
    if (!['application', 'security', 'system', 'windows powershell'].includes(log.toLowerCase())) { c.error(`The event log '${log}' on computer '.' does not exist.`, { category: 'NotSpecified', target: '', exception: 'InvalidOperationException', id: 'System.InvalidOperationException' }); return []; }
    let ev = w.events.filter((e) => e.log.toLowerCase() === log.toLowerCase());
    if (c.has('EntryType')) ev = ev.filter((e) => c.strs('EntryType')!.some((t) => t.toLowerCase() === e.level.toLowerCase()));
    if (c.has('Source')) ev = ev.filter((e) => c.strs('Source')!.some((s) => wildcard(s).test(e.provider)));
    if (c.has('InstanceId')) { const ids = flatten(c.p.InstanceId).map((x) => toNum(x)); ev = ev.filter((e) => ids.includes(e.id)); }
    ev = [...ev].sort((a, b) => b.time - a.time || b.recordId - a.recordId);
    if (c.has('Newest')) ev = ev.slice(0, toNum(c.p.Newest) ?? 0);
    if (!ev.length) c.error('No matches found', { category: 'ObjectNotFound', target: '', exception: 'ArgumentException', id: 'GetEventLogNoEntriesFound' });
    return ev.map((e) => obj('System.Diagnostics.EventLogEntry', { Index: e.recordId, TimeGenerated: date(e.time), EntryType: e.level, Source: e.provider, InstanceID: e.id, Message: e.message }));
  },
});

// ---------------------------------------------------------------------------
// Local users and groups
// ---------------------------------------------------------------------------

export const GROUPS: Record<string, string> = {
  Administrators: 'Administrators have complete and unrestricted access to the computer/domain',
  'Backup Operators': 'Backup Operators can override security restrictions for the sole purpose of backing up or restoring files',
  Guests: 'Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted',
  'Remote Desktop Users': 'Members in this group are granted the right to logon remotely',
  'Remote Management Users': 'Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.',
  Users: 'Users are prevented from making accidental or intentional system-wide changes and can run most applications',
};

export function userDisabled(host: Host, name: string): boolean {
  const u = host.users[name];
  return !u || u.name === 'Guest' || (host.win!.registry['__disabled'] ?? {})[name.toLowerCase()] === 1;
}

export function setDisabled(host: Host, name: string, disabled: boolean): void {
  const r = (host.win!.registry['__disabled'] ??= {});
  if (disabled) r[name.toLowerCase()] = 1;
  else delete r[name.toLowerCase()];
}

function userObj(host: Host, name: string): PSObject {
  const u = host.users[name];
  return obj('Microsoft.PowerShell.Commands.LocalUser', { Name: u.name, Enabled: !userDisabled(host, u.name), Description: u.gecos, FullName: u.name === 'alice' ? 'Alice Admin' : '', SID: `S-1-5-21-3623811015-3361044348-30300820-${u.uid}`, PrincipalSource: 'Local', ObjectClass: 'User', PasswordRequired: true, __str: u.name });
}

function findUser(c: Call, name: string): string | undefined {
  const k = Object.keys(c.ctx.host.users).find((x) => x.toLowerCase() === name.replace(/^.*\\/, '').toLowerCase());
  if (!k) c.error(`User ${name} was not found.`, { category: 'ObjectNotFound', target: name, exception: 'UserNotFoundException', id: 'UserNotFound' });
  return k;
}

function needAdmin(c: Call): boolean {
  if (isAdmin(c)) return false;
  c.error('Access denied.', { category: 'PermissionDenied', target: '', exception: 'AccessDeniedException', id: 'AccessDenied' });
  return true;
}

function plain(v: PSValue): string | null {
  if (isObj(v) && v.__t === 'System.Security.SecureString') return toStr((v as unknown as { plain: string }).plain);
  return null;
}

export function complexEnough(pw: string, user: string): boolean {
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  return pw.length >= 7 && classes >= 3 && !pw.toLowerCase().includes(user.toLowerCase());
}

function localCmdlet(name: string, synopsis: string, params: { name: string; aliases?: string[]; type?: 'switch' | 'string' | 'strings' | 'any'; position?: number }[], run: (c: Call) => PSValue[] | void): void {
  cmdlet({ name, module: ACCOUNTS, synopsis, params, run, cls: `Microsoft.PowerShell.Commands.${name.replace('-', '')}Command` });
}

localCmdlet('Get-LocalUser', 'Gets local user accounts.', [{ name: 'Name', type: 'strings', position: 0 }], (c) => {
  const names = Object.keys(c.ctx.host.users).sort();
  if (!c.has('Name')) return names.map((n) => userObj(c.ctx.host, n));
  const out: PSValue[] = [];
  for (const n of c.strs('Name')!) {
    const hit = names.filter((x) => wildcard(n).test(x));
    if (!hit.length && !hasWildcard(n)) c.error(`User ${n} was not found.`, { category: 'ObjectNotFound', target: n, exception: 'UserNotFoundException', id: 'UserNotFound' });
    out.push(...hit.map((x) => userObj(c.ctx.host, x)));
  }
  return out;
});

localCmdlet('New-LocalUser', 'Creates a local user account.', [{ name: 'Name', type: 'string', position: 0 }, { name: 'Password', type: 'any' }, { name: 'NoPassword', type: 'switch' }, { name: 'FullName', type: 'string' }, { name: 'Description', type: 'string' }, { name: 'AccountNeverExpires', type: 'switch' }, { name: 'PasswordNeverExpires', type: 'switch' }], (c) => {
  if (needAdmin(c)) return [];
  const name = c.str('Name') ?? '';
  if (Object.keys(c.ctx.host.users).some((x) => x.toLowerCase() === name.toLowerCase())) { c.error(`User ${name} already exists.`, { category: 'ResourceExists', target: name, exception: 'UserExistsException', id: 'UserExists' }); return []; }
  let pw: string | null = null;
  if (c.has('Password')) {
    pw = plain(c.p.Password);
    if (pw === null) { c.error(`Cannot bind parameter 'Password'. Cannot convert the "${toStr(c.p.Password)}" value of type "System.String" to type "System.Security.SecureString".`, { category: 'InvalidArgument', target: '', exception: 'ParameterBindingException', id: 'CannotConvertArgumentNoMessage' }); return []; }
    if (!complexEnough(pw, name)) { c.error('Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.', { category: 'InvalidOperation', target: '', exception: 'InvalidPasswordException', id: 'InvalidPassword' }); return []; }
  } else if (!c.has('NoPassword')) {
    pw = c.ctx.ask('Password: ', true);
  }
  if (c.whatIf('New-LocalUser', name)) return [];
  const uid = 1000 + Object.keys(c.ctx.host.users).length + 1;
  c.ctx.host.users[name] = { name, uid, gid: 513, primaryGroup: 'Users', groups: ['Users'], home: `C:\\Users\\${name}`, shell: 'powershell.exe', gecos: c.str('Description') ?? '', password: pw };
  winEvent(c.ctx.world, c.ctx.host, 'Security', 4720, 'Microsoft-Windows-Security-Auditing', `A user account was created.\n\nNew Account:\n\tAccount Name:\t\t${name}`);
  return [userObj(c.ctx.host, name)];
});

localCmdlet('Set-LocalUser', 'Modifies a local user account.', [{ name: 'Name', type: 'string', position: 0 }, { name: 'Password', type: 'any' }, { name: 'Description', type: 'string' }, { name: 'FullName', type: 'string' }, { name: 'InputObject', type: 'any' }], (c) => {
  if (needAdmin(c)) return;
  const k = findUser(c, c.str('Name') ?? toStr(getProp(c.input[0], 'Name')));
  if (!k) return;
  const u = c.ctx.host.users[k];
  if (c.has('Password')) {
    const pw = plain(c.p.Password);
    if (pw === null || !complexEnough(pw, k)) { c.error('Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.', { category: 'InvalidOperation', target: '', exception: 'InvalidPasswordException', id: 'InvalidPassword' }); return; }
    u.password = pw;
    winEvent(c.ctx.world, c.ctx.host, 'Security', 4724, 'Microsoft-Windows-Security-Auditing', `An attempt was made to reset an account's password.\n\nTarget Account:\n\tAccount Name:\t\t${k}`);
  }
  if (c.has('Description')) u.gecos = c.str('Description')!;
});

for (const [verb, dis] of [['Enable', false], ['Disable', true]] as const) {
  localCmdlet(`${verb}-LocalUser`, `${verb}s a local user account.`, [{ name: 'Name', type: 'strings', position: 0 }, { name: 'InputObject', type: 'any' }], (c) => {
    if (needAdmin(c)) return;
    for (const n of c.strs('Name') ?? c.input.map((i) => toStr(getProp(i, 'Name')))) {
      const k = findUser(c, n);
      if (!k || c.whatIf(`${verb}-LocalUser`, k)) continue;
      setDisabled(c.ctx.host, k, dis);
      winEvent(c.ctx.world, c.ctx.host, 'Security', dis ? 4725 : 4722, 'Microsoft-Windows-Security-Auditing', `A user account was ${dis ? 'disabled' : 'enabled'}.\n\nTarget Account:\n\tAccount Name:\t\t${k}`);
    }
  });
}

localCmdlet('Remove-LocalUser', 'Deletes local user accounts.', [{ name: 'Name', type: 'strings', position: 0 }, { name: 'InputObject', type: 'any' }], (c) => {
  if (needAdmin(c)) return;
  for (const n of c.strs('Name') ?? c.input.map((i) => toStr(getProp(i, 'Name')))) {
    const k = findUser(c, n);
    if (!k || c.whatIf('Remove-LocalUser', k)) continue;
    if (k === 'Administrator') { c.error('Cannot perform this operation on built-in accounts.', { category: 'InvalidOperation', target: k, exception: 'InvalidOperationException', id: 'InvalidOperation' }); continue; }
    delete c.ctx.host.users[k];
    winEvent(c.ctx.world, c.ctx.host, 'Security', 4726, 'Microsoft-Windows-Security-Auditing', `A user account was deleted.\n\nTarget Account:\n\tAccount Name:\t\t${k}`);
  }
});

function findGroup(c: Call, name: string): string | undefined {
  const g = Object.keys(GROUPS).find((x) => x.toLowerCase() === name.replace(/^.*\\/, '').toLowerCase());
  if (!g) c.error(`Group ${name} was not found.`, { category: 'ObjectNotFound', target: name, exception: 'GroupNotFoundException', id: 'GroupNotFound' });
  return g;
}

localCmdlet('Get-LocalGroup', 'Gets the local security groups.', [{ name: 'Name', type: 'strings', position: 0 }], (c) => {
  const names = Object.keys(GROUPS).filter((g) => !c.has('Name') || c.strs('Name')!.some((n) => wildcard(n).test(g)));
  if (c.has('Name') && !names.length && !c.strs('Name')!.some(hasWildcard)) c.error(`Group ${c.str('Name')} was not found.`, { category: 'ObjectNotFound', target: c.str('Name'), exception: 'GroupNotFoundException', id: 'GroupNotFound' });
  return names.map((g) => obj('Microsoft.PowerShell.Commands.LocalGroup', { Name: g, Description: GROUPS[g], __str: g }));
});

localCmdlet('Get-LocalGroupMember', 'Gets members from a local group.', [{ name: 'Group', aliases: ['Name'], type: 'string', position: 0 }, { name: 'Member', type: 'strings', position: 1 }], (c) => {
  const g = findGroup(c, c.str('Group') ?? '');
  if (!g) return [];
  const host = c.ctx.host;
  const members = Object.values(host.users).filter((u) => u.groups.includes(g) && !(g === 'Users' && u.name === 'Guest'));
  return members.map((u) => obj('Microsoft.PowerShell.Commands.LocalPrincipal', { ObjectClass: 'User', Name: `${host.hostname.toUpperCase()}\\${u.name}`, PrincipalSource: 'Local', SID: `S-1-5-21-3623811015-3361044348-30300820-${u.uid}` }));
});

for (const [verb, add] of [['Add', true], ['Remove', false]] as const) {
  localCmdlet(`${verb}-LocalGroupMember`, `${add ? 'Adds members to' : 'Removes members from'} a local group.`, [{ name: 'Group', aliases: ['Name'], type: 'string', position: 0 }, { name: 'Member', type: 'strings', position: 1 }], (c) => {
    if (needAdmin(c)) return;
    const g = findGroup(c, c.str('Group') ?? '');
    if (!g) return;
    for (const m of c.strs('Member') ?? []) {
      const k = Object.keys(c.ctx.host.users).find((x) => x.toLowerCase() === m.replace(/^.*\\/, '').toLowerCase());
      if (!k) { c.error(`Principal ${m} was not found.`, { category: 'ObjectNotFound', target: m, exception: 'PrincipalNotFoundException', id: 'PrincipalNotFound' }); continue; }
      const u = c.ctx.host.users[k];
      const qualified = `${c.ctx.host.hostname.toUpperCase()}\\${k}`;
      if (add && u.groups.includes(g)) { c.error(`${qualified} is already a member of group ${g}.`, { category: 'ResourceExists', target: g, exception: 'MemberExistsException', id: 'MemberExists' }); continue; }
      if (!add && !u.groups.includes(g)) { c.error(`Member ${qualified} was not found in group ${g}.`, { category: 'ObjectNotFound', target: k, exception: 'MemberNotFoundException', id: 'MemberNotFound' }); continue; }
      if (c.whatIf(`${verb}-LocalGroupMember`, `${qualified} to group ${g}`)) continue;
      u.groups = add ? [...u.groups, g] : u.groups.filter((x) => x !== g);
      winEvent(c.ctx.world, c.ctx.host, 'Security', add ? 4732 : 4733, 'Microsoft-Windows-Security-Auditing', `A member was ${add ? 'added to' : 'removed from'} a security-enabled local group.\n\nMember:\n\tAccount Name:\t\t${qualified}\n\nGroup:\n\tGroup Name:\t\t${g}`);
    }
  });
}

// ---------------------------------------------------------------------------
// Computer
// ---------------------------------------------------------------------------

cmdlet({
  name: 'Get-ComputerInfo', module: MGMT, synopsis: 'Gets a consolidated object of system and operating system properties.',
  params: [{ name: 'Property', type: 'strings', position: 0 }],
  run(c) {
    const h = c.ctx.host;
    const w = h.win!;
    const all: Record<string, PSValue> = {
      WindowsBuildLabEx: `${w.build}.1.amd64fre.fe_release.210507-1500`, WindowsCurrentVersion: '6.3', WindowsEditionId: 'ServerStandard', WindowsInstallationType: 'Server', WindowsProductName: w.productName, WindowsVersion: '2009',
      CsName: h.hostname.toUpperCase(), CsDomain: w.workgroup, CsPartOfDomain: false, CsWorkgroup: w.workgroup, CsManufacturer: 'Microsoft Corporation', CsModel: 'Virtual Machine', CsNumberOfLogicalProcessors: 2, CsTotalPhysicalMemory: 4294430720,
      OsName: `Microsoft ${w.productName}`, OsVersion: `10.0.${w.build}`, OsBuildNumber: w.build, OsLastBootUpTime: date(h.bootTime), OsUptime: `${Math.floor((c.ctx.world.clock - h.bootTime) / 86400000)}.${new Date(c.ctx.world.clock - h.bootTime).toISOString().slice(11, 19)}`, TimeZone: '(UTC) Coordinated Universal Time', LogonServer: `\\\\${h.hostname.toUpperCase()}`, PowerPlatformRole: 'Desktop',
    };
    const props = c.strs('Property');
    const keys = props ? Object.keys(all).filter((k) => props.some((p) => wildcard(p).test(k))) : Object.keys(all);
    return [obj('Microsoft.PowerShell.Commands.ComputerInfo', Object.fromEntries(keys.map((k) => [k, all[k]])))];
  },
});

cmdlet({
  name: 'Get-CimInstance', module: 'CimCmdlets', synopsis: 'Gets the CIM instances of a class from a CIM server.',
  params: [{ name: 'ClassName', aliases: ['Class'], type: 'string', position: 0 }, { name: 'Filter', type: 'string' }],
  run(c) {
    const cls = (c.str('ClassName') ?? '').toLowerCase();
    const h = c.ctx.host;
    if (cls === 'win32_operatingsystem') return [obj('Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_OperatingSystem', { SystemDirectory: 'C:\\Windows\\system32', Organization: '', BuildNumber: h.win!.build, RegisteredUser: 'Windows User', SerialNumber: '00454-60000-00001-AA712', Version: `10.0.${h.win!.build}`, Caption: `Microsoft ${h.win!.productName}`, CSName: h.hostname.toUpperCase(), LastBootUpTime: date(h.bootTime) })];
    if (cls === 'win32_computersystem') return [obj('Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_ComputerSystem', { Name: h.hostname.toUpperCase(), PrimaryOwnerName: 'Windows User', Domain: h.win!.workgroup, TotalPhysicalMemory: 4294430720, Model: 'Virtual Machine', Manufacturer: 'Microsoft Corporation' })];
    if (cls === 'win32_service') return Object.values(h.win!.services).map((s) => obj('Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Service', { ProcessId: s.pid ?? 0, Name: s.name, StartMode: s.startType === 'Automatic' || s.startType === 'AutomaticDelayedStart' ? 'Auto' : s.startType === 'Manual' ? 'Manual' : 'Disabled', State: s.status, Status: 'OK', ExitCode: 0, PathName: s.process === 'svchost' ? `C:\\Windows\\system32\\svchost.exe -k netsvcs -p` : `C:\\Windows\\system32\\${s.process}.exe`, StartName: 'LocalSystem' }));
    c.error(`Invalid class `, { category: 'MetadataError', target: `root\\cimv2:${c.str('ClassName')}`, exception: 'CimException', id: 'HRESULT 0x80041010' });
    return [];
  },
});

cmdlet({
  name: 'Restart-Computer', module: MGMT, synopsis: 'Restarts the operating system on local and remote computers.',
  params: [{ name: 'Force', type: 'switch' }, { name: 'ComputerName', type: 'strings' }],
  run(c) {
    if (!isAdmin(c)) { c.error('Privilege not held.', { category: 'OperationStopped', target: c.ctx.host.hostname, exception: 'InvalidOperationException', id: 'RestartcomputerFailed' }); return; }
    if (c.whatIf('Restart-Computer', c.ctx.host.hostname.toUpperCase())) return;
    winEvent(c.ctx.world, c.ctx.host, 'System', 1074, 'User32', `The process C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe (${c.ctx.host.hostname.toUpperCase()}) has initiated the restart of computer ${c.ctx.host.hostname.toUpperCase()} on behalf of user ${c.ctx.host.hostname.toUpperCase()}\\${c.ctx.user.name} for the following reason: No title for this reason could be found`);
    c.ctx.reboot = true;
  },
});

cmdlet({ name: 'Get-TimeZone', module: MGMT, synopsis: 'Gets the current time zone or a list of available time zones.', params: [], run: () => [obj('System.TimeZoneInfo', { Id: 'UTC', DisplayName: '(UTC) Coordinated Universal Time', StandardName: 'Coordinated Universal Time', DaylightName: 'Coordinated Universal Time', BaseUtcOffset: '00:00:00', SupportsDaylightSavingTime: false })] });

cmdlet({
  name: 'Get-HotFix', module: MGMT, synopsis: 'Gets the hotfixes that are installed on local or remote computers.', params: [{ name: 'Id', type: 'strings', position: 0 }],
  run: (c) => [['KB5041948', 'Update', '9/11/2026'], ['KB5042881', 'Security Update', '10/14/2026']].filter(([k]) => !c.has('Id') || c.strs('Id')!.includes(k)).map(([k, d, t]) => obj('System.Management.ManagementObject#root\\cimv2\\Win32_QuickFixEngineering', { Source: c.ctx.host.hostname.toUpperCase(), Description: d, HotFixID: k, InstalledBy: 'NT AUTHORITY\\SYSTEM', InstalledOn: date(Date.parse(t)) })),
});
registerView('System.Management.ManagementObject#root\\cimv2\\Win32_QuickFixEngineering', { kind: 'table', columns: [{ label: 'Source', value: 'Source', width: 13 }, { label: 'Description', value: 'Description', width: 16 }, { label: 'HotFixID', value: 'HotFixID', width: 13 }, { label: 'InstalledBy', value: 'InstalledBy', width: 20 }, { label: 'InstalledOn', value: (o) => toStr(o.InstalledOn).split(' ')[0] }] });
