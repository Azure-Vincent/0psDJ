// FileSystem and Registry providers: Windows paths (case-insensitive, "\" or
// "/", ~, .., drive-relative), directory listings in PowerShell's format, file
// content cmdlets, and the registry values the lab uses (RDP settings).

import { mkdir, writeFile } from '../../../fs';
import type { Host, World } from '../../../types';
import { startWinService, TS_KEY, winEvent } from '../../model';
import { formatOutput, registerView } from '../format';
import { cmdlet, type Call, type PsCtx } from '../runtime';
import { date, flatten, hasWildcard, obj, toNum, toStr, wildcard, type PSObject, type PSValue } from '../values';
import { setReadLines } from './core';

const MGMT = 'Microsoft.PowerShell.Management';

function lastWrite(o: PSObject): string {
  const d = new Date((o.LastWriteTime as { ms: number }).ms);
  const h = d.getUTCHours();
  const t = `${h % 12 === 0 ? 12 : h % 12}:${String(d.getUTCMinutes()).padStart(2, '0')} ${h < 12 ? 'AM' : 'PM'}`;
  return `${`${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()}`.padStart(10)} ${t.padStart(8)}`;
}

const FS_COLUMNS = [
  { label: 'Mode', value: 'Mode', width: 13 },
  { label: 'LastWriteTime', value: lastWrite, width: 20, align: 'right' as const },
  { label: 'Length', value: (o: PSObject) => (o.PSIsContainer ? '' : o.Length), width: 14, align: 'right' as const },
  { label: 'Name', value: 'Name' },
];
registerView('System.IO.DirectoryInfo', { kind: 'table', columns: FS_COLUMNS, groupBy: { prop: '__dir', label: 'Directory' } });
registerView('System.IO.FileInfo', { kind: 'table', columns: FS_COLUMNS, groupBy: { prop: '__dir', label: 'Directory' } });
registerView('System.Management.Automation.PathInfo', { kind: 'table', columns: [{ label: 'Path', value: 'Path' }] });

export function isAdmin(c: { ctx: PsCtx }): boolean {
  return c.ctx.user.uid === 500 || c.ctx.user.groups.includes('Administrators');
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** Canonical absolute path ("C:\Users\x"), without checking existence. */
export function absPath(ctx: PsCtx, p: string): string {
  let s = p.replace(/\//g, '\\').replace(/^Microsoft\.PowerShell\.Core\\FileSystem::/i, '');
  if (s === '~' || s.startsWith('~\\')) s = ctx.user.home + s.slice(1);
  if (/^[a-z]:$/i.test(s)) s += '\\';
  if (s.startsWith('\\')) s = ctx.session.cwd.slice(0, 2) + s;
  else if (!/^[a-z]:\\/i.test(s)) s = `${ctx.session.cwd.replace(/\\$/, '')}\\${s}`;
  const drive = s.slice(0, 2).toUpperCase();
  const parts: string[] = [];
  for (const seg of s.slice(3).split('\\')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return `${drive}\\${parts.join('\\')}`;
}

/** The stored key for a path, matched case-insensitively. */
export function findKey(host: Host, p: string): string | undefined {
  if (host.fs[p]) return p;
  const lp = p.toLowerCase();
  return Object.keys(host.fs).find((k) => k.toLowerCase() === lp);
}

function parentOf(p: string): string {
  const i = p.lastIndexOf('\\');
  return i <= 2 ? p.slice(0, 3) : p.slice(0, i);
}

function children(host: Host, dir: string): string[] {
  const prefix = dir.endsWith('\\') ? dir : dir + '\\';
  const lp = prefix.toLowerCase();
  return Object.keys(host.fs).filter((k) => k.toLowerCase().startsWith(lp) && k.length > prefix.length && !k.slice(prefix.length).includes('\\')).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
}

function itemObj(host: Host, key: string): PSObject {
  const n = host.fs[key];
  const name = key.length <= 3 ? key : key.slice(key.lastIndexOf('\\') + 1);
  const dir = n.type === 'dir';
  const special = /\\Users\\[^\\]+\\(Desktop|Documents|Downloads)$/i.test(key);
  return obj(dir ? 'System.IO.DirectoryInfo' : 'System.IO.FileInfo', {
    Mode: dir ? (special ? 'd-r---' : 'd-----') : '-a----',
    LastWriteTime: date(n.mtime),
    Length: dir ? null : n.size ?? n.content.length,
    Name: name,
    FullName: key,
    Extension: dir ? '' : /\.[^.\\]+$/.exec(name)?.[0] ?? '',
    PSIsContainer: dir,
    __dir: parentOf(key),
    __str: name,
  });
}

function notFound(c: Call, p: string, id = 'PathNotFound'): void {
  c.error(`Cannot find path '${p}' because it does not exist.`, { category: 'ObjectNotFound', target: p, exception: 'ItemNotFoundException', id });
}

function denied(c: Call, p: string): void {
  c.error(`Access to the path '${p}' is denied.`, { category: 'PermissionDenied', target: p, exception: 'UnauthorizedAccessException', id: 'UnauthorizedAccessException' });
}

function canWrite(c: Call, p: string): boolean {
  if (isAdmin(c)) return true;
  const lp = p.toLowerCase();
  return [c.ctx.user.home.toLowerCase(), 'c:\\temp', 'c:\\users\\public'].some((d) => lp === d || lp.startsWith(d + '\\'));
}

/** Expand wildcards in the last path component. */
function expand(ctx: PsCtx, p: string): string[] {
  const abs = absPath(ctx, p);
  if (!hasWildcard(abs)) { const k = findKey(ctx.host, abs); return k ? [k] : []; }
  const dir = findKey(ctx.host, parentOf(abs));
  if (!dir) return [];
  const re = wildcard(abs.slice(abs.lastIndexOf('\\') + 1));
  return children(ctx.host, dir).filter((k) => re.test(k.slice(k.lastIndexOf('\\') + 1)));
}

// ---------------------------------------------------------------------------
// Registry (the keys the lab uses)
// ---------------------------------------------------------------------------

export function regKey(p: string): string | null {
  const m = /^(?:Registry::)?(HKLM:|HKEY_LOCAL_MACHINE|HKCU:|HKEY_CURRENT_USER)[\\/]?(.*)$/i.exec(p.trim());
  if (!m) return null;
  const hive = /^HK(LM|EY_LOCAL)/i.test(m[1]) ? 'HKLM:' : 'HKCU:';
  return `${hive}\\${m[2].replace(/\//g, '\\').replace(/\\+$/, '')}`;
}

export function findReg(host: Host, key: string): string | undefined {
  return Object.keys(host.win!.registry).find((k) => k.toLowerCase() === key.toLowerCase());
}

/** Registry keys that exist because they have children with values. */
function regExists(host: Host, key: string): boolean {
  const lk = key.toLowerCase();
  return Object.keys(host.win!.registry).some((k) => k.toLowerCase() === lk || k.toLowerCase().startsWith(lk + '\\'));
}

function regProps(key: string, values: Record<string, PSValue>, only?: string[]): PSObject {
  const leaf = key.slice(key.lastIndexOf('\\') + 1);
  const shown = only ? Object.fromEntries(Object.entries(values).filter(([k]) => only.some((n) => wildcard(n).test(k)))) : values;
  const full = key.replace(/^HKLM:/, 'HKEY_LOCAL_MACHINE').replace(/^HKCU:/, 'HKEY_CURRENT_USER');
  return obj('System.Management.Automation.PSCustomObject', { ...shown, PSPath: `Microsoft.PowerShell.Core\\Registry::${full}`, PSParentPath: `Microsoft.PowerShell.Core\\Registry::${full.slice(0, full.lastIndexOf('\\'))}`, PSChildName: leaf, PSDrive: key.slice(0, 4), PSProvider: 'Microsoft.PowerShell.Core\\Registry' });
}

/** Side effects of registry values (TermService watches its keys). */
function regChanged(c: { ctx: PsCtx }, key: string, name: string): void {
  regValueChanged(c.ctx.world, c.ctx.host, key, name);
}

/** Side effects of a registry value change, whichever tool made it (Set-ItemProperty, reg add, reg import). */
export function regValueChanged(world: World, host: Host, key: string, name: string): void {
  const c = { ctx: { world, host } };
  const w = host.win!;
  if (key.toLowerCase() === TS_KEY.toLowerCase() && name.toLowerCase() === 'fdenytsconnections') {
    // TermService watches this value: the RDP listener opens or closes at once.
    winEvent(c.ctx.world, host, 'System', 1056, 'TermService', `Remote Desktop connections are now ${Number(w.registry[key][name]) === 0 ? 'allowed' : 'denied'} (fDenyTSConnections = ${w.registry[key][name]}).`);
    if (w.services.TermService?.status !== 'Running') startWinService(c.ctx.world, host, 'TermService');
  }
}

// ---------------------------------------------------------------------------
// Cmdlets
// ---------------------------------------------------------------------------

function envItems(c: Call, filter?: string): PSObject[] {
  const names = ['ALLUSERSPROFILE', 'COMPUTERNAME', 'OS', 'Path', 'PROCESSOR_ARCHITECTURE', 'ProgramData', 'ProgramFiles', 'PUBLIC', 'SystemDrive', 'SystemRoot', 'TEMP', 'USERDOMAIN', 'USERNAME', 'USERPROFILE', 'windir'];
  const val = (n: string) => toStr(n === 'ALLUSERSPROFILE' ? 'C:\\ProgramData' : (c.ctx.session.vars[`env:${n.toLowerCase()}`] ?? envLookup(c, n)));
  return names.filter((n) => !filter || wildcard(filter).test(n)).map((n) => obj('System.Collections.DictionaryEntry', { Name: n, Value: val(n) }));
}

function envLookup(c: Call, n: string): string {
  const h = c.ctx.host;
  const u = c.ctx.user;
  const m: Record<string, string> = { COMPUTERNAME: h.hostname.toUpperCase(), OS: 'Windows_NT', Path: 'C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\', PROCESSOR_ARCHITECTURE: 'AMD64', ProgramData: 'C:\\ProgramData', ProgramFiles: 'C:\\Program Files', PUBLIC: 'C:\\Users\\Public', SystemDrive: 'C:', SystemRoot: 'C:\\Windows', TEMP: `${u.home}\\AppData\\Local\\Temp`, USERDOMAIN: h.hostname.toUpperCase(), USERNAME: u.name, USERPROFILE: u.home, windir: 'C:\\Windows' };
  return m[n] ?? '';
}

cmdlet({
  name: 'Get-ChildItem', module: MGMT, synopsis: 'Gets the items and child items in one or more specified locations.',
  params: [{ name: 'Path', aliases: ['LiteralPath'], type: 'strings', position: 0 }, { name: 'Filter', type: 'string', position: 1 }, { name: 'Recurse', aliases: ['s'], type: 'switch' }, { name: 'File', type: 'switch' }, { name: 'Directory', aliases: ['ad'], type: 'switch' }, { name: 'Force', type: 'switch' }, { name: 'Name', type: 'switch' }, { name: 'Include', type: 'strings' }, { name: 'Depth', type: 'int' }],
  run(c) {
    const host = c.ctx.host;
    const paths = c.strs('Path') ?? [c.ctx.session.cwd];
    const out: PSValue[] = [];
    for (const p of paths) {
      if (/^env:\\?/i.test(p)) { out.push(...envItems(c, p.replace(/^env:\\?/i, '') || undefined)); continue; }
      const keys = expand(c.ctx, p);
      if (!keys.length) { notFound(c, absPath(c.ctx, p)); continue; }
      const walk = (dir: string, depth: number) => {
        for (const k of children(host, dir)) {
          const it = itemObj(host, k);
          const okType = (!c.has('File') || !it.PSIsContainer) && (!c.has('Directory') || it.PSIsContainer);
          const name = String(it.Name);
          const okName = (!c.has('Filter') || wildcard(c.str('Filter')!).test(name)) && (!c.has('Include') || c.strs('Include')!.some((i) => wildcard(i).test(name)));
          if (okType && okName) out.push(c.has('Name') ? (c.has('Recurse') ? k.slice(dir.length + 1) : name) : it);
          if (c.has('Recurse') && it.PSIsContainer && (!c.has('Depth') || depth < (toNum(c.p.Depth) ?? 0))) walk(k, depth + 1);
        }
      };
      for (const k of keys) {
        if (host.fs[k].type === 'dir') walk(k, 0);
        else out.push(c.has('Name') ? String(itemObj(host, k).Name) : itemObj(host, k));
      }
    }
    return out;
  },
});

cmdlet({
  name: 'Get-Item', module: MGMT, synopsis: 'Gets the item at the specified location.',
  params: [{ name: 'Path', aliases: ['LiteralPath'], type: 'strings', position: 0 }, { name: 'Force', type: 'switch' }],
  run(c) {
    const out: PSValue[] = [];
    for (const p of c.strs('Path') ?? ['.']) {
      const keys = expand(c.ctx, p);
      if (!keys.length) notFound(c, absPath(c.ctx, p));
      out.push(...keys.map((k) => itemObj(c.ctx.host, k)));
    }
    return out;
  },
});

function contentOf(c: Call, p: string): { key: string; text: string } | null {
  const key = findKey(c.ctx.host, absPath(c.ctx, p));
  if (!key) { notFound(c, absPath(c.ctx, p)); return null; }
  const n = c.ctx.host.fs[key];
  if (n.type === 'dir') {
    c.error(`Unable to get content because it is a directory: '${key}'. Please use 'Get-ChildItem' instead.`, { category: 'ObjectNotFound', target: key, exception: 'ItemNotFoundException', id: 'GetContentReaderUnauthorizedAccessError' });
    return null;
  }
  return { key, text: n.content };
}

function lines(t: string): string[] {
  const l = t.replace(/\r\n/g, '\n').split('\n');
  if (l.length && l[l.length - 1] === '') l.pop();
  return l;
}

setReadLines((c, paths) => paths.flatMap((p) => expand(c.ctx, p).filter((k) => c.ctx.host.fs[k].type === 'file').map((k) => ({ path: k, lines: lines(c.ctx.host.fs[k].content) }))));

cmdlet({
  name: 'Get-Content', module: MGMT, synopsis: 'Gets the content of the item at the specified location.',
  params: [{ name: 'Path', aliases: ['LiteralPath', 'FullName'], type: 'strings', position: 0 }, { name: 'Tail', aliases: ['Last'], type: 'int' }, { name: 'TotalCount', aliases: ['Head', 'First'], type: 'int' }, { name: 'Raw', type: 'switch' }, { name: 'Wait', type: 'switch' }, { name: 'Encoding', type: 'string' }],
  run(c) {
    const out: PSValue[] = [];
    for (const p of c.strs('Path') ?? []) {
      for (const k of hasWildcard(p) ? expand(c.ctx, p) : [p]) {
        const r = contentOf(c, k);
        if (!r) continue;
        if (c.has('Raw')) { out.push(r.text); continue; }
        let l = lines(r.text);
        if (c.has('TotalCount')) l = l.slice(0, toNum(c.p.TotalCount) ?? 0);
        if (c.has('Tail')) l = l.slice(-(toNum(c.p.Tail) ?? 0) || l.length);
        out.push(...l);
      }
    }
    return out;
  },
});

function writeContent(c: Call, append: boolean): PSValue[] {
  const value = c.has('Value') ? flatten(c.p.Value) : c.input;
  const data = value.map(toStr).join('\r\n') + '\r\n';
  for (const p of c.strs('Path') ?? []) {
    const abs = absPath(c.ctx, p);
    const key = findKey(c.ctx.host, abs) ?? abs;
    const parent = findKey(c.ctx.host, parentOf(abs));
    if (!parent) { c.error(`Could not find a part of the path '${abs}'.`, { category: 'ObjectNotFound', target: abs, exception: 'DirectoryNotFoundException', id: 'GetContentWriterDirectoryNotFoundError' }); continue; }
    if (!canWrite(c, key)) { denied(c, key); continue; }
    if (c.whatIf(append ? 'Add Content' : 'Set Content', `Path: ${key}`)) continue;
    const existing = c.ctx.host.fs[key];
    if (existing?.type === 'dir') { denied(c, key); continue; }
    writeFile(c.ctx.host, key, append && existing ? existing.content + data : data, c.ctx.world.clock, { owner: c.ctx.user.name, group: c.ctx.user.name });
  }
  return [];
}

cmdlet({ name: 'Set-Content', module: MGMT, synopsis: 'Writes new content or replaces existing content in a file.', params: [{ name: 'Path', type: 'strings', position: 0 }, { name: 'Value', type: 'any', position: 1 }, { name: 'Encoding', type: 'string' }, { name: 'Force', type: 'switch' }, { name: 'NoNewline', type: 'switch' }], run: (c) => writeContent(c, false) });
cmdlet({ name: 'Add-Content', module: MGMT, synopsis: 'Adds content to the specified items, such as adding words to a file.', params: [{ name: 'Path', type: 'strings', position: 0 }, { name: 'Value', type: 'any', position: 1 }, { name: 'Encoding', type: 'string' }, { name: 'Force', type: 'switch' }], run: (c) => writeContent(c, true) });

cmdlet({
  name: 'Out-File', module: 'Microsoft.PowerShell.Utility', synopsis: 'Sends output to a file.',
  params: [{ name: 'FilePath', aliases: ['Path'], type: 'string', position: 0, mandatory: true }, { name: 'Append', type: 'switch' }, { name: 'Encoding', type: 'string', position: 1 }, { name: 'InputObject', type: 'any' }, { name: 'Force', type: 'switch' }, { name: 'Width', type: 'int' }],
  run(c) {
    const items = c.has('InputObject') ? flatten(c.p.InputObject) : c.input;
    // Out-File writes what the console would show.
    const call = { ...c, p: { ...c.p, Path: c.p.FilePath, Value: formatOutput(items).split('\n') }, has: (n: string) => n === 'Value' || n === 'Path' || c.has(n), strs: (n: string) => (n === 'Path' ? [c.str('FilePath')!] : c.strs(n)) } as Call;
    return writeContent(call, c.has('Append'));
  },
});

cmdlet({
  name: 'New-Item', module: MGMT, synopsis: 'Creates a new item.',
  params: [{ name: 'Path', type: 'strings', position: 0 }, { name: 'Name', type: 'string' }, { name: 'ItemType', aliases: ['Type'], type: 'string' }, { name: 'Value', type: 'any' }, { name: 'Force', type: 'switch' }],
  run(c) {
    const out: PSValue[] = [];
    for (const p0 of c.strs('Path') ?? ['.']) {
      const p = c.has('Name') ? `${p0}\\${c.str('Name')}` : p0;
      const rk = regKey(p);
      if (rk) {
        if (!c.ctx.host.win!.registry[rk]) c.ctx.host.win!.registry[rk] = {};
        continue;
      }
      const abs = absPath(c.ctx, p);
      const type = (c.str('ItemType') ?? 'File').toLowerCase();
      const exists = findKey(c.ctx.host, abs);
      if (exists && !c.has('Force')) { c.error(`An item with the specified name ${abs} already exists.`, { category: 'ResourceExists', target: abs, exception: 'IOException', id: 'NewItemIOError' }); continue; }
      if (!findKey(c.ctx.host, parentOf(abs))) {
        if (!c.has('Force')) { c.error(`Could not find a part of the path '${abs}'.`, { category: 'WriteError', target: abs, exception: 'DirectoryNotFoundException', id: 'NewItemIOError' }); continue; }
        const parts = abs.split('\\');
        for (let i = 2; i < parts.length; i++) { const d = parts.slice(0, i).join('\\'); if (!findKey(c.ctx.host, d)) mkdir(c.ctx.host, d, c.ctx.world.clock); }
      }
      if (!canWrite(c, abs)) { denied(c, abs); continue; }
      if (c.whatIf(type.startsWith('dir') ? 'Create Directory' : 'Create File', `Destination: ${abs}`)) continue;
      if (type.startsWith('dir')) mkdir(c.ctx.host, abs, c.ctx.world.clock, { owner: c.ctx.user.name, group: c.ctx.user.name });
      else writeFile(c.ctx.host, abs, c.has('Value') ? toStr(c.p.Value) : '', c.ctx.world.clock, { owner: c.ctx.user.name, group: c.ctx.user.name });
      out.push(itemObj(c.ctx.host, abs));
    }
    return out;
  },
});

cmdlet({
  name: 'mkdir', module: '', synopsis: 'Creates a directory (function wrapping New-Item -ItemType Directory).',
  params: [{ name: 'Path', type: 'strings', position: 0 }, { name: 'Force', type: 'switch' }],
  run(c) {
    const out: PSValue[] = [];
    for (const p of c.strs('Path') ?? []) {
      const abs = absPath(c.ctx, p);
      if (findKey(c.ctx.host, abs)) { c.error(`An item with the specified name ${abs} already exists.`, { category: 'ResourceExists', target: abs, exception: 'IOException', id: 'DirectoryExist,Microsoft.PowerShell.Commands.NewItemCommand' }); continue; }
      if (!canWrite(c, abs)) { denied(c, abs); continue; }
      const parts = abs.split('\\');
      for (let i = 2; i <= parts.length; i++) { const d = parts.slice(0, i).join('\\'); if (!findKey(c.ctx.host, d)) mkdir(c.ctx.host, d, c.ctx.world.clock, { owner: c.ctx.user.name, group: c.ctx.user.name }); }
      out.push(itemObj(c.ctx.host, abs));
    }
    return out;
  },
});

cmdlet({
  name: 'Remove-Item', module: MGMT, synopsis: 'Deletes the specified items.',
  params: [{ name: 'Path', aliases: ['LiteralPath'], type: 'strings', position: 0 }, { name: 'Recurse', type: 'switch' }, { name: 'Force', type: 'switch' }],
  run(c) {
    const host = c.ctx.host;
    for (const p of c.strs('Path') ?? []) {
      const keys = expand(c.ctx, p);
      if (!keys.length) { notFound(c, absPath(c.ctx, p)); continue; }
      for (const k of keys) {
        if (!canWrite(c, k) || k.length <= 3) { denied(c, k); continue; }
        if (c.whatIf(host.fs[k].type === 'dir' ? 'Remove Directory' : 'Remove File', k)) continue;
        const kids = children(host, k);
        if (host.fs[k].type === 'dir' && kids.length && !c.has('Recurse')) {
          const a = c.ctx.ask(`\nConfirm\nThe item at ${k} has children and the Recurse parameter was not specified. If you continue, all children will be removed with the item. Are you sure you want to continue?\n[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): `, false);
          if (!/^(y|a|)$/i.test(a.trim())) continue;
        }
        const lk = k.toLowerCase();
        for (const x of Object.keys(host.fs)) if (x.toLowerCase() === lk || x.toLowerCase().startsWith(lk + '\\')) delete host.fs[x];
      }
    }
  },
});

function copyMove(c: Call, move: boolean): void {
  const host = c.ctx.host;
  const destRaw = c.str('Destination');
  if (!destRaw) return;
  for (const p of c.strs('Path') ?? []) {
    const keys = expand(c.ctx, p);
    if (!keys.length) { notFound(c, absPath(c.ctx, p)); continue; }
    for (const k of keys) {
      let dest = absPath(c.ctx, destRaw);
      const dk = findKey(host, dest);
      if (dk && host.fs[dk].type === 'dir') dest = `${dk}\\${k.slice(k.lastIndexOf('\\') + 1)}`;
      if (!findKey(host, parentOf(dest))) { c.error(`Could not find a part of the path '${dest}'.`, { category: 'WriteError', target: dest, exception: 'DirectoryNotFoundException', id: 'CopyItemIOError' }); continue; }
      if (!canWrite(c, dest) || (move && !canWrite(c, k))) { denied(c, dest); continue; }
      const lk = k.toLowerCase();
      for (const x of Object.keys(host.fs)) {
        if (x.toLowerCase() !== lk && !x.toLowerCase().startsWith(lk + '\\')) continue;
        if (host.fs[k].type === 'dir' && x !== k && !c.has('Recurse') && !move) continue;
        host.fs[dest + x.slice(k.length)] = { ...host.fs[x], mtime: move ? host.fs[x].mtime : c.ctx.world.clock };
        if (move) delete host.fs[x];
      }
    }
  }
}

cmdlet({ name: 'Copy-Item', module: MGMT, synopsis: 'Copies an item from one location to another.', params: [{ name: 'Path', type: 'strings', position: 0 }, { name: 'Destination', type: 'string', position: 1 }, { name: 'Recurse', type: 'switch' }, { name: 'Force', type: 'switch' }], run(c) { copyMove(c, false); } });
cmdlet({ name: 'Move-Item', module: MGMT, synopsis: 'Moves an item from one location to another.', params: [{ name: 'Path', type: 'strings', position: 0 }, { name: 'Destination', type: 'string', position: 1 }, { name: 'Force', type: 'switch' }], run(c) { copyMove(c, true); } });

cmdlet({
  name: 'Rename-Item', module: MGMT, synopsis: 'Renames an item in a PowerShell provider namespace.',
  params: [{ name: 'Path', type: 'string', position: 0, mandatory: true }, { name: 'NewName', type: 'string', position: 1, mandatory: true }, { name: 'Force', type: 'switch' }],
  run(c) {
    const k = findKey(c.ctx.host, absPath(c.ctx, c.str('Path') ?? ''));
    if (!k) { notFound(c, absPath(c.ctx, c.str('Path') ?? '')); return; }
    copyMove({ ...c, strs: (n: string) => (n === 'Path' ? [k] : c.strs(n)), str: (n: string) => (n === 'Destination' ? `${parentOf(k)}\\${c.str('NewName')}` : c.str(n)) } as Call, true);
  },
});

cmdlet({
  name: 'Test-Path', module: MGMT, synopsis: 'Determines whether all elements of a path exist.',
  params: [{ name: 'Path', aliases: ['LiteralPath'], type: 'strings', position: 0 }, { name: 'PathType', type: 'string' }],
  run(c) {
    return (c.strs('Path') ?? []).map((p) => {
      const rk = regKey(p);
      if (rk) return regExists(c.ctx.host, rk);
      const keys = expand(c.ctx, p);
      const t = (c.str('PathType') ?? 'Any').toLowerCase();
      return keys.some((k) => t === 'any' || (t === 'container') === (c.ctx.host.fs[k].type === 'dir'));
    });
  },
});

cmdlet({ name: 'Get-Location', module: MGMT, synopsis: 'Gets information about the current working location or a location stack.', params: [], run: (c) => [obj('System.Management.Automation.PathInfo', { Drive: 'C', Provider: 'Microsoft.PowerShell.Core\\FileSystem', ProviderPath: c.ctx.session.cwd, Path: c.ctx.session.cwd, __str: c.ctx.session.cwd })] });

cmdlet({
  name: 'Set-Location', module: MGMT, synopsis: 'Sets the current working location to a specified location.',
  params: [{ name: 'Path', aliases: ['LiteralPath'], type: 'string', position: 0 }, { name: 'PassThru', type: 'switch' }],
  run(c) {
    const p = c.str('Path') ?? '~';
    const k = findKey(c.ctx.host, absPath(c.ctx, p));
    if (!k || c.ctx.host.fs[k].type !== 'dir') { notFound(c, absPath(c.ctx, p)); return; }
    c.ctx.session.cwd = k;
  },
});

cmdlet({
  name: 'Get-ItemProperty', module: MGMT, synopsis: 'Gets the properties of a specified item.',
  params: [{ name: 'Path', type: 'strings', position: 0 }, { name: 'Name', type: 'strings', position: 1 }],
  run(c) {
    const out: PSValue[] = [];
    for (const p of c.strs('Path') ?? ['.']) {
      const rk = regKey(p);
      if (!rk) {
        const k = findKey(c.ctx.host, absPath(c.ctx, p));
        if (!k) notFound(c, absPath(c.ctx, p));
        else out.push(itemObj(c.ctx.host, k));
        continue;
      }
      const key = findReg(c.ctx.host, rk);
      if (!key && !regExists(c.ctx.host, rk)) { notFound(c, rk.replace(/^HKLM:/, 'HKLM:')); continue; }
      const values = key ? c.ctx.host.win!.registry[key] : {};
      const names = c.strs('Name');
      if (names) {
        const missing = names.filter((n) => !hasWildcard(n) && !Object.keys(values).some((k) => k.toLowerCase() === n.toLowerCase()));
        for (const n of missing) c.error(`Property ${n} does not exist at path ${(key ?? rk).replace(/^HKLM:/, 'HKEY_LOCAL_MACHINE')}.`, { category: 'InvalidArgument', target: n, exception: 'PSArgumentException', id: 'System.Management.Automation.PSArgumentException,Microsoft.PowerShell.Commands.GetItemPropertyCommand' });
        if (missing.length === names.length) continue;
      }
      out.push(regProps(key ?? rk, values, names));
    }
    return out;
  },
});

function setRegistry(c: Call, create: boolean): void {
  const p = c.str('Path') ?? '';
  const rk = regKey(p);
  if (!rk) {
    c.error(`Cannot use interface. The IPropertyCmdletProvider interface is not supported by this provider.`, { category: 'NotImplemented', target: p, exception: 'PSNotSupportedException', id: 'NotSupported' });
    return;
  }
  if (!isAdmin(c)) { c.error(`Requested registry access is not allowed.`, { category: 'PermissionDenied', target: rk.replace(/^HKLM:/, 'HKEY_LOCAL_MACHINE'), exception: 'SecurityException', id: 'System.Security.SecurityException' }); return; }
  let key = findReg(c.ctx.host, rk);
  if (!key) {
    if (!regExists(c.ctx.host, rk) && !create) { notFound(c, rk); return; }
    key = rk;
    c.ctx.host.win!.registry[key] = {};
  }
  const name = c.str('Name') ?? '';
  const values = c.ctx.host.win!.registry[key];
  const existing = Object.keys(values).find((k) => k.toLowerCase() === name.toLowerCase());
  if (create && existing && !c.has('Force')) { c.error(`The property already exists.`, { category: 'ResourceExists', target: key.replace(/^HKLM:/, 'HKEY_LOCAL_MACHINE'), exception: 'IOException', id: 'System.IO.IOException,Microsoft.PowerShell.Commands.NewItemPropertyCommand' }); return; }
  if (c.whatIf('Set Property', `Item: ${key.replace(/^HKLM:/, 'HKEY_LOCAL_MACHINE')} Property: ${name}`)) return;
  const raw = c.p.Value;
  const n = toNum(raw);
  values[existing ?? name] = n !== null && typeof raw !== 'string' ? n : n !== null && /^\d+$/.test(toStr(raw)) ? n : toStr(raw);
  regChanged(c, key, name);
}

cmdlet({ name: 'Set-ItemProperty', module: MGMT, synopsis: 'Creates or changes the value of a property of an item.', params: [{ name: 'Path', type: 'string', position: 0 }, { name: 'Name', type: 'string', position: 1 }, { name: 'Value', type: 'any', position: 2 }, { name: 'Type', type: 'string' }, { name: 'Force', type: 'switch' }], run(c) { setRegistry(c, false); } });
cmdlet({ name: 'New-ItemProperty', module: MGMT, synopsis: 'Creates a new property for an item and sets its value.', params: [{ name: 'Path', type: 'string', position: 0 }, { name: 'Name', type: 'string', position: 1 }, { name: 'Value', type: 'any', position: 2 }, { name: 'PropertyType', aliases: ['Type'], type: 'string' }, { name: 'Force', type: 'switch' }], run(c) { setRegistry(c, true); } });

