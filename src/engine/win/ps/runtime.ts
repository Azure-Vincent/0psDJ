// The PowerShell engine: evaluates statements and pipelines, binds parameters
// like PowerShell (named, unambiguous prefixes, positional, switches, common
// parameters such as -ErrorAction and -WhatIf), resolves aliases, and reports
// errors in Windows PowerShell 5.1's format.

import type { Host, UserAccount, World } from '../../types';
import { formatOutput } from './format';
import { parse, PsParseError, type Arg, type CommandEl, type Expr, type Pipeline, type Statement } from './parse';
import {
  date, flatten, getProp, hash, hashGet, hashSet, isDate, isHash, isObj, obj, propNames, psCompare, psEquals, toBool, toNum, toStr, typeName, wildcard,
  type PSBlock, type PSValue,
} from './values';

export interface PsSession {
  vars: Record<string, PSValue>;
  cwd: string;
  history: string[];
  lastOk: boolean;
  lastExit: number;
  errors: string[];
}

export function newSession(home: string): PsSession {
  return { vars: {}, cwd: home, history: [], lastOk: true, lastExit: 0, errors: [] };
}

export interface ParamDef {
  name: string;
  aliases?: string[];
  type?: 'switch' | 'string' | 'strings' | 'int' | 'block' | 'any' | 'bool';
  position?: number;
}

export interface ErrorInfo {
  category?: string;
  target?: string;
  exception?: string;
  id?: string;
}

export interface Call {
  ctx: PsCtx;
  name: string;
  p: Record<string, PSValue>;
  has(name: string): boolean;
  /** String parameter value (first element for arrays). */
  str(name: string): string | undefined;
  /** String-list parameter value. */
  strs(name: string): string[] | undefined;
  input: PSValue[];
  error(message: string, info?: ErrorInfo): void;
  warn(text: string): void;
  host(text: string): void;
  whatIf(operation: string, target: string): boolean;
}

export interface CmdletDef {
  name: string;
  synopsis: string;
  params: ParamDef[];
  /** .NET class for FullyQualifiedErrorId (e.g. Microsoft.PowerShell.Commands.GetServiceCommand); defaults to the cmdlet name. */
  cls?: string;
  /** Module shown by Get-Command (Source). */
  module?: string;
  /** Extra syntax text for Get-Help. */
  syntax?: string;
  run(c: Call): PSValue[] | void;
}

export interface NativeDef {
  name: string;
  synopsis: string;
  /** `input`: the previous pipeline element's output as text lines (a native program's stdin). */
  run(args: string[], ctx: PsCtx, input: string[]): { out: string; code: number };
}

export const CMDLETS: Record<string, CmdletDef> = {};
export const NATIVES: Record<string, NativeDef> = {};

export function cmdlet(def: CmdletDef): void {
  CMDLETS[def.name.toLowerCase()] = def;
}

export function native(def: NativeDef): void {
  NATIVES[def.name.toLowerCase()] = def;
}

export const ALIASES: Record<string, string> = {
  '?': 'Where-Object', '%': 'ForEach-Object', cat: 'Get-Content', cd: 'Set-Location', chdir: 'Set-Location', clear: 'Clear-Host', cls: 'Clear-Host', copy: 'Copy-Item', cp: 'Copy-Item',
  curl: 'Invoke-WebRequest', del: 'Remove-Item', dir: 'Get-ChildItem', echo: 'Write-Output', erase: 'Remove-Item', fl: 'Format-List', foreach: 'ForEach-Object', ft: 'Format-Table',
  gc: 'Get-Content', gci: 'Get-ChildItem', gcm: 'Get-Command', gal: 'Get-Alias', gi: 'Get-Item', gl: 'Get-Location', gp: 'Get-ItemProperty', gps: 'Get-Process', group: 'Group-Object',
  gsv: 'Get-Service', h: 'Get-History', history: 'Get-History', iwr: 'Invoke-WebRequest', kill: 'Stop-Process', ls: 'Get-ChildItem', man: 'Get-Help', help: 'Get-Help', measure: 'Measure-Object',
  mi: 'Move-Item', move: 'Move-Item', mv: 'Move-Item', ni: 'New-Item', ps: 'Get-Process', pwd: 'Get-Location', rd: 'Remove-Item', ren: 'Rename-Item', ri: 'Remove-Item', rm: 'Remove-Item',
  rmdir: 'Remove-Item', sasv: 'Start-Service', sc: 'Set-Content', select: 'Select-Object', sl: 'Set-Location', sleep: 'Start-Sleep', sls: 'Select-String', sort: 'Sort-Object',
  sp: 'Set-ItemProperty', spps: 'Stop-Process', spsv: 'Stop-Service', tee: 'Tee-Object', tnc: 'Test-NetConnection', type: 'Get-Content', wget: 'Invoke-WebRequest', where: 'Where-Object',
  write: 'Write-Output', md: 'mkdir', ipconfig: 'ipconfig.exe',
};

export interface PsCtx {
  world: World;
  host: Host;
  user: UserAccount;
  session: PsSession;
  ask(text: string, secret: boolean): string;
  /** Console output stream (objects, and text written directly). */
  out: PSValue[];
  line: string;
  /** Set by Clear-Host. */
  clear?: boolean;
  /** Set by Restart-Computer / exit. */
  reboot?: boolean;
  exit?: boolean;
}

class Terminating extends Error {
  constructor(public text: string) { super(text); }
}

export function text(t: string): PSValue {
  return obj('__text', { text: t });
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

function underline(ctx: PsCtx, start: number, end: number): string[] {
  const line = ctx.line.split('\n')[0];
  return [`At line:1 char:${start + 1}`, `+ ${line}`, `+ ${' '.repeat(start)}${'~'.repeat(Math.max(1, Math.min(end, line.length) - start))}`];
}

export function formatError(ctx: PsCtx, cmd: string, message: string, start: number, end: number, info: ErrorInfo, cls?: string): string {
  return [
    `${cmd} : ${message}`,
    ...underline(ctx, start, end),
    `    + CategoryInfo          : ${info.category ?? 'NotSpecified'}: (${info.target ?? ''}${info.target !== undefined ? ':String' : ':'}) [${cmd}], ${info.exception ?? 'Exception'}`,
    `    + FullyQualifiedErrorId : ${info.id ?? 'Error'}${(info.id ?? '').endsWith(`,${cls ?? cmd}`) ? '' : `,${cls ?? cmd}`}`,
    ' ',
  ].join('\n');
}

function writeError(ctx: PsCtx, t: string): void {
  ctx.out.push(text(t));
  ctx.session.errors.unshift(t.split('\n')[0]);
  ctx.session.lastOk = false;
}

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

const PS_VERSION = hash([['PSVersion', obj('System.Version', { Major: 5, Minor: 1, Build: 20348, Revision: 2849, __str: '5.1.20348.2849' })], ['PSEdition', 'Desktop'], ['PSCompatibleVersions', ['1.0', '2.0', '3.0', '4.0', '5.0', '5.1.20348.2849']], ['BuildVersion', '10.0.20348.2849'], ['CLRVersion', '4.0.30319.42000'], ['WSManStackVersion', '3.0'], ['PSRemotingProtocolVersion', '2.3'], ['SerializationVersion', '1.1.0.1']]);

function envVars(ctx: PsCtx): Record<string, string> {
  const h = ctx.host;
  return {
    COMPUTERNAME: h.hostname.toUpperCase(), USERNAME: ctx.user.name, USERDOMAIN: h.hostname.toUpperCase(), USERPROFILE: ctx.user.home, HOMEDRIVE: 'C:', HOMEPATH: ctx.user.home.slice(2),
    SystemRoot: 'C:\\Windows', windir: 'C:\\Windows', SystemDrive: 'C:', TEMP: `${ctx.user.home}\\AppData\\Local\\Temp`, TMP: `${ctx.user.home}\\AppData\\Local\\Temp`, OS: 'Windows_NT',
    PROCESSOR_ARCHITECTURE: 'AMD64', NUMBER_OF_PROCESSORS: '2', ProgramFiles: 'C:\\Program Files', ProgramData: 'C:\\ProgramData', PUBLIC: 'C:\\Users\\Public',
    Path: 'C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;C:\\Windows\\System32\\OpenSSH\\',
    PSModulePath: 'C:\\Users\\Administrator\\Documents\\WindowsPowerShell\\Modules;C:\\Program Files\\WindowsPowerShell\\Modules;C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules',
  };
}

function getVar(ctx: PsCtx, name: string, item: PSValue | undefined): PSValue {
  const n = name.toLowerCase();
  if (n === '_' || n === 'psitem') return item ?? null;
  if (n === 'true') return true;
  if (n === 'false') return false;
  if (n === 'null') return null;
  if (n === '?') return ctx.session.lastOk;
  if (n === 'lastexitcode') return ctx.session.lastExit;
  if (n === 'error') return ctx.session.errors.slice(0, 256);
  if (n === 'home') return ctx.user.home;
  if (n === 'pwd') return obj('System.Management.Automation.PathInfo', { Path: ctx.session.cwd, __str: ctx.session.cwd });
  if (n === 'psversiontable') return PS_VERSION;
  if (n === 'pid') return 4128;
  if (n === 'host') return obj('System.Management.Automation.Internal.Host.InternalHost', { Name: 'ConsoleHost', Version: '5.1.20348.2849' });
  if (n.startsWith('env:')) {
    const env = envVars(ctx);
    const k = Object.keys(env).find((x) => x.toLowerCase() === n.slice(4));
    return k ? env[k] : (ctx.session.vars[n] ?? null);
  }
  const k = Object.keys(ctx.session.vars).find((x) => x.toLowerCase() === n);
  return k ? ctx.session.vars[k] : null;
}

function setVar(ctx: PsCtx, name: string, v: PSValue): void {
  const n = name.toLowerCase();
  if (['true', 'false', 'null', '?', 'home', 'pwd', 'pid', 'host', 'psversiontable'].includes(n)) throw new Terminating(`Cannot overwrite variable ${name} because it is read-only or constant.`);
  const k = Object.keys(ctx.session.vars).find((x) => x.toLowerCase() === n) ?? (n.startsWith('env:') ? n : name);
  ctx.session.vars[k] = v;
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

function single(vals: PSValue[]): PSValue {
  return vals.length === 0 ? null : vals.length === 1 ? vals[0] : vals;
}

function memberGet(v: PSValue, name: string): PSValue {
  if (Array.isArray(v)) {
    const ln = name.toLowerCase();
    if (ln === 'count' || ln === 'length') return v.length;
    // Member enumeration: (Get-Service).Name
    const vals = v.map((x) => memberGet(x, name)).filter((x) => x !== null && x !== undefined);
    return vals.length ? (vals.flatMap((x) => (Array.isArray(x) ? x : [x])) as PSValue) : null;
  }
  const ln = name.toLowerCase();
  if (typeof v === 'string') return ln === 'length' ? v.length : null;
  if (isDate(v)) {
    const d = new Date(v.ms);
    const m: Record<string, PSValue> = { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, day: d.getUTCDate(), hour: d.getUTCHours(), minute: d.getUTCMinutes(), second: d.getUTCSeconds(), dayofweek: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][d.getUTCDay()], date: date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())), ticks: v.ms * 10000 + 621355968000000000 };
    return m[ln] ?? null;
  }
  if (ln === 'count' && v !== null && v !== undefined) return 1;
  const p = getProp(v, name);
  return p === undefined ? null : p;
}

function callMethod(ctx: PsCtx, target: PSValue, name: string, args: PSValue[]): PSValue {
  const ln = name.toLowerCase();
  if (ln === 'tostring') return isDate(target) && args[0] ? fmtDate((target as { ms: number }).ms, toStr(args[0])) : toStr(target);
  if (ln === 'gettype') return obj('System.RuntimeType', { IsPublic: true, IsSerial: true, Name: typeName(target).split('.').pop(), BaseType: 'System.Object', FullName: typeName(target), __str: typeName(target) });
  if (typeof target === 'string') {
    const a = args.map(toStr);
    switch (ln) {
      case 'toupper': return target.toUpperCase();
      case 'tolower': return target.toLowerCase();
      case 'trim': return a[0] ? target.replace(new RegExp(`^[${escRe(a[0])}]+|[${escRe(a[0])}]+$`, 'g'), '') : target.trim();
      case 'trimstart': return target.replace(/^\s+/, '');
      case 'trimend': return target.replace(/\s+$/, '');
      case 'split': return target.split(new RegExp(`[${escRe(a.join(''))}]`));
      case 'contains': return target.includes(a[0]);
      case 'startswith': return target.toLowerCase().startsWith(a[0].toLowerCase()) && target.startsWith(a[0]);
      case 'endswith': return target.endsWith(a[0]);
      case 'replace': return target.split(a[0]).join(a[1] ?? '');
      case 'substring': return target.substr(Number(a[0]), a[1] === undefined ? undefined : Number(a[1]));
      case 'indexof': return target.indexOf(a[0]);
      case 'padleft': return target.padStart(Number(a[0]), a[1] ?? ' ');
      case 'padright': return target.padEnd(Number(a[0]), a[1] ?? ' ');
    }
  }
  if (isDate(target)) {
    const n = toNum(args[0]) ?? 0;
    const add: Record<string, number> = { adddays: 86400000, addhours: 3600000, addminutes: 60000, addseconds: 1000 };
    if (add[ln]) return date(target.ms + n * add[ln]);
  }
  if (Array.isArray(target) && ln === 'contains') return target.some((x) => psEquals(x, args[0]));
  if (isHash(target) && ln === 'containskey') return hashGet(target, toStr(args[0])) !== null;
  throw new Terminating(`Method invocation failed because [${typeName(target)}] does not contain a method named '${name}'.`);
  void ctx;
}

function escRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&');
}

function fmtDate(ms: number, f: string): string {
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return f.replace(/yyyy/g, String(d.getUTCFullYear())).replace(/MM/g, p(d.getUTCMonth() + 1)).replace(/dd/g, p(d.getUTCDate())).replace(/HH/g, p(d.getUTCHours())).replace(/mm/g, p(d.getUTCMinutes())).replace(/ss/g, p(d.getUTCSeconds()));
}

function staticMember(ctx: PsCtx, type: string, name: string, args?: PSValue[]): PSValue {
  const t = type.toLowerCase().replace(/^system\./, '');
  const n = name.toLowerCase();
  const nums = (args ?? []).map((a) => toNum(a) ?? 0);
  if (t === 'math') {
    if (n === 'round') return Math.round(nums[0] * 10 ** (nums[1] ?? 0)) / 10 ** (nums[1] ?? 0);
    if (n === 'floor') return Math.floor(nums[0]);
    if (n === 'ceiling') return Math.ceil(nums[0]);
    if (n === 'max') return Math.max(nums[0], nums[1]);
    if (n === 'min') return Math.min(nums[0], nums[1]);
    if (n === 'abs') return Math.abs(nums[0]);
    if (n === 'pi') return Math.PI;
  }
  if (t === 'datetime' && n === 'now') return date(ctx.world.clock + (ctx.host.clockOffset ?? 0));
  if (t === 'environment' && n === 'machinename') return ctx.host.hostname.toUpperCase();
  if (t === 'environment' && n === 'username') return ctx.user.name;
  if (t === 'environment' && n === 'osversion') return obj('System.OperatingSystem', { Platform: 'Win32NT', ServicePack: '', Version: `10.0.${ctx.host.win?.build ?? '20348'}.0`, VersionString: `Microsoft Windows NT 10.0.${ctx.host.win?.build ?? '20348'}.0`, __str: `Microsoft Windows NT 10.0.${ctx.host.win?.build ?? '20348'}.0` });
  if (t === 'int32' && n === 'maxvalue') return 2147483647;
  throw new Terminating(`Unable to find type [${type}].`);
}

function cast(type: string, v: PSValue): PSValue {
  const t = type.toLowerCase().replace(/^system\./, '');
  if (t === 'int' || t === 'int32' || t === 'long' || t === 'int64') {
    const n = toNum(v);
    if (n === null) throw new Terminating(`Cannot convert value "${toStr(v)}" to type "System.Int32". Error: "Input string was not in a correct format."`);
    return Math.round(n);
  }
  if (t === 'double' || t === 'decimal') return toNum(v) ?? 0;
  if (t === 'string') return toStr(v);
  if (t === 'bool' || t === 'boolean') return toBool(v);
  if (t === 'array' || t === 'object[]' || t === 'string[]') return flatten(v).map((x) => (t === 'string[]' ? toStr(x) : x));
  if (t === 'datetime') {
    const ms = Date.parse(toStr(v));
    if (Number.isNaN(ms)) throw new Terminating(`Cannot convert value "${toStr(v)}" to type "System.DateTime".`);
    return date(ms);
  }
  if (t === 'ipaddress') {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(toStr(v))) throw new Terminating(`Cannot convert value "${toStr(v)}" to type "System.Net.IPAddress". Error: "An invalid IP address was specified."`);
    return obj('System.Net.IPAddress', { Address: toStr(v), AddressFamily: 'InterNetwork', IPAddressToString: toStr(v), __str: toStr(v) });
  }
  if (t === 'pscustomobject' && isHash(v)) return obj('System.Management.Automation.PSCustomObject', Object.fromEntries(v.keys.map((k) => [k, v.entries[k]])));
  if (t === 'hashtable' && isHash(v)) return v;
  return v;
}

export function evalExpr(ctx: PsCtx, e: Expr, item?: PSValue): PSValue {
  switch (e.k) {
    case 'str': return e.v;
    case 'num': return e.v;
    case 'xstr': return e.parts.map((p) => (typeof p === 'string' ? p : toStr(evalExpr(ctx, p, item)))).join('');
    case 'var': return getVar(ctx, e.name, item);
    case 'arr': return e.items.map((x) => evalExpr(ctx, x, item));
    case 'sub': {
      const vals = runStatements(ctx, e.body, item, true);
      return e.array ? vals : single(vals);
    }
    case 'hash': return hash(e.entries.map(([k, v]) => [toStr(evalExpr(ctx, k, item)), evalExpr(ctx, v, item)]));
    case 'block': return { __t: 'System.Management.Automation.ScriptBlock', text: e.text, body: e.body } as PSBlock;
    case 'type': return obj('System.RuntimeType', { Name: e.name, FullName: e.name, __str: e.name });
    case 'cast': return cast(e.type, evalExpr(ctx, e.e, item));
    case 'member': {
      const name = toStr(evalExpr(ctx, e.name, item));
      if (e.isStatic && e.obj.k === 'type') return staticMember(ctx, e.obj.name, name, e.args?.map((a) => evalExpr(ctx, a, item)));
      const target = evalExpr(ctx, e.obj, item);
      if (e.args) return callMethod(ctx, target, name, e.args.map((a) => evalExpr(ctx, a, item)));
      return memberGet(target, name);
    }
    case 'index': {
      const target = evalExpr(ctx, e.obj, item);
      const idx = evalExpr(ctx, e.idx, item);
      if (isHash(target)) return hashGet(target, toStr(idx));
      const arr = typeof target === 'string' ? target.split('') : flatten(target);
      const pick = (i: PSValue) => { const n = toNum(i) ?? 0; return arr[n < 0 ? arr.length + n : n] ?? null; };
      return Array.isArray(idx) ? idx.map(pick) : pick(idx);
    }
    case 'un': {
      const v = evalExpr(ctx, e.e, item);
      if (e.op === 'not') return !toBool(v);
      const n = toNum(v);
      if (n === null) throw new Terminating(`Cannot convert value "${toStr(v)}" to type "System.Int32".`);
      return -n;
    }
    case 'bin': return binary(ctx, e.op, e.l, e.r, item);
  }
}

function binary(ctx: PsCtx, op: string, le: Expr, re: Expr, item?: PSValue): PSValue {
  if (op === 'and') return toBool(evalExpr(ctx, le, item)) && toBool(evalExpr(ctx, re, item));
  if (op === 'or') return toBool(evalExpr(ctx, le, item)) || toBool(evalExpr(ctx, re, item));
  const l = evalExpr(ctx, le, item);
  const r = evalExpr(ctx, re, item);
  const cs = op.startsWith('c') && op.length > 2 && !['contains'].includes(op);
  const o = cs ? op.slice(1) : op;
  const scalarOp = (a: PSValue): boolean => {
    switch (o) {
      case 'eq': return psEquals(a, r, cs);
      case 'ne': return !psEquals(a, r, cs);
      case 'gt': return psCompare(a, r) > 0;
      case 'ge': return psCompare(a, r) >= 0;
      case 'lt': return psCompare(a, r) < 0;
      case 'le': return psCompare(a, r) <= 0;
      case 'like': return wildcard(toStr(r)).test(toStr(a));
      case 'notlike': return !wildcard(toStr(r)).test(toStr(a));
      case 'match': case 'notmatch': {
        const m = new RegExp(toStr(r), cs ? '' : 'i').exec(toStr(a));
        if (m && o === 'match') ctx.session.vars.Matches = hash(m.map((g, i) => [String(i), g ?? null]));
        return o === 'match' ? !!m : !m;
      }
    }
    return false;
  };
  switch (o) {
    case 'eq': case 'ne': case 'gt': case 'ge': case 'lt': case 'le': case 'like': case 'notlike': case 'match': case 'notmatch':
      return Array.isArray(l) ? l.filter((x) => scalarOp(x)) : scalarOp(l);
    case 'contains': return flatten(l).some((x) => psEquals(x, r));
    case 'notcontains': return !flatten(l).some((x) => psEquals(x, r));
    case 'in': return flatten(r).some((x) => psEquals(x, l));
    case 'notin': return !flatten(r).some((x) => psEquals(x, l));
    case 'replace': {
      const [pat, rep] = flatten(r).map(toStr);
      const f = (s: PSValue) => toStr(s).replace(new RegExp(pat, cs ? 'g' : 'gi'), (rep ?? '').replace(/\$(\d)/g, '$$$1'));
      return Array.isArray(l) ? l.map(f) : f(l);
    }
    case 'split': return toStr(l).split(new RegExp(toStr(r), 'i'));
    case 'join': return flatten(l).map(toStr).join(toStr(r));
    case 'f': {
      // .NET composite formatting: {index[,alignment][:format]}
      const args = flatten(r);
      return toStr(l).replace(/\{(\d+)(?:,(-?\d+))?(?::([A-Za-z])(\d*))?\}/g, (_m, i: string, align?: string, f?: string, digits?: string) => {
        const v = args[Number(i)] ?? null;
        let t = toStr(v);
        const n = toNum(v);
        if (f && n !== null) {
          const d = digits === undefined || digits === '' ? (f.toUpperCase() === 'D' ? 0 : 2) : Number(digits);
          if (f.toUpperCase() === 'N') t = n.toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });
          else if (f.toUpperCase() === 'F') t = n.toFixed(d);
          else if (f.toUpperCase() === 'D') t = String(Math.trunc(n)).padStart(d, '0');
          else if (f.toUpperCase() === 'X') t = Math.trunc(n).toString(16).padStart(d, '0');
          else if (f.toUpperCase() === 'P') t = `${(n * 100).toFixed(d)} %`;
        }
        if (align) t = Number(align) < 0 ? t.padEnd(-Number(align)) : t.padStart(Number(align));
        return t;
      }).replace(/\{\{/g, '{').replace(/\}\}/g, '}');
    }
    case 'is': return typeName(l).toLowerCase().endsWith(toStr(r).toLowerCase().replace(/^system\./, '')) || (toStr(r).toLowerCase() === 'string' && typeof l === 'string');
    case 'isnot': return !binary(ctx, 'is', le, re, item);
    case 'as': try { return cast(toStr(r), l); } catch { return null; }
    case 'xor': return toBool(l) !== toBool(r);
    case '..': {
      const a = toNum(l) ?? 0, b = toNum(r) ?? 0;
      const out: number[] = [];
      for (let i = a; a <= b ? i <= b : i >= b; i += a <= b ? 1 : -1) { out.push(i); if (out.length > 10000) break; }
      return out;
    }
    case '+': {
      if (Array.isArray(l)) return [...l, ...flatten(r)];
      if (typeof l === 'string') return l + toStr(r);
      if (isDate(l)) return l;
      const a = toNum(l), b = toNum(r);
      if (a === null || b === null) throw new Terminating(`Cannot convert value "${toStr(r)}" to type "System.Int32". Error: "Input string was not in a correct format."`);
      return a + b;
    }
    case '-': case '*': case '/': case '%': {
      if (o === '*' && typeof l === 'string') return l.repeat(Math.max(0, toNum(r) ?? 0));
      const a = toNum(l), b = toNum(r);
      if (a === null || b === null) throw new Terminating(`Method invocation failed because [${typeName(l)}] does not contain a method named 'op_${o === '-' ? 'Subtraction' : o === '*' ? 'Multiply' : o === '/' ? 'Division' : 'Modulus'}'.`);
      if (o === '/' && b === 0) throw new Terminating('Attempted to divide by zero.');
      return o === '-' ? a - b : o === '*' ? a * b : o === '/' ? a / b : a % b;
    }
  }
  throw new Terminating(`Unexpected operator -${op}.`);
}

/** Run a script block with $_ bound to `item`. */
export function invokeBlock(ctx: PsCtx, b: PSBlock, item?: PSValue): PSValue[] {
  return runStatements(ctx, b.body as Statement[], item, true);
}

// ---------------------------------------------------------------------------
// Statements and pipelines
// ---------------------------------------------------------------------------

function runStatements(ctx: PsCtx, body: Statement[], item: PSValue | undefined, collect: boolean): PSValue[] {
  const out: PSValue[] = [];
  for (const st of body) out.push(...runStatement(ctx, st, item, collect));
  return out;
}

function runStatement(ctx: PsCtx, st: Statement, item: PSValue | undefined, collect: boolean): PSValue[] {
  switch (st.k) {
    case 'pipe': return runPipeline(ctx, st.p, item, collect);
    case 'assign': {
      const vals = runPipeline(ctx, st.value, item, true);
      let v: PSValue = single(vals);
      if (st.target.k === 'var') {
        if (st.op === '+=') v = binaryValues(getVar(ctx, st.target.name, item), v, '+');
        if (st.op === '-=') v = binaryValues(getVar(ctx, st.target.name, item), v, '-');
        setVar(ctx, st.target.name, v);
      } else if (st.target.k === 'member') {
        const o = evalExpr(ctx, st.target.obj, item);
        const name = toStr(evalExpr(ctx, st.target.name, item));
        if (isHash(o)) hashSet(o, name, v);
        else if (isObj(o)) {
          const k = propNames(o).find((x) => x.toLowerCase() === name.toLowerCase());
          if (!k) throw new Terminating(`The property '${name}' cannot be found on this object. Verify that the property exists and can be set.`);
          o[k] = v;
        }
      } else if (st.target.k === 'index') {
        const o = evalExpr(ctx, st.target.obj, item);
        const idx = evalExpr(ctx, st.target.idx, item);
        if (isHash(o)) hashSet(o, toStr(idx), v);
        else if (Array.isArray(o)) o[toNum(idx) ?? 0] = v;
      }
      return [];
    }
    case 'if': {
      for (const c of st.clauses) {
        if (toBool(single(runPipeline(ctx, c.cond, item, true)))) return runStatements(ctx, c.body, item, collect);
      }
      return st.otherwise ? runStatements(ctx, st.otherwise, item, collect) : [];
    }
    case 'foreach': {
      const coll = runPipeline(ctx, st.coll, item, true);
      const out: PSValue[] = [];
      for (const x of coll.flatMap((v) => flatten(v))) {
        setVar(ctx, st.v, x);
        out.push(...runStatements(ctx, st.body, item, collect));
      }
      return out;
    }
  }
}

function binaryValues(l: PSValue, r: PSValue, op: '+' | '-'): PSValue {
  if (Array.isArray(l)) return [...l, ...flatten(r)];
  if (typeof l === 'string' && op === '+') return l + toStr(r);
  if (l === null) return r;
  const a = toNum(l) ?? 0, b = toNum(r) ?? 0;
  return op === '+' ? a + b : a - b;
}

/** Resolve a command name: alias → cmdlet / native program / function. */
export function resolveCommand(name: string): { kind: 'cmdlet'; def: CmdletDef } | { kind: 'native'; def: NativeDef } | null {
  let n = name.toLowerCase();
  const alias = Object.keys(ALIASES).find((a) => a === n);
  if (alias) n = ALIASES[alias].toLowerCase();
  if (CMDLETS[n]) return { kind: 'cmdlet', def: CMDLETS[n] };
  const exe = n.replace(/\.(exe|com)$/, '');
  if (NATIVES[exe]) return { kind: 'native', def: NATIVES[exe] };
  return null;
}

const COMMON = ['erroraction', 'warningaction', 'whatif', 'confirm', 'verbose', 'debug', 'outvariable', 'errorvariable', 'informationaction'];
const COMMON_ALIASES: Record<string, string> = { ea: 'erroraction', wa: 'warningaction', wi: 'whatif', cf: 'confirm', vb: 'verbose', db: 'debug', ov: 'outvariable', ev: 'errorvariable', infa: 'informationaction' };

function bindError(ctx: PsCtx, el: CommandEl, def: CmdletDef, message: string, id: string, category = 'InvalidArgument'): never {
  throw new Terminating(formatError(ctx, def.name, message, el.start, el.end, { category, target: '', exception: 'ParameterBindingException', id }, def.cls ?? `Microsoft.PowerShell.Commands.${def.name.replace('-', '')}Command`));
}

function bindParams(ctx: PsCtx, el: CommandEl, def: CmdletDef, item: PSValue | undefined): { p: Record<string, PSValue>; common: Record<string, PSValue> } {
  const p: Record<string, PSValue> = {};
  const common: Record<string, PSValue> = {};
  const positional: { e: Expr; text: string }[] = [];
  const args = el.args;
  for (let i = 0; i < args.length; i++) {
    const a: Arg = args[i];
    if (a.k === 'value') { positional.push({ e: a.e, text: a.text }); continue; }
    const want = a.name.toLowerCase();
    const commonName = COMMON_ALIASES[want] ?? COMMON.find((c) => c === want) ?? (want.length >= 3 ? COMMON.find((c) => c.startsWith(want)) : undefined);
    const exact = def.params.filter((d) => d.name.toLowerCase() === want || d.aliases?.some((x) => x.toLowerCase() === want));
    const prefixed = exact.length ? exact : def.params.filter((d) => d.name.toLowerCase().startsWith(want));
    if (!prefixed.length && commonName) {
      const isSwitch = ['whatif', 'confirm', 'verbose', 'debug'].includes(commonName);
      if (a.value) common[commonName] = evalExpr(ctx, a.value, item);
      else if (isSwitch) common[commonName] = true;
      else {
        const next = args[i + 1];
        if (!next || next.k !== 'value') bindError(ctx, el, def, `Missing an argument for parameter '${a.name}'. Specify a parameter of type 'System.Management.Automation.ActionPreference' and try again.`, 'MissingArgument');
        common[commonName] = evalExpr(ctx, next.e, item);
        i++;
      }
      continue;
    }
    if (prefixed.length === 0) bindError(ctx, el, def, `A parameter cannot be found that matches parameter name '${a.name}'.`, 'NamedParameterNotFound');
    if (prefixed.length > 1) bindError(ctx, el, def, `Parameter cannot be processed because the parameter name '${a.name}' is ambiguous. Possible matches include: ${prefixed.map((x) => `-${x.name}`).join(' ')}.`, 'AmbiguousParameter');
    const d = prefixed[0];
    if (d.type === 'switch') {
      p[d.name] = a.value ? toBool(evalExpr(ctx, a.value, item)) : true;
      continue;
    }
    if (a.value) { p[d.name] = evalExpr(ctx, a.value, item); continue; }
    const next = args[i + 1];
    if (!next || next.k !== 'value') {
      const t = d.type === 'int' ? 'System.Int32' : d.type === 'strings' ? 'System.String[]' : d.type === 'block' ? 'System.Management.Automation.ScriptBlock' : d.type === 'bool' ? 'System.Boolean' : 'System.String';
      bindError(ctx, el, def, `Missing an argument for parameter '${d.name}'. Specify a parameter of type '${t}' and try again.`, 'MissingArgument');
    }
    p[d.name] = evalExpr(ctx, next.e, item);
    i++;
  }
  const slots = def.params.filter((d) => d.position !== undefined && !(d.name in p)).sort((a, b) => a.position! - b.position!);
  for (const v of positional) {
    const d = slots.shift();
    if (!d) bindError(ctx, el, def, `A positional parameter cannot be found that accepts argument '${v.text}'.`, 'PositionalParameterNotFound');
    p[d.name] = evalExpr(ctx, v.e, item);
  }
  for (const d of def.params) {
    if (!(d.name in p)) continue;
    if (d.type === 'int') {
      const n = toNum(p[d.name]);
      if (n === null) bindError(ctx, el, def, `Cannot bind parameter '${d.name}'. Cannot convert value "${toStr(p[d.name])}" to type "System.Int32". Error: "Input string was not in a correct format."`, 'CannotConvertArgumentNoMessage');
      p[d.name] = n;
    }
    if (d.type === 'bool') p[d.name] = toBool(typeof p[d.name] === 'string' ? /^(true|1|\$true)$/i.test(p[d.name] as string) : p[d.name]);
  }
  return { p, common };
}

function runPipeline(ctx: PsCtx, pl: Pipeline, item: PSValue | undefined, collect: boolean): PSValue[] {
  let data: PSValue[] = [];
  let formatted = false;
  pl.els.forEach((el, idx) => {
    if (el.k === 'expr') {
      if (idx > 0) throw new Terminating(formatParse(ctx, el.start, 'Expressions are only allowed as the first element of a pipeline.', 'ExpressionsMustBeFirstInPipeline'));
      const v = evalExpr(ctx, el.e, item);
      data = v === null || v === undefined ? [] : Array.isArray(v) ? v : [v];
      return;
    }
    const r = resolveCommand(el.name);
    if (!r) {
      throw new Terminating([
        `${el.name} : The term '${el.name}' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.`,
        ...underline(ctx, el.start, el.start + el.name.length),
        `    + CategoryInfo          : ObjectNotFound: (${el.name}:String) [], CommandNotFoundException`,
        '    + FullyQualifiedErrorId : CommandNotFoundException',
        ' ',
      ].join('\n'));
    }
    if (r.kind === 'native') {
      const args = el.args.map((a) => (a.k === 'param' ? (a.value ? `-${a.name}:${toStr(evalExpr(ctx, a.value, item))}` : `-${a.name}`) : flatten(evalExpr(ctx, a.e, item)).map(toStr).join(' ')));
      const stdin = data.length ? formatOutput(data).split('\n') : [];
      const res = r.def.run(args, ctx, stdin);
      ctx.session.lastExit = res.code;
      ctx.session.lastOk = res.code === 0;
      data = res.out === '' ? [] : res.out.split('\n');
      return;
    }
    const def = r.def;
    const { p, common } = bindParams(ctx, el, def, item);
    const ea = toStr(common.erroraction ?? ctx.session.vars.ErrorActionPreference ?? 'Continue').toLowerCase();
    const call: Call = {
      ctx, name: def.name, p, input: data,
      has: (n) => n in p,
      str: (n) => (n in p ? toStr(Array.isArray(p[n]) ? (p[n] as PSValue[])[0] : p[n]) : undefined),
      strs: (n) => (n in p ? flatten(p[n]).map(toStr) : undefined),
      error: (message, info = {}) => {
        if (ea === 'silentlycontinue' || ea === 'ignore') { ctx.session.lastOk = false; return; }
        const t = formatError(ctx, def.name, message, el.start, el.end, info, def.cls ?? `Microsoft.PowerShell.Commands.${def.name.replace('-', '')}Command`);
        if (ea === 'stop') throw new Terminating(t);
        writeError(ctx, t);
      },
      warn: (t) => { if (toStr(common.warningaction).toLowerCase() !== 'silentlycontinue') ctx.out.push(text(`WARNING: ${t}`)); },
      host: (t) => ctx.out.push(text(t)),
      whatIf: (operation, target) => {
        if (!toBool(common.whatif)) return false;
        ctx.out.push(text(`What if: Performing the operation "${operation}" on target "${target}".`));
        return true;
      },
    };
    ctx.session.lastOk = true;
    const res = def.run(call) ?? [];
    data = res;
    if (/^format-/i.test(def.name)) formatted = true;
  });
  void formatted;
  void collect;
  return data;
}

function formatParse(ctx: PsCtx, pos: number, message: string, id: string): string {
  const l = ctx.line.split('\n')[0];
  return [`At line:1 char:${pos + 1}`, `+ ${l}`, `+ ${' '.repeat(pos)}~`, message, '    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException', `    + FullyQualifiedErrorId : ${id}`, ' '].join('\n');
}

// ---------------------------------------------------------------------------
// Running a command line
// ---------------------------------------------------------------------------

export function runLine(ctx: PsCtx, line: string): void {
  let body: Statement[];
  try {
    body = parse(line);
  } catch (e) {
    if (!(e instanceof PsParseError)) throw e;
    const l = line.split('\n')[0];
    ctx.out.push(text([`At line:1 char:${Math.min(e.pos, l.length) + 1}`, `+ ${l}`, `+ ${' '.repeat(Math.min(e.pos, l.length))}~`, e.message, '    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException', `    + FullyQualifiedErrorId : ${e.id}`, ' '].join('\n')));
    ctx.session.lastOk = false;
    return;
  }
  ctx.session.lastOk = true;
  try {
    for (const st of body) {
      const vals = runStatement(ctx, st, undefined, false);
      ctx.out.push(...vals);
    }
  } catch (e) {
    if (e instanceof Terminating) {
      const t = /^At line:|\n {4}\+ CategoryInfo/.test(e.text) ? e.text : [e.text, ...underline(ctx, 0, line.split('\n')[0].length), '    + CategoryInfo          : NotSpecified: (:) [], RuntimeException', '    + FullyQualifiedErrorId : RuntimeException', ' '].join('\n');
      writeError(ctx, t);
      return;
    }
    throw e;
  }
}

export function renderOutput(ctx: PsCtx): string {
  return formatOutput(ctx.out);
}

export { Terminating };
