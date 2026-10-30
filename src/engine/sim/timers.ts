// systemd units written by the administrator in /etc/systemd/system: oneshot
// services that run a command line, and timers that start them on a calendar
// schedule (OnCalendar=), after boot (OnBootSec=) or after their last run
// (OnUnitActiveSec=). Unlike the packaged services in services.ts, these are
// executed: ExecStart runs through the shell as User= with the unit's
// Environment=/EnvironmentFile=, its output goes to the journal under the
// unit, and the exit status decides the unit's state.
//
// systemd keeps the unit text it loaded: a file edited later is not used until
// `systemctl daemon-reload` (status warns that it changed on disk). Timers with
// Persistent=true record their last trigger in /var/lib/systemd/timers/ and
// catch up a run missed while the machine was off.

import { sha256Hex } from '../util/sha256';
import { basename, mkdir, readFile, writeFile } from '../fs';
import type { Host, World } from '../types';
import { log } from './journal';

export const UNIT_DIR = '/etc/systemd/system';
const STAMP_DIR = '/var/lib/systemd/timers';

export interface UnitRuntime {
  /** active: a timer waiting for its next elapse (oneshot services are inactive again after a run). */
  state: 'inactive' | 'active' | 'failed';
  enabled: boolean;
  since: number;
  /** systemd's Result=: success, exit-code, resources … */
  result: string;
  /** The unit text systemd loaded (null before the first load). */
  loaded: string | null;
  /** Services: the last run. */
  lastRun?: { pid: number; start: number; end: number; exec: string; code: number };
  /** Timers: the last time the timer triggered its service. */
  lastTrigger?: number;
  /** Timers: a Persistent= run missed while the machine was off, due as soon as the system is up. */
  catchUp?: boolean;
}

/** Runs a unit's command line on a host (registered by the shell, which owns command execution). */
export interface UnitRunner {
  run(world: World, hostId: string, user: string, line: string, env: Record<string, string>, cwd: string): { out: string; code: number };
  /** Whether PROGRAM (an absolute path or a bare name looked up in systemd's PATH) can be executed. */
  resolve(host: Host, program: string): { path: string } | { error: string };
}

let runner: UnitRunner | null = null;
export function setUnitRunner(r: UnitRunner): void {
  runner = r;
}

// ---------------------------------------------------------------------------
// Unit files
// ---------------------------------------------------------------------------

export type UnitFile = Record<string, Record<string, string[]>>;

export function parseUnit(text: string): UnitFile {
  const out: UnitFile = {};
  let sec = '';
  let pending = '';
  for (const raw of text.split('\n')) {
    let line = pending + raw.trim();
    pending = '';
    if (line.endsWith('\\')) { pending = line.slice(0, -1) + ' '; continue; }
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const s = /^\[(.+)\]$/.exec(line);
    if (s) { sec = s[1]; out[sec] ??= {}; continue; }
    const i = line.indexOf('=');
    if (i < 0 || !sec) continue;
    const k = line.slice(0, i).trim();
    line = line.slice(i + 1).trim();
    // An empty assignment resets the list (ExecStart=, OnCalendar=).
    if (line === '') out[sec][k] = [];
    else (out[sec][k] ??= []).push(line);
  }
  return out;
}

const one = (u: UnitFile, sec: string, key: string): string | undefined => u[sec]?.[key]?.at(-1);

export function isUserUnit(host: Host, name: string): boolean {
  return /\.(service|timer)$/.test(name) && host.fs[`${UNIT_DIR}/${name}`]?.type === 'file';
}

/** The full unit name for what the user typed (backup → backup.service). */
export function unitName(host: Host, typed: string): string | null {
  const n = /\.(service|timer)$/.test(typed) ? typed : `${typed}.service`;
  return isUserUnit(host, n) ? n : null;
}

export function userUnits(host: Host): string[] {
  const pre = `${UNIT_DIR}/`;
  return Object.keys(host.fs).filter((p) => p.startsWith(pre) && !p.slice(pre.length).includes('/') && /\.(service|timer)$/.test(p) && host.fs[p].type === 'file').map((p) => p.slice(pre.length)).sort();
}

export function runtime(host: Host, name: string): UnitRuntime {
  host.units ??= {};
  return (host.units[name] ??= { state: 'inactive', enabled: false, since: 0, result: 'success', loaded: null });
}

/** The text systemd uses: loaded once (first use, boot, daemon-reload), not re-read when the file changes. */
export function loadedUnit(host: Host, name: string): { unit: UnitFile; text: string; changed: boolean } | null {
  const text = readFile(host, `${UNIT_DIR}/${name}`);
  const rt = runtime(host, name);
  if (rt.loaded === null) {
    if (text === undefined) return null;
    rt.loaded = text;
  }
  return { unit: parseUnit(rt.loaded), text: rt.loaded, changed: text !== rt.loaded };
}

export function daemonReload(world: World, host: Host): void {
  log(world, host, 'systemd', 'Reloading.', { pid: 1 });
  const present = new Set(userUnits(host));
  for (const name of Object.keys(host.units ?? {})) {
    if (!present.has(name)) { delete host.units![name]; continue; }
  }
  for (const name of present) runtime(host, name).loaded = readFile(host, `${UNIT_DIR}/${name}`) ?? null;
}

export function description(host: Host, name: string): string {
  return (loadedUnit(host, name) && one(loadedUnit(host, name)!.unit, 'Unit', 'Description')) || name;
}

/** The service a timer starts (Unit=, default: same name). */
export function timerTarget(host: Host, timer: string): string {
  const l = loadedUnit(host, timer);
  return (l && one(l.unit, 'Timer', 'Unit')) || timer.replace(/\.timer$/, '.service');
}

export function hasInstall(host: Host, name: string): boolean {
  const l = loadedUnit(host, name);
  return !!l && !!(l.unit.Install?.WantedBy?.length || l.unit.Install?.RequiredBy?.length);
}

/** Timers that trigger SERVICE. */
export function triggeredBy(host: Host, service: string): string[] {
  return userUnits(host).filter((u) => u.endsWith('.timer') && timerTarget(host, u) === service);
}

// ---------------------------------------------------------------------------
// Calendar specifications (systemd.time(7)), evaluated in UTC
// ---------------------------------------------------------------------------

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const SHORTHAND: Record<string, string> = {
  minutely: '*-*-* *:*:00', hourly: '*-*-* *:00:00', daily: '*-*-* 00:00:00', weekly: 'Mon *-*-* 00:00:00',
  monthly: '*-*-01 00:00:00', yearly: '*-01-01 00:00:00', annually: '*-01-01 00:00:00',
  quarterly: '*-01,04,07,10-01 00:00:00', semiannually: '*-01,07-01 00:00:00',
};

interface Field { values: number[] | null; text: string }
export interface CalendarSpec { dow: number[] | null; dowText: string; year: Field; month: Field; day: Field; hour: Field; minute: Field; second: Field }

function field(text: string, min: number, max: number, pad: number): Field | null {
  if (text === '*') return { values: null, text: '*' };
  const vals = new Set<number>();
  const parts: string[] = [];
  for (const part of text.split(',')) {
    const m = /^(\*|\d+)(?:\.\.(\d+))?(?:\/(\d+))?$/.exec(part);
    if (!m) return null;
    const start = m[1] === '*' ? min : Number(m[1]);
    const end = m[2] !== undefined ? Number(m[2]) : m[3] !== undefined || m[1] === '*' ? max : start;
    const step = m[3] !== undefined ? Number(m[3]) : 1;
    if (start < min || end > max || step < 1 || start > end) return null;
    for (let v = start; v <= end; v += step) vals.add(v);
    const p = (n: number) => String(n).padStart(pad, '0');
    parts.push(m[1] === '*' && m[3] ? `*/${m[3]}` : `${p(start)}${m[2] !== undefined ? `..${p(end)}` : ''}${m[3] ? `/${m[3]}` : ''}`);
  }
  return { values: [...vals].sort((a, b) => a - b), text: parts.join(',') };
}

function dowSet(text: string): { set: number[]; text: string } | null {
  const set = new Set<number>();
  const parts: string[] = [];
  for (const part of text.split(',')) {
    const [a, b] = part.split('..');
    const ia = DAYS.findIndex((d) => a.toLowerCase().startsWith(d.toLowerCase()) && /^[a-z]+$/i.test(a));
    const ib = b === undefined ? ia : DAYS.findIndex((d) => b.toLowerCase().startsWith(d.toLowerCase()));
    if (ia < 0 || ib < 0) return null;
    for (let i = ia; ; i = (i + 1) % 7) { set.add(i); if (i === ib) break; }
    parts.push(b === undefined ? DAYS[ia] : `${DAYS[ia]}..${DAYS[ib]}`);
  }
  return { set: [...set], text: parts.join(',') };
}

export function parseCalendar(spec: string): CalendarSpec | null {
  let s = spec.trim();
  s = SHORTHAND[s.toLowerCase()] ?? s;
  let words = s.split(/\s+/);
  let dow: { set: number[]; text: string } | null = null;
  if (words[0] && /^[a-z]/i.test(words[0])) {
    dow = dowSet(words[0]);
    if (!dow) return null;
    words = words.slice(1);
  }
  let date = '*-*-*';
  let time = '00:00:00';
  if (words.length === 2) [date, time] = words;
  else if (words.length === 1) { if (words[0].includes(':')) time = words[0]; else date = words[0]; }
  else if (words.length > 2) return null;
  const dp = date.split('-');
  if (dp.length === 2) dp.unshift('*');
  if (dp.length !== 3) return null;
  const tp = time.split(':');
  if (tp.length === 2) tp.push('00');
  if (tp.length !== 3) return null;
  const year = field(dp[0], 1970, 2199, 4);
  const month = field(dp[1], 1, 12, 2);
  const day = field(dp[2], 1, 31, 2);
  const hour = field(tp[0], 0, 23, 2);
  const minute = field(tp[1], 0, 59, 2);
  const second = field(tp[2], 0, 59, 2);
  if (!year || !month || !day || !hour || !minute || !second) return null;
  return { dow: dow?.set ?? null, dowText: dow?.text ?? '', year, month, day, hour, minute, second };
}

export function normalizedCalendar(c: CalendarSpec): string {
  return `${c.dowText ? c.dowText + ' ' : ''}${c.year.text}-${c.month.text}-${c.day.text} ${c.hour.text}:${c.minute.text}:${c.second.text}`;
}

const has = (f: Field, v: number) => f.values === null || f.values.includes(v);
const range = (f: Field, max: number, min = 0) => f.values ?? Array.from({ length: max - min + 1 }, (_, i) => i + min);

/** The first elapse strictly after AFTER (ms, UTC), or null within the next ~5 years. */
export function nextElapse(c: CalendarSpec, after: number): number | null {
  const start = new Date(Math.floor(after / 1000) * 1000 + 1000);
  const day0 = Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate());
  for (let d = 0; d < 366 * 5; d++) {
    const t = new Date(day0 + d * 86_400_000);
    if (!has(c.year, t.getUTCFullYear()) || !has(c.month, t.getUTCMonth() + 1) || !has(c.day, t.getUTCDate())) continue;
    if (c.dow && !c.dow.includes(t.getUTCDay())) continue;
    for (const h of range(c.hour, 23)) for (const m of range(c.minute, 59)) for (const s of range(c.second, 59)) {
      const ms = day0 + d * 86_400_000 + ((h * 60 + m) * 60 + s) * 1000;
      if (ms > after) return ms;
    }
  }
  return null;
}

/** systemd time spans: "15min", "1h 30min", "2d", "90" (seconds). */
export function parseSpan(text: string): number | null {
  const units: Record<string, number> = { us: 0.001, ms: 1, s: 1000, sec: 1000, second: 1000, seconds: 1000, m: 60_000, min: 60_000, minute: 60_000, minutes: 60_000, h: 3_600_000, hr: 3_600_000, hour: 3_600_000, hours: 3_600_000, d: 86_400_000, day: 86_400_000, days: 86_400_000, w: 604_800_000, week: 604_800_000, weeks: 604_800_000 };
  let total = 0;
  const re = /(\d+)\s*([a-z]*)/gi;
  let seen = false;
  const rest = text.replace(re, (all, n: string, u: string) => {
    const f = u ? units[u.toLowerCase()] : 1000;
    if (f === undefined) return all;
    total += Number(n) * f;
    seen = true;
    return '';
  });
  return seen && !rest.trim() ? total : null;
}

/** Human span as systemctl prints it: "1 day 3h", "3h 1min", "5min 18s". */
export function span(ms: number): string {
  let s = Math.max(0, Math.floor(ms / 1000));
  const parts: string[] = [];
  const d = Math.floor(s / 86400); s %= 86400;
  const h = Math.floor(s / 3600); s %= 3600;
  const m = Math.floor(s / 60); s %= 60;
  if (d) parts.push(`${d} day${d > 1 ? 's' : ''}`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}min`);
  if (s && !d) parts.push(`${s}s`);
  return parts.slice(0, 2).join(' ') || '0s';
}

export function dayTime(ms: number): string {
  const d = new Date(Math.floor(ms));
  return `${DAYS[d.getUTCDay()]} ${d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}`;
}

/** When TIMER next elapses, given its runtime (null: no trigger configured or not active). */
export function timerNext(host: Host, timer: string): number | null {
  const l = loadedUnit(host, timer);
  const rt = runtime(host, timer);
  if (!l || rt.state !== 'active') return null;
  const t = l.unit.Timer ?? {};
  const base = Math.max(rt.lastTrigger ?? 0, rt.since);
  const candidates: number[] = [];
  for (const spec of t.OnCalendar ?? []) {
    const c = parseCalendar(spec);
    const n = c && nextElapse(c, base);
    if (n !== null && n !== undefined) candidates.push(n);
  }
  const boot = t.OnBootSec?.at(-1) && parseSpan(t.OnBootSec.at(-1)!);
  if (boot && !rt.lastTrigger) candidates.push(host.bootTime + boot);
  const every = t.OnUnitActiveSec?.at(-1) && parseSpan(t.OnUnitActiveSec.at(-1)!);
  if (every) candidates.push((rt.lastTrigger ?? rt.since) + every);
  return candidates.length ? Math.min(...candidates) : null;
}

export function timerProblems(host: Host, timer: string): string[] {
  const l = loadedUnit(host, timer);
  if (!l) return [];
  const t = l.unit.Timer ?? {};
  const out: string[] = [];
  for (const spec of t.OnCalendar ?? []) if (!parseCalendar(spec)) out.push(`${UNIT_DIR}/${timer}:${lineOf(l.text, spec)}: Failed to parse calendar specification, ignoring: ${spec}`);
  const valid = (t.OnCalendar ?? []).some((s) => parseCalendar(s)) || !!t.OnBootSec?.length || !!t.OnUnitActiveSec?.length || !!t.OnActiveSec?.length;
  if (!valid) out.push(`${timer}: Timer unit lacks value setting. Refusing.`);
  return out;
}

function lineOf(text: string, value: string): number {
  return text.split('\n').findIndex((l) => l.includes(value)) + 1;
}

// ---------------------------------------------------------------------------
// Running services and timers
// ---------------------------------------------------------------------------

const EXIT_NAMES: Record<number, string> = { 0: 'SUCCESS', 1: 'FAILURE', 2: 'INVALIDARGUMENT', 3: 'NOTIMPLEMENTED', 4: 'NOPERMISSION', 5: 'NOTINSTALLED', 6: 'NOTCONFIGURED', 7: 'NOTRUNNING', 203: 'EXEC', 217: 'USER' };
export const exitText = (code: number) => `${code}/${EXIT_NAMES[code] ?? (code > 128 ? 'SIG' : 'FAILURE')}`.replace(/\/SIG$/, '');

/** Split an Exec line the way systemd does: whitespace, quotes; $VAR and ${VAR} from the unit's environment. No shell. */
export function splitExec(line: string, env: Record<string, string>): string[] {
  const out: string[] = [];
  let cur = '';
  let has = false;
  let q: string | null = null;
  const sub = (s: string) => s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, n: string) => env[n] ?? '');
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === q) q = null; else cur += c; continue; }
    if (c === '"' || c === "'") { q = c; has = true; continue; }
    if (c === '\\' && i + 1 < line.length) { cur += line[++i]; continue; }
    if (/\s/.test(c)) { if (cur || has) out.push(cur); cur = ''; has = false; continue; }
    cur += c;
  }
  if (cur || has) out.push(cur);
  // A word that is exactly $VAR is split on whitespace (like systemd); ${VAR} is kept as one argument.
  return out.flatMap((w) => {
    const m = /^\$([A-Za-z_][A-Za-z0-9_]*)$/.exec(w);
    return m ? (env[m[1]] ?? '').split(/\s+/).filter(Boolean) : [sub(w)];
  });
}

function unitEnv(host: Host, unit: UnitFile): { env: Record<string, string>; error?: string } {
  const env: Record<string, string> = {};
  for (const e of unit.Service?.Environment ?? []) {
    for (const m of e.matchAll(/"([^"]*)"|(\S+)/g)) {
      const a = m[1] ?? m[2];
      const i = a.indexOf('=');
      if (i > 0) env[a.slice(0, i)] = a.slice(i + 1);
    }
  }
  for (let f of unit.Service?.EnvironmentFile ?? []) {
    const optional = f.startsWith('-');
    if (optional) f = f.slice(1);
    const text = readFile(host, f);
    if (text === undefined) {
      if (optional) continue;
      return { env, error: f };
    }
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith(';')) continue;
      const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
      if (m) env[m[1]] = m[2].replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
    }
  }
  return { env };
}

const shq = (s: string) => (/^[A-Za-z0-9_./:=@%+,-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

/** Start a oneshot user service now: run ExecStartPre/ExecStart, log like systemd, record the result. */
export function startUserService(world: World, host: Host, name: string): { ok: boolean; message?: string } {
  const l = loadedUnit(host, name);
  if (!l) return { ok: false, message: `Failed to start ${name}: Unit ${name} not found.` };
  const desc = one(l.unit, 'Unit', 'Description') ?? name;
  const label = `${name} - ${desc}`;
  const svc = l.unit.Service ?? {};
  const execs = [...(svc.ExecStartPre ?? []).map((e) => ({ e, pre: true })), ...(svc.ExecStart ?? []).map((e) => ({ e, pre: false }))];
  if (!(svc.ExecStart ?? []).length) {
    log(world, host, 'systemd', `${name}: Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.`, { pid: 1, unit: name, priority: 'err' });
    return { ok: false, message: `Failed to start ${name}: Unit ${name} has a bad unit file setting.\nSee system logs and 'systemctl status ${name}' for details.` };
  }
  const user = one(l.unit, 'Service', 'User') ?? 'root';
  const pid = (host.nextPid += 7);
  const start = world.clock;
  log(world, host, 'systemd', `Starting ${label}...`, { pid: 1, unit: name });
  const fail = (code: number, result: string, step?: string, why?: string, exec = '') => {
    if (step) log(world, host, `(${basename(exec.split(/\s/)[0] || name)})`, `${name}: Failed at step ${step} spawning ${exec.split(/\s/)[0]}: ${why}`, { pid, unit: name, priority: 'err' });
    log(world, host, 'systemd', `${name}: Main process exited, code=exited, status=${exitText(code)}`, { pid: 1, unit: name, priority: 'notice' });
    log(world, host, 'systemd', `${name}: Failed with result '${result}'.`, { pid: 1, unit: name, priority: 'warning' });
    log(world, host, 'systemd', `Failed to start ${label}.`, { pid: 1, unit: name, priority: 'err' });
    // The unit's command ran in the shell, which may have replaced host.units: look the runtime up again.
    Object.assign(runtime(host, name), { state: 'failed', result, since: world.clock, lastRun: { pid, start, end: world.clock, exec: exec || (svc.ExecStart?.at(-1) ?? ''), code } });
    return { ok: false, message: `Job for ${name} failed because the control process exited with error code.\nSee "systemctl status ${name}" and "journalctl -xeu ${name}" for details.` };
  };
  if (!host.users[user]) {
    log(world, host, `(${name.replace(/\.service$/, '')})`, `${name}: Failed to determine user credentials: No such process`, { pid, unit: name, priority: 'err' });
    return fail(217, 'exit-code', 'USER', 'No such process', svc.ExecStart?.at(-1) ?? '');
  }
  const ue = unitEnv(host, l.unit);
  if (ue.error) {
    log(world, host, 'systemd', `${name}: Failed to load environment files: No such file or directory`, { pid: 1, unit: name, priority: 'err' });
    log(world, host, 'systemd', `${name}: Failed to run 'start' task: No such file or directory`, { pid: 1, unit: name, priority: 'err' });
    log(world, host, 'systemd', `${name}: Failed with result 'resources'.`, { pid: 1, unit: name, priority: 'warning' });
    log(world, host, 'systemd', `Failed to start ${label}.`, { pid: 1, unit: name, priority: 'err' });
    Object.assign(runtime(host, name), { state: 'failed', result: 'resources', since: world.clock });
    return { ok: false, message: `Job for ${name} failed because of unavailable resources or another system error.\nSee "systemctl status ${name}" and "journalctl -xeu ${name}" for details.` };
  }
  const u = host.users[user];
  // INVOCATION_ID: systemd marks every service run; there is no terminal to prompt on.
  const env = { HOME: u.home, USER: user, LOGNAME: user, SHELL: u.shell, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8', INVOCATION_ID: sha256Hex(`${name}:${pid}:${start}`).slice(0, 32), ...ue.env };
  const cwd = one(l.unit, 'Service', 'WorkingDirectory') ?? '/';
  let lastExec = '';
  for (const { e } of execs) {
    let line = e;
    let ignore = false;
    while (/^[-@:+!]/.test(line)) { if (line[0] === '-') ignore = true; line = line.slice(1); }
    lastExec = line;
    const argv = splitExec(line, env);
    if (!argv.length || !runner) continue;
    const res = runner.resolve(host, argv[0]);
    if ('error' in res) {
      if (ignore) continue;
      return fail(203, 'exit-code', 'EXEC', res.error, line);
    }
    const ident = basename(argv[0]);
    const r = runner.run(world, host.id, user, argv.map(shq).join(' '), env, host.fs[cwd] ? cwd : '/');
    for (const out of r.out.split('\n').filter((x) => x.length)) log(world, host, ident, out, { pid, unit: name, priority: r.code ? 'err' : 'info' });
    if (r.code !== 0 && !ignore) return fail(r.code, 'exit-code', undefined, undefined, line);
  }
  log(world, host, 'systemd', `${name}: Deactivated successfully.`, { pid: 1, unit: name });
  log(world, host, 'systemd', `Finished ${label}.`, { pid: 1, unit: name });
  Object.assign(runtime(host, name), { state: 'inactive', result: 'success', since: world.clock, lastRun: { pid, start, end: world.clock, exec: lastExec, code: 0 } });
  return { ok: true };
}

/** Activate a timer (systemctl start, enable --now, boot). */
export function startTimer(world: World, host: Host, timer: string, atBoot = false): { ok: boolean; message?: string } {
  const l = loadedUnit(host, timer);
  if (!l) return { ok: false, message: `Failed to start ${timer}: Unit ${timer} not found.` };
  const problems = timerProblems(host, timer);
  for (const p of problems) log(world, host, 'systemd', p, { pid: 1, unit: timer, priority: 'warning' });
  if (problems.some((p) => p.includes('Refusing'))) {
    const rt = runtime(host, timer);
    rt.state = 'failed';
    rt.result = 'resources';
    return { ok: false, message: `Failed to start ${timer}: Unit ${timer} has a bad unit file setting.\nSee system logs and 'systemctl status ${timer}' for details.` };
  }
  const rt = runtime(host, timer);
  if (rt.state === 'active') return { ok: true };
  rt.state = 'active';
  rt.since = world.clock;
  rt.result = 'success';
  const persistent = /^(yes|true|1|on)$/i.test(one(l.unit, 'Timer', 'Persistent') ?? '');
  const stamp = host.fs[`${STAMP_DIR}/stamp-${timer}`];
  if (persistent && stamp) {
    rt.lastTrigger = Math.max(rt.lastTrigger ?? 0, stamp.mtime);
    // A calendar elapse passed while the timer was not running: trigger once as soon as possible.
    const specs = (l.unit.Timer?.OnCalendar ?? []).map(parseCalendar).filter((c): c is CalendarSpec => !!c);
    if (specs.some((c) => { const n = nextElapse(c, stamp.mtime); return n !== null && n <= world.clock; })) rt.catchUp = true;
  }
  if (!atBoot) log(world, host, 'systemd', `Started ${timer} - ${one(l.unit, 'Unit', 'Description') ?? timer}.`, { pid: 1, unit: timer });
  return { ok: true };
}

export function stopTimer(world: World, host: Host, timer: string): void {
  const rt = runtime(host, timer);
  if (rt.state === 'active') log(world, host, 'systemd', `${timer}: Deactivated successfully.`, { pid: 1, unit: timer });
  rt.state = 'inactive';
  rt.since = world.clock;
  rt.catchUp = false;
}

function trigger(world: World, host: Host, timer: string, at: number): void {
  const rt = runtime(host, timer);
  const now = world.clock;
  world.clock = Math.max(at, 0);
  rt.lastTrigger = world.clock;
  rt.catchUp = false;
  const l = loadedUnit(host, timer);
  if (l && /^(yes|true|1|on)$/i.test(one(l.unit, 'Timer', 'Persistent') ?? '')) {
    for (const d of ['/var', '/var/lib', '/var/lib/systemd', STAMP_DIR]) if (!host.fs[d]) mkdir(host, d, world.clock);
    writeFile(host, `${STAMP_DIR}/stamp-${timer}`, '', world.clock, { mode: 0o644 });
  }
  const svc = timerTarget(host, timer);
  if (isUserUnit(host, svc)) startUserService(world, host, svc);
  else log(world, host, 'systemd', `${timer}: Failed to queue unit startup job: Unit ${svc} not found.`, { pid: 1, unit: timer, priority: 'warning' });
  world.clock = Math.max(now, world.clock);
}

let firing = false;
/** Fire every active timer whose next elapse has passed (in order of time), on every Linux host. */
export function runDueTimers(world: World): void {
  if (firing || !runner) return;
  firing = true;
  try {
    for (let guard = 0; guard < 500; guard++) {
      let best: { host: Host; timer: string; at: number } | null = null;
      for (const host of Object.values(world.hosts)) {
        if (!host.units || host.kind === 'windows' || host.kind === 'pfsense' || host.kind === 'container') continue;
        for (const [name, rt] of Object.entries(host.units)) {
          if (!name.endsWith('.timer') || rt.state !== 'active') continue;
          // A missed Persistent= run starts right after the timer was activated (boot or start).
          const at = rt.catchUp ? rt.since + 1_000 : timerNext(host, name);
          if (at === null || at > world.clock) continue;
          if (!best || at < best.at) best = { host, timer: name, at };
        }
      }
      if (!best) break;
      trigger(world, best.host, best.timer, best.at);
    }
  } finally {
    firing = false;
  }
}

/** Boot: every unit is reloaded from disk, services are stopped, enabled timers start (catching up if Persistent). */
export function bootUserUnits(world: World, host: Host): void {
  for (const name of Object.keys(host.units ?? {})) {
    if (!host.fs[`${UNIT_DIR}/${name}`]) { delete host.units![name]; continue; }
    const rt = host.units![name];
    rt.loaded = null;
    rt.state = 'inactive';
    rt.catchUp = false;
  }
  for (const name of userUnits(host)) {
    const rt = runtime(host, name);
    if (name.endsWith('.timer') && rt.enabled && hasInstall(host, name)) startTimer(world, host, name, true);
  }
}
