// rsyslog 8.2302 (Debian 12). rsyslogd reads new journal entries (imuxsock /
// imjournal), runs them through the rules of /etc/rsyslog.conf and its includes
// (facility.priority selectors, property filters, "& stop"), writes files
// (static paths or templates such as /var/log/remote/%HOSTNAME%/syslog.log) and
// forwards to other hosts over UDP (@host) or TCP (@@host, action(type="omfwd")).
// Receivers listen with imudp / imtcp.
//
// Forwarding is queued and sent by syslogFlush(), which runs before every shell
// command and before checks: the daemon works in the background. A TCP action
// that cannot connect is suspended (rsyslog's messages), and what was queued
// for it is lost unless the action has a queue (queue.type="LinkedList").

import { mkdir, readFile, writeFile } from '../fs';
import { isIpAddress } from '../net/addr';
import type { Host, LogEntry, Packet, ServiceRuntime, World } from '../types';
import { resolve } from './dns';
import { journalHooks, log } from './journal';
import { nextId, sendIcmpError, sourceAddress, transmit } from './network';
import { findListener } from './services';
import { tcpConnect } from './tcp';
import { withRecorder } from './trace';

export const RSYSLOG_VERSION = '8.2302.0';
export const RSYSLOG_CONF = '/etc/rsyslog.conf';

const FACILITIES = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'security', 'console', 'solaris-cron', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
export const SEVERITIES: LogEntry['priority'][] = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];
const SEV_ALIASES: Record<string, LogEntry['priority']> = { error: 'err', warn: 'warning', panic: 'emerg' };

export const severityOf = (name: string): LogEntry['priority'] | undefined => (SEVERITIES as string[]).includes(name) ? name as LogEntry['priority'] : SEV_ALIASES[name];
export const isFacility = (name: string) => FACILITIES.includes(name);

/** The facility a program logs to (sshd: auth; sudo, su, login: authpriv; kernel: kern; cron: cron). */
export function facilityOf(e: LogEntry): string {
  if (e.facility) return e.facility;
  const id = e.ident.toLowerCase();
  if (id === 'sshd') return 'auth';
  if (['sudo', 'su', 'login', 'systemd-logind', 'polkitd', 'passwd', 'chage', 'useradd', 'usermod'].includes(id) || id.startsWith('pam')) return 'authpriv';
  if (id === 'kernel') return 'kern';
  if (id === 'cron' || id === 'crond') return 'cron';
  if (id === 'rsyslogd') return 'syslog';
  return 'daemon';
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

interface Selector { facilities: string[] | '*'; mode: 'atleast' | 'exactly' | 'not' | 'none'; severity: number }
type Filter =
  | { kind: 'selector'; selectors: Selector[] }
  | { kind: 'property'; prop: string; op: string; negate: boolean; value: string };

export type SyslogAction =
  | { kind: 'file'; path: string }
  | { kind: 'dynafile'; template: string }
  | { kind: 'fwd'; proto: 'udp' | 'tcp'; target: string; port: number; queued: boolean; id: number }
  | { kind: 'stop' }
  | { kind: 'usrmsg' };

export interface SyslogRule { filter: Filter; actions: SyslogAction[]; line: number; file: string }

export interface FwdState { suspended: boolean; pending: SyslogMessage[]; errorLogged?: string; /** Address resolved when the connection was opened (rsyslog keeps it until it reconnects). */ ip?: string }

export interface RsyslogLoaded {
  rules: SyslogRule[];
  templates: Record<string, string>;
  inputs: { udp?: number; tcp?: number };
  errors: string[];
  fwd: Record<number, FwdState>;
}

export interface SyslogMessage { time: number; hostname: string; program: string; pid: number | null; facility: string; severity: LogEntry['priority']; text: string; fromIp: string }

const KNOWN_LEGACY = new Set(['$fileowner', '$filegroup', '$filecreatemode', '$dircreatemode', '$umask', '$workdirectory', '$actionfiledefaulttemplate', '$repeatedmsgreduction', '$privdroptouser', '$privdroptogroup', '$modload', '$udpserverrun', '$inputtcpserverrun', '$includeconfig', '$template', '$actionqueuetype', '$actionqueuefilename', '$actionresumeretrycount', '$actionqueuesavedonshutdown', '$actionqueuemaxdiskspace', '$systemlogratelimitinterval', '$maxmessagesize']);

const kv = (s: string) => Object.fromEntries([...s.matchAll(/([\w.]+)\s*=\s*"([^"]*)"/g)].map((m) => [m[1].toLowerCase(), m[2]]));

function parseSelectors(text: string): Selector[] | null {
  const out: Selector[] = [];
  for (const part of text.split(';')) {
    const m = /^([\w*,-]+)\.(!?=?)([\w*]+)$/.exec(part.trim());
    if (!m) return null;
    const facs = m[1] === '*' ? '*' : m[1].split(',');
    if (facs !== '*' && !facs.every(isFacility)) return null;
    let mode: Selector['mode'] = m[2] === '=' ? 'exactly' : m[2] === '!' || m[2] === '!=' ? 'not' : 'atleast';
    let severity = 7;
    if (m[3] === 'none') mode = 'none';
    else if (m[3] !== '*') {
      const sev = severityOf(m[3]);
      if (!sev) return null;
      severity = SEVERITIES.indexOf(sev);
    }
    out.push({ facilities: facs, mode, severity });
  }
  return out;
}

function parseAction(text: string, nextId: () => number): SyslogAction | null {
  const t = text.trim();
  if (t === 'stop' || t === '~') return { kind: 'stop' };
  if (t.startsWith(':omusrmsg:')) return { kind: 'usrmsg' };
  if (t.startsWith('?')) return { kind: 'dynafile', template: t.slice(1).split(';')[0] };
  const file = /^-?(\/\S+)/.exec(t);
  if (file) return { kind: 'file', path: file[1] };
  const fwd = /^(@@?)(\(o\))?\[?([\w.:-]+?)\]?(?::(\d+))?(;\S+)?$/.exec(t);
  if (fwd) return { kind: 'fwd', proto: fwd[1] === '@@' ? 'tcp' : 'udp', target: fwd[3], port: Number(fwd[4] ?? 514), queued: false, id: nextId() };
  const act = /^action\((.*)\)$/s.exec(t);
  if (act) {
    const a = kv(act[1]);
    if (a.type === 'omfwd') return { kind: 'fwd', proto: (a.protocol ?? 'udp') === 'tcp' ? 'tcp' : 'udp', target: a.target ?? '', port: Number(a.port ?? 514), queued: !!a['queue.type'] && a['queue.type'].toLowerCase() !== 'direct', id: nextId() };
    if (a.type === 'omfile') return a.dynafile ? { kind: 'dynafile', template: a.dynafile } : { kind: 'file', path: a.file ?? '' };
  }
  return null;
}

/** Split a file into statements: RainerScript blocks with parentheses may span lines. */
function statements(text: string): { text: string; line: number }[] {
  const out: { text: string; line: number }[] = [];
  let cur = '';
  let start = 0;
  let depth = 0;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line && !cur) return;
    if (!cur) start = i + 1;
    cur = cur ? `${cur} ${line}` : line;
    depth += (line.match(/\(/g) ?? []).length - (line.match(/\)/g) ?? []).length;
    if (depth <= 0) { if (cur) out.push({ text: cur, line: start }); cur = ''; depth = 0; }
  });
  if (cur) out.push({ text: cur, line: start });
  return out;
}

/** Glob for "$IncludeConfig /etc/rsyslog.d/*.conf" in the simulated filesystem (sorted, like rsyslog). */
function includeFiles(host: Host, pattern: string): string[] {
  const dir = pattern.slice(0, pattern.lastIndexOf('/'));
  const glob = pattern.slice(pattern.lastIndexOf('/') + 1);
  const re = new RegExp(`^${glob.replace(/\./g, '\\.').replace(/\*/g, '[^/]*')}$`);
  return Object.keys(host.fs).filter((p) => p.startsWith(dir + '/') && !p.slice(dir.length + 1).includes('/') && re.test(p.slice(dir.length + 1)) && host.fs[p].type === 'file').sort();
}

/** Parse rsyslog.conf and its includes the way rsyslogd does: bad lines are reported and skipped. */
export function loadRsyslog(host: Host): RsyslogLoaded {
  const loaded: RsyslogLoaded = { rules: [], templates: {}, inputs: {}, errors: [], fwd: {} };
  let ids = 0;
  const nextAction = () => ++ids;
  const modules = new Set<string>(['builtin:omfile', 'builtin:omfwd']);
  const visit = (file: string) => {
    const text = readFile(host, file);
    if (text === undefined) return;
    let last: SyslogRule | null = null;
    for (const st of statements(text)) {
      const s = st.text;
      const err = (msg: string, code: number) => loaded.errors.push(`${msg} [v${RSYSLOG_VERSION} try https://www.rsyslog.com/e/${code} ]`);
      const low = s.toLowerCase();
      if (low.startsWith('module(')) {
        const a = kv(s);
        if (a.load) modules.add(a.load);
        continue;
      }
      if (low.startsWith('input(')) {
        const a = kv(s);
        if (!modules.has(a.type)) { err(`input module name '${a.type}' is unknown`, 2209); continue; }
        if (a.type === 'imudp') loaded.inputs.udp = Number(a.port ?? 514);
        if (a.type === 'imtcp') loaded.inputs.tcp = Number(a.port ?? 514);
        continue;
      }
      if (low.startsWith('include(')) { const a = kv(s); for (const f of includeFiles(host, a.file ?? '')) visit(f); continue; }
      if (low.startsWith('template(')) { const a = kv(s); if (a.name) loaded.templates[a.name] = a.string ?? ''; continue; }
      if (low.startsWith('global(') || low.startsWith('main_queue(')) continue;
      if (s.startsWith('$')) {
        const [d, ...rest] = s.split(/\s+/);
        const arg = rest.join(' ');
        const dl = d.toLowerCase();
        if (!KNOWN_LEGACY.has(dl) && !dl.startsWith('$template')) { err(`invalid or yet-unknown config file command '${d.slice(1)}' - have you forgotten to load a module?`, 3003); continue; }
        if (dl === '$modload') modules.add(arg.trim());
        if (dl === '$udpserverrun') { if (modules.has('imudp')) loaded.inputs.udp = Number(arg); else err(`invalid or yet-unknown config file command 'UDPServerRun' - have you forgotten to load a module?`, 3003); }
        if (dl === '$inputtcpserverrun') { if (modules.has('imtcp')) loaded.inputs.tcp = Number(arg); else err(`invalid or yet-unknown config file command 'InputTCPServerRun' - have you forgotten to load a module?`, 3003); }
        if (dl === '$includeconfig') for (const f of includeFiles(host, arg.trim())) visit(f);
        if (dl === '$template') { const m = /^(\w+)\s*,\s*"([^"]*)"/.exec(arg); if (m) loaded.templates[m[1]] = m[2]; }
        continue;
      }
      if (s.startsWith('&')) {
        const a = parseAction(s.slice(1), nextAction);
        if (!a || !last) { err(`error during parsing file ${file}, on or before line ${st.line}: invalid action`, 2207); continue; }
        last.actions.push(a);
        continue;
      }
      if (s.startsWith(':')) {
        const m = /^:([\w-]+)\s*,\s*(!?)(\w+)\s*,\s*"([^"]*)"\s+(.+)$/.exec(s);
        const a = m ? parseAction(m[5], nextAction) : null;
        if (!m || !a) { err(`error during parsing file ${file}, on or before line ${st.line}: syntax error`, 2207); continue; }
        last = { filter: { kind: 'property', prop: m[1].toLowerCase(), negate: m[2] === '!', op: m[3].toLowerCase(), value: m[4] }, actions: [a], line: st.line, file };
        loaded.rules.push(last);
        continue;
      }
      const m = /^(\S+)\s+(.+)$/.exec(s);
      const sel = m ? parseSelectors(m[1]) : null;
      const a = m ? parseAction(m[2], nextAction) : null;
      if (!sel || !a) { err(`error during parsing file ${file}, on or before line ${st.line}: syntax error`, 2207); continue; }
      last = { filter: { kind: 'selector', selectors: sel }, actions: [a], line: st.line, file };
      loaded.rules.push(last);
    }
  };
  visit(RSYSLOG_CONF);
  for (const r of loaded.rules) for (const a of r.actions) if (a.kind === 'fwd') loaded.fwd[a.id] = { suspended: false, pending: [] };
  return loaded;
}

function matches(f: Filter, m: SyslogMessage): boolean {
  if (f.kind === 'property') {
    const v = f.prop === 'fromhost-ip' ? m.fromIp : f.prop === 'hostname' || f.prop === 'fromhost' ? m.hostname : f.prop === 'programname' ? m.program : m.text;
    const r = f.op === 'isequal' ? v === f.value : f.op === 'contains' ? v.includes(f.value) : f.op === 'startswith' ? v.startsWith(f.value) : f.op === 'regex' ? new RegExp(f.value).test(v) : false;
    return f.negate ? !r : r;
  }
  // Later selectors override earlier ones for the facilities they name.
  let sel = false;
  const sev = SEVERITIES.indexOf(m.severity);
  for (const s of f.selectors) {
    if (s.facilities !== '*' && !s.facilities.includes(m.facility)) continue;
    if (s.mode === 'none') sel = false;
    else if (s.mode === 'exactly') sel = sev === s.severity;
    else if (s.mode === 'not') sel = sev > s.severity;
    else sel = sev <= s.severity;
  }
  return sel;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function rfc3164Time(ms: number): string {
  const d = new Date(Math.floor(ms));
  const p = (n: number) => String(n).padStart(2, '0');
  return `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

/** RSYSLOG_TraditionalFileFormat: "Oct 19 08:31:12 srv01 sshd[1234]: message". */
export const fileLine = (m: SyslogMessage) => `${rfc3164Time(m.time)} ${m.hostname} ${m.program}${m.pid !== null ? `[${m.pid}]` : ''}: ${m.text}`;

const pri = (m: SyslogMessage) => FACILITIES.indexOf(m.facility) * 8 + SEVERITIES.indexOf(m.severity);

function expandTemplate(t: string, m: SyslogMessage): string {
  const d = new Date(Math.floor(m.time)).toISOString();
  return t.replace(/%([$\w-]+)%/g, (_x, k: string) => {
    switch (k.toUpperCase()) {
      case 'HOSTNAME': case 'FROMHOST': return m.hostname;
      case 'FROMHOST-IP': return m.fromIp;
      case 'PROGRAMNAME': return m.program;
      case 'SYSLOGFACILITY-TEXT': return m.facility;
      case '$YEAR': return d.slice(0, 4);
      case '$MONTH': return d.slice(5, 7);
      case '$DAY': return d.slice(8, 10);
      default: return '';
    }
  });
}

function appendLine(host: Host, path: string, line: string, t: number): void {
  const dir = path.slice(0, path.lastIndexOf('/')) || '/';
  const parts = dir.split('/').filter(Boolean);
  for (let i = 1; i <= parts.length; i++) {
    const p = '/' + parts.slice(0, i).join('/');
    if (!host.fs[p]) mkdir(host, p, t, { mode: 0o755 });
  }
  const prev = readFile(host, path);
  writeFile(host, path, (prev ?? '') + line + '\n', t, prev === undefined ? { mode: 0o640, owner: 'root', group: 'adm' } : undefined);
}

/** Run one message through the rules (local journal entries and messages received from the network). */
export function processMessage(host: Host, l: RsyslogLoaded, m: SyslogMessage): void {
  for (const r of l.rules) {
    if (!matches(r.filter, m)) continue;
    for (const a of r.actions) {
      if (a.kind === 'stop') return;
      if (a.kind === 'file') appendLine(host, a.path, fileLine(m), m.time);
      else if (a.kind === 'dynafile') {
        const t = l.templates[a.template];
        if (t !== undefined) appendLine(host, expandTemplate(t, m), fileLine(m), m.time);
      } else if (a.kind === 'fwd') {
        const st = l.fwd[a.id];
        // A suspended action without a queue discards what arrives meanwhile (the default "direct" queue).
        if (st && (!st.suspended || a.queued) && st.pending.length < 10_000) st.pending.push(m);
      }
    }
  }
}

journalHooks.onLog = (_world, host, e) => {
  const rt = host.services.rsyslog;
  if (rt?.state !== 'active' || !rt.loaded) return;
  processMessage(host, rt.loaded as RsyslogLoaded, { time: e.time, hostname: host.hostname, program: e.ident, pid: e.pid, facility: facilityOf(e), severity: e.priority, text: e.message, fromIp: '127.0.0.1' });
};

// ---------------------------------------------------------------------------
// The daemon and forwarding
// ---------------------------------------------------------------------------

export function rsyslogStart(world: World, host: Host, rt: ServiceRuntime, pid: number): boolean {
  const l = loadRsyslog(host);
  rt.loaded = l;
  const opts = { pid, unit: 'rsyslog.service' };
  log(world, host, 'rsyslogd', `imuxsock: Acquired UNIX socket '/run/systemd/journal/syslog' (fd 3) from systemd.  [v${RSYSLOG_VERSION}]`, opts);
  for (const e of l.errors) log(world, host, 'rsyslogd', e, { ...opts, priority: 'err' });
  log(world, host, 'rsyslogd', `[origin software="rsyslogd" swVersion="${RSYSLOG_VERSION}" x-pid="${pid}" x-info="https://www.rsyslog.com"] start`, opts);
  return true;
}

export function rsyslogListeners(rt: ServiceRuntime): { proto: 'udp' | 'tcp'; port: number }[] {
  const l = rt.loaded as RsyslogLoaded | null;
  const out: { proto: 'udp' | 'tcp'; port: number }[] = [];
  if (l?.inputs.udp) out.push({ proto: 'udp', port: l.inputs.udp });
  if (l?.inputs.tcp) out.push({ proto: 'tcp', port: l.inputs.tcp });
  return out;
}

const actionName = (id: number) => `action-${id}-builtin:omfwd`;

function suspend(world: World, host: Host, rt: ServiceRuntime, a: SyslogAction & { kind: 'fwd' }, st: FwdState, reason: string): void {
  if (!a.queued) st.pending = [];
  st.ip = undefined;
  if (st.suspended && st.errorLogged === reason) return;
  st.suspended = true;
  st.errorLogged = reason;
  const opts = { pid: rt.pid, unit: 'rsyslog.service', priority: 'err' as const };
  log(world, host, 'rsyslogd', `${reason} [v${RSYSLOG_VERSION} try https://www.rsyslog.com/e/2027 ]`, opts);
  log(world, host, 'rsyslogd', `action '${actionName(a.id)}' suspended (module 'builtin:omfwd'), retry 0. There should be messages before this one giving the reason for suspension. [v${RSYSLOG_VERSION} try https://www.rsyslog.com/e/2007 ]`, { ...opts, priority: 'warning' });
}

/** Deliver messages that arrived on a receiver's imudp/imtcp input. */
function receive(rcv: Host, fromIp: string, msgs: SyslogMessage[]): void {
  const l = rcv.services.rsyslog?.loaded as RsyslogLoaded | undefined;
  if (!l) return;
  for (const m of msgs) processMessage(rcv, l, { ...m, fromIp });
}

function flushAction(world: World, host: Host, rt: ServiceRuntime, a: SyslogAction & { kind: 'fwd' }, st: FwdState): void {
  const msgs = st.pending;
  let ip = isIpAddress(a.target) ? a.target : st.ip;
  if (!ip) {
    const r = resolve(world, host, a.target, { family: 4 });
    if (!r.ok) return suspend(world, host, rt, a, st, `omfwd: could not get addrinfo for hostname '${a.target}':'${a.port}': Name or service not known`);
    ip = r.ip;
    st.ip = ip;
  }
  if (a.proto === 'udp') {
    st.pending = [];
    for (const m of msgs) {
      const text = `<${pri(m)}>${rfc3164Time(m.time)} ${m.hostname} ${m.program}${m.pid !== null ? `[${m.pid}]` : ''}: ${m.text}`;
      const p: Packet = {
        id: nextId(world), src: sourceAddress(host, ip), dst: ip, ttl: 64, proto: 'udp',
        udp: { sport: 40000 + (world.counter % 20000), dport: a.port, len: text.length },
        app: { protocol: 'SYSLOG', info: `${m.facility}.${m.severity}`, fields: [{ name: 'Message', value: text }] },
      };
      const d = transmit(world, host.id, p);
      if (d.status !== 'delivered') continue; // UDP: lost without a trace
      const rcv = world.hosts[d.host];
      const lis = findListener(rcv, 'udp', d.final.dst, a.port);
      if (lis?.process === 'rsyslogd') receive(rcv, d.final.src, [m]);
      // Nothing listening: the kernel answers with ICMP port unreachable, which rsyslog ignores.
      else if (!lis) sendIcmpError(world, rcv, d.final, 'port-unreachable');
    }
    return;
  }
  const c = tcpConnect(world, host, ip, a.port, { timeoutMs: 5000 });
  if (!c.ok) {
    const why = c.errno === 'ECONNREFUSED' ? 'Connection refused' : c.errno === 'ETIMEDOUT' ? 'Connection timed out' : c.errno === 'EHOSTUNREACH' ? 'No route to host' : 'Network is unreachable';
    return suspend(world, host, rt, a, st, `cannot connect to ${a.target}:${a.port}: ${why}`);
  }
  const conn = c.conn;
  const lis = findListener(conn.server, 'tcp', conn.sv.local, a.port);
  conn.send('c2s', msgs.reduce((n, m) => n + m.text.length + 40, 0), { protocol: 'SYSLOG', info: `${msgs.length} syslog message(s), octet-counted framing`, fields: [] });
  conn.close('client');
  if (lis?.process === 'rsyslogd') receive(conn.server, conn.sv.peer, msgs);
  st.pending = [];
  if (st.suspended) {
    st.suspended = false;
    st.errorLogged = undefined;
    log(world, host, 'rsyslogd', `action '${actionName(a.id)}' resumed (module 'builtin:omfwd') [v${RSYSLOG_VERSION} try https://www.rsyslog.com/e/2359 ]`, { pid: rt.pid, unit: 'rsyslog.service' });
  }
}

/**
 * Send what the rsyslog daemons have queued for other hosts. Runs before every
 * command and before checks; it never moves the world clock (it happens in the
 * background). Messages logged while flushing (rsyslog's own errors) wait for
 * the next round.
 */
export function syslogFlush(world: World): void {
  // Background traffic: it shows in captures, never in the step-by-step trace of what the user runs.
  withRecorder(null, () => flushAll(world));
}

function flushAll(world: World): void {
  const start = world.clock;
  for (const host of Object.values(world.hosts)) {
    const rt = host.services.rsyslog;
    if (rt?.state !== 'active' || !rt.loaded) continue;
    const l = rt.loaded as RsyslogLoaded;
    for (const r of l.rules) for (const a of r.actions) {
      if (a.kind !== 'fwd') continue;
      const st = l.fwd[a.id];
      if (!st) continue;
      if (!st.pending.length && !st.suspended) continue;
      flushAction(world, host, rt, a, st);
    }
  }
  world.clock = start;
}

/** logger -n SERVER: send one message straight to a syslog server (UDP by default, -T for TCP). */
export function sendSyslog(world: World, host: Host, proto: 'udp' | 'tcp', target: string, port: number, m: SyslogMessage): string | null {
  const start = world.clock;
  try {
    let ip = isIpAddress(target) ? target : undefined;
    if (!ip) {
      const r = resolve(world, host, target, { family: 4 });
      if (!r.ok) return `logger: failed to connect to ${target} port ${port}`;
      ip = r.ip;
    }
    if (proto === 'udp') {
      const text = `<${pri(m)}>${rfc3164Time(m.time)} ${m.hostname} ${m.program}: ${m.text}`;
      const p: Packet = {
        id: nextId(world), src: sourceAddress(host, ip), dst: ip, ttl: 64, proto: 'udp',
        udp: { sport: 40000 + (world.counter % 20000), dport: port, len: text.length },
        app: { protocol: 'SYSLOG', info: `${m.facility}.${m.severity}`, fields: [{ name: 'Message', value: text }] },
      };
      const d = transmit(world, host.id, p);
      if (d.status === 'delivered') {
        const rcv = world.hosts[d.host];
        if (findListener(rcv, 'udp', d.final.dst, port)?.process === 'rsyslogd') receive(rcv, d.final.src, [m]);
      }
      return null;
    }
    const c = tcpConnect(world, host, ip, port, { timeoutMs: 5000 });
    if (!c.ok) return `logger: failed to connect to ${target} port ${port}`;
    c.conn.send('c2s', m.text.length + 40, { protocol: 'SYSLOG', info: '1 syslog message, octet-counted framing', fields: [] });
    c.conn.close('client');
    if (findListener(c.conn.server, 'tcp', c.conn.sv.local, port)?.process === 'rsyslogd') receive(c.conn.server, c.conn.sv.peer, [m]);
    return null;
  } finally {
    world.clock = Math.max(world.clock, start);
  }
}
