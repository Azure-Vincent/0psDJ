// systemctl verbs for the administrator's own units in /etc/systemd/system
// (oneshot services and timers, see sim/timers.ts), `systemctl list-timers`
// and `systemd-analyze calendar`.

import { formatEntry } from '../sim/journal';
import {
  type UnitRuntime, UNIT_DIR, dayTime, description, exitText, hasInstall, loadedUnit, nextElapse, normalizedCalendar,
  parseCalendar, runtime, span, startTimer, startUserService, stopTimer, timerNext, timerProblems, timerTarget, triggeredBy, userUnits,
} from '../sim/timers';
import { type CmdCtx, type CommandDef, err, ok } from './types';

const NO_INSTALL = `The unit files have no installation config (WantedBy=, RequiredBy=, Also=,
Alias= settings in the [Install] section, and DefaultInstance= for template
units). This means they are not meant to be enabled or disabled using systemctl.

Possible reasons for having this kind of units are:
• A unit may be statically enabled by being symlinked from another unit's
  .wants/ or .requires/ directory.
• A unit's purpose may be to act as a helper for some other unit which has
  a requirement dependency on it.
• A unit may be started when needed via activation (socket, path, timer,
  D-Bus, udev, scripted systemctl call, ...).
• In case of template units, the unit is meant to be enabled with some
  instance name specified.`;

const changedWarning = (name: string) => `Warning: The unit file, source configuration file or drop-ins of ${name} changed on disk. Run 'systemctl daemon-reload' to reload units.`;

function unitState(rt: UnitRuntime, timer: boolean): { icon: string; active: string } {
  if (rt.state === 'failed') return { icon: '×', active: `failed (Result: ${rt.result})` };
  if (rt.state === 'active') return { icon: '●', active: timer ? 'active (waiting)' : 'active (exited)' };
  return { icon: '○', active: 'inactive (dead)' };
}

function status(ctx: CmdCtx, name: string): { lines: string[]; code: number } {
  const host = ctx.host;
  const l = loadedUnit(host, name)!;
  const rt = runtime(host, name);
  const timer = name.endsWith('.timer');
  const st = unitState(rt, timer);
  const lines: string[] = [];
  if (l.changed) lines.push(changedWarning(name));
  lines.push(`${st.icon} ${name} - ${description(host, name)}`);
  const inst = hasInstall(host, name) ? (rt.enabled ? 'enabled' : 'disabled') + '; preset: enabled' : 'static';
  lines.push(`     Loaded: loaded (${UNIT_DIR}/${name}; ${inst})`);
  const since = rt.since ? ` since ${dayTime(rt.since)}; ${span(ctx.world.clock - rt.since)} ago` : '';
  lines.push(`     Active: ${st.active}${rt.state === 'inactive' && !rt.since ? '' : since}`);
  if (timer) {
    const next = timerNext(host, name);
    lines.push(`    Trigger: ${next !== null ? `${dayTime(next)}; ${span(next - ctx.world.clock)} left` : 'n/a'}`);
    const svc = timerTarget(host, name);
    const srt = host.units?.[svc];
    lines.push(`   Triggers: ${srt?.state === 'failed' ? '×' : '●'} ${svc}`);
  } else {
    const by = triggeredBy(host, name);
    if (by.length) lines.push(`TriggeredBy: ${by.map((t) => `${host.units?.[t]?.state === 'active' ? '●' : '○'} ${t}`).join('\n             ')}`);
    if (rt.lastRun) {
      const r = rt.lastRun;
      lines.push(`    Process: ${r.pid} ExecStart=${r.exec} (code=exited, status=${exitText(r.code)})`, `   Main PID: ${r.pid} (code=exited, status=${exitText(r.code)})`, `        CPU: ${Math.max(12, Math.round((r.end - r.start) / 40))}ms`);
    }
  }
  if (ctx.user.uid === 0 || ctx.user.groups.includes('adm')) {
    const logs = host.journal.filter((e) => e.unit === name).slice(-10);
    if (logs.length) lines.push('', ...logs.map(formatEntry));
  } else lines.push('', 'Hint: You are currently not seeing messages from other users and the system.', '      Users in groups \'adm\', \'systemd-journal\' can see all messages.');
  return { lines, code: rt.state === 'active' ? 0 : 3 };
}

/** A systemctl verb on a user unit; null when NAME is not one (the caller handles packaged services). */
export function userUnitVerb(ctx: CmdCtx, verb: string, name: string, now: boolean): { lines: string[]; code: number } | null {
  const host = ctx.host;
  if (!loadedUnit(host, name)) return null;
  const timer = name.endsWith('.timer');
  const rt = runtime(host, name);
  const needRoot = ['start', 'stop', 'restart', 'enable', 'disable', 'reset-failed'].includes(verb);
  if (needRoot && ctx.user.uid !== 0) return { lines: [`Failed to ${verb} ${name}: Access denied`, `See system logs and 'systemctl status ${name}' for details.`], code: 1 };
  const changed = loadedUnit(host, name)!.changed && ['start', 'restart', 'enable'].includes(verb) ? [changedWarning(name)] : [];
  const start = (): { lines: string[]; code: number } => {
    const r = timer ? startTimer(ctx.world, host, name) : startUserService(ctx.world, host, name);
    return r.ok ? { lines: changed, code: 0 } : { lines: [...changed, r.message ?? `Failed to start ${name}.`], code: 1 };
  };
  switch (verb) {
    case 'status': return status(ctx, name);
    case 'start': return start();
    case 'restart':
      if (timer) stopTimer(ctx.world, host, name);
      return start();
    case 'stop':
      if (timer) stopTimer(ctx.world, host, name);
      else if (rt.state === 'failed') { rt.state = 'inactive'; }
      return { lines: [], code: 0 };
    case 'enable': {
      if (!hasInstall(host, name)) return { lines: [NO_INSTALL], code: 0 };
      const lines = [...changed];
      const target = loadedUnit(host, name)!.unit.Install?.WantedBy?.at(-1) ?? 'timers.target';
      if (!rt.enabled) lines.push(`Created symlink ${UNIT_DIR}/${target}.wants/${name} → ${UNIT_DIR}/${name}.`);
      rt.enabled = true;
      if (now) { const r = start(); lines.push(...r.lines.filter((x) => !changed.includes(x))); return { lines, code: r.code }; }
      return { lines, code: 0 };
    }
    case 'disable': {
      const lines: string[] = [];
      const target = loadedUnit(host, name)!.unit.Install?.WantedBy?.at(-1) ?? 'timers.target';
      if (rt.enabled) lines.push(`Removed "${UNIT_DIR}/${target}.wants/${name}".`);
      rt.enabled = false;
      if (now && timer) stopTimer(ctx.world, host, name);
      return { lines, code: 0 };
    }
    case 'is-active': return { lines: [rt.state === 'active' ? 'active' : rt.state], code: rt.state === 'active' ? 0 : 3 };
    case 'is-enabled': return hasInstall(host, name) ? { lines: [rt.enabled ? 'enabled' : 'disabled'], code: rt.enabled ? 0 : 1 } : { lines: ['static'], code: 0 };
    case 'is-failed': return { lines: [rt.state], code: rt.state === 'failed' ? 0 : 1 };
    case 'reset-failed': if (rt.state === 'failed') { rt.state = 'inactive'; rt.result = 'success'; } return { lines: [], code: 0 };
    case 'cat': return { lines: [`# ${UNIT_DIR}/${name}`, (loadedUnit(host, name)!.text).replace(/\n$/, '')], code: 0 };
    case 'list-dependencies': return { lines: [name, timer ? `● ├─sysinit.target\n● └─time-set.target` : '● ├─system.slice\n● └─sysinit.target'], code: 0 };
    default: return null;
  }
}

export function listTimers(ctx: CmdCtx, all: boolean): string {
  const host = ctx.host;
  const now = ctx.world.clock;
  const rows: string[][] = [];
  for (const name of userUnits(host).filter((u) => u.endsWith('.timer'))) {
    const rt = runtime(host, name);
    if (!loadedUnit(host, name) || (rt.state !== 'active' && !all)) continue;
    const next = timerNext(host, name);
    rows.push([
      next !== null ? dayTime(next) : 'n/a',
      next !== null ? `${span(next - now)} left` : 'n/a',
      rt.lastTrigger ? dayTime(rt.lastTrigger) : 'n/a',
      rt.lastTrigger ? `${span(now - rt.lastTrigger)} ago` : 'n/a',
      name,
      timerTarget(host, name),
    ]);
  }
  rows.sort((a, b) => (a[0] === 'n/a' ? 1 : b[0] === 'n/a' ? -1 : a[0].localeCompare(b[0])));
  const head = ['NEXT', 'LEFT', 'LAST', 'PASSED', 'UNIT', 'ACTIVATES'];
  const w = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  const fmt = (r: string[]) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(w[i]))).join(' ');
  const out = [fmt(head), ...rows.map(fmt), '', `${rows.length} timers listed.`];
  if (!all) out.push('Pass --all to see loaded but inactive timers, too.');
  out.push('(The simulator lists the timers written in /etc/systemd/system; Debian\'s own timers such as apt-daily.timer and logrotate.timer are not modelled.)');
  return out.join('\n');
}

/** list-units rows for the administrator's units that systemd currently tracks. */
export function userUnitRows(ctx: CmdCtx, failedOnly: boolean, all: boolean): string[][] {
  const rows: string[][] = [];
  for (const name of userUnits(ctx.host)) {
    const rt = ctx.host.units?.[name];
    if (!rt || rt.loaded === null) continue;
    if (failedOnly ? rt.state !== 'failed' : rt.state === 'inactive' && !all) continue;
    const sub = rt.state === 'active' ? (name.endsWith('.timer') ? 'waiting' : 'exited') : rt.state === 'failed' ? 'failed' : 'dead';
    rows.push([rt.state === 'failed' ? '●' : ' ', name, 'loaded', rt.state, sub, description(ctx.host, name)]);
  }
  return rows;
}

export const systemdAnalyze: CommandDef = {
  name: 'systemd-analyze',
  summary: 'analyze and debug systemd (calendar expressions, unit files)',
  usage: 'systemd-analyze calendar [--iterations=N] "SPEC" | systemd-analyze verify UNIT-FILE...',
  run(args, ctx) {
    const [verb, ...rest] = args;
    if (verb === 'calendar') {
      const it = Number(rest.find((a) => a.startsWith('--iterations='))?.split('=')[1] ?? 1);
      const specs = rest.filter((a) => !a.startsWith('--'));
      if (!specs.length) return err('Expected at least one calendar specification.', 1);
      const out: string[] = [];
      for (const s of specs) {
        const c = parseCalendar(s);
        if (!c) return err(`Failed to parse calendar specification '${s}': Invalid argument`, 1);
        if (out.length) out.push('');
        out.push(`  Original form: ${s}`, `Normalized form: ${normalizedCalendar(c)}`);
        let t = ctx.world.clock;
        for (let i = 0; i < Math.max(1, it); i++) {
          const n = nextElapse(c, t);
          if (n === null) { out.push('    Next elapse: never'); break; }
          out.push(`${i === 0 ? '    Next elapse' : `       Iter. #${i + 1}`}: ${dayTime(n)}`);
          if (i === 0) out.push(`       From now: ${span(n - ctx.world.clock)} left`);
          t = n;
        }
      }
      return ok(out.join('\n'));
    }
    if (verb === 'verify') {
      const out: string[] = [];
      for (const f of rest) {
        const name = f.split('/').pop()!;
        const text = ctx.host.fs[f]?.content;
        if (text === undefined) { out.push(`Failed to prepare filename ${f}: No such file or directory`); continue; }
        if (name.endsWith('.timer')) {
          const save = ctx.host.units?.[name];
          runtime(ctx.host, name).loaded = text;
          out.push(...timerProblems(ctx.host, name));
          if (save) ctx.host.units![name] = save; else delete ctx.host.units![name];
        }
        if (name.endsWith('.service') && !/^ExecStart=/m.test(text)) out.push(`${name}: Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.`);
      }
      return { out: out.join('\n'), code: out.length ? 1 : 0 };
    }
    return err(`Unknown command verb '${verb ?? ''}'.\n(The simulator supports: calendar, verify)`, 1);
  },
};
