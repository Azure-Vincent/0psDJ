// chronyc: chronyd's command-line client (chrony 4.3). It talks to the daemon
// over its Unix socket (root) or UDP 127.0.0.1:323; reporting commands work for
// everyone, clients and makestep need root.

import { chronySync, type ChronyLoaded, type ChronySource } from '../sim/ntp';
import { type CommandDef, err, ok } from './types';

/** chronyc's compact offsets: +312ns, -1520us, +12ms, +600s. */
function fmtOffset(ms: number): string {
  const sign = ms < 0 ? '-' : '+';
  const a = Math.abs(ms);
  if (a < 0.001) return `${sign}${Math.round(a * 1e6)}ns`;
  if (a < 10) return `${sign}${Math.round(a * 1000)}us`;
  if (a < 10_000) return `${sign}${Math.round(a)}ms`;
  return `${sign}${Math.round(a / 1000)}s`;
}

/** chronyc's compact intervals: 35, 17m, 4h, 3d. */
function ago(ms: number): string {
  const sec = Math.max(1, Math.round(ms / 1000));
  if (sec < 1000) return String(sec);
  if (sec < 60 * 1000) return `${Math.round(sec / 60)}m`;
  if (sec < 3600 * 100) return `${Math.round(sec / 3600)}h`;
  return `${Math.round(sec / 86400)}d`;
}

function ctime(ms: number): string {
  const d = new Date(Math.floor(ms));
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.toUTCString().slice(0, 3)} ${d.toUTCString().slice(8, 11)} ${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} ${d.getUTCFullYear()}`;
}

const SOURCES_LEGEND = `  .-- Source mode  '^' = server, '=' = peer, '#' = local clock.
 / .- Source state '*' = current best, '+' = combined, '-' = not combined,
| /             'x' = may be in error, '~' = too variable, '?' = unusable.
||                                                 .- xxxx [ yyyy ] +/- zzzz
||      Reachability register (octal) -.           |  xxxx = adjusted offset,
||      Log2(Polling interval) --.      |          |  yyyy = measured offset,
||                                \\     |          |  zzzz = estimated error.
||                                 |    |           \\`;

export const chronyc: CommandDef = {
  name: 'chronyc',
  summary: 'chrony control: tracking, sources, activity, clients, makestep',
  usage: 'chronyc tracking | sources [-v] | activity | clients | makestep',
  run(args, ctx) {
    const rt = ctx.host.services.chrony;
    if (!rt) return err('-bash: chronyc: command not found', 127);
    const sub = args.find((a) => !a.startsWith('-')) ?? 'tracking';
    if (rt.state !== 'active' || !rt.loaded) return err('506 Cannot talk to daemon', 1);
    const l = rt.loaded as ChronyLoaded;
    const root = ctx.user.uid === 0;
    const now = ctx.world.clock;
    switch (sub) {
      case 'tracking': {
        const sel = l.sources.find((s) => s.state === '*');
        const sysMs = sel && Math.abs(sel.offsetMs) >= 1 ? -sel.offsetMs : 0.000312;
        const local = !l.synced && l.localStratum !== undefined;
        return ok([
          `Reference ID    : ${local ? '7F7F0101' : l.refId} (${l.synced ? l.refName : ''})`,
          `Stratum         : ${l.synced ? l.stratum : local ? l.localStratum : 0}`,
          `Ref time (UTC)  : ${l.synced ? ctime(now - ((now - l.refTime) % 64_000)) : 'Thu Jan 01 00:00:00 1970'}`,
          `System time     : ${(Math.abs(sysMs) / 1000).toFixed(9)} seconds ${sysMs >= 0 ? 'fast' : 'slow'} of NTP time`,
          `Last offset     : ${l.synced ? '-0.000000187' : '+0.000000000'} seconds`,
          `RMS offset      : ${l.synced ? '0.000002104' : '0.000000000'} seconds`,
          'Frequency       : 4.112 ppm slow',
          `Residual freq   : ${l.synced ? '-0.001' : '+0.000'} ppm`,
          `Skew            : ${l.synced ? '0.035' : '0.000'} ppm`,
          `Root delay      : ${l.synced ? (l.refclock ? '0.000000001' : '0.001834517') : '1.000000000'} seconds`,
          `Root dispersion : ${l.synced ? '0.000412213' : '1.000000000'} seconds`,
          `Update interval : ${l.synced ? '64.2' : '0.0'} seconds`,
          `Leap status     : ${l.synced || local ? 'Normal' : 'Not synchronised'}`,
        ].join('\n'));
      }
      case 'sources': {
        // chronyd polls every 64 s: between two of our polls the report shows what a running daemon would.
        const POLL = 64_000;
        const row = (s: ChronySource, mode: string) => {
          const ok = (s.reach & 1) === 1;
          const age = s.lastRxMs === undefined ? undefined : now - s.lastRxMs;
          const lastRx = age === undefined ? '-' : String(Math.max(1, Math.round((ok && age > POLL ? age % POLL : age) / 1000)));
          const longRunning = s.lastPollMs !== undefined && now - s.lastPollMs > 8 * POLL;
          const reach = longRunning ? (ok ? 0o377 : 0) : s.reach;
          const off = age === undefined ? '+0ns' : fmtOffset(s.offsetMs || 0.000312);
          const sample = `${off.padStart(6)}[${off.padStart(6)}] +/- ${(age === undefined ? '0ns' : '234us').padStart(6)}`;
          return `${mode}${s.state} ${s.name.padEnd(27)}  ${String(s.stratum).padStart(2)}   6   ${reach.toString(8).padStart(3)}  ${lastRx.padStart(4)}  ${sample}`;
        };
        const rows = l.refclock
          ? [row({ name: l.refclock, state: '*', stratum: 0, reach: 0o377, lastRxMs: now - 10_000, lastPollMs: now - 10_000, offsetMs: -0.000312 }, '#')]
          : l.sources.map((s) => row(s, '^'));
        return ok([...(args.includes('-v') ? [SOURCES_LEGEND] : []), 'MS Name/IP address         Stratum Poll Reach LastRx Last sample               ', '='.repeat(79), ...rows].join('\n'));
      }
      case 'activity': {
        const online = l.refclock ? 1 : l.sources.filter((s) => s.ip).length;
        const unknown = l.refclock ? 0 : l.sources.filter((s) => !s.ip).length;
        return ok(['200 OK', `${online} sources online`, '0 sources offline', '0 sources doing burst (return to online)', '0 sources doing burst (return to offline)', `${unknown} sources with unknown address`].join('\n'));
      }
      case 'clients': {
        if (!root) return err('501 Not authorised', 1);
        const rows = Object.entries(l.clients).map(([ip, c]) => `${ip.padEnd(25)} ${String(c.ntp).padStart(7)} ${String(c.drop).padStart(6)}   6   -  ${ago(now - c.last).padStart(4)}       0      0   -     -`);
        return ok(['Hostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last', '='.repeat(79), ...rows].join('\n'));
      }
      case 'makestep': {
        if (!root) return err('501 Not authorised', 1);
        chronySync(ctx.world, ctx.host, rt, true);
        return ok('200 OK');
      }
      case 'burst': case 'online': case 'offline': {
        if (!root) return err('501 Not authorised', 1);
        chronySync(ctx.world, ctx.host, rt);
        return ok('200 OK');
      }
      case 'waitsync': {
        chronySync(ctx.world, ctx.host, rt);
        return l.synced ? ok(`try: 1, refid: ${l.refId}, correction: 0.000000312, skew: 0.035`) : err('try: 1, refid: 00000000, correction: 0.000000000, skew: 0.000', 1);
      }
      default:
        return err('Unrecognized command', 1);
    }
  },
};

export const NTP_COMMANDS: CommandDef[] = [chronyc];
