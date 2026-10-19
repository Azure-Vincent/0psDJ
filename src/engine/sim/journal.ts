// systemd-journal style logging used by every simulated service.
import type { Host, LogEntry, World } from '../types';

export function log(
  world: World,
  host: Host,
  ident: string,
  message: string,
  opts: { pid?: number | null; unit?: string | null; priority?: LogEntry['priority'] } = {},
): void {
  host.journal.push({
    time: world.clock,
    host: host.hostname,
    ident,
    pid: opts.pid ?? null,
    unit: opts.unit ?? null,
    priority: opts.priority ?? 'info',
    message,
  });
  if (host.journal.length > 2000) host.journal.splice(0, host.journal.length - 2000);
}

export function kernelLog(world: World, host: Host, message: string): void {
  log(world, host, 'kernel', message, { priority: 'warning' });
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Format like the default `journalctl` short output (UTC is used throughout the labs). */
export function formatSyslogTime(ms: number): string {
  const d = new Date(Math.floor(ms));
  const p = (n: number) => String(n).padStart(2, '0');
  return `${MONTHS[d.getUTCMonth()]} ${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

export function formatEntry(e: LogEntry): string {
  const id = e.pid !== null ? `${e.ident}[${e.pid}]` : e.ident;
  return `${formatSyslogTime(e.time)} ${e.host} ${id}: ${e.message}`;
}

export function isoTime(ms: number): string {
  return new Date(Math.floor(ms)).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}
