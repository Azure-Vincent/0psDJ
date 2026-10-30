// Monitoring with the Prometheus stack as Debian 12 packages it: node_exporter
// (1.5.0) on the servers, Prometheus (2.42.0) and Alertmanager (0.25.0) on
// mon01, all configured from /etc/prometheus and /etc/default.
//
// Metrics come from the simulated machines themselves (disks, interfaces,
// services, clocks, textfile *.prom files). Prometheus scrapes its targets
// over the simulated network and evaluates its rules as simulated time passes
// (a background hook of the timer runner). Scrapes run on a copy of the world,
// so they leave no packets or clock jumps behind; their results, rule states
// and log lines are written back. Alertmanager groups the alerts it receives
// and mails notifications through the configured smarthost (Postfix on mail01).
//
// Simplification: Prometheus keeps only the last few samples of each series,
// so range functions see the last scrapes, not hours of history. Between two
// commands the machines do not change, which lets one evaluation stand for the
// many a real server would run during a long pause.

import { mkdir, readFile, writeFile } from '../fs';
import type { Host, ServiceRuntime, World } from '../types';
import { parseYaml, YamlError, type Yaml } from '../config/yaml';
import { diskUsedKB } from './disk';
import { resolve } from './dns';
import type { HttpRequestInfo, HttpResponse } from './http';
import { httpHooks } from './httpHooks';
import { log } from './journal';
import { smtpConversation } from './mail';
import { clockSynchronized, hostClock } from './ntp';
import { evaluate, formatValue, type Labels, type Node, parseDuration, parsePromQL, PromQLError, type Series, type Value, dropName, formatDuration } from './promql';
import { allListeners, type Listener, serviceDef } from './services';
import { tcpConnect } from './tcp';
import { withRecorder } from './trace';
import { backgroundHooks, runtime, userUnits } from './timers';


export const PROMETHEUS_VERSION = '2.42.0+ds';
export const ALERTMANAGER_VERSION = '0.25.0+ds';
export const NODE_EXPORTER_VERSION = '1.5.0';
export const PROM_CONFIG = '/etc/prometheus/prometheus.yml';
export const AM_CONFIG = '/etc/prometheus/alertmanager.yml';
export const NODE_DEFAULTS = '/etc/default/prometheus-node-exporter';
export const PROM_DEFAULTS = '/etc/default/prometheus';
export const TEXTFILE_DIR = '/var/lib/prometheus/node-exporter';

/** Samples kept per series (enough for rate() and the *_over_time functions over the last scrapes). */
const KEEP = 4;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const seeded = (s: string): number => { let h = 2166136261; for (const c of s) h = Math.imul(h ^ c.charCodeAt(0), 16777619); return ((h >>> 0) % 10_000) / 10_000; };
const isoTs = (t: number) => new Date(Math.floor(t)).toISOString().replace(/(\.\d{3})\d*Z$/, '$1Z');

/** Prometheus' logfmt lines: ts=… caller=… level=… msg="…" key=value. */
function plog(world: World, host: Host, ident: string, unit: string, pid: number | null, caller: string, level: 'info' | 'warn' | 'error', msg: string, kv: Record<string, string | number> = {}): void {
  const q = (v: string | number) => (typeof v === 'number' || /^[\w./:@-]+$/.test(v) ? String(v) : `"${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`);
  const extra = Object.entries(kv).map(([k, v]) => `${k}=${q(v)}`).join(' ');
  log(world, host, ident, `ts=${isoTs(hostClock(world, host))} caller=${caller} level=${level} msg=${q(msg)}${extra ? ' ' + extra : ''}`, { pid, unit, priority: level === 'error' ? 'err' : level === 'warn' ? 'warning' : 'info' });
}

/** Debian's ARGS="…" line in /etc/default/<service>. */
export function defaultArgs(host: Host, file: string): string[] {
  const text = readFile(host, file) ?? '';
  const m = [...text.matchAll(/^\s*ARGS\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S*))\s*$/gm)].pop();
  const v = m ? (m[1] ?? m[2] ?? m[3] ?? '') : '';
  return v.split(/\s+/).filter(Boolean);
}

/** Parse --flag=value / --flag value / --[no-]flag into a map; unknown flags are reported like kingpin does. */
function parseFlags(args: string[], known: Set<string>, bools: Set<string>, prog: string): { flags: Map<string, string>; error?: string } {
  const flags = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('--')) return { flags, error: `${prog}: error: unexpected ${a}, try --help` };
    const [k, v] = a.slice(2).split(/=(.*)/s);
    const name = k.replace(/^no-/, '');
    if (!known.has(name) && !bools.has(name)) return { flags, error: `${prog}: error: unknown long flag '--${k}', try --help` };
    if (bools.has(name)) { flags.set(name, k.startsWith('no-') ? 'false' : v ?? 'true'); continue; }
    if (v !== undefined) flags.set(name, v);
    else if (i + 1 < args.length) flags.set(name, args[++i]);
    else return { flags, error: `${prog}: error: expected argument for flag '--${k}', try --help` };
  }
  return { flags };
}

/** "host:port" or ":port" → { addr, port } as Go's net.Listen sees it. */
function listenAddr(spec: string, defPort: number): { addr: string; port: number } | null {
  const m = /^(?:\[?([^\]]*)\]?)?:(\d+)$/.exec(spec);
  if (!m) return null;
  const host = m[1] ?? '';
  return { addr: host === '' || host === '0.0.0.0' ? '0.0.0.0' : host === 'localhost' ? '127.0.0.1' : host, port: Number(m[2] || defPort) };
}

// ---------------------------------------------------------------------------
// node_exporter
// ---------------------------------------------------------------------------

export interface NodeExporterLoaded { pid: number; listen: { addr: string; port: number }; systemd: boolean; textfileDir: string; disabled: string[]; unitInclude?: string }

const NODE_FLAGS = new Set(['web.listen-address', 'web.telemetry-path', 'collector.textfile.directory', 'collector.filesystem.mount-points-exclude', 'collector.systemd.unit-include', 'log.level', 'web.config.file']);
const NODE_BOOLS = new Set(['collector.systemd', 'collector.textfile', 'collector.filesystem', 'collector.netdev', 'collector.cpu', 'collector.meminfo', 'collector.loadavg', 'collector.timex', 'collector.time', 'collector.uname', 'collector.diskstats', 'collector.processes']);

function nodeExporterStart(world: World, host: Host, rt: ServiceRuntime): NodeExporterLoaded | null {
  const pid = rt.pid ?? 0;
  const unit = 'prometheus-node-exporter.service';
  const args = defaultArgs(host, NODE_DEFAULTS);
  const p = parseFlags(args, NODE_FLAGS, NODE_BOOLS, 'prometheus-node-exporter');
  if (p.error) {
    log(world, host, 'prometheus-node-exporter', p.error, { pid, unit, priority: 'err' });
    return null;
  }
  const listen = listenAddr(p.flags.get('web.listen-address') ?? ':9100', 9100);
  if (!listen) {
    plog(world, host, 'prometheus-node-exporter', unit, pid, 'node_exporter.go:199', 'error', 'listen tcp: address ' + p.flags.get('web.listen-address') + ': missing port in address');
    return null;
  }
  const loaded: NodeExporterLoaded = {
    pid, listen,
    systemd: p.flags.get('collector.systemd') === 'true',
    textfileDir: p.flags.get('collector.textfile.directory') ?? TEXTFILE_DIR,
    disabled: [...p.flags].filter(([, v]) => v === 'false').map(([k]) => k.replace(/^collector\./, '')),
    unitInclude: p.flags.get('collector.systemd.unit-include')?.replace(/^['"]|['"]$/g, ''),
  };
  if (loaded.unitInclude) { try { new RegExp(loaded.unitInclude); } catch { log(world, host, 'prometheus-node-exporter', `prometheus-node-exporter: error: invalid regular expression ${loaded.unitInclude}`, { pid, unit, priority: 'err' }); return null; } }
  plog(world, host, 'prometheus-node-exporter', unit, pid, 'node_exporter.go:180', 'info', 'Starting node_exporter', { version: `(version=${NODE_EXPORTER_VERSION}, branch=debian/sid, revision=1.5.0-1+b6)` });
  const enabled = ['cpu', 'filesystem', 'loadavg', 'meminfo', 'netdev', 'textfile', 'time', 'timex', 'uname', ...(loaded.systemd ? ['systemd'] : [])].filter((c) => !loaded.disabled.includes(c));
  plog(world, host, 'prometheus-node-exporter', unit, pid, 'node_exporter.go:115', 'info', 'Enabled collectors');
  for (const c of enabled) plog(world, host, 'prometheus-node-exporter', unit, pid, 'node_exporter.go:122', 'info', '', { collector: c });
  plog(world, host, 'prometheus-node-exporter', unit, pid, 'tls_config.go:232', 'info', 'Listening on', { address: `[::]:${listen.port}` });
  return loaded;
}

interface Metric { name: string; help: string; type: 'gauge' | 'counter' | 'untyped'; samples: { labels: Labels; value: number }[] }

/** Overrides tickets set to make a machine busy or short of memory (a runaway process). */
export interface HostLoad { load1?: number; memAvailablePct?: number; busyProcess?: string }

/** The metrics node_exporter serves for `host` at time t (ms). */
export function nodeMetrics(world: World, host: Host, loaded: NodeExporterLoaded, t: number): { metrics: Metric[]; errors: string[] } {
  const metrics: Metric[] = [];
  const errors: string[] = [];
  const add = (name: string, help: string, type: Metric['type'], samples: { labels?: Labels; value: number }[]) => metrics.push({ name, help, type, samples: samples.map((s) => ({ labels: s.labels ?? {}, value: s.value })) });
  const off = (c: string) => !loaded.disabled.includes(c);
  const up = (t - host.bootTime) / 1000;
  const perf = (host as Host & { load?: HostLoad }).load ?? {};
  const base = 0.05 + seeded(host.id) * 0.3;
  if (off('cpu')) {
    const busy = Math.min(1.9, perf.load1 ?? base) / 2;
    const s: { labels: Labels; value: number }[] = [];
    for (const cpu of ['0', '1']) {
      const r2 = (x: number) => Math.round(x * 100) / 100;
      s.push({ labels: { cpu, mode: 'idle' }, value: r2(up * (1 - busy) * 0.97) });
      s.push({ labels: { cpu, mode: 'iowait' }, value: r2(up * 0.004) });
      s.push({ labels: { cpu, mode: 'system' }, value: r2(up * (busy * 0.3 + 0.006)) });
      s.push({ labels: { cpu, mode: 'user' }, value: r2(up * (busy * 0.7 + 0.01)) });
    }
    add('node_cpu_seconds_total', 'Seconds the CPUs spent in each mode.', 'counter', s);
  }
  if (off('loadavg')) {
    const l1 = perf.load1 ?? base;
    add('node_load1', '1m load average.', 'gauge', [{ value: Number(l1.toFixed(2)) }]);
    add('node_load5', '5m load average.', 'gauge', [{ value: Number((l1 * 0.9).toFixed(2)) }]);
    add('node_load15', '15m load average.', 'gauge', [{ value: Number((l1 * 0.8).toFixed(2)) }]);
  }
  if (off('meminfo')) {
    const total = 2_067_427_328;
    const availPct = perf.memAvailablePct ?? 0.62 + seeded(host.id + 'm') * 0.2;
    add('node_memory_MemTotal_bytes', 'Memory information field MemTotal_bytes.', 'gauge', [{ value: total }]);
    add('node_memory_MemAvailable_bytes', 'Memory information field MemAvailable_bytes.', 'gauge', [{ value: Math.round(total * availPct) }]);
    add('node_memory_SwapTotal_bytes', 'Memory information field SwapTotal_bytes.', 'gauge', [{ value: 1_022_357_504 }]);
  }
  if (off('filesystem')) {
    const fsl = [{ device: '/dev/vda1', fstype: 'ext4', mountpoint: '/', size: 20_466_256 * 1024, avail: 16_200_344 * 1024, free: 17_264_692 * 1024 }];
    for (const d of host.disks ?? []) {
      const used = Math.min(d.sizeKB, diskUsedKB(host, d));
      fsl.push({ device: d.device, fstype: 'ext4', mountpoint: d.mount, size: d.sizeKB * 1024, free: Math.max(0, d.sizeKB - used) * 1024, avail: Math.max(0, Math.round(d.sizeKB * 0.95) - used) * 1024 });
    }
    add('node_filesystem_size_bytes', 'Filesystem size in bytes.', 'gauge', fsl.map((f) => ({ labels: { device: f.device, fstype: f.fstype, mountpoint: f.mountpoint }, value: f.size })));
    add('node_filesystem_free_bytes', 'Filesystem free space in bytes.', 'gauge', fsl.map((f) => ({ labels: { device: f.device, fstype: f.fstype, mountpoint: f.mountpoint }, value: f.free })));
    add('node_filesystem_avail_bytes', 'Filesystem space available to non-root users in bytes.', 'gauge', fsl.map((f) => ({ labels: { device: f.device, fstype: f.fstype, mountpoint: f.mountpoint }, value: f.avail })));
    add('node_filesystem_readonly', 'Filesystem read-only status.', 'gauge', fsl.map((f) => ({ labels: { device: f.device, fstype: f.fstype, mountpoint: f.mountpoint }, value: 0 })));
  }
  if (off('netdev')) {
    const ifs = host.ifaces.filter((i) => i.name !== 'lo');
    const rate = 1800 + seeded(host.id + 'n') * 6000;
    add('node_network_receive_bytes_total', 'Network device statistic receive_bytes.', 'counter', ifs.map((i) => ({ labels: { device: i.name }, value: i.up ? Math.round(up * rate) : Math.round(Math.min(up, 3600) * rate) })));
    add('node_network_transmit_bytes_total', 'Network device statistic transmit_bytes.', 'counter', ifs.map((i) => ({ labels: { device: i.name }, value: i.up ? Math.round(up * rate * 0.7) : Math.round(Math.min(up, 3600) * rate * 0.7) })));
    add('node_network_up', 'Value is 1 if operstate is \'up\', 0 otherwise.', 'gauge', ifs.map((i) => ({ labels: { device: i.name }, value: i.up ? 1 : 0 })));
  }
  if (off('time')) add('node_time_seconds', 'System time in seconds since epoch (1970).', 'gauge', [{ value: Math.round(hostClockAt(world, host, t)) / 1000 }]);
  add('node_boot_time_seconds', 'Node boot time, in unixtime.', 'gauge', [{ value: Math.floor(host.bootTime / 1000) }]);
  if (off('timex')) {
    const synced = clockSynchronized(host);
    add('node_timex_sync_status', 'Is clock synchronized to a reliable server (1 = yes, 0 = no).', 'gauge', [{ value: synced ? 1 : 0 }]);
    add('node_timex_offset_seconds', 'Time offset in between local system and reference clock.', 'gauge', [{ value: synced ? 0.000041 : (hostClockAt(world, host, t) - t) / 1000 }]);
    add('node_timex_maxerror_seconds', 'Maximum error in seconds.', 'gauge', [{ value: synced ? 0.0125 : 16 }]);
  }
  if (off('uname')) add('node_uname_info', 'Labeled system information as provided by the uname system call.', 'gauge', [{ labels: { domainname: '(none)', machine: 'x86_64', nodename: host.hostname, release: '6.1.0-26-amd64', sysname: 'Linux', version: '#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)' }, value: 1 }]);
  if (loaded.systemd && off('systemd')) {
    const s: { labels: Labels; value: number }[] = [];
    const units: [string, string][] = [];
    for (const [name, rt] of Object.entries(host.services)) units.push([serviceDef(name)?.unit ?? unitName(name), rt.state === 'active' ? 'active' : rt.state === 'failed' ? 'failed' : 'inactive']);
    for (const name of userUnits(host)) { const rt = runtime(host, name); units.push([name, rt.state]); }
    const include = loaded.unitInclude ? new RegExp(`^(?:${loaded.unitInclude})$`) : null;
    for (const [name, state] of units.filter(([n]) => !include || include.test(n)).sort((a, b) => a[0].localeCompare(b[0]))) for (const st of ['activating', 'active', 'deactivating', 'failed', 'inactive']) s.push({ labels: { name, state: st, type: name.endsWith('.timer') ? 'timer' : 'simple' }, value: st === state ? 1 : 0 });
    add('node_systemd_unit_state', 'Systemd unit', 'gauge', s);
  }
  if (off('textfile')) {
    const dir = loaded.textfileDir.replace(/\/$/, '');
    const files = Object.keys(host.fs).filter((p) => p.startsWith(dir + '/') && p.endsWith('.prom') && !p.slice(dir.length + 1).includes('/')).sort();
    const mtimes: { labels: Labels; value: number }[] = [];
    let scrapeError = 0;
    for (const f of files) {
      const parsed = parseExposition(host.fs[f].content);
      if (parsed.error) {
        errors.push(`failed to collect textfile data from "${f}": ${parsed.error}`);
        scrapeError = 1;
        continue;
      }
      mtimes.push({ labels: { file: f }, value: Math.floor(host.fs[f].mtime / 1000) });
      for (const m of parsed.metrics) {
        const existing = metrics.find((x) => x.name === m.name);
        if (existing) existing.samples.push(...m.samples); else metrics.push(m);
      }
    }
    if (mtimes.length) add('node_textfile_mtime_seconds', 'Unixtime mtime of textfiles successfully read.', 'gauge', mtimes);
    add('node_textfile_scrape_error', '1 if there was an error opening or reading a file, 0 otherwise', 'gauge', [{ value: scrapeError }]);
  }
  add('node_exporter_build_info', 'A metric with a constant \'1\' value labeled by version, revision, branch, goversion from which node_exporter was built, and the goos and goarch for the build.', 'gauge', [{ labels: { branch: 'debian/sid', goarch: 'amd64', goos: 'linux', goversion: 'go1.19.8', revision: '1.5.0-1+b6', version: NODE_EXPORTER_VERSION }, value: 1 }]);
  return { metrics, errors };
}

function hostClockAt(world: World, host: Host, t: number): number {
  return hostClock(world, host) - world.clock + t;
}

/** The unit name a service runtime belongs to (prometheus → prometheus.service). */
function unitName(service: string): string {
  return service.includes('.') ? service : `${service}.service`;
}

/** Prometheus text exposition format (what /metrics returns and textfile *.prom files contain). */
export function formatExposition(metrics: Metric[]): string {
  const out: string[] = [];
  for (const m of metrics) {
    out.push(`# HELP ${m.name} ${m.help}`, `# TYPE ${m.name} ${m.type}`);
    for (const s of m.samples) {
      const keys = Object.keys(s.labels).sort();
      out.push(`${m.name}${keys.length ? `{${keys.map((k) => `${k}="${s.labels[k]}"`).join(',')}}` : ''} ${formatValue(s.value)}`);
    }
  }
  return out.join('\n') + '\n';
}

/** Parse exposition text; errors read like node_exporter's textfile collector. */
export function parseExposition(text: string): { metrics: Metric[]; error?: string } {
  const metrics: Metric[] = [];
  const help: Record<string, string> = {};
  const types: Record<string, Metric['type']> = {};
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].trim();
    if (!l) continue;
    const h = /^#\s*HELP\s+(\S+)\s*(.*)$/.exec(l);
    if (h) { help[h[1]] = h[2]; continue; }
    const ty = /^#\s*TYPE\s+(\S+)\s+(\S+)$/.exec(l);
    if (ty) {
      if (!['gauge', 'counter', 'untyped', 'summary', 'histogram'].includes(ty[2])) return { metrics, error: `text format parsing error in line ${i + 1}: unknown metric type "${ty[2]}"` };
      types[ty[1]] = ty[2] as Metric['type'];
      continue;
    }
    if (l.startsWith('#')) continue;
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)(\s+\d+)?$/.exec(l);
    if (!m) return { metrics, error: `text format parsing error in line ${i + 1}: ${/^[^a-zA-Z_:]/.test(l) ? `invalid metric name` : `expected float as value, got "${l.split(/\s+/)[1] ?? ''}"`}` };
    const value = m[3] === '+Inf' ? Infinity : m[3] === '-Inf' ? -Infinity : Number(m[3]);
    if (Number.isNaN(value) && m[3] !== 'NaN') return { metrics, error: `text format parsing error in line ${i + 1}: expected float as value, got "${m[3]}"` };
    const labels: Labels = {};
    if (m[2]) for (const lm of m[2].slice(1, -1).matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"/g)) labels[lm[1]] = lm[2].replace(/\\(.)/g, '$1');
    let metric = metrics.find((x) => x.name === m[1]);
    if (!metric) { metric = { name: m[1], help: help[m[1]] ?? `Metric read from ${m[1]}`, type: types[m[1]] ?? 'untyped', samples: [] }; metrics.push(metric); }
    metric.samples.push({ labels, value });
  }
  return { metrics };
}

// ---------------------------------------------------------------------------
// Prometheus configuration
// ---------------------------------------------------------------------------

export interface ScrapeTarget { address: string; labels: Labels }
export interface ScrapeConfig { job: string; interval: number; timeout: number; path: string; scheme: 'http' | 'https'; targets: ScrapeTarget[] }
export interface RuleDef { kind: 'alert' | 'record'; name: string; expr: string; node: Node; forMs: number; labels: Labels; annotations: Record<string, string>; group: string; file: string }
export interface PromConfig {
  scrapeInterval: number; scrapeTimeout: number; evalInterval: number; external: Labels;
  scrapes: ScrapeConfig[]; ruleFiles: string[]; rules: RuleDef[]; alertmanagers: { address: string; scheme: string; prefix: string }[];
}

class ConfigError extends Error {}

const GLOBAL_FIELDS = new Set(['scrape_interval', 'scrape_timeout', 'evaluation_interval', 'external_labels', 'query_log_file']);
const SCRAPE_FIELDS = new Set(['job_name', 'scrape_interval', 'scrape_timeout', 'metrics_path', 'scheme', 'static_configs', 'honor_labels', 'params', 'relabel_configs', 'metric_relabel_configs', 'basic_auth', 'tls_config', 'file_sd_configs']);
const TOP_FIELDS = new Set(['global', 'alerting', 'rule_files', 'scrape_configs', 'remote_write', 'remote_read', 'storage', 'tracing']);

function asMap(v: Yaml, ctx: string): Record<string, Yaml> {
  if (v === null || v === undefined) return {};
  if (typeof v !== 'object' || Array.isArray(v)) throw new ConfigError(`yaml: unmarshal errors:\n  cannot unmarshal !!${Array.isArray(v) ? 'seq' : 'str'} into ${ctx}`);
  return v as Record<string, Yaml>;
}
function asList(v: Yaml, ctx: string): Yaml[] {
  if (v === null || v === undefined) return [];
  if (!Array.isArray(v)) throw new ConfigError(`yaml: unmarshal errors:\n  cannot unmarshal !!${typeof v === 'object' ? 'map' : 'str'} into ${ctx}`);
  return v;
}
function unknownField(m: Record<string, Yaml>, allowed: Set<string>, type: string, text: string): void {
  for (const k of Object.keys(m)) if (!allowed.has(k)) {
    const line = text.split('\n').findIndex((l) => new RegExp(`^\\s*-?\\s*${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:`).test(l)) + 1;
    throw new ConfigError(`yaml: unmarshal errors:\n  line ${line}: field ${k} not found in type ${type}`);
  }
}
function dur(v: Yaml, def: number): number {
  if (v === null || v === undefined) return def;
  const d = parseDuration(String(v));
  if (d === null) throw new ConfigError(`not a valid duration string: "${String(v)}"`);
  return d;
}

/** A shell-style glob relative to the config file's directory, as rule_files are expanded. */
export function globFiles(host: Host, pattern: string, base: string): string[] {
  const abs = pattern.startsWith('/') ? pattern : `${base}/${pattern}`;
  if (!/[*?[]/.test(abs)) return host.fs[abs]?.type === 'file' ? [abs] : [];
  const rx = new RegExp('^' + abs.split('/').map((seg) => seg.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')).join('/') + '$');
  return Object.keys(host.fs).filter((p) => host.fs[p].type === 'file' && rx.test(p)).sort();
}

export function loadPromConfig(host: Host, file = PROM_CONFIG, withRules = true): { config?: PromConfig; error?: string; ruleCount: number } {
  const text = readFile(host, file);
  if (text === undefined) return { error: `open ${file}: no such file or directory`, ruleCount: 0 };
  let doc: Yaml;
  try { doc = parseYaml(text); } catch (e) { return { error: `parsing YAML file ${file}: ${(e as Error).message}`, ruleCount: 0 }; }
  try {
    const top = asMap(doc, 'config.plain');
    unknownField(top, TOP_FIELDS, 'config.plain', text);
    const g = asMap(top.global ?? null, 'config.GlobalConfig');
    unknownField(g, GLOBAL_FIELDS, 'config.GlobalConfig', text);
    const scrapeInterval = dur(g.scrape_interval, 60_000);
    const scrapeTimeout = dur(g.scrape_timeout, Math.min(10_000, scrapeInterval));
    const evalInterval = dur(g.evaluation_interval, 60_000);
    if (scrapeTimeout > scrapeInterval) throw new ConfigError('global scrape timeout greater than scrape interval');
    const external = Object.fromEntries(Object.entries(asMap(g.external_labels ?? null, 'labels')).map(([k, v]) => [k, String(v)]));
    const scrapes: ScrapeConfig[] = [];
    for (const raw of asList(top.scrape_configs ?? null, '[]*config.ScrapeConfig')) {
      const sc = asMap(raw, 'config.ScrapeConfig');
      unknownField(sc, SCRAPE_FIELDS, 'config.ScrapeConfig', text);
      const job = sc.job_name ? String(sc.job_name) : '';
      if (!job) throw new ConfigError('job_name is empty');
      if (scrapes.some((x) => x.job === job)) throw new ConfigError(`found multiple scrape configs with job name "${job}"`);
      const interval = dur(sc.scrape_interval, scrapeInterval);
      const timeout = dur(sc.scrape_timeout, Math.min(scrapeTimeout, interval));
      if (timeout > interval) throw new ConfigError(`scrape timeout greater than scrape interval for scrape config with job name "${job}"`);
      const scheme = String(sc.scheme ?? 'http');
      if (scheme !== 'http' && scheme !== 'https') throw new ConfigError(`unknown scrape config scheme: ${scheme}`);
      const targets: ScrapeTarget[] = [];
      for (const st of asList(sc.static_configs ?? null, '[]*targetgroup.Group')) {
        const m = asMap(st, 'targetgroup.Group');
        const labels = Object.fromEntries(Object.entries(asMap(m.labels ?? null, 'model.LabelSet')).map(([k, v]) => [k, String(v)]));
        for (const t of asList(m.targets ?? null, '[]string')) {
          const addr = String(t);
          if (/^https?:\/\//.test(addr) || addr.includes('/')) throw new ConfigError(`"${addr}" is not a valid hostname`);
          targets.push({ address: addr, labels });
        }
      }
      scrapes.push({ job, interval, timeout, path: String(sc.metrics_path ?? '/metrics'), scheme, targets });
    }
    const alerting = asMap(top.alerting ?? null, 'config.AlertingConfig');
    const alertmanagers: PromConfig['alertmanagers'] = [];
    for (const a of asList(alerting.alertmanagers ?? null, '[]*config.AlertmanagerConfig')) {
      const am = asMap(a, 'config.AlertmanagerConfig');
      for (const st of asList(am.static_configs ?? null, '[]*targetgroup.Group')) for (const t of asList(asMap(st, 'targetgroup.Group').targets ?? null, '[]string')) alertmanagers.push({ address: String(t), scheme: String(am.scheme ?? 'http'), prefix: String(am.path_prefix ?? '') });
    }
    const ruleFiles = asList(top.rule_files ?? null, '[]string').map(String);
    const base = file.slice(0, file.lastIndexOf('/')) || '/';
    const rules: RuleDef[] = [];
    for (const pattern of withRules ? ruleFiles : []) {
      for (const f of globFiles(host, pattern, base)) {
        const r = loadRuleFile(host, f);
        if (r.errors.length) throw new ConfigError(`loading groups failed: ${r.errors[0]}`);
        rules.push(...r.rules);
      }
    }
    return { config: { scrapeInterval, scrapeTimeout, evalInterval, external, scrapes, ruleFiles, rules, alertmanagers }, ruleCount: rules.length };
  } catch (e) {
    if (e instanceof ConfigError || e instanceof YamlError) return { error: `parsing YAML file ${file}: ${e.message}`.replace(/parsing YAML file [^:]+: (found multiple|scrape timeout|global scrape|job_name|unknown scrape|"|not a valid|loading groups)/, '$1'), ruleCount: 0 };
    throw e;
  }
}

/** One rule file: groups → rules. Errors are formatted like promtool's. */
export function loadRuleFile(host: Host, file: string): { rules: RuleDef[]; errors: string[]; groups: number } {
  const text = readFile(host, file);
  if (text === undefined) return { rules: [], errors: [`${file}: open ${file}: no such file or directory`], groups: 0 };
  let doc: Yaml;
  try { doc = parseYaml(text); } catch (e) { return { rules: [], errors: [`${file}: ${(e as Error).message}`], groups: 0 }; }
  const rules: RuleDef[] = [];
  const errors: string[] = [];
  const lines = text.split('\n');
  const lineOf = (needle: string, from = 0) => { const i = lines.findIndex((l, k) => k >= from && l.includes(needle)); return i < 0 ? 0 : i + 1; };
  const top = (doc ?? {}) as Record<string, Yaml>;
  if (typeof top !== 'object' || Array.isArray(top)) return { rules, errors: [`${file}: yaml: unmarshal errors:\n  cannot unmarshal !!seq into rulefmt.RuleGroups`], groups: 0 };
  for (const k of Object.keys(top)) if (k !== 'groups') errors.push(`${file}: yaml: unmarshal errors:\n  line ${lineOf(k + ':')}: field ${k} not found in type rulefmt.RuleGroups`);
  const groups = Array.isArray(top.groups) ? top.groups : [];
  const names = new Set<string>();
  groups.forEach((gRaw) => {
    const g = (gRaw ?? {}) as Record<string, Yaml>;
    const gname = String(g.name ?? '');
    if (!gname) { errors.push(`${file}: 0:0: Groupname must not be empty`); return; }
    if (names.has(gname)) errors.push(`${file}: ${lineOf(`name: ${gname}`)}:11: groupname: "${gname}" is repeated in the same file`);
    names.add(gname);
    const rs = Array.isArray(g.rules) ? g.rules : [];
    rs.forEach((rRaw, i) => {
      const r = (rRaw ?? {}) as Record<string, Yaml>;
      const name = String(r.alert ?? r.record ?? '');
      const kind = r.alert !== undefined ? 'alert' : 'record';
      const at = lineOf(`${kind}: ${name}`);
      const where = `${file}: ${at}:${kind === 'alert' ? 14 : 15}: group "${gname}", rule ${i + 1}, "${name}"`;
      for (const k of Object.keys(r)) if (!['alert', 'record', 'expr', 'for', 'labels', 'annotations', 'keep_firing_for'].includes(k)) { errors.push(`${file}: yaml: unmarshal errors:\n  line ${lineOf(k + ':', at - 1)}: field ${k} not found in type rulefmt.RuleNode`); return; }
      if (r.alert !== undefined && r.record !== undefined) { errors.push(`${where}: only one of 'record' and 'alert' must be set`); return; }
      if (!name) { errors.push(`${file}: ${at}:0: group "${gname}", rule ${i + 1}: one of 'record' or 'alert' must be set`); return; }
      if (kind === 'record' && !/^[a-zA-Z_:][a-zA-Z0-9_:]*$/.test(name)) { errors.push(`${where}: invalid recording rule name: ${name}`); return; }
      const expr = r.expr === undefined || r.expr === null ? '' : String(r.expr).trim();
      if (!expr) { errors.push(`${where}: field 'expr' must be set in rule`); return; }
      let node: Node;
      try { node = parsePromQL(expr); } catch (e) { errors.push(`${file}: ${lineOf('expr:', at - 1)}:${kind === 'alert' ? 15 : 15}: group "${gname}", rule ${i + 1}, "${name}": could not parse expression: ${(e as Error).message}`); return; }
      let forMs = 0;
      if (r.for !== undefined && r.for !== null) {
        const d = parseDuration(String(r.for));
        if (d === null) { errors.push(`${file}: yaml: unmarshal errors:\n  line ${lineOf('for:', at - 1)}: not a valid duration string: "${String(r.for)}"`); return; }
        if (kind === 'record') { errors.push(`${where}: invalid field 'for' in recording rule`); return; }
        forMs = d;
      }
      const labels = Object.fromEntries(Object.entries((r.labels ?? {}) as Record<string, Yaml>).map(([k, v]) => [k, String(v)]));
      const annotations = Object.fromEntries(Object.entries((r.annotations ?? {}) as Record<string, Yaml>).map(([k, v]) => [k, String(v)]));
      if (kind === 'record' && Object.keys(annotations).length) { errors.push(`${where}: invalid field 'annotations' in recording rule`); return; }
      rules.push({ kind, name, expr, node, forMs, labels, annotations, group: gname, file });
    });
  });
  return { rules, errors, groups: groups.length };
}

// ---------------------------------------------------------------------------
// Prometheus runtime
// ---------------------------------------------------------------------------

export interface TargetState {
  job: string; instance: string; address: string; labels: Labels; scrapeUrl: string;
  health: 'up' | 'down' | 'unknown'; lastScrape: number; lastError: string; durationMs: number;
}
export interface AlertState {
  rule: string; labels: Labels; annotations: Record<string, string>; state: 'pending' | 'firing'; activeAt: number; value: number; resolvedAt?: number; lastSentAt?: number;
  /** When it started firing: activeAt + for (the machines did not change between evaluations). */
  firedAt?: number;
}
export interface PromLoaded {
  pid: number; listen: { addr: string; port: number }; config: PromConfig; lifecycle: boolean;
  targets: TargetState[];
  /** Series by "target key" (job/instance, or rule:<name>): newest samples only. */
  store: Record<string, Record<string, Series>>;
  alerts: Record<string, AlertState>;
  lastScrapeAt: number; lastEvalAt: number;
  reloadOk: boolean; reloadAt: number;
  ruleFailures: number;
  sendErrors: number;
}

const PROM_FLAGS = new Set(['web.listen-address', 'config.file', 'storage.tsdb.path', 'storage.tsdb.retention.time', 'web.external-url', 'query.lookback-delta', 'log.level', 'web.console.templates', 'web.console.libraries']);
const PROM_BOOLS = new Set(['web.enable-lifecycle', 'web.enable-admin-api']);

function promStart(world: World, host: Host, rt: ServiceRuntime): PromLoaded | null {
  const pid = rt.pid ?? 0;
  const unit = 'prometheus.service';
  const p = parseFlags(defaultArgs(host, PROM_DEFAULTS), PROM_FLAGS, PROM_BOOLS, 'prometheus');
  if (p.error) { log(world, host, 'prometheus', p.error, { pid, unit, priority: 'err' }); return null; }
  const listen = listenAddr(p.flags.get('web.listen-address') ?? '0.0.0.0:9090', 9090);
  const file = p.flags.get('config.file') ?? PROM_CONFIG;
  plog(world, host, 'prometheus', unit, pid, 'main.go:512', 'info', 'No time or size retention was set so using the default time retention', { duration: '15d' });
  plog(world, host, 'prometheus', unit, pid, 'main.go:556', 'info', 'Starting Prometheus Server', { mode: 'server', version: `(version=${PROMETHEUS_VERSION}, branch=debian/sid, revision=2.42.0+ds-5+b5)` });
  plog(world, host, 'prometheus', unit, pid, 'main.go:1214', 'info', 'Loading configuration file', { filename: file });
  const c = loadPromConfig(host, file);
  if (!c.config || !listen) {
    plog(world, host, 'prometheus', unit, pid, 'main.go:1239', 'error', 'Error loading config', { err: c.error ? `couldn't load configuration (--config.file="${file}"): ${c.error}` : 'missing port in address' });
    return null;
  }
  plog(world, host, 'prometheus', unit, pid, 'main.go:1251', 'info', 'Completed loading of configuration file', { filename: file, totalDuration: '1.212ms' });
  plog(world, host, 'prometheus', unit, pid, 'main.go:993', 'info', 'Server is ready to receive web requests.');
  return {
    pid, listen, config: c.config, lifecycle: p.flags.get('web.enable-lifecycle') === 'true',
    targets: targetsOf(c.config, []), store: {}, alerts: {}, lastScrapeAt: 0, lastEvalAt: 0, reloadOk: true, reloadAt: world.clock, ruleFailures: 0, sendErrors: 0,
  };
}

function targetsOf(cfg: PromConfig, prev: TargetState[]): TargetState[] {
  const out: TargetState[] = [];
  for (const sc of cfg.scrapes) for (const t of sc.targets) {
    const old = prev.find((x) => x.job === sc.job && x.address === t.address);
    out.push({
      job: sc.job, instance: t.address, address: t.address, labels: { ...t.labels, instance: t.address, job: sc.job }, scrapeUrl: `${sc.scheme}://${t.address}${sc.path}`,
      health: old?.health ?? 'unknown', lastScrape: old?.lastScrape ?? 0, lastError: old?.lastError ?? '', durationMs: old?.durationMs ?? 0,
    });
  }
  return out;
}

/** systemctl reload (SIGHUP) and POST /-/reload: a bad file is logged and the running configuration kept. */
export function promReload(world: World, host: Host, rt: ServiceRuntime): boolean {
  const l = rt.loaded as PromLoaded | null;
  if (!l) return false;
  const file = PROM_CONFIG;
  plog(world, host, 'prometheus', 'prometheus.service', l.pid, 'main.go:1214', 'info', 'Loading configuration file', { filename: file });
  const c = loadPromConfig(host, file);
  l.reloadAt = world.clock;
  if (!c.config) {
    l.reloadOk = false;
    plog(world, host, 'prometheus', 'prometheus.service', l.pid, 'main.go:977', 'error', 'Error reloading config', { err: `couldn't load configuration (--config.file="${file}"): ${c.error}` });
    return true;
  }
  l.reloadOk = true;
  l.config = c.config;
  l.targets = targetsOf(c.config, l.targets);
  const keep = new Set(l.targets.map((t) => `${t.job}/${t.instance}`));
  for (const k of Object.keys(l.store)) if (!k.startsWith('rule:') && !keep.has(k)) delete l.store[k];
  const names = new Set(c.config.rules.map((r) => r.name));
  for (const [k, a] of Object.entries(l.alerts)) if (!names.has(a.rule)) delete l.alerts[k];
  plog(world, host, 'prometheus', 'prometheus.service', l.pid, 'main.go:1251', 'info', 'Completed loading of configuration file', { filename: file, totalDuration: '0.912ms' });
  return true;
}

/** Everything Prometheus has stored, as a PromQL data source. */
export function promDataSource(l: PromLoaded) {
  return {
    series(name: string | undefined): Series[] {
      const out: Series[] = [];
      for (const group of Object.values(l.store)) for (const s of Object.values(group)) if (!name || s.labels.__name__ === name) out.push(s);
      // ALERTS{alertname, alertstate, …}: the synthetic series of pending and firing alerts.
      if (!name || name === 'ALERTS') {
        for (const a of Object.values(l.alerts)) if (a.resolvedAt === undefined) out.push({ labels: { __name__: 'ALERTS', alertstate: a.state, ...a.labels }, samples: [[l.lastEvalAt, 1]] });
      }
      return out;
    },
  };
}

const keyOf = (labels: Labels) => Object.keys(labels).sort().map((k) => `${k}=${labels[k]}`).join(',');

function pushSample(group: Record<string, Series>, labels: Labels, t: number, v: number): void {
  const k = keyOf(labels);
  const s = (group[k] ??= { labels, samples: [] });
  s.samples.push([t, v]);
  if (s.samples.length > KEEP) s.samples.splice(0, s.samples.length - KEEP);
}

/** What answers on host:port over HTTP, by listener process. */
export type MetricsApp = (world: World, host: Host, path: string, t: number) => { status: number; body: string; errors?: string[] };
export const metricsApps: Record<string, MetricsApp> = {};

/** One scrape of `target` from Prometheus' host at time t (on the world copy). */
function scrapeOnce(w: World, prom: Host, target: TargetState, timeoutMs: number, path: string, t: number): { ok: boolean; error: string; metrics: Metric[]; durationMs: number } {
  const [hostPart, portStr] = target.address.startsWith('[') ? [target.address.slice(1, target.address.indexOf(']')), target.address.split(']:')[1]] : target.address.split(':');
  const port = Number(portStr ?? 80);
  const url = target.scrapeUrl;
  const start = w.clock;
  const fail = (error: string) => ({ ok: false, error: `Get "${url}": ${error}`, metrics: [], durationMs: Math.min(timeoutMs, w.clock - start + 0.6) });
  const r = resolve(w, prom, hostPart === 'localhost' ? '127.0.0.1' : hostPart, { family: 4 });
  if (!r.ok) {
    const ns = /^nameserver\s+(\S+)/m.exec(readFile(prom, '/etc/resolv.conf') ?? '')?.[1] ?? '127.0.0.53';
    return fail(`dial tcp: lookup ${hostPart} on ${ns}:53: ${r.error === 'NXDOMAIN' ? 'no such host' : 'server misbehaving'}`);
  }
  const ip = r.ip;
  const c = tcpConnect(w, prom, ip, port, { timeoutMs });
  if (!c.ok) {
    if (c.errno === 'ETIMEDOUT') return { ok: false, error: 'context deadline exceeded', metrics: [], durationMs: timeoutMs };
    return fail(`dial tcp ${ip}:${port}: connect: ${c.errno === 'ECONNREFUSED' ? 'connection refused' : c.errno === 'EHOSTUNREACH' ? 'no route to host' : 'network is unreachable'}`);
  }
  const server = c.conn.server;
  const listener = allListeners(server).find((l) => l.proto === 'tcp' && l.port === c.conn.sv.localPort);
  c.conn.send('c2s', 220, { protocol: 'HTTP', info: `GET ${path} HTTP/1.1`, fields: [] });
  const app = listener ? metricsApps[listener.process] : undefined;
  if (!app) {
    c.conn.close('server');
    if (listener?.process === 'sshd') return fail('net/http: HTTP/1.x transport connection broken: malformed HTTP response "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"');
    if (listener?.process === 'nginx') return { ok: false, error: 'server returned HTTP status 404 Not Found', metrics: [], durationMs: 3 };
    return fail('EOF');
  }
  const res = app(w, server, path, t);
  c.conn.send('s2c', Math.min(res.body.length, 1400) + 200, { protocol: 'HTTP', info: `HTTP/1.1 ${res.status}`, fields: [] });
  c.conn.close('client');
  const durationMs = Math.max(2, Math.min(timeoutMs, w.clock - start + 4 + res.body.length / 20_000));
  if (res.status !== 200) return { ok: false, error: `server returned HTTP status ${res.status} ${res.status === 404 ? 'Not Found' : res.status === 503 ? 'Service Unavailable' : 'Error'}`, metrics: [], durationMs };
  const parsed = parseExposition(res.body);
  if (parsed.error) return { ok: false, error: parsed.error.replace('text format parsing error', 'text format parsing error'), metrics: [], durationMs };
  return { ok: true, error: '', metrics: parsed.metrics, durationMs };
}

/** Scrape every target at time t on the world copy, storing samples in `l`. */
function scrapeAll(w: World, prom: Host, l: PromLoaded, t: number): void {
  const saved = w.clock;
  for (const target of l.targets) {
    const sc = l.config.scrapes.find((s) => s.job === target.job)!;
    w.clock = t;
    const r = scrapeOnce(w, prom, target, sc.timeout, sc.path, t);
    w.clock = saved;
    const key = `${target.job}/${target.instance}`;
    const group = (l.store[key] ??= {});
    // A failed scrape marks the target's series stale: only the synthetic ones remain.
    if (!r.ok) for (const k of Object.keys(group)) if (!['up', 'scrape_duration_seconds', 'scrape_samples_scraped'].includes(group[k].labels.__name__)) delete group[k];
    if (r.ok) {
      const seen = new Set<string>();
      for (const m of r.metrics) for (const s of m.samples) {
        const labels: Labels = { ...s.labels, __name__: m.name, ...l.config.external, ...target.labels };
        for (const [k, v] of Object.entries(s.labels)) if (k === 'job' || k === 'instance') labels[`exported_${k}`] = v;
        seen.add(keyOf(labels));
        pushSample(group, labels, t, s.value);
      }
      for (const k of Object.keys(group)) if (!seen.has(k) && !['up', 'scrape_duration_seconds', 'scrape_samples_scraped'].includes(group[k].labels.__name__)) delete group[k];
    }
    pushSample(group, { __name__: 'up', ...l.config.external, ...target.labels }, t, r.ok ? 1 : 0);
    pushSample(group, { __name__: 'scrape_duration_seconds', ...l.config.external, ...target.labels }, t, r.durationMs / 1000);
    pushSample(group, { __name__: 'scrape_samples_scraped', ...l.config.external, ...target.labels }, t, r.metrics.reduce((n, m) => n + m.samples.length, 0));
    target.health = r.ok ? 'up' : 'down';
    target.lastScrape = t;
    target.lastError = r.error;
    target.durationMs = r.durationMs;
  }
  l.lastScrapeAt = t;
}

/** {{ $labels.x }}, {{ $value }}, {{ $value | humanize }}, {{ printf "%.1f" $value }} … */
export function expandTemplate(tpl: string, labels: Labels, value: number): string {
  const humanize = (v: number) => {
    if (v === 0 || !Number.isFinite(v)) return formatValue(v);
    const units = ['', 'k', 'M', 'G', 'T', 'P'];
    let i = 0;
    let x = v;
    while (Math.abs(x) >= 1000 && i < units.length - 1) { x /= 1000; i++; }
    return `${Number(x.toPrecision(4))}${units[i]}`;
  };
  const bytes = (v: number) => {
    const units = ['B', 'kiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    let x = v;
    while (Math.abs(x) >= 1024 && i < units.length - 1) { x /= 1024; i++; }
    return `${Number(x.toPrecision(4))}${units[i]}`;
  };
  return tpl.replace(/\{\{-?\s*(.*?)\s*-?\}\}/g, (_m, body: string) => {
    const parts = body.split('|').map((x) => x.trim());
    let v: string | number;
    const head = parts[0];
    const pf = /^printf\s+"([^"]*)"\s+(\$\w+(?:\.\w+)?)$/.exec(head);
    const get = (ref: string): string | number => (ref === '$value' || ref === '.Value' ? value : ref.startsWith('$labels.') ? labels[ref.slice(8)] ?? '' : ref.startsWith('.Labels.') ? labels[ref.slice(8)] ?? '' : '');
    if (pf) {
      const arg = Number(get(pf[2]));
      v = pf[1].replace(/%\.(\d+)f/, (_x, d) => arg.toFixed(Number(d))).replace(/%d/, String(Math.round(arg))).replace(/%s|%v/, String(get(pf[2])));
    } else v = get(head);
    for (const f of parts.slice(1)) {
      const n = Number(v);
      if (f === 'humanize') v = humanize(n);
      else if (f === 'humanizePercentage') v = `${Number((n * 100).toPrecision(4))}%`;
      else if (f === 'humanize1024') v = bytes(n);
      else if (f === 'humanizeDuration') v = formatDuration(Math.round(n * 1000)) || '0s';
      else if (/^printf/.test(f)) { const fm = /"([^"]*)"/.exec(f)?.[1] ?? '%v'; v = fm.replace(/%\.(\d+)f/, (_x, d) => n.toFixed(Number(d))).replace(/%v|%s/, String(v)); }
    }
    return typeof v === 'number' ? formatValue(v) : v;
  });
}

/** Evaluate every rule at time t; alert states move inactive → pending → firing → resolved. */
function evaluateRules(l: PromLoaded, t: number): void {
  const ds = promDataSource(l);
  for (const r of l.config.rules) {
    let v: Value;
    try { v = evaluate(ds, r.node, t); } catch { l.ruleFailures++; continue; }
    const samples = v.kind === 'vector' ? v.samples : v.kind === 'scalar' ? [{ labels: {}, value: v.value, t }] : [];
    if (r.kind === 'record') {
      const group = (l.store[`rule:${r.name}`] = {} as Record<string, Series>);
      for (const s of samples) pushSample(group, { ...dropName(s.labels), ...r.labels, __name__: r.name }, t, s.value);
      continue;
    }
    const active = new Set<string>();
    for (const s of samples) {
      const labels: Labels = { ...dropName(s.labels), ...r.labels, alertname: r.name };
      const key = `${r.name}|${keyOf(labels)}`;
      active.add(key);
      const annotations = Object.fromEntries(Object.entries(r.annotations).map(([k, tpl]) => [k, expandTemplate(tpl, dropName(s.labels), s.value)]));
      const prev = l.alerts[key];
      if (!prev || prev.resolvedAt !== undefined) {
        l.alerts[key] = { rule: r.name, labels, annotations, state: r.forMs === 0 ? 'firing' : 'pending', activeAt: t, value: s.value, ...(r.forMs === 0 ? { firedAt: t } : {}) };
      } else {
        prev.value = s.value;
        prev.annotations = annotations;
        if (prev.state === 'pending' && t - prev.activeAt >= r.forMs) {
          prev.state = 'firing';
          prev.firedAt = Math.min(t, Math.ceil((prev.activeAt + r.forMs) / l.config.evalInterval) * l.config.evalInterval);
        }
      }
    }
    for (const [key, a] of Object.entries(l.alerts)) {
      if (a.rule !== r.name || active.has(key) || a.resolvedAt !== undefined) continue;
      if (a.state === 'pending') delete l.alerts[key];
      else a.resolvedAt = t;
    }
  }
  // Resolved alerts are kept (and re-sent) for 15 minutes, then forgotten.
  for (const [key, a] of Object.entries(l.alerts)) if (a.resolvedAt !== undefined && t - a.resolvedAt > 15 * 60_000) delete l.alerts[key];
  l.lastEvalAt = t;
}

// ---------------------------------------------------------------------------
// Alertmanager
// ---------------------------------------------------------------------------

export interface AmRoute { receiver: string; groupBy: string[]; groupWait: number; groupInterval: number; repeatInterval: number; matchers: { name: string; op: string; value: string }[]; continue: boolean; routes: AmRoute[] }
export interface AmReceiver { name: string; email: { to: string; from: string; smarthost: string; requireTls: boolean; hello: string; authUser?: string; authPassword?: string; sendResolved: boolean }[] }
export interface AmInhibit { source: { name: string; op: string; value: string }[]; target: { name: string; op: string; value: string }[]; equal: string[] }
export interface AmConfig { route: AmRoute; receivers: AmReceiver[]; inhibit: AmInhibit[]; global: Record<string, string> }
export interface AmAlert { labels: Labels; annotations: Record<string, string>; startsAt: number; endsAt: number; updatedAt: number; generator: string }
export interface AmGroup { key: string; receiver: string; labels: Labels; created: number; nextFlush: number; lastNotified: number; lastFiring: string; lastResolved: string }
export interface AmSilence { id: string; matchers: { name: string; op: string; value: string }[]; startsAt: number; endsAt: number; createdBy: string; comment: string }
export interface AmLoaded {
  pid: number; listen: { addr: string; port: number }; config: AmConfig;
  alerts: Record<string, AmAlert>; groups: Record<string, AmGroup>; silences: AmSilence[];
  sent: number; failed: number; lastError: string;
}

const AM_GLOBAL = new Set(['smtp_smarthost', 'smtp_from', 'smtp_hello', 'smtp_auth_username', 'smtp_auth_password', 'smtp_require_tls', 'resolve_timeout']);

function parseAmMatchers(list: Yaml, legacy: Yaml, legacyRe: Yaml): AmRoute['matchers'] {
  const out: AmRoute['matchers'] = [];
  for (const m of Array.isArray(list) ? list : []) {
    const mm = /^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*"?([^"]*)"?\s*$/.exec(String(m));
    if (!mm) throw new ConfigError(`bad matcher format: ${String(m)}`);
    out.push({ name: mm[1], op: mm[2], value: mm[3] });
  }
  for (const [k, v] of Object.entries((legacy ?? {}) as Record<string, Yaml>)) out.push({ name: k, op: '=', value: String(v) });
  for (const [k, v] of Object.entries((legacyRe ?? {}) as Record<string, Yaml>)) out.push({ name: k, op: '=~', value: String(v) });
  return out;
}

function parseRoute(r: Record<string, Yaml>, parent: AmRoute | null, text: string): AmRoute {
  unknownField(r, new Set(['receiver', 'group_by', 'group_wait', 'group_interval', 'repeat_interval', 'matchers', 'match', 'match_re', 'continue', 'routes', 'mute_time_intervals']), 'config.plain', text);
  const route: AmRoute = {
    receiver: r.receiver !== undefined ? String(r.receiver) : parent?.receiver ?? '',
    groupBy: Array.isArray(r.group_by) ? r.group_by.map(String) : parent?.groupBy ?? [],
    groupWait: dur(r.group_wait, parent?.groupWait ?? 30_000),
    groupInterval: dur(r.group_interval, parent?.groupInterval ?? 300_000),
    repeatInterval: dur(r.repeat_interval, parent?.repeatInterval ?? 4 * 3_600_000),
    matchers: parseAmMatchers(r.matchers ?? null, r.match ?? null, r.match_re ?? null),
    continue: String(r.continue ?? 'false') === 'true',
    routes: [],
  };
  route.routes = (Array.isArray(r.routes) ? r.routes : []).map((x) => parseRoute((x ?? {}) as Record<string, Yaml>, route, text));
  return route;
}

export function loadAmConfig(host: Host, file = AM_CONFIG): { config?: AmConfig; error?: string } {
  const text = readFile(host, file);
  if (text === undefined) return { error: `open ${file}: no such file or directory` };
  try {
    const top = asMap(parseYaml(text), 'config.plain');
    unknownField(top, new Set(['global', 'route', 'receivers', 'inhibit_rules', 'templates', 'time_intervals']), 'config.plain', text);
    const g = asMap(top.global ?? null, 'config.GlobalConfig');
    unknownField(g, AM_GLOBAL, 'config.plain', text);
    const global = Object.fromEntries(Object.entries(g).map(([k, v]) => [k, String(v)]));
    if (!top.route) throw new ConfigError('no routes provided');
    const route = parseRoute(asMap(top.route, 'config.Route'), null, text);
    if (!route.receiver) throw new ConfigError('root route must specify a default receiver');
    if (route.matchers.length) throw new ConfigError('root route must not have any matchers');
    const receivers: AmReceiver[] = [];
    for (const raw of asList(top.receivers ?? null, '[]config.Receiver')) {
      const r = asMap(raw, 'config.Receiver');
      unknownField(r, new Set(['name', 'email_configs', 'webhook_configs', 'slack_configs', 'pagerduty_configs']), 'config.plain', text);
      const name = String(r.name ?? '');
      if (!name) throw new ConfigError('missing name in receiver');
      if (receivers.some((x) => x.name === name)) throw new ConfigError(`notification config name "${name}" is not unique`);
      const email = asList(r.email_configs ?? null, '[]*config.EmailConfig').map((e) => {
        const m = asMap(e, 'config.EmailConfig');
        unknownField(m, new Set(['to', 'from', 'smarthost', 'hello', 'auth_username', 'auth_password', 'require_tls', 'send_resolved', 'headers', 'html', 'text']), 'config.plain', text);
        if (!m.to) throw new ConfigError('missing to address in email config');
        const smarthost = String(m.smarthost ?? global.smtp_smarthost ?? '');
        if (!smarthost) throw new ConfigError('no global SMTP smarthost set');
        const from = String(m.from ?? global.smtp_from ?? '');
        if (!from) throw new ConfigError('no global SMTP from set');
        return { to: String(m.to), from, smarthost, hello: String(m.hello ?? global.smtp_hello ?? 'localhost'), requireTls: String(m.require_tls ?? global.smtp_require_tls ?? 'true') !== 'false', authUser: m.auth_username ? String(m.auth_username) : global.smtp_auth_username, authPassword: m.auth_password ? String(m.auth_password) : global.smtp_auth_password, sendResolved: String(m.send_resolved ?? 'false') === 'true' };
      });
      receivers.push({ name, email });
    }
    const check = (rt: AmRoute) => { if (!receivers.some((x) => x.name === rt.receiver)) throw new ConfigError(`undefined receiver "${rt.receiver}" used in route`); rt.routes.forEach(check); };
    check(route);
    const inhibit: AmInhibit[] = asList(top.inhibit_rules ?? null, '[]config.InhibitRule').map((x) => {
      const m = asMap(x, 'config.InhibitRule');
      return { source: parseAmMatchers(m.source_matchers ?? null, m.source_match ?? null, m.source_match_re ?? null), target: parseAmMatchers(m.target_matchers ?? null, m.target_match ?? null, m.target_match_re ?? null), equal: Array.isArray(m.equal) ? m.equal.map(String) : [] };
    });
    return { config: { route, receivers, inhibit, global } };
  } catch (e) {
    if (e instanceof ConfigError || e instanceof YamlError) return { error: e.message };
    throw e;
  }
}

function amStart(world: World, host: Host, rt: ServiceRuntime): AmLoaded | null {
  const pid = rt.pid ?? 0;
  const unit = 'prometheus-alertmanager.service';
  const p = parseFlags(defaultArgs(host, '/etc/default/prometheus-alertmanager'), new Set(['web.listen-address', 'config.file', 'storage.path', 'cluster.listen-address', 'log.level', 'web.external-url', 'data.retention']), new Set([]), 'prometheus-alertmanager');
  if (p.error) { log(world, host, 'prometheus-alertmanager', p.error, { pid, unit, priority: 'err' }); return null; }
  const file = p.flags.get('config.file') ?? AM_CONFIG;
  plog(world, host, 'prometheus-alertmanager', unit, pid, 'main.go:240', 'info', 'Starting Alertmanager', { version: `(version=${ALERTMANAGER_VERSION}, branch=debian/sid, revision=0.25.0+ds-2+b6)` });
  const c = loadAmConfig(host, file);
  if (!c.config) {
    plog(world, host, 'prometheus-alertmanager', unit, pid, 'coordinator.go:118', 'error', 'Loading configuration file failed', { component: 'configuration', file, err: c.error ?? '' });
    return null;
  }
  plog(world, host, 'prometheus-alertmanager', unit, pid, 'coordinator.go:113', 'info', 'Loading configuration file', { component: 'configuration', file });
  plog(world, host, 'prometheus-alertmanager', unit, pid, 'coordinator.go:126', 'info', 'Completed loading of configuration file', { component: 'configuration', file });
  const listen = listenAddr(p.flags.get('web.listen-address') ?? ':9093', 9093)!;
  plog(world, host, 'prometheus-alertmanager', unit, pid, 'tls_config.go:232', 'info', 'Listening on', { address: `[::]:${listen.port}` });
  return { pid, listen, config: c.config, alerts: {}, groups: {}, silences: loadSilences(host), sent: 0, failed: 0, lastError: '' };
}

/** Silences survive restarts: Alertmanager keeps them in its data directory. */
export const SILENCES_FILE = '/var/lib/prometheus/alertmanager/silences';
function loadSilences(host: Host): AmSilence[] {
  try { return JSON.parse(readFile(host, SILENCES_FILE) ?? '[]') as AmSilence[]; } catch { return []; }
}
export function saveSilences(host: Host, l: AmLoaded, t: number): void {
  writeFile(host, SILENCES_FILE, JSON.stringify(l.silences), t, { mode: 0o644, owner: 'prometheus', group: 'prometheus' });
}

function amReload(world: World, host: Host, rt: ServiceRuntime): boolean {
  const l = rt.loaded as AmLoaded | null;
  if (!l) return false;
  const c = loadAmConfig(host);
  if (!c.config) {
    plog(world, host, 'prometheus-alertmanager', 'prometheus-alertmanager.service', l.pid, 'coordinator.go:118', 'error', 'Loading configuration file failed', { component: 'configuration', file: AM_CONFIG, err: c.error ?? '' });
    return true;
  }
  l.config = c.config;
  l.groups = {};
  plog(world, host, 'prometheus-alertmanager', 'prometheus-alertmanager.service', l.pid, 'coordinator.go:126', 'info', 'Completed loading of configuration file', { component: 'configuration', file: AM_CONFIG });
  return true;
}

const matchOne = (labels: Labels, m: { name: string; op: string; value: string }) => {
  const v = labels[m.name] ?? '';
  if (m.op === '=') return v === m.value;
  if (m.op === '!=') return v !== m.value;
  const ok = new RegExp(`^(?:${m.value})$`).test(v);
  return m.op === '=~' ? ok : !ok;
};

/** The routes an alert takes (the deepest matching child, or the parent). */
export function routeAlert(route: AmRoute, labels: Labels): AmRoute[] {
  const out: AmRoute[] = [];
  for (const child of route.routes) {
    if (!child.matchers.every((m) => matchOne(labels, m))) continue;
    out.push(...routeAlert(child, labels));
    if (!child.continue) break;
  }
  return out.length ? out : [route];
}

export function silencedBy(l: AmLoaded, labels: Labels, now: number): AmSilence | undefined {
  return l.silences.find((s) => s.startsAt <= now && s.endsAt > now && s.matchers.every((m) => matchOne(labels, m)));
}

function inhibited(l: AmLoaded, labels: Labels, now: number): boolean {
  return l.config.inhibit.some((ir) => ir.target.every((m) => matchOne(labels, m)) && Object.values(l.alerts).some((a) => a.endsAt > now && ir.source.every((m) => matchOne(a.labels, m)) && ir.equal.every((k) => (a.labels[k] ?? '') === (labels[k] ?? '')) && keyOf(a.labels) !== keyOf(labels)));
}

/** Alerts posted by Prometheus (POST /api/v2/alerts). */
export function amReceive(l: AmLoaded, alerts: { labels: Labels; annotations: Record<string, string>; startsAt: number; endsAt: number; generator: string }[], now: number): void {
  for (const a of alerts) {
    const k = keyOf(a.labels);
    l.alerts[k] = { ...a, updatedAt: now };
    for (const route of routeAlert(l.config.route, a.labels)) {
      const gl: Labels = {};
      for (const name of route.groupBy) if (a.labels[name] !== undefined) gl[name] = a.labels[name];
      const gkey = `${route.receiver}|${keyOf(gl)}`;
      if (!l.groups[gkey]) l.groups[gkey] = { key: gkey, receiver: route.receiver, labels: gl, created: now, nextFlush: now + route.groupWait, lastNotified: 0, lastFiring: '', lastResolved: '' };
    }
  }
  // Alerts resolved more than 5 minutes ago are garbage-collected (data.retention is longer, but nothing reads them).
  for (const [k, a] of Object.entries(l.alerts)) if (a.endsAt < now - 5 * 60_000) delete l.alerts[k];
}

function groupAlerts(l: AmLoaded, g: AmGroup): AmAlert[] {
  return Object.values(l.alerts).filter((a) => routeAlert(l.config.route, a.labels).some((r) => r.receiver === g.receiver && r.groupBy.every((n) => (a.labels[n] ?? undefined) === g.labels[n])));
}

function routeFor(l: AmLoaded, g: AmGroup): AmRoute {
  const find = (r: AmRoute): AmRoute | undefined => (r.receiver === g.receiver && r.routes.length === 0 ? r : r.routes.map(find).find(Boolean)) ?? (r.receiver === g.receiver ? r : undefined);
  return find(l.config.route) ?? l.config.route;
}

/** The notification mail Alertmanager's default templates produce. */
function notificationMail(g: AmGroup, firing: AmAlert[], resolved: AmAlert[], from: string, to: string, extUrl: string, now: number): { subject: string; content: string } {
  const status = firing.length ? 'firing' : 'resolved';
  const all = [...firing, ...resolved];
  const common = Object.fromEntries(Object.entries(all[0]?.labels ?? {}).filter(([k, v]) => all.every((a) => a.labels[k] === v)));
  const groupVals = Object.keys(g.labels).sort().map((k) => g.labels[k]);
  const extra = Object.keys(common).filter((k) => !(k in g.labels)).sort().map((k) => common[k]);
  const subject = `[${status.toUpperCase()}${status === 'firing' ? `:${firing.length}` : ''}] ${groupVals.join(' ')}${extra.length ? ` (${extra.join(' ')})` : ''}`;
  const block = (a: AmAlert) => [
    'Labels:', ...Object.keys(a.labels).sort().map((k) => ` - ${k} = ${a.labels[k]}`),
    'Annotations:', ...Object.keys(a.annotations).sort().map((k) => ` - ${k} = ${a.annotations[k]}`),
    `Source: ${a.generator}`, '',
  ];
  const body = [
    subject, '',
    `View in Alertmanager: ${extUrl}/#/alerts?receiver=${g.receiver}`, '',
    ...(firing.length ? [`[${firing.length}] Firing`, ...firing.flatMap(block)] : []),
    ...(resolved.length ? [`[${resolved.length}] Resolved`, ...resolved.flatMap(block)] : []),
  ];
  const d = new Date(Math.floor(now));
  const content = [
    `From: ${from}`, `To: ${to}`, `Subject: ${subject}`, `Date: ${d.toUTCString().replace('GMT', '+0000')}`,
    `Message-Id: <${Math.floor(now)}.${g.key.length}@${from.split('@')[1] ?? 'localhost'}>`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', '',
    ...body,
  ].join('\n');
  return { subject, content };
}

/** Send one email notification; returns an error text as Alertmanager logs it, or null. */
function sendEmail(world: World, amHost: Host, e: AmReceiver['email'][number], content: string): string | null {
  const [hostPart, portStr] = e.smarthost.split(':');
  if (!portStr) return `address ${e.smarthost}: missing port in address`;
  const port = Number(portStr);
  const saved = world.clock;
  try {
    const r = resolve(world, amHost, hostPart, { family: 4 });
    if (!r.ok) return `establish connection to server: dial tcp: lookup ${hostPart}: no such host`;
    const c = tcpConnect(world, amHost, r.ip, port, { timeoutMs: 10_000 });
    if (!c.ok) return `establish connection to server: dial tcp ${r.ip}:${port}: ${c.errno === 'ECONNREFUSED' ? 'connect: connection refused' : c.errno === 'ETIMEDOUT' ? 'i/o timeout' : 'connect: no route to host'}`;
    const to = e.to.split(',').map((x) => x.trim()).filter(Boolean);
    const res = smtpConversation(world, c.conn, { helo: e.hello, from: e.from, to, content, tls: e.requireTls ? 'required' : 'opportunistic', ...(e.authUser ? { auth: { mech: 'PLAIN', user: e.authUser, password: e.authPassword ?? '' } } : {}) });
    if (res.result === 'sent') return null;
    if (res.result === 'no-tls') return `'require_tls' is true (default) but "${e.smarthost}" does not advertise the STARTTLS extension`;
    if (res.result === 'tls-failed') return `starttls failed: x509: certificate signed by unknown authority`;
    const failed = res.steps.find((s) => s.reply && s.reply.code >= 400);
    const cmd = failed?.cmd.split(' ')[0].replace(/:$/, '') ?? 'MAIL';
    const what = cmd === 'RCPT' ? 'send RCPT TO' : cmd === 'MAIL' ? 'send MAIL FROM' : cmd === 'DATA' ? 'send DATA command' : cmd === 'AUTH' ? 'send AUTH command' : 'send';
    return `${what}: ${failed?.reply ? `${failed.reply.code} ${failed.reply.text.join(' ')}` : 'EOF'}`;
  } finally {
    world.clock = saved;
  }
}

/** Flush due groups: one notification per group and receiver. */
function amDispatch(world: World, host: Host, l: AmLoaded): void {
  const now = world.clock;
  const unit = 'prometheus-alertmanager.service';
  for (const g of Object.values(l.groups)) {
    if (g.nextFlush > now) continue;
    const route = routeFor(l, g);
    const alerts = groupAlerts(l, g).filter((a) => !silencedBy(l, a.labels, now) && !inhibited(l, a.labels, now));
    const firing = alerts.filter((a) => a.endsAt > now).sort((a, b) => keyOf(a.labels).localeCompare(keyOf(b.labels)));
    const resolved = alerts.filter((a) => a.endsAt <= now);
    const firingKey = firing.map((a) => keyOf(a.labels)).join(';');
    const resolvedKey = resolved.map((a) => keyOf(a.labels)).join(';');
    g.nextFlush = now + route.groupInterval;
    if (!firing.length && !resolved.length) { if (!groupAlerts(l, g).length) delete l.groups[g.key]; continue; }
    const changed = firingKey !== g.lastFiring || (resolvedKey !== g.lastResolved && resolved.length > 0);
    const repeatDue = g.lastNotified > 0 && now - g.lastNotified >= route.repeatInterval;
    if (!changed && !repeatDue) continue;
    const receiver = l.config.receivers.find((r) => r.name === g.receiver);
    let ok = true;
    for (const [i, e] of (receiver?.email ?? []).entries()) {
      if (!firing.length && !e.sendResolved) continue;
      const mail = notificationMail(g, firing, e.sendResolved ? resolved : [], e.from, e.to, `http://${host.hostname}:${l.listen.port}`, now);
      const error = sendEmail(world, host, e, mail.content);
      if (error) {
        ok = false;
        l.failed++;
        l.lastError = error;
        plog(world, host, 'prometheus-alertmanager', unit, l.pid, 'dispatch.go:352', 'error', 'Notify for alerts failed', { component: 'dispatcher', num_alerts: firing.length + resolved.length, err: `${g.receiver}/email[${i}]: notify retry canceled ${/^send|^'require|^starttls|^address/.test(error) ? 'due to unrecoverable error after 1 attempts' : 'after 4 attempts'}: ${error}` });
      } else l.sent++;
    }
    if (ok) { g.lastNotified = now; g.lastFiring = firingKey; g.lastResolved = resolvedKey; }
    if (!firing.length && ok) delete l.groups[g.key];
  }
}

// ---------------------------------------------------------------------------
// The background tick
// ---------------------------------------------------------------------------

const ALIGN = (t: number, step: number) => Math.floor(t / step) * step;

/** Advance every Prometheus and Alertmanager to world.clock (invisible to packet recordings). */
export function monitoringTick(world: World): void {
  withRecorder(null, () => tick(world));
}

function tick(world: World): void {
  const proms = Object.values(world.hosts).filter((h) => h.services.prometheus?.state === 'active' && h.services.prometheus.loaded);
  for (const host of proms) {
    const l = host.services.prometheus.loaded as PromLoaded;
    const now = world.clock;
    const ei = l.config.evalInterval;
    const si = l.config.scrapeInterval;
    const lastAligned = ALIGN(now, si);
    if (lastAligned <= l.lastScrapeAt && ALIGN(now, ei) <= l.lastEvalAt) continue;
    const evalTimes: number[] = [];
    const eNow = ALIGN(now, ei);
    if (eNow > l.lastEvalAt) {
      // A long pause: the machines did not change in between, so evaluating once right after the
      // previous evaluation and once now gives the same "for:" timing as evaluating every interval.
      if (l.lastEvalAt > 0 && eNow - l.lastEvalAt > ei) evalTimes.push(l.lastEvalAt + ei);
      else if (l.lastEvalAt === 0 && eNow - (host.services.prometheus.since || 0) > ei) evalTimes.push(Math.max(ALIGN(host.services.prometheus.since, ei) + ei, eNow - 60 * ei));
      evalTimes.push(eNow);
    }
    const scrapeTimes = [...new Set([...evalTimes, lastAligned - si, lastAligned].filter((t) => t > l.lastScrapeAt && t <= now))].sort((a, b) => a - b);
    // Scrapes and alert delivery happen on a copy: the world itself sees no packets or delays.
    const w = structuredClone(world);
    const wl = w.hosts[host.id].services.prometheus.loaded as PromLoaded;
    const journalBefore = w.hosts[host.id].journal.length;
    const deliveries: { amHost: string; alerts: Parameters<typeof amReceive>[1]; at: number }[] = [];
    for (const t of scrapeTimes) {
      scrapeAll(w, w.hosts[host.id], wl, t);
      if (evalTimes.includes(t)) {
        evaluateRules(wl, t);
        // Firing alerts are re-sent every minute (--rules.alert.resend-delay), resolved ones once more.
        const send = Object.values(wl.alerts).filter((a) => a.state === 'firing' && (a.lastSentAt === undefined || (a.resolvedAt === undefined ? t - a.lastSentAt >= 60_000 : a.lastSentAt < a.resolvedAt)));
        if (send.length) {
          // While the machines did not change, Prometheus re-sent every minute: date this delivery
          // when the first of those re-sends happened, as Alertmanager would have received it.
          const sentAt = Math.min(...send.map((a) => (a.resolvedAt !== undefined ? t : a.lastSentAt === undefined ? Math.min(t, a.firedAt ?? t) : Math.min(t, a.lastSentAt + 60_000))));
          for (const am of wl.config.alertmanagers) {
            const target = amTarget(w, w.hosts[host.id], am.address);
            if ('error' in target) {
              wl.sendErrors++;
              plog(w, w.hosts[host.id], 'prometheus', 'prometheus.service', wl.pid, 'notifier.go:532', 'error', 'Error sending alert', { component: 'notifier', alertmanager: `${am.scheme}://${am.address}${am.prefix}/api/v2/alerts`, count: send.length, err: `Post "${am.scheme}://${am.address}${am.prefix}/api/v2/alerts": ${target.error}` });
              continue;
            }
            deliveries.push({
              amHost: target.host, at: sentAt,
              alerts: send.map((a) => ({ labels: { ...a.labels, ...wl.config.external }, annotations: a.annotations, startsAt: a.activeAt, endsAt: a.resolvedAt ?? t + 4 * Math.max(ei, 60_000), generator: `http://${host.hostname}:${wl.listen.port}/graph?g0.expr=${encodeURIComponent(wl.config.rules.find((r) => r.name === a.rule)?.expr ?? '').replace(/%20/g, '+')}&g0.tab=1` })),
            });
          }
          for (const a of send) a.lastSentAt = t;
        }
      }
    }
    // Write back what Prometheus learned and logged.
    host.services.prometheus.loaded = wl;
    for (const e of w.hosts[host.id].journal.slice(journalBefore)) host.journal.push(e);
    for (const d of deliveries) {
      const amh = world.hosts[d.amHost];
      const al = amh?.services['prometheus-alertmanager']?.loaded as AmLoaded | null;
      if (al) amReceive(al, d.alerts, d.at);
    }
  }
  for (const host of Object.values(world.hosts)) {
    const rt = host.services['prometheus-alertmanager'];
    if (rt?.state !== 'active' || !rt.loaded) continue;
    amDispatch(world, host, rt.loaded as AmLoaded);
  }
}

/** Where an alertmanager address leads (host id), or the error Prometheus logs. */
function amTarget(w: World, prom: Host, address: string): { host: string } | { error: string } {
  const [h, p] = address.split(':');
  const r = resolve(w, prom, h === 'localhost' ? '127.0.0.1' : h, { family: 4 });
  if (!r.ok) return { error: `dial tcp: lookup ${h}: no such host` };
  const port = Number(p ?? 9093);
  const c = tcpConnect(w, prom, r.ip, port, { timeoutMs: 10_000 });
  if (!c.ok) return { error: c.errno === 'ETIMEDOUT' ? 'context deadline exceeded' : `dial tcp ${h === 'localhost' ? '[::1]' : r.ip}:${port}: connect: ${c.errno === 'ECONNREFUSED' ? 'connection refused' : 'no route to host'}` };
  const server = c.conn.server;
  const l = allListeners(server).find((x) => x.proto === 'tcp' && x.port === c.conn.sv.localPort);
  c.conn.close('client');
  if (l?.process !== 'prometheus-aler') return { error: l ? 'server returned HTTP status 404 Not Found' : 'EOF' };
  return { host: server.id };
}

backgroundHooks.push(monitoringTick);

/** Let monitoring catch up over `ms` of simulated time (ticket setups: the problem has been there a while). */
export function monitoringAdvance(world: World, ms: number): void {
  const end = world.clock + ms;
  const step = Math.max(15_000, Math.floor(ms / 8));
  while (world.clock < end) {
    world.clock = Math.min(end, world.clock + step);
    monitoringTick(world);
  }
}

// ---------------------------------------------------------------------------
// HTTP: /metrics, the Prometheus and Alertmanager APIs
// ---------------------------------------------------------------------------

const json = (status: number, body: unknown, now: number, server: string): HttpResponse => {
  const text = JSON.stringify(body) + '\n';
  return { status, reason: status === 200 ? 'OK' : status === 400 ? 'Bad Request' : status === 403 ? 'Forbidden' : status === 404 ? 'Not Found' : status === 405 ? 'Method Not Allowed' : status === 422 ? 'Unprocessable Entity' : 'Error', body: text, size: text.length, binary: false, headers: [['Content-Type', 'application/json'], ['Date', new Date(Math.floor(now)).toUTCString()], ['Content-Length', String(text.length)], ...(server ? [['Server', server] as [string, string]] : [])] };
};
const plain = (status: number, text: string, now: number, type = 'text/plain; charset=utf-8'): HttpResponse => ({ status, reason: status === 200 ? 'OK' : status === 404 ? 'Not Found' : status === 403 ? 'Forbidden' : status === 405 ? 'Method Not Allowed' : 'Error', body: text, size: text.length, binary: false, headers: [['Content-Type', type], ['Date', new Date(Math.floor(now)).toUTCString()], ['Content-Length', String(text.length)]] });

function query(path: string): { path: string; params: URLSearchParams } {
  const [p, q] = path.split('?');
  return { path: p, params: new URLSearchParams(q ?? '') };
}

metricsApps['prometheus-node'] = (world, host, path, t) => {
  const l = host.services['prometheus-node-exporter']?.loaded as NodeExporterLoaded | null;
  if (!l) return { status: 503, body: '' };
  if (path.split('?')[0] !== '/metrics') return { status: 404, body: '404 page not found\n' };
  const r = nodeMetrics(world, host, l, t);
  return { status: 200, body: formatExposition(r.metrics), errors: r.errors };
};

metricsApps.prometheus = (_world, host, path, t) => {
  const l = host.services.prometheus?.loaded as PromLoaded | null;
  if (!l || path.split('?')[0] !== '/metrics') return { status: 404, body: '404 page not found\n' };
  const m: Metric[] = [
    { name: 'prometheus_build_info', help: 'A metric with a constant \'1\' value labeled by version, revision, branch, goversion from which prometheus was built, and the goos and goarch for the build.', type: 'gauge', samples: [{ labels: { branch: 'debian/sid', version: PROMETHEUS_VERSION }, value: 1 }] },
    { name: 'prometheus_config_last_reload_successful', help: 'Whether the last configuration reload attempt was successful.', type: 'gauge', samples: [{ labels: {}, value: l.reloadOk ? 1 : 0 }] },
    { name: 'prometheus_config_last_reload_success_timestamp_seconds', help: 'Timestamp of the last successful configuration reload.', type: 'gauge', samples: [{ labels: {}, value: Math.floor(l.reloadAt / 1000) }] },
    { name: 'prometheus_notifications_errors_total', help: 'Total number of errors sending alert notifications.', type: 'counter', samples: [{ labels: { alertmanager: l.config.alertmanagers[0] ? `http://${l.config.alertmanagers[0].address}/api/v2/alerts` : '' }, value: l.sendErrors }] },
    { name: 'prometheus_rule_evaluation_failures_total', help: 'The total number of rule evaluation failures.', type: 'counter', samples: [{ labels: {}, value: l.ruleFailures }] },
    { name: 'prometheus_tsdb_head_series', help: 'Total number of series in the head block.', type: 'gauge', samples: [{ labels: {}, value: Object.values(l.store).reduce((n, g) => n + Object.keys(g).length, 0) }] },
  ];
  void t;
  return { status: 200, body: formatExposition(m) };
};

metricsApps['prometheus-aler'] = (_world, host, path) => {
  const l = host.services['prometheus-alertmanager']?.loaded as AmLoaded | null;
  if (!l || path.split('?')[0] !== '/metrics') return { status: 404, body: '404 page not found\n' };
  const m: Metric[] = [
    { name: 'alertmanager_notifications_total', help: 'The total number of attempted notifications.', type: 'counter', samples: [{ labels: { integration: 'email' }, value: l.sent + l.failed }] },
    { name: 'alertmanager_notifications_failed_total', help: 'The total number of failed notifications.', type: 'counter', samples: [{ labels: { integration: 'email' }, value: l.failed }] },
    { name: 'alertmanager_alerts', help: 'How many alerts by state.', type: 'gauge', samples: [{ labels: { state: 'active' }, value: Object.values(l.alerts).filter((a) => a.endsAt > _world.clock).length }, { labels: { state: 'suppressed' }, value: 0 }] },
  ];
  return { status: 200, body: formatExposition(m) };
};

/** curl and the web endpoints: everything served on 9100, 9090 and 9093. */
for (const proc of ['prometheus-node', 'prometheus', 'prometheus-aler']) {
  httpHooks.apps[proc] = (world: World, host: Host, req: HttpRequestInfo): HttpResponse => {
    const now = req.now;
    const { path, params } = query(req.path);
    if (path === '/metrics') {
      const r = metricsApps[proc](world, host, req.path, now);
      return plain(r.status, r.body, now, r.status === 200 ? 'text/plain; version=0.0.4; charset=utf-8' : 'text/plain; charset=utf-8');
    }
    if (proc === 'prometheus-node') return path === '/' ? plain(200, '<html>\n<head><title>Node Exporter</title></head>\n<body>\n<h1>Node Exporter</h1>\n<p><a href="/metrics">Metrics</a></p>\n</body>\n</html>\n', now, 'text/html; charset=utf-8') : plain(404, '404 page not found\n', now);
    if (proc === 'prometheus') return promApi(world, host, req.method, path, params, now);
    return amApi(world, host, req.method, path, params, now);
  };
}

function promApi(world: World, host: Host, method: string, path: string, params: URLSearchParams, now: number): HttpResponse {
  const l = host.services.prometheus?.loaded as PromLoaded | null;
  if (!l) return plain(503, 'Service Unavailable\n', now);
  if (path === '/-/healthy') return plain(200, 'Prometheus Server is Healthy.\n', now);
  if (path === '/-/ready') return plain(200, 'Prometheus Server is Ready.\n', now);
  if (path === '/-/reload') {
    if (!l.lifecycle) return plain(403, 'Lifecycle API is not enabled.\n', now);
    if (method !== 'POST' && method !== 'PUT') return plain(405, 'Only POST or PUT requests allowed\n', now);
    promReload(world, host, host.services.prometheus);
    const after = host.services.prometheus.loaded as PromLoaded;
    return after.reloadOk ? plain(200, '', now) : plain(500, `failed to reload config: couldn't load configuration (--config.file="${PROM_CONFIG}"): ${loadPromConfig(host).error}\n`, now);
  }
  if (path === '/api/v1/query') {
    const q = params.get('query') ?? '';
    const at = params.get('time') ? Number(params.get('time')) * 1000 : now;
    try {
      const v = evaluate(promDataSource(l), parsePromQL(q), at);
      return json(200, { status: 'success', data: apiResult(v, at) }, now, '');
    } catch (e) {
      if (e instanceof PromQLError) return json(400, { status: 'error', errorType: 'bad_data', error: e.message.replace(/^\d+:\d+: /, (x) => x) }, now, '');
      return json(422, { status: 'error', errorType: 'execution', error: (e as Error).message }, now, '');
    }
  }
  if (path === '/api/v1/targets') {
    return json(200, { status: 'success', data: { activeTargets: l.targets.map((t) => ({ discoveredLabels: { __address__: t.address, __metrics_path__: l.config.scrapes.find((s) => s.job === t.job)?.path ?? '/metrics', __scheme__: 'http', job: t.job }, labels: t.labels, scrapePool: t.job, scrapeUrl: t.scrapeUrl, globalUrl: t.scrapeUrl, lastError: t.lastError, lastScrape: t.lastScrape ? isoTs(t.lastScrape) : '0001-01-01T00:00:00Z', lastScrapeDuration: t.durationMs / 1000, health: t.health, scrapeInterval: formatDuration(l.config.scrapes.find((s) => s.job === t.job)?.interval ?? 60_000), scrapeTimeout: formatDuration(l.config.scrapes.find((s) => s.job === t.job)?.timeout ?? 10_000) })), droppedTargets: [] } }, now, '');
  }
  if (path === '/api/v1/alerts') {
    return json(200, { status: 'success', data: { alerts: Object.values(l.alerts).filter((a) => a.resolvedAt === undefined).map((a) => ({ labels: a.labels, annotations: a.annotations, state: a.state, activeAt: isoTs(a.activeAt), value: formatValue(a.value) })) } }, now, '');
  }
  if (path === '/api/v1/rules') {
    const groups = [...new Set(l.config.rules.map((r) => `${r.file}\u0000${r.group}`))].map((g) => {
      const [file, name] = g.split('\u0000');
      return {
        name, file, interval: l.config.evalInterval / 1000,
        rules: l.config.rules.filter((r) => r.file === file && r.group === name).map((r) => {
          const alerts = Object.values(l.alerts).filter((a) => a.rule === r.name && a.resolvedAt === undefined);
          return r.kind === 'alert'
            ? { name: r.name, query: r.expr, duration: r.forMs / 1000, labels: r.labels, annotations: r.annotations, alerts: alerts.map((a) => ({ labels: a.labels, state: a.state, activeAt: isoTs(a.activeAt), value: formatValue(a.value) })), health: 'ok', type: 'alerting', state: alerts.some((a) => a.state === 'firing') ? 'firing' : alerts.length ? 'pending' : 'inactive' }
            : { name: r.name, query: r.expr, labels: r.labels, health: 'ok', type: 'recording' };
        }),
      };
    });
    return json(200, { status: 'success', data: { groups } }, now, '');
  }
  if (path === '/api/v1/status/config') return json(200, { status: 'success', data: { yaml: readFile(host, PROM_CONFIG) ?? '' } }, now, '');
  if (path === '/api/v1/status/buildinfo') return json(200, { status: 'success', data: { version: PROMETHEUS_VERSION, revision: '2.42.0+ds-5+b5', branch: 'debian/sid', goVersion: 'go1.19.8' } }, now, '');
  if (path === '/' || path === '/graph') return plain(200, '<!doctype html><html lang="en"><head><title>Prometheus Time Series Collection and Processing Server</title></head><body><div id="root"></div></body></html>\n', now, 'text/html; charset=utf-8');
  return plain(404, '404 page not found\n', now);
}

export function apiResult(v: Value, at: number): unknown {
  const ts = Math.round(at) / 1000;
  if (v.kind === 'scalar') return { resultType: 'scalar', result: [ts, formatValue(v.value)] };
  if (v.kind === 'string') return { resultType: 'string', result: [ts, v.value] };
  if (v.kind === 'matrix') return { resultType: 'matrix', result: v.series.map((s) => ({ metric: s.labels, values: s.samples.map(([t, x]) => [t / 1000, formatValue(x)]) })) };
  return { resultType: 'vector', result: v.samples.map((s) => ({ metric: s.labels, value: [ts, formatValue(s.value)] })) };
}

export function amApiAlerts(l: AmLoaded, now: number) {
  return Object.values(l.alerts).filter((a) => a.endsAt > now).map((a) => {
    const s = silencedBy(l, a.labels, now);
    return {
      labels: a.labels, annotations: a.annotations, startsAt: isoTs(a.startsAt), endsAt: isoTs(a.endsAt), updatedAt: isoTs(a.updatedAt), generatorURL: a.generator, fingerprint: fingerprint(a.labels),
      receivers: routeAlert(l.config.route, a.labels).map((r) => ({ name: r.receiver })),
      status: { state: s ? 'suppressed' : 'active', silencedBy: s ? [s.id] : [], inhibitedBy: [] },
    };
  });
}

export const fingerprint = (labels: Labels) => {
  let h = 0n;
  for (const c of keyOf(labels)) h = (h * 1099511628211n ^ BigInt(c.charCodeAt(0))) & 0xffffffffffffffffn;
  return h.toString(16).padStart(16, '0');
};

function amApi(world: World, host: Host, method: string, path: string, _params: URLSearchParams, now: number): HttpResponse {
  const l = host.services['prometheus-alertmanager']?.loaded as AmLoaded | null;
  if (!l) return plain(503, 'Service Unavailable\n', now);
  if (path === '/-/healthy') return plain(200, 'OK', now);
  if (path === '/-/ready') return plain(200, 'OK', now);
  if (path === '/-/reload') {
    if (method !== 'POST') return plain(405, 'Method Not Allowed\n', now);
    amReload(world, host, host.services['prometheus-alertmanager']);
    const c = loadAmConfig(host);
    return c.config ? plain(200, '', now) : plain(500, `failed to reload config: ${c.error}\n`, now);
  }
  if (path === '/api/v2/alerts') return json(200, amApiAlerts(l, now), now, '');
  if (path === '/api/v2/silences') return json(200, l.silences.map((s) => ({ id: s.id, matchers: s.matchers.map((m) => ({ name: m.name, value: m.value, isRegex: m.op.includes('~'), isEqual: !m.op.startsWith('!') })), startsAt: isoTs(s.startsAt), endsAt: isoTs(s.endsAt), createdBy: s.createdBy, comment: s.comment, status: { state: s.endsAt <= now ? 'expired' : s.startsAt > now ? 'pending' : 'active' } })), now, '');
  if (path === '/api/v2/status') return json(200, { cluster: { status: 'disabled' }, versionInfo: { version: ALERTMANAGER_VERSION }, config: { original: readFile(host, AM_CONFIG) ?? '' }, uptime: isoTs(host.services['prometheus-alertmanager'].since) }, now, '');
  if (path === '/' ) return plain(200, '<!DOCTYPE html><html><head><title>Alertmanager</title></head><body></body></html>\n', now, 'text/html; charset=utf-8');
  return plain(404, '404 page not found\n', now);
}

// ---------------------------------------------------------------------------
// systemd services
// ---------------------------------------------------------------------------

/** Listener rows for ss -tlnp. */
export function monitorListeners(service: string, rt: ServiceRuntime): Listener[] {
  if (rt.state !== 'active' || !rt.loaded) return [];
  if (service === 'prometheus-node-exporter') { const l = rt.loaded as NodeExporterLoaded; return [{ proto: 'tcp', addr: l.listen.addr, port: l.listen.port, process: 'prometheus-node', pid: l.pid, service }]; }
  if (service === 'prometheus') { const l = rt.loaded as PromLoaded; return [{ proto: 'tcp', addr: l.listen.addr, port: l.listen.port, process: 'prometheus', pid: l.pid, service }]; }
  const l = rt.loaded as AmLoaded;
  return [{ proto: 'tcp', addr: l.listen.addr, port: l.listen.port, process: 'prometheus-aler', pid: l.pid, service }, { proto: 'tcp', addr: '0.0.0.0', port: 9094, process: 'prometheus-aler', pid: l.pid, service }, { proto: 'udp', addr: '0.0.0.0', port: 9094, process: 'prometheus-aler', pid: l.pid, service }];
}

export const monitorStart = { nodeExporterStart, promStart, amStart, amReload };

/** Create the directories Debian's packages own. */
export function installMonitoringDirs(host: Host, t: number): void {
  for (const d of ['/etc/prometheus', '/etc/default', '/var/lib/prometheus', TEXTFILE_DIR]) if (!host.fs[d]) mkdir(host, d, t, d.startsWith('/var/lib') ? { mode: 0o755, owner: 'prometheus', group: 'prometheus' } : undefined);
}

