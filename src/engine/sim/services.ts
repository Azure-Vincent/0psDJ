// systemd-style service lifecycle and the per-service behaviour that matters for
// troubleshooting: config validation at start, bind() results, reload semantics,
// enablement at boot, and the sockets each service listens on.

import { effectiveConfig, formatErrors, parseSshdConfig, type SshdEffective } from '../config/sshdConfig';
import { emptyRuleset, NftError, parseRulesetFile } from '../config/nft';
import { parseInterfaces } from '../config/netconf';
import { parseZone, ZoneError, type Zone } from '../config/zone';
import { readFile } from '../fs';
import type { Host, ServiceRuntime, World } from '../types';
import { log } from './journal';
import { isLocalAddress, LOOPBACK } from './network';
import { parsePublicKey, type ParsedPublicKey } from './keys';

export interface Listener {
  proto: 'tcp' | 'udp';
  addr: string; // '0.0.0.0', '::' or a specific address
  port: number;
  process: string;
  pid: number;
  service: string;
}

export interface SshdLoaded {
  parsed: ReturnType<typeof loadSshdConfig>;
  effective: SshdEffective;
  hostKeys: { path: string; key: ParsedPublicKey }[];
  binds: { addr: string; port: number }[];
}

export interface NamedLoaded {
  zones: Zone[];
  failedZones: string[];
}

interface ServiceDef {
  name: string;
  unit: string;
  aliases: string[];
  description: string;
  oneshot?: boolean;
  start(world: World, host: Host, rt: ServiceRuntime): boolean;
  reload?(world: World, host: Host, rt: ServiceRuntime): boolean;
  stop?(world: World, host: Host, rt: ServiceRuntime): void;
  listeners(host: Host, rt: ServiceRuntime): Listener[];
  statusLines?(host: Host, rt: ServiceRuntime): string[];
  configFiles: string[];
}

function sysd(world: World, host: Host, msg: string, unit: string, priority: 'info' | 'err' | 'notice' = 'info') {
  log(world, host, 'systemd', msg, { pid: 1, unit, priority });
}

function allocPid(host: Host): number {
  host.nextPid += 7;
  return host.nextPid;
}

// ---------------------------------------------------------------------------
// sshd
// ---------------------------------------------------------------------------

export function loadSshdConfig(host: Host) {
  return parseSshdConfig(
    '/etc/ssh/sshd_config',
    (p) => readFile(host, p),
    () => Object.keys(host.fs).filter((p) => host.fs[p].type === 'file'),
  );
}

/** Run the equivalent of `sshd -t`; returns error lines (empty when valid). */
export function sshdTest(host: Host): { errors: string[]; parsed: ReturnType<typeof loadSshdConfig> } {
  const parsed = loadSshdConfig(host);
  const errors = formatErrors(parsed.errors);
  if (errors.length === 0) {
    const eff = effectiveConfig(parsed);
    const keys = eff.hostKeys.filter((p) => host.fs[p]);
    if (keys.length === 0) errors.push('sshd: no hostkeys available -- exiting.');
    for (const p of eff.hostKeys) {
      const n = host.fs[p];
      if (n && (n.mode & 0o077) !== 0) {
        errors.push(
          '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
          '@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @',
          '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
          `Permissions 0${(n.mode & 0o777).toString(8)} for '${p}' are too open.`,
          `Unable to load host key: ${p}`,
        );
      }
    }
    if (errors.length && eff.hostKeys.some((p) => host.fs[p] && (host.fs[p].mode & 0o077) === 0)) {
      // sshd only exits if *no* host key could be loaded; keep warnings but drop fatal status.
      return { errors: errors.filter((e) => !e.startsWith('sshd: no hostkeys')), parsed };
    }
  }
  return { errors, parsed };
}

function sshdLoad(world: World, host: Host, rt: ServiceRuntime, pid: number): SshdLoaded | null {
  const { errors, parsed } = sshdTest(host);
  const fatal = errors.some((e) => /Bad configuration|terminating|no hostkeys|unsupported|Badly formatted|Bad SSH2|missing argument|Invalid number|log level/.test(e));
  for (const e of errors) log(world, host, 'sshd', e, { pid, unit: 'ssh.service', priority: 'err' });
  if (fatal) return null;
  const eff = effectiveConfig(parsed);
  const hostKeys = eff.hostKeys
    .filter((p) => host.fs[p] && (host.fs[p].mode & 0o077) === 0 && host.fs[p + '.pub'])
    .map((p) => ({ path: p, key: parsePublicKey(readFile(host, p + '.pub') ?? '')! }))
    .filter((k) => k.key);
  if (hostKeys.length === 0) {
    log(world, host, 'sshd', 'sshd: no hostkeys available -- exiting.', { pid, unit: 'ssh.service', priority: 'err' });
    return null;
  }
  // bind()
  const wanted: { addr: string; port: number }[] = [];
  const addrs = eff.listenAddresses.length ? eff.listenAddresses : eff.addressFamily === 'inet6' ? ['::'] : eff.addressFamily === 'inet' ? ['0.0.0.0'] : ['0.0.0.0', '::'];
  for (const a of addrs) {
    const m = /^(.*):(\d+)$/.exec(a);
    if (m && !a.includes('::')) wanted.push({ addr: m[1], port: Number(m[2]) });
    else for (const p of eff.ports) wanted.push({ addr: a, port: p });
  }
  const others = allListeners(host).filter((l) => l.service !== 'ssh' && l.proto === 'tcp');
  const binds: SshdLoaded['binds'] = [];
  for (const w of wanted) {
    const v6 = w.addr.includes(':');
    if (!v6 && w.addr !== '0.0.0.0' && !isLocalAddress(host, w.addr)) {
      log(world, host, 'sshd', `error: Bind to port ${w.port} on ${w.addr} failed: Cannot assign requested address.`, { pid, unit: 'ssh.service', priority: 'err' });
      continue;
    }
    const conflict = others.find((o) => o.port === w.port && (o.addr === w.addr || o.addr === '0.0.0.0' || w.addr === '0.0.0.0' || o.addr === '::' || w.addr === '::'));
    if (conflict) {
      log(world, host, 'sshd', `error: Bind to port ${w.port} on ${w.addr} failed: Address already in use.`, { pid, unit: 'ssh.service', priority: 'err' });
      continue;
    }
    binds.push(w);
    log(world, host, 'sshd', `Server listening on ${w.addr} port ${w.port}.`, { pid, unit: 'ssh.service' });
  }
  if (binds.length === 0) {
    log(world, host, 'sshd', 'fatal: Cannot bind any address.', { pid, unit: 'ssh.service', priority: 'err' });
    return null;
  }
  void rt;
  return { parsed, effective: eff, hostKeys, binds };
}

const sshd: ServiceDef = {
  name: 'ssh',
  unit: 'ssh.service',
  aliases: ['sshd', 'sshd.service', 'ssh', 'ssh.service', 'openssh-server'],
  description: 'OpenBSD Secure Shell server',
  configFiles: ['/etc/ssh/sshd_config'],
  start(world, host, rt) {
    const pid = allocPid(host);
    const loaded = sshdLoad(world, host, rt, pid);
    if (!loaded) return false;
    rt.loaded = loaded;
    rt.pid = pid;
    return true;
  },
  reload(world, host, rt) {
    const test = sshdTest(host);
    if (test.errors.some((e) => /Bad configuration|terminating|no hostkeys|unsupported|Badly formatted|Bad SSH2/.test(e))) {
      for (const e of test.errors) log(world, host, 'sshd', e, { pid: allocPid(host), unit: 'ssh.service', priority: 'err' });
      return false;
    }
    log(world, host, 'sshd', 'Received SIGHUP; restarting.', { pid: rt.pid, unit: 'ssh.service' });
    const loaded = sshdLoad(world, host, rt, rt.pid!);
    if (!loaded) return false;
    rt.loaded = loaded;
    return true;
  },
  listeners(_host, rt) {
    const l = rt.loaded as SshdLoaded | null;
    if (!l) return [];
    return l.binds.map((b) => ({ proto: 'tcp' as const, addr: b.addr, port: b.port, process: 'sshd', pid: rt.pid!, service: 'ssh' }));
  },
  statusLines(_host, rt) {
    return rt.state === 'active' ? [`             └─${rt.pid} "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"`] : [];
  },
};

// ---------------------------------------------------------------------------
// BIND 9
// ---------------------------------------------------------------------------

function namedLoad(world: World, host: Host, pid: number): NamedLoaded {
  const conf = readFile(host, '/etc/bind/named.conf.local') ?? '';
  const zones: Zone[] = [];
  const failed: string[] = [];
  const re = /zone\s+"([^"]+)"\s*\{[^}]*?file\s+"([^"]+)"\s*;[^}]*\}\s*;/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(conf))) {
    const [, name, file] = m;
    const text = readFile(host, file);
    if (text === undefined) {
      log(world, host, 'named', `zone ${name}/IN: loading from master file ${file} failed: file not found`, { pid, unit: 'named.service', priority: 'err' });
      log(world, host, 'named', `zone ${name}/IN: not loaded due to errors.`, { pid, unit: 'named.service', priority: 'err' });
      failed.push(name);
      continue;
    }
    try {
      const z = parseZone(text, name, file);
      zones.push(z);
      log(world, host, 'named', `zone ${name}/IN: loaded serial ${z.serial}`, { pid, unit: 'named.service' });
    } catch (e) {
      const msg = e instanceof ZoneError ? e.message : String(e);
      log(world, host, 'named', `dns_master_load: ${msg}`, { pid, unit: 'named.service', priority: 'err' });
      log(world, host, 'named', `zone ${name}/IN: loading from master file ${file} failed: ${msg.split(': ').pop()}`, { pid, unit: 'named.service', priority: 'err' });
      log(world, host, 'named', `zone ${name}/IN: not loaded due to errors.`, { pid, unit: 'named.service', priority: 'err' });
      failed.push(name);
    }
  }
  return { zones, failedZones: failed };
}

const named: ServiceDef = {
  name: 'named',
  unit: 'named.service',
  aliases: ['named', 'named.service', 'bind9', 'bind9.service'],
  description: 'BIND Domain Name Server',
  configFiles: ['/etc/bind/named.conf.local'],
  start(world, host, rt) {
    const pid = allocPid(host);
    log(world, host, 'named', 'starting BIND 9.18.28-1~deb12u2-Debian (Extended Support Version) <id:>', { pid, unit: 'named.service' });
    rt.loaded = namedLoad(world, host, pid);
    log(world, host, 'named', 'all zones loaded', { pid, unit: 'named.service' });
    log(world, host, 'named', 'running', { pid, unit: 'named.service' });
    rt.pid = pid;
    return true;
  },
  reload(world, host, rt) {
    log(world, host, 'named', 'received control channel command \'reload\'', { pid: rt.pid, unit: 'named.service' });
    rt.loaded = namedLoad(world, host, rt.pid!);
    log(world, host, 'named', 'reloading zones succeeded', { pid: rt.pid, unit: 'named.service' });
    return true;
  },
  listeners(_host, rt) {
    const pid = rt.pid!;
    return [
      { proto: 'udp', addr: '0.0.0.0', port: 53, process: 'named', pid, service: 'named' },
      { proto: 'tcp', addr: '0.0.0.0', port: 53, process: 'named', pid, service: 'named' },
      { proto: 'tcp', addr: '127.0.0.1', port: 953, process: 'named', pid, service: 'named' },
    ];
  },
};

// ---------------------------------------------------------------------------
// nftables (oneshot loader for /etc/nftables.conf)
// ---------------------------------------------------------------------------

const nftables: ServiceDef = {
  name: 'nftables',
  unit: 'nftables.service',
  aliases: ['nftables', 'nftables.service'],
  description: 'nftables',
  oneshot: true,
  configFiles: ['/etc/nftables.conf'],
  start(world, host) {
    try {
      host.nft = parseRulesetFile(readFile(host, '/etc/nftables.conf') ?? '');
      return true;
    } catch (e) {
      log(world, host, 'nft', e instanceof NftError ? e.message : String(e), { pid: allocPid(host), unit: 'nftables.service', priority: 'err' });
      return false;
    }
  },
  // Debian's unit: ExecReload=/usr/sbin/nft -f /etc/nftables.conf. nft -f is atomic:
  // if the file has an error nothing changes and the old ruleset stays loaded.
  reload(world, host) {
    try {
      host.nft = parseRulesetFile(readFile(host, '/etc/nftables.conf') ?? '');
      return true;
    } catch (e) {
      log(world, host, 'nft', e instanceof NftError ? e.message : String(e), { pid: allocPid(host), unit: 'nftables.service', priority: 'err' });
      return false;
    }
  },
  // ExecStop=/usr/sbin/nft flush ruleset: stopping (and therefore restarting) removes every rule.
  stop(_world, host) {
    host.nft = emptyRuleset();
  },
  listeners: () => [],
};

// ---------------------------------------------------------------------------
// nginx (present so that port ownership and `ss` output are realistic)
// ---------------------------------------------------------------------------

const nginx: ServiceDef = {
  name: 'nginx',
  unit: 'nginx.service',
  aliases: ['nginx', 'nginx.service'],
  description: 'A high performance web server and a reverse proxy server',
  configFiles: ['/etc/nginx/nginx.conf'],
  start(_world, host, rt) {
    rt.pid = allocPid(host);
    return true;
  },
  listeners(_host, rt) {
    return [
      { proto: 'tcp', addr: '0.0.0.0', port: 80, process: 'nginx', pid: rt.pid!, service: 'nginx' },
      { proto: 'tcp', addr: '::', port: 80, process: 'nginx', pid: rt.pid!, service: 'nginx' },
    ];
  },
};

// ---------------------------------------------------------------------------
// networking (ifupdown)
// ---------------------------------------------------------------------------

/** Apply /etc/network/interfaces to runtime interface/route state. */
export function applyNetworkConfig(world: World, host: Host): string[] {
  const { ifaces, errors } = parseInterfaces(readFile(host, '/etc/network/interfaces') ?? '');
  host.routes = [];
  for (const i of host.ifaces) {
    if (i.name === LOOPBACK) continue;
    i.address = null;
    i.prefix = null;
    i.up = false;
  }
  for (const cfg of ifaces) {
    const iface = host.ifaces.find((i) => i.name === cfg.name);
    if (!iface || iface.name === LOOPBACK || !cfg.auto) continue;
    iface.up = true;
    if (cfg.method === 'static' && cfg.address) {
      iface.address = cfg.address;
      iface.prefix = cfg.prefix ?? 24;
    }
    if (cfg.gateway) host.routes.push({ dest: 'default', via: cfg.gateway, dev: iface.name, proto: 'boot' });
    for (const r of cfg.routes) host.routes.push({ dest: r.dest, via: r.via, dev: iface.name, proto: 'boot' });
  }
  host.neighbors = [];
  for (const e of errors) log(world, host, 'ifup', e, { unit: 'networking.service', priority: 'err' });
  return errors;
}

const networking: ServiceDef = {
  name: 'networking',
  unit: 'networking.service',
  aliases: ['networking', 'networking.service'],
  description: 'Raise network interfaces',
  oneshot: true,
  configFiles: ['/etc/network/interfaces'],
  start(world, host) {
    return applyNetworkConfig(world, host).length === 0;
  },
  listeners: () => [],
};

export const SERVICE_DEFS: ServiceDef[] = [networking, nftables, named, sshd, nginx];

export function findService(host: Host, name: string): ServiceDef | undefined {
  const n = name.replace(/\.service$/, '');
  return SERVICE_DEFS.find((d) => host.services[d.name] && (d.name === n || d.aliases.includes(name) || d.aliases.includes(n)));
}

export function serviceDef(name: string): ServiceDef | undefined {
  return SERVICE_DEFS.find((d) => d.name === name);
}

// ---------------------------------------------------------------------------
// Lifecycle operations (what `systemctl` does)
// ---------------------------------------------------------------------------

export function startService(world: World, host: Host, def: ServiceDef): boolean {
  const rt = host.services[def.name];
  if (rt.state === 'active') return true;
  sysd(world, host, `Starting ${def.unit} - ${def.description}...`, def.unit);
  world.clock += 150;
  const ok = def.start(world, host, rt);
  rt.since = world.clock;
  if (ok) {
    rt.state = 'active';
    rt.result = 'success';
    sysd(world, host, `${def.oneshot ? 'Finished' : 'Started'} ${def.unit} - ${def.description}.`, def.unit);
  } else {
    rt.state = 'failed';
    rt.pid = null;
    rt.loaded = null;
    rt.result = 'exit-code';
    sysd(world, host, `${def.unit}: Control process exited, code=exited, status=255/EXCEPTION`, def.unit, 'notice');
    sysd(world, host, `${def.unit}: Failed with result 'exit-code'.`, def.unit, 'notice');
    sysd(world, host, `Failed to start ${def.unit} - ${def.description}.`, def.unit, 'err');
  }
  return ok;
}

export function stopService(world: World, host: Host, def: ServiceDef): void {
  const rt = host.services[def.name];
  if (rt.state !== 'active') {
    rt.state = 'inactive';
    return;
  }
  sysd(world, host, `Stopping ${def.unit} - ${def.description}...`, def.unit);
  def.stop?.(world, host, rt);
  rt.state = 'inactive';
  rt.pid = null;
  rt.loaded = null;
  rt.result = 'success';
  rt.since = world.clock;
  sysd(world, host, `${def.unit}: Deactivated successfully.`, def.unit);
  sysd(world, host, `Stopped ${def.unit} - ${def.description}.`, def.unit);
}

export function restartService(world: World, host: Host, def: ServiceDef): boolean {
  stopService(world, host, def);
  return startService(world, host, def);
}

export function reloadService(world: World, host: Host, def: ServiceDef): { ok: boolean; message?: string } {
  const rt = host.services[def.name];
  if (rt.state !== 'active') return { ok: false, message: `${def.unit} is not active, cannot reload.` };
  if (!def.reload) {
    if (def.oneshot) return { ok: restartService(world, host, def) };
    return { ok: false, message: `Failed to reload ${def.unit}: Job type reload is not applicable for unit ${def.unit}.` };
  }
  sysd(world, host, `Reloading ${def.unit} - ${def.description}...`, def.unit);
  const ok = def.reload(world, host, rt);
  if (ok) sysd(world, host, `Reloaded ${def.unit} - ${def.description}.`, def.unit);
  else {
    sysd(world, host, `${def.unit}: Control process exited, code=exited, status=255/EXCEPTION`, def.unit, 'notice');
    sysd(world, host, `Reload failed for ${def.unit} - ${def.description}.`, def.unit, 'err');
  }
  return { ok, message: ok ? undefined : `Job for ${def.unit} failed.\nSee "systemctl status ${def.unit}" and "journalctl -xeu ${def.unit}" for details.` };
}

export function allListeners(host: Host): Listener[] {
  const out: Listener[] = [];
  for (const def of SERVICE_DEFS) {
    const rt = host.services[def.name];
    if (rt && rt.state === 'active') out.push(...def.listeners(host, rt));
  }
  return out;
}

export function findListener(host: Host, proto: 'tcp' | 'udp', addr: string, port: number): Listener | undefined {
  return allListeners(host).find(
    (l) => l.proto === proto && l.port === port && (l.addr === addr || l.addr === '0.0.0.0' || (l.addr === '127.0.0.1' && addr.startsWith('127.'))),
  );
}

/** Simulated reboot: runtime state is discarded and rebuilt from persistent files. */
export function bootHost(world: World, host: Host): void {
  host.conntrack = [];
  host.neighbors = [];
  host.nft = emptyRuleset();
  for (const rt of Object.values(host.services)) {
    rt.state = 'inactive';
    rt.pid = null;
    rt.loaded = null;
    rt.result = 'success';
  }
  for (const i of host.ifaces) if (i.name === LOOPBACK) { i.up = true; i.address = '127.0.0.1'; i.prefix = 8; }
  world.clock += 1000;
  host.bootTime = world.clock;
  host.nextPid = 400;
  log(world, host, 'kernel', 'Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1');
  const sysctl = Object.keys(host.fs)
    .filter((p) => p === '/etc/sysctl.conf' || p.startsWith('/etc/sysctl.d/'))
    .map((p) => readFile(host, p) ?? '')
    .join('\n');
  host.ipForward = /^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$/m.test(sysctl);
  // networking always runs at boot on these Debian hosts (it is enabled by default)
  for (const def of SERVICE_DEFS) {
    const rt = host.services[def.name];
    if (!rt) continue;
    if (rt.enabled) startService(world, host, def);
  }
  if (!host.services.networking) applyNetworkConfig(world, host);
}
