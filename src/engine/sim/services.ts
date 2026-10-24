// systemd-style service lifecycle and the per-service behaviour that matters for
// troubleshooting: config validation at start, bind() results, reload semantics,
// enablement at boot, and the sockets each service listens on.

import { faillockClearAll } from './accounts';
import { effectiveConfig, formatErrors, parseSshdConfig, type SshdEffective } from '../config/sshdConfig';
import { emptyRuleset, NftError, parseRulesetFile } from '../config/nft';
import { parseInterfaces, vlanOf } from '../config/netconf';
import { parseZone, ZoneError, type Zone } from '../config/zone';
import { DhcpConfigError, parseDhcpdConf } from '../config/dhcpd';
import { escapeBinary, inPrefix6, parseDhcpd6Conf, parseLeases6 } from '../config/dhcpd6';
import { dhcp6Acquire, duidLlt, LEASES6, type Dhcpd6Loaded } from './dhcp6';
import { dhcpAcquire, type DhcpdLoaded } from './dhcp';
import { inCidr, parseCidr, parseIp } from '../net/ip';
import { readFile, writeFile } from '../fs';
import { parseNginxServers } from '../config/nginx';
import { type Cert, parseCerts, parseKey } from './pki';
import type { Host, ServiceRuntime, World } from '../types';
import { log } from './journal';
import { isLocalAddress, LOOPBACK } from './network';
import { linkLocalFromMac } from '../net/ip6';
import { bridgeFromConfig, recomputeL2 } from './l2';
import { parseRadvdConf, RadvdConfigError, routerSolicit, sendRa, type RadvdLoaded } from './slaac';
import { parsePublicKey, type ParsedPublicKey } from './keys';
import { bootWindows, winListeners } from '../win/model';
import { bootPfsense, pfListeners } from '../pf/model';
import { parseKadmAcl, parseKdcConf, parsePrincipalDb, ProfileError, type KdcConf } from '../config/krb5';

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
      // Debian's named.conf.options has "listen-on-v6 { any; };"
      { proto: 'udp', addr: '::', port: 53, process: 'named', pid, service: 'named' },
      { proto: 'tcp', addr: '::', port: 53, process: 'named', pid, service: 'named' },
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

export interface NginxLoadedServer {
  listens: { addr: string; port: number; ssl: boolean; def: boolean }[];
  names: string[];
  root: string;
  index: string[];
  ret?: { code: number; target: string };
  /** Certificate chain and key id as read at (re)load time: nginx keeps them in memory. */
  tls?: { chain: Cert[]; keyId: string; certPath: string };
}

export interface NginxLoaded {
  binds: { addr: string; port: number }[];
  servers?: NginxLoadedServer[];
}

const NO_FILE = (path: string) => `BIO_new_file() failed (SSL: error:80000002:system library::No such file or directory:calling fopen(${path}, r) error:10000080:BIO routines::no such file)`;

/**
 * Load the server blocks the way nginx does at start and reload, including the TLS
 * certificate/key checks (missing file, no PEM data, key values mismatch).
 */
export function loadNginxServers(host: Host, file = '/etc/nginx/nginx.conf'): { servers: NginxLoadedServer[]; errors: string[] } {
  const errors: string[] = [];
  const servers: NginxLoadedServer[] = [];
  for (const s of parseNginxServers(readFile(host, file) ?? '')) {
    const ls: NginxLoadedServer = { listens: s.listens.map(({ addr, port, ssl, def }) => ({ addr, port, ssl, def })), names: s.names, root: s.root, index: s.index, ret: s.ret };
    const sslListen = s.listens.find((l) => l.ssl);
    if (sslListen) {
      if (!s.cert) {
        errors.push(`nginx: [emerg] no "ssl_certificate" is defined for the "listen ... ssl" directive in ${file}:${sslListen.line}`);
        continue;
      }
      const certText = readFile(host, s.cert.path);
      if (certText === undefined) { errors.push(`nginx: [emerg] cannot load certificate "${s.cert.path}": ${NO_FILE(s.cert.path)}`); continue; }
      const chain = parseCerts(certText).filter((c): c is Cert => !!c);
      if (chain.length === 0) { errors.push(`nginx: [emerg] cannot load certificate "${s.cert.path}": PEM_read_bio_X509_AUX() failed (SSL: error:0480006C:PEM routines::no start line:Expecting: TRUSTED CERTIFICATE)`); continue; }
      if (!s.key) { errors.push(`nginx: [emerg] no "ssl_certificate_key" is defined for certificate "${s.cert.path}" in ${file}:${s.cert.line}`); continue; }
      const keyText = readFile(host, s.key.path);
      if (keyText === undefined) { errors.push(`nginx: [emerg] cannot load certificate key "${s.key.path}": ${NO_FILE(s.key.path)}`); continue; }
      const key = parseKey(keyText);
      if (!key) { errors.push(`nginx: [emerg] cannot load certificate key "${s.key.path}": PEM_read_bio_PrivateKey() failed (SSL: error:1E08010C:DECODER routines::unsupported:No supported data to decode. Input type: PEM)`); continue; }
      if (key.keyId !== chain[0].keyId) { errors.push(`nginx: [emerg] SSL_CTX_use_PrivateKey("${s.key.path}") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)`); continue; }
      ls.tls = { chain, keyId: key.keyId, certPath: s.cert.path };
    }
    servers.push(ls);
  }
  return { servers, errors };
}

/** Parse the `listen` directives of nginx.conf (nginx -t subset). Returns errors in nginx's format. */
export function parseNginxListens(text: string, file = '/etc/nginx/nginx.conf'): { binds: { addr: string; port: number }[]; errors: string[] } {
  const binds: { addr: string; port: number }[] = [];
  const errors: string[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    const m = /^listen\s+([^\s;]+)[^;]*;?$/.exec(line);
    if (!line.startsWith('listen')) return;
    if (!m || !line.endsWith(';')) {
      errors.push(`nginx: [emerg] invalid number of arguments in "listen" directive in ${file}:${i + 1}`);
      return;
    }
    const spec = m[1];
    let addr = '0.0.0.0';
    let portStr = spec;
    const v6 = /^\[(.*)\]:(\d+)$/.exec(spec);
    if (v6) { addr = v6[1] || '::'; portStr = v6[2]; }
    else if (spec.includes(':')) { [addr, portStr] = spec.split(':'); }
    const port = Number(portStr);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push(`nginx: [emerg] invalid port in "${spec}" of the "listen" directive in ${file}:${i + 1}`);
      return;
    }
    if (!binds.some((b) => b.addr === addr && b.port === port)) binds.push({ addr, port });
  });
  return { binds, errors };
}

function nginxLoad(world: World, host: Host, pid: number): NginxLoaded | null {
  const parsed = parseNginxListens(readFile(host, '/etc/nginx/nginx.conf') ?? '');
  const { binds } = parsed;
  const loaded = parsed.errors.length ? { servers: [], errors: [] } : loadNginxServers(host);
  const errors = [...parsed.errors, ...loaded.errors];
  for (const e of errors) log(world, host, 'nginx', e, { pid, unit: 'nginx.service', priority: 'err' });
  if (errors.length) {
    log(world, host, 'nginx', 'nginx: configuration file /etc/nginx/nginx.conf test failed', { pid, unit: 'nginx.service', priority: 'err' });
    return null;
  }
  const others = allListeners(host).filter((l) => l.service !== 'nginx' && l.proto === 'tcp');
  for (const b of binds) {
    if (!b.addr.includes(':') && b.addr !== '0.0.0.0' && !isLocalAddress(host, b.addr)) {
      log(world, host, 'nginx', `nginx: [emerg] bind() to ${b.addr}:${b.port} failed (99: Cannot assign requested address)`, { pid, unit: 'nginx.service', priority: 'err' });
      return null;
    }
    if (others.some((o) => o.port === b.port && (o.addr === b.addr || o.addr === '0.0.0.0' || b.addr === '0.0.0.0'))) {
      log(world, host, 'nginx', `nginx: [emerg] bind() to ${b.addr}:${b.port} failed (98: Address already in use)`, { pid, unit: 'nginx.service', priority: 'err' });
      return null;
    }
  }
  return { binds, servers: loaded.servers };
}

const nginx: ServiceDef = {
  name: 'nginx',
  unit: 'nginx.service',
  aliases: ['nginx', 'nginx.service'],
  description: 'A high performance web server and a reverse proxy server',
  configFiles: ['/etc/nginx/nginx.conf'],
  start(world, host, rt) {
    const pid = allocPid(host);
    const loaded = nginxLoad(world, host, pid);
    if (!loaded) return false;
    rt.pid = pid;
    rt.loaded = loaded;
    return true;
  },
  reload(world, host, rt) {
    const loaded = nginxLoad(world, host, rt.pid!);
    if (!loaded) return false;
    rt.loaded = loaded;
    return true;
  },
  listeners(_host, rt) {
    const l = rt.loaded as NginxLoaded | null;
    return (l?.binds ?? []).map((b) => ({ proto: 'tcp' as const, addr: b.addr, port: b.port, process: 'nginx', pid: rt.pid!, service: 'nginx' }));
  },
};

// ---------------------------------------------------------------------------
// ISC DHCP server
// ---------------------------------------------------------------------------

export function dhcpdInterfaces(host: Host, family: 4 | 6 = 4): string[] {
  const re = family === 4 ? /^INTERFACESv4="([^"]*)"/m : /^INTERFACESv6="([^"]*)"/m;
  const m = re.exec(readFile(host, '/etc/default/isc-dhcp-server') ?? '');
  return m ? m[1].split(/\s+/).filter(Boolean) : [];
}

/** dhcpd -t [-6]: returns error lines (empty when valid). */
export function dhcpdTest(host: Host, family: 4 | 6 = 4, file?: string): string[] {
  const path = file ?? (family === 4 ? '/etc/dhcp/dhcpd.conf' : '/etc/dhcp/dhcpd6.conf');
  const text = readFile(host, path);
  if (text === undefined) return [`Can't open ${path}: No such file or directory`];
  try {
    if (family === 4) parseDhcpdConf(text, path);
    else parseDhcpd6Conf(text, path);
    return [];
  } catch (e) {
    return [e instanceof DhcpConfigError ? e.message : String(e), 'Configuration file errors encountered -- exiting'];
  }
}

function startDhcpd4(world: World, host: Host, pid: number): DhcpdLoaded | null {
  const l = (m: string, prio: 'info' | 'err' = 'info') => log(world, host, 'dhcpd', m, { pid, unit: 'isc-dhcp-server.service', priority: prio });
  l('Internet Systems Consortium DHCP Server 4.4.3-P1');
  let config;
  try {
    config = parseDhcpdConf(readFile(host, '/etc/dhcp/dhcpd.conf') ?? '');
  } catch (e) {
    l(e instanceof DhcpConfigError ? e.message : String(e), 'err');
    l('Configuration file errors encountered -- exiting', 'err');
    return null;
  }
  const usable: string[] = [];
  for (const name of dhcpdInterfaces(host)) {
    const iface = host.ifaces.find((i) => i.name === name);
    if (!iface || !iface.address) {
      l(`No subnet declaration for ${name} (no IPv4 addresses).`, 'err');
      l(`** Ignoring requests on ${name}.  If this is not what`, 'err');
      continue;
    }
    const sub = config.subnets.find((s) => inCidr(iface.address!, parseCidr(`${s.network}/${s.prefix}`)!));
    if (!sub) {
      l(`No subnet declaration for ${name} (${iface.address}).`, 'err');
      l(`** Ignoring requests on ${name}.  If this is not what`, 'err');
      continue;
    }
    l(`Listening on LPF/${name}/${iface.mac}/${sub.network}/${sub.prefix}`);
    l(`Sending on   LPF/${name}/${iface.mac}/${sub.network}/${sub.prefix}`);
    usable.push(name);
  }
  if (usable.length === 0) {
    l('Not configured to listen on any interfaces!', 'err');
    return null;
  }
  l('Server starting service.');
  return { config, interfaces: usable };
}

function startDhcpd6(world: World, host: Host, pid: number): Dhcpd6Loaded | null {
  const l = (m: string, prio: 'info' | 'err' = 'info') => log(world, host, 'dhcpd', m, { pid, unit: 'isc-dhcp-server.service', priority: prio });
  l('Internet Systems Consortium DHCP Server 4.4.3-P1');
  const text = readFile(host, '/etc/dhcp/dhcpd6.conf');
  if (text === undefined) {
    l("Can't open /etc/dhcp/dhcpd6.conf: No such file or directory", 'err');
    return null;
  }
  let config;
  try {
    config = parseDhcpd6Conf(text);
  } catch (e) {
    l(e instanceof DhcpConfigError ? e.message : String(e), 'err');
    l('Configuration file errors encountered -- exiting', 'err');
    return null;
  }
  const leases = parseLeases6(readFile(host, LEASES6) ?? '').filter((x) => x.state === 'active' && x.ends > world.clock);
  l(`Wrote ${leases.length} NA, 0 TA, 0 PD leases to lease file.`);
  l('Bound to *:547');
  const usable: Dhcpd6Loaded['interfaces'] = [];
  for (const name of dhcpdInterfaces(host, 6)) {
    const iface = host.ifaces.find((i) => i.name === name);
    // dhcpd -6 serves a link when one of the interface's own global addresses lies in a subnet6.
    const globals = (iface?.addrs6 ?? []).filter((a) => a.scope === 'global' && a.origin !== 'dhcp6');
    const sub = config.subnets.find((s) => globals.some((a) => inPrefix6(a.address, s.prefix)));
    if (!iface || !iface.up || !sub) {
      const ll = iface?.addrs6?.find((a) => a.scope === 'link')?.address;
      l(`No subnet6 declaration for ${name} (${globals[0]?.address ?? ll ?? 'no IPv6 addresses'}).`, 'err');
      l(`** Ignoring requests on ${name}.  If this is not what`, 'err');
      l('   you want, please write a subnet6 declaration', 'err');
      l('   in your dhcpd.conf file for the network segment', 'err');
      l(`   to which interface ${name} is attached. **`, 'err');
      continue;
    }
    l(`Listening on Socket/${name}/${sub.prefix}`);
    l(`Sending on   Socket/${name}/${sub.prefix}`);
    usable.push({ name, subnet: sub.prefix });
  }
  if (usable.length === 0) {
    l('Not configured to listen on any interfaces!', 'err');
    return null;
  }
  // dhcpd creates its DUID-LLT once and keeps it in the lease file.
  const leaseText = readFile(host, LEASES6) ?? '';
  const first = host.ifaces.find((i) => i.name === usable[0].name)!;
  const duid = duidLlt(first.mac);
  if (!/^server-duid /m.test(leaseText)) writeFile(host, LEASES6, `${leaseText}server-duid "${escapeBinary(duid.split(':').map((x) => parseInt(x, 16)))}";\n\n`, world.clock);
  l('Server starting service.');
  return { config, interfaces: usable, duid };
}

const dhcpd: ServiceDef = {
  name: 'dhcpd',
  unit: 'isc-dhcp-server.service',
  aliases: ['isc-dhcp-server', 'isc-dhcp-server.service', 'dhcpd'],
  description: 'LSB: DHCP server',
  configFiles: ['/etc/dhcp/dhcpd.conf', '/etc/dhcp/dhcpd6.conf', '/etc/default/isc-dhcp-server'],
  start(world, host, rt) {
    // The Debian init script starts dhcpd -4 and/or dhcpd -6 depending on INTERFACESv4/INTERFACESv6.
    const has4 = dhcpdInterfaces(host, 4).length > 0;
    const has6 = dhcpdInterfaces(host, 6).length > 0;
    const script = allocPid(host);
    log(world, host, 'isc-dhcp-server', has4 && !has6 ? 'Launching IPv4 server only.' : !has4 && has6 ? 'Launching IPv6 server only.' : 'Launching both IPv4 and IPv6 servers (please configure INTERFACES in /etc/default/isc-dhcp-server if you only want one or the other).', { pid: script, unit: 'isc-dhcp-server.service' });
    const run4 = has4 || !has6;
    const pid4 = run4 ? allocPid(host) : 0;
    const v4 = run4 ? startDhcpd4(world, host, pid4) : null;
    const pid6 = has6 ? allocPid(host) : 0;
    const v6 = has6 ? startDhcpd6(world, host, pid6) : null;
    if ((run4 && !v4) || (has6 && !v6)) {
      log(world, host, 'isc-dhcp-server', `Starting ISC DHCP${run4 && !v4 ? 'v4' : 'v6'} server: dhcpd${run4 && !v4 ? '' : '6'}check syslog for diagnostics. ... failed!`, { pid: script, unit: 'isc-dhcp-server.service', priority: 'err' });
      return false;
    }
    rt.pid = run4 ? pid4 : pid6;
    rt.loaded = { config: v4?.config ?? parseDhcpdConf(''), interfaces: v4?.interfaces ?? [], v6: v6 ?? undefined, pid6: v6 ? pid6 : undefined } satisfies DhcpdLoaded;
    return true;
  },
  listeners(_host, rt) {
    const loaded = rt.loaded as DhcpdLoaded | null;
    const out: Listener[] = [];
    if (loaded?.interfaces.length) out.push({ proto: 'udp', addr: '0.0.0.0', port: 67, process: 'dhcpd', pid: rt.pid!, service: 'dhcpd' });
    if (loaded?.v6) out.push({ proto: 'udp', addr: '::', port: 547, process: 'dhcpd', pid: loaded.pid6!, service: 'dhcpd' });
    return out;
  },
};

// ---------------------------------------------------------------------------
// ISC DHCP relay agent (isc-dhcp-relay, dhcrelay)
// ---------------------------------------------------------------------------

export interface DhcrelayLoaded {
  servers: string[];
  /** Interfaces where client broadcasts are accepted (-id, or the legacy -i/INTERFACES list). */
  downstream: string[];
  /** Interfaces where server replies are read with a packet socket (-iu, or -i/INTERFACES). */
  upstream: string[];
}

function defaultsVar(text: string, name: string): string[] {
  const m = new RegExp(`^${name}="([^"]*)"`, 'm').exec(text);
  return m ? m[1].split(/\s+/).filter(Boolean) : [];
}

const dhcrelay: ServiceDef = {
  name: 'dhcrelay',
  unit: 'isc-dhcp-relay.service',
  aliases: ['isc-dhcp-relay', 'isc-dhcp-relay.service', 'dhcrelay'],
  description: 'LSB: DHCP relay',
  configFiles: ['/etc/default/isc-dhcp-relay'],
  start(world, host, rt) {
    const pid = allocPid(host);
    const l = (m: string, prio: 'info' | 'err' = 'info') => log(world, host, 'dhcrelay', m, { pid, unit: 'isc-dhcp-relay.service', priority: prio });
    const text = readFile(host, '/etc/default/isc-dhcp-relay') ?? '';
    const servers = defaultsVar(text, 'SERVERS');
    const interfaces = defaultsVar(text, 'INTERFACES');
    // OPTIONS may carry -id IFACE (downstream only) and -iu IFACE (upstream only), as recommended
    // for ISC dhcrelay 4.4 so that the relay does not also relay broadcasts on the server side.
    const opts = defaultsVar(text, 'OPTIONS');
    const down = [...interfaces];
    const up = [...interfaces];
    for (let i = 0; i < opts.length; i++) {
      if (opts[i] === '-id' && opts[i + 1]) down.push(opts[++i]);
      else if (opts[i] === '-iu' && opts[i + 1]) up.push(opts[++i]);
      else if (opts[i] === '-i' && opts[i + 1]) { down.push(opts[i + 1]); up.push(opts[++i]); }
    }
    l('Internet Systems Consortium DHCP Relay Agent 4.4.3-P1');
    l('Copyright 2004-2022 Internet Systems Consortium.');
    l('All rights reserved.');
    l('For info, please visit https://www.isc.org/software/dhcp/');
    if (servers.length === 0) {
      l('No servers specified.', 'err');
      l('Usage: dhcrelay [-4] [-d] [-q] [-a] [-D] [-A <length>] [-c <hops>] [-p <port>] [-pf <pid-file>] [--no-pid] [-m append|replace|forward|discard] [-i interface0 [ ... -i interfaceN] server0 [ ... serverN]', 'err');
      return false;
    }
    for (const s of servers) {
      if (parseIp(s) === null) {
        l(`${s}: host unknown`, 'err');
        return false;
      }
    }
    for (const name of [...new Set([...down, ...up])]) {
      const iface = host.ifaces.find((i) => i.name === name);
      if (!iface) {
        l(`Error getting hardware address for "${name}": No such device`, 'err');
        return false;
      }
      l(`Listening on LPF/${name}/${iface.mac}`);
      l(`Sending on   LPF/${name}/${iface.mac}`);
    }
    l('Sending on   Socket/fallback');
    rt.pid = pid;
    rt.loaded = { servers, downstream: down, upstream: up } satisfies DhcrelayLoaded;
    return true;
  },
  listeners(_host, rt) {
    return [{ proto: 'udp', addr: '0.0.0.0', port: 67, process: 'dhcrelay', pid: rt.pid!, service: 'dhcrelay' }];
  },
};

// ---------------------------------------------------------------------------
// radvd (IPv6 router advertisement daemon)
// ---------------------------------------------------------------------------

function radvdLoad(world: World, host: Host, pid: number): RadvdLoaded | null {
  const l = (m: string, prio: 'info' | 'err' | 'warning' = 'info') => log(world, host, 'radvd', m, { pid, unit: 'radvd.service', priority: prio });
  let ifaces;
  try {
    ifaces = parseRadvdConf(readFile(host, '/etc/radvd.conf') ?? '');
  } catch (e) {
    l(e instanceof RadvdConfigError ? e.message : String(e), 'err');
    l('error parsing or activating the config file: /etc/radvd.conf', 'err');
    return null;
  }
  if (!host.ip6Forward) {
    l('IPv6 forwarding setting is: 0, should be 1 or 2', 'warning');
    l('IPv6 forwarding seems to be disabled, but continuing anyway', 'warning');
  }
  for (const c of ifaces) {
    const i = host.ifaces.find((x) => x.name === c.name);
    if (!i || !i.up) l(`interface ${c.name} does not exist or is not set up properly, ignoring the interface`, 'warning');
  }
  return { ifaces };
}

function radvdAdvertise(world: World, host: Host, loaded: RadvdLoaded) {
  for (const c of loaded.ifaces) {
    const i = host.ifaces.find((x) => x.name === c.name);
    if (i?.up) sendRa(world, host, i, c);
  }
}

const radvd: ServiceDef = {
  name: 'radvd',
  unit: 'radvd.service',
  aliases: ['radvd', 'radvd.service'],
  description: 'Router advertisement daemon for IPv6',
  configFiles: ['/etc/radvd.conf'],
  start(world, host, rt) {
    const pid = allocPid(host);
    const loaded = radvdLoad(world, host, pid);
    if (!loaded) return false;
    rt.pid = pid;
    rt.loaded = loaded;
    log(world, host, 'radvd', `version 2.19 started`, { pid, unit: 'radvd.service' });
    radvdAdvertise(world, host, loaded);
    return true;
  },
  reload(world, host, rt) {
    const loaded = radvdLoad(world, host, rt.pid!);
    if (!loaded) return false;
    rt.loaded = loaded;
    radvdAdvertise(world, host, loaded);
    return true;
  },
  listeners: () => [],
};

// ---------------------------------------------------------------------------
// MIT Kerberos KDC (krb5kdc) and admin server (kadmind)
// ---------------------------------------------------------------------------

const KDC_CONF = '/etc/krb5kdc/kdc.conf';

function loadKdcConf(world: World, host: Host, ident: string, unit: string, pid: number): KdcConf | null {
  try {
    const conf = parseKdcConf(readFile(host, KDC_CONF));
    for (const [realm, r] of Object.entries(conf.realms)) {
      if (parsePrincipalDb(readFile(host, r.databaseName)) === null) {
        log(world, host, ident, `Cannot open DB2 database '${r.databaseName}': No such file or directory - while initializing database for realm ${realm}`, { pid, unit, priority: 'err' });
        return null;
      }
    }
    if (!Object.keys(conf.realms).length) {
      log(world, host, ident, 'No realms specified in kdc.conf - while initializing realms', { pid, unit, priority: 'err' });
      return null;
    }
    return conf;
  } catch (e) {
    if (!(e instanceof ProfileError)) throw e;
    log(world, host, ident, `Improper format of Kerberos configuration file (${e.message}) - while initializing`, { pid, unit, priority: 'err' });
    return null;
  }
}

const krb5kdc: ServiceDef = {
  name: 'krb5-kdc',
  unit: 'krb5-kdc.service',
  aliases: ['krb5-kdc', 'krb5-kdc.service', 'krb5kdc'],
  description: 'Kerberos 5 Key Distribution Center',
  configFiles: [KDC_CONF],
  start(world, host, rt) {
    const pid = allocPid(host);
    const conf = loadKdcConf(world, host, 'krb5kdc', 'krb5-kdc.service', pid);
    if (!conf) return false;
    rt.pid = pid;
    rt.loaded = { conf };
    log(world, host, 'krb5kdc', 'setting up network...', { pid, unit: 'krb5-kdc.service' });
    const r = Object.values(conf.realms)[0];
    log(world, host, 'krb5kdc', `set up ${r.kdcPorts.length * 2 + r.kdcTcpPorts.length * 2} sockets`, { pid, unit: 'krb5-kdc.service' });
    log(world, host, 'krb5kdc', `commencing operation`, { pid, unit: 'krb5-kdc.service' });
    return true;
  },
  listeners(_host, rt) {
    const conf = (rt.loaded as { conf: KdcConf }).conf;
    const udp = [...new Set(Object.values(conf.realms).flatMap((r) => r.kdcPorts))];
    const tcp = [...new Set(Object.values(conf.realms).flatMap((r) => r.kdcTcpPorts))];
    return [
      ...udp.flatMap((port) => ['0.0.0.0', '::'].map((addr) => ({ proto: 'udp' as const, addr, port, process: 'krb5kdc', pid: rt.pid!, service: 'krb5-kdc' }))),
      ...tcp.flatMap((port) => ['0.0.0.0', '::'].map((addr) => ({ proto: 'tcp' as const, addr, port, process: 'krb5kdc', pid: rt.pid!, service: 'krb5-kdc' }))),
    ];
  },
};

const kadmind: ServiceDef = {
  name: 'krb5-admin-server',
  unit: 'krb5-admin-server.service',
  aliases: ['krb5-admin-server', 'krb5-admin-server.service', 'kadmind', 'kadmin'],
  description: 'Kerberos 5 Admin Server',
  configFiles: [KDC_CONF, '/etc/krb5kdc/kadm5.acl'],
  start(world, host, rt) {
    const pid = allocPid(host);
    const conf = loadKdcConf(world, host, 'kadmind', 'krb5-admin-server.service', pid);
    if (!conf) return false;
    const aclFile = Object.values(conf.realms)[0].aclFile;
    const text = readFile(host, aclFile);
    if (text === undefined) {
      log(world, host, 'kadmind', `Cannot open ACL file ${aclFile}: No such file or directory - while initializing ACL file, aborting`, { pid, unit: 'krb5-admin-server.service', priority: 'err' });
      return false;
    }
    rt.pid = pid;
    rt.loaded = { conf, acl: parseKadmAcl(text), aclFile };
    log(world, host, 'kadmind', 'Seeding random number generator', { pid, unit: 'krb5-admin-server.service' });
    log(world, host, 'kadmind', 'starting', { pid, unit: 'krb5-admin-server.service' });
    return true;
  },
  listeners(_host, rt) {
    const pid = rt.pid!;
    return [
      { proto: 'tcp', addr: '0.0.0.0', port: 749, process: 'kadmind', pid, service: 'krb5-admin-server' },
      { proto: 'tcp', addr: '0.0.0.0', port: 464, process: 'kadmind', pid, service: 'krb5-admin-server' },
      { proto: 'udp', addr: '0.0.0.0', port: 464, process: 'kadmind', pid, service: 'krb5-admin-server' },
    ];
  },
};

// ---------------------------------------------------------------------------
// systemd-timesyncd: NTP client. Simplified: NTP packets are not modelled; when
// the service starts it sets the clock from the time server named in timesyncd.conf.
// ---------------------------------------------------------------------------

const timesyncd: ServiceDef = {
  name: 'systemd-timesyncd',
  unit: 'systemd-timesyncd.service',
  aliases: ['systemd-timesyncd', 'systemd-timesyncd.service', 'timesyncd'],
  description: 'Network Time Synchronization',
  configFiles: ['/etc/systemd/timesyncd.conf'],
  start(world, host, rt) {
    const pid = allocPid(host);
    rt.pid = pid;
    rt.loaded = {};
    const server = /^NTP=(\S+)/m.exec(readFile(host, '/etc/systemd/timesyncd.conf') ?? '')?.[1] ?? '0.debian.pool.ntp.org';
    const off = host.clockOffset ?? 0;
    host.clockOffset = 0;
    log(world, host, 'systemd-timesyncd', `Contacted time server ${server}:123.`, { pid, unit: 'systemd-timesyncd.service' });
    log(world, host, 'systemd-timesyncd', `Initial clock synchronization to ${new Date(world.clock).toUTCString().slice(0, 3)} ${new Date(world.clock).toISOString().replace('T', ' ').replace('Z', '')} UTC${Math.abs(off) >= 1000 ? ` (clock was ${Math.round(Math.abs(off) / 1000)} s ${off > 0 ? 'ahead' : 'behind'})` : ''}.`, { pid, unit: 'systemd-timesyncd.service' });
    return true;
  },
  listeners: () => [],
};

// ---------------------------------------------------------------------------
// networking (ifupdown)
// ---------------------------------------------------------------------------

/**
 * Apply /etc/network/interfaces to runtime state: VLAN sub-interfaces, IPv4 and
 * IPv6 addresses (link-local is automatic), routes, the switch's bridge, then
 * DHCP and router solicitation (which need the resulting broadcast domains).
 */
export function applyNetworkConfig(world: World, host: Host): string[] {
  const { ifaces, errors } = parseInterfaces(readFile(host, '/etc/network/interfaces') ?? '');
  host.routes = [];
  host.routes6 = [];
  // Dummy devices made with ip link add are not ifupdown's: a networking restart leaves them alone.
  host.ifaces = host.ifaces.filter((i) => !i.vlan);
  for (const i of host.ifaces) {
    if (i.name === LOOPBACK) { i.addrs6 = [{ address: '::1', prefix: 128, scope: 'host', origin: 'kernel' }]; continue; }
    if (i.kind) continue;
    i.address = null;
    i.prefix = null;
    i.up = false;
    i.addrs6 = [];
    delete i.mtu;
    delete i.dhcp;
    delete i.dhcpRetryAt;
    delete i.dhcp6;
    delete i.dhcp6RetryAt;
    delete i.dhcpPid;
    delete i.dhcp6Pid;
    delete i.autoconf6;
  }
  const autoCfg = ifaces.filter((c) => c.auto && c.name !== LOOPBACK);
  // VLAN sub-interfaces (Debian "vlan" package: eth3.30 → raw device eth3, VLAN id 30)
  for (const cfg of autoCfg) {
    const v = vlanOf(cfg);
    if (!v || host.ifaces.some((i) => i.name === cfg.name)) continue;
    const parent = host.ifaces.find((i) => i.name === v.parent);
    if (!parent) { errors.push(`${cfg.name}: vlan-raw-device ${v.parent} does not exist`); continue; }
    host.ifaces.push({ name: cfg.name, mac: parent.mac, segment: null, address: null, prefix: null, up: false, addrs6: [], vlan: v });
  }
  if (host.kind === 'switch') host.bridge = bridgeFromConfig(ifaces, errors);
  const slaac: string[] = [];
  const dhcp6: string[] = [];
  const missing = new Set<string>();
  for (const cfg of autoCfg) {
    const iface = host.ifaces.find((i) => i.name === cfg.name);
    if (!iface) {
      // ifupdown cannot configure a NIC that does not exist (renamed after a hardware or VM change).
      if (host.kind !== 'switch' && !cfg.options['bridge-ports'] && !missing.has(cfg.name)) {
        missing.add(cfg.name);
        errors.push(`Cannot find device "${cfg.name}"`, `ifup: failed to bring up ${cfg.name}`);
      }
      continue;
    }
    iface.up = true;
    if (cfg.options.mtu !== undefined) {
      const mtu = Number(cfg.options.mtu);
      if (Number.isInteger(mtu) && mtu >= 68 && mtu <= 9216) iface.mtu = mtu;
      else errors.push(`${cfg.name}: invalid mtu ${cfg.options.mtu} (68-9216)`);
    }
    if (iface.vlan) {
      const parent = host.ifaces.find((i) => i.name === iface.vlan!.parent);
      if (parent) parent.up = true; // ifup brings the raw device up first
    }
    if (cfg.family === 'inet6') {
      if (cfg.method === 'static' && cfg.address) iface.addrs6!.push({ address: cfg.address, prefix: cfg.prefix ?? 64, scope: 'global', origin: 'static' });
      if (cfg.method === 'auto') slaac.push(iface.name);
      // "inet6 dhcp": dhclient -6 for the address; router advertisements still give the default route.
      if (cfg.method === 'dhcp') { dhcp6.push(iface.name); if (!slaac.includes(iface.name)) slaac.push(iface.name); }
      // ifupdown's "autoconf 0" sets net.ipv6.conf.IF.autoconf=0: no SLAAC addresses from RAs.
      if (cfg.options.autoconf === '0') iface.autoconf6 = false;
      if (cfg.gateway) host.routes6.push({ dest: 'default', via: cfg.gateway, dev: iface.name, proto: 'boot' });
      for (const r of cfg.routes) if (r.dest.includes(':')) host.routes6.push({ dest: r.dest, via: r.via, dev: iface.name, proto: 'boot' });
      continue;
    }
    if (cfg.method === 'static' && cfg.address) {
      iface.address = cfg.address;
      iface.prefix = cfg.prefix ?? 24;
    }
    if (cfg.gateway) host.routes.push({ dest: 'default', via: cfg.gateway, dev: iface.name, proto: 'boot' });
    for (const r of cfg.routes) if (!r.dest.includes(':')) host.routes.push({ dest: r.dest, via: r.via, dev: iface.name, proto: 'boot' });
  }
  // A switch port enslaved to the bridge is up when listed in bridge-ports.
  if (host.bridge) for (const name of Object.keys(host.bridge.ports)) { const p = host.ifaces.find((i) => i.name === name); if (p) p.up = true; }
  // Every up interface gets an EUI-64 link-local address (switch ports carry no IP).
  for (const i of host.ifaces) {
    if (i.name === LOOPBACK || !i.up || host.bridge?.ports[i.name]) continue;
    if (!i.addrs6!.some((a) => a.scope === 'link')) i.addrs6!.push({ address: linkLocalFromMac(i.mac), prefix: 64, scope: 'link', origin: 'kernel' });
  }
  recomputeL2(world);
  host.neighbors = [];
  for (const cfg of autoCfg) {
    const iface = host.ifaces.find((i) => i.name === cfg.name);
    if (iface && cfg.family === 'inet' && cfg.method === 'dhcp') dhcpAcquire(world, host, iface);
  }
  if (!host.ip6Forward) for (const name of slaac) routerSolicit(world, host, host.ifaces.find((i) => i.name === name)!);
  for (const name of dhcp6) dhcp6Acquire(world, host, host.ifaces.find((i) => i.name === name)!);
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

export const SERVICE_DEFS: ServiceDef[] = [networking, timesyncd, nftables, named, krb5kdc, kadmind, dhcpd, dhcrelay, radvd, sshd, nginx];

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
  out.push(...winListeners(host), ...pfListeners(host));
  return out;
}

/**
 * Socket lookup for an incoming packet. "0.0.0.0" accepts IPv4 only and "::"
 * IPv6 only (sshd and nginx set IPV6_V6ONLY on their [::] sockets).
 */
export function findListener(host: Host, proto: 'tcp' | 'udp', addr: string, port: number): Listener | undefined {
  const v6 = addr.includes(':');
  return allListeners(host).find(
    (l) => l.proto === proto && l.port === port && (l.addr === addr || (!v6 && l.addr === '0.0.0.0') || (v6 && l.addr === '::') || (l.addr === '127.0.0.1' && addr.startsWith('127.'))),
  );
}

/** Simulated reboot: runtime state is discarded and rebuilt from persistent files. */
export function bootHost(world: World, host: Host): void {
  if (host.kind === 'windows' && host.win) {
    bootWindows(world, host);
    return;
  }
  if (host.kind === 'pfsense') {
    bootPfsense(world, host, (on) => {
      const def = serviceDef('ssh')!;
      const rt = host.services.ssh;
      if (!rt) return;
      rt.state = 'inactive';
      rt.pid = null;
      rt.loaded = null;
      rt.enabled = on;
      if (on) startService(world, host, def);
    });
    return;
  }
  host.conntrack = [];
  host.nat = [];
  host.neighbors = [];
  host.pmtu = {};
  host.routes6 = [];
  host.nft = emptyRuleset();
  faillockClearAll(host);
  for (const rt of Object.values(host.services)) {
    rt.state = 'inactive';
    rt.pid = null;
    rt.loaded = null;
    rt.result = 'success';
  }
  host.ifaces = host.ifaces.filter((i) => !i.kind); // runtime-only devices are gone after a reboot
  for (const i of host.ifaces) if (i.name === LOOPBACK) { i.up = true; i.address = '127.0.0.1'; i.prefix = 8; }
  world.clock += 1000;
  host.bootTime = world.clock;
  host.nextPid = 400;
  log(world, host, 'kernel', 'Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1');
  const sysctl = Object.keys(host.fs)
    .filter((p) => p === '/etc/sysctl.conf' || p.startsWith('/etc/sysctl.d/'))
    .sort() // systemd-sysctl applies files in lexical order; the last assignment wins
    .map((p) => readFile(host, p) ?? '')
    .join('\n');
  host.ipForward = /^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$/m.test(sysctl);
  // Last assignment wins, as with sysctl --system.
  const f6 = [...sysctl.matchAll(/^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*([01])\s*$/gm)].pop();
  host.ip6Forward = f6 ? f6[1] === '1' : false;
  // networking always runs at boot on these Debian hosts (it is enabled by default)
  for (const def of SERVICE_DEFS) {
    const rt = host.services[def.name];
    if (!rt) continue;
    if (rt.enabled && !rt.masked) startService(world, host, def);
  }
  if (!host.services.networking) applyNetworkConfig(world, host);
}
