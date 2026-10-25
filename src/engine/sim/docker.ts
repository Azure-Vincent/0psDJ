// Docker Engine 26 on a Debian 12 host. dockerd keeps its state where the real
// daemon does (/var/lib/docker/containers/<id>/config.v2.json and the json-file
// logs next to it); a running container is a small Host of kind "container" on
// the bridge network's segment, so ARP, routing, nftables and NAT apply to its
// traffic exactly as to any other machine. Published ports are DNAT rules in
// the "ip nat" / "ip filter" tables that dockerd writes (iptables-nft), plus a
// docker-proxy listener on the host: flushing the ruleset removes the rules but
// not the proxy, as on a real host.

import { emptyRuleset, parseRulesetFile, type Ruleset } from '../config/nft';
import { listDir, mkdir, readFile, writeFile } from '../fs';
import type { Host, World } from '../types';
import { sha256Hex } from '../util/sha256';
import { dnsHooks, dnsQuery, resolve, resolverConf, type DnsExchange } from './dns';
import { log } from './journal';
import { httpHooks, type HttpResponse } from './http';
import { findHostByIp } from './network';
import { allListeners, SERVICE_DEFS, serviceDef, type Listener, type ServiceDef } from './services';
import { tcpConnect } from './tcp';

export const DOCKER_VERSION = '26.1.4';
const ROOT = '/var/lib/docker';
const NETWORKS_FILE = `${ROOT}/network/files/networks.json`;

// ---------------------------------------------------------------------------
// Persistent model
// ---------------------------------------------------------------------------

export interface PortBinding { hostIp: string; hostPort: number; ctrPort: number; proto: 'tcp' | 'udp' }
export interface Mount { kind: 'volume' | 'bind'; source: string; target: string; ro: boolean }
export type RestartPolicy = 'no' | 'always' | 'unless-stopped' | 'on-failure';

export interface ContainerState {
  status: 'created' | 'running' | 'exited' | 'restarting';
  exitCode: number;
  startedAt: number;
  finishedAt: number;
  restartCount: number;
  /** Stopped with docker stop / compose stop: "unless-stopped" does not bring it back. */
  manuallyStopped: boolean;
  pid: number;
  ip?: string;
  mac?: string;
  error?: string;
}

export interface ContainerConfig {
  id: string;
  name: string;
  image: string;
  created: number;
  env: string[];
  cmd: string[];
  ports: PortBinding[];
  restart: RestartPolicy;
  network: string;
  aliases: string[];
  mounts: Mount[];
  labels: Record<string, string>;
  state: ContainerState;
}

export interface NetworkConfig {
  id: string;
  name: string;
  driver: 'bridge' | 'host' | 'null';
  subnet: string;
  gateway: string;
  /** Linux bridge device: docker0 for the default network, br-<id12> for user-defined ones. */
  bridge: string;
  created: number;
  labels: Record<string, string>;
}

export interface DaemonConfig { iptables: boolean; liveRestore: boolean; bip?: string; dns?: string[] }

const ctrDir = (id: string) => `${ROOT}/containers/${id}`;
const configPath = (id: string) => `${ctrDir(id)}/config.v2.json`;
const logPath = (id: string) => `${ctrDir(id)}/${id}-json.log`;

export function listContainers(host: Host): ContainerConfig[] {
  return listDir(host, `${ROOT}/containers`)
    .map((d) => readFile(host, configPath(d)))
    .filter((t): t is string => !!t)
    .map((t) => JSON.parse(t) as ContainerConfig)
    .sort((a, b) => a.created - b.created);
}

export function saveContainer(host: Host, c: ContainerConfig, t: number): void {
  for (const d of [ROOT, `${ROOT}/containers`, ctrDir(c.id)]) if (!host.fs[d]) mkdir(host, d, t, { mode: 0o710 });
  writeFile(host, configPath(c.id), JSON.stringify(c, null, 2) + '\n', t, { mode: 0o600 });
}

export function findContainer(host: Host, ref: string): ContainerConfig | undefined {
  const all = listContainers(host);
  return all.find((c) => c.name === ref.replace(/^\//, '')) ?? (ref.length >= 3 ? all.find((c) => c.id.startsWith(ref)) : undefined);
}

export function deleteContainer(host: Host, c: ContainerConfig): void {
  for (const p of Object.keys(host.fs)) if (p === ctrDir(c.id) || p.startsWith(ctrDir(c.id) + '/')) delete host.fs[p];
}

export function listNetworks(host: Host): NetworkConfig[] {
  const t = readFile(host, NETWORKS_FILE);
  return t ? (JSON.parse(t) as NetworkConfig[]) : [];
}

export function saveNetworks(host: Host, nets: NetworkConfig[], t: number): void {
  for (const d of [ROOT, `${ROOT}/network`, `${ROOT}/network/files`]) if (!host.fs[d]) mkdir(host, d, t, { mode: 0o750 });
  writeFile(host, NETWORKS_FILE, JSON.stringify(nets, null, 2) + '\n', t, { mode: 0o600 });
}

export function daemonConfig(host: Host): { config: DaemonConfig; error?: string } {
  const text = readFile(host, '/etc/docker/daemon.json');
  const config: DaemonConfig = { iptables: true, liveRestore: false };
  if (!text || !text.trim()) return { config };
  try {
    const j = JSON.parse(text) as Record<string, unknown>;
    if (j.iptables === false) config.iptables = false;
    if (j['live-restore'] === true) config.liveRestore = true;
    if (typeof j.bip === 'string') config.bip = j.bip;
    if (Array.isArray(j.dns)) config.dns = j.dns.map(String);
    return { config };
  } catch {
    return { config, error: `unable to configure the Docker daemon with file /etc/docker/daemon.json: ${goJsonError(text)}` };
  }
}

/** The first syntax error in a JSON text, worded like Go's encoding/json (what dockerd prints). */
export function goJsonError(text: string): string {
  let i = 0;
  const ch = () => text[i];
  const q = (c: string | undefined) => (c === undefined ? '' : c === "'" ? "'\\''" : `'${c}'`);
  const ws = () => { while (i < text.length && /\s/.test(text[i])) i++; };
  class E extends Error {}
  const bad = (msg: string): never => { throw new E(msg); };
  const eof = () => bad('unexpected end of JSON input');
  const value = (): void => {
    ws();
    const c = ch();
    if (c === undefined) eof();
    if (c === '{') {
      i++; ws();
      if (ch() === '}') { i++; return; }
      for (;;) {
        ws();
        if (ch() === undefined) eof();
        if (ch() !== '"') bad(`invalid character ${q(ch())} looking for beginning of object key string`);
        str(); ws();
        if (ch() === undefined) eof();
        if (ch() !== ':') bad(`invalid character ${q(ch())} after object key`);
        i++; value(); ws();
        if (ch() === undefined) eof();
        if (ch() === ',') { i++; continue; }
        if (ch() === '}') { i++; return; }
        bad(`invalid character ${q(ch())} after object key:value pair`);
      }
    }
    if (c === '[') {
      i++; ws();
      if (ch() === ']') { i++; return; }
      for (;;) {
        value(); ws();
        if (ch() === undefined) eof();
        if (ch() === ',') { i++; ws(); if (ch() === ']') bad(`invalid character ']' looking for beginning of value`); continue; }
        if (ch() === ']') { i++; return; }
        bad(`invalid character ${q(ch())} after array element`);
      }
    }
    if (c === '"') return str();
    const lit = /^(true|false|null|-?\d+(\.\d+)?([eE][+-]?\d+)?)/.exec(text.slice(i));
    if (lit) { i += lit[0].length; return; }
    bad(`invalid character ${q(c)} looking for beginning of value`);
  };
  const str = () => {
    i++;
    while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    if (i >= text.length) eof();
    i++;
  };
  try {
    value(); ws();
    if (i < text.length) bad(`invalid character ${q(ch())} after top-level value`);
    return 'invalid JSON';
  } catch (e) {
    return e instanceof E ? e.message : 'invalid JSON';
  }
}

export function newId(world: World, seed: string): string {
  world.counter += 1;
  return sha256Hex(`${seed}|${world.counter}|${world.clock}`);
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

export interface ImageDef {
  repo: string;
  tag: string;
  id: string;
  created: string;
  size: string;
  cmd: string[];
  /** Shown in docker ps' COMMAND column. */
  command: string;
  env: string[];
  exposed: number[];
  /** Programs present in the image (docker exec of anything else fails). */
  tools: string[];
  users: { name: string; uid: number }[];
  files: Record<string, string>;
  start(world: World, docker: Host, ctr: Host, c: ContainerConfig): { ok: true; lines: string[] } | { ok: false; lines: string[]; exitCode: number };
}

const BASE_TOOLS = ['cat', 'ls', 'echo', 'printf', 'grep', 'head', 'tail', 'sh', 'bash', 'env', 'printenv', 'hostname', 'id', 'pwd', 'wc', 'sed', 'tee', 'touch', 'mkdir', 'rm', 'date', 'stat', 'sleep', 'uname', 'whoami', 'cd', 'cp', 'mv', 'diff', 'getent', 'true', 'false'];

const NGINX_CONTAINER_CONF = `user  nginx;
worker_processes  auto;
http {
    server {
        listen       80;
        listen  [::]:80;
        server_name  localhost;
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }
}
`;

const NGINX_INDEX = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
</body>
</html>
`;

const envOf = (c: ContainerConfig, key: string): string | undefined => {
  const e = [...c.env].reverse().find((x) => x.startsWith(key + '='));
  return e === undefined ? undefined : e.slice(key.length + 1);
};

const stamp = (ms: number) => new Date(Math.floor(ms)).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
const nginxStamp = (ms: number) => stamp(ms).replace(/-/g, '/');

export const IMAGES: ImageDef[] = [
  {
    repo: 'nginx', tag: '1.25', id: 'sha256:2ac752d7aeb1d9281f708e7c51501c41baf90de15ffc9bca7c5d38b8da41b580', created: '5 months ago', size: '188MB',
    cmd: ['nginx', '-g', 'daemon off;'], command: '"/docker-entrypoint.…"', env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NGINX_VERSION=1.25.5'], exposed: [80],
    tools: [...BASE_TOOLS, 'curl', 'nginx'], users: [{ name: 'nginx', uid: 101 }],
    files: { '/etc/nginx/nginx.conf': NGINX_CONTAINER_CONF, '/usr/share/nginx/html/index.html': NGINX_INDEX, '/usr/share/nginx/html/50x.html': '<html><body><h1>An error occurred.</h1></body></html>\n', '/docker-entrypoint.sh': '#!/bin/sh\n' },
    start(world, _docker, ctr) {
      const def = serviceDef('nginx')!;
      ctr.services.nginx = { state: 'inactive', enabled: false, since: world.clock, pid: null, loaded: null, result: 'success' };
      const before = ctr.journal.length;
      const ok = def.start(world, ctr, ctr.services.nginx);
      const t = nginxStamp(world.clock);
      const entry = ['/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration', '/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/', '/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh', '/docker-entrypoint.sh: Configuration complete; ready for start up'];
      if (!ok) return { ok: false, exitCode: 1, lines: [...entry, ...ctr.journal.slice(before).filter((e) => e.ident === 'nginx').map((e) => `${t} [emerg] 1#1: ${e.message.replace(/^nginx: \[emerg\] /, '')}`)] };
      Object.assign(ctr.services.nginx, { state: 'active', pid: 1 });
      return { ok: true, lines: [...entry, `${t} [notice] 1#1: using the "epoll" event method`, `${t} [notice] 1#1: nginx/1.25.5`, `${t} [notice] 1#1: built by gcc 12.2.0 (Debian 12.2.0-14)`, `${t} [notice] 1#1: OS: Linux 6.1.0-26-amd64`, `${t} [notice] 1#1: start worker processes`, `${t} [notice] 1#1: start worker process 29`] };
    },
  },
  {
    repo: 'postgres', tag: '16', id: 'sha256:d1f3a6b0e9c845a8b0e3d8f6a1c27e44c12f0a7b9e5d3c1a2b4f6e8d0c9a7b5e', created: '4 months ago', size: '432MB',
    cmd: ['postgres'], command: '"docker-entrypoint.s…"', env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/16/bin', 'PG_MAJOR=16', 'PGDATA=/var/lib/postgresql/data'], exposed: [5432],
    tools: [...BASE_TOOLS, 'psql', 'pg_isready'], users: [{ name: 'postgres', uid: 999 }],
    files: { '/usr/local/bin/docker-entrypoint.sh': '#!/usr/bin/env bash\n' },
    start(world, _docker, ctr, c) {
      const pw = envOf(c, 'POSTGRES_PASSWORD');
      const trust = envOf(c, 'POSTGRES_HOST_AUTH_METHOD') === 'trust';
      if (!pw && !trust) {
        return { ok: false, exitCode: 1, lines: [
          'Error: Database is uninitialized and superuser password is not specified.',
          '       You must specify POSTGRES_PASSWORD to a non-empty value for the',
          '       superuser. For example, "-e POSTGRES_PASSWORD=password" on "docker run".',
          '',
          '       You may also use "POSTGRES_HOST_AUTH_METHOD=trust" to allow all',
          '       connections without a password. This is *not* recommended.',
        ] };
      }
      ctr.services.postgres = { state: 'active', enabled: false, since: world.clock, pid: 1, loaded: { port: 5432 }, result: 'success' };
      const t = `${stamp(world.clock)}.118 UTC`;
      return { ok: true, lines: [
        'PostgreSQL Database directory appears to contain a database; Skipping initialization',
        '',
        `${t} [1] LOG:  starting PostgreSQL 16.4 (Debian 16.4-1.pgdg120+2) on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit`,
        `${t} [1] LOG:  listening on IPv4 address "0.0.0.0", port 5432`,
        `${t} [1] LOG:  listening on IPv6 address "::", port 5432`,
        `${t} [1] LOG:  listening on Unix socket "/var/run/postgresql/.s.PGSQL.5432"`,
        `${t} [1] LOG:  database system is ready to accept connections`,
      ] };
    },
  },
  {
    repo: 'corp/inventory', tag: '1.4', id: 'sha256:7c4e0b19a2f35d6e8b1c0a9f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d', created: '3 weeks ago', size: '156MB',
    cmd: ['gunicorn', '--bind', '0.0.0.0:8000', 'inventory.wsgi'], command: '"gunicorn --bind 0.0…"',
    env: ['PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'PYTHON_VERSION=3.12.4', 'DB_HOST=db', 'DB_PORT=5432', 'DB_USER=postgres'], exposed: [8000],
    tools: [...BASE_TOOLS, 'python', 'python3', 'pip'], users: [{ name: 'app', uid: 1000 }],
    files: { '/app/inventory/wsgi.py': '# corp/inventory 1.4\n', '/app/requirements.txt': 'Django==5.0.7\ngunicorn==22.0.0\npsycopg2-binary==2.9.9\n' },
    start(world, _docker, ctr, c) {
      const host = envOf(c, 'DB_HOST') ?? 'db';
      const port = Number(envOf(c, 'DB_PORT') ?? '5432');
      const user = envOf(c, 'DB_USER') ?? 'postgres';
      const pw = envOf(c, 'DB_PASSWORD') ?? '';
      const t = `[${stamp(world.clock)} +0000]`;
      const boot = [`${t} [1] [INFO] Starting gunicorn 22.0.0`, `${t} [1] [INFO] Listening at: http://0.0.0.0:8000 (1)`, `${t} [1] [INFO] Using worker: sync`, `${t} [7] [INFO] Booting worker with pid: 7`];
      const crash = (msg: string) => ({ ok: false as const, exitCode: 3, lines: [
        ...boot,
        `${t} [7] [ERROR] Exception in worker process`,
        'Traceback (most recent call last):',
        '  File "/app/inventory/db.py", line 14, in connect',
        '    conn = psycopg2.connect(host=settings.DB_HOST, port=settings.DB_PORT, user=settings.DB_USER, password=settings.DB_PASSWORD)',
        `psycopg2.OperationalError: ${msg}`,
        `${t} [7] [INFO] Worker exiting (pid: 7)`,
        `${t} [1] [ERROR] Worker (pid:7) exited with code 3`,
        `${t} [1] [ERROR] Shutting down: Master`,
        `${t} [1] [ERROR] Reason: Worker failed to boot.`,
      ] });
      const res = resolve(world, ctr, host, { family: 4 });
      if (!res.ok) return crash(`could not translate host name "${host}" to address: ${res.error === 'EAI_AGAIN' ? 'Temporary failure in name resolution' : 'Name or service not known'}`);
      const conn = tcpConnect(world, ctr, res.ip, port, { timeoutMs: 5000 });
      const at = `connection to server at "${host}" (${res.ip}), port ${port} failed`;
      if (!conn.ok) return crash(`${at}: ${conn.errno === 'ECONNREFUSED' ? 'Connection refused\n\tIs the server running on that host and accepting TCP/IP connections?' : conn.errno === 'ETIMEDOUT' ? 'Connection timed out\n\tIs the server running on that host and accepting TCP/IP connections?' : 'No route to host'}`);
      conn.conn.close('client');
      const db = findHostByIp(world, res.ip);
      const dbCfg = db?.container ? findContainer(world.hosts[db.container.host], db.container.id) : undefined;
      if (dbCfg && db?.services.postgres?.state === 'active') {
        const want = envOf(dbCfg, 'POSTGRES_PASSWORD');
        const dbUser = envOf(dbCfg, 'POSTGRES_USER') ?? 'postgres';
        const trust = envOf(dbCfg, 'POSTGRES_HOST_AUTH_METHOD') === 'trust';
        if (!trust && (user !== dbUser || pw !== want)) return crash(`${at}: FATAL:  password authentication failed for user "${user}"`);
      }
      ctr.services.gunicorn = { state: 'active', enabled: false, since: world.clock, pid: 1, loaded: { port: 8000 }, result: 'success' };
      return { ok: true, lines: [...boot, `${t} [7] [INFO] Connected to PostgreSQL at ${host}:${port} as ${user}`] };
    },
  },
];

export const findImage = (ref: string): ImageDef | undefined => {
  const [repo, tag = 'latest'] = ref.includes(':') ? ref.split(':') : [ref, 'latest'];
  return IMAGES.find((i) => i.repo === repo && (i.tag === tag || (tag === 'latest' && i.repo === repo && repo !== 'corp/inventory')));
};

/** Images present on the host (docker pull / docker run add to it). */
export function pulledImages(host: Host): string[] {
  const t = readFile(host, `${ROOT}/image/overlay2/repositories.json`);
  return t ? (JSON.parse(t).images as string[]) : [];
}

export function addPulledImage(host: Host, ref: string, t: number): void {
  const imgs = [...new Set([...pulledImages(host), ref])];
  for (const d of [ROOT, `${ROOT}/image`, `${ROOT}/image/overlay2`]) if (!host.fs[d]) mkdir(host, d, t, { mode: 0o700 });
  writeFile(host, `${ROOT}/image/overlay2/repositories.json`, JSON.stringify({ images: imgs }) + '\n', t, { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Networks and the daemon's firewall rules
// ---------------------------------------------------------------------------

export const segmentOf = (host: Host, net: NetworkConfig) => `docker:${host.id}:${net.name}`;

function ipAt(subnet: string, n: number): string {
  const [base] = subnet.split('/');
  const p = base.split('.').map(Number);
  const v = ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] + n;
  return [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}

export function defaultNetworks(host: Host, t: number, bip = '172.17.0.1/16'): NetworkConfig[] {
  const [gw, prefix] = bip.split('/');
  const subnet = `${gw.split('.').slice(0, 2).join('.')}.0.0/${prefix}`;
  return [
    { id: sha256Hex(`${host.id}-bridge`), name: 'bridge', driver: 'bridge', subnet, gateway: gw, bridge: 'docker0', created: t, labels: {} },
    { id: sha256Hex(`${host.id}-host`), name: 'host', driver: 'host', subnet: '', gateway: '', bridge: '', created: t, labels: {} },
    { id: sha256Hex(`${host.id}-none`), name: 'none', driver: 'null', subnet: '', gateway: '', bridge: '', created: t, labels: {} },
  ];
}

/** docker network create: the next free 172.x.0.0/16 (172.18 onwards), like the default address pools. */
export function nextSubnet(nets: NetworkConfig[]): string {
  for (let b = 18; b < 32; b++) if (!nets.some((n) => n.subnet.startsWith(`172.${b}.`))) return `172.${b}.0.0/16`;
  return '192.168.0.0/20';
}

/** Create the bridge device of each network on the host (dockerd does this at start). */
export function ensureBridges(world: World, host: Host): void {
  for (const n of listNetworks(host).filter((x) => x.driver === 'bridge')) {
    const seg = segmentOf(host, n);
    world.segments[seg] = { id: seg, name: `${host.hostname} ${n.bridge}`, cidr: n.subnet };
    const prefix = Number(n.subnet.split('/')[1]);
    const existing = host.ifaces.find((i) => i.name === n.bridge);
    const iface = existing ?? { name: n.bridge, mac: macFor(`${host.id}${n.bridge}`), segment: seg, address: null, prefix: null, up: false, addrs6: [], staticSegment: seg };
    Object.assign(iface, { segment: seg, staticSegment: seg, address: n.gateway, prefix, up: true });
    if (!existing) host.ifaces.push(iface);
  }
}

function macFor(seed: string): string {
  const h = sha256Hex(seed);
  return `02:42:${h.slice(0, 2)}:${h.slice(2, 4)}:${h.slice(4, 6)}:${h.slice(6, 8)}`;
}

/** The rules dockerd keeps in "ip nat" and "ip filter" (as `nft list ruleset` shows them with iptables-nft). */
export function dockerRulesText(host: Host): string {
  const nets = listNetworks(host).filter((n) => n.driver === 'bridge');
  const running = listContainers(host).filter((c) => c.state.status === 'running' && c.state.ip);
  const netOf = (c: ContainerConfig) => nets.find((n) => n.name === c.network)!;
  const dnat: string[] = [];
  const fwd: string[] = [];
  for (const n of nets) dnat.push(`\t\tiifname "${n.bridge}" return`);
  for (const c of running) {
    const n = netOf(c);
    if (!n) continue;
    for (const p of c.ports) {
      dnat.push(`\t\t${p.hostIp !== '0.0.0.0' ? `ip daddr ${p.hostIp} ` : ''}iifname != "${n.bridge}" ${p.proto} dport ${p.hostPort} dnat to ${c.state.ip}:${p.ctrPort}`);
      fwd.push(`\t\tip daddr ${c.state.ip} iifname != "${n.bridge}" oifname "${n.bridge}" ${p.proto} dport ${p.ctrPort} accept`);
    }
  }
  const forward = nets.flatMap((n) => [
    `\t\toifname "${n.bridge}" ct state related,established accept`,
    `\t\toifname "${n.bridge}" jump DOCKER`,
    `\t\tiifname "${n.bridge}" oifname != "${n.bridge}" accept`,
    `\t\tiifname "${n.bridge}" oifname "${n.bridge}" accept`,
  ]);
  return `table ip nat {
\tchain DOCKER {
${dnat.join('\n')}
\t}
\tchain PREROUTING {
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t\tjump DOCKER
\t}
\tchain POSTROUTING {
\t\ttype nat hook postrouting priority srcnat; policy accept;
${nets.map((n) => `\t\tip saddr ${n.subnet} oifname != "${n.bridge}" masquerade`).join('\n')}
\t}
}
table ip filter {
\tchain DOCKER {
${fwd.join('\n')}
\t}
\tchain DOCKER-USER {
\t\treturn
\t}
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy drop;
\t\tjump DOCKER-USER
${forward.join('\n')}
\t}
}
`;
}

/** Replace dockerd's tables in the host's live ruleset (no-op with "iptables": false). */
export function syncDockerRules(host: Host): void {
  if (!daemonConfig(host).config.iptables) return;
  const parsed = parseRulesetFile(dockerRulesText(host), 'dockerd');
  const rs: Ruleset = host.nft ?? emptyRuleset();
  rs.tables = rs.tables.filter((t) => !(t.family === 'ip' && (t.name === 'nat' || t.name === 'filter')));
  for (const tb of parsed.tables) {
    tb.handle = rs.nextHandle++;
    for (const ch of tb.chains) {
      ch.handle = rs.nextHandle++;
      for (const r of ch.rules) r.handle = rs.nextHandle++;
    }
    rs.tables.push(tb);
  }
  host.nft = rs;
}

// ---------------------------------------------------------------------------
// Container lifecycle
// ---------------------------------------------------------------------------

export function containerHostId(c: ContainerConfig): string {
  return `ctr-${c.id.slice(0, 12)}`;
}

export function runningHost(world: World, docker: Host, c: ContainerConfig): Host | undefined {
  const h = world.hosts[containerHostId(c)];
  return h?.container?.host === docker.id ? h : undefined;
}

function appendLog(docker: Host, c: ContainerConfig, lines: string[], t: number, stream: 'stdout' | 'stderr' = 'stdout'): void {
  if (!lines.length) return;
  const prev = readFile(docker, logPath(c.id)) ?? '';
  const iso = new Date(Math.floor(t)).toISOString().replace('Z', '000000Z');
  writeFile(docker, logPath(c.id), prev + lines.map((l) => JSON.stringify({ log: l + '\n', stream, time: iso }) + '\n').join(''), t, { mode: 0o640 });
}

/** The container's output: the json-file log, plus nginx's access/error logs (symlinked to stdout/stderr in the image). */
export function containerLogs(world: World, docker: Host, c: ContainerConfig): { time: string; line: string; stream: string }[] {
  const out = (readFile(docker, logPath(c.id)) ?? '').split('\n').filter(Boolean).map((l) => {
    const j = JSON.parse(l) as { log: string; stream: string; time: string };
    return { time: j.time, line: j.log.replace(/\n$/, ''), stream: j.stream };
  });
  const live = runningHost(world, docker, c);
  if (live) for (const [p, stream] of [['/var/log/nginx/access.log', 'stdout'], ['/var/log/nginx/error.log', 'stderr']] as const) {
    for (const l of (readFile(live, p) ?? '').split('\n').filter(Boolean)) out.push({ time: new Date(Math.floor(world.clock)).toISOString(), line: l, stream });
  }
  return out;
}

function hostResolvConf(docker: Host, user: boolean): string {
  const rc = resolverConf(docker);
  const search = rc.search.length ? `search ${rc.search.join(' ')}\n` : '';
  if (user) return `${search}nameserver 127.0.0.11\noptions ndots:0\n`;
  const daemon = daemonConfig(docker).config.dns;
  const servers = (daemon ?? rc.nameservers).filter((s) => !s.startsWith('127.'));
  const list = servers.length ? servers : ['8.8.8.8', '8.8.4.4'];
  return `# Generated by Docker Engine.\n# This file can be edited; Docker Engine will not make further changes once it\n# has been modified.\n\n${list.map((s) => `nameserver ${s}`).join('\n')}\n${search}`;
}

/** Build the container's Host: image filesystem, mounts, its address on the network and the default route. */
function materialise(world: World, docker: Host, c: ContainerConfig, img: ImageDef, net: NetworkConfig, ip: string): Host {
  const t = world.clock;
  const seg = segmentOf(docker, net);
  const short = c.id.slice(0, 12);
  const ctr: Host = {
    id: containerHostId(c), hostname: short, domain: '', osName: 'Debian GNU/Linux 12 (bookworm)', kind: 'container', role: `container ${c.name} (${c.image})`,
    container: { host: docker.id, id: c.id, name: c.name, image: c.image },
    users: {}, fs: {},
    ifaces: [
      { name: 'lo', mac: '00:00:00:00:00:00', segment: null, address: '127.0.0.1', prefix: 8, up: true, addrs6: [{ address: '::1', prefix: 128, scope: 'host', origin: 'kernel' }] },
      { name: 'eth0', mac: c.state.mac ?? macFor(c.id + ip), segment: seg, staticSegment: seg, address: ip, prefix: Number(net.subnet.split('/')[1]), up: true, addrs6: [] },
    ],
    routes: [{ dest: 'default', via: net.gateway, dev: 'eth0', proto: 'boot' }], routes6: [], neighbors: [], nft: emptyRuleset(), conntrack: [], nat: [], ipForward: false, ip6Forward: false,
    services: {}, journal: [], capture: [], nextPid: 1, bootTime: t,
  };
  for (const d of ['/', '/etc', '/root', '/tmp', '/var', '/var/log', '/usr', '/usr/share', '/bin']) mkdir(ctr, d, t, d === '/tmp' ? { mode: 0o1777 } : undefined);
  ctr.users.root = { name: 'root', uid: 0, gid: 0, primaryGroup: 'root', groups: [], home: '/root', shell: '/bin/bash', gecos: 'root', password: null };
  for (const u of img.users) ctr.users[u.name] = { name: u.name, uid: u.uid, gid: u.uid, primaryGroup: u.name, groups: [], home: '/nonexistent', shell: '/usr/sbin/nologin', gecos: u.name, password: null };
  for (const b of ['/bin/bash', '/bin/sh']) writeFile(ctr, b, '', t, { mode: 0o755 });
  for (const [p, content] of Object.entries(img.files)) {
    const parts = p.split('/').slice(1, -1);
    for (let k = 1; k <= parts.length; k++) { const d = '/' + parts.slice(0, k).join('/'); if (!ctr.fs[d]) mkdir(ctr, d, t); }
    writeFile(ctr, p, content, t, p.endsWith('.sh') ? { mode: 0o755 } : undefined);
  }
  // Bind mounts: the host directory's files as they are at start; named volumes persist in /var/lib/docker/volumes.
  for (const m of c.mounts) {
    const src = m.kind === 'bind' ? m.source : `${ROOT}/volumes/${m.source}/_data`;
    if (!ctr.fs[m.target]) mkdir(ctr, m.target, t);
    for (const [p, n] of Object.entries(docker.fs)) {
      if (!p.startsWith(src + '/')) continue;
      const dest = m.target + p.slice(src.length);
      ctr.fs[dest] = { ...n, mode: m.ro ? n.mode & ~0o222 : n.mode };
    }
  }
  writeFile(ctr, '/etc/hostname', `${short}\n`, t);
  const peers = c.aliases.length ? `\t${c.aliases.join(' ')}` : '';
  writeFile(ctr, '/etc/hosts', `127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n${ip}\t${short}${peers}\n`, t);
  writeFile(ctr, '/etc/resolv.conf', hostResolvConf(docker, net.name !== 'bridge'), t);
  writeFile(ctr, '/etc/nsswitch.conf', 'hosts:          files dns\n', t);
  return ctr;
}

export type StartError = { message: string };

/** docker start: allocate an address, check the published ports, run the image's process. */
export function startContainer(world: World, docker: Host, ref: ContainerConfig, opts: { restartAttempt?: boolean } = {}): StartError | null {
  const c = findContainer(docker, ref.id) ?? ref;
  if (runningHost(world, docker, c)) return null;
  const img = findImage(c.image)!;
  const nets = listNetworks(docker);
  const net = nets.find((n) => n.name === c.network);
  if (!net) return { message: `Error response from daemon: network ${c.network} not found` };
  const t = world.clock;
  // Published ports: another container, or a host process, may already own the port.
  const others = listContainers(docker).filter((o) => o.id !== c.id && o.state.status === 'running');
  for (const p of c.ports) {
    const clash = others.find((o) => o.ports.some((q) => q.hostPort === p.hostPort && q.proto === p.proto && (q.hostIp === p.hostIp || q.hostIp === '0.0.0.0' || p.hostIp === '0.0.0.0')));
    if (clash) {
      return { message: `Error response from daemon: driver failed programming external connectivity on endpoint ${c.name} (${sha256Hex(c.id + 'ep')}): Bind for ${p.hostIp}:${p.hostPort} failed: port is already allocated` };
    }
    const hostUse = allListeners(docker).find((l) => l.process !== 'docker-proxy' && l.proto === p.proto && l.port === p.hostPort && (l.addr === '0.0.0.0' || l.addr === p.hostIp || p.hostIp === '0.0.0.0') && !l.addr.includes(':'));
    if (hostUse) {
      return { message: `Error response from daemon: driver failed programming external connectivity on endpoint ${c.name} (${sha256Hex(c.id + 'ep')}): Error starting userland proxy: listen ${p.proto}4 ${p.hostIp}:${p.hostPort}: bind: address already in use` };
    }
  }
  const used = new Set(others.filter((o) => o.network === c.network).map((o) => o.state.ip));
  let n = 2;
  while (used.has(ipAt(net.subnet, n))) n++;
  const ip = c.state.ip && !used.has(c.state.ip) && c.network === net.name ? c.state.ip : ipAt(net.subnet, n);
  const ctr = materialise(world, docker, c, img, net, ip);
  world.hosts[ctr.id] = ctr;
  const r = img.start(world, docker, ctr, c);
  c.state.ip = ip;
  c.state.mac = ctr.ifaces[1].mac;
  appendLog(docker, c, r.lines, t, r.ok ? 'stdout' : 'stderr');
  if (r.ok) {
    c.state = { ...c.state, status: 'running', exitCode: 0, startedAt: t, pid: docker.nextPid += 13, manuallyStopped: false, error: undefined };
    saveContainer(docker, c, t);
    syncDockerRules(docker);
    return null;
  }
  // The process exited: the container stops. A restart policy brings it back (docker retries with a back-off).
  delete world.hosts[ctr.id];
  const restarts = c.restart === 'always' || c.restart === 'unless-stopped' || (c.restart === 'on-failure' && r.exitCode !== 0);
  c.state = { ...c.state, status: restarts ? 'restarting' : 'exited', exitCode: r.exitCode, startedAt: t, finishedAt: t + 400, pid: 0, restartCount: c.state.restartCount + (opts.restartAttempt ? 1 : 0) };
  saveContainer(docker, c, t + 400);
  syncDockerRules(docker);
  return null;
}

/** docker stop: SIGTERM to PID 1; nginx and postgres exit 0, gunicorn exits 0 as well. */
export function stopContainer(world: World, docker: Host, c: ContainerConfig, manual = true): void {
  const live = runningHost(world, docker, c);
  const t = world.clock;
  if (live) {
    const flushed: string[] = [];
    for (const p of ['/var/log/nginx/access.log', '/var/log/nginx/error.log']) flushed.push(...(readFile(live, p) ?? '').split('\n').filter(Boolean));
    appendLog(docker, c, flushed, t);
    delete world.hosts[live.id];
  }
  if (c.state.status === 'running' || c.state.status === 'restarting') {
    c.state = { ...c.state, status: 'exited', exitCode: c.state.status === 'running' ? 0 : c.state.exitCode, finishedAt: t, pid: 0, manuallyStopped: manual };
  }
  saveContainer(docker, c, t);
  syncDockerRules(docker);
}

/** dockerd's restart manager: containers in "restarting" are tried again (called before every docker command and check). */
export function dockerTick(world: World, docker: Host): void {
  if (docker.services.docker?.state !== 'active') return;
  for (const c of listContainers(docker).filter((x) => x.state.status === 'restarting')) {
    world.clock += 2000;
    startContainer(world, docker, c, { restartAttempt: true });
  }
}

// ---------------------------------------------------------------------------
// dockerd (docker.service)
// ---------------------------------------------------------------------------

function dockerdStart(world: World, host: Host, pid: number): boolean {
  const unit = 'docker.service';
  const { config, error } = daemonConfig(host);
  if (error) {
    log(world, host, 'dockerd', error, { pid, unit, priority: 'err' });
    return false;
  }
  log(world, host, 'dockerd', `time="${new Date(world.clock).toISOString()}" level=info msg="Starting up"`, { pid, unit });
  if (!listNetworks(host).length) saveNetworks(host, defaultNetworks(host, world.clock, config.bip), world.clock);
  ensureBridges(world, host);
  host.ipForward = true;
  log(world, host, 'dockerd', `time="${new Date(world.clock).toISOString()}" level=info msg="Loading containers: start."`, { pid, unit });
  if (config.iptables) syncDockerRules(host);
  else log(world, host, 'dockerd', `time="${new Date(world.clock).toISOString()}" level=warning msg="iptables is disabled: published ports will not be forwarded"`, { pid, unit, priority: 'warning' });
  host.services.docker.pid = pid;
  host.services.docker.state = 'active';
  for (const c of listContainers(host)) {
    // After a daemon restart, only "always" and "unless-stopped" (not stopped by hand) come back.
    const wasUp = c.state.status === 'running' || c.state.status === 'restarting';
    if (wasUp) c.state = { ...c.state, status: 'exited', exitCode: c.state.status === 'running' ? 255 : c.state.exitCode, finishedAt: world.clock, pid: 0 };
    saveContainer(host, c, world.clock);
    if (c.restart === 'always' || (c.restart === 'unless-stopped' && !c.state.manuallyStopped)) startContainer(world, host, c);
  }
  log(world, host, 'dockerd', `time="${new Date(world.clock).toISOString()}" level=info msg="Loading containers: done."`, { pid, unit });
  log(world, host, 'dockerd', `time="${new Date(world.clock).toISOString()}" level=info msg="Docker daemon" commit=de5c9cf containerd-snapshotter=false storage-driver=overlay2 version=${DOCKER_VERSION}`, { pid, unit });
  log(world, host, 'dockerd', `time="${new Date(world.clock).toISOString()}" level=info msg="API listen on /run/docker.sock"`, { pid, unit });
  return true;
}

function dockerdStop(world: World, host: Host): void {
  const live = daemonConfig(host).config.liveRestore;
  for (const c of listContainers(host).filter((x) => x.state.status === 'running' || x.state.status === 'restarting')) {
    if (live) continue;
    stopContainer(world, host, c, false);
    // Not a manual stop: "unless-stopped" containers return with the daemon.
  }
}

const dockerd: ServiceDef = {
  name: 'docker',
  unit: 'docker.service',
  aliases: ['docker', 'docker.service', 'dockerd'],
  description: 'Docker Application Container Engine',
  configFiles: ['/etc/docker/daemon.json'],
  start(world, host, rt) {
    host.nextPid += 7;
    const pid = host.nextPid;
    rt.pid = pid;
    return dockerdStart(world, host, pid);
  },
  stop(world, host) {
    dockerdStop(world, host);
  },
  listeners(host, rt) {
    const out: Listener[] = [];
    let k = 0;
    for (const c of listContainers(host).filter((x) => x.state.status === 'running')) {
      for (const p of c.ports) {
        const pid = (rt.pid ?? 0) + 40 + k++;
        out.push({ proto: p.proto, addr: p.hostIp, port: p.hostPort, process: 'docker-proxy', pid, service: 'docker' });
        if (p.hostIp === '0.0.0.0') out.push({ proto: p.proto, addr: '::', port: p.hostPort, process: 'docker-proxy', pid: pid + 1, service: 'docker' });
      }
    }
    return out;
  },
};

/** Processes inside containers that are not systemd services (their listeners still show in ss and accept connections). */
const containerProcess = (name: string, process: string): ServiceDef => ({
  name, unit: `${name}.service`, aliases: [], description: name, configFiles: [],
  start: () => true,
  listeners(_host, rt) {
    const port = (rt.loaded as { port: number } | null)?.port;
    return port ? [{ proto: 'tcp', addr: '0.0.0.0', port, process, pid: 1, service: name }] : [];
  },
});

SERVICE_DEFS.push(dockerd, containerProcess('postgres', 'postgres'), containerProcess('gunicorn', 'gunicorn'));

/** Where a docker-proxy listener forwards: the container and port behind a published host port. */
export function proxyTarget(world: World, docker: Host, port: number, proto: 'tcp' | 'udp' = 'tcp'): { ctr: Host; port: number } | null {
  for (const c of listContainers(docker).filter((x) => x.state.status === 'running')) {
    const p = c.ports.find((q) => q.hostPort === port && q.proto === proto);
    const live = p && runningHost(world, docker, c);
    if (p && live) return { ctr: live, port: p.ctrPort };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Embedded DNS (127.0.0.11) on user-defined networks
// ---------------------------------------------------------------------------

dnsHooks.embedded = (world: World, host: Host, server: string, qname: string, qtype: string): DnsExchange | null => {
  if (server !== '127.0.0.11' || !host.container) return null;
  const docker = world.hosts[host.container.host];
  const self = docker && findContainer(docker, host.container.id);
  if (!docker || !self) return null;
  const name = qname.toLowerCase().replace(/\.$/, '');
  const peers = listContainers(docker).filter((c) => c.network === self.network && c.state.status === 'running' && runningHost(world, docker, c));
  const hit = peers.find((c) => c.name === name || c.aliases.includes(name) || c.id.startsWith(name));
  if (hit && qtype === 'A') {
    return { server, qname, outcome: 'answer', rttMs: 1, answer: { rcode: 'NOERROR', authoritative: false, answers: [{ name: `${name}.`, ttl: 600, type: 'A', data: hit.state.ip! }] } };
  }
  if (hit) return { server, qname, outcome: 'nodata', rttMs: 1, answer: { rcode: 'NOERROR', authoritative: false, answers: [] } };
  // Anything else is forwarded to the host's resolvers, from the host.
  const ns = resolverConf(docker).nameservers[0];
  if (!ns) return { server, qname, outcome: 'servfail', rttMs: 1 };
  const ex = dnsQuery(world, docker, ns, qname, 5, qtype as never);
  return { ...ex, server };
};

// ---------------------------------------------------------------------------
// HTTP: docker-proxy and the inventory application (gunicorn)
// ---------------------------------------------------------------------------

httpHooks.proxy = (world, host, port) => {
  const t = proxyTarget(world, host, port);
  return t ? { host: t.ctr, port: t.port } : null;
};

httpHooks.apps.gunicorn = (world, host, req): HttpResponse => {
  const json = (status: number, reason: string, body: unknown): HttpResponse => {
    const text = JSON.stringify(body) + '\n';
    return { status, reason, body: text, size: text.length, binary: false, headers: [['Server', 'gunicorn'], ['Date', new Date(Math.floor(req.now)).toUTCString()], ['Connection', 'close'], ['Content-Type', 'application/json'], ['Content-Length', String(text.length)]] };
  };
  const path = req.path.split('?')[0];
  if (path === '/' || path === '/api/items') return json(200, 'OK', { service: 'inventory', version: '1.4', items: 128 });
  if (path === '/health') {
    // The database must still be there: the health check opens a connection.
    const docker = host.container ? world.hosts[host.container.host] : undefined;
    const self = docker && host.container ? findContainer(docker, host.container.id) : undefined;
    const dbName = self ? envOf(self, 'DB_HOST') ?? 'db' : 'db';
    const db = docker ? listContainers(docker).find((c) => c.network === self?.network && (c.name === dbName || c.aliases.includes(dbName))) : undefined;
    const up = !!(db && docker && runningHost(world, docker, db)?.services.postgres?.state === 'active');
    return up ? json(200, 'OK', { status: 'ok', database: 'ok' }) : json(503, 'Service Unavailable', { status: 'error', database: `could not connect to ${dbName}:5432` });
  }
  return json(404, 'Not Found', { detail: 'Not found.' });
};
