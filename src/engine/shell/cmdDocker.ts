// The docker CLI (Docker Engine 26.1, Debian 12): run, ps, logs, inspect, exec,
// start/stop/restart/kill/rm, images/pull, port, network ls/create/rm/inspect,
// volume ls, version and info. Output follows the real client's formats and
// error messages; containers are simulated hosts (see sim/docker.ts).

import {
  addPulledImage, containerHostId, containerLogs, daemonConfig, deleteContainer, DOCKER_SOCK, DOCKER_VERSION, dockerTick, ensureBridges, findContainer, findImage,
  IMAGES, listContainers, listNetworks, newId, nextSubnet, pulledImages, runningHost, saveContainer, saveNetworks, startContainer, stopContainer,
  syncDockerRules, type ContainerConfig, type Mount, type NetworkConfig, type PortBinding, type RestartPolicy,
} from '../sim/docker';
import { canAccess } from '../fs';
import { sha256Hex } from '../util/sha256';
import { composeConfig, composeDown, composeUp, loadProject, progress, projectContainers } from '../sim/compose';
import type { Host } from '../types';
import { type CmdCtx, type CmdResult, type CommandDef, err, ok } from './types';

const SOCK_DENIED = (path: string) => `permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: ${path}: dial unix /var/run/docker.sock: connect: permission denied`;
const NO_DAEMON = 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?';

/** go-units HumanDuration, as used by docker ps and docker images. */
export function humanDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 1) return 'Less than a second';
  if (s === 1) return '1 second';
  if (s < 60) return `${s} seconds`;
  const m = Math.floor(s / 60);
  if (m === 1) return 'About a minute';
  if (m < 60) return `${m} minutes`;
  const h = Math.round(s / 3600);
  if (h === 1) return 'About an hour';
  if (h < 48) return `${h} hours`;
  if (h < 24 * 7 * 2) return `${Math.floor(h / 24)} days`;
  if (h < 24 * 30 * 2) return `${Math.floor(h / 24 / 7)} weeks`;
  if (h < 24 * 365 * 2) return `${Math.floor(h / 24 / 30)} months`;
  return `${Math.floor(h / 24 / 365)} years`;
}

/** text/tabwriter with padding 3, as the docker CLI uses for tables. */
function table(rows: string[][]): string {
  const w = rows[0].map((_, i) => Math.max(...rows.map((r) => (r[i] ?? '').length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(w[i] + 3))).join('').trimEnd()).join('\n');
}

const ADJ = ['admiring', 'brave', 'clever', 'eager', 'elegant', 'focused', 'gifted', 'happy', 'jolly', 'keen', 'nifty', 'quirky', 'serene', 'vibrant', 'zealous'];
const NAMES = ['hopper', 'lovelace', 'turing', 'ritchie', 'thompson', 'torvalds', 'kare', 'hamilton', 'babbage', 'shannon', 'cerf', 'kahn', 'postel', 'perlman', 'mockapetris'];

export function portsText(c: ContainerConfig): string {
  const img = findImage(c.image);
  if (c.state.status !== 'running') return '';
  const published = c.ports.flatMap((p) => p.hostIp === '0.0.0.0' ? [`0.0.0.0:${p.hostPort}->${p.ctrPort}/${p.proto}`, `:::${p.hostPort}->${p.ctrPort}/${p.proto}`] : [`${p.hostIp}:${p.hostPort}->${p.ctrPort}/${p.proto}`]);
  const unpublished = (img?.exposed ?? []).filter((e) => !c.ports.some((p) => p.ctrPort === e)).map((e) => `${e}/tcp`);
  return [...unpublished, ...published].join(', ');
}

export function statusText(c: ContainerConfig, now: number): string {
  switch (c.state.status) {
    case 'running': return `Up ${humanDuration(now - c.state.startedAt)}`;
    case 'restarting': return `Restarting (${c.state.exitCode}) ${humanDuration(now - c.state.finishedAt)} ago`;
    case 'exited': return `Exited (${c.state.exitCode}) ${humanDuration(now - c.state.finishedAt)} ago`;
    default: return 'Created';
  }
}

function inspectObject(docker: Host, c: ContainerConfig) {
  const img = findImage(c.image)!;
  const net = listNetworks(docker).find((n) => n.name === c.network);
  const iso = (ms: number) => (ms ? new Date(Math.floor(ms)).toISOString().replace('Z', '000000Z') : '0001-01-01T00:00:00Z');
  const ports: Record<string, { HostIp: string; HostPort: string }[] | null> = {};
  for (const e of img.exposed) ports[`${e}/tcp`] = null;
  for (const p of c.ports) ports[`${p.ctrPort}/${p.proto}`] = [...(ports[`${p.ctrPort}/${p.proto}`] ?? []), { HostIp: p.hostIp, HostPort: String(p.hostPort) }];
  const running = c.state.status === 'running';
  return {
    Id: c.id,
    Created: iso(c.created),
    Path: img.cmd[0],
    Args: (c.cmd.length ? c.cmd : img.cmd).slice(1),
    State: { Status: c.state.status, Running: running, Paused: false, Restarting: c.state.status === 'restarting', OOMKilled: false, Dead: false, Pid: running ? c.state.pid : 0, ExitCode: c.state.exitCode, Error: c.state.error ?? '', StartedAt: iso(c.state.startedAt), FinishedAt: iso(c.state.finishedAt) },
    Image: img.id,
    Name: `/${c.name}`,
    RestartCount: c.state.restartCount,
    Mounts: c.mounts.map((m) => ({ Type: m.kind, Source: m.kind === 'bind' ? m.source : `/var/lib/docker/volumes/${m.source}/_data`, Destination: m.target, RW: !m.ro })),
    HostConfig: {
      PortBindings: Object.fromEntries(c.ports.map((p) => [`${p.ctrPort}/${p.proto}`, [{ HostIp: p.hostIp === '0.0.0.0' ? '' : p.hostIp, HostPort: String(p.hostPort) }]])),
      RestartPolicy: { Name: c.restart, MaximumRetryCount: 0 },
      NetworkMode: c.network === 'bridge' ? 'bridge' : c.network,
      Binds: c.mounts.map((m) => `${m.source}:${m.target}${m.ro ? ':ro' : ''}`),
    },
    Config: { Hostname: c.id.slice(0, 12), Env: [...img.env, ...c.env], Cmd: c.cmd.length ? c.cmd : img.cmd, Image: c.image, ExposedPorts: Object.fromEntries(img.exposed.map((e) => [`${e}/tcp`, {}])), Labels: c.labels },
    NetworkSettings: {
      Ports: running ? ports : {},
      Networks: { [c.network]: { Aliases: c.aliases.length ? c.aliases : null, NetworkID: net?.id ?? '', Gateway: running ? net?.gateway ?? '' : '', IPAddress: running ? c.state.ip ?? '' : '', IPPrefixLen: running ? Number(net?.subnet.split('/')[1] ?? 16) : 0, MacAddress: running ? c.state.mac ?? '' : '' } },
    },
  };
}

/** Go's fmt %v for the values a docker -f template prints. */
function goValue(v: unknown): string {
  if (v === null || v === undefined) return '<no value>';
  if (Array.isArray(v)) return `[${v.map(goValue).join(' ')}]`;
  if (typeof v === 'object') return `map[${Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, x]) => `${k}:${goValue(x)}`).join(' ')}]`;
  return String(v);
}

/** The subset of Go templates people type with docker inspect -f: fields, json, range … end, index. */
export function goTemplate(tpl: string, data: unknown): string {
  const get = (obj: unknown, path: string): unknown => {
    if (path === '.' || path === '') return obj;
    return path.replace(/^\./, '').split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), obj);
  };
  let out = '';
  let i = 0;
  while (i < tpl.length) {
    const open = tpl.indexOf('{{', i);
    if (open < 0) { out += tpl.slice(i); break; }
    out += tpl.slice(i, open);
    const close = tpl.indexOf('}}', open);
    const action = tpl.slice(open + 2, close).trim();
    i = close + 2;
    const range = /^range\s+(\S+)$/.exec(action);
    if (range) {
      const end = tpl.indexOf('{{end}}', i);
      const body = tpl.slice(i, end);
      i = end + 7;
      const coll = get(data, range[1]);
      const items = Array.isArray(coll) ? coll : coll && typeof coll === 'object' ? Object.values(coll) : [];
      for (const it of items) out += goTemplate(body, it);
      continue;
    }
    const json = /^json\s+(\S+)$/.exec(action);
    if (json) { out += JSON.stringify(get(data, json[1]) ?? null); continue; }
    const index = /^index\s+(\S+)\s+"([^"]*)"$/.exec(action);
    if (index) { out += goValue((get(data, index[1]) as Record<string, unknown> | undefined)?.[index[2]]); continue; }
    out += goValue(get(data, action));
  }
  return out;
}

function parsePort(spec: string): PortBinding | string {
  const [main, proto = 'tcp'] = spec.split('/');
  const parts = main.split(':');
  let hostIp = '0.0.0.0';
  let hostPort: number;
  let ctrPort: number;
  if (parts.length === 3) { hostIp = parts[0] || '0.0.0.0'; hostPort = Number(parts[1]); ctrPort = Number(parts[2]); }
  else if (parts.length === 2) { hostPort = Number(parts[0]); ctrPort = Number(parts[1]); }
  else { ctrPort = Number(parts[0]); hostPort = 32768 + (ctrPort % 1000); }
  if (!Number.isInteger(ctrPort) || ctrPort < 1 || ctrPort > 65535) return `invalid containerPort: ${parts.at(-1)}`;
  if (!Number.isInteger(hostPort) || hostPort < 1 || hostPort > 65535) return `invalid hostPort: ${parts.at(-2)}`;
  if (proto !== 'tcp' && proto !== 'udp') return `invalid proto: ${proto}`;
  return { hostIp, hostPort, ctrPort, proto };
}

function pullOutput(ref: string): string {
  const [repo, tag = 'latest'] = ref.split(':');
  const lib = repo.includes('/') ? repo : `library/${repo}`;
  const layers = ['a2abf6c4d29d', 'a9edb18cadd1', '589b7251471a', '186b1aaa4aa6', 'b4df32aa5a72', 'a0bcbecc962e'];
  return [`${tag}: Pulling from ${lib}`, ...layers.map((l) => `${l}: Pull complete`), `Digest: sha256:${sha256Hex(ref)}`, `Status: Downloaded newer image for ${repo}:${tag}`, `docker.io/${lib}:${tag}`].join('\n');
}

function parseMount(spec: string): Mount | string {
  const [source, target, mode] = spec.split(':');
  if (!source || !target) return `invalid volume specification: '${spec}'`;
  return { kind: source.startsWith('/') ? 'bind' : 'volume', source, target, ro: mode === 'ro' };
}

/** docker run / docker create: build the container configuration from the flags. */
function runCmd(ctx: CmdCtx, docker: Host, args: string[]): CmdResult {
  let detach = false;
  let name: string | undefined;
  let restart: RestartPolicy = 'no';
  let network = 'bridge';
  let removeAfter = false;
  const env: string[] = [];
  const ports: PortBinding[] = [];
  const mounts: Mount[] = [];
  const aliases: string[] = [];
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('-')) break;
    const [flag, inline] = a.includes('=') && a.startsWith('--') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, undefined];
    const val = () => inline ?? args[++i];
    if (flag === '-d' || flag === '--detach') detach = true;
    else if (/^-[it]+$/.test(flag) || /^-[itd]+$/.test(flag)) { if (flag.includes('d')) detach = true; }
    else if (flag === '--rm') removeAfter = true;
    else if (flag === '--name') name = val();
    else if (flag === '-e' || flag === '--env') env.push(val());
    else if (flag === '-p' || flag === '--publish') {
      const p = parsePort(val());
      if (typeof p === 'string') return err(`docker: ${p}.\nSee 'docker run --help'.`, 125);
      ports.push(p);
    } else if (flag === '-v' || flag === '--volume') {
      const m = parseMount(val());
      if (typeof m === 'string') return err(`docker: Error response from daemon: ${m}.\nSee 'docker run --help'.`, 125);
      mounts.push(m);
    } else if (flag === '--restart') {
      const r = val().split(':')[0];
      if (!['no', 'always', 'unless-stopped', 'on-failure'].includes(r)) return err(`docker: Error response from daemon: invalid restart policy '${r}'.\nSee 'docker run --help'.`, 125);
      restart = r as RestartPolicy;
    } else if (flag === '--network' || flag === '--net') network = val();
    else if (flag === '--network-alias') aliases.push(val());
    else return err(`unknown flag: ${flag}\nSee 'docker run --help'.`, 125);
  }
  const imageRef = args[i];
  if (!imageRef) return err(`"docker run" requires at least 1 argument.\nSee 'docker run --help'.\n\nUsage:  docker run [OPTIONS] IMAGE [COMMAND] [ARG...]\n\nCreate and run a new container from an image`, 1);
  const cmd = args.slice(i + 1);
  const out: string[] = [];
  const img = findImage(imageRef);
  const ref = imageRef.includes(':') ? imageRef : `${imageRef}:latest`;
  if (!img) return err(`Unable to find image '${ref}' locally\ndocker: Error response from daemon: pull access denied for ${imageRef.split(':')[0]}, repository does not exist or may require 'docker login': denied: requested access to the resource is denied.\nSee 'docker run --help'.`, 125);
  if (!pulledImages(docker).includes(ref)) {
    out.push(`Unable to find image '${ref}' locally`, pullOutput(ref).split('\n').slice(0, -1).join('\n'));
    addPulledImage(docker, ref, ctx.world.clock);
  }
  const nets = listNetworks(docker);
  if (!nets.some((n) => n.name === network)) return err([...out, `docker: Error response from daemon: network ${network} not found.\nSee 'docker run --help'.`].join('\n'), 125);
  const existing = listContainers(docker);
  const cname = name ?? `${ADJ[ctx.world.counter % ADJ.length]}_${NAMES[(ctx.world.counter >> 3) % NAMES.length]}`;
  const clash = existing.find((c) => c.name === cname);
  if (clash) return err([...out, `docker: Error response from daemon: Conflict. The container name "/${cname}" is already in use by container "${clash.id}". You have to remove (or rename) that container to be able to reuse that name.\nSee 'docker run --help'.`].join('\n'), 125);
  const t = ctx.world.clock;
  const c: ContainerConfig = {
    id: newId(ctx.world, cname), name: cname, image: ref, created: t, env, cmd, ports, restart, network, aliases: network === 'bridge' ? [] : [cname, ...aliases], mounts, labels: {},
    state: { status: 'created', exitCode: 0, startedAt: 0, finishedAt: 0, restartCount: 0, manuallyStopped: false, pid: 0 },
  };
  saveContainer(docker, c, t);
  const e = startContainer(ctx.world, docker, c);
  if (e) {
    const failed = findContainer(docker, c.id)!;
    failed.state.error = e.message.replace(/^Error response from daemon: /, '');
    saveContainer(docker, failed, t);
    return err([...out, detach ? c.id : '', `docker: ${e.message}.`].filter(Boolean).join('\n'), 125);
  }
  const after = findContainer(docker, c.id)!;
  if (detach) return ok([...out, c.id].join('\n'));
  // Foreground: the container's output; the simulator detaches once it is up (or has exited).
  const logs = containerLogs(ctx.world, docker, after).map((l) => l.line);
  if (after.state.status !== 'running') {
    if (removeAfter) deleteContainer(docker, after);
    return err([...out, ...logs].join('\n'), after.state.exitCode);
  }
  return ok([...out, ...logs, '', `[Infrastructure Lab: the container keeps running in the foreground; the simulator detaches here. Use -d to start it in the background, docker logs -f ${cname} to follow it.]`].join('\n'));
}

function containerArg(docker: Host, ref: string | undefined, cmd: string): ContainerConfig | CmdResult {
  if (!ref) return err(`"docker ${cmd}" requires at least 1 argument.\nSee 'docker ${cmd} --help'.`, 1);
  return findContainer(docker, ref) ?? err(`Error response from daemon: No such container: ${ref}`, 1);
}
const isResult = (x: unknown): x is CmdResult => !!x && typeof x === 'object' && 'code' in x && 'out' in x;

const PS_HEADERS: Record<string, string> = { ID: 'CONTAINER ID', Image: 'IMAGE', Command: 'COMMAND', RunningFor: 'CREATED', CreatedAt: 'CREATED AT', Status: 'STATUS', Ports: 'PORTS', Names: 'NAMES', State: 'STATE', Networks: 'NETWORKS' };

function psCmd(ctx: CmdCtx, docker: Host, args: string[]): CmdResult {
  const all = args.includes('-a') || args.includes('--all');
  const quiet = args.includes('-q') || args.includes('--quiet');
  const fi = args.findIndex((a) => a === '--format' || a.startsWith('--format='));
  const format = fi < 0 ? undefined : args[fi].startsWith('--format=') ? args[fi].slice(9) : args[fi + 1];
  const list = listContainers(docker).filter((c) => all || c.state.status === 'running' || c.state.status === 'restarting').reverse();
  if (quiet) return ok(list.map((c) => c.id.slice(0, 12)).join('\n'));
  const now = ctx.world.clock;
  if (format) {
    const fields = (c: ContainerConfig) => ({
      ID: c.id.slice(0, 12), Image: c.image.replace(/:latest$/, ''), Command: findImage(c.image)!.command, RunningFor: `${humanDuration(now - c.created)} ago`,
      CreatedAt: new Date(Math.floor(c.created)).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' +0000 UTC'), Status: statusText(c, now), Ports: portsText(c), Names: c.name, State: c.state.status, Networks: c.network,
    });
    const tpl = format.replace(/\\t/g, '\t');
    if (tpl.startsWith('table')) {
      const body = tpl.replace(/^table\s*/, '');
      const header = body.replace(/\{\{\s*\.(\w+)\s*\}\}/g, (_m, k) => PS_HEADERS[k] ?? k.toUpperCase());
      return ok(table([header, ...list.map((c) => goTemplate(body, fields(c)))].map((l) => l.split('\t'))));
    }
    return ok(list.map((c) => goTemplate(tpl, fields(c))).join('\n'));
  }
  const rows = [['CONTAINER ID', 'IMAGE', 'COMMAND', 'CREATED', 'STATUS', 'PORTS', 'NAMES']];
  for (const c of list) {
    const img = findImage(c.image)!;
    rows.push([c.id.slice(0, 12), c.image.replace(/:latest$/, ''), img.command, `${humanDuration(now - c.created)} ago`, statusText(c, now), portsText(c), c.name]);
  }
  return ok(table(rows));
}

function logsCmd(ctx: CmdCtx, docker: Host, args: string[]): CmdResult {
  let tail = Infinity;
  let ts = false;
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tail' || args[i] === '-n') tail = args[++i] === 'all' ? Infinity : Number(args[i]);
    else if (args[i].startsWith('--tail=')) tail = Number(args[i].slice(7));
    else if (args[i] === '-t' || args[i] === '--timestamps') ts = true;
    else if (args[i] === '-f' || args[i] === '--follow') continue;
    else rest.push(args[i]);
  }
  const c = containerArg(docker, rest[0], 'logs');
  if (isResult(c)) return c;
  const lines = containerLogs(ctx.world, docker, c);
  const shown = Number.isFinite(tail) ? lines.slice(-tail) : lines;
  return ok(shown.map((l) => (ts ? `${l.time} ${l.line}` : l.line)).join('\n'));
}

function inspectCmd(docker: Host, args: string[]): CmdResult {
  let fmt: string | undefined;
  const refs: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-f' || args[i] === '--format') fmt = args[++i];
    else if (args[i].startsWith('--format=')) fmt = args[i].slice(9);
    else refs.push(args[i]);
  }
  if (!refs.length) return err(`"docker inspect" requires at least 1 argument.\nSee 'docker inspect --help'.`, 1);
  const objs: unknown[] = [];
  const errors: string[] = [];
  for (const r of refs) {
    const c = findContainer(docker, r);
    const n = !c ? listNetworks(docker).find((x) => x.name === r || x.id.startsWith(r)) : undefined;
    if (c) objs.push(inspectObject(docker, c));
    else if (n) objs.push(networkObject(docker, n));
    else errors.push(`Error: No such object: ${r}`);
  }
  const out = fmt ? objs.map((o) => goTemplate(fmt!, o)).join('\n') : JSON.stringify(objs, null, 4);
  return errors.length ? err([objs.length ? out : '', ...errors].filter((x) => x !== '').join('\n'), 1) : ok(out);
}

function networkObject(docker: Host, n: NetworkConfig) {
  const ctrs = listContainers(docker).filter((c) => c.network === n.name && c.state.status === 'running');
  return {
    Name: n.name, Id: n.id, Created: new Date(Math.floor(n.created)).toISOString(), Scope: 'local', Driver: n.driver, EnableIPv6: false,
    IPAM: { Driver: 'default', Options: null, Config: n.subnet ? [{ Subnet: n.subnet, Gateway: n.gateway }] : [] },
    Internal: false, Attachable: false,
    Containers: Object.fromEntries(ctrs.map((c) => [c.id, { Name: c.name, MacAddress: c.state.mac, IPv4Address: `${c.state.ip}/${n.subnet.split('/')[1]}`, IPv6Address: '' }])),
    Options: n.name === 'bridge' ? { 'com.docker.network.bridge.default_bridge': 'true', 'com.docker.network.bridge.name': 'docker0' } : {},
    Labels: n.labels,
  };
}

function execCmd(ctx: CmdCtx, docker: Host, args: string[]): CmdResult {
  let user = 'root';
  let i = 0;
  for (; i < args.length && args[i].startsWith('-'); i++) {
    if (args[i] === '-u' || args[i] === '--user') user = args[++i];
  }
  const c = containerArg(docker, args[i], 'exec');
  if (isResult(c)) return c;
  const argv = args.slice(i + 1);
  if (!argv.length) return err(`"docker exec" requires at least 2 arguments.\nSee 'docker exec --help'.`, 1);
  const live = runningHost(ctx.world, docker, c);
  if (!live) return err(`Error response from daemon: container ${c.id} is not running`, 1);
  const img = findImage(c.image)!;
  const prog = argv[0];
  if (!img.tools.includes(prog)) return err(`OCI runtime exec failed: exec failed: unable to start container process: exec: "${prog}": executable file not found in $PATH: unknown`, 127);
  if (prog === 'env' || prog === 'printenv') {
    const vars = [...img.env, `HOSTNAME=${c.id.slice(0, 12)}`, ...c.env, 'HOME=/root'];
    return ok(prog === 'printenv' && argv[1] ? vars.filter((v) => v.startsWith(argv[1] + '=')).map((v) => v.split('=').slice(1).join('=')).join('\n') : vars.join('\n'));
  }
  if ((prog === 'sh' || prog === 'bash') && argv[1] === '-c') return ctx.run(argv.slice(2).join(' '), `${live.id}:${user}`);
  if ((prog === 'sh' || prog === 'bash') && argv.length === 1) return err('[Infrastructure Lab: interactive shells in containers are not simulated; run single commands: docker exec NAME cat /etc/resolv.conf]', 1);
  const quote = (s: string) => (/^[\w./:=@%+-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
  return ctx.run(argv.map(quote).join(' '), `${live.id}:${user}`);
}

function networkCmd(ctx: CmdCtx, docker: Host, args: string[]): CmdResult {
  const sub = args[0];
  const nets = listNetworks(docker);
  const t = ctx.world.clock;
  if (!sub || sub === 'ls' || sub === 'list') {
    return ok(table([['NETWORK ID', 'NAME', 'DRIVER', 'SCOPE'], ...nets.map((n) => [n.id.slice(0, 12), n.name, n.driver, 'local'])]));
  }
  if (sub === 'create') {
    let subnet: string | undefined;
    const rest: string[] = [];
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--subnet') subnet = args[++i];
      else if (args[i].startsWith('--subnet=')) subnet = args[i].slice(9);
      else if (args[i] === '-d' || args[i] === '--driver') i++;
      else rest.push(args[i]);
    }
    const name = rest[0];
    if (!name) return err(`"docker network create" requires exactly 1 argument.\nSee 'docker network create --help'.`, 1);
    if (nets.some((n) => n.name === name)) return err(`Error response from daemon: network with name ${name} already exists`, 1);
    const sn = subnet ?? nextSubnet(nets);
    const id = sha256Hex(`${docker.id}-net-${name}-${t}`);
    const gw = sn.replace(/\.0\/(\d+)$/, '.1');
    const n: NetworkConfig = { id, name, driver: 'bridge', subnet: sn, gateway: gw, bridge: `br-${id.slice(0, 12)}`, created: t, labels: {} };
    saveNetworks(docker, [...nets, n], t);
    ensureBridges(ctx.world, docker);
    syncDockerRules(docker);
    return ok(id);
  }
  if (sub === 'rm' || sub === 'remove') {
    const out: string[] = [];
    let code = 0;
    let keep = nets;
    for (const r of args.slice(1)) {
      const n = keep.find((x) => x.name === r || x.id.startsWith(r));
      if (!n) { out.push(`Error response from daemon: network ${r} not found`); code = 1; continue; }
      if (['bridge', 'host', 'none'].includes(n.name)) { out.push(`Error response from daemon: ${n.name} is a pre-defined network and cannot be removed`); code = 1; continue; }
      const busy = listContainers(docker).filter((c) => c.network === n.name && c.state.status === 'running');
      if (busy.length) { out.push(`Error response from daemon: error while removing network: network ${n.name} id ${n.id} has active endpoints`); code = 1; continue; }
      keep = keep.filter((x) => x !== n);
      docker.ifaces = docker.ifaces.filter((x) => x.name !== n.bridge);
      out.push(r);
    }
    saveNetworks(docker, keep, t);
    syncDockerRules(docker);
    return { out: out.join('\n'), code };
  }
  if (sub === 'inspect') return inspectCmd(docker, args.slice(1));
  return err(`docker: 'network ${sub}' is not a docker command.\nSee 'docker network --help'`, 1);
}

function lifecycle(ctx: CmdCtx, docker: Host, verb: string, args: string[]): CmdResult {
  const force = args.includes('-f') || args.includes('--force');
  const refs = args.filter((a) => !a.startsWith('-') && !/^\d+$/.test(a));
  if (!refs.length) return err(`"docker ${verb}" requires at least 1 argument.\nSee 'docker ${verb} --help'.`, 1);
  const out: string[] = [];
  let code = 0;
  for (const r of refs) {
    const c = findContainer(docker, r);
    if (!c) { out.push(`Error response from daemon: No such container: ${r}`); code = 1; continue; }
    if (verb === 'stop' || verb === 'kill') {
      if (verb === 'kill' && c.state.status !== 'running') { out.push(`Error response from daemon: cannot kill container: ${r}: container ${c.id} is not running`); code = 1; continue; }
      stopContainer(ctx.world, docker, c, true);
      if (verb === 'kill') { const k = findContainer(docker, c.id)!; k.state.exitCode = 137; saveContainer(docker, k, ctx.world.clock); }
      out.push(r);
    } else if (verb === 'start' || verb === 'restart') {
      if (verb === 'restart') stopContainer(ctx.world, docker, c, false);
      const e = startContainer(ctx.world, docker, findContainer(docker, c.id)!);
      if (e) { out.push(`${e.message}\nError: failed to start containers: ${r}`); code = 1; continue; }
      out.push(r);
    } else if (verb === 'rm') {
      if (c.state.status === 'running' || c.state.status === 'restarting') {
        if (!force) { out.push(`Error response from daemon: cannot remove container "/${c.name}": container is running: stop the container before removing or force remove`); code = 1; continue; }
        stopContainer(ctx.world, docker, c, true);
      }
      deleteContainer(docker, c);
      syncDockerRules(docker);
      out.push(r);
    }
  }
  return { out: out.join('\n'), code };
}

function infoCmd(docker: Host): CmdResult {
  const all = listContainers(docker);
  const n = (s: string) => all.filter((c) => c.state.status === s).length;
  const dc = daemonConfig(docker).config;
  return ok([
    'Client: Docker Engine - Community', ` Version:    ${DOCKER_VERSION}`, ' Context:    default', '', 'Server:',
    ` Containers: ${all.length}`, `  Running: ${n('running')}`, '  Paused: 0', `  Stopped: ${n('exited') + n('created') + n('restarting')}`,
    ` Images: ${pulledImages(docker).length}`, ` Server Version: ${DOCKER_VERSION}`, ' Storage Driver: overlay2', ' Logging Driver: json-file', ' Cgroup Driver: systemd', ' Cgroup Version: 2',
    ' Kernel Version: 6.1.0-26-amd64', ' Operating System: Debian GNU/Linux 12 (bookworm)', ` Name: ${docker.hostname}`, ' Docker Root Dir: /var/lib/docker', ` Live Restore Enabled: ${dc.liveRestore}`,
    ...(dc.iptables ? [] : ['', 'WARNING: iptables is disabled; published ports are not forwarded']),
  ].join('\n'));
}

/** docker compose (v2.27): up, down, ps, logs, config, start/stop/restart, pull, version. */
function composeCmd(ctx: CmdCtx, docker: Host, args: string[]): CmdResult {
  let file: string | undefined;
  let i = 0;
  for (; i < args.length && args[i].startsWith('-'); i++) {
    if (args[i] === '-f' || args[i] === '--file') file = args[++i];
  }
  const sub = args[i];
  const rest = args.slice(i + 1);
  if (sub === 'version') return ok('Docker Compose version v2.27.1');
  if (!sub) return ok('Usage:  docker compose [OPTIONS] COMMAND\n\nDefine and run multi-container applications with Docker\n\nCommands:\n  config      Parse, resolve and render compose file in canonical format\n  down        Stop and remove containers, networks\n  logs        View output from containers\n  ps          List containers\n  restart     Restart service containers\n  start       Start services\n  stop        Stop services\n  up          Create and start containers');
  const p = loadProject(docker, ctx.frame.cwd, file);
  if ('error' in p) return err(p.error, 1);
  const svcArgs = rest.filter((a) => !a.startsWith('-') && !/^\d+$/.test(a));
  for (const sname of svcArgs) if (!p.services.some((x) => x.name === sname)) return err(`no such service: ${sname}`, 1);
  const warn = p.warnings.length ? p.warnings.join('\n') + '\n' : '';
  const now = ctx.world.clock;
  switch (sub) {
    case 'up': {
      const r = composeUp(ctx.world, docker, p, svcArgs, rest.includes('--remove-orphans'));
      if (r.code || rest.includes('-d') || rest.includes('--detach')) return { out: r.out, code: r.code };
      const logs = projectContainers(docker, p.name).flatMap((c) => containerLogs(ctx.world, docker, c).map((l) => `${c.labels['com.docker.compose.service']}-1  | ${l.line}`));
      return ok([r.out, 'Attaching to ' + projectContainers(docker, p.name).map((c) => `${c.labels['com.docker.compose.service']}-1`).join(', '), ...logs, '', '[Infrastructure Lab: the simulator detaches here; the containers keep running. Use docker compose up -d.]'].join('\n'));
    }
    case 'down': return ok(composeDown(ctx.world, docker, p, rest.includes('-v') || rest.includes('--volumes')));
    case 'ps': {
      const all = rest.includes('-a') || rest.includes('--all');
      const list = projectContainers(docker, p.name).filter((c) => all || c.state.status === 'running' || c.state.status === 'restarting');
      const rows = [['NAME', 'IMAGE', 'COMMAND', 'SERVICE', 'CREATED', 'STATUS', 'PORTS']];
      for (const c of list) rows.push([c.name, c.image.replace(/:latest$/, ''), findImage(c.image)!.command, c.labels['com.docker.compose.service'], `${humanDuration(now - c.created)} ago`, statusText(c, now), portsText(c)]);
      return ok(warn + table(rows));
    }
    case 'logs': {
      let tail = Infinity;
      for (let k = 0; k < rest.length; k++) if (rest[k] === '--tail' || rest[k] === '-n') tail = Number(rest[++k]);
      const list = projectContainers(docker, p.name).filter((c) => !svcArgs.length || svcArgs.includes(c.labels['com.docker.compose.service']));
      const w = Math.max(0, ...list.map((c) => c.labels['com.docker.compose.service'].length + 2));
      const out: string[] = [];
      for (const c of list) {
        const lines = containerLogs(ctx.world, docker, c);
        for (const l of Number.isFinite(tail) ? lines.slice(-tail) : lines) out.push(`${(c.labels['com.docker.compose.service'] + '-1').padEnd(w)}  | ${l.line}`);
      }
      return ok(warn + out.join('\n'));
    }
    case 'config': return ok(warn + composeConfig(p));
    case 'stop': case 'start': case 'restart': {
      const targets = projectContainers(docker, p.name).filter((c) => !svcArgs.length || svcArgs.includes(c.labels['com.docker.compose.service']));
      const steps: { kind: 'Container'; name: string; verb: string; ok: boolean }[] = [];
      const errors: string[] = [];
      for (const c of targets) {
        if (sub !== 'start') stopContainer(ctx.world, docker, c, sub === 'stop');
        if (sub !== 'stop') {
          const e = startContainer(ctx.world, docker, findContainer(docker, c.id)!);
          if (e) { errors.push(e.message); steps.push({ kind: 'Container', name: c.name, verb: 'Error', ok: false }); continue; }
        }
        steps.push({ kind: 'Container', name: c.name, verb: sub === 'stop' ? 'Stopped' : 'Started', ok: true });
      }
      return { out: [warn + progress(steps, sub === 'stop' ? 'Stopping' : sub === 'start' ? 'Running' : 'Restarting'), ...errors].filter(Boolean).join('\n'), code: errors.length ? 1 : 0 };
    }
    case 'pull': {
      const steps = p.services.map((s) => ({ kind: 'Container' as const, name: s.name, verb: findImage(s.image) ? 'Pulled' : 'Error', ok: !!findImage(s.image) }));
      for (const s of p.services) if (findImage(s.image)) addPulledImage(docker, s.image.includes(':') ? s.image : `${s.image}:latest`, ctx.world.clock);
      return ok(warn + progress(steps, 'Pulling').replace(/ Container /g, ' '));
    }
    default: return err(`unknown docker command: "compose ${sub}"`, 1);
  }
}

const docker: CommandDef = {
  name: 'docker',
  summary: 'manage containers, images and networks (Docker Engine 26)',
  usage: 'docker run|ps|logs|inspect|exec|start|stop|restart|kill|rm|images|pull|port|network|volume|info|version ...',
  run(args, ctx) {
    const host = ctx.host;
    if (!host.services.docker) return err('-bash: docker: command not found', 127);
    const sub = args[0];
    if (sub === 'version' || sub === '--version' || sub === '-v') {
      if (sub !== 'version') return ok(`Docker version ${DOCKER_VERSION}, build b9d17ea`);
    }
    // The CLI needs read/write on the API socket (root:docker 0660 unless someone changed it).
    const sock = host.fs[DOCKER_SOCK];
    const isAdmin = ctx.user.uid === 0 || (sock ? canAccess(sock, ctx.user, 'r') && canAccess(sock, ctx.user, 'w') : ctx.user.groups.includes('docker'));
    if (!isAdmin) return err(SOCK_DENIED(sub === 'ps' ? 'Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.45/containers/json"' : 'Head "http://%2Fvar%2Frun%2Fdocker.sock/_ping"'), 1);
    if (host.services.docker.state !== 'active') return err(NO_DAEMON, 1);
    dockerTick(ctx.world, host);
    const rest = args.slice(1);
    switch (sub) {
      case 'run': return runCmd(ctx, host, rest);
      case 'ps': return psCmd(ctx, host, rest);
      case 'container': {
        const s = rest[0];
        if (s === 'ls' || s === 'list') return psCmd(ctx, host, rest.slice(1));
        return docker.run([s, ...rest.slice(1)], ctx);
      }
      case 'logs': return logsCmd(ctx, host, rest);
      case 'inspect': return inspectCmd(host, rest);
      case 'exec': return execCmd(ctx, host, rest);
      case 'start': case 'stop': case 'restart': case 'kill': case 'rm': return lifecycle(ctx, host, sub, rest);
      case 'images': case 'image': {
        if (sub === 'image' && rest[0] !== 'ls' && rest[0] !== 'list') return err(`docker: 'image ${rest[0] ?? ''}' is not a docker command.\nSee 'docker image --help'`, 1);
        const rows = [['REPOSITORY', 'TAG', 'IMAGE ID', 'CREATED', 'SIZE']];
        for (const ref of pulledImages(host)) {
          const img = findImage(ref)!;
          rows.push([ref.split(':')[0], ref.split(':')[1], img.id.slice(7, 19), img.created, img.size]);
        }
        return ok(table(rows));
      }
      case 'pull': {
        const ref = rest[0];
        if (!ref) return err(`"docker pull" requires exactly 1 argument.\nSee 'docker pull --help'.`, 1);
        const full = ref.includes(':') ? ref : `${ref}:latest`;
        if (!findImage(ref)) return err(`Error response from daemon: pull access denied for ${ref.split(':')[0]}, repository does not exist or may require 'docker login': denied: requested access to the resource is denied`, 1);
        addPulledImage(host, full, ctx.world.clock);
        return ok(pullOutput(full));
      }
      case 'port': {
        const c = containerArg(host, rest[0], 'port');
        if (isResult(c)) return c;
        if (c.state.status !== 'running') return ok('');
        return ok(c.ports.flatMap((p) => (p.hostIp === '0.0.0.0' ? [`${p.ctrPort}/${p.proto} -> 0.0.0.0:${p.hostPort}`, `${p.ctrPort}/${p.proto} -> [::]:${p.hostPort}`] : [`${p.ctrPort}/${p.proto} -> ${p.hostIp}:${p.hostPort}`])).join('\n'));
      }
      case 'network': return networkCmd(ctx, host, rest);
      case 'compose': return composeCmd(ctx, host, rest);
      case 'volume': {
        const vols = [...new Set(listContainers(host).flatMap((c) => c.mounts.filter((m) => m.kind === 'volume').map((m) => m.source)))];
        return ok(table([['DRIVER', 'VOLUME NAME'], ...vols.map((v) => ['local', v])]));
      }
      case 'info': return infoCmd(host);
      case 'version': return ok(`Client: Docker Engine - Community\n Version:           ${DOCKER_VERSION}\n API version:       1.45\n Go version:        go1.21.11\n OS/Arch:           linux/amd64\n\nServer: Docker Engine - Community\n Engine:\n  Version:          ${DOCKER_VERSION}\n  API version:      1.45 (minimum version 1.24)\n  OS/Arch:          linux/amd64\n containerd:\n  Version:          1.6.33\n runc:\n  Version:          1.1.12`);
      case undefined: return ok('Usage:  docker [OPTIONS] COMMAND\n\nA self-sufficient runtime for containers\n\nCommon Commands:\n  run         Create and run a new container from an image\n  exec        Execute a command in a running container\n  ps          List containers\n  logs        Fetch the logs of a container\n  inspect     Return low-level information on Docker objects\n  network     Manage networks\n  images      List images');
      default: return err(`docker: '${sub}' is not a docker command.\nSee 'docker --help'`, 1);
    }
  },
};

export const DOCKER_COMMANDS: CommandDef[] = [docker];
export { IMAGES, containerHostId };
