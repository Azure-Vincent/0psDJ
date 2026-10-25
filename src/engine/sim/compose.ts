// Docker Compose v2 (2.27) on top of the simulated Docker Engine: compose.yaml
// with ${VAR} interpolation from the project's .env, one network per project
// (<project>_default) where services find each other by name, containers named
// <project>-<service>-1, depends_on start order, and recreation when a
// service's configuration changed. Errors read like the real tool's.

import { dirname, basename, readFile, mkdir } from '../fs';
import type { Host, World } from '../types';
import { sha256Hex } from '../util/sha256';
import {
  addPulledImage, deleteContainer, ensureBridges, findImage, listContainers, listNetworks, newId, nextSubnet, pulledImages, saveContainer, saveNetworks,
  startContainer, stopContainer, syncDockerRules, type ContainerConfig, type Mount, type NetworkConfig, type PortBinding, type RestartPolicy,
} from './docker';

// ---------------------------------------------------------------------------
// YAML (the subset compose files use)
// ---------------------------------------------------------------------------

export type Yaml = string | Yaml[] | { [k: string]: Yaml } | null;

export class YamlError extends Error {}

function scalar(raw: string): Yaml {
  const v = raw.trim();
  if (v === '' || v === '~' || v === 'null') return null;
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  if (v.startsWith('[') && v.endsWith(']')) return v.slice(1, -1).split(',').map((x) => x.trim()).filter(Boolean).map((x) => scalar(x) as string);
  if (v === '{}') return {};
  return v;
}

/** Strip a comment (a # after whitespace, outside quotes). */
function uncomment(line: string): string {
  let q: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

export function parseYaml(text: string): Yaml {
  const lines: { n: number; indent: number; text: string }[] = [];
  text.split('\n').forEach((raw, i) => {
    if (/^\s*\t/.test(raw) || /^\t/.test(raw)) throw new YamlError(`yaml: line ${i + 1}: found character that cannot start any token`);
    const t = uncomment(raw).replace(/\s+$/, '');
    if (!t.trim()) return;
    lines.push({ n: i + 1, indent: t.length - t.trimStart().length, text: t.trim() });
  });
  let pos = 0;
  const block = (indent: number): Yaml => {
    const first = lines[pos];
    if (!first) return null;
    if (first.text.startsWith('- ') || first.text === '-') {
      const out: Yaml[] = [];
      while (pos < lines.length && lines[pos].indent === indent && (lines[pos].text.startsWith('- ') || lines[pos].text === '-')) {
        const l = lines[pos];
        const rest = l.text.replace(/^-\s*/, '');
        pos++;
        const kv = /^([^:'"\s][^:]*?):(\s+(.*))?$/.exec(rest);
        if (kv && !/^\S+:\/\//.test(rest) && !/^[\d.]+:\d/.test(rest)) {
          // "- key: value" starts a mapping whose other keys are indented further.
          const obj: Record<string, Yaml> = {};
          obj[kv[1]] = kv[3] !== undefined ? scalar(kv[3]) : pos < lines.length && lines[pos].indent > l.indent ? block(lines[pos].indent) : null;
          if (pos < lines.length && lines[pos].indent > l.indent && !(lines[pos].text.startsWith('- '))) Object.assign(obj, block(lines[pos].indent) as Record<string, Yaml>);
          out.push(obj);
        } else if (rest === '') {
          out.push(pos < lines.length && lines[pos].indent > indent ? block(lines[pos].indent) : null);
        } else out.push(scalar(rest));
      }
      if (pos < lines.length && lines[pos].indent > indent) throw new YamlError(`yaml: line ${lines[pos].n}: did not find expected '-' indicator`);
      return out;
    }
    const obj: Record<string, Yaml> = {};
    while (pos < lines.length && lines[pos].indent === indent) {
      const l = lines[pos];
      const m = /^("[^"]*"|'[^']*'|[^:]+?):(\s+(.*)|)$/.exec(l.text);
      if (!m) throw new YamlError(`yaml: line ${l.n}: could not find expected ':'`);
      const key = (scalar(m[1]) as string) ?? '';
      pos++;
      if (m[3] !== undefined && m[3] !== '') obj[key] = scalar(m[3]);
      else if (pos < lines.length && lines[pos].indent > indent) obj[key] = block(lines[pos].indent);
      else if (pos < lines.length && lines[pos].indent === indent && lines[pos].text.startsWith('- ')) obj[key] = block(indent);
      else obj[key] = null;
    }
    if (pos < lines.length && lines[pos].indent > indent) throw new YamlError(`yaml: line ${lines[pos].n}: mapping values are not allowed in this context`);
    return obj;
  };
  const doc = block(lines[0]?.indent ?? 0);
  if (pos < lines.length) throw new YamlError(`yaml: line ${lines[pos].n}: did not find expected key`);
  return doc;
}

// ---------------------------------------------------------------------------
// The project
// ---------------------------------------------------------------------------

export interface ComposeService {
  name: string;
  image: string;
  ports: PortBinding[];
  env: string[];
  restart: RestartPolicy;
  dependsOn: string[];
  mounts: Mount[];
}

export interface ComposeProject {
  name: string;
  dir: string;
  file: string;
  services: ComposeService[];
  volumes: string[];
  warnings: string[];
}

export const COMPOSE_FILES = ['compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'];

function parseDotEnv(text: string | undefined): Record<string, string> {
  const env: Record<string, string> = {};
  for (const l of (text ?? '').split('\n')) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(l);
    if (m && !l.trim().startsWith('#')) env[m[1]] = m[2].replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
  }
  return env;
}

function interpolate(text: string, env: Record<string, string>, warnings: string[]): string {
  return text.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (_m, a: string | undefined, def: string | undefined, b: string | undefined) => {
    const k = (a ?? b)!;
    if (env[k] !== undefined && env[k] !== '') return env[k];
    if (def !== undefined) return def;
    if (!warnings.some((w) => w.includes(`"${k}"`))) warnings.push(`WARN[0000] The "${k}" variable is not set. Defaulting to a blank string.`);
    return '';
  });
}

const asList = (v: Yaml | undefined): Yaml[] => (Array.isArray(v) ? v : v === null || v === undefined ? [] : [v]);

/** Load and validate compose.yaml in dir (as `docker compose` does in the current directory). */
export function loadProject(host: Host, dir: string, file?: string): ComposeProject | { error: string } {
  const path = file ? (file.startsWith('/') ? file : `${dir}/${file}`) : COMPOSE_FILES.map((f) => `${dir}/${f}`).find((p) => readFile(host, p) !== undefined);
  const text = path ? readFile(host, path) : undefined;
  if (!path || text === undefined) return { error: file ? `open ${path}: no such file or directory` : 'no configuration file provided: not found' };
  const projDir = dirname(path);
  const name = basename(projDir).toLowerCase().replace(/[^a-z0-9_-]/g, '');
  const warnings: string[] = [];
  let doc: Yaml;
  try {
    doc = parseYaml(interpolate(text, parseDotEnv(readFile(host, `${projDir}/.env`)), warnings));
  } catch (e) {
    return { error: e instanceof YamlError ? e.message : String(e) };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { error: 'Top-level object must be a mapping' };
  if ((doc as Record<string, Yaml>).version !== undefined) warnings.push(`WARN[0000] ${path}: \`version\` is obsolete`);
  const svcs = (doc as Record<string, Yaml>).services;
  if (!svcs || typeof svcs !== 'object' || Array.isArray(svcs)) return { error: 'no service selected' };
  const services: ComposeService[] = [];
  for (const [sname, raw] of Object.entries(svcs)) {
    const s = (raw ?? {}) as Record<string, Yaml>;
    if (typeof s !== 'object' || Array.isArray(s)) return { error: `services.${sname} must be a mapping` };
    if (!s.image) return { error: `service "${sname}" has neither an image nor a build context specified: invalid compose project` };
    const ports: PortBinding[] = [];
    for (const p of asList(s.ports)) {
      const spec = String(p);
      const parts = spec.split('/')[0].split(':');
      const proto = (spec.split('/')[1] ?? 'tcp') as 'tcp' | 'udp';
      const [hostIp, hostPort, ctrPort] = parts.length === 3 ? [parts[0], parts[1], parts[2]] : parts.length === 2 ? ['0.0.0.0', parts[0], parts[1]] : ['0.0.0.0', String(32768 + (Number(parts[0]) % 1000)), parts[0]];
      if (!/^\d+$/.test(hostPort) || !/^\d+$/.test(ctrPort)) return { error: `services.${sname}.ports: invalid port "${spec}"` };
      ports.push({ hostIp: hostIp || '0.0.0.0', hostPort: Number(hostPort), ctrPort: Number(ctrPort), proto });
    }
    const envRaw = s.environment;
    const env = Array.isArray(envRaw) ? envRaw.map(String) : envRaw && typeof envRaw === 'object' ? Object.entries(envRaw).map(([k, v]) => `${k}=${v ?? ''}`) : [];
    const restart = String(s.restart ?? 'no').split(':')[0];
    if (!['no', 'always', 'unless-stopped', 'on-failure'].includes(restart)) return { error: `services.${sname}.restart: invalid restart policy "${restart}"` };
    const deps = Array.isArray(s.depends_on) ? s.depends_on.map(String) : s.depends_on && typeof s.depends_on === 'object' ? Object.keys(s.depends_on) : [];
    const mounts: Mount[] = asList(s.volumes).map((v) => {
      const [src, target, mode] = String(v).split(':');
      const bind = src.startsWith('/') || src.startsWith('.');
      return { kind: bind ? 'bind' : 'volume', source: bind ? (src.startsWith('.') ? `${projDir}/${src.replace(/^\.\/?/, '')}`.replace(/\/$/, '') : src) : `${name}_${src}`, target, ro: mode === 'ro' };
    });
    services.push({ name: sname, image: String(s.image), ports, env, restart: restart as RestartPolicy, dependsOn: deps, mounts });
  }
  for (const s of services) for (const d of s.dependsOn) if (!services.some((x) => x.name === d)) return { error: `service "${s.name}" depends on undefined service "${d}": invalid compose project` };
  const vols = (doc as Record<string, Yaml>).volumes;
  return { name, dir: projDir, file: path, services, volumes: vols && typeof vols === 'object' && !Array.isArray(vols) ? Object.keys(vols) : [], warnings };
}

/** depends_on first. */
function startOrder(p: ComposeProject): ComposeService[] {
  const out: ComposeService[] = [];
  const visit = (s: ComposeService) => {
    if (out.includes(s)) return;
    for (const d of s.dependsOn) visit(p.services.find((x) => x.name === d)!);
    out.push(s);
  };
  p.services.forEach(visit);
  return out;
}

export const containerName = (p: ComposeProject, s: ComposeService | string) => `${p.name}-${typeof s === 'string' ? s : s.name}-1`;
const configHash = (s: ComposeService) => sha256Hex(JSON.stringify([s.image, s.ports, s.env, s.restart, s.mounts]));

export function projectContainers(docker: Host, project: string): ContainerConfig[] {
  return listContainers(docker).filter((c) => c.labels['com.docker.compose.project'] === project);
}

type Step = { kind: 'Network' | 'Volume' | 'Container'; name: string; verb: string; ok: boolean };

/** The final frame of Compose's TTY progress display. */
export function progress(steps: Step[], title = 'Running'): string {
  if (!steps.length) return '';
  const w = Math.max(...steps.map((s) => `${s.kind} ${s.name}`.length));
  const done = steps.filter((s) => s.ok).length;
  return [`[+] ${title} ${done}/${steps.length}`, ...steps.map((s, i) => ` ${s.ok ? '✔' : '✘'} ${`${s.kind} ${s.name}`.padEnd(w)}  ${s.verb.padEnd(9)} ${(0.1 + i * 0.3).toFixed(1)}s`)].join('\n');
}

/** docker compose up -d. */
export function composeUp(world: World, docker: Host, p: ComposeProject, only: string[] = [], removeOrphans = false): { out: string; code: number } {
  const steps: Step[] = [];
  if (removeOrphans) {
    for (const c of projectContainers(docker, p.name).filter((x) => !p.services.some((s) => s.name === x.labels['com.docker.compose.service']))) {
      stopContainer(world, docker, c, true);
      deleteContainer(docker, c);
      steps.push({ kind: 'Container', name: c.name, verb: 'Removed', ok: true });
    }
  }
  const t = world.clock;
  const netName = `${p.name}_default`;
  let nets = listNetworks(docker);
  if (!nets.some((n) => n.name === netName)) {
    const id = sha256Hex(`${docker.id}-net-${netName}-${t}`);
    const subnet = nextSubnet(nets);
    const n: NetworkConfig = { id, name: netName, driver: 'bridge', subnet, gateway: subnet.replace(/\.0\/(\d+)$/, '.1'), bridge: `br-${id.slice(0, 12)}`, created: t, labels: { 'com.docker.compose.project': p.name, 'com.docker.compose.network': 'default' } };
    nets = [...nets, n];
    saveNetworks(docker, nets, t);
    ensureBridges(world, docker);
    steps.push({ kind: 'Network', name: netName, verb: 'Created', ok: true });
  }
  for (const v of p.volumes) {
    const path = `/var/lib/docker/volumes/${p.name}_${v}/_data`;
    if (!docker.fs[path]) {
      for (const d of ['/var/lib/docker/volumes', `/var/lib/docker/volumes/${p.name}_${v}`, path]) if (!docker.fs[d]) mkdir(docker, d, t);
      steps.push({ kind: 'Volume', name: `"${p.name}_${v}"`, verb: 'Created', ok: true });
    }
  }
  const errors: string[] = [];
  const order = startOrder(p).filter((s) => !only.length || only.includes(s.name) || p.services.some((x) => only.includes(x.name) && x.dependsOn.includes(s.name)));
  for (const s of order) {
    const name = containerName(p, s);
    const ref = s.image.includes(':') ? s.image : `${s.image}:latest`;
    if (!findImage(s.image)) {
      errors.push(`Error response from daemon: pull access denied for ${s.image.split(':')[0]}, repository does not exist or may require 'docker login': denied: requested access to the resource is denied`);
      steps.push({ kind: 'Container', name, verb: 'Error', ok: false });
      break;
    }
    if (!pulledImages(docker).includes(ref)) addPulledImage(docker, ref, t);
    const hash = configHash(s);
    let c = listContainers(docker).find((x) => x.name === name);
    let verb = 'Started';
    if (c && c.labels['com.docker.compose.config-hash'] !== hash) {
      stopContainer(world, docker, c, false);
      deleteContainer(docker, c);
      c = undefined;
      verb = 'Recreated';
    } else if (c && c.state.status === 'running') {
      steps.push({ kind: 'Container', name, verb: 'Running', ok: true });
      continue;
    }
    if (!c) {
      c = {
        id: newId(world, name), name, image: ref, created: world.clock, env: s.env, cmd: [], ports: s.ports, restart: s.restart, network: netName, aliases: [s.name, name], mounts: s.mounts,
        labels: { 'com.docker.compose.project': p.name, 'com.docker.compose.service': s.name, 'com.docker.compose.config-hash': hash, 'com.docker.compose.project.working_dir': p.dir },
        state: { status: 'created', exitCode: 0, startedAt: 0, finishedAt: 0, restartCount: 0, manuallyStopped: false, pid: 0 },
      };
      saveContainer(docker, c, world.clock);
    }
    world.clock += 300;
    const e = startContainer(world, docker, c);
    if (e) {
      errors.push(e.message);
      steps.push({ kind: 'Container', name, verb: 'Starting', ok: false });
      break;
    }
    steps.push({ kind: 'Container', name, verb, ok: true });
  }
  syncDockerRules(docker);
  const orphans = projectContainers(docker, p.name).filter((c) => !p.services.some((x) => x.name === c.labels['com.docker.compose.service'])).map((c) => c.name);
  const orphanWarn = orphans.length ? `WARN[0000] Found orphan containers ([${orphans.join(' ')}]) for this project. If you removed or renamed this service in your compose file, you can run this command with the --remove-orphans flag to clean it up.` : '';
  return { out: [...p.warnings, orphanWarn, progress(steps), ...errors].filter(Boolean).join('\n'), code: errors.length ? 1 : 0 };
}

/** docker compose down [-v]. */
export function composeDown(world: World, docker: Host, p: ComposeProject, volumes: boolean): string {
  const steps: Step[] = [];
  for (const c of projectContainers(docker, p.name).reverse()) {
    stopContainer(world, docker, c, true);
    deleteContainer(docker, c);
    steps.push({ kind: 'Container', name: c.name, verb: 'Removed', ok: true });
  }
  const netName = `${p.name}_default`;
  const net = listNetworks(docker).find((n) => n.name === netName);
  if (net) {
    saveNetworks(docker, listNetworks(docker).filter((n) => n !== net && n.name !== netName), world.clock);
    docker.ifaces = docker.ifaces.filter((i) => i.name !== net.bridge);
    steps.push({ kind: 'Network', name: netName, verb: 'Removed', ok: true });
  }
  if (volumes) {
    for (const v of p.volumes) {
      const base = `/var/lib/docker/volumes/${p.name}_${v}`;
      if (!docker.fs[base]) continue;
      for (const k of Object.keys(docker.fs)) if (k === base || k.startsWith(base + '/')) delete docker.fs[k];
      steps.push({ kind: 'Volume', name: `${p.name}_${v}`, verb: 'Removed', ok: true });
    }
  }
  syncDockerRules(docker);
  return [...p.warnings, progress(steps)].filter(Boolean).join('\n');
}

/** docker compose config: the resolved project as YAML. */
export function composeConfig(p: ComposeProject): string {
  const out = [`name: ${p.name}`, 'services:'];
  for (const s of p.services) {
    out.push(`  ${s.name}:`);
    if (s.dependsOn.length) { out.push('    depends_on:'); for (const d of s.dependsOn) out.push(`      ${d}:`, '        condition: service_started', '        required: true'); }
    if (s.env.length) { out.push('    environment:'); for (const e of s.env) { const [k, ...v] = e.split('='); out.push(`      ${k}: ${v.join('=') || '""'}`); } }
    out.push(`    image: ${s.image}`, '    networks:', '      default: null');
    if (s.ports.length) {
      out.push('    ports:');
      for (const x of s.ports) out.push('      - mode: ingress', ...(x.hostIp !== '0.0.0.0' ? [`        host_ip: ${x.hostIp}`] : []), `        target: ${x.ctrPort}`, `        published: "${x.hostPort}"`, `        protocol: ${x.proto}`);
    }
    out.push(`    restart: ${s.restart}`);
    if (s.mounts.length) { out.push('    volumes:'); for (const m of s.mounts) out.push(`      - type: ${m.kind}`, `        source: ${m.kind === 'volume' ? m.source.replace(`${p.name}_`, '') : m.source}`, `        target: ${m.target}`, ...(m.ro ? ['        read_only: true'] : []), ...(m.kind === 'volume' ? ['        volume: {}'] : [])); }
  }
  out.push('networks:', '  default:', `    name: ${p.name}_default`);
  if (p.volumes.length) { out.push('volumes:'); for (const v of p.volumes) out.push(`  ${v}:`, `    name: ${p.name}_${v}`); }
  return out.join('\n');
}
