// kubectl (v1.30, as shipped with k3s): get, describe, logs, exec, apply,
// delete, create, expose, scale, set image, rollout, label, cordon/uncordon,
// drain, config, cluster-info and version. Output follows the real client's
// tables and error messages. The cluster itself is simulated in sim/k8s.ts.

import { canAccess, canTraverse } from '../fs';
import { parseYaml, YamlError, type Yaml } from '../config/yaml';
import { resolve } from '../sim/dns';
import {
  addObject, allocateClusterIp, allocateNodePort, API_VERSION, b64decode, b64encode, deletePod, event, find, imageRef, isPodReady, K3S_VERSION, KUBE_NODES, KUBECONFIG_PATH,
  kubeHooks, kubeServer, kubeTick, kubeWait, KUBECTL_VERSION, list, loadStore, matchLabels, NAMESPACED, nodeAllocated, nodeReady, objNs, podCtrHostId, podLogs, podRequests,
  removeObject, saveStore, type J, type KEvent, type KObj, type Store,
} from '../sim/k8s';
import { findImage } from '../sim/docker';
import { tcpConnect } from '../sim/tcp';
import type { Host, World } from '../types';
import { Shell } from './shell';
import { type CmdCtx, type CmdResult, type CommandDef, err, ok } from './types';

// Probes that run a command in the container use a shell on the (copied) world.
kubeHooks.run = (world: World, hostId: string, line: string) => {
  let w = world;
  const sh = new Shell(() => w, (n) => (w = n), { hostId, user: 'root', cwd: '/' });
  const r = sh.execute(line);
  return { out: r.output, code: r.code };
};

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/** k8s.io/apimachinery duration.HumanDuration (the AGE column). */
export function age(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 0) return '0s';
  if (s < 120) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 10) return s % 60 ? `${m}m${s % 60}s` : `${m}m`;
  if (m < 180) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 8) return m % 60 ? `${h}h${m % 60}m` : `${h}h`;
  if (h < 48) return `${h}h`;
  const d = Math.floor(h / 24);
  if (h < 24 * 8) return h % 24 ? `${d}d${h % 24}h` : `${d}d`;
  if (d < 365 * 2) return `${d}d`;
  const y = Math.floor(d / 365);
  return y < 8 ? (d % 365 ? `${y}y${d % 365}d` : `${y}y`) : `${y}y`;
}

/** kubectl's printers: columns separated by at least three spaces, left-aligned. */
function table(rows: string[][]): string {
  if (!rows.length) return '';
  const w = rows[0].map((_, i) => Math.max(...rows.map((r) => (r[i] ?? '').length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(w[i] + 3))).join('').trimEnd()).join('\n');
}

const iso = (ms: number) => new Date(Math.floor(ms)).toISOString().replace(/\.\d+Z$/, 'Z');
const rfc1123 = (ms: number) => new Date(Math.floor(ms)).toUTCString().replace('GMT', '+0000');

/** A small YAML emitter for -o yaml and --dry-run output. */
export function toYaml(v: unknown, indent = 0): string {
  const pad = ' '.repeat(indent);
  const scalar = (x: unknown): string => {
    if (x === null || x === undefined) return 'null';
    if (typeof x === 'number' || typeof x === 'boolean') return String(x);
    const s = String(x);
    if (s === '' || /^[\s]|[\s]$|^[-?:,[\]{}#&*!|>'"%@`]|: | #|^(true|false|null|yes|no|on|off|~)$|^[-+]?\d+(\.\d+)?$/i.test(s) || s.includes('\n')) {
      if (s.includes('\n')) return `|\n${s.replace(/\n$/, '').split('\n').map((l) => `${pad}  ${l}`).join('\n')}`;
      return JSON.stringify(s);
    }
    return s;
  };
  if (Array.isArray(v)) {
    if (!v.length) return `${pad}[]\n`;
    return v.map((item) => {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        const body = toYaml(item, indent + 2);
        return `${pad}- ${body.slice(indent + 2)}`;
      }
      return `${pad}- ${scalar(item)}\n`;
    }).join('');
  }
  if (v && typeof v === 'object') {
    const entries = Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== undefined);
    if (!entries.length) return `${pad}{}\n`;
    return entries.map(([k, x]) => {
      const key = /^[\w./-]+$/.test(k) ? k : JSON.stringify(k);
      if (x && typeof x === 'object') {
        if (Array.isArray(x) && !x.length) return `${pad}${key}: []\n`;
        if (!Array.isArray(x) && !Object.keys(x).length) return `${pad}${key}: {}\n`;
        return `${pad}${key}:\n${toYaml(x, Array.isArray(x) ? indent : indent + 2)}`;
      }
      const sc = scalar(x);
      return sc.startsWith('|') ? `${pad}${key}: ${sc}\n` : `${pad}${key}: ${sc}\n`;
    }).join('');
  }
  return `${pad}${scalar(v)}\n`;
}

// ---------------------------------------------------------------------------
// Resource names
// ---------------------------------------------------------------------------

const RESOURCES: Record<string, { kind: string; plural: string; group: string; short?: string[] }> = {};
for (const [kind, plural, group, short] of [
  ['Pod', 'pods', '', ['po', 'pod']], ['Deployment', 'deployments', 'apps', ['deploy', 'deployment']], ['ReplicaSet', 'replicasets', 'apps', ['rs', 'replicaset']],
  ['Service', 'services', '', ['svc', 'service']], ['Endpoints', 'endpoints', '', ['ep']], ['Node', 'nodes', '', ['no', 'node']], ['Namespace', 'namespaces', '', ['ns', 'namespace']],
  ['ConfigMap', 'configmaps', '', ['cm', 'configmap']], ['Secret', 'secrets', '', ['secret']], ['Event', 'events', '', ['ev', 'event']],
] as [string, string, string, string[]][]) {
  const def = { kind, plural, group, short };
  RESOURCES[plural] = def;
  RESOURCES[`${plural}.${group || 'core'}`] = def;
  if (group) RESOURCES[`${plural}.${group}`] = def;
  for (const s of short) RESOURCES[s] = def;
  RESOURCES[kind.toLowerCase()] = def;
}

const resOf = (kind: string) => Object.values(RESOURCES).find((r) => r.kind === kind)!;
/** "deployment.apps/web", "pod/web-1", "service/web" */
export const refName = (o: { kind: string; metadata: { name: string } }) => `${o.kind.toLowerCase()}${resOf(o.kind).group ? '.' + resOf(o.kind).group : ''}/${o.metadata.name}`;
const shortRef = (o: KObj) => `${o.kind.toLowerCase()}/${o.metadata.name}`;
/** "deployments.apps" or "pods" (NotFound messages). */
const groupRes = (kind: string) => `${resOf(kind).plural}${resOf(kind).group ? '.' + resOf(kind).group : ''}`;
const notFound = (kind: string, name: string) => `Error from server (NotFound): ${groupRes(kind)} "${name}" not found`;

// ---------------------------------------------------------------------------
// Connecting to the API server
// ---------------------------------------------------------------------------

interface Conn { st: Store; ns: string; world: World; server: Host }

function readKubeconfig(ctx: CmdCtx, path: string): { server: string; namespace?: string } | CmdResult {
  const node = ctx.host.fs[path];
  if (!node) return err(`error: error loading config file "${path}": open ${path}: no such file or directory`, 1);
  if (!canTraverse(ctx.host, path, ctx.user) || !canAccess(node, ctx.user, 'r')) {
    const warn = path === KUBECONFIG_PATH ? `WARN[0000] Unable to read ${KUBECONFIG_PATH}, please start server with --write-kubeconfig-mode or --write-kubeconfig-group to modify kube config permissions \n` : '';
    return err(`${warn}error: error loading config file "${path}": open ${path}: permission denied`, 1);
  }
  try {
    const y = parseYaml(node.content) as J;
    const ctxName = y?.['current-context'];
    const c = (y?.contexts ?? []).find((x: J) => x.name === ctxName)?.context ?? {};
    const cl = (y?.clusters ?? []).find((x: J) => x.name === c.cluster)?.cluster;
    if (!cl?.server) return err('error: no configuration has been provided, try setting KUBERNETES_MASTER environment variable', 1);
    return { server: String(cl.server), namespace: c.namespace ? String(c.namespace) : undefined };
  } catch (e) {
    return err(`error: error loading config file "${path}": ${(e as Error).message}`, 1);
  }
}

function connect(ctx: CmdCtx, nsFlag?: string): Conn | CmdResult {
  const h = ctx.host;
  if (!h.fs['/usr/local/bin/kubectl'] && !h.fs['/usr/bin/kubectl']) return err(`-bash: kubectl: command not found`, 127);
  const home = ctx.user.home;
  const envPath = ctx.env.KUBECONFIG;
  const userCfg = `${home}/.kube/config`;
  // k3s' kubectl falls back to the server's admin kubeconfig.
  const k3s = !!h.fs['/usr/local/bin/k3s'];
  let path = envPath || (h.fs[userCfg] ? userCfg : k3s && h.fs[KUBECONFIG_PATH] ? KUBECONFIG_PATH : '');
  if (!path) {
    if (k3s) path = KUBECONFIG_PATH;
    else return err('E1102 10:24:31.112480    4021 memcache.go:265] couldn\'t get current server API group list: Get "http://localhost:8080/api?timeout=32s": dial tcp [::1]:8080: connect: connection refused\nThe connection to the server localhost:8080 was refused - did you specify the right host or port?', 1);
  }
  if (path === KUBECONFIG_PATH && !h.fs[path]) return err('The connection to the server localhost:8080 was refused - did you specify the right host or port?', 1);
  const cfg = readKubeconfig(ctx, path);
  if ('code' in cfg) return cfg;
  const m = /^https?:\/\/([^:/]+)(?::(\d+))?/.exec(cfg.server);
  const hostName = m?.[1] ?? '';
  const port = Number(m?.[2] ?? 443);
  const shown = `${hostName}:${port}`;
  const r = resolve(ctx.world, h, hostName, { family: 4 });
  if (!r.ok) return err(`E1102 10:24:31.112480    4021 memcache.go:265] couldn't get current server API group list: Get "${cfg.server}/api?timeout=32s": dial tcp: lookup ${hostName} on ${(h.fs['/etc/resolv.conf']?.content.match(/nameserver\s+(\S+)/)?.[1]) ?? '127.0.0.53'}:53: no such host\nUnable to connect to the server: dial tcp: lookup ${hostName} on ${(h.fs['/etc/resolv.conf']?.content.match(/nameserver\s+(\S+)/)?.[1]) ?? '127.0.0.53'}:53: no such host`, 1);
  const c = tcpConnect(ctx.world, h, r.ip, port, { timeoutMs: 10_000 });
  if (!c.ok) {
    if (c.errno === 'ECONNREFUSED') return err(`E1102 10:24:31.112480    4021 memcache.go:265] couldn't get current server API group list: Get "${cfg.server}/api?timeout=32s": dial tcp ${r.ip}:${port}: connect: connection refused\nThe connection to the server ${shown} was refused - did you specify the right host or port?`, 1);
    return err(`E1102 10:24:31.112480    4021 memcache.go:265] couldn't get current server API group list: Get "${cfg.server}/api?timeout=32s": dial tcp ${r.ip}:${port}: i/o timeout\nUnable to connect to the server: dial tcp ${r.ip}:${port}: i/o timeout`, 1);
  }
  c.conn.close('client');
  const server = c.conn.server;
  if (server.id !== kubeServer(ctx.world)?.id || port !== 6443) return err(`Unable to connect to the server: tls: failed to verify certificate: x509: certificate signed by unknown authority`, 1);
  // The API server answers: the cluster has kept running meanwhile.
  ctx.world.clock += 600;
  kubeTick(ctx.world);
  return { st: loadStore(ctx.world), ns: nsFlag ?? cfg.namespace ?? 'default', world: ctx.world, server };
}

const isConn = (c: Conn | CmdResult): c is Conn => 'st' in c;

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

interface Args { pos: string[]; flags: Map<string, string | true>; rest: string[] }

const VALUE_FLAGS = new Set(['-n', '--namespace', '-o', '--output', '-l', '--selector', '-f', '--filename', '-c', '--container', '--tail', '--replicas', '--image', '--port', '--target-port', '--type', '--name', '--from-literal', '--from-file', '--timeout', '--dry-run', '--to-revision', '--grace-period', '--sort-by', '--field-selector', '--protocol', '--node-port', '--context', '--since', '--for']);

function parseArgs(args: string[]): Args {
  const pos: string[] = [];
  const flags = new Map<string, string | true>();
  const multi: Record<string, string[]> = {};
  let rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { rest = args.slice(i + 1); break; }
    if (a.startsWith('--') && a.includes('=')) {
      const [k, ...v] = a.split('=');
      const val = v.join('=');
      if (k === '--from-literal' || k === '--from-file') (multi[k] ??= []).push(val);
      flags.set(k, val);
      continue;
    }
    if (a.startsWith('-') && a.length > 1 && !/^-\d/.test(a)) {
      if (/^-[a-zA-Z]{2,}$/.test(a) && !VALUE_FLAGS.has(a.slice(0, 2))) { for (const ch of a.slice(1)) flags.set(`-${ch}`, true); continue; }
      if (/^-[nolfc].+/.test(a) && !a.startsWith('--')) { flags.set(a.slice(0, 2), a.slice(2)); continue; }
      if (VALUE_FLAGS.has(a)) {
        const val = args[++i] ?? '';
        if (a === '--from-literal' || a === '--from-file') (multi[a] ??= []).push(val);
        flags.set(a, val);
      } else flags.set(a, true);
      continue;
    }
    pos.push(a);
  }
  for (const [k, v] of Object.entries(multi)) flags.set(k, v.join('\u0000'));
  return { pos, flags, rest };
}

const flag = (a: Args, ...names: string[]) => { for (const n of names) { const v = a.flags.get(n); if (v !== undefined) return v; } return undefined; };
const flagStr = (a: Args, ...names: string[]) => { const v = flag(a, ...names); return typeof v === 'string' ? v : undefined; };

/** "app=web,tier!=db,env" label selectors. */
function selectorMatch(sel: string | undefined, labels: Record<string, string> | undefined): boolean {
  if (!sel) return true;
  return sel.split(',').map((x) => x.trim()).filter(Boolean).every((term) => {
    let m = /^([\w./-]+)\s*!=\s*(.*)$/.exec(term);
    if (m) return labels?.[m[1]] !== m[2];
    m = /^([\w./-]+)\s*==?\s*(.*)$/.exec(term);
    if (m) return labels?.[m[1]] === m[2];
    m = /^!([\w./-]+)$/.exec(term);
    if (m) return !(labels && m[1] in labels);
    m = /^([\w./-]+)\s+in\s+\(([^)]*)\)$/.exec(term);
    if (m) return m[2].split(',').map((x) => x.trim()).includes(labels?.[m[1]] ?? '\u0000');
    return !!labels && term in labels;
  });
}

// ---------------------------------------------------------------------------
// Pod status as kubectl shows it
// ---------------------------------------------------------------------------

export function podStatus(p: KObj): string {
  if (p.metadata.deletionTimestamp) return 'Terminating';
  const cs = p.status?.containerStatuses?.[0];
  if (cs?.state?.waiting?.reason) return cs.state.waiting.reason;
  if (cs?.state?.terminated) return cs.state.terminated.reason ?? 'Error';
  if (p.status?.phase === 'Pending' && !p.spec.nodeName) return 'Pending';
  return p.status?.phase ?? 'Pending';
}

function restartsCol(p: KObj, now: number): string {
  const cs = p.status?.containerStatuses?.[0];
  const n = cs?.restartCount ?? 0;
  const last = cs?.lastState?.terminated?.finishedAt;
  return n && last ? `${n} (${age(now - last)} ago)` : String(n);
}

const readyCol = (p: KObj) => `${(p.status?.containerStatuses ?? []).filter((c: J) => c.ready).length}/${Math.max(1, (p.spec.containers ?? []).length)}`;

function portsCol(s: KObj): string {
  return (s.spec.ports ?? []).map((p: J) => `${p.port}${p.nodePort && s.spec.type === 'NodePort' ? `:${p.nodePort}` : ''}/${p.protocol ?? 'TCP'}`).join(',') || '<none>';
}

function selectorCol(sel: Record<string, string> | undefined): string {
  return sel && Object.keys(sel).length ? Object.entries(sel).map(([k, v]) => `${k}=${v}`).join(',') : '<none>';
}

const labelsCol = (o: KObj) => (o.metadata.labels && Object.keys(o.metadata.labels).length ? Object.entries(o.metadata.labels).map(([k, v]) => `${k}=${v}`).join(',') : '<none>');

function endpointsCol(ep: J): string {
  const addrs: string[] = [];
  for (const s of ep.subsets ?? []) for (const a of s.addresses ?? []) for (const p of s.ports ?? []) addrs.push(`${a.ip}:${p.port}`);
  if (!addrs.length) return '<none>';
  return addrs.length > 3 ? `${addrs.slice(0, 3).join(',')} + ${addrs.length - 3} more...` : addrs.join(',');
}

function nodeStatusCol(n: KObj): string {
  return `${n.status?.ready ? 'Ready' : 'NotReady'}${n.spec.unschedulable ? ',SchedulingDisabled' : ''}`;
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

function rowsFor(kind: string, objs: KObj[], st: Store, now: number, wide: boolean, showNs: boolean, showLabels: boolean): string[][] {
  const head: Record<string, string[]> = {
    Pod: ['NAME', 'READY', 'STATUS', 'RESTARTS', 'AGE', ...(wide ? ['IP', 'NODE', 'NOMINATED NODE', 'READINESS GATES'] : [])],
    Deployment: ['NAME', 'READY', 'UP-TO-DATE', 'AVAILABLE', 'AGE', ...(wide ? ['CONTAINERS', 'IMAGES', 'SELECTOR'] : [])],
    ReplicaSet: ['NAME', 'DESIRED', 'CURRENT', 'READY', 'AGE', ...(wide ? ['CONTAINERS', 'IMAGES', 'SELECTOR'] : [])],
    Service: ['NAME', 'TYPE', 'CLUSTER-IP', 'EXTERNAL-IP', 'PORT(S)', 'AGE', ...(wide ? ['SELECTOR'] : [])],
    Endpoints: ['NAME', 'ENDPOINTS', 'AGE'],
    Node: ['NAME', 'STATUS', 'ROLES', 'AGE', 'VERSION', ...(wide ? ['INTERNAL-IP', 'EXTERNAL-IP', 'OS-IMAGE', 'KERNEL-VERSION', 'CONTAINER-RUNTIME'] : [])],
    Namespace: ['NAME', 'STATUS', 'AGE'],
    ConfigMap: ['NAME', 'DATA', 'AGE'],
    Secret: ['NAME', 'TYPE', 'DATA', 'AGE'],
  };
  const row = (o: KObj): string[] => {
    const a = age(now - o.metadata.creationTimestamp);
    switch (kind) {
      case 'Pod': return [o.metadata.name, readyCol(o), podStatus(o), restartsCol(o, now), a, ...(wide ? [o.status?.podIP ?? '<none>', o.spec.nodeName ?? '<none>', '<none>', '<none>'] : [])];
      case 'Deployment': {
        const c = (o.spec.template?.spec?.containers ?? []) as J[];
        return [o.metadata.name, `${o.status?.readyReplicas ?? 0}/${o.spec.replicas ?? 1}`, String(o.status?.updatedReplicas ?? 0), String(o.status?.availableReplicas ?? 0), a, ...(wide ? [c.map((x) => x.name).join(','), c.map((x) => x.image).join(','), selectorCol(o.spec.selector?.matchLabels)] : [])];
      }
      case 'ReplicaSet': {
        const c = (o.spec.template?.spec?.containers ?? []) as J[];
        return [o.metadata.name, String(o.spec.replicas ?? 0), String(o.status?.replicas ?? 0), String(o.status?.readyReplicas ?? 0), a, ...(wide ? [c.map((x) => x.name).join(','), c.map((x) => x.image).join(','), selectorCol(o.spec.selector?.matchLabels)] : [])];
      }
      case 'Service': return [o.metadata.name, o.spec.type ?? 'ClusterIP', o.spec.clusterIP ?? '<none>', '<none>', portsCol(o), a, ...(wide ? [selectorCol(o.spec.selector)] : [])];
      case 'Endpoints': return [o.metadata.name, endpointsCol(o), a];
      case 'Node': {
        const n = KUBE_NODES.find((x) => x.id === o.metadata.name);
        return [o.metadata.name, nodeStatusCol(o), n?.roles ?? '<none>', a, K3S_VERSION, ...(wide ? [n?.ip ?? '<none>', '<none>', 'Debian GNU/Linux 12 (bookworm)', '6.1.0-26-amd64', 'containerd://1.7.22-k3s1'] : [])];
      }
      case 'Namespace': return [o.metadata.name, 'Active', a];
      case 'ConfigMap': return [o.metadata.name, String(Object.keys(o.data ?? {}).length), a];
      case 'Secret': return [o.metadata.name, o.type ?? 'Opaque', String(Object.keys(o.data ?? {}).length), a];
      default: return [o.metadata.name, a];
    }
  };
  void st;
  const h = head[kind] ?? ['NAME', 'AGE'];
  return [[...(showNs ? ['NAMESPACE'] : []), ...h, ...(showLabels ? ['LABELS'] : [])], ...objs.map((o) => [...(showNs ? [objNs(o)] : []), ...row(o), ...(showLabels ? [labelsCol(o)] : [])])];
}

/** The API object as -o yaml/json shows it (the simulator's bookkeeping removed). */
export function publicObject(o: KObj): J {
  const clean = (v: J): J => {
    if (Array.isArray(v)) return v.map(clean);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([k]) => !['_sim', 'lastSchedMsg', 'transition', 'ready', 'address', 'lastProgress', 'updated', 'updatedReady', 'complete', 'failed', 'newRs'].includes(k) || !('creationTimestamp' in (o.metadata ?? {}))).map(([k, x]) => [k, clean(x)]));
    return v;
  };
  const meta: J = { ...o.metadata, creationTimestamp: iso(o.metadata.creationTimestamp) };
  if (meta.deletionTimestamp) meta.deletionTimestamp = iso(meta.deletionTimestamp);
  if (!meta.namespace) delete meta.namespace;
  const out: J = { apiVersion: o.apiVersion, kind: o.kind, metadata: meta };
  if (o.data) out.data = o.data;
  if (o.type) out.type = o.type;
  if ((o as J).subsets) out.subsets = (o as J).subsets;
  if (o.spec) out.spec = clean(o.spec);
  if (o.status) {
    const s = clean(o.status);
    for (const k of ['_sim', 'lastSchedMsg', 'transition', 'ready', 'address', 'lastProgress', 'updated', 'updatedReady', 'complete', 'failed', 'newRs', 'probeCache']) delete s[k];
    if (o.kind === 'Pod' && s.startTime) s.startTime = iso(s.startTime);
    for (const c of s.containerStatuses ?? []) for (const st of [c.state, c.lastState]) for (const v of Object.values(st ?? {}) as J[]) { for (const k of ['startedAt', 'finishedAt']) if (typeof v?.[k] === 'number') v[k] = iso(v[k]); }
    out.status = s;
  }
  return out;
}

/** -o jsonpath='{.spec.clusterIP}' and '{.items[*].metadata.name}' (the common subset). */
function jsonpath(expr: string, data: J): string {
  const body = expr.replace(/^'|'$/g, '');
  return body.replace(/\{([^}]*)\}/g, (_m, path: string) => {
    if (path === '"\\n"' || path === "'\\n'") return '\n';
    const parts = path.replace(/^\./, '').split('.').filter(Boolean);
    let cur: J[] = [data];
    for (const part of parts) {
      const m = /^([\w-]+)?(?:\[(\*|\d+)\])?$/.exec(part);
      if (!m) return '';
      const next: J[] = [];
      for (const c of cur) {
        let v = m[1] ? c?.[m[1]] : c;
        if (m[2] === '*') { if (Array.isArray(v)) next.push(...v); continue; }
        if (m[2] !== undefined) v = Array.isArray(v) ? v[Number(m[2])] : undefined;
        if (v !== undefined) next.push(v);
      }
      cur = next;
    }
    return cur.map((v) => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(' ');
  });
}

function output(objs: KObj[], fmt: string | undefined, single: boolean): string | null {
  if (!fmt) return null;
  if (fmt === 'name') return objs.map(refName).join('\n');
  const data = single ? publicObject(objs[0]) : { apiVersion: 'v1', items: objs.map(publicObject), kind: 'List', metadata: { resourceVersion: '' } };
  if (fmt === 'yaml') return toYaml(data).trimEnd();
  if (fmt === 'json') return JSON.stringify(data, null, 4);
  if (fmt.startsWith('jsonpath=')) return jsonpath(fmt.slice(9), data);
  return null;
}

function resolveTargets(a: Args, startAt: number): { res: (typeof RESOURCES)[string]; names: string[] }[] | string {
  const out: { res: (typeof RESOURCES)[string]; names: string[] }[] = [];
  const pos = a.pos.slice(startAt);
  if (!pos.length) return 'error: You must specify the type of resource to get. Use "kubectl api-resources" for a complete list of supported resources.';
  if (pos[0].includes('/')) {
    for (const p of pos) {
      const [r, n] = p.split('/');
      const res = RESOURCES[r.toLowerCase()];
      if (!res) return `error: the server doesn't have a resource type "${r}"`;
      const e = out.find((x) => x.res === res);
      if (e) e.names.push(n); else out.push({ res, names: [n] });
    }
    return out;
  }
  for (const r of pos[0].split(',')) {
    if (r === 'all') { for (const k of ['pods', 'services', 'deployments', 'replicasets']) out.push({ res: RESOURCES[k], names: [] }); continue; }
    const res = RESOURCES[r.toLowerCase()];
    if (!res) return `error: the server doesn't have a resource type "${r}"`;
    out.push({ res, names: pos.slice(1) });
  }
  return out;
}

function getCmd(ctx: CmdCtx, a: Args): CmdResult {
  if (flag(a, '-w', '--watch')) return err('[Cyber Owl Lab: --watch is not simulated; run the command again to see the current state]', 1);
  const all = !!flag(a, '-A', '--all-namespaces');
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const targets = resolveTargets(a, 1);
  if (typeof targets === 'string') return err(targets, 1);
  const fmt = flagStr(a, '-o', '--output');
  const wide = fmt === 'wide';
  const sel = flagStr(a, '-l', '--selector');
  const showLabels = !!flag(a, '--show-labels');
  const now = ctx.world.clock;
  const outs: string[] = [];
  const errs: string[] = [];
  const allObjs: KObj[] = [];
  const multi = targets.length > 1 || a.pos[1] === 'all';
  for (const t of targets) {
    if (t.res.kind === 'Event') {
      const evs = c.st.events.filter((e) => all || e.ns === c.ns).sort((x, y) => x.last - y.last);
      if (!evs.length) { errs.push(`No resources found in ${c.ns} namespace.`); continue; }
      outs.push(table([[...(all ? ['NAMESPACE'] : []), 'LAST SEEN', 'TYPE', 'REASON', 'OBJECT', 'MESSAGE'], ...evs.map((e) => [...(all ? [e.ns] : []), age(now - e.last), e.type, e.reason, `${e.kind.toLowerCase()}/${e.name}`, e.message])]));
      continue;
    }
    const ns = NAMESPACED.has(t.res.kind) ? (all ? undefined : c.ns) : undefined;
    let objs = list(c.st, t.res.kind, ns).filter((o) => selectorMatch(sel, o.metadata.labels));
    if (t.names.length) {
      const found: KObj[] = [];
      for (const n of t.names) {
        const o = objs.find((x) => x.metadata.name === n);
        if (o) found.push(o); else errs.push(notFound(t.res.kind, n));
      }
      objs = found;
    }
    objs.sort((x, y) => objNs(x).localeCompare(objNs(y)) || x.metadata.name.localeCompare(y.metadata.name));
    if (!objs.length) { if (!t.names.length && !multi) errs.push(NAMESPACED.has(t.res.kind) && !all ? `No resources found in ${c.ns} namespace.` : 'No resources found'); continue; }
    allObjs.push(...objs);
    if (fmt && fmt !== 'wide') continue;
    const rows = rowsFor(t.res.kind, objs, c.st, now, wide, all && NAMESPACED.has(t.res.kind), showLabels);
    if (multi) rows.forEach((r, i) => { if (i > 0) r[all ? 1 : 0] = `${t.res.kind.toLowerCase()}${t.res.group ? '.' + t.res.group : ''}/${r[all ? 1 : 0]}`; });
    outs.push(table(rows));
  }
  if (fmt && fmt !== 'wide') {
    if (!allObjs.length) return err(errs.join('\n') || `No resources found in ${c.ns} namespace.`, errs.some((e) => e.startsWith('Error')) ? 1 : 0);
    const single = targets.length === 1 && targets[0].names.length === 1;
    const o = output(allObjs, fmt, single);
    if (o === null) return err(`error: unable to match a printer suitable for the output format "${fmt}", allowed formats are: custom-columns,custom-columns-file,go-template,go-template-file,json,jsonpath,jsonpath-as-json,jsonpath-file,name,template,templatefile,wide,yaml`, 1);
    return { out: [o, ...errs].filter(Boolean).join('\n'), code: errs.some((e) => e.startsWith('Error')) ? 1 : 0 };
  }
  if (a.pos[1] === 'all' && !outs.length) return ok(`No resources found in ${c.ns} namespace.`);
  return { out: [outs.join('\n\n'), ...errs].filter(Boolean).join('\n'), code: errs.some((e) => e.startsWith('Error')) ? 1 : 0 };
}

// ---------------------------------------------------------------------------
// describe
// ---------------------------------------------------------------------------

function kv(lines: string[], k: string, v: string, w = 16): void {
  lines.push(`${(k + ':').padEnd(Math.max(w, k.length + 3))}${v}`);
}

function mapLines(m: Record<string, string> | undefined, w = 16, first = ''): string[] {
  const e = Object.entries(m ?? {});
  if (!e.length) return [`${first.padEnd(w)}<none>`];
  return e.map(([k, v], i) => `${(i === 0 ? first : '').padEnd(w)}${k}=${v}`);
}

function eventsBlock(st: Store, o: KObj, now: number): string[] {
  const evs = st.events.filter((e) => e.kind === o.kind && e.name === o.metadata.name && e.ns === (objNs(o) || 'default')).sort((x, y) => x.first - y.first);
  if (!evs.length) return ['Events:          <none>'];
  const ageCol = (e: KEvent) => (e.count > 1 ? `${age(now - e.last)} (x${e.count} over ${age(now - e.first)})` : age(now - e.first));
  return ['Events:', ...table([['Type', 'Reason', 'Age', 'From', 'Message'], ['----', '------', '----', '----', '-------'], ...evs.map((e) => [e.type, e.reason, ageCol(e), e.source, e.message])]).split('\n').map((l) => `  ${l}`)];
}

function probeText(p: J): string {
  const t = `delay=${p.initialDelaySeconds ?? 0}s timeout=${p.timeoutSeconds ?? 1}s period=${p.periodSeconds ?? 10}s #success=${p.successThreshold ?? 1} #failure=${p.failureThreshold ?? 3}`;
  if (p.httpGet) return `http-get http://:${p.httpGet.port}${p.httpGet.path ?? '/'} ${t}`;
  if (p.tcpSocket) return `tcp-socket :${p.tcpSocket.port} ${t}`;
  if (p.exec) return `exec [${(p.exec.command ?? []).join(' ')}] ${t}`;
  return t;
}

function stateLines(label: string, s: J, now: number): string[] {
  if (!s) return [];
  const [k, v] = (Object.entries(s)[0] ?? []) as [string, J];
  if (!k) return [];
  const out = [`    ${(label + ':').padEnd(16)}${k[0].toUpperCase() + k.slice(1)}`];
  if (v?.reason) out.push(`      Reason:       ${v.reason}`);
  if (v?.message && k === 'waiting' && v.reason !== 'CrashLoopBackOff') out.push(`      Message:      ${v.message}`);
  if (k === 'terminated') out.push(`      Exit Code:    ${v.exitCode}`);
  if (v?.startedAt) out.push(`      Started:      ${rfc1123(v.startedAt)}`);
  if (v?.finishedAt) out.push(`      Finished:     ${rfc1123(v.finishedAt)}`);
  void now;
  return out;
}

function describePod(st: Store, p: KObj, now: number): string {
  const L: string[] = [];
  kv(L, 'Name', p.metadata.name);
  kv(L, 'Namespace', objNs(p));
  kv(L, 'Priority', '0');
  kv(L, 'Service Account', 'default');
  kv(L, 'Node', p.spec.nodeName ? `${p.spec.nodeName}/${KUBE_NODES.find((n) => n.id === p.spec.nodeName)?.ip}` : '<none>');
  if (p.status?.startTime) kv(L, 'Start Time', rfc1123(p.status.startTime));
  L.push(...mapLines(p.metadata.labels, 16, 'Labels:'));
  kv(L, 'Annotations', '<none>');
  kv(L, 'Status', p.metadata.deletionTimestamp ? 'Terminating' : p.status?.phase ?? 'Pending');
  kv(L, 'IP', p.status?.podIP ?? '');
  L.push('IPs:', ...(p.status?.podIP ? [`  IP:  ${p.status.podIP}`] : ['  <none>']));
  const owner = p.metadata.ownerReferences?.[0];
  if (owner) kv(L, 'Controlled By', `${owner.kind}/${owner.name}`);
  L.push('Containers:');
  for (const c of p.spec.containers ?? []) {
    const cs = (p.status?.containerStatuses ?? []).find((x: J) => x.name === c.name) ?? {};
    L.push(`  ${c.name}:`);
    L.push(`    Container ID:   ${cs.containerID ?? ''}`);
    L.push(`    Image:          ${c.image}`);
    L.push(`    Image ID:       ${cs.imageID ?? ''}`);
    const ports = (c.ports ?? []).map((x: J) => `${x.containerPort}/${x.protocol ?? 'TCP'}`).join(', ');
    L.push(`    Port:           ${ports || '<none>'}`, `    Host Port:      ${ports ? '0/TCP' : '<none>'}`);
    if (c.command) L.push('    Command:', ...c.command.map((x: string) => `      ${x}`));
    if (c.args) L.push('    Args:', ...c.args.map((x: string) => `      ${x}`));
    L.push(...stateLines('State', cs.state, now), ...stateLines('Last State', cs.lastState, now));
    L.push(`    Ready:          ${cs.ready ? 'True' : 'False'}`, `    Restart Count:  ${cs.restartCount ?? 0}`);
    if (c.resources?.limits) L.push('    Limits:', ...Object.entries(c.resources.limits).map(([k, v]) => `      ${k}:  ${v}`));
    if (c.resources?.requests) L.push('    Requests:', ...Object.entries(c.resources.requests).map(([k, v]) => `      ${k}:  ${v}`));
    if (c.livenessProbe) L.push(`    Liveness:       ${probeText(c.livenessProbe)}`);
    if (c.readinessProbe) L.push(`    Readiness:      ${probeText(c.readinessProbe)}`);
    const env: string[] = [];
    for (const e of c.env ?? []) {
      if (e.value !== undefined) env.push(`      ${e.name}:  ${e.value}`);
      else if (e.valueFrom?.configMapKeyRef) env.push(`      ${e.name}:  <set to the key '${e.valueFrom.configMapKeyRef.key}' of config map '${e.valueFrom.configMapKeyRef.name}'>  Optional: false`);
      else if (e.valueFrom?.secretKeyRef) env.push(`      ${e.name}:  <set to the key '${e.valueFrom.secretKeyRef.key}' in secret '${e.valueFrom.secretKeyRef.name}'>  Optional: false`);
    }
    if (c.envFrom?.length) L.push('    Environment Variables from:', ...c.envFrom.map((e: J) => `      ${(e.configMapRef ?? e.secretRef).name}  ${e.configMapRef ? 'ConfigMap' : 'Secret'}  Optional: false`));
    L.push(env.length ? '    Environment:' : '    Environment:    <none>', ...env);
    L.push('    Mounts:', ...(c.volumeMounts ?? []).map((m: J) => `      ${m.mountPath} from ${m.name} (${m.readOnly ? 'ro' : 'rw'})`), '      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access (ro)');
  }
  L.push('Conditions:', '  Type                        Status', ...(p.status?.conditions ?? [{ type: 'PodScheduled', status: 'False' }]).map((c: J) => `  ${c.type.padEnd(28)}${c.status}`));
  L.push('Volumes:');
  for (const v of p.spec.volumes ?? []) {
    L.push(`  ${v.name}:`);
    if (v.configMap) L.push('    Type:      ConfigMap (a volume populated by a ConfigMap)', `    Name:      ${v.configMap.name}`, '    Optional:  false');
    else if (v.secret) L.push('    Type:        Secret (a volume populated by a Secret)', `    SecretName:  ${v.secret.secretName}`, '    Optional:    false');
    else if (v.emptyDir) L.push('    Type:       EmptyDir (a temporary directory that shares a pod\'s lifetime)', '    Medium:     ', '    SizeLimit:  <unset>');
  }
  L.push('  kube-api-access:', '    Type:                    Projected (a volume that contains injected data from multiple sources)', '    TokenExpirationSeconds:  3607');
  const req = podRequests(p.spec);
  const lim = (p.spec.containers ?? []).every((c: J) => c.resources?.limits?.cpu && c.resources?.limits?.memory && JSON.stringify(c.resources.limits) === JSON.stringify(c.resources.requests ?? c.resources.limits));
  kv(L, 'QoS Class', req.cpu || req.mem ? (lim ? 'Guaranteed' : 'Burstable') : 'BestEffort', 27);
  kv(L, 'Node-Selectors', p.spec.nodeSelector ? Object.entries(p.spec.nodeSelector).map(([k, v]) => `${k}=${v}`).join('\n                             ') : '<none>', 27);
  kv(L, 'Tolerations', 'node.kubernetes.io/not-ready:NoExecute op=Exists for 300s\n                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s', 27);
  L.push(...eventsBlock(st, p, now));
  return L.join('\n');
}

function describeDeployment(st: Store, d: KObj, now: number): string {
  const L: string[] = [];
  kv(L, 'Name', d.metadata.name, 24);
  kv(L, 'Namespace', objNs(d), 24);
  kv(L, 'CreationTimestamp', rfc1123(d.metadata.creationTimestamp), 24);
  L.push(...mapLines(d.metadata.labels, 24, 'Labels:'));
  const rss = list(st, 'ReplicaSet', objNs(d)).filter((r) => r.metadata.ownerReferences?.some((o) => o.uid === d.metadata.uid));
  const newRs = rss.find((r) => r.metadata.name === d.status?.newRs);
  kv(L, 'Annotations', `deployment.kubernetes.io/revision: ${newRs?.metadata.annotations?.['deployment.kubernetes.io/revision'] ?? 1}`, 24);
  kv(L, 'Selector', selectorCol(d.spec.selector?.matchLabels), 24);
  const s = d.status ?? {};
  kv(L, 'Replicas', `${d.spec.replicas ?? 1} desired | ${s.updatedReplicas ?? 0} updated | ${s.replicas ?? 0} total | ${s.availableReplicas ?? 0} available | ${s.unavailableReplicas ?? 0} unavailable`, 24);
  kv(L, 'StrategyType', d.spec.strategy?.type ?? 'RollingUpdate', 24);
  kv(L, 'MinReadySeconds', String(d.spec.minReadySeconds ?? 0), 24);
  if ((d.spec.strategy?.type ?? 'RollingUpdate') === 'RollingUpdate') kv(L, 'RollingUpdateStrategy', `${d.spec.strategy?.rollingUpdate?.maxUnavailable ?? '25%'} max unavailable, ${d.spec.strategy?.rollingUpdate?.maxSurge ?? '25%'} max surge`, 24);
  L.push('Pod Template:', ...mapLines(d.spec.template?.metadata?.labels, 13, '  Labels:'), '  Containers:');
  for (const c of d.spec.template?.spec?.containers ?? []) {
    L.push(`   ${c.name}:`, `    Image:      ${c.image}`, `    Port:       ${(c.ports ?? []).map((x: J) => `${x.containerPort}/${x.protocol ?? 'TCP'}`).join(', ') || '<none>'}`, `    Host Port:  ${(c.ports ?? []).length ? '0/TCP' : '<none>'}`);
    if (c.livenessProbe) L.push(`    Liveness:   ${probeText(c.livenessProbe)}`);
    if (c.readinessProbe) L.push(`    Readiness:  ${probeText(c.readinessProbe)}`);
    L.push(`    Environment:${(c.env ?? []).length ? '' : '  <none>'}`, ...(c.env ?? []).map((e: J) => `      ${e.name}:  ${e.value ?? (e.valueFrom?.secretKeyRef ? `<set to the key '${e.valueFrom.secretKeyRef.key}' in secret '${e.valueFrom.secretKeyRef.name}'>` : `<set to the key '${e.valueFrom?.configMapKeyRef?.key}' of config map '${e.valueFrom?.configMapKeyRef?.name}'>`)}`), `    Mounts:       ${(c.volumeMounts ?? []).length ? '' : '<none>'}`);
  }
  L.push(`  Volumes:         ${(d.spec.template?.spec?.volumes ?? []).length ? (d.spec.template.spec.volumes as J[]).map((v) => v.name).join(', ') : '<none>'}`, '  Node-Selectors:  <none>', '  Tolerations:     <none>');
  const ready = (s.availableReplicas ?? 0) >= (d.spec.replicas ?? 1);
  L.push('Conditions:', '  Type           Status  Reason', '  ----           ------  ------', `  Available      ${ready ? 'True ' : 'False'}   ${ready ? 'MinimumReplicasAvailable' : 'MinimumReplicasUnavailable'}`, `  Progressing    ${s.failed ? 'False' : 'True '}   ${s.failed ? 'ProgressDeadlineExceeded' : s.complete ? 'NewReplicaSetAvailable' : 'ReplicaSetUpdated'}`);
  const olds = rss.filter((r) => r !== newRs && (r.spec.replicas ?? 0) > 0);
  kv(L, 'OldReplicaSets', olds.length ? olds.map((r) => `${r.metadata.name} (${r.status?.replicas ?? 0}/${r.spec.replicas} replicas created)`).join(', ') : '<none>', 16);
  kv(L, 'NewReplicaSet', newRs ? `${newRs.metadata.name} (${newRs.status?.replicas ?? 0}/${newRs.spec.replicas} replicas created)` : '<none>', 16);
  L.push(...eventsBlock(st, d, now));
  return L.join('\n');
}

function describeService(st: Store, s: KObj, now: number): string {
  const L: string[] = [];
  kv(L, 'Name', s.metadata.name, 25);
  kv(L, 'Namespace', objNs(s), 25);
  L.push(...mapLines(s.metadata.labels, 25, 'Labels:'));
  kv(L, 'Annotations', '<none>', 25);
  kv(L, 'Selector', selectorCol(s.spec.selector), 25);
  kv(L, 'Type', s.spec.type ?? 'ClusterIP', 25);
  kv(L, 'IP Family Policy', 'SingleStack', 25);
  kv(L, 'IP Families', 'IPv4', 25);
  kv(L, 'IP', s.spec.clusterIP, 25);
  kv(L, 'IPs', s.spec.clusterIP, 25);
  const ep = find(st, 'Endpoints', objNs(s), s.metadata.name) as J;
  for (const p of s.spec.ports ?? []) {
    kv(L, 'Port', `${p.name ?? '<unset>'}  ${p.port}/${p.protocol ?? 'TCP'}`, 25);
    kv(L, 'TargetPort', `${p.targetPort ?? p.port}/${p.protocol ?? 'TCP'}`, 25);
    if (s.spec.type === 'NodePort') kv(L, 'NodePort', `${p.name ?? '<unset>'}  ${p.nodePort}/${p.protocol ?? 'TCP'}`, 25);
    kv(L, 'Endpoints', ep ? endpointsCol(ep).replace('<none>', '') : '', 25);
  }
  kv(L, 'Session Affinity', 'None', 25);
  if (s.spec.type === 'NodePort') kv(L, 'External Traffic Policy', 'Cluster', 25);
  kv(L, 'Internal Traffic Policy', 'Cluster', 25);
  L.push(...eventsBlock(st, s, now));
  return L.join('\n');
}

function describeNode(st: Store, n: KObj, now: number): string {
  const L: string[] = [];
  const def = KUBE_NODES.find((x) => x.id === n.metadata.name)!;
  kv(L, 'Name', n.metadata.name, 20);
  kv(L, 'Roles', def.roles, 20);
  L.push(...mapLines(n.metadata.labels, 20, 'Labels:'));
  kv(L, 'CreationTimestamp', rfc1123(n.metadata.creationTimestamp), 20);
  kv(L, 'Taints', (n.spec.taints ?? []).map((t: J) => `${t.key}${t.value ? '=' + t.value : ''}:${t.effect}`).join('\n                    ') || '<none>', 20);
  kv(L, 'Unschedulable', n.spec.unschedulable ? 'true' : 'false', 20);
  const r = n.status?.ready;
  L.push('Conditions:', '  Type             Status  Reason                       Message', '  ----             ------  ------                       -------',
    '  MemoryPressure   False   KubeletHasSufficientMemory   kubelet has sufficient memory available',
    '  DiskPressure     False   KubeletHasNoDiskPressure     kubelet has no disk pressure',
    '  PIDPressure      False   KubeletHasSufficientPID      kubelet has sufficient PID available',
    r ? '  Ready            True    KubeletReady                 kubelet is posting ready status' : '  Ready            Unknown NodeStatusUnknown            Kubelet stopped posting node status.');
  L.push('Addresses:', `  InternalIP:  ${def.ip}`, `  Hostname:    ${n.metadata.name}`);
  L.push('Capacity:', '  cpu:                2', '  memory:             4005716Ki', '  pods:               110', 'Allocatable:', '  cpu:                2', '  memory:             4005716Ki', '  pods:               110');
  L.push('System Info:', '  Kernel Version:             6.1.0-26-amd64', '  OS Image:                   Debian GNU/Linux 12 (bookworm)', '  Operating System:           linux', '  Architecture:               amd64', '  Container Runtime Version:  containerd://1.7.22-k3s1', `  Kubelet Version:            ${K3S_VERSION}`, `  Kube-Proxy Version:         ${K3S_VERSION}`);
  kv(L, 'PodCIDR', def.podCidr, 20);
  kv(L, 'PodCIDRs', def.podCidr, 20);
  const pods = list(st, 'Pod').filter((p) => p.spec.nodeName === n.metadata.name && !['Succeeded', 'Failed'].includes(p.status?.phase));
  L.push(`Non-terminated Pods:          (${pods.length} in total)`, ...table([['Namespace', 'Name', 'CPU Requests', 'Memory Requests', 'Age'], ['---------', '----', '------------', '---------------', '---'], ...pods.map((p) => { const q = podRequests(p.spec); return [objNs(p), p.metadata.name, q.cpu ? `${q.cpu}m (${Math.round(q.cpu / 20)}%)` : '0 (0%)', q.mem ? `${Math.round(q.mem)}Mi (${Math.round(q.mem / 39)}%)` : '0 (0%)', age(now - p.metadata.creationTimestamp)]; })]).split('\n').map((l) => `  ${l}`));
  const used = nodeAllocated(st, n.metadata.name);
  L.push('Allocated resources:', '  (Total limits may be over 100 percent, i.e., overcommitted.)', '  Resource           Requests     Limits', '  --------           --------     ------', `  cpu                ${used.cpu}m (${Math.round(used.cpu / 20)}%)   0 (0%)`, `  memory             ${Math.round(used.mem)}Mi (${Math.round(used.mem / 39)}%)   0 (0%)`);
  L.push(...eventsBlock(st, n, now));
  return L.join('\n');
}

function describeGeneric(st: Store, o: KObj, now: number): string {
  const L: string[] = [];
  kv(L, 'Name', o.metadata.name);
  if (objNs(o)) kv(L, 'Namespace', objNs(o));
  L.push(...mapLines(o.metadata.labels, 16, 'Labels:'));
  kv(L, 'Annotations', '<none>');
  if (o.kind === 'ConfigMap') { L.push('', 'Data', '===='); for (const [k, v] of Object.entries(o.data ?? {})) L.push(`${k}:`, '----', v, ''); L.push('BinaryData', '====', ''); }
  if (o.kind === 'Secret') { L.push('', `Type:  ${o.type ?? 'Opaque'}`, '', 'Data', '===='); for (const [k, v] of Object.entries(o.data ?? {})) L.push(`${k}:  ${b64decode(v).length} bytes`); }
  if (o.kind === 'ReplicaSet') { kv(L, 'Selector', selectorCol(o.spec.selector?.matchLabels)); kv(L, 'Replicas', `${o.status?.replicas ?? 0} current / ${o.spec.replicas} desired`); kv(L, 'Pods Status', `${o.status?.readyReplicas ?? 0} Running / 0 Waiting / 0 Succeeded / 0 Failed`); }
  if (o.kind === 'Namespace') kv(L, 'Status', 'Active');
  L.push(...eventsBlock(st, o, now));
  return L.join('\n');
}

function describeCmd(ctx: CmdCtx, a: Args): CmdResult {
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const targets = resolveTargets(a, 1);
  if (typeof targets === 'string') return err(targets.replace('to get', 'to describe'), 1);
  const out: string[] = [];
  const errs: string[] = [];
  const sel = flagStr(a, '-l', '--selector');
  for (const t of targets) {
    const ns = NAMESPACED.has(t.res.kind) ? c.ns : undefined;
    let objs = list(c.st, t.res.kind, ns).filter((o) => selectorMatch(sel, o.metadata.labels));
    if (t.names.length) {
      // describe accepts a name prefix (describe pod web shows all web-… pods).
      objs = t.names.flatMap((n) => {
        const exact = objs.filter((o) => o.metadata.name === n);
        const pre = exact.length ? exact : objs.filter((o) => o.metadata.name.startsWith(n));
        if (!pre.length) errs.push(notFound(t.res.kind, n));
        return pre;
      });
    }
    for (const o of objs.sort((x, y) => x.metadata.name.localeCompare(y.metadata.name))) {
      out.push(o.kind === 'Pod' ? describePod(c.st, o, ctx.world.clock) : o.kind === 'Deployment' ? describeDeployment(c.st, o, ctx.world.clock) : o.kind === 'Service' ? describeService(c.st, o, ctx.world.clock) : o.kind === 'Node' ? describeNode(c.st, o, ctx.world.clock) : describeGeneric(c.st, o, ctx.world.clock));
    }
  }
  if (!out.length && !errs.length) return ok(`No resources found in ${c.ns} namespace.`);
  return { out: [out.join('\n\n\n'), ...errs].filter(Boolean).join('\n'), code: errs.length ? 1 : 0 };
}

// ---------------------------------------------------------------------------
// Picking a pod (logs, exec): pod name, or deploy/NAME, svc/NAME …
// ---------------------------------------------------------------------------

function pickPod(c: Conn, ref: string | undefined, verb: string): { pod: KObj; note?: string } | CmdResult {
  if (!ref) return err(`error: expected 'logs [-f] [-p] (POD | TYPE/NAME) [-c CONTAINER]'.\nPOD or TYPE/NAME is a required argument for the logs command\nSee 'kubectl logs -h' for help and examples`.replace('logs', verb), 1);
  if (ref.includes('/')) {
    const [r, n] = ref.split('/');
    const res = RESOURCES[r.toLowerCase()];
    if (!res) return err(`error: the server doesn't have a resource type "${r}"`, 1);
    if (res.kind === 'Pod') { const p = find(c.st, 'Pod', c.ns, n); return p ? { pod: p } : err(notFound('Pod', n), 1); }
    const owner = find(c.st, res.kind, c.ns, n);
    if (!owner) return err(notFound(res.kind, n), 1);
    const sel = res.kind === 'Service' ? owner.spec.selector : owner.spec.selector?.matchLabels;
    const pods = list(c.st, 'Pod', c.ns).filter((p) => matchLabels(sel, p.metadata.labels) && !p.metadata.deletionTimestamp).sort((x, y) => Number(isPodReady(y)) - Number(isPodReady(x)) || x.metadata.creationTimestamp - y.metadata.creationTimestamp);
    if (!pods.length) return err(`error: timed out waiting for the condition`, 1);
    return { pod: pods[0], note: pods.length > 1 ? `Found ${pods.length} pods, using pod/${pods[0].metadata.name}` : undefined };
  }
  const p = find(c.st, 'Pod', c.ns, ref);
  return p ? { pod: p } : err(notFound('Pod', ref), 1);
}

function logsCmd(ctx: CmdCtx, a: Args): CmdResult {
  if (flag(a, '-f', '--follow')) return err('[Cyber Owl Lab: -f (follow) is not simulated; run kubectl logs again to see new lines]', 1);
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const pk = pickPod(c, a.pos[1], 'logs');
  if ('code' in pk) return pk;
  const p = pk.pod;
  const ctrName = flagStr(a, '-c', '--container') ?? p.spec.containers?.[0]?.name;
  if (!(p.spec.containers ?? []).some((x: J) => x.name === ctrName)) return err(`error: container ${ctrName} is not valid for pod ${p.metadata.name}`, 1);
  const prev = !!flag(a, '-p', '--previous');
  const cs = p.status?.containerStatuses?.[0];
  if (!prev && cs?.state?.waiting && !(cs.restartCount > 0)) {
    const r = cs.state.waiting.reason;
    const why = r === 'ContainerCreating' ? 'ContainerCreating' : r === 'ErrImagePull' || r === 'ImagePullBackOff' ? 'trying and failing to pull image' : r === 'CreateContainerConfigError' ? 'CreateContainerConfigError' : r;
    return err(`Error from server (BadRequest): container "${ctrName}" in pod "${p.metadata.name}" is waiting to start: ${why}`, 1);
  }
  if (!p.spec.nodeName) return err(`Error from server (BadRequest): container "${ctrName}" in pod "${p.metadata.name}" is waiting to start: ContainerCreating`, 1);
  const lines = podLogs(ctx.world, p, ctrName, prev || (!!cs?.state?.waiting && !prev && false));
  if (lines === null) return err(prev ? `Error from server (BadRequest): previous terminated container "${ctrName}" in pod "${p.metadata.name}" not found` : `Error from server (BadRequest): container "${ctrName}" in pod "${p.metadata.name}" is waiting to start`, 1);
  // A crashing container: kubectl logs shows the last (current) attempt's output.
  let shown = lines;
  if (!prev && cs?.state?.waiting?.reason === 'CrashLoopBackOff') shown = podLogs(ctx.world, p, ctrName, false) ?? [];
  const tail = flagStr(a, '--tail');
  if (tail && Number(tail) >= 0) shown = shown.slice(-Number(tail));
  return ok([pk.note, ...shown].filter((x) => x !== undefined).join('\n'));
}

function execCmd(ctx: CmdCtx, a: Args): CmdResult {
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  if (!a.rest.length) return err('error: you must specify at least one command for the container', 1);
  const pk = pickPod(c, a.pos[1], 'exec');
  if ('code' in pk) return pk;
  const p = pk.pod;
  const host = podCtrHostId(p) ? ctx.world.hosts[podCtrHostId(p)!] : undefined;
  if (!host) {
    const why = p.status?.phase === 'Pending' ? 'pod does not have a host assigned' : `container not found ("${p.spec.containers?.[0]?.name}")`;
    return err(`error: unable to upgrade connection: ${why}`, 1);
  }
  const img = findImage(imageRef(String(p.spec.containers?.[0]?.image)));
  const prog = a.rest[0];
  if (img && !img.tools.includes(prog.split('/').pop()!)) return err(`error: Internal error occurred: error executing command in container: failed to exec in container: failed to start exec "${host.container!.id.slice(0, 64)}": OCI runtime exec failed: exec failed: unable to start container process: exec: "${prog}": executable file not found in $PATH: unknown`, 1);
  if (prog === 'env' || prog === 'printenv') {
    const vars = [`PATH=${(img?.env ?? []).find((e) => e.startsWith('PATH='))?.slice(5) ?? '/usr/bin:/bin'}`, `HOSTNAME=${p.metadata.name}`, ...(host.container?.env ?? []).filter((e) => !e.startsWith('PATH=')), 'KUBERNETES_SERVICE_HOST=10.43.0.1', 'KUBERNETES_SERVICE_PORT=443', 'HOME=/root'];
    return ok(prog === 'printenv' && a.rest[1] ? vars.filter((v) => v.startsWith(a.rest[1] + '=')).map((v) => v.split('=').slice(1).join('=')).join('\n') : vars.join('\n'));
  }
  if ((prog === 'sh' || prog === 'bash') && a.rest[1] === '-c') return ctx.run(a.rest.slice(2).join(' '), `${host.id}:root`);
  if ((prog === 'sh' || prog === 'bash') && a.rest.length === 1) return err('[Cyber Owl Lab: interactive shells in pods are not simulated; run single commands: kubectl exec POD -- cat /etc/resolv.conf]', 1);
  const quote = (s: string) => (/^[\w./:=@%+-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
  return ctx.run(a.rest.map(quote).join(' '), `${host.id}:root`);
}

// ---------------------------------------------------------------------------
// apply / create -f: admission (schema, validation, defaults)
// ---------------------------------------------------------------------------

type Schema = { [k: string]: Schema | 'free' | 'leaf' | [Schema | 'leaf'] };
const META: Schema = { name: 'leaf', namespace: 'leaf', labels: 'free', annotations: 'free', generateName: 'leaf', uid: 'leaf', resourceVersion: 'leaf', creationTimestamp: 'leaf', ownerReferences: 'free', finalizers: 'free', generation: 'leaf', managedFields: 'free' };
const KEYREF: Schema = { name: 'leaf', key: 'leaf', optional: 'leaf' };
const PROBE: Schema = { httpGet: { path: 'leaf', port: 'leaf', host: 'leaf', scheme: 'leaf', httpHeaders: 'free' }, tcpSocket: { port: 'leaf', host: 'leaf' }, exec: { command: ['leaf'] }, grpc: 'free', initialDelaySeconds: 'leaf', periodSeconds: 'leaf', timeoutSeconds: 'leaf', failureThreshold: 'leaf', successThreshold: 'leaf', terminationGracePeriodSeconds: 'leaf' };
const CONTAINER: Schema = {
  name: 'leaf', image: 'leaf', command: ['leaf'], args: ['leaf'], workingDir: 'leaf', imagePullPolicy: 'leaf', stdin: 'leaf', tty: 'leaf', terminationMessagePath: 'leaf', terminationMessagePolicy: 'leaf', securityContext: 'free', lifecycle: 'free',
  ports: [{ name: 'leaf', containerPort: 'leaf', protocol: 'leaf', hostPort: 'leaf', hostIP: 'leaf' }],
  env: [{ name: 'leaf', value: 'leaf', valueFrom: { configMapKeyRef: KEYREF, secretKeyRef: KEYREF, fieldRef: 'free', resourceFieldRef: 'free' } }],
  envFrom: [{ configMapRef: { name: 'leaf', optional: 'leaf' }, secretRef: { name: 'leaf', optional: 'leaf' }, prefix: 'leaf' }],
  resources: { requests: 'free', limits: 'free', claims: 'free' },
  volumeMounts: [{ name: 'leaf', mountPath: 'leaf', readOnly: 'leaf', subPath: 'leaf', subPathExpr: 'leaf', mountPropagation: 'leaf' }],
  livenessProbe: PROBE, readinessProbe: PROBE, startupProbe: PROBE,
};
const POD_SPEC: Schema = {
  containers: [CONTAINER], initContainers: [CONTAINER], restartPolicy: 'leaf', nodeSelector: 'free', nodeName: 'leaf', tolerations: 'free', affinity: 'free', serviceAccountName: 'leaf', serviceAccount: 'leaf', automountServiceAccountToken: 'leaf',
  terminationGracePeriodSeconds: 'leaf', dnsPolicy: 'leaf', dnsConfig: 'free', hostNetwork: 'leaf', securityContext: 'free', imagePullSecrets: 'free', priorityClassName: 'leaf', schedulerName: 'leaf', hostname: 'leaf', subdomain: 'leaf', enableServiceLinks: 'leaf', topologySpreadConstraints: 'free',
  volumes: [{ name: 'leaf', configMap: { name: 'leaf', items: 'free', defaultMode: 'leaf', optional: 'leaf' }, secret: { secretName: 'leaf', items: 'free', defaultMode: 'leaf', optional: 'leaf' }, emptyDir: 'free', persistentVolumeClaim: 'free', hostPath: 'free', projected: 'free', downwardAPI: 'free' }],
};
const TOP: Record<string, Schema> = {
  Deployment: { apiVersion: 'leaf', kind: 'leaf', metadata: META, status: 'free', spec: { replicas: 'leaf', selector: { matchLabels: 'free', matchExpressions: 'free' }, template: { metadata: META, spec: POD_SPEC }, strategy: { type: 'leaf', rollingUpdate: { maxSurge: 'leaf', maxUnavailable: 'leaf' } }, minReadySeconds: 'leaf', revisionHistoryLimit: 'leaf', progressDeadlineSeconds: 'leaf', paused: 'leaf' } },
  Pod: { apiVersion: 'leaf', kind: 'leaf', metadata: META, status: 'free', spec: POD_SPEC },
  Service: { apiVersion: 'leaf', kind: 'leaf', metadata: META, status: 'free', spec: { type: 'leaf', selector: 'free', clusterIP: 'leaf', clusterIPs: 'free', externalTrafficPolicy: 'leaf', internalTrafficPolicy: 'leaf', sessionAffinity: 'leaf', externalName: 'leaf', ipFamilies: 'free', ipFamilyPolicy: 'leaf', externalIPs: 'free', publishNotReadyAddresses: 'leaf', loadBalancerIP: 'leaf', ports: [{ name: 'leaf', port: 'leaf', targetPort: 'leaf', nodePort: 'leaf', protocol: 'leaf', appProtocol: 'leaf' }] } },
  ConfigMap: { apiVersion: 'leaf', kind: 'leaf', metadata: META, data: 'free', binaryData: 'free', immutable: 'leaf' },
  Secret: { apiVersion: 'leaf', kind: 'leaf', metadata: META, data: 'free', stringData: 'free', type: 'leaf', immutable: 'leaf' },
  Namespace: { apiVersion: 'leaf', kind: 'leaf', metadata: META, spec: 'free', status: 'free' },
};

/** Unknown fields, as the API server's strict field validation reports them ("spec.template.spec.containers[0].imagePullPolicyy"). */
function unknownFields(v: Yaml, s: Schema | 'free' | 'leaf' | [Schema | 'leaf'], path: string, out: string[]): void {
  if (s === 'free' || s === 'leaf' || v === null || typeof v === 'string') return;
  if (Array.isArray(s)) { if (Array.isArray(v)) v.forEach((x, i) => unknownFields(x, s[0], `${path}[${i}]`, out)); return; }
  if (Array.isArray(v)) return;
  for (const [k, x] of Object.entries(v)) {
    if (!(k in s)) { out.push(`${path ? path + '.' : ''}${k}`); continue; }
    unknownFields(x, s[k], `${path ? path + '.' : ''}${k}`, out);
  }
}

const NUMERIC = new Set(['replicas', 'containerPort', 'port', 'nodePort', 'hostPort', 'initialDelaySeconds', 'periodSeconds', 'timeoutSeconds', 'failureThreshold', 'successThreshold', 'revisionHistoryLimit', 'progressDeadlineSeconds', 'minReadySeconds', 'terminationGracePeriodSeconds', 'defaultMode']);
const INT_OR_STRING = new Set(['targetPort', 'maxSurge', 'maxUnavailable']);
/** YAML scalars arrive as strings: give numeric fields their numbers (and int-or-string fields numbers when they are digits). */
function normalise(v: J, key = ''): J {
  if (Array.isArray(v)) return v.map((x) => normalise(x, key));
  if (v && typeof v === 'object') {
    const out: J = {};
    for (const [k, x] of Object.entries(v)) out[k] = ['labels', 'annotations', 'data', 'stringData', 'nodeSelector', 'matchLabels', 'selector', 'requests', 'limits'].includes(k) && x && typeof x === 'object' && !Array.isArray(x)
      ? Object.fromEntries(Object.entries(x).map(([a, b]) => [a, b === null ? '' : typeof b === 'object' ? normalise(b, a) : String(b)]))
      : normalise(x, k);
    return out;
  }
  if (typeof v === 'string' && (NUMERIC.has(key) || INT_OR_STRING.has(key) || (key === 'port' && /^\d+$/.test(v))) && /^-?\d+$/.test(v)) return Number(v);
  if (typeof v === 'string' && ['optional', 'readOnly', 'paused', 'immutable', 'hostNetwork', 'stdin', 'tty', 'automountServiceAccountToken', 'enableServiceLinks'].includes(key)) return v === 'true';
  return v;
}

const DNS1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const goMap = (m: Record<string, string> | undefined) => `map[string]string{${Object.entries(m ?? {}).map(([k, v]) => `"${k}":"${v}"`).join(', ')}}`;

function validate(o: J, st: Store, ns: string): string[] {
  const e: string[] = [];
  const name = o.metadata?.name;
  if (!name) e.push('metadata.name: Required value: name or generateName is required');
  else if (!DNS1123.test(name) || name.length > 253) e.push(`metadata.name: Invalid value: "${name}": a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')`);
  const containers = (base: string, spec: J) => {
    if (!spec?.containers?.length) { e.push(`${base}.containers: Required value`); return; }
    spec.containers.forEach((c: J, i: number) => {
      if (!c.name) e.push(`${base}.containers[${i}].name: Required value`);
      else if (!LABEL.test(c.name)) e.push(`${base}.containers[${i}].name: Invalid value: "${c.name}": a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character (e.g. 'my-name',  or '123-abc', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?')`);
      if (!c.image) e.push(`${base}.containers[${i}].image: Required value`);
      (c.ports ?? []).forEach((p: J, k: number) => { if (!(Number(p.containerPort) >= 1 && Number(p.containerPort) <= 65535)) e.push(`${base}.containers[${i}].ports[${k}].containerPort: Invalid value: ${p.containerPort ?? 0}: must be between 1 and 65535, inclusive`); });
      for (const [k, q] of Object.entries({ ...(c.resources?.requests ?? {}), ...(c.resources?.limits ?? {}) })) if (k === 'memory' && !/^\d+(\.\d+)?(Ki|Mi|Gi|Ti|K|M|G|k)?$/.test(String(q))) e.push(`${base}.containers[${i}].resources.requests[memory]: Invalid value: "${q}": quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'`);
    });
    if (spec.restartPolicy && !['Always', 'OnFailure', 'Never'].includes(spec.restartPolicy)) e.push(`${base}.restartPolicy: Unsupported value: "${spec.restartPolicy}": supported values: "Always", "OnFailure", "Never"`);
  };
  if (o.kind === 'Deployment') {
    const sel = o.spec?.selector?.matchLabels;
    const tl = o.spec?.template?.metadata?.labels;
    if (!o.spec?.selector) e.push('spec.selector: Required value');
    if (!o.spec?.selector || (sel && !Object.entries(sel).every(([k, v]) => tl?.[k] === v)) || !sel || !Object.keys(sel).length) e.push(`spec.template.metadata.labels: Invalid value: ${goMap(tl)}: \`selector\` does not match template \`labels\``);
    if (o.spec?.replicas !== undefined && !(Number(o.spec.replicas) >= 0)) e.push(`spec.replicas: Invalid value: ${o.spec.replicas}: must be greater than or equal to 0`);
    containers('spec.template.spec', o.spec?.template?.spec);
    if (o.spec?.template?.spec?.restartPolicy && o.spec.template.spec.restartPolicy !== 'Always') e.push(`spec.template.spec.restartPolicy: Unsupported value: "${o.spec.template.spec.restartPolicy}": supported values: "Always"`);
  }
  if (o.kind === 'Pod') containers('spec', o.spec);
  if (o.kind === 'Service') {
    const type = o.spec?.type ?? 'ClusterIP';
    if (!['ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName'].includes(type)) e.push(`spec.type: Unsupported value: "${type}": supported values: "ClusterIP", "ExternalName", "LoadBalancer", "NodePort"`);
    if (!o.spec?.ports?.length) e.push('spec.ports: Required value');
    (o.spec?.ports ?? []).forEach((p: J, i: number) => {
      if (!(Number(p.port) >= 1 && Number(p.port) <= 65535)) e.push(`spec.ports[${i}].port: ${p.port === undefined ? 'Required value' : `Invalid value: ${p.port}: must be between 1 and 65535, inclusive`}`);
      if (p.nodePort !== undefined && !(Number(p.nodePort) >= 30000 && Number(p.nodePort) <= 32767)) e.push(`spec.ports[${i}].nodePort: Invalid value: ${p.nodePort}: provided port is not in the valid range. The range of valid ports is 30000-32767`);
      if (p.nodePort !== undefined && type === 'ClusterIP') e.push(`spec.ports[${i}].nodePort: Forbidden: may not be used when \`type\` is 'ClusterIP'`);
      const clash = list(st, 'Service').find((s) => !(s.metadata.name === o.metadata?.name && objNs(s) === ns) && (s.spec.ports ?? []).some((q: J) => p.nodePort && Number(q.nodePort) === Number(p.nodePort)));
      if (clash) e.push(`spec.ports[${i}].nodePort: Invalid value: ${p.nodePort}: provided port is already allocated`);
      if ((o.spec?.ports ?? []).length > 1 && !p.name) e.push(`spec.ports[${i}].name: Required value`);
    });
  }
  if (o.kind === 'ConfigMap' || o.kind === 'Secret') {
    for (const k of Object.keys(o.data ?? {})) if (!/^[-._a-zA-Z0-9]+$/.test(k)) e.push(`data[${k}]: Invalid value: "${k}": a valid config key must consist of alphanumeric characters, '-', '_' or '.' (e.g. 'key.name',  or 'KEY_NAME',  or 'key-name', regex used for validation is '[-._a-zA-Z0-9]+')`);
    if (o.kind === 'Secret') for (const [k, v] of Object.entries(o.data ?? {})) if (!/^[A-Za-z0-9+/]*={0,2}$/.test(String(v))) e.push(`data[${k}]: Invalid value: illegal base64 data at input byte 0`);
  }
  return e;
}

interface Applied { line: string; code: number }

/** Create or update one object (apply / create -f / replace). */
function admit(c: Conn, raw: J, file: string, verb: 'apply' | 'create', nsFlag: string | undefined, dryRun: boolean): Applied {
  const kind = raw?.kind;
  const apiVersion = raw?.apiVersion;
  const where = `"${file}"`;
  if (!kind || !apiVersion) {
    const missing = !apiVersion && !kind ? 'apiVersion not set, kind not set' : !apiVersion ? 'apiVersion not set' : 'kind not set';
    return { line: `error: error validating ${where}: error validating data: [${missing.split(', ').map((m) => m).join(', ')}]; if you choose to ignore these errors, turn validation off with --validate=false`, code: 1 };
  }
  if (!TOP[kind] || API_VERSION[kind] !== apiVersion) {
    return { line: `error: resource mapping not found for name: "${raw.metadata?.name ?? ''}" namespace: "${raw.metadata?.namespace ?? ''}" from ${where}: no matches for kind "${kind}" in version "${apiVersion}"\nensure CRDs are installed first`, code: 1 };
  }
  const unknown: string[] = [];
  unknownFields(raw, TOP[kind], '', unknown);
  const o: J = normalise(raw);
  const namespaced = NAMESPACED.has(kind);
  const ns = namespaced ? (o.metadata?.namespace ?? nsFlag ?? c.ns) : undefined;
  if (namespaced && nsFlag && o.metadata?.namespace && o.metadata.namespace !== nsFlag) return { line: `error: the namespace from the provided object "${o.metadata.namespace}" does not match the namespace "${nsFlag}". You must pass '--namespace=${o.metadata.namespace}' to perform this operation.`, code: 1 };
  const existing = find(c.st, kind, ns ?? '', o.metadata?.name);
  const action = existing ? 'updating' : 'creating';
  if (unknown.length) return { line: `Error from server (BadRequest): error when ${action} ${where}: ${kind} in version "v1" cannot be handled as a ${kind}: strict decoding error: ${unknown.map((u) => `unknown field "${u}"`).join(', ')}`, code: 1 };
  if (namespaced && !find(c.st, 'Namespace', '', ns!)) return { line: `Error from server (NotFound): error when ${action} ${where}: namespaces "${ns}" not found`, code: 1 };
  const errs = validate(o, c.st, ns ?? '');
  if (errs.length) return { line: `The ${kind} "${o.metadata?.name ?? ''}" is invalid: ${errs.length === 1 ? errs[0] : '\n' + errs.map((x) => `* ${x}`).join('\n')}`, code: 1 };
  const label = refName({ kind, metadata: { name: o.metadata.name } });
  if (existing && verb === 'create') return { line: `Error from server (AlreadyExists): error when creating ${where}: ${groupRes(kind)} "${o.metadata.name}" already exists`, code: 1 };
  // Secrets: stringData is merged into data (base64).
  if (kind === 'Secret') { o.data = { ...(o.data ?? {}), ...Object.fromEntries(Object.entries(o.stringData ?? {}).map(([k, v]) => [k, b64encode(String(v))])) }; delete o.stringData; o.type ??= 'Opaque'; }
  if (existing) {
    if (kind === 'Deployment' && JSON.stringify(existing.spec.selector) !== JSON.stringify(o.spec.selector)) return { line: `The Deployment "${o.metadata.name}" is invalid: spec.selector: Invalid value: v1.LabelSelector{MatchLabels:${goMap(o.spec.selector?.matchLabels)}, MatchExpressions:[]v1.LabelSelectorRequirement(nil)}: field is immutable`, code: 1 };
    if (kind === 'Pod') {
      const strip = (s: J) => JSON.stringify({ ...s, nodeName: undefined, containers: (s.containers ?? []).map((x: J) => ({ ...x, image: undefined })) });
      if (strip(existing.spec) !== strip({ ...o.spec, nodeName: existing.spec.nodeName })) return { line: `The Pod "${o.metadata.name}" is invalid: spec: Forbidden: pod updates may not change fields other than \`spec.containers[*].image\`,\`spec.initContainers[*].image\`,\`spec.activeDeadlineSeconds\`,\`spec.tolerations\` (only additions to existing tolerations),\`spec.terminationGracePeriodSeconds\` (allow it to be set to 1 if it was previously negative)`, code: 1 };
    }
    if (kind === 'Service' && o.spec.clusterIP && o.spec.clusterIP !== existing.spec.clusterIP) return { line: `The Service "${o.metadata.name}" is invalid: spec.clusterIPs[0]: Invalid value: []string{"${o.spec.clusterIP}"}: may not change once set`, code: 1 };
    const before = JSON.stringify([existing.spec, existing.data, existing.metadata.labels]);
    const next: J = { ...existing };
    if (kind === 'Service') {
      const ports = (o.spec.ports ?? []).map((p: J, i: number) => ({ protocol: 'TCP', targetPort: p.port, ...p, ...(o.spec.type === 'NodePort' ? { nodePort: p.nodePort ?? existing.spec.ports?.[i]?.nodePort ?? allocateNodePort(c.st, `${o.metadata.name}${i}`) } : {}) }));
      next.spec = { ...defaults('Service', o.spec), clusterIP: existing.spec.clusterIP, ports };
      if (next.spec.type !== 'NodePort') for (const p of next.spec.ports) delete p.nodePort;
    } else if (o.spec) next.spec = kind === 'Pod' ? { ...existing.spec, containers: existing.spec.containers.map((x: J, i: number) => ({ ...x, image: o.spec.containers?.[i]?.image ?? x.image })) } : defaults(kind, o.spec);
    if (o.data) next.data = o.data;
    next.metadata = { ...existing.metadata, labels: o.metadata.labels ?? existing.metadata.labels, annotations: o.metadata.annotations ?? existing.metadata.annotations };
    const after = JSON.stringify([next.spec, next.data, next.metadata.labels]);
    if (before === after) return { line: `${label} unchanged`, code: 0 };
    if (!dryRun) {
      Object.assign(existing, next);
      if (kind === 'Deployment' && JSON.stringify(existing.spec) !== before) existing.metadata.generation = (existing.metadata.generation ?? 1) + 1;
      existing.metadata.resourceVersion = String(++c.st.rv);
      if (kind === 'Pod') { /* image change: the kubelet restarts the container */ const p = existing; if (p.status?._sim) { p.status._sim.nextStart = undefined; } }
    }
    return { line: `${label} configured${dryRun ? ' (dry run)' : ''}`, code: 0 };
  }
  if (dryRun) return { line: `${label} created (dry run)`, code: 0 };
  const obj: KObj = { apiVersion, kind, metadata: { name: o.metadata.name, namespace: ns, uid: '', creationTimestamp: 0, labels: o.metadata.labels, annotations: o.metadata.annotations, generation: kind === 'Deployment' ? 1 : undefined } };
  if (o.spec) obj.spec = defaults(kind, o.spec);
  if (o.data) obj.data = o.data;
  if (kind === 'Secret') obj.type = o.type;
  if (kind === 'ConfigMap' || kind === 'Secret') obj.data ??= {};
  if (kind === 'Namespace') obj.status = { phase: 'Active' };
  else obj.status = kind === 'Pod' ? { phase: 'Pending' } : {};
  if (kind === 'Namespace') obj.metadata.labels = { ...(obj.metadata.labels ?? {}), 'kubernetes.io/metadata.name': obj.metadata.name };
  if (kind === 'Service') {
    obj.spec.clusterIP = o.spec.clusterIP ?? allocateClusterIp(c.st, `${ns}/${o.metadata.name}/${c.world.counter}`);
    obj.spec.ports = (o.spec.ports ?? []).map((p: J, i: number) => ({ protocol: 'TCP', targetPort: p.port, ...p, ...(obj.spec.type === 'NodePort' ? { nodePort: p.nodePort ?? allocateNodePort(c.st, `${o.metadata.name}${i}${c.world.counter}`) } : {}) }));
  }
  addObject(c.world, c.st, obj);
  return { line: `${label} created`, code: 0 };
}

function defaults(kind: string, spec: J): J {
  const s = JSON.parse(JSON.stringify(spec));
  const podDefaults = (p: J) => {
    p.restartPolicy ??= 'Always';
    p.dnsPolicy ??= 'ClusterFirst';
    p.terminationGracePeriodSeconds ??= 30;
    for (const c of p.containers ?? []) {
      c.imagePullPolicy ??= /:latest$|^[^:]+$/.test(String(c.image)) ? 'Always' : 'IfNotPresent';
      for (const port of c.ports ?? []) port.protocol ??= 'TCP';
      for (const pr of [c.livenessProbe, c.readinessProbe]) if (pr) { pr.periodSeconds ??= 10; pr.timeoutSeconds ??= 1; pr.failureThreshold ??= 3; pr.successThreshold ??= 1; if (pr.httpGet) pr.httpGet.scheme ??= 'HTTP'; }
    }
  };
  if (kind === 'Deployment') {
    s.replicas ??= 1;
    s.revisionHistoryLimit ??= 10;
    s.progressDeadlineSeconds ??= 600;
    s.strategy ??= { type: 'RollingUpdate', rollingUpdate: { maxSurge: '25%', maxUnavailable: '25%' } };
    if (s.strategy.type === 'RollingUpdate') s.strategy.rollingUpdate ??= { maxSurge: '25%', maxUnavailable: '25%' };
    podDefaults(s.template.spec);
  }
  if (kind === 'Pod') podDefaults(s);
  if (kind === 'Service') { s.type ??= 'ClusterIP'; s.sessionAffinity ??= 'None'; }
  return s;
}

function readManifests(ctx: CmdCtx, file: string): { docs: J[]; name: string } | CmdResult {
  const path = (file.startsWith('/') ? file : `${ctx.frame.cwd.replace(/\/$/, '')}/${file}`).replace(/\/\.?\/?$/, '').replace(/\/\.\//g, '/') || '/';
  const node = ctx.host.fs[path];
  if (!node) return err(`error: the path "${file}" does not exist`, 1);
  if (node.type === 'dir') {
    const files = Object.keys(ctx.host.fs).filter((p) => p.startsWith(path + '/') && /\.(ya?ml|json)$/.test(p) && !p.slice(path.length + 1).includes('/')).sort();
    const docs: J[] = [];
    for (const f of files) { const r = readManifests(ctx, f); if ('code' in r) return r; docs.push(...r.docs.map((d) => ({ ...d, __file: f.slice(f.lastIndexOf('/') + 1) }))); }
    return { docs, name: file };
  }
  if (!canAccess(node, ctx.user, 'r')) return err(`error: open ${file}: permission denied`, 1);
  const docs: J[] = [];
  const parts = node.content.split(/^---\s*$/m);
  let line = 1;
  for (const part of parts) {
    if (part.trim() && !/^\s*(#.*)?$/s.test(part.replace(/^#.*$/gm, '').trim() ? 'x' : '')) {
      try {
        const y = path.endsWith('.json') ? JSON.parse(part) : parseYaml(part);
        if (y && typeof y === 'object') {
          if ((y as J).kind === 'List' && Array.isArray((y as J).items)) docs.push(...(y as J).items);
          else docs.push(y);
        }
      } catch (e) {
        const msg = e instanceof YamlError ? e.message.replace(/line (\d+)/, (_m, n: string) => `line ${Number(n) + line - 1}`) : (e as Error).message;
        return err(`error: error parsing ${file}: error converting YAML to JSON: ${msg}`, 1);
      }
    }
    line += part.split('\n').length;
  }
  return { docs, name: file };
}

function applyCmd(ctx: CmdCtx, a: Args, verb: 'apply' | 'create'): CmdResult {
  const file = flagStr(a, '-f', '--filename');
  if (!file) return err(verb === 'apply' ? 'error: must specify one of -f and -k' : 'error: must specify one of -f and -k', 1);
  const nsFlag = flagStr(a, '-n', '--namespace');
  const c = connect(ctx, nsFlag);
  if (!isConn(c)) return c;
  const m = readManifests(ctx, file);
  if ('code' in m) return m;
  if (!m.docs.length) return err('error: no objects passed to ' + verb, 1);
  const dry = flagStr(a, '--dry-run');
  const lines: string[] = [];
  let code = 0;
  for (const d0 of m.docs) {
    const { __file: file0, ...d } = d0;
    const r = admit(c, d, file0 ?? m.name, verb, nsFlag, !!dry && dry !== 'none');
    lines.push(r.line);
    code = Math.max(code, r.code);
  }
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return { out: lines.join('\n'), code };
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

function cascade(world: World, st: Store, o: KObj): void {
  for (const child of st.objects.filter((x) => x.metadata.ownerReferences?.some((r) => r.uid === o.metadata.uid))) cascade(world, st, child);
  if (o.kind === 'Pod') deletePod(world, st, o);
  else removeObject(st, o);
  if (o.kind === 'Namespace') for (const x of st.objects.filter((y) => objNs(y) === o.metadata.name)) cascade(world, st, x);
  if (o.kind === 'Service') { const ep = find(st, 'Endpoints', objNs(o), o.metadata.name); if (ep) removeObject(st, ep); }
}

function deleteCmd(ctx: CmdCtx, a: Args): CmdResult {
  const nsFlag = flagStr(a, '-n', '--namespace');
  const c = connect(ctx, nsFlag);
  if (!isConn(c)) return c;
  const out: string[] = [];
  let code = 0;
  const file = flagStr(a, '-f', '--filename');
  if (file) {
    const m = readManifests(ctx, file);
    if ('code' in m) return m;
    for (const d of m.docs) {
      const kind = d.kind;
      const ns = NAMESPACED.has(kind) ? (d.metadata?.namespace ?? c.ns) : '';
      const o = find(c.st, kind, ns, d.metadata?.name);
      if (!o) { out.push(`Error from server (NotFound): error when deleting "${file}": ${groupRes(kind)} "${d.metadata?.name}" not found`); code = 1; continue; }
      cascade(ctx.world, c.st, o);
      out.push(`${refName(o)} deleted`);
    }
  } else {
    const targets = resolveTargets(a, 1);
    if (typeof targets === 'string') return err(targets.replace('to get', 'to delete'), 1);
    const sel = flagStr(a, '-l', '--selector');
    const all = !!flag(a, '--all');
    for (const t of targets) {
      const ns = NAMESPACED.has(t.res.kind) ? c.ns : undefined;
      let objs: KObj[];
      if (t.names.length) objs = t.names.map((n) => { const o = find(c.st, t.res.kind, ns ?? '', n); if (!o && !flag(a, '--ignore-not-found')) { out.push(notFound(t.res.kind, n)); code = 1; } return o; }).filter((x): x is KObj => !!x);
      else if (sel || all) objs = list(c.st, t.res.kind, ns).filter((o) => selectorMatch(sel, o.metadata.labels));
      else return err('error: resource(s) were provided, but no name was specified', 1);
      if (!objs.length && !t.names.length) out.push(`No resources found`);
      for (const o of objs) {
        if (o.kind === 'Namespace' && ['default', 'kube-system', 'kube-public', 'kube-node-lease'].includes(o.metadata.name)) { out.push(`Error from server (Forbidden): namespaces "${o.metadata.name}" is forbidden: this namespace may not be deleted`); code = 1; continue; }
        if (o.kind === 'Node') { removeObject(c.st, o); out.push(`node "${o.metadata.name}" deleted`); continue; }
        cascade(ctx.world, c.st, o);
        out.push(`${o.kind.toLowerCase()}${resOf(o.kind).group ? '.' + resOf(o.kind).group : ''} "${o.metadata.name}" deleted`);
      }
    }
  }
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return { out: out.join('\n'), code };
}

// ---------------------------------------------------------------------------
// Imperative commands: create, expose, scale, set image, rollout, label, cordon, drain
// ---------------------------------------------------------------------------

function deployFromArg(c: Conn, ref: string | undefined, next?: string): KObj | CmdResult {
  if (!ref) return err('error: required resource not specified', 1);
  if (!ref.includes('/') && RESOURCES[ref.toLowerCase()] && next) ref = `${ref}/${next}`;
  const [r, n] = ref.includes('/') ? ref.split('/') : ['deployment', ref];
  const res = RESOURCES[r.toLowerCase()];
  if (!res || res.kind !== 'Deployment') return err(`error: no objects passed to the command (only deployments are supported here: deployment/NAME)`, 1);
  return find(c.st, 'Deployment', c.ns, n) ?? err(notFound('Deployment', n), 1);
}

function createCmd(ctx: CmdCtx, a: Args): CmdResult {
  if (flagStr(a, '-f', '--filename')) return applyCmd(ctx, a, 'create');
  const what = a.pos[1];
  const name = a.pos[2];
  const nsFlag = flagStr(a, '-n', '--namespace');
  const fmt = flagStr(a, '-o', '--output');
  const dry = flagStr(a, '--dry-run');
  const isDry = !!dry && dry !== 'none';
  let o: J;
  const literals = (flagStr(a, '--from-literal') ?? '').split('\u0000').filter(Boolean);
  const kv0 = (s: string) => { const i = s.indexOf('='); return [s.slice(0, i), s.slice(i + 1)]; };
  switch (what) {
    case 'deployment': case 'deploy': {
      const image = flagStr(a, '--image');
      if (!name) return err('error: exactly one NAME is required, got 0', 1);
      if (!image) return err('error: required flag(s) "image" not set', 1);
      const port = flagStr(a, '--port');
      o = { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { labels: { app: name }, name }, spec: { replicas: Number(flagStr(a, '--replicas') ?? 1), selector: { matchLabels: { app: name } }, strategy: {}, template: { metadata: { labels: { app: name } }, spec: { containers: [{ image, name: image.split('/').pop()!.split(':')[0], resources: {}, ...(port ? { ports: [{ containerPort: Number(port) }] } : {}) }] } } } };
      break;
    }
    case 'namespace': case 'ns':
      if (!name) return err('error: exactly one NAME is required, got 0', 1);
      o = { apiVersion: 'v1', kind: 'Namespace', metadata: { name } };
      break;
    case 'configmap': case 'cm':
      if (!name) return err('error: exactly one NAME is required, got 0', 1);
      o = { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name }, data: Object.fromEntries(literals.map(kv0)) };
      for (const f of (flagStr(a, '--from-file') ?? '').split('\u0000').filter(Boolean)) {
        const [k, p] = f.includes('=') ? kv0(f) : [f.split('/').pop()!, f];
        const node = ctx.host.fs[p.startsWith('/') ? p : `${ctx.frame.cwd}/${p}`];
        if (!node) return err(`error: error reading ${p}: no such file or directory`, 1);
        o.data[k] = node.content;
      }
      break;
    case 'secret': {
      if (name !== 'generic') return err(`error: Unexpected args: [${name ?? ''}] — create secret generic NAME --from-literal=KEY=VALUE (docker-registry and tls are not simulated)`, 1);
      const n2 = a.pos[3];
      if (!n2) return err('error: exactly one NAME is required, got 0', 1);
      o = { apiVersion: 'v1', kind: 'Secret', metadata: { name: n2 }, type: 'Opaque', data: Object.fromEntries(literals.map(kv0).map(([k, v]) => [k, b64encode(v)])) };
      break;
    }
    default:
      return err(`error: Unexpected args: [${what ?? ''}]\nAvailable: deployment, namespace, configmap, secret generic (and create -f FILE)`, 1);
  }
  if (isDry && fmt) return ok(fmt === 'json' ? JSON.stringify(o, null, 2) : toYaml({ ...o, metadata: { ...o.metadata, creationTimestamp: null }, ...(o.kind === 'Deployment' ? { status: {} } : {}) }).trimEnd());
  const c = connect(ctx, nsFlag);
  if (!isConn(c)) return c;
  const r = admit(c, o, '', 'create', nsFlag, isDry);
  if (r.code) return err(r.line.replace(/error when creating "": /, ''), r.code);
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return ok(r.line);
}

function exposeCmd(ctx: CmdCtx, a: Args): CmdResult {
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const ref = a.pos[1];
  const [r, n] = (ref ?? '').includes('/') ? ref.split('/') : [ref ?? '', a.pos[2] ?? ''];
  const res = RESOURCES[r.toLowerCase()];
  if (!res || !['Deployment', 'Pod', 'Service', 'ReplicaSet'].includes(res.kind)) return err(`error: cannot expose a ${r}`, 1);
  const src = find(c.st, res.kind, c.ns, n);
  if (!src) return err(notFound(res.kind, n), 1);
  const sel = res.kind === 'Pod' ? src.metadata.labels : res.kind === 'Service' ? src.spec.selector : src.spec.selector?.matchLabels;
  const port = flagStr(a, '--port') ?? String(src.spec.template?.spec?.containers?.[0]?.ports?.[0]?.containerPort ?? src.spec.containers?.[0]?.ports?.[0]?.containerPort ?? '');
  if (!port) return err(`error: couldn't find port via --port flag or introspection\nSee 'kubectl expose -h' for help and examples`, 1);
  const tp = flagStr(a, '--target-port');
  const type = flagStr(a, '--type') ?? 'ClusterIP';
  const o: J = { apiVersion: 'v1', kind: 'Service', metadata: { name: flagStr(a, '--name') ?? n, labels: src.metadata.labels }, spec: { type, selector: sel, ports: [{ port: Number(port), targetPort: tp ? (/^\d+$/.test(tp) ? Number(tp) : tp) : Number(port), protocol: flagStr(a, '--protocol') ?? 'TCP' }] } };
  const dry = flagStr(a, '--dry-run');
  if (dry && dry !== 'none') return ok(toYaml({ ...o, metadata: { ...o.metadata, creationTimestamp: null }, status: { loadBalancer: {} } }).trimEnd());
  const res2 = admit(c, o, '', 'create', undefined, false);
  if (res2.code) return err(res2.line.replace(/error when creating "": /, ''), 1);
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return ok(`service/${o.metadata.name} exposed`);
}

function scaleCmd(ctx: CmdCtx, a: Args): CmdResult {
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const n = flagStr(a, '--replicas');
  if (n === undefined) return err('error: required flag(s) "replicas" not set', 1);
  if (!/^\d+$/.test(n)) return err(`error: invalid argument "${n}" for "--replicas" flag: strconv.ParseInt: parsing "${n}": invalid syntax`, 1);
  const d = deployFromArg(c, a.pos[1], a.pos[2]);
  if ('code' in d) return d;
  d.spec.replicas = Number(n);
  d.metadata.generation = (d.metadata.generation ?? 1) + 1;
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return ok(`deployment.apps/${d.metadata.name} scaled`);
}

function setCmd(ctx: CmdCtx, a: Args): CmdResult {
  if (a.pos[1] !== 'image') return err(`error: unknown command "${a.pos[1] ?? ''}" for "kubectl set" (set image is simulated)`, 1);
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const typed = !a.pos[2]?.includes('/') && !!RESOURCES[(a.pos[2] ?? '').toLowerCase()];
  const d = deployFromArg(c, a.pos[2], a.pos[3]);
  if ('code' in d) return d;
  const pairs = a.pos.slice(typed ? 4 : 3);
  if (!pairs.length) return err('error: at least one image update is required', 1);
  for (const p of pairs) {
    const [ctr, img] = p.split('=');
    const cs = (d.spec.template.spec.containers ?? []) as J[];
    const target = ctr === '*' ? cs : cs.filter((x) => x.name === ctr);
    if (!target.length) return err(`error: unable to find container named "${ctr}"`, 1);
    for (const x of target) x.image = img;
  }
  d.metadata.generation = (d.metadata.generation ?? 1) + 1;
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return ok(`deployment.apps/${d.metadata.name} image updated`);
}

function rolloutCmd(ctx: CmdCtx, a: Args): CmdResult {
  const sub = a.pos[1];
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const d = deployFromArg(c, a.pos[2], a.pos[3]);
  if ('code' in d) return d;
  const name = d.metadata.name;
  const rss = () => list(c.st, 'ReplicaSet', c.ns).filter((r) => r.metadata.ownerReferences?.some((o) => o.uid === d.metadata.uid)).sort((x, y) => Number(x.metadata.annotations?.['deployment.kubernetes.io/revision']) - Number(y.metadata.annotations?.['deployment.kubernetes.io/revision']));
  switch (sub) {
    case 'status': {
      const out: string[] = [];
      const timeout = flagStr(a, '--timeout');
      const limit = timeout ? Number(timeout.replace(/s$/, '')) * (timeout.endsWith('m') ? 60_000 : 1000) : Infinity;
      const start = ctx.world.clock;
      let last = '';
      for (;;) {
        const st = loadStore(ctx.world);
        const cur = find(st, 'Deployment', c.ns, name);
        if (!cur) return err(notFound('Deployment', name), 1);
        const s = cur.status ?? {};
        const want = cur.spec.replicas ?? 1;
        if (s.failed) { out.push(`error: deployment "${name}" exceeded its progress deadline`); return { out: out.join('\n'), code: 1 }; }
        if (s.complete && (s.availableReplicas ?? 0) >= want) { out.push(`deployment "${name}" successfully rolled out`); return ok(out.join('\n')); }
        const msg = (s.updatedReplicas ?? 0) < want ? `Waiting for deployment "${name}" rollout to finish: ${s.updatedReplicas ?? 0} out of ${want} new replicas have been updated...`
          : (s.replicas ?? 0) > (s.updatedReplicas ?? 0) ? `Waiting for deployment "${name}" rollout to finish: ${(s.replicas ?? 0) - (s.updatedReplicas ?? 0)} old replicas are pending termination...`
          : `Waiting for deployment "${name}" rollout to finish: ${s.updatedReady ?? 0} of ${want} updated replicas are available...`;
        if (msg !== last) { out.push(msg); last = msg; }
        if (ctx.world.clock - start >= limit) { out.push('error: timed out waiting for the condition'); return { out: out.join('\n'), code: 1 }; }
        kubeWait(ctx.world, 5000);
        if (ctx.world.clock - start > 15 * 60_000) return { out: out.join('\n'), code: 1 };
      }
    }
    case 'history': {
      const rev = flagStr(a, '--revision');
      if (rev) {
        const r = rss().find((x) => x.metadata.annotations?.['deployment.kubernetes.io/revision'] === rev);
        if (!r) return err(`error: unable to find the specified revision`, 1);
        return ok(`deployment.apps/${name} with revision #${rev}\nPod Template:\n  Labels:\t${Object.entries(r.spec.template.metadata?.labels ?? {}).map(([k, v]) => `${k}=${v}`).join('\n\t')}\n  Containers:\n${(r.spec.template.spec.containers ?? []).map((x: J) => `   ${x.name}:\n    Image:\t${x.image}`).join('\n')}`);
      }
      return ok(`deployment.apps/${name} \n${table([['REVISION', 'CHANGE-CAUSE'], ...rss().map((r) => [r.metadata.annotations?.['deployment.kubernetes.io/revision'] ?? '1', r.metadata.annotations?.['kubernetes.io/change-cause'] ?? '<none>'])])}`);
    }
    case 'undo': {
      const all = rss();
      const curRev = Math.max(...all.map((r) => Number(r.metadata.annotations?.['deployment.kubernetes.io/revision'])));
      const to = flagStr(a, '--to-revision');
      const target = to ? all.find((r) => r.metadata.annotations?.['deployment.kubernetes.io/revision'] === to) : all.filter((r) => Number(r.metadata.annotations?.['deployment.kubernetes.io/revision']) < curRev).pop();
      if (!target) return err(to ? `error: unable to find specified revision ${to} in history` : `error: no rollout history found for deployment "${name}"`, 1);
      const tpl = JSON.parse(JSON.stringify(target.spec.template));
      delete tpl.metadata.labels['pod-template-hash'];
      d.spec.template = tpl;
      d.metadata.generation = (d.metadata.generation ?? 1) + 1;
      saveStore(ctx.world, c.st);
      kubeTick(ctx.world);
      return ok(`deployment.apps/${name} rolled back`);
    }
    case 'restart': {
      d.spec.template.metadata = { ...(d.spec.template.metadata ?? {}), annotations: { ...(d.spec.template.metadata?.annotations ?? {}), 'kubectl.kubernetes.io/restartedAt': iso(ctx.world.clock).replace('Z', '+00:00') } };
      d.metadata.generation = (d.metadata.generation ?? 1) + 1;
      saveStore(ctx.world, c.st);
      kubeTick(ctx.world);
      return ok(`deployment.apps/${name} restarted`);
    }
    default:
      return err(`error: unknown command "${sub ?? ''}" for "kubectl rollout"\nAvailable: status, history, undo, restart`, 1);
  }
}

function labelCmd(ctx: CmdCtx, a: Args): CmdResult {
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const ref = a.pos[1] ?? '';
  let res = RESOURCES[ref.split('/')[0].toLowerCase()];
  let name = ref.includes('/') ? ref.split('/')[1] : a.pos[2];
  const changes = a.pos.slice(ref.includes('/') ? 2 : 3);
  if (!res) return err(`error: the server doesn't have a resource type "${ref}"`, 1);
  const o = find(c.st, res.kind, NAMESPACED.has(res.kind) ? c.ns : '', name);
  if (!o) return err(notFound(res.kind, name), 1);
  const labels = { ...(o.metadata.labels ?? {}) };
  for (const ch of changes) {
    if (ch.endsWith('-')) { delete labels[ch.slice(0, -1)]; continue; }
    const [k, v] = ch.split('=');
    if (labels[k] !== undefined && labels[k] !== v && !flag(a, '--overwrite')) return err(`error: '${k}' already has a value (${labels[k]}), and --overwrite is false`, 1);
    labels[k] = v;
  }
  o.metadata.labels = labels;
  void res; res = resOf(o.kind); name = o.metadata.name;
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return ok(`${shortRef(o)} ${changes.every((x) => x.endsWith('-')) ? 'unlabeled' : 'labeled'}`);
}

function cordonCmd(ctx: CmdCtx, a: Args, on: boolean, drain = false): CmdResult {
  const c = connect(ctx);
  if (!isConn(c)) return c;
  const name = a.pos[1];
  const n = find(c.st, 'Node', '', name);
  if (!n) return err(`Error from server (NotFound): nodes "${name}" not found`, 1);
  const out: string[] = [];
  const was = !!n.spec.unschedulable;
  n.spec.unschedulable = on || undefined;
  if (was !== on) event(ctx.world, c.st, n, 'Normal', on ? 'NodeNotSchedulable' : 'NodeSchedulable', `Node ${name} status is now: ${on ? 'NodeNotSchedulable' : 'NodeSchedulable'}`, 'kubelet');
  out.push(`node/${name} ${on ? (was ? 'already cordoned' : 'cordoned') : (was ? 'uncordoned' : 'already uncordoned')}`);
  if (drain) {
    const pods = list(c.st, 'Pod').filter((p) => p.spec.nodeName === name);
    const bare = pods.filter((p) => !p.metadata.ownerReferences?.length);
    if (bare.length && !flag(a, '--force')) {
      return err(`${out.join('\n')}\nerror: unable to drain node "${name}" due to error: cannot delete Pods declare no controller (use --force to override): ${bare.map((p) => `${objNs(p)}/${p.metadata.name}`).join(', ')}, continuing command...\nThere are pending nodes to be drained:\n ${name}\ncannot delete Pods declare no controller (use --force to override): ${bare.map((p) => `${objNs(p)}/${p.metadata.name}`).join(', ')}`, 1);
    }
    for (const p of pods) out.push(`evicting pod ${objNs(p)}/${p.metadata.name}`);
    for (const p of pods) { deletePod(ctx.world, c.st, p); event(ctx.world, c.st, p, 'Normal', 'Killing', `Stopping container ${p.spec.containers?.[0]?.name}`, 'kubelet'); out.push(`pod/${p.metadata.name} evicted`); }
    out.push(`node/${name} drained`);
  }
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return ok(out.join('\n'));
}

function configCmd(ctx: CmdCtx, a: Args): CmdResult {
  const sub = a.pos[1];
  const path = ctx.env.KUBECONFIG || (ctx.host.fs[`${ctx.user.home}/.kube/config`] ? `${ctx.user.home}/.kube/config` : KUBECONFIG_PATH);
  const cfg = readKubeconfig(ctx, path);
  if ('code' in cfg) return cfg;
  if (sub === 'current-context') return ok('default');
  if (sub === 'get-contexts') return ok(table([['CURRENT', 'NAME', 'CLUSTER', 'AUTHINFO', 'NAMESPACE'], ['*', 'default', 'default', path.includes('k3s') ? 'default' : 'alice', cfg.namespace ?? '']]));
  if (sub === 'view') return ok(ctx.host.fs[path].content.replace(/(certificate-authority-data|client-certificate-data|client-key-data): .*/g, (_m, k: string) => `${k}: DATA+OMITTED`).replace('client-key-data: DATA+OMITTED', 'client-key-data: DATA+OMITTED').trimEnd());
  if (sub === 'set-context' && flag(a, '--current') && flagStr(a, '--namespace')) {
    const node = ctx.host.fs[path];
    if (!canAccess(node, ctx.user, 'w')) return err(`error: open ${path}: permission denied`, 1);
    const ns = flagStr(a, '--namespace')!;
    node.content = node.content.includes('    namespace:') ? node.content.replace(/    namespace: .*/, `    namespace: ${ns}`) : node.content.replace('    cluster: default\n', `    cluster: default\n    namespace: ${ns}\n`);
    return ok('Context "default" modified.');
  }
  return err(`error: unknown command "${sub ?? ''}" for "kubectl config"\nAvailable: view, current-context, get-contexts, set-context --current --namespace=NS`, 1);
}

function waitCmd(ctx: CmdCtx, a: Args): CmdResult {
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const cond = flagStr(a, '--for') ?? '';
  const timeout = flagStr(a, '--timeout') ?? '30s';
  const ms = Number(timeout.replace(/[sm]$/, '')) * (timeout.endsWith('m') ? 60_000 : 1000);
  const targets = resolveTargets(a, 1);
  if (typeof targets === 'string') return err(targets, 1);
  const sel = flagStr(a, '-l', '--selector');
  const end = ctx.world.clock + ms;
  for (;;) {
    const st = loadStore(ctx.world);
    const objs = targets.flatMap((t) => (t.names.length ? t.names.map((n) => find(st, t.res.kind, c.ns, n)) : list(st, t.res.kind, c.ns).filter((o) => selectorMatch(sel, o.metadata.labels)))).filter((x): x is KObj => !!x);
    const okNow = objs.length > 0 && objs.every((o) => (cond === 'condition=Ready' || cond === 'condition=ready' ? isPodReady(o) : cond === 'condition=Available' ? (o.status?.availableReplicas ?? 0) >= (o.spec.replicas ?? 1) : false));
    if (okNow) return ok(objs.map((o) => `${shortRef(o)} condition met`).join('\n'));
    if (ctx.world.clock >= end) return err(`error: timed out waiting for the condition on ${objs.length ? shortRef(objs[0]) : targets[0].res.plural}`, 1);
    kubeWait(ctx.world, 2000);
  }
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

const HELP = `kubectl controls the Kubernetes cluster manager.

 Find more information at: https://kubernetes.io/docs/reference/kubectl/

Basic Commands (Beginner):
  create          Create a resource from a file or from stdin
  expose          Take a replication controller, service, deployment or pod and expose it as a new Kubernetes service
  run             Run a particular image on the cluster
  set             Set specific features on objects

Basic Commands (Intermediate):
  get             Display one or many resources
  delete          Delete resources by file names, stdin, resources and names, or by resources and label selector

Deploy Commands:
  rollout         Manage the rollout of a resource
  scale           Set a new size for a deployment, replica set, or replication controller

Cluster Management Commands:
  cluster-info    Display cluster information
  cordon          Mark node as unschedulable
  uncordon        Mark node as schedulable
  drain           Drain node in preparation for maintenance

Troubleshooting and Debugging Commands:
  describe        Show details of a specific resource or group of resources
  logs            Print the logs for a container in a pod
  exec            Execute a command in a container
  wait            Experimental: Wait for a specific condition on one or many resources

Advanced Commands:
  apply           Apply a configuration to a resource by file name or stdin

Settings Commands:
  label           Update the labels on a resource

Other Commands:
  config          Modify kubeconfig files
  version         Print the client and server version information

Usage:
  kubectl [flags] [options]`;

function runCmd(ctx: CmdCtx, a: Args): CmdResult {
  const name = a.pos[1];
  const image = flagStr(a, '--image');
  if (!name || !image) return err('error: NAME is required for run', 1);
  const c = connect(ctx, flagStr(a, '-n', '--namespace'));
  if (!isConn(c)) return c;
  const restart = flagStr(a, '--restart') ?? 'Always';
  const o: J = { apiVersion: 'v1', kind: 'Pod', metadata: { name, labels: { run: name } }, spec: { restartPolicy: restart, containers: [{ name, image, ...(a.rest.length ? { command: a.rest } : {}), ...(flagStr(a, '--port') ? { ports: [{ containerPort: Number(flagStr(a, '--port')) }] } : {}) }] } };
  const r = admit(c, o, '', 'create', undefined, false);
  if (r.code) return err(r.line.replace(/error when creating "": /, ''), 1);
  saveStore(ctx.world, c.st);
  kubeTick(ctx.world);
  return ok(`pod/${name} created`);
}

const kubectl: CommandDef = {
  name: 'kubectl',
  summary: 'Kubernetes command-line client (k3s cluster)',
  usage: 'kubectl get|describe|logs|exec|apply|delete|create|expose|scale|set image|rollout|label|cordon|uncordon|drain|wait|config|cluster-info|version ...',
  run(args, ctx) {
    const a = parseArgs(['kubectl', ...args]);
    const verb = a.pos[1];
    // Global flags go anywhere; shift the verb into position 0-relative helpers expect (pos[0] = verb).
    a.pos = a.pos.slice(1);
    switch (verb) {
      case undefined: case 'help': return ok(HELP);
      case 'version': {
        const cl = `Client Version: ${KUBECTL_VERSION}\nKustomize Version: v5.0.4-0.20230601165947-6ce0bf390ce3`;
        if (flag(a, '--client')) return ok(cl);
        const c = connect(ctx);
        if (!isConn(c)) return { out: `${cl}\n${c.out}`, code: 1 };
        return ok(`${cl}\nServer Version: ${K3S_VERSION}`);
      }
      case 'cluster-info': {
        const c = connect(ctx);
        if (!isConn(c)) return c;
        const url = ctx.host.id === 'kube01' ? 'https://127.0.0.1:6443' : 'https://kube01.corp.lab:6443';
        return ok(`\x1b[0;32mKubernetes control plane\x1b[0m is running at \x1b[0;33m${url}\x1b[0m\n\x1b[0;32mCoreDNS\x1b[0m is running at \x1b[0;33m${url}/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy\x1b[0m\n\nTo further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.`.replace(/\x1b\[[0-9;]*m/g, ''));
      }
      case 'get': return getCmd(ctx, a);
      case 'describe': return describeCmd(ctx, a);
      case 'logs': return logsCmd(ctx, a);
      case 'exec': return execCmd(ctx, a);
      case 'apply': return applyCmd(ctx, a, 'apply');
      case 'create': return createCmd(ctx, a);
      case 'delete': return deleteCmd(ctx, a);
      case 'expose': return exposeCmd(ctx, a);
      case 'scale': return scaleCmd(ctx, a);
      case 'set': return setCmd(ctx, a);
      case 'rollout': return rolloutCmd(ctx, a);
      case 'label': return labelCmd(ctx, a);
      case 'cordon': return cordonCmd(ctx, a, true);
      case 'uncordon': return cordonCmd(ctx, a, false);
      case 'drain': return cordonCmd(ctx, a, true, true);
      case 'wait': return waitCmd(ctx, a);
      case 'run': return runCmd(ctx, a);
      case 'config': return configCmd(ctx, a);
      case 'top': return err('error: Metrics API not available', 1);
      case 'edit': return err('[Cyber Owl Lab: kubectl edit is not simulated. Export, change and apply instead:\n  kubectl get deploy web -o yaml > web.yaml ; nano web.yaml ; kubectl apply -f web.yaml]', 1);
      case 'port-forward': case 'proxy': case 'debug': case 'attach': case 'cp': case 'patch': case 'replace': case 'explain': case 'api-resources': case 'auth': case 'certificate': case 'taint': case 'annotate': case 'autoscale':
        return err(`[Cyber Owl Lab: kubectl ${verb} is not simulated. Simulated: get, describe, logs, exec, apply, create, delete, expose, scale, set image, rollout, label, cordon, uncordon, drain, wait, run, config, cluster-info, version]`, 1);
      default:
        return err(`error: unknown command "${verb}" for "kubectl"\n\nDid you mean this?\n\t${['get', 'describe', 'logs', 'apply', 'delete'].find((v) => v[0] === verb[0]) ?? 'get'}\n`, 1);
    }
  },
};

/** crictl on the nodes: the containers and images the kubelet runs (ps, images, logs). */
const crictl: CommandDef = {
  name: 'crictl',
  summary: 'CRI client: containers and images on a Kubernetes node',
  usage: 'crictl ps [-a] | images | pods | logs CONTAINER',
  run(args, ctx) {
    if (!ctx.host.fs['/usr/local/bin/crictl']) return err('-bash: crictl: command not found', 127);
    if (ctx.user.uid !== 0) return err(`time="${iso(ctx.world.clock)}" level=fatal msg="validate service connection: validate CRI v1 runtime API for endpoint \\"unix:///run/k3s/containerd/containerd.sock\\": rpc error: code = Unavailable desc = connection error: desc = \\"transport: Error while dialing: dial unix /run/k3s/containerd/containerd.sock: connect: permission denied\\""`, 1);
    kubeTick(ctx.world);
    const st = loadStore(ctx.world);
    const pods = list(st, 'Pod').filter((p) => p.spec.nodeName === ctx.host.id);
    const sub = args[0];
    if (sub === 'ps') {
      const rows = pods.filter((p) => args.includes('-a') || podCtrHostId(p)).map((p) => {
        const cs = p.status?.containerStatuses?.[0] ?? {};
        const running = !!podCtrHostId(p);
        return [(cs.containerID ?? 'containerd://' + p.metadata.uid.replace(/-/g, '')).replace('containerd://', '').slice(0, 13), (findImage(imageRef(String(p.spec.containers?.[0]?.image)))?.id ?? '').replace('sha256:', '').slice(0, 13), age(ctx.world.clock - (cs.state?.running?.startedAt ?? p.metadata.creationTimestamp)) + ' ago', running ? 'Running' : 'Exited', p.spec.containers?.[0]?.name ?? '', String(cs.restartCount ?? 0), p.metadata.uid.replace(/-/g, '').slice(0, 13), p.metadata.name];
      });
      return ok(table([['CONTAINER', 'IMAGE', 'CREATED', 'STATE', 'NAME', 'ATTEMPT', 'POD ID', 'POD'], ...rows]));
    }
    if (sub === 'pods') return ok(table([['POD ID', 'CREATED', 'STATE', 'NAME', 'NAMESPACE', 'ATTEMPT', 'RUNTIME'], ...pods.map((p) => [p.metadata.uid.replace(/-/g, '').slice(0, 13), age(ctx.world.clock - p.metadata.creationTimestamp) + ' ago', 'Ready', p.metadata.name, objNs(p), '0', '(default)'])]));
    if (sub === 'images') {
      const t = ctx.host.fs['/var/lib/rancher/k3s/agent/containerd/images.json']?.content;
      const imgs: string[] = t ? JSON.parse(t) : [];
      return ok(table([['IMAGE', 'TAG', 'IMAGE ID', 'SIZE'], ...imgs.map((r) => { const d = findImage(r); const [repo, tag] = r.split(':'); return [repo.includes('/') && !repo.split('/')[0].includes('.') ? `docker.io/${repo}` : `docker.io/library/${repo}`, tag ?? 'latest', (d?.id ?? '').replace('sha256:', '').slice(0, 13), d?.size ?? '']; })]));
    }
    if (sub === 'logs') {
      const p = pods.find((x) => (x.status?.containerStatuses?.[0]?.containerID ?? '').replace('containerd://', '').startsWith(args[1] ?? '\u0000'));
      if (!p) return err(`E1102 10:24:31.000000 ${ctx.world.counter} remote_runtime.go:432] "ContainerStatus from runtime service failed" err="rpc error: code = NotFound desc = an error occurred when try to find container \\"${args[1] ?? ''}\\": not found"`, 1);
      return ok((podLogs(ctx.world, p, p.spec.containers[0].name, false) ?? []).join('\n'));
    }
    return err('Usage: crictl ps [-a] | pods | images | logs CONTAINER', 1);
  },
};

export const KUBE_COMMANDS: CommandDef[] = [kubectl, crictl];
export { nodeReady };
