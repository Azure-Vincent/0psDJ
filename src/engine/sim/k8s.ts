// Kubernetes (k3s v1.30) on two Debian 12 nodes: kube01 runs the server
// (API server, scheduler, controllers, kubelet) and kube02 an agent (kubelet).
// The cluster's objects live in the server's datastore (here a JSON file in
// /var/lib/rancher/k3s/server/db). Controllers reconcile them each time the
// cluster is looked at (kubeTick): Deployments create ReplicaSets, ReplicaSets
// create Pods, the scheduler binds Pods to nodes, and the kubelet runs each Pod
// as a container Host on its node's cni0 bridge (the same container hosts the
// Docker engine uses), so a Pod's traffic goes through the real network
// simulation. flannel (host-gw backend) routes each node's pod subnet via the
// other node; kube-proxy writes Service rules (ClusterIP and NodePort DNAT) to
// the nodes' nftables; CoreDNS answers cluster names for the Pods.
//
// Simplified: one container per Pod is run (others are not simulated); a
// Service with several endpoints always DNATs to the first ready one (no load
// balancing); no NetworkPolicy, PersistentVolumes, Ingress, DaemonSets or Jobs.

import { emptyRuleset, parseRulesetFile, type Ruleset } from '../config/nft';
import { mkdir, readFile, writeFile } from '../fs';
import type { Host, World } from '../types';
import { sha256Hex } from '../util/sha256';
import { findImage, materialise, type ContainerConfig, type ImageDef, type NetworkConfig } from './docker';
import { dnsHooks, dnsQuery, resolverConf, type DnsExchange } from './dns';
import { log } from './journal';
import { allListeners, SERVICE_DEFS, type NginxLoaded, type ServiceDef } from './services';
import { handleRequest, httpHooks, selectServer, type HttpResponse } from './http';
import { tcpConnect } from './tcp';

export const K3S_VERSION = 'v1.30.6+k3s1';
export const KUBECTL_VERSION = 'v1.30.6+k3s1';
export const KUBE_SERVER = 'kube01';
export const SERVICE_CIDR = '10.43.0.0/16';
export const DNS_IP = '10.43.0.10';
export const KUBE_NODES = [
  { id: 'kube01', ip: '10.0.20.90', podCidr: '10.42.0.0/24', gw: '10.42.0.1', roles: 'control-plane,master', mac: '52:54:00:4b:00:5a' },
  { id: 'kube02', ip: '10.0.20.91', podCidr: '10.42.1.0/24', gw: '10.42.1.1', roles: '<none>', mac: '52:54:00:4b:00:5b' },
];
const STATE = '/var/lib/rancher/k3s/server/db/state.json';
export const KUBECONFIG_PATH = '/etc/rancher/k3s/k3s.yaml';

/** Node allocatable resources (2 vCPU, 4 GiB; k3s reserves nothing by default). */
const NODE_CPU_M = 2000;
const NODE_MEM_MI = 3900;
/** Memory a process needs to start (an OOM kill below it). */
const IMAGE_MEM_MI: Record<string, number> = { nginx: 8, postgres: 60, 'corp/inventory': 120, busybox: 1, 'rancher/mirrored-coredns-coredns': 20 };

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

/* eslint-disable @typescript-eslint/no-explicit-any */
export type J = any;

export interface Meta {
  name: string;
  namespace?: string;
  uid: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  creationTimestamp: number;
  generation?: number;
  resourceVersion?: string;
  ownerReferences?: { apiVersion: string; kind: string; name: string; uid: string; controller: boolean }[];
  deletionTimestamp?: number;
}

export interface KObj { apiVersion: string; kind: string; metadata: Meta; spec?: J; status?: J; data?: Record<string, string>; type?: string }

export interface KEvent { ns: string; kind: string; name: string; type: 'Normal' | 'Warning'; reason: string; message: string; source: string; first: number; last: number; count: number }

export interface Store { rv: number; objects: KObj[]; events: KEvent[]; lastTick?: number }

export const NAMESPACED = new Set(['Pod', 'Deployment', 'ReplicaSet', 'Service', 'Endpoints', 'ConfigMap', 'Secret', 'Event']);
export const API_VERSION: Record<string, string> = { Pod: 'v1', Service: 'v1', Endpoints: 'v1', ConfigMap: 'v1', Secret: 'v1', Namespace: 'v1', Node: 'v1', Deployment: 'apps/v1', ReplicaSet: 'apps/v1' };

export function kubeServer(world: World): Host | undefined {
  return world.hosts[KUBE_SERVER];
}

export function loadStore(world: World): Store {
  const s = kubeServer(world);
  const t = s ? readFile(s, STATE) : undefined;
  return t ? (JSON.parse(t) as Store) : { rv: 1, objects: [], events: [] };
}

export function saveStore(world: World, st: Store): void {
  const s = kubeServer(world);
  if (!s) return;
  for (const d of ['/var/lib/rancher', '/var/lib/rancher/k3s', '/var/lib/rancher/k3s/server', '/var/lib/rancher/k3s/server/db']) if (!s.fs[d]) mkdir(s, d, world.clock, { mode: 0o700 });
  writeFile(s, STATE, JSON.stringify(st), world.clock, { mode: 0o600 });
}

export const objNs = (o: KObj) => o.metadata.namespace ?? '';
export function find(st: Store, kind: string, ns: string, name: string): KObj | undefined {
  return st.objects.find((o) => o.kind === kind && o.metadata.name === name && (!NAMESPACED.has(kind) || objNs(o) === ns));
}
export const list = (st: Store, kind: string, ns?: string) => st.objects.filter((o) => o.kind === kind && (ns === undefined || !NAMESPACED.has(kind) || objNs(o) === ns));

export function newUid(world: World, seed: string): string {
  world.counter += 1;
  const h = sha256Hex(`${seed}|${world.counter}|${world.clock}`);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/** Random-looking suffixes as the controllers generate them (consonants and digits, no vowels). */
const SUFFIX_CHARS = 'bcdfghjklmnpqrstvwxz2456789';
export function suffix(seed: string, n: number): string {
  const h = sha256Hex(seed);
  let out = '';
  for (let i = 0; i < n; i++) out += SUFFIX_CHARS[parseInt(h.slice(i * 2, i * 2 + 2), 16) % SUFFIX_CHARS.length];
  return out;
}

export function addObject(world: World, st: Store, o: KObj): KObj {
  o.metadata.uid ||= newUid(world, `${o.kind}/${o.metadata.name}`);
  o.metadata.creationTimestamp ||= world.clock;
  o.metadata.resourceVersion = String(++st.rv);
  st.objects.push(o);
  return o;
}

export function removeObject(st: Store, o: KObj): void {
  st.objects = st.objects.filter((x) => x !== o && x.metadata.uid !== o.metadata.uid);
}

export function event(world: World, st: Store, o: KObj, type: 'Normal' | 'Warning', reason: string, message: string, source: string): void {
  const ns = objNs(o) || 'default';
  const e = st.events.find((x) => x.ns === ns && x.kind === o.kind && x.name === o.metadata.name && x.reason === reason && x.message === message);
  if (e) { e.count++; e.last = world.clock; return; }
  st.events.push({ ns, kind: o.kind, name: o.metadata.name, type, reason, message, source, first: world.clock, last: world.clock, count: 1 });
  if (st.events.length > 400) st.events.shift();
}

// ---------------------------------------------------------------------------
// Labels and quantities
// ---------------------------------------------------------------------------

export function matchLabels(sel: Record<string, string> | undefined, labels: Record<string, string> | undefined): boolean {
  if (!sel || !Object.keys(sel).length) return false;
  return Object.entries(sel).every(([k, v]) => labels?.[k] === v);
}

/** "250m" → 250, "1" → 1000, "0.5" → 500 (millicores). */
export function cpuMilli(q: unknown): number {
  if (q === undefined || q === null || q === '') return 0;
  const s = String(q);
  return s.endsWith('m') ? Number(s.slice(0, -1)) : Math.round(Number(s) * 1000);
}

/** "128Mi" → 128, "1Gi" → 1024, "64M" → 61, plain bytes too (MiB). */
export function memMi(q: unknown): number {
  if (q === undefined || q === null || q === '') return 0;
  const m = /^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|K|M|G|k)?$/.exec(String(q));
  if (!m) return NaN;
  const n = Number(m[1]);
  const f: Record<string, number> = { Ki: 1 / 1024, Mi: 1, Gi: 1024, Ti: 1024 * 1024, K: 1000 / 1048576, k: 1000 / 1048576, M: 1e6 / 1048576, G: 1e9 / 1048576 };
  return m[2] ? n * f[m[2]] : n / 1048576;
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

export function nodeHosts(world: World): Host[] {
  return KUBE_NODES.map((n) => world.hosts[n.id]).filter((h): h is Host => !!h);
}

/** A node is Ready when its kubelet (k3s server or agent) runs and can reach the server. */
export function nodeReady(world: World, id: string): boolean {
  const h = world.hosts[id];
  const unit = id === KUBE_SERVER ? 'k3s' : 'k3s-agent';
  return !!h && h.services[unit]?.state === 'active' && kubeServer(world)?.services.k3s?.state === 'active';
}

function syncNodes(world: World, st: Store): void {
  for (const n of KUBE_NODES) {
    if (!world.hosts[n.id]) continue;
    let o = find(st, 'Node', '', n.id);
    if (!o) {
      o = addObject(world, st, {
        apiVersion: 'v1', kind: 'Node',
        metadata: { name: n.id, uid: '', creationTimestamp: 0, labels: { 'kubernetes.io/hostname': n.id, 'kubernetes.io/os': 'linux', 'kubernetes.io/arch': 'amd64', ...(n.id === KUBE_SERVER ? { 'node-role.kubernetes.io/control-plane': 'true', 'node-role.kubernetes.io/master': 'true' } : {}) } },
        spec: { podCIDR: n.podCidr, podCIDRs: [n.podCidr] },
        status: {},
      });
    }
    const ready = nodeReady(world, n.id);
    const was = o.status.ready;
    o.status = { ...o.status, ready, address: n.ip };
    if (was !== undefined && was !== ready) {
      event(world, st, o, ready ? 'Normal' : 'Normal', ready ? 'NodeReady' : 'NodeNotReady', ready ? `Node ${n.id} status is now: NodeReady` : `Node ${n.id} status is now: NodeNotReady`, 'node-controller');
      o.status.transition = world.clock;
    }
    o.status.transition ??= o.metadata.creationTimestamp;
    // Taints: an unreachable node gets the NoSchedule taint from the node controller.
    const taints = (o.spec.taints ?? []).filter((t: J) => t.key !== 'node.kubernetes.io/unreachable');
    if (!ready) taints.push({ key: 'node.kubernetes.io/unreachable', effect: 'NoSchedule' });
    o.spec.taints = taints.length ? taints : undefined;
  }
}

// ---------------------------------------------------------------------------
// Controllers: Deployment → ReplicaSet → Pod
// ---------------------------------------------------------------------------

export function templateHash(tpl: J): string {
  const h = sha256Hex(JSON.stringify(tpl));
  return suffix(h, 9).slice(0, 10).replace(/^(.{9}).*/, '$1').slice(0, 9 + (parseInt(h[0], 16) % 2));
}

const owned = (st: Store, kind: string, owner: KObj) => st.objects.filter((o) => o.kind === kind && o.metadata.ownerReferences?.some((r) => r.uid === owner.metadata.uid));
const ownerRef = (o: KObj) => ({ apiVersion: o.apiVersion, kind: o.kind, name: o.metadata.name, uid: o.metadata.uid, controller: true });

function percentOf(v: unknown, total: number, roundUp: boolean): number {
  if (v === undefined || v === null) return roundUp ? Math.ceil(total * 0.25) : Math.floor(total * 0.25);
  const s = String(v);
  if (s.endsWith('%')) { const x = (Number(s.slice(0, -1)) / 100) * total; return roundUp ? Math.ceil(x) : Math.floor(x); }
  return Number(s);
}

export const isPodReady = (p: KObj) => !p.metadata.deletionTimestamp && p.status?.phase === 'Running' && (p.status.containerStatuses ?? []).every((c: J) => c.ready);

function reconcileDeployments(world: World, st: Store): void {
  for (const d of list(st, 'Deployment')) {
    const desired = Number(d.spec.replicas ?? 1);
    const tpl = d.spec.template;
    const hash = templateHash(tpl);
    const rss = owned(st, 'ReplicaSet', d);
    let cur = rss.find((r) => r.metadata.labels?.['pod-template-hash'] === hash);
    const maxRev = Math.max(0, ...rss.map((r) => Number(r.metadata.annotations?.['deployment.kubernetes.io/revision'] ?? 0)));
    if (!cur) {
      cur = addObject(world, st, {
        apiVersion: 'apps/v1', kind: 'ReplicaSet',
        metadata: { name: `${d.metadata.name}-${hash}`, namespace: objNs(d), uid: '', creationTimestamp: 0, labels: { ...(tpl.metadata?.labels ?? {}), 'pod-template-hash': hash }, annotations: { 'deployment.kubernetes.io/revision': String(maxRev + 1), 'deployment.kubernetes.io/desired-replicas': String(desired) }, ownerReferences: [ownerRef(d)] },
        spec: { replicas: 0, selector: { matchLabels: { ...(d.spec.selector?.matchLabels ?? {}), 'pod-template-hash': hash } }, template: { metadata: { labels: { ...(tpl.metadata?.labels ?? {}), 'pod-template-hash': hash } }, spec: tpl.spec } },
        status: { replicas: 0, readyReplicas: 0 },
      });
      event(world, st, d, 'Normal', 'ScalingReplicaSet', `Scaled up replica set ${cur.metadata.name} to ${Math.min(desired, desired === 0 ? 0 : 1)}`, 'deployment-controller');
      d.status = { ...(d.status ?? {}), lastProgress: world.clock };
    } else if (Number(cur.metadata.annotations?.['deployment.kubernetes.io/revision'] ?? 0) < maxRev) {
      // A rollback to an older template: that ReplicaSet becomes the newest revision again.
      cur.metadata.annotations = { ...cur.metadata.annotations, 'deployment.kubernetes.io/revision': String(maxRev + 1) };
      d.status = { ...(d.status ?? {}), lastProgress: world.clock };
    }
    const olds = rss.filter((r) => r !== cur);
    const surge = percentOf(d.spec.strategy?.rollingUpdate?.maxSurge, desired, true);
    const unavail = percentOf(d.spec.strategy?.rollingUpdate?.maxUnavailable, desired, false);
    const recreate = d.spec.strategy?.type === 'Recreate';
    const readyOf = (r: KObj) => list(st, 'Pod', objNs(d)).filter((p) => p.metadata.ownerReferences?.some((o) => o.uid === r.metadata.uid) && isPodReady(p)).length;
    const oldTotal = olds.reduce((n, r) => n + Number(r.spec.replicas), 0);
    if (recreate) {
      for (const r of olds) if (r.spec.replicas > 0) { r.spec.replicas = 0; event(world, st, d, 'Normal', 'ScalingReplicaSet', `Scaled down replica set ${r.metadata.name} to 0 from ${r.status?.replicas ?? 0}`, 'deployment-controller'); }
      const oldPods = list(st, 'Pod', objNs(d)).filter((p) => olds.some((r) => p.metadata.ownerReferences?.some((o) => o.uid === r.metadata.uid)));
      if (!oldPods.length && cur.spec.replicas !== desired) scaleRs(world, st, d, cur, desired);
    } else {
      // Scale up the new ReplicaSet within maxSurge.
      const allowed = Math.max(0, desired + Math.max(surge, unavail === 0 ? 1 : 0) - oldTotal);
      const target = olds.length ? Math.min(desired, Math.max(cur.spec.replicas, allowed)) : desired;
      if (target !== cur.spec.replicas) scaleRs(world, st, d, cur, target);
      // Scale down old ReplicaSets while enough pods stay available.
      const minAvail = desired - unavail;
      let avail = readyOf(cur) + olds.reduce((n, r) => n + readyOf(r), 0);
      for (const r of olds.sort((a, b) => a.metadata.creationTimestamp - b.metadata.creationTimestamp)) {
        let n = Number(r.spec.replicas);
        const unready = n - readyOf(r);
        // Unready old pods can always go; ready ones only above the minimum available.
        let remove = Math.min(n, unready + Math.max(0, avail - minAvail - 0));
        if (readyOf(cur) + oldTotal - remove < 0) remove = 0;
        // Never remove more than the new ReplicaSet can replace (total ≥ desired - maxUnavailable).
        remove = Math.min(remove, Math.max(0, cur.spec.replicas + oldTotal - minAvail - (cur.spec.replicas - readyOf(cur))));
        if (remove > 0) {
          n -= remove;
          avail -= Math.min(remove, readyOf(r));
          r.spec.replicas = n;
          event(world, st, d, 'Normal', 'ScalingReplicaSet', `Scaled down replica set ${r.metadata.name} to ${n} from ${n + remove}`, 'deployment-controller');
        }
      }
    }
    // Old ReplicaSets beyond revisionHistoryLimit (default 10) are deleted once empty.
    const keep = Number(d.spec.revisionHistoryLimit ?? 10);
    const empty = olds.filter((r) => r.spec.replicas === 0).sort((a, b) => b.metadata.creationTimestamp - a.metadata.creationTimestamp);
    for (const r of empty.slice(keep)) removeObject(st, r);
    // Status.
    const pods = list(st, 'Pod', objNs(d)).filter((p) => owned(st, 'ReplicaSet', d).some((r) => p.metadata.ownerReferences?.some((o) => o.uid === r.metadata.uid)) && !p.metadata.deletionTimestamp);
    const updated = pods.filter((p) => p.metadata.labels?.['pod-template-hash'] === hash).length;
    const ready = pods.filter(isPodReady).length;
    const updatedReady = pods.filter((p) => p.metadata.labels?.['pod-template-hash'] === hash && isPodReady(p)).length;
    const prev = d.status ?? {};
    const complete = updatedReady >= desired && pods.length === updated;
    const progressed = updatedReady > (prev.updatedReady ?? -1) || updated > (prev.updated ?? -1);
    const lastProgress = progressed ? world.clock : (prev.lastProgress ?? world.clock);
    const deadline = Number(d.spec.progressDeadlineSeconds ?? 600) * 1000;
    const failed = !complete && world.clock - lastProgress > deadline;
    if (failed && !prev.failed) event(world, st, d, 'Warning', 'ProgressDeadlineExceeded', `Deployment "${d.metadata.name}" has timed out progressing.`, 'deployment-controller');
    d.status = { replicas: pods.length, updatedReplicas: updated, readyReplicas: ready, availableReplicas: ready, unavailableReplicas: Math.max(0, desired - ready), observedGeneration: d.metadata.generation ?? 1, lastProgress, updated, updatedReady, complete, failed, newRs: cur.metadata.name };
  }
}

function scaleRs(world: World, st: Store, d: KObj, r: KObj, n: number): void {
  const from = Number(r.spec.replicas);
  if (from === n) return;
  r.spec.replicas = n;
  r.metadata.annotations = { ...r.metadata.annotations, 'deployment.kubernetes.io/desired-replicas': String(d.spec.replicas ?? 1) };
  event(world, st, d, 'Normal', 'ScalingReplicaSet', n > from ? `Scaled up replica set ${r.metadata.name} to ${n} from ${from}` : `Scaled down replica set ${r.metadata.name} to ${n} from ${from}`, 'deployment-controller');
}

function reconcileReplicaSets(world: World, st: Store): void {
  for (const r of list(st, 'ReplicaSet')) {
    const pods = list(st, 'Pod', objNs(r)).filter((p) => p.metadata.ownerReferences?.some((o) => o.uid === r.metadata.uid) && !p.metadata.deletionTimestamp);
    const want = Number(r.spec.replicas ?? 1);
    if (pods.length < want) {
      for (let i = pods.length; i < want; i++) {
        const name = `${r.metadata.name}-${suffix(`${r.metadata.uid}|${world.counter}|${i}|${world.clock}`, 5)}`;
        world.counter++;
        addObject(world, st, {
          apiVersion: 'v1', kind: 'Pod',
          metadata: { name, namespace: objNs(r), uid: '', creationTimestamp: 0, labels: { ...(r.spec.template.metadata?.labels ?? {}) }, ownerReferences: [ownerRef(r)] },
          spec: JSON.parse(JSON.stringify(r.spec.template.spec)),
          status: { phase: 'Pending' },
        });
        event(world, st, r, 'Normal', 'SuccessfulCreate', `Created pod: ${name}`, 'replicaset-controller');
      }
    } else if (pods.length > want) {
      // Delete unready, then unscheduled, then the newest pods first.
      const victims = [...pods].sort((a, b) => Number(isPodReady(a)) - Number(isPodReady(b)) || Number(!!a.spec.nodeName) - Number(!!b.spec.nodeName) || b.metadata.creationTimestamp - a.metadata.creationTimestamp).slice(0, pods.length - want);
      for (const p of victims) { deletePod(world, st, p); event(world, st, r, 'Normal', 'SuccessfulDelete', `Deleted pod: ${p.metadata.name}`, 'replicaset-controller'); }
    }
    const live = list(st, 'Pod', objNs(r)).filter((p) => p.metadata.ownerReferences?.some((o) => o.uid === r.metadata.uid) && !p.metadata.deletionTimestamp);
    r.status = { replicas: live.length, readyReplicas: live.filter(isPodReady).length, availableReplicas: live.filter(isPodReady).length };
  }
}

/** Delete a Pod: the kubelet stops its container and the object goes away (graceful termination is not waited for). */
export function deletePod(world: World, st: Store, p: KObj): void {
  stopPodContainer(world, p);
  removeObject(st, p);
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

export function podRequests(spec: J): { cpu: number; mem: number } {
  let cpu = 0;
  let mem = 0;
  for (const c of spec.containers ?? []) {
    cpu += cpuMilli(c.resources?.requests?.cpu ?? c.resources?.limits?.cpu);
    mem += memMi(c.resources?.requests?.memory ?? c.resources?.limits?.memory) || 0;
  }
  return { cpu, mem };
}

export function nodeAllocated(st: Store, node: string): { cpu: number; mem: number } {
  return list(st, 'Pod').filter((p) => p.spec.nodeName === node && !['Succeeded', 'Failed'].includes(p.status?.phase)).map((p) => podRequests(p.spec)).reduce((a, b) => ({ cpu: a.cpu + b.cpu, mem: a.mem + b.mem }), { cpu: 0, mem: 0 });
}

function schedule(world: World, st: Store): void {
  const nodes = list(st, 'Node');
  for (const p of list(st, 'Pod').filter((x) => !x.spec.nodeName && !x.metadata.deletionTimestamp)) {
    const req = podRequests(p.spec);
    const reasons: Record<string, number> = {};
    const fits: KObj[] = [];
    for (const n of nodes) {
      const why = (r: string) => { reasons[r] = (reasons[r] ?? 0) + 1; };
      if (n.spec.unschedulable) { why('node(s) were unschedulable'); continue; }
      const taints = (n.spec.taints ?? []).filter((t: J) => t.effect !== 'PreferNoSchedule' && !(p.spec.tolerations ?? []).some((tol: J) => tol.operator === 'Exists' ? (!tol.key || tol.key === t.key) : tol.key === t.key && (tol.value ?? '') === (t.value ?? '')));
      if (taints.length) { why(`node(s) had untolerated taint {${taints[0].key}: ${taints[0].value ?? ''}}`); continue; }
      const sel = p.spec.nodeSelector as Record<string, string> | undefined;
      if (sel && !Object.entries(sel).every(([k, v]) => n.metadata.labels?.[k] === String(v))) { why("node(s) didn't match Pod's node affinity/selector"); continue; }
      const used = nodeAllocated(st, n.metadata.name);
      if (used.cpu + req.cpu > NODE_CPU_M) { why('Insufficient cpu'); continue; }
      if (used.mem + req.mem > NODE_MEM_MI) { why('Insufficient memory'); continue; }
      fits.push(n);
    }
    if (!fits.length) {
      const msg = `0/${nodes.length} nodes are available: ${Object.entries(reasons).sort(([a], [b]) => a.localeCompare(b)).map(([r, k]) => `${k} ${r}`).join(', ')}. preemption: 0/${nodes.length} nodes are available: ${nodes.length} Preemption is not helpful for scheduling.`;
      p.status = { ...p.status, phase: 'Pending', conditions: [{ type: 'PodScheduled', status: 'False', reason: 'Unschedulable', message: msg }] };
      if (p.status.lastSchedMsg !== msg) { event(world, st, p, 'Warning', 'FailedScheduling', msg, 'default-scheduler'); p.status.lastSchedMsg = msg; }
      continue;
    }
    // Spread the replicas of one owner across nodes, then prefer the less loaded node.
    const owner = p.metadata.ownerReferences?.[0]?.uid;
    const score = (n: KObj) => {
      const on = list(st, 'Pod').filter((x) => x.spec.nodeName === n.metadata.name && !x.metadata.deletionTimestamp);
      const used = nodeAllocated(st, n.metadata.name);
      return (owner ? on.filter((x) => x.metadata.ownerReferences?.[0]?.uid === owner).length : 0) * 1000 + on.length * 10 + used.cpu / 100 + used.mem / 200;
    };
    fits.sort((a, b) => score(a) - score(b) || a.metadata.name.localeCompare(b.metadata.name));
    const node = fits[0].metadata.name;
    p.spec.nodeName = node;
    p.status = { phase: 'Pending', conditions: [{ type: 'PodScheduled', status: 'True' }], hostIP: KUBE_NODES.find((n) => n.id === node)!.ip };
    event(world, st, p, 'Normal', 'Scheduled', `Successfully assigned ${objNs(p)}/${p.metadata.name} to ${node}`, 'default-scheduler');
  }
}

// ---------------------------------------------------------------------------
// Kubelet: run the pod's container as a Host on the node's cni0 bridge
// ---------------------------------------------------------------------------

/** Late-bound helpers registered by the shell (running a probe command needs the shell; importing it here would be circular). */
export const kubeHooks: { run?: (world: World, hostId: string, line: string) => { out: string; code: number } } = {};

const podSim = (p: KObj): J => (p.status._sim ??= { backoff: 0 });
export const podCtrHostId = (p: KObj) => (p.status?._sim?.host as string | undefined);

const IMAGES_FILE = '/var/lib/rancher/k3s/agent/containerd/images.json';
/** Images in the node's containerd store. */
export function pulledOn(node: Host): string[] {
  const t = readFile(node, IMAGES_FILE);
  return t ? (JSON.parse(t) as string[]) : [];
}
export function savePulled(world: World, node: Host, imgs: string[]): void {
  for (const d of ['/var/lib/rancher', '/var/lib/rancher/k3s', '/var/lib/rancher/k3s/agent', '/var/lib/rancher/k3s/agent/containerd']) if (!node.fs[d]) mkdir(node, d, world.clock, { mode: 0o700 });
  writeFile(node, IMAGES_FILE, JSON.stringify([...new Set(imgs)]), world.clock, { mode: 0o600 });
}

function podNetwork(node: (typeof KUBE_NODES)[number]): NetworkConfig {
  return { id: sha256Hex(`${node.id}-cni0`), name: 'cni0', driver: 'bridge', subnet: node.podCidr, gateway: node.gw, bridge: 'cni0', created: 0, labels: {} };
}

/** Image references as the kubelet sees them: docker.io/library/nginx:1.25 → nginx:1.25. */
export function imageRef(ref: string): string {
  return ref.replace(/^docker\.io\/library\//, '').replace(/^docker\.io\//, '');
}

function pullError(ref: string): string {
  const full = ref.includes('/') && ref.split('/')[0].includes('.') ? ref : `docker.io/${ref.includes('/') ? '' : 'library/'}${ref.includes(':') ? ref : `${ref}:latest`}`;
  if (ref.split('/')[0] === 'registry.corp.lab') return `rpc error: code = Unknown desc = failed to pull and unpack image "${full}": failed to resolve reference "${full}": failed to do request: Head "https://registry.corp.lab/v2/${ref.split('/').slice(1).join('/').split(':')[0]}/manifests/${ref.split(':')[1] ?? 'latest'}": dial tcp: lookup registry.corp.lab on 10.0.10.53:53: no such host`;
  return `rpc error: code = NotFound desc = failed to pull and unpack image "${full}": failed to resolve reference "${full}": ${full}: not found`;
}

/** Environment of a container: env (with configMapKeyRef / secretKeyRef) and envFrom. A missing reference blocks the start. */
function containerEnv(st: Store, ns: string, c: J): { env: string[]; error?: string } {
  const out: string[] = [];
  for (const ef of c.envFrom ?? []) {
    const ref = ef.configMapRef ?? ef.secretRef;
    const kind = ef.configMapRef ? 'ConfigMap' : 'Secret';
    const o = find(st, kind, ns, ref?.name);
    if (!o) { if (ref?.optional === true || ref?.optional === 'true') continue; return { env: out, error: `${kind.toLowerCase()} "${ref?.name}" not found` }; }
    for (const [k, v] of Object.entries(o.data ?? {})) out.push(`${ef.prefix ?? ''}${k}=${kind === 'Secret' ? b64decode(v) : v}`);
  }
  for (const e of c.env ?? []) {
    if (e.value !== undefined) { out.push(`${e.name}=${e.value ?? ''}`); continue; }
    const ref = e.valueFrom?.configMapKeyRef ?? e.valueFrom?.secretKeyRef;
    if (!ref) { out.push(`${e.name}=`); continue; }
    const kind = e.valueFrom.configMapKeyRef ? 'ConfigMap' : 'Secret';
    const o = find(st, kind, ns, ref.name);
    if (!o) return { env: out, error: `${kind.toLowerCase()} "${ref.name}" not found` };
    if (!(ref.key in (o.data ?? {}))) return { env: out, error: `couldn't find key ${ref.key} in ${kind} ${ns}/${ref.name}` };
    out.push(`${e.name}=${kind === 'Secret' ? b64decode(o.data![ref.key]) : o.data![ref.key]}`);
  }
  return { env: out };
}

export const b64encode = (s: string) => (typeof btoa === 'function' ? btoa(unescape(encodeURIComponent(s))) : Buffer.from(s, 'utf8').toString('base64'));
export const b64decode = (s: string) => { try { return typeof atob === 'function' ? decodeURIComponent(escape(atob(s))) : Buffer.from(s, 'base64').toString('utf8'); } catch { return s; } };

function podLogPath(p: KObj, ctr: string, restart: number): string {
  return `/var/log/pods/${objNs(p)}_${p.metadata.name}_${p.metadata.uid}/${ctr}/${restart}.log`;
}

function writePodLog(world: World, node: Host, p: KObj, ctr: string, restart: number, lines: string[], stream = 'stdout'): void {
  const path = podLogPath(p, ctr, restart);
  const parts = path.split('/').slice(1, -1);
  for (let k = 1; k <= parts.length; k++) { const d = '/' + parts.slice(0, k).join('/'); if (!node.fs[d]) mkdir(node, d, world.clock); }
  const iso = new Date(Math.floor(world.clock)).toISOString().replace('Z', '000000Z');
  writeFile(node, path, (readFile(node, path) ?? '') + lines.map((l) => `${iso} ${stream} F ${l}\n`).join(''), world.clock, { mode: 0o640 });
}

/** The container's log lines (CRI format on the node, plus nginx's access/error logs while it runs). */
export function podLogs(world: World, p: KObj, ctr: string, previous: boolean): string[] | null {
  const node = p.spec.nodeName ? world.hosts[p.spec.nodeName] : undefined;
  if (!node) return null;
  const cs = (p.status?.containerStatuses ?? []).find((c: J) => c.name === ctr);
  const restart = (cs?.restartCount ?? 0) - (previous ? 1 : 0);
  if (restart < 0) return null;
  const text = readFile(node, podLogPath(p, ctr, restart));
  if (text === undefined) return previous ? null : [];
  const lines = text.split('\n').filter(Boolean).map((l) => l.replace(/^\S+ \S+ [FP] /, ''));
  const live = !previous && podCtrHostId(p) ? world.hosts[podCtrHostId(p)!] : undefined;
  if (live) for (const f of ['/var/log/nginx/access.log', '/var/log/nginx/error.log']) lines.push(...(readFile(live, f) ?? '').split('\n').filter(Boolean));
  return lines;
}

function stopPodContainer(world: World, p: KObj): void {
  const id = podCtrHostId(p);
  if (id && world.hosts[id]) {
    const node = p.spec.nodeName ? world.hosts[p.spec.nodeName] : undefined;
    const live = world.hosts[id];
    if (node) {
      const cs = (p.status?.containerStatuses ?? [])[0];
      const flushed: string[] = [];
      for (const f of ['/var/log/nginx/access.log', '/var/log/nginx/error.log']) flushed.push(...(readFile(live, f) ?? '').split('\n').filter(Boolean));
      if (flushed.length && cs) writePodLog(world, node, p, cs.name, cs.restartCount ?? 0, flushed);
    }
    delete world.hosts[id];
  }
  if (p.status?._sim) p.status._sim.host = undefined;
}

/** Back-off between restarts: 10 s, doubled each time, at most 5 minutes. */
const backoffMs = (n: number) => Math.min(300_000, 10_000 * 2 ** Math.max(0, n - 1));

function containerSpec(p: KObj): J {
  return (p.spec.containers ?? [])[0] ?? {};
}

function setContainerStatus(p: KObj, patch: J): J {
  const c = containerSpec(p);
  const list0 = p.status.containerStatuses ?? [];
  const cur = list0[0] ?? { name: c.name, image: c.image, imageID: '', ready: false, restartCount: 0, started: false, state: { waiting: { reason: 'ContainerCreating' } } };
  const next = { ...cur, name: c.name, image: c.image, ...patch };
  p.status.containerStatuses = [next];
  return next;
}

function startPod(world: World, st: Store, p: KObj): void {
  const node = KUBE_NODES.find((n) => n.id === p.spec.nodeName)!;
  const nodeHost = world.hosts[node.id];
  const c = containerSpec(p);
  const sim = podSim(p);
  const ref = imageRef(String(c.image ?? ''));
  const img = findImage(ref);
  const pulled = pulledOn(nodeHost);
  if (!img) {
    const msg = `Failed to pull image "${c.image}": ${pullError(ref)}`;
    const first = !sim.pullFailedAt;
    sim.pullFailedAt ??= world.clock;
    // ErrImagePull on the first failure, then ImagePullBackOff while the kubelet waits to retry.
    const backoff = world.clock - sim.pullFailedAt > 5000;
    setContainerStatus(p, { ready: false, started: false, state: { waiting: { reason: backoff ? 'ImagePullBackOff' : 'ErrImagePull', message: backoff ? `Back-off pulling image "${c.image}"` : msg } } });
    if (first) {
      event(world, st, p, 'Normal', 'Pulling', `Pulling image "${c.image}"`, `kubelet`);
      event(world, st, p, 'Warning', 'Failed', msg, 'kubelet');
      event(world, st, p, 'Warning', 'Failed', 'Error: ErrImagePull', 'kubelet');
    } else if (backoff) {
      event(world, st, p, 'Normal', 'BackOff', `Back-off pulling image "${c.image}"`, 'kubelet');
      event(world, st, p, 'Warning', 'Failed', 'Error: ImagePullBackOff', 'kubelet');
    }
    p.status.phase = 'Pending';
    return;
  }
  sim.pullFailedAt = undefined;
  // Creating the pod sandbox (and pulling the image the first time) takes a few seconds.
  if (sim.createAt === undefined) {
    sim.createAt = world.clock + (pulled.includes(ref) ? 1500 : 4000);
    setContainerStatus(p, { ready: false, started: false, state: { waiting: { reason: 'ContainerCreating' } } });
    p.status.phase = 'Pending';
  }
  if (world.clock < sim.createAt) return;
  if (!pulled.includes(ref)) {
    savePulled(world, nodeHost, [...pulled, ref]);
    event(world, st, p, 'Normal', 'Pulling', `Pulling image "${c.image}"`, 'kubelet');
    event(world, st, p, 'Normal', 'Pulled', `Successfully pulled image "${c.image}" in 2.1s (2.1s including waiting). Image size: ${img.size.replace(/MB$/, '')}000000 bytes.`, 'kubelet');
  } else if (!(p.status.containerStatuses?.[0]?.restartCount > 0)) {
    event(world, st, p, 'Normal', 'Pulled', `Container image "${c.image}" already present on machine`, 'kubelet');
  }
  const envR = containerEnv(st, objNs(p), c);
  if (envR.error) {
    setContainerStatus(p, { ready: false, started: false, state: { waiting: { reason: 'CreateContainerConfigError', message: envR.error } } });
    if (sim.configErr !== envR.error) event(world, st, p, 'Warning', 'Failed', `Error: ${envR.error}`, 'kubelet');
    sim.configErr = envR.error;
    p.status.phase = 'Pending';
    return;
  }
  sim.configErr = undefined;
  // Volumes from ConfigMaps and Secrets must exist before the container is created.
  for (const v of p.spec.volumes ?? []) {
    const kind = v.configMap ? 'ConfigMap' : v.secret ? 'Secret' : '';
    const name = v.configMap?.name ?? v.secret?.secretName;
    if (kind && !find(st, kind, objNs(p), name)) {
      const msg = `MountVolume.SetUp failed for volume "${v.name}" : ${kind.toLowerCase()} "${name}" not found`;
      setContainerStatus(p, { ready: false, started: false, state: { waiting: { reason: 'ContainerCreating' } } });
      if (sim.mountErr !== msg) event(world, st, p, 'Warning', 'FailedMount', msg, 'kubelet');
      sim.mountErr = msg;
      p.status.phase = 'Pending';
      return;
    }
  }
  sim.mountErr = undefined;
  const restart = p.status.containerStatuses?.[0]?.restartCount ?? 0;
  const ip = sim.ip ?? allocatePodIp(world, st, node);
  sim.ip = ip;
  const cmd = [...(c.command ?? []), ...(c.args ?? [])].map(String);
  const cfg: ContainerConfig = {
    id: sha256Hex(`${p.metadata.uid}|${c.name}|${restart}`), name: `${c.name}`, image: ref, created: world.clock,
    env: [...img.env, ...envR.env], cmd: cmd.length ? cmd : img.cmd, ports: [], restart: 'no', network: 'cni0', aliases: [], mounts: [], labels: {},
    state: { status: 'running', exitCode: 0, startedAt: world.clock, finishedAt: 0, restartCount: 0, manuallyStopped: false, pid: 0, ip },
  };
  const ctr = materialise(world, nodeHost, cfg, img as ImageDef, podNetwork(node), ip);
  ctr.hostname = p.metadata.name;
  ctr.role = `pod ${objNs(p)}/${p.metadata.name} (${c.image})`;
  ctr.container = { host: node.id, id: cfg.id, name: p.metadata.name, image: ref, env: cfg.env, pod: `${objNs(p)}/${p.metadata.name}` };
  writeFile(ctr, '/etc/hostname', `${p.metadata.name}\n`, world.clock);
  writeFile(ctr, '/etc/hosts', `# Kubernetes-managed hosts file.\n127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n${ip}\t${p.metadata.name}\n`, world.clock);
  writeFile(ctr, '/etc/resolv.conf', `search ${objNs(p)}.svc.cluster.local svc.cluster.local cluster.local corp.lab\nnameserver ${DNS_IP}\noptions ndots:5\n`, world.clock);
  // ConfigMap and Secret volumes: one file per key under the mount path.
  for (const m of c.volumeMounts ?? []) {
    const v = (p.spec.volumes ?? []).find((x: J) => x.name === m.name);
    if (!v) continue;
    const src = v.configMap ? find(st, 'ConfigMap', objNs(p), v.configMap.name) : v.secret ? find(st, 'Secret', objNs(p), v.secret.secretName) : undefined;
    const dir = String(m.mountPath).replace(/\/$/, '');
    const parts = dir.split('/').slice(1);
    for (let k = 1; k <= parts.length; k++) { const d = '/' + parts.slice(0, k).join('/'); if (!ctr.fs[d]) mkdir(ctr, d, world.clock); }
    if (src) for (const [k, val] of Object.entries(src.data ?? {})) {
      const target = m.subPath ? dir : `${dir}/${k}`;
      if (m.subPath && m.subPath !== k) continue;
      writeFile(ctr, target, v.secret ? b64decode(val) : val, world.clock, { mode: v.secret ? 0o644 : 0o644 });
    }
  }
  world.hosts[ctr.id] = ctr;
  const r = img.start(world, nodeHost, ctr, cfg);
  const limit = memMi(c.resources?.limits?.memory);
  const need = IMAGE_MEM_MI[ref.split(':')[0]] ?? 16;
  const oom = r.ok && limit > 0 && limit < need;
  event(world, st, p, 'Normal', 'Created', `Created container ${c.name}`, 'kubelet');
  event(world, st, p, 'Normal', 'Started', `Started container ${c.name}`, 'kubelet');
  writePodLog(world, nodeHost, p, c.name, restart, r.lines, r.ok ? 'stdout' : 'stderr');
  if (r.ok && !oom) {
    sim.host = ctr.id;
    sim.startedAt = world.clock;
    sim.livenessFailSince = undefined;
    setContainerStatus(p, { imageID: `${ref.split(':')[0].includes('/') ? '' : 'docker.io/library/'}${ref.split(':')[0]}@${img.id}`, containerID: `containerd://${cfg.id}`, started: true, ready: false, state: { running: { startedAt: world.clock } } });
    p.status.phase = 'Running';
    p.status.podIP = ip;
    p.status.startTime ??= world.clock;
    return;
  }
  // The process exited (or was OOM-killed): the container stops and the kubelet restarts it after a back-off.
  delete world.hosts[ctr.id];
  sim.host = undefined;
  const exitCode = oom ? 137 : (r as { exitCode: number }).exitCode;
  const reason = oom ? 'OOMKilled' : exitCode === 0 ? 'Completed' : 'Error';
  terminated(world, st, p, exitCode, reason);
}

/** The container ended: record it, then wait for the back-off (restartPolicy Always / OnFailure) or stay terminated (Never). */
function terminated(world: World, st: Store, p: KObj, exitCode: number, reason: string): void {
  const sim = podSim(p);
  const policy = p.spec.restartPolicy ?? 'Always';
  const cs = p.status.containerStatuses?.[0] ?? {};
  const term = { terminated: { exitCode, reason, startedAt: sim.startedAt ?? world.clock, finishedAt: world.clock } };
  p.status.podIP = p.status.podIP ?? sim.ip;
  if (policy === 'Never' || (policy === 'OnFailure' && exitCode === 0)) {
    setContainerStatus(p, { ready: false, started: false, state: term });
    p.status.phase = exitCode === 0 ? 'Succeeded' : 'Failed';
    return;
  }
  sim.crashes = (sim.crashes ?? 0) + 1;
  sim.nextStart = world.clock + backoffMs(sim.crashes);
  setContainerStatus(p, { ready: false, started: false, lastState: term, state: { waiting: { reason: 'CrashLoopBackOff', message: `back-off ${Math.round(backoffMs(sim.crashes) / 1000)}s restarting failed container=${cs.name ?? containerSpec(p).name} pod=${p.metadata.name}_${objNs(p)}(${p.metadata.uid})` } } });
  p.status.phase = 'Running';
  event(world, st, p, 'Warning', 'BackOff', 'Back-off restarting failed container', 'kubelet');
}

function allocatePodIp(world: World, st: Store, node: (typeof KUBE_NODES)[number]): string {
  const used = new Set(list(st, 'Pod').map((p) => p.status?._sim?.ip).filter(Boolean));
  const base = node.podCidr.split('.').slice(0, 3).join('.');
  for (let i = 2; i < 255; i++) if (!used.has(`${base}.${i}`) && !Object.values(world.hosts).some((h) => h.ifaces.some((f) => f.address === `${base}.${i}`))) return `${base}.${i}`;
  return `${base}.254`;
}

/** One HTTP GET from `from` (the kubelet's probes): the response status, or why there is none. */
export function httpGet(world: World, from: Host, ip: string, port: number, path: string): { code?: number; err?: 'refused' | 'timeout' | 'closed' } {
  const c = tcpConnect(world, from, ip, port, { timeoutMs: 1000 });
  if (!c.ok) return { err: c.errno === 'ECONNREFUSED' ? 'refused' : 'timeout' };
  const server = c.conn.server;
  const listener = allListeners(server).find((l) => l.proto === 'tcp' && l.port === port);
  const app = listener ? httpHooks.apps[listener.process] : undefined;
  const req = { method: 'GET', path, hostHeader: `${ip}:${port}`, plainOnTls: false, now: world.clock, client: { ip: from.ifaces.find((i) => i.name === 'cni0')?.address ?? '', ua: 'kube-probe/1.30' } };
  let res: HttpResponse | undefined;
  if (app) res = app(world, server, req);
  else if (listener?.process === 'nginx' && server.services.nginx?.state === 'active') {
    const srv = selectServer(server.services.nginx.loaded as NginxLoaded, ip, port);
    if (srv) res = handleRequest(server, srv, req, world);
  }
  c.conn.close('client');
  return res ? { code: res.status } : { err: 'closed' };
}

/** Run a probe from the node (HTTP GET, TCP connect or a command in the container); returns null when it passes, else the failure text. */
function runProbe(world: World, p: KObj, probe: J): string | null {
  const sim = podSim(p);
  const key = JSON.stringify(probe);
  if (sim.probeCache?.clock === world.clock && key in sim.probeCache.r) return sim.probeCache.r[key];
  const r = runProbeNow(world, p, probe);
  if (sim.probeCache?.clock !== world.clock) sim.probeCache = { clock: world.clock, r: {} };
  sim.probeCache.r[key] = r;
  return r;
}

function runProbeNow(world: World, p: KObj, probe: J): string | null {
  const ip = p.status.podIP;
  const node = p.spec.nodeName;
  if (!ip) return null;
  const c = containerSpec(p);
  const portOf = (v: unknown) => {
    if (typeof v === 'string' && !/^\d+$/.test(v)) return Number((c.ports ?? []).find((x: J) => x.name === v)?.containerPort ?? 0);
    return Number(v);
  };
  const clock = world.clock;
  try {
    if (probe.httpGet) {
      const port = portOf(probe.httpGet.port);
      const path0 = String(probe.httpGet.path ?? '/');
      const path = path0.startsWith('/') ? path0 : '/' + path0;
      const url = `http://${ip}:${port}${path}`;
      const r = httpGet(world, world.hosts[node], ip, port, path);
      if (r.err === 'refused') return `Get "${url}": dial tcp ${ip}:${port}: connect: connection refused`;
      if (r.err === 'timeout') return `Get "${url}": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`;
      if (r.err === 'closed') return `Get "${url}": EOF`;
      if (!(r.code! >= 200 && r.code! < 400)) return `HTTP probe failed with statuscode: ${r.code}`;
      return null;
    }
    if (probe.tcpSocket) {
      const port = portOf(probe.tcpSocket.port);
      const c = tcpConnect(world, world.hosts[node], ip, port, { timeoutMs: 1000 });
      if (c.ok) { c.conn.close('client'); return null; }
      return c.errno === 'ECONNREFUSED' ? `dial tcp ${ip}:${port}: connect: connection refused` : `dial tcp ${ip}:${port}: i/o timeout`;
    }
    if (probe.exec) {
      const ctr = podCtrHostId(p);
      if (!ctr) return 'container not running';
      const cmd = (probe.exec.command ?? []).map(String);
      const img = findImage(imageRef(String(c.image)));
      if (img && !img.tools.includes(cmd[0]?.split('/').pop() ?? '')) return `OCI runtime exec failed: exec failed: unable to start container process: exec: "${cmd[0]}": executable file not found in $PATH: unknown`;
      const line = cmd[0] === 'sh' && cmd[1] === '-c' ? cmd.slice(2).join(' ') : cmd.map((a: string) => (/^[\w./:=@%+-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(' ');
      if (!kubeHooks.run) return null;
      const r = kubeHooks.run(world, `${ctr}`, line);
      return r.code === 0 ? null : `command ${JSON.stringify(cmd.join(' '))} exited with ${r.code}${r.out.trim() ? `: ${r.out.trim().split('\n')[0]}` : ''}`;
    }
    return null;
  } finally {
    world.clock = clock;
  }
}

function kubelet(world: World, st: Store): void {
  for (const p of list(st, 'Pod').filter((x) => x.spec.nodeName && !x.metadata.deletionTimestamp)) {
    const sim = podSim(p);
    const node = p.spec.nodeName as string;
    if (!nodeReady(world, node)) continue;
    if (['Succeeded', 'Failed'].includes(p.status.phase)) continue;
    const running = sim.host && world.hosts[sim.host];
    if (sim.host && !running) {
      // The container host is gone (the node rebooted): the kubelet starts a new container.
      sim.host = undefined;
      const cs = p.status.containerStatuses?.[0];
      if (cs) setContainerStatus(p, { restartCount: (cs.restartCount ?? 0) + 1, ready: false, state: { waiting: { reason: 'ContainerCreating' } } });
    }
    if (!sim.host) {
      if (sim.nextStart && world.clock < sim.nextStart) continue;
      if (sim.nextStart) {
        const cs = p.status.containerStatuses?.[0];
        setContainerStatus(p, { restartCount: (cs?.restartCount ?? 0) + 1 });
        sim.nextStart = undefined;
      }
      startPod(world, st, p);
      if (!sim.host) continue;
    }
    // The container runs: the process may have died (a service stopped inside), then probes.
    const ctr = world.hosts[sim.host!];
    const main = Object.entries(ctr.services).find(([k]) => ['nginx', 'postgres', 'gunicorn', 'coredns'].includes(k));
    if (main && main[1].state !== 'active') { stopPodContainer(world, p); terminated(world, st, p, 1, 'Error'); continue; }
    const c = containerSpec(p);
    const since = world.clock - (sim.startedAt ?? world.clock);
    if (c.livenessProbe && since >= Number(c.livenessProbe.initialDelaySeconds ?? 0) * 1000) {
      const fail = runProbe(world, p, c.livenessProbe);
      if (fail) {
        sim.livenessFailSince ??= world.clock;
        if (sim.lastLiveness !== fail) event(world, st, p, 'Warning', 'Unhealthy', `Liveness probe failed: ${fail}`, 'kubelet');
        sim.lastLiveness = fail;
        const limit = Number(c.livenessProbe.periodSeconds ?? 10) * Number(c.livenessProbe.failureThreshold ?? 3) * 1000;
        if (world.clock - sim.livenessFailSince >= limit - Number(c.livenessProbe.periodSeconds ?? 10) * 1000) {
          event(world, st, p, 'Normal', 'Killing', `Container ${c.name} failed liveness probe, will be restarted`, 'kubelet');
          stopPodContainer(world, p);
          terminated(world, st, p, 137, 'Error');
          continue;
        }
      } else { sim.livenessFailSince = undefined; sim.lastLiveness = undefined; }
    }
    let ready = true;
    if (c.readinessProbe) {
      if (since < Number(c.readinessProbe.initialDelaySeconds ?? 0) * 1000) ready = false;
      else {
        const fail = runProbe(world, p, c.readinessProbe);
        if (fail) {
          ready = false;
          if (sim.lastReadiness !== fail) event(world, st, p, 'Warning', 'Unhealthy', `Readiness probe failed: ${fail}`, 'kubelet');
          sim.lastReadiness = fail;
        } else sim.lastReadiness = undefined;
      }
    }
    // A container that keeps running long enough resets its crash back-off.
    if (since > 600_000) sim.crashes = 0;
    setContainerStatus(p, { ready });
  }
  // Pod conditions.
  for (const p of list(st, 'Pod').filter((x) => x.spec.nodeName)) {
    const ready = isPodReady(p);
    const cs = p.status.containerStatuses?.[0];
    const conds = [
      { type: 'PodReadyToStartContainers', status: p.status._sim?.ip ? 'True' : 'False' },
      { type: 'Initialized', status: 'True' },
      { type: 'Ready', status: ready ? 'True' : 'False', ...(ready ? {} : { reason: 'ContainersNotReady', message: `containers with unready status: [${cs?.name ?? containerSpec(p).name}]` }) },
      { type: 'ContainersReady', status: ready ? 'True' : 'False', ...(ready ? {} : { reason: 'ContainersNotReady', message: `containers with unready status: [${cs?.name ?? containerSpec(p).name}]` }) },
      { type: 'PodScheduled', status: 'True' },
    ];
    p.status.conditions = conds;
  }
}

// ---------------------------------------------------------------------------
// Services: ClusterIP allocation, endpoints, kube-proxy rules
// ---------------------------------------------------------------------------

export function allocateClusterIp(st: Store, seed: string): string {
  const used = new Set(list(st, 'Service').map((s) => s.spec.clusterIP));
  const h = sha256Hex(seed);
  for (let k = 0; k < 200; k++) {
    const a = (parseInt(h.slice(k % 56, (k % 56) + 4), 16) + k * 97) % 65000;
    const ip = `10.43.${Math.floor(a / 254) % 256}.${(a % 254) + 1}`;
    if (!used.has(ip) && ip !== DNS_IP && ip !== '10.43.0.1') return ip;
  }
  return '10.43.255.250';
}

export function allocateNodePort(st: Store, seed: string): number {
  const used = new Set(list(st, 'Service').flatMap((s) => (s.spec.ports ?? []).map((p: J) => Number(p.nodePort))));
  let n = 30000 + (parseInt(sha256Hex(seed).slice(0, 6), 16) % 2768);
  while (used.has(n)) n = n === 32767 ? 30000 : n + 1;
  return n;
}

function targetPortOf(svcPort: J, pod: KObj): number {
  const tp = svcPort.targetPort ?? svcPort.port;
  if (typeof tp === 'string' && !/^\d+$/.test(tp)) {
    const named = (pod.spec.containers ?? []).flatMap((c: J) => c.ports ?? []).find((x: J) => x.name === tp);
    return named ? Number(named.containerPort) : NaN;
  }
  return Number(tp);
}

function reconcileEndpoints(world: World, st: Store): void {
  for (const s of list(st, 'Service')) {
    if (!s.spec.selector) continue;
    const pods = list(st, 'Pod', objNs(s)).filter((p) => matchLabels(s.spec.selector, p.metadata.labels) && p.status?.podIP && !p.metadata.deletionTimestamp);
    const subsets = {
      addresses: pods.filter(isPodReady).sort((a, b) => a.metadata.name.localeCompare(b.metadata.name)).map((p) => ({ ip: p.status.podIP, nodeName: p.spec.nodeName, targetRef: { kind: 'Pod', name: p.metadata.name } })),
      notReadyAddresses: pods.filter((p) => !isPodReady(p)).map((p) => ({ ip: p.status.podIP, nodeName: p.spec.nodeName, targetRef: { kind: 'Pod', name: p.metadata.name } })),
      ports: (s.spec.ports ?? []).map((sp: J) => ({ name: sp.name, port: pods[0] ? targetPortOf(sp, pods[0]) : Number(sp.targetPort ?? sp.port), protocol: sp.protocol ?? 'TCP' })),
    };
    let ep = find(st, 'Endpoints', objNs(s), s.metadata.name);
    if (!ep) ep = addObject(world, st, { apiVersion: 'v1', kind: 'Endpoints', metadata: { name: s.metadata.name, namespace: objNs(s), uid: '', creationTimestamp: 0, labels: s.metadata.labels }, data: undefined, spec: undefined, status: undefined });
    (ep as J).subsets = subsets.addresses.length || subsets.notReadyAddresses.length ? [subsets] : [];
  }
  // Endpoints of deleted services go with them.
  for (const ep of list(st, 'Endpoints')) if (!find(st, 'Service', objNs(ep), ep.metadata.name)) removeObject(st, ep);
}

/** kube-proxy's rules (nftables mode): DNAT ClusterIP and NodePort traffic to the first ready endpoint; reject services without endpoints. */
export function kubeProxyRules(st: Store, nodeIp: string): string {
  const dnat: string[] = [];
  const reject: string[] = [];
  for (const s of list(st, 'Service')) {
    const ep = find(st, 'Endpoints', objNs(s), s.metadata.name) as J;
    const first = ep?.subsets?.[0]?.addresses?.[0];
    for (const sp of s.spec.ports ?? []) {
      const proto = String(sp.protocol ?? 'TCP').toLowerCase();
      const portIdx = (s.spec.ports ?? []).indexOf(sp);
      const tport = ep?.subsets?.[0]?.ports?.[portIdx]?.port;
      const comment = `comment "${objNs(s)}/${s.metadata.name}${sp.name ? ':' + sp.name : ''}"`;
      const targets = [`ip daddr ${s.spec.clusterIP} ${proto} dport ${sp.port}`];
      if (s.spec.type === 'NodePort' && sp.nodePort) targets.push(`ip daddr ${nodeIp} ${proto} dport ${sp.nodePort}`);
      for (const m of targets) {
        if (first && Number.isFinite(tport)) dnat.push(`\t\t${m} dnat to ${first.ip}:${tport} ${comment}`);
        else reject.push(`\t\t${m} reject ${comment}`);
      }
    }
  }
  return `table ip kube-proxy {
\tchain filter-input {
\t\ttype filter hook input priority -110; policy accept;
${reject.join('\n')}
\t}
\tchain filter-forward {
\t\ttype filter hook forward priority -110; policy accept;
${reject.join('\n')}
\t}
\tchain filter-output {
\t\ttype filter hook output priority -110; policy accept;
${reject.join('\n')}
\t}
\tchain nat-prerouting {
\t\ttype nat hook prerouting priority dstnat; policy accept;
${dnat.join('\n')}
\t}
\tchain nat-output {
\t\ttype nat hook output priority -100; policy accept;
${dnat.join('\n')}
\t}
\tchain nat-postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname "cni0" masquerade comment "SNAT traffic routed to pods (service and hairpin traffic)"
\t}
}
`.replace(/\n\n/g, '\n');
}

function syncKubeProxy(world: World, st: Store): void {
  for (const n of KUBE_NODES) {
    const h = world.hosts[n.id];
    if (!h) continue;
    const want = nodeReady(world, n.id) ? kubeProxyRules(st, n.ip) : '';
    const has = h.nft?.tables.some((t) => t.family === 'ip' && t.name === 'kube-proxy');
    if (h.kubeProxyRules === want && (has || !want)) continue;
    h.kubeProxyRules = want;
    const rs: Ruleset = h.nft ?? emptyRuleset();
    rs.tables = rs.tables.filter((t) => !(t.family === 'ip' && t.name === 'kube-proxy'));
    if (want) {
      const parsed = parseRulesetFile(want, 'kube-proxy');
      for (const tb of parsed.tables) {
        tb.handle = rs.nextHandle++;
        for (const ch of tb.chains) { ch.handle = rs.nextHandle++; for (const r of ch.rules) r.handle = rs.nextHandle++; }
        rs.tables.push(tb);
      }
    }
    h.nft = rs;
  }
}

// ---------------------------------------------------------------------------
// The reconcile loop
// ---------------------------------------------------------------------------

function reconcile(world: World, st: Store): void {
  syncNodes(world, st);
  const snap = () => JSON.stringify(st.objects.map((o) => [o.metadata.uid, o.spec?.replicas, o.spec?.nodeName, o.status?.phase, o.status?.containerStatuses?.[0]?.ready, o.status?.containerStatuses?.[0]?.state]));
  for (let pass = 0; pass < 6; pass++) {
    const before = snap();
    reconcileDeployments(world, st);
    reconcileReplicaSets(world, st);
    schedule(world, st);
    kubelet(world, st);
    reconcileEndpoints(world, st);
    if (before === snap()) break;
  }
  syncKubeProxy(world, st);
}

/**
 * Bring the cluster up to the current time: the controllers and kubelets run
 * every 5 s of simulated time since the last look (so a crashing container has
 * restarted with its back-off while the learner was doing something else).
 */
export function kubeTick(world: World): void {
  const server = kubeServer(world);
  if (!server || server.services.k3s?.state !== 'active') {
    // Without the API server nothing reconciles, but kube-proxy rules stay as they were.
    return;
  }
  const st = loadStore(world);
  const now = world.clock;
  const last = st.lastTick ?? now;
  // At most 15 minutes are replayed step by step; a longer gap jumps ahead.
  let t = Math.max(last, now - 15 * 60_000);
  while (t + 5000 < now) {
    t += 5000;
    world.clock = t;
    reconcile(world, st);
  }
  world.clock = now;
  reconcile(world, st);
  st.lastTick = now;
  saveStore(world, st);
}

/** Let the cluster run for `ms` of simulated time (back-offs expire, rollouts progress). */
export function kubeWait(world: World, ms: number): void {
  world.clock += ms;
  kubeTick(world);
}

// ---------------------------------------------------------------------------
// CoreDNS: cluster names for pods
// ---------------------------------------------------------------------------

function coreDnsUp(world: World): boolean {
  if (kubeServer(world)?.services.k3s?.state !== 'active') return false;
  const st = loadStore(world);
  const ep = find(st, 'Endpoints', 'kube-system', 'kube-dns') as J;
  return !!ep?.subsets?.[0]?.addresses?.length;
}

const prevEmbedded = dnsHooks.embedded;
dnsHooks.embedded = (world: World, host: Host, server: string, qname: string, qtype): DnsExchange | null => {
  if (server !== DNS_IP) return prevEmbedded?.(world, host, server, qname, qtype) ?? null;
  const inCluster = !!host.container?.pod || KUBE_NODES.some((n) => n.id === host.id);
  if (!inCluster) return null;
  if (!coreDnsUp(world)) return { server, qname, outcome: 'timeout', rttMs: 5000 };
  const name = qname.toLowerCase().replace(/\.$/, '');
  const m = /^([a-z0-9-]+)\.([a-z0-9-]+)\.svc\.cluster\.local$/.exec(name);
  if (m) {
    const st = loadStore(world);
    const svc = find(st, 'Service', m[2], m[1]);
    if (!svc) return { server, qname, outcome: 'nxdomain', rttMs: 1, answer: { rcode: 'NXDOMAIN', authoritative: true, answers: [] } };
    if (qtype !== 'A') return { server, qname, outcome: 'nodata', rttMs: 1, answer: { rcode: 'NOERROR', authoritative: true, answers: [] } };
    return { server, qname, outcome: 'answer', rttMs: 1, answer: { rcode: 'NOERROR', authoritative: true, answers: [{ name: `${name}.`, ttl: 5, type: 'A', data: svc.spec.clusterIP }] } };
  }
  if (name.endsWith('cluster.local')) return { server, qname, outcome: 'nxdomain', rttMs: 1, answer: { rcode: 'NXDOMAIN', authoritative: true, answers: [] } };
  // Everything else: CoreDNS forwards to the node's resolvers (forward . /etc/resolv.conf).
  const node = world.hosts[KUBE_SERVER];
  const ns = node ? resolverConf(node).nameservers[0] : undefined;
  if (!node || !ns) return { server, qname, outcome: 'servfail', rttMs: 1 };
  const ex = dnsQuery(world, node, ns, qname, 5, qtype);
  return { ...ex, server };
};

// ---------------------------------------------------------------------------
// k3s services (server and agent) on the nodes
// ---------------------------------------------------------------------------

function nodeSetup(world: World, host: Host): void {
  const n = KUBE_NODES.find((x) => x.id === host.id)!;
  const seg = `docker:${host.id}:cni0`;
  world.segments[seg] = { id: seg, name: `${host.hostname} cni0`, cidr: n.podCidr };
  const prefix = Number(n.podCidr.split('/')[1]);
  const existing = host.ifaces.find((i) => i.name === 'cni0');
  const iface = existing ?? { name: 'cni0', mac: `02:42:${sha256Hex(host.id).slice(0, 2)}:${sha256Hex(host.id).slice(2, 4)}:${sha256Hex(host.id).slice(4, 6)}:01`, segment: seg, address: null, prefix: null, up: false, addrs6: [], staticSegment: seg };
  Object.assign(iface, { segment: seg, staticSegment: seg, address: n.gw, prefix, up: true });
  if (!existing) host.ifaces.push(iface);
  host.ipForward = true;
  // flannel host-gw: the other nodes' pod subnets via those nodes.
  host.routes = host.routes.filter((r) => !r.dest.startsWith('10.42.'));
  for (const o of KUBE_NODES.filter((x) => x.id !== host.id && world.hosts[x.id])) host.routes.push({ dest: o.podCidr, via: o.ip, dev: 'eth0', proto: 'boot' });
}

function nodeTeardown(world: World, host: Host): void {
  // Stopping k3s leaves the containers running (as with containerd); a reboot removes them.
  host.nft.tables = host.nft.tables.filter((t) => !(t.family === 'ip' && t.name === 'kube-proxy'));
  void world;
}

const k3sServer: ServiceDef = {
  name: 'k3s',
  unit: 'k3s.service',
  aliases: ['k3s', 'k3s.service'],
  description: 'Lightweight Kubernetes',
  configFiles: ['/etc/rancher/k3s/config.yaml'],
  start(world, host, rt) {
    host.nextPid += 11;
    rt.pid = host.nextPid;
    nodeSetup(world, host);
    log(world, host, 'k3s', `time="${new Date(world.clock).toISOString()}" level=info msg="Starting k3s ${K3S_VERSION} (bc6ec0ac)"`, { pid: rt.pid, unit: 'k3s.service' });
    log(world, host, 'k3s', `time="${new Date(world.clock).toISOString()}" level=info msg="Running kube-apiserver --advertise-address=${KUBE_NODES[0].ip} --service-cluster-ip-range=${SERVICE_CIDR} ..."`, { pid: rt.pid, unit: 'k3s.service' });
    log(world, host, 'k3s', `time="${new Date(world.clock).toISOString()}" level=info msg="k3s is up and running"`, { pid: rt.pid, unit: 'k3s.service' });
    rt.state = 'active';
    // Pods whose containers were removed by a reboot are restarted on the next reconcile.
    kubeTick(world);
    return true;
  },
  stop(world, host) { nodeTeardown(world, host); },
  listeners(_host, rt) {
    const pid = rt.pid ?? 0;
    return [
      { proto: 'tcp', addr: '0.0.0.0', port: 6443, process: 'k3s-server', pid, service: 'k3s' },
      { proto: 'tcp', addr: '0.0.0.0', port: 10250, process: 'k3s-server', pid, service: 'k3s' },
      { proto: 'tcp', addr: '127.0.0.1', port: 10248, process: 'k3s-server', pid, service: 'k3s' },
      { proto: 'tcp', addr: '127.0.0.1', port: 6444, process: 'k3s-server', pid, service: 'k3s' },
    ];
  },
};

const k3sAgent: ServiceDef = {
  name: 'k3s-agent',
  unit: 'k3s-agent.service',
  aliases: ['k3s-agent', 'k3s-agent.service'],
  description: 'Lightweight Kubernetes',
  configFiles: ['/etc/rancher/k3s/config.yaml'],
  start(world, host, rt) {
    host.nextPid += 11;
    rt.pid = host.nextPid;
    const server = kubeServer(world);
    if (!server || server.services.k3s?.state !== 'active') {
      log(world, host, 'k3s', `time="${new Date(world.clock).toISOString()}" level=info msg="Waiting to retrieve agent configuration; server is not ready: Get \\"https://${KUBE_NODES[0].ip}:6443/v1-k3s/serving-kubelet.crt\\": dial tcp ${KUBE_NODES[0].ip}:6443: connect: connection refused"`, { pid: rt.pid, unit: 'k3s-agent.service', priority: 'err' });
    }
    nodeSetup(world, host);
    log(world, host, 'k3s', `time="${new Date(world.clock).toISOString()}" level=info msg="Starting k3s agent ${K3S_VERSION} (bc6ec0ac)"`, { pid: rt.pid, unit: 'k3s-agent.service' });
    rt.state = 'active';
    kubeTick(world);
    return true;
  },
  stop(world, host) { nodeTeardown(world, host); },
  listeners(_host, rt) {
    const pid = rt.pid ?? 0;
    return [
      { proto: 'tcp', addr: '0.0.0.0', port: 10250, process: 'k3s-agent', pid, service: 'k3s-agent' },
      { proto: 'tcp', addr: '127.0.0.1', port: 6444, process: 'k3s-agent', pid, service: 'k3s-agent' },
    ];
  },
};

SERVICE_DEFS.push(k3sServer, k3sAgent);
