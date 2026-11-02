// A k3s cluster on the server VLAN: kube01 (server: control plane and
// workloads) on sw01 swp24 and kube02 (agent) on swp25, both Debian 12. The
// team's images are in the nodes' containerd stores; CoreDNS runs in
// kube-system. ws01 has kubectl with alice's kubeconfig for the API server
// (https://kube01.corp.lab:6443). Built on demand (buildKubeLab): the other
// tickets and labs do not carry the cluster.

import { mkdir, readFile, writeFile } from '../fs';
import { recomputeL2 } from '../sim/l2';
import { bootHost } from '../sim/services';
import { addObject, DNS_IP, KUBE_NODES, KUBECONFIG_PATH, kubeTick, loadStore, saveStore, savePulled, type KObj, type Store } from '../sim/k8s';
import { script } from '../scenarios/engine';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { trustCorpRoot } from './pkiLab';
import { buildSshLab, DEBIAN_SSHD_CONFIG, installHostKeys, SW01_INTERFACES } from './sshLab';

export const KUBE01_IP = KUBE_NODES[0].ip;
export const KUBE02_IP = KUBE_NODES[1].ip;
export const KUBE_ALICE_PASSWORD = 'kube01-alice';
const SWITCH_PORTS: Record<string, string> = { kube01: 'swp24', kube02: 'swp25' };

/** A kubeconfig for the cluster (k3s writes the admin one to /etc/rancher/k3s/k3s.yaml). */
export function kubeconfig(server: string, user = 'default', namespace?: string): string {
  return `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkekNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnkKZG1WeUxXTmhRREUzTXpBd05qQXdOVEF3SGhjTk1qUXhNREk0TVRVek5ERXdXaGNOTXpReE1ESTJNVFV6TkRFdwpXakFqTVNFd0h3WURWUVFEREJock0zTXRjMlZ5ZG1WeUxXTmhRREUzTXpBd05qQXdOVEF3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFRCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    server: ${server}
  name: default
contexts:
- context:
    cluster: default
${namespace ? `    namespace: ${namespace}\n` : ''}    user: ${user}
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: ${user}
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJrVENDQVRlZ0F3SUJBZ0lJWUt5T3c5S0l
    client-key-data: LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUdrc3k4
`;
}

function mkdirs(h: Host, path: string, t: number, opts?: { mode?: number; owner?: string; group?: string }): void {
  const parts = path.split('/').slice(1);
  for (let k = 1; k <= parts.length; k++) { const d = '/' + parts.slice(0, k).join('/'); if (!h.fs[d]) mkdir(h, d, t, k === parts.length ? opts : undefined); }
}

function installNode(world: World, n: (typeof KUBE_NODES)[number]): Host {
  const t = world.clock;
  const server = n.id === 'kube01';
  const port = SWITCH_PORTS[n.id];
  const sw = world.hosts.sw01;
  sw.ifaces.push({ name: port, mac: `52:54:00:5e:00:${port === 'swp24' ? '18' : '19'}`, segment: null, address: null, prefix: null, up: false, staticSegment: null, addrs6: [] });
  const swConf = readFile(sw, '/etc/network/interfaces') ?? SW01_INTERFACES;
  writeFile(sw, '/etc/network/interfaces', swConf
    .replace('auto br0\n', `auto ${port}\niface ${port}\n    alias ${n.id} (Kubernetes ${server ? 'server' : 'agent'})\n    bridge-access 20\n\nauto br0\n`)
    .replace(/(bridge-ports .*)\n/, `$1 ${port}\n`), t);
  world.links = [...(world.links ?? []), { a: { host: n.id, iface: 'eth0' }, b: { host: 'sw01', iface: port } }];
  const h = createHost(world, {
    id: n.id, hostname: n.id, domain: 'corp.lab', role: server ? 'Kubernetes server (k3s: control plane and workloads)' : 'Kubernetes agent (k3s worker)',
    ifaces: [{ name: 'eth0', mac: n.mac, segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'ssh', server ? 'k3s' : 'k3s-agent'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${n.ip}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: KUBE_ALICE_PASSWORD }, t);
  // k3s: one binary; kubectl, crictl and ctr are links to it.
  mkdirs(h, '/usr/local/bin', t);
  for (const b of ['k3s', 'kubectl', 'crictl', 'ctr']) writeFile(h, `/usr/local/bin/${b}`, b === 'k3s' ? '' : '-> k3s', t, { mode: 0o755 });
  mkdirs(h, '/etc/rancher/k3s', t);
  writeFile(h, '/etc/rancher/k3s/config.yaml', server
    ? `# k3s server configuration (CHG-4120)\nwrite-kubeconfig-mode: "0600"\ntls-san:\n  - kube01.corp.lab\nflannel-backend: host-gw\ndisable:\n  - traefik\n  - servicelb\n  - metrics-server\n  - local-storage\n`
    : `# k3s agent configuration (CHG-4120)\nserver: https://kube01.corp.lab:6443\ntoken-file: /etc/rancher/k3s/token\n`, t);
  if (server) writeFile(h, KUBECONFIG_PATH, kubeconfig('https://127.0.0.1:6443'), t, { mode: 0o600 });
  else writeFile(h, '/etc/rancher/k3s/token', 'K10f4b2c9d1e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1::server:3c9e2b7a1f6d4e8c\n', t, { mode: 0o600 });
  mkdirs(h, '/var/lib/rancher/k3s/agent/containerd', t, { mode: 0o700 });
  savePulled(world, h, ['nginx:1.25', 'postgres:16', 'corp/inventory:1.4', 'busybox:1.36', 'rancher/mirrored-coredns-coredns:1.11.3']);
  return h;
}

function systemObjects(world: World, st: Store): void {
  const t = world.clock;
  const meta = (name: string, namespace?: string, labels?: Record<string, string>) => ({ name, namespace, uid: '', creationTimestamp: t, labels });
  for (const ns of ['default', 'kube-system', 'kube-public', 'kube-node-lease']) addObject(world, st, { apiVersion: 'v1', kind: 'Namespace', metadata: meta(ns, undefined, { 'kubernetes.io/metadata.name': ns }), spec: { finalizers: ['kubernetes'] }, status: { phase: 'Active' } });
  addObject(world, st, { apiVersion: 'v1', kind: 'Service', metadata: meta('kubernetes', 'default', { component: 'apiserver', provider: 'kubernetes' }), spec: { type: 'ClusterIP', clusterIP: '10.43.0.1', ports: [{ name: 'https', port: 443, protocol: 'TCP', targetPort: 6443 }] }, status: {} });
  const ep: KObj = { apiVersion: 'v1', kind: 'Endpoints', metadata: meta('kubernetes', 'default', { 'endpointslice.kubernetes.io/skip-mirror': 'true' }) };
  (ep as { subsets?: unknown }).subsets = [{ addresses: [{ ip: KUBE01_IP }], notReadyAddresses: [], ports: [{ name: 'https', port: 6443, protocol: 'TCP' }] }];
  addObject(world, st, ep);
  addObject(world, st, { apiVersion: 'v1', kind: 'ConfigMap', metadata: meta('coredns', 'kube-system'), data: { Corefile: '.:53 {\n    errors\n    health\n    ready\n    kubernetes cluster.local in-addr.arpa ip6.arpa {\n      pods insecure\n      fallthrough in-addr.arpa ip6.arpa\n    }\n    prometheus :9153\n    forward . /etc/resolv.conf\n    cache 30\n    loop\n    reload\n    loadbalance\n}\n' } });
  addObject(world, st, {
    apiVersion: 'apps/v1', kind: 'Deployment', metadata: { ...meta('coredns', 'kube-system', { 'k8s-app': 'kube-dns', 'kubernetes.io/name': 'CoreDNS' }), generation: 1 },
    spec: {
      replicas: 1, revisionHistoryLimit: 0, progressDeadlineSeconds: 600, selector: { matchLabels: { 'k8s-app': 'kube-dns' } },
      strategy: { type: 'RollingUpdate', rollingUpdate: { maxSurge: '25%', maxUnavailable: 1 } },
      template: { metadata: { labels: { 'k8s-app': 'kube-dns' } }, spec: {
        nodeSelector: { 'kubernetes.io/os': 'linux' }, tolerations: [{ key: 'CriticalAddonsOnly', operator: 'Exists' }, { key: 'node-role.kubernetes.io/control-plane', operator: 'Exists', effect: 'NoSchedule' }],
        containers: [{ name: 'coredns', image: 'rancher/mirrored-coredns-coredns:1.11.3', args: ['-conf', '/etc/coredns/Corefile'], ports: [{ name: 'dns', containerPort: 53, protocol: 'UDP' }, { name: 'dns-tcp', containerPort: 53, protocol: 'TCP' }, { name: 'metrics', containerPort: 9153, protocol: 'TCP' }], resources: { requests: { cpu: '100m', memory: '70Mi' }, limits: { memory: '170Mi' } }, volumeMounts: [{ name: 'config-volume', mountPath: '/etc/coredns' }] }],
        volumes: [{ name: 'config-volume', configMap: { name: 'coredns' } }], restartPolicy: 'Always', dnsPolicy: 'Default',
      } },
    },
    status: {},
  });
  addObject(world, st, { apiVersion: 'v1', kind: 'Service', metadata: meta('kube-dns', 'kube-system', { 'k8s-app': 'kube-dns', 'kubernetes.io/name': 'CoreDNS' }), spec: { type: 'ClusterIP', clusterIP: DNS_IP, selector: { 'k8s-app': 'kube-dns' }, ports: [{ name: 'dns', port: 53, protocol: 'UDP', targetPort: 53 }, { name: 'dns-tcp', port: 53, protocol: 'TCP', targetPort: 53 }, { name: 'metrics', port: 9153, protocol: 'TCP', targetPort: 9153 }] }, status: {} });
}

/** Add the cluster to a world built by buildSshLab: cable and boot the nodes, add DNS names and kubectl on ws01. */
export function installKube(world: World): void {
  const t0 = world.clock;
  const nodes = KUBE_NODES.map((n) => installNode(world, n));
  recomputeL2(world);
  script(world, 'sw01', ['ifreload -a']);
  // DNS: kube01 and kube02 in corp.lab.
  const ns1 = world.hosts.ns1;
  const zone = readFile(ns1, '/etc/bind/db.corp.lab') ?? '';
  const bumped = zone.replace(/(\d{10})(\s*;\s*serial)/, (_m, n: string, rest: string) => `${Number(n) + 1}${rest}`);
  writeFile(ns1, '/etc/bind/db.corp.lab', `${bumped.trimEnd()}\nkube01  IN A    ${KUBE01_IP}\nkube02  IN A    ${KUBE02_IP}\n`, world.clock);
  script(world, 'ns1', ['rndc reload corp.lab']);
  // The datastore: system namespaces, the kubernetes and kube-dns Services, CoreDNS.
  world.clock = Math.max(world.clock, t0) + 60_000;
  const st = loadStore(world);
  if (!st.objects.length) systemObjects(world, st);
  saveStore(world, st);
  for (const h of nodes) bootHost(world, h);
  // A few seconds pass: CoreDNS is scheduled, created and becomes ready.
  for (let i = 0; i < 4; i++) { world.clock += 3000; kubeTick(world); }
  // ws01: kubectl (Debian package) with alice's kubeconfig for the API server.
  const ws = world.hosts.ws01;
  mkdirs(ws, '/usr/local/bin', world.clock);
  writeFile(ws, '/usr/local/bin/kubectl', '', world.clock, { mode: 0o755 });
  mkdirs(ws, '/home/alice/.kube', world.clock, { mode: 0o700, owner: 'alice', group: 'alice' });
  writeFile(ws, '/home/alice/.kube/config', kubeconfig('https://kube01.corp.lab:6443', 'alice'), world.clock, { mode: 0o600, owner: 'alice', group: 'alice' });
}

/** The standard lab plus the Kubernetes cluster. */
export function buildKubeLab(): World {
  const world = buildSshLab();
  installKube(world);
  return world;
}
