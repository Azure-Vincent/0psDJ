// Kubernetes tickets on the k3s cluster (kube01, kube02): the inventory
// application (corp/inventory API and PostgreSQL) runs in the namespace
// "inventory", deployed from the manifests in /srv/k8s/inventory, and users
// reach it on NodePort 30800 of either node. Each ticket breaks it the way it
// breaks in production: a Service whose selector matches nothing, a wrong
// targetPort, a readiness probe on the wrong path, a Secret renamed during a
// rotation, CoreDNS scaled away, a memory limit below what PostgreSQL needs,
// and a release with an image tag that was never pushed.

import { mkdir, readFile, writeFile } from '../fs';
import { installKube } from '../lab/kubeLab';
import { b64encode, find, kubeTick, list, loadStore } from '../sim/k8s';
import type { World } from '../types';
import { script } from './engine';
import type { CommandGoal, Constraint, HttpGoal, Scenario } from './types';

export const K8S_APP_DIR = '/srv/k8s/inventory';
export const K8S_DB_PASSWORD = 'Inv-K8s-2026';
const B64 = b64encode;

export const NS_YAML = `apiVersion: v1
kind: Namespace
metadata:
  name: inventory
`;

export const SECRET_YAML = (name = 'inventory-db', password = K8S_DB_PASSWORD) => `# Database credentials (the password is base64-encoded, not encrypted).
apiVersion: v1
kind: Secret
metadata:
  name: ${name}
  namespace: inventory
type: Opaque
data:
  password: ${B64(password)}
`;

export const DB_YAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: db
  namespace: inventory
spec:
  replicas: 1
  strategy:
    type: Recreate          # one database pod at a time
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
      - name: postgres
        image: postgres:16
        env:
        - name: POSTGRES_USER
          value: inventory
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: inventory-db
              key: password
        ports:
        - containerPort: 5432
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            memory: 256Mi
        readinessProbe:
          tcpSocket:
            port: 5432
---
apiVersion: v1
kind: Service
metadata:
  name: db
  namespace: inventory
spec:
  selector:
    app: db
  ports:
  - port: 5432
    targetPort: 5432
`;

export const API_YAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: inventory
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: corp/inventory:1.4
        env:
        - name: DB_HOST
          value: db
        - name: DB_USER
          value: inventory
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: inventory-db
              key: password
        ports:
        - containerPort: 8000
        resources:
          requests:
            cpu: 100m
            memory: 192Mi
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
`;

export const API_SVC_YAML = `# Users reach the API on port 30800 of any node (http://kube01.corp.lab:30800/).
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: inventory
spec:
  type: NodePort
  selector:
    app: api
  ports:
  - port: 80
    targetPort: 8000
    nodePort: 30800
`;

const FILES: [string, string][] = [['00-namespace.yaml', NS_YAML], ['10-secret.yaml', SECRET_YAML()], ['20-db.yaml', DB_YAML], ['30-api.yaml', API_YAML], ['31-api-svc.yaml', API_SVC_YAML]];

/** The cluster plus the inventory application, deployed and running for a while. */
export function deployK8sInventory(world: World, files: [string, string][] = FILES): void {
  // Already deployed (a chained ticket applies a second fault to the same cluster): only time passes.
  if (world.hosts.kube01 && find(loadStore(world), 'Namespace', '', 'inventory')) {
    world.clock += 3600_000;
    kubeTick(world);
    return;
  }
  installKube(world);
  const h = world.hosts.kube01;
  for (const d of ['/srv', '/srv/k8s', K8S_APP_DIR]) if (!h.fs[d]) mkdir(h, d, world.clock);
  for (const [f, text] of files) writeFile(h, `${K8S_APP_DIR}/${f}`, text, world.clock, f.includes('secret') ? { mode: 0o600 } : undefined);
  script(world, 'kube01', [`kubectl apply -f ${K8S_APP_DIR}/`], 10_000);
  // The application has been running for an hour.
  for (let i = 0; i < 12; i++) { world.clock += 5_000; kubeTick(world); }
  world.clock += 3600_000;
  kubeTick(world);
}

/** Change one manifest as the colleague did, and apply it. */
function change(world: World, file: string, edit: (s: string) => string, extra: string[] = []): void {
  const h = world.hosts.kube01;
  world.clock += 1800_000;
  kubeTick(world);
  writeFile(h, `${K8S_APP_DIR}/${file}`, edit(readFile(h, `${K8S_APP_DIR}/${file}`) ?? ''), world.clock);
  script(world, 'kube01', [`kubectl apply -f ${K8S_APP_DIR}/${file}`, ...extra], 20_000);
  for (let i = 0; i < 8; i++) { world.clock += 15_000; kubeTick(world); }
}

export const K8S_API_CHECK: HttpGoal = {
  kind: 'http', fromHost: 'ws01', fromUser: 'alice', url: 'http://kube01.corp.lab:30800/health',
  description: 'From ws01, http://kube01.corp.lab:30800/health answers 200 (the API runs, is Ready and reaches its database).',
};

const rolledOut = (dep: string): CommandGoal => ({
  kind: 'command',
  description: `The ${dep} Deployment is fully rolled out: kubectl rollout status deploy/${dep} -n inventory succeeds.`,
  steps: [{ host: 'kube01', user: 'root', command: `kubectl rollout status deploy/${dep} -n inventory --timeout=10s` }],
  expect: 'successfully rolled out',
});

function k8sConstraint(id: string, description: string, test: (st: ReturnType<typeof loadStore>) => string | null): Constraint {
  return {
    id, required: true, description,
    check(world: World) {
      const st = loadStore(world);
      const bad = test(st);
      return bad ? { id, ok: false, required: true, message: bad } : { id, ok: true, required: true, message: description };
    },
  };
}

const NODEPORT_KEPT = k8sConstraint('nodeport-30800', 'The api Service still publishes NodePort 30800 (users and the monitoring check use it).', (st) => {
  const s = find(st, 'Service', 'inventory', 'api');
  return s?.spec.type === 'NodePort' && (s.spec.ports ?? []).some((p: { nodePort?: number }) => Number(p.nodePort) === 30800) ? null : 'The api Service no longer publishes NodePort 30800.';
});

const TWO_REPLICAS = k8sConstraint('api-replicas', 'The api Deployment keeps 2 replicas (one may fail without an outage).', (st) => {
  const d = find(st, 'Deployment', 'inventory', 'api');
  return Number(d?.spec.replicas ?? 0) >= 2 ? null : 'The api Deployment has fewer than 2 replicas.';
});

const PASSWORD_FROM_SECRET = k8sConstraint('password-in-secret', 'The database password stays in a Secret (secretKeyRef), not written into a Deployment.', (st) => {
  for (const d of list(st, 'Deployment', 'inventory')) {
    for (const c of d.spec.template?.spec?.containers ?? []) {
      for (const e of c.env ?? []) if (/PASSWORD/.test(e.name) && e.value !== undefined) return `${d.metadata.name}: ${e.name} is a plain value in the Deployment.`;
    }
  }
  return null;
});

const BRIEFING = [
  'The k3s cluster: kube01 (10.0.20.90, server and worker) and kube02 (10.0.20.91, worker). Root on kube01 has kubectl (admin); alice on ws01 has kubectl with her kubeconfig (~/.kube/config → https://kube01.corp.lab:6443).',
  'The inventory application runs in the namespace "inventory", deployed from /srv/k8s/inventory on kube01 (kubectl apply -f /srv/k8s/inventory/): Deployment "api" (corp/inventory:1.4, 2 replicas, gunicorn on 8000, /health answers 200 only when the database is reachable) and Deployment "db" (postgres:16), Services "api" (NodePort 30800 → 8000) and "db" (ClusterIP, 5432), Secret "inventory-db".',
  'Users open http://kube01.corp.lab:30800/ (any node\'s address works for a NodePort).',
  'Work with kubectl: get, describe (read the Events), logs (--previous), exec, get endpoints; change the manifests in /srv/k8s/inventory and kubectl apply them, so the fix is in the files too. Fixes must survive a reboot of the nodes.',
];

const TERMINALS = [
  { hostId: 'kube01', user: 'root', label: 'kube01 (root)', banner: 'kube01: k3s server, logged in as root. Manifests in /srv/k8s/inventory. Try: kubectl get all -n inventory, kubectl get pods -n inventory -o wide, kubectl describe pod -n inventory -l app=api, kubectl get endpoints -n inventory, kubectl get events -n inventory.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01: a user\'s view, with kubectl. Try: curl -sS -i http://kube01.corp.lab:30800/health, kubectl get pods -n inventory.' },
  { hostId: 'kube02', user: 'root', label: 'kube02 (root)', banner: 'kube02: k3s agent (worker), root. Try: systemctl status k3s-agent, crictl ps -a, nft list table ip kube-proxy.' },
];

const CANDIDATES = ['k8s-selector-mismatch', 'k8s-target-port', 'k8s-readiness-probe', 'k8s-missing-secret', 'k8s-dns-down', 'k8s-oom-limit', 'k8s-bad-image', 'k8s-node-notready', 'k8s-pending-resources', 'dns-wrong-record'];

const NOT = {
  node: 'Both nodes are Ready (kubectl get nodes) and the agent runs on kube02.',
  pending: 'No pod is Pending: they are all scheduled (kubectl get pods -o wide shows a node for each).',
  dns: 'kube01.corp.lab resolves to 10.0.20.90 on ws01 (getent hosts kube01.corp.lab), and the connection reaches the node.',
};

export const KUBE_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'k8s-selector-mismatch',
    title: 'Every pod is Running, and nobody can connect',
    difficulty: 'beginner',
    ticket: 'Users: "http://kube01.corp.lab:30800 refuses the connection since 14:00." The platform team: "All pods are Running and Ready, nothing restarted. We only aligned the labels in the Service manifests with the new naming standard (app: inventory-api)."',
    briefing: BRIEFING,
    goals: [K8S_API_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployK8sInventory(world);
      change(world, '31-api-svc.yaml', (s) => s.replace('  selector:\n    app: api\n', '  selector:\n    app: inventory-api      # naming standard (PLAT-112)\n'));
    },
    rootCauses: ['k8s-selector-mismatch'],
    candidates: CANDIDATES,
    feedback: {
      'k8s-target-port': 'The targetPort is 8000, the port the API listens on. The Service has no endpoints at all: kubectl get endpoints api -n inventory shows <none>.',
      'k8s-readiness-probe': 'The pods are 1/1 Ready: their readiness probe passes.',
      'k8s-missing-secret': 'The pods started and run: no CreateContainerConfigError.',
      'k8s-dns-down': 'CoreDNS runs, and the API reaches its database (its pods are Ready).',
      'k8s-oom-limit': 'No container was OOMKilled; nothing restarts.',
      'k8s-bad-image': 'The image corp/inventory:1.4 is pulled and running.',
      'k8s-node-notready': NOT.node,
      'k8s-pending-resources': NOT.pending,
      'dns-wrong-record': NOT.dns,
    },
    hints: [
      'Pods Running and Ready but connections refused: look at what the Service sends traffic to. kubectl get endpoints api -n inventory.',
      'ENDPOINTS <none>: the Service selects no pod. Compare kubectl get svc api -n inventory -o wide (SELECTOR) with kubectl get pods -n inventory --show-labels.',
      'The Service selects app=inventory-api but the pods are labelled app=api. Make them match in /srv/k8s/inventory/31-api-svc.yaml (selector: app: api) and kubectl apply -f it. (Changing the Deployment\'s selector instead is refused: it is immutable.)',
    ],
    explanation: {
      rootCause: 'The api Service\'s selector was changed to app=inventory-api, while the pods carry app=api. A Service sends traffic only to the Ready pods its selector matches: it matches none.',
      manifestation: 'The Service has no endpoints, so kube-proxy rejects connections to its ClusterIP and NodePort: users get "connection refused", although every pod runs and is Ready.',
      evidence: 'kubectl get endpoints api -n inventory → <none>; kubectl get svc -o wide → SELECTOR app=inventory-api; kubectl get pods --show-labels → app=api; nft list table ip kube-proxy → a reject rule for the api Service.',
      prevention: 'Change labels and selectors together (Deployment template, Service selector) and check kubectl get endpoints after every Service change; a rename of labels is a migration, not a cosmetic edit.',
    },
    solution: [{ host: 'kube01', commands: [`sed -i 's/app: inventory-api .*/app: api/' ${K8S_APP_DIR}/31-api-svc.yaml`, `kubectl apply -f ${K8S_APP_DIR}/31-api-svc.yaml`] }],
    constraints: [NODEPORT_KEPT, TWO_REPLICAS],
    concepts: ['k8s.networking'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'k8s-target-port',
    title: 'The endpoints are there',
    difficulty: 'intermediate',
    ticket: 'Monitoring: "inventory API down" since the platform team "harmonised the Service ports to 80 everywhere". They checked: "kubectl get endpoints shows both pods, so the Service is fine."',
    briefing: BRIEFING,
    goals: [K8S_API_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployK8sInventory(world);
      change(world, '31-api-svc.yaml', (s) => s.replace('    targetPort: 8000\n', '    targetPort: 80          # all web services on port 80 (PLAT-118)\n'));
    },
    rootCauses: ['k8s-target-port'],
    candidates: CANDIDATES,
    feedback: {
      'k8s-selector-mismatch': 'The selector matches: the endpoints list both pods. Look at the port in those endpoints.',
      'k8s-readiness-probe': 'The pods are Ready (that is why they are in the endpoints).',
      'k8s-missing-secret': 'The pods run.',
      'k8s-dns-down': 'The pods are Ready, so they reach their database by name.',
      'k8s-oom-limit': 'Nothing restarts.',
      'k8s-bad-image': 'The image runs.',
      'k8s-node-notready': NOT.node,
      'k8s-pending-resources': NOT.pending,
      'dns-wrong-record': NOT.dns,
    },
    hints: [
      'The endpoints exist: kubectl get endpoints api -n inventory. Read them closely: which port do they use? And which port does the API listen on (kubectl describe pod, Port; or the gunicorn log)?',
      'The endpoints are POD_IP:80, but gunicorn listens on 8000: the Service\'s targetPort sends traffic to a port where nothing listens. Test it: kubectl exec -n inventory deploy/api -- python3 -c ... is not possible; from kube01: curl http://POD_IP:80/ (refused) vs curl http://POD_IP:8000/health.',
      'Set targetPort: 8000 again in /srv/k8s/inventory/31-api-svc.yaml (port: 80 is the Service\'s own port and can stay), then kubectl apply -f it.',
    ],
    explanation: {
      rootCause: 'The Service\'s targetPort was changed to 80. targetPort is the port on the pods that traffic is sent to; the API listens on 8000. (port: is the Service\'s own port; nodePort is the port on the nodes.)',
      manifestation: 'kube-proxy DNATs the NodePort to POD_IP:80 where nothing listens, so the pod answers with a TCP reset: "connection refused", although the endpoints list both pods.',
      evidence: 'kubectl get endpoints api -n inventory → 10.42.x.y:80; kubectl describe svc api → TargetPort 80/TCP; kubectl describe pod → Port 8000/TCP; curl POD_IP:8000/health works, POD_IP:80 is refused.',
      prevention: 'Name the container port (ports: - name: http, containerPort: 8000) and use targetPort: http, so the Service follows the container; test the Service from inside the cluster after every change.',
    },
    solution: [{ host: 'kube01', commands: [`sed -i 's/targetPort: 80 .*/targetPort: 8000/' ${K8S_APP_DIR}/31-api-svc.yaml`, `kubectl apply -f ${K8S_APP_DIR}/31-api-svc.yaml`] }],
    constraints: [NODEPORT_KEPT, TWO_REPLICAS],
    concepts: ['k8s.networking'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'k8s-readiness-path',
    title: 'The release that never finishes',
    difficulty: 'intermediate',
    ticket: 'The release pipeline is blocked: its step "kubectl rollout status deploy/api -n inventory" times out since the platform team applied the new probe standard ("/healthz on every service"). Users have not noticed anything yet.',
    briefing: BRIEFING,
    goals: [rolledOut('api'), K8S_API_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployK8sInventory(world);
      change(world, '30-api.yaml', (s) => s.replace('            path: /health\n', '            path: /healthz       # probe standard (PLAT-120)\n'));
    },
    rootCauses: ['k8s-readiness-probe'],
    candidates: CANDIDATES,
    feedback: {
      'k8s-selector-mismatch': 'The Service still sends traffic to the old, Ready pods: users are fine. The new pods are the problem.',
      'k8s-target-port': 'The Service works (users are served by the old pods).',
      'k8s-missing-secret': 'The new pod started: it is Running, just not Ready.',
      'k8s-dns-down': 'The new pod reaches the database (its log says "Connected to PostgreSQL").',
      'k8s-oom-limit': 'Nothing restarts.',
      'k8s-bad-image': 'The image is the same corp/inventory:1.4; only the probe changed.',
      'k8s-node-notready': NOT.node,
      'k8s-pending-resources': NOT.pending,
      'dns-wrong-record': NOT.dns,
    },
    hints: [
      'kubectl get pods -n inventory: one new pod is Running but 0/1 (not Ready), the two old pods are still there. A rolling update waits for new pods to be Ready before removing old ones.',
      'Why is it not Ready? kubectl describe pod (the new one): the Events say "Readiness probe failed: HTTP probe failed with statuscode: 404". Which path does the probe ask for, and which path does the API serve (the Service and users use /health)?',
      'Set the probe path back to /health in /srv/k8s/inventory/30-api.yaml and kubectl apply -f it; kubectl rollout status deploy/api -n inventory then completes.',
    ],
    explanation: {
      rootCause: 'The readiness probe was changed to GET /healthz, but corp/inventory 1.4 serves its health check on /health; /healthz answers 404.',
      manifestation: 'The new pod never becomes Ready, so the rolling update cannot remove the old pods (maxUnavailable rounds down to 0 for 2 replicas): the rollout stalls and its status times out, while the old pods keep serving users.',
      evidence: 'kubectl get pods → a new pod 0/1 Running beside two old 1/1 pods; kubectl describe pod → Readiness probe failed: HTTP probe failed with statuscode: 404; kubectl get rs → the new ReplicaSet 1 desired, 0 ready.',
      prevention: 'Probe what the application really serves (check with curl from a debug pod first); keep rollout status in the pipeline with a timeout: it caught this before users did.',
    },
    solution: [{ host: 'kube01', commands: [`sed -i 's#path: /healthz .*#path: /health#' ${K8S_APP_DIR}/30-api.yaml`, `kubectl apply -f ${K8S_APP_DIR}/30-api.yaml`, 'kubectl rollout status deploy/api -n inventory'] }],
    constraints: [TWO_REPLICAS, k8sConstraint('api-readiness', 'The api containers still have a readiness probe (without one, a pod that cannot reach its database would get traffic).', (st) => (find(st, 'Deployment', 'inventory', 'api')?.spec.template.spec.containers?.[0]?.readinessProbe ? null : 'The readiness probe was removed from the api Deployment.'))],
    concepts: ['k8s.workloads'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'k8s-missing-secret',
    title: 'Password rotation',
    difficulty: 'intermediate',
    ticket: 'Security rotated the inventory database password this morning: "new Secret inventory-db-2026 created, the old inventory-db deleted, db Deployment updated and verified". Since the API pods were restarted after the change, the site is down.',
    briefing: BRIEFING,
    goals: [K8S_API_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployK8sInventory(world);
      const h = world.hosts.kube01;
      world.clock += 1800_000;
      kubeTick(world);
      writeFile(h, `${K8S_APP_DIR}/10-secret.yaml`, SECRET_YAML('inventory-db-2026', 'Inv-K8s-2026-Q4'), world.clock, { mode: 0o600 });
      writeFile(h, `${K8S_APP_DIR}/20-db.yaml`, DB_YAML.replace('              name: inventory-db\n', '              name: inventory-db-2026\n'), world.clock);
      script(world, 'kube01', [
        `kubectl apply -f ${K8S_APP_DIR}/10-secret.yaml`,
        'kubectl delete secret inventory-db -n inventory',
        `kubectl apply -f ${K8S_APP_DIR}/20-db.yaml`,
        'kubectl delete pod -n inventory -l app=api',
      ], 20_000);
      for (let i = 0; i < 8; i++) { world.clock += 15_000; kubeTick(world); }
    },
    rootCauses: ['k8s-missing-secret'],
    candidates: CANDIDATES,
    feedback: {
      'k8s-selector-mismatch': 'The Service selector is unchanged; it has no endpoints because the new api pods never started.',
      'k8s-target-port': 'The Service is unchanged.',
      'k8s-readiness-probe': 'The containers were never created, so no probe ran.',
      'k8s-dns-down': 'CoreDNS runs; the api containers do not even start.',
      'k8s-oom-limit': 'No container ran, so none was killed.',
      'k8s-bad-image': 'The image is present (Pulled / already present on machine).',
      'k8s-node-notready': NOT.node,
      'k8s-pending-resources': NOT.pending,
      'dns-wrong-record': NOT.dns,
    },
    hints: [
      'kubectl get pods -n inventory: the api pods show CreateContainerConfigError. The kubelet could not build the container\'s configuration.',
      'kubectl describe pod -n inventory -l app=api → Events: Error: secret "inventory-db" not found. Which Secrets exist (kubectl get secrets -n inventory), and which one does the api Deployment reference (30-api.yaml)?',
      'Point the api Deployment at the new Secret: in /srv/k8s/inventory/30-api.yaml the secretKeyRef name becomes inventory-db-2026; kubectl apply -f it. (Re-creating the old Secret would bring back the password that was rotated away.)',
    ],
    explanation: {
      rootCause: 'The rotation created inventory-db-2026 and deleted inventory-db, but only the db Deployment was updated; the api Deployment still takes DB_PASSWORD from the Secret inventory-db, which no longer exists.',
      manifestation: 'Running pods keep the environment they started with, so nothing broke until the api pods were recreated: the new ones stay in CreateContainerConfigError, the Service has no endpoints, and users get "connection refused".',
      evidence: 'kubectl get pods → CreateContainerConfigError; kubectl describe pod → Error: secret "inventory-db" not found; kubectl get secrets → only inventory-db-2026; grep -n inventory-db /srv/k8s/inventory/*.yaml.',
      prevention: 'Find every reference before renaming or deleting a Secret (grep the manifests, kubectl get deploy -A -o yaml); restart and check one consumer at a time; prefer updating the Secret\'s data under the same name when the consumers allow it.',
    },
    solution: [{ host: 'kube01', commands: [`sed -i 's/name: inventory-db$/name: inventory-db-2026/' ${K8S_APP_DIR}/30-api.yaml`, `kubectl apply -f ${K8S_APP_DIR}/30-api.yaml`, 'kubectl rollout status deploy/api -n inventory'] }],
    constraints: [TWO_REPLICAS, PASSWORD_FROM_SECRET, k8sConstraint('old-secret-gone', 'The rotated-away Secret inventory-db stays deleted.', (st) => (find(st, 'Secret', 'inventory', 'inventory-db') ? 'The old Secret inventory-db exists again (its password was rotated away).' : null))],
    concepts: ['k8s.workloads'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'k8s-coredns-scaled-down',
    title: 'Cost savings',
    difficulty: 'advanced',
    ticket: 'The inventory API has been down since the nightly node maintenance restarted its pods; they keep restarting. Last week finance\'s "cloud cost review" scaled down "unused deployments in kube-system"; everything kept working afterwards.',
    briefing: BRIEFING,
    goals: [K8S_API_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployK8sInventory(world);
      world.clock += 1800_000;
      kubeTick(world);
      script(world, 'kube01', ['kubectl scale deploy coredns -n kube-system --replicas=0'], 10_000);
      world.clock += 7 * 24 * 3600_000;
      kubeTick(world);
      script(world, 'kube01', ['kubectl delete pod -n inventory -l app=api'], 10_000);
      for (let i = 0; i < 10; i++) { world.clock += 15_000; kubeTick(world); }
    },
    rootCauses: ['k8s-dns-down'],
    candidates: CANDIDATES,
    feedback: {
      'k8s-selector-mismatch': 'The selector matches the api pods; they are just never Ready.',
      'k8s-target-port': 'The Service is unchanged.',
      'k8s-readiness-probe': 'The containers exit before any probe can pass: CrashLoopBackOff, not "Running 0/1".',
      'k8s-missing-secret': 'The containers start (and crash): the Secret is there.',
      'k8s-oom-limit': 'Last State says Error, exit code 3, not OOMKilled.',
      'k8s-bad-image': 'The image runs; it exits with an application error.',
      'k8s-node-notready': NOT.node,
      'k8s-pending-resources': NOT.pending,
      'dns-wrong-record': 'The name that fails is "db", inside the pods (cluster DNS), not kube01.corp.lab.',
    },
    hints: [
      'kubectl get pods -n inventory: the api pods are in CrashLoopBackOff. Read why they exit: kubectl logs -n inventory deploy/api (or --previous on a pod).',
      '"could not translate host name "db" to address": the pods cannot resolve the Service name. Who answers cluster names? kubectl get pods,deploy -n kube-system; a debug pod: kubectl run dbg -n inventory --image=busybox:1.36 -- sleep 3600, then kubectl exec -n inventory dbg -- nslookup db.',
      'CoreDNS has 0 replicas. Scale it back (kubectl scale deploy coredns -n kube-system --replicas=1); the api pods recover at their next restart (kubectl rollout restart deploy/api -n inventory skips the back-off).',
    ],
    explanation: {
      rootCause: 'The coredns Deployment in kube-system was scaled to 0 replicas. Pods resolve Service names through the cluster DNS Service (10.43.0.10), which then has no endpoints.',
      manifestation: 'Pods that were already running kept their connections and nothing broke for a week; when the api pods were recreated, they could not resolve "db" at start, exited (code 3) and went into CrashLoopBackOff.',
      evidence: 'kubectl logs → psycopg2 "could not translate host name "db" to address"; kubectl get deploy -n kube-system → coredns 0/0; kubectl get endpoints kube-dns -n kube-system → <none>; nslookup from a debug pod → no servers could be reached.',
      prevention: 'kube-system holds the cluster\'s own components: never scale or delete there without knowing what each Deployment is; monitor CoreDNS (and test a lookup from a pod) like any critical service.',
    },
    solution: [{ host: 'kube01', commands: ['kubectl scale deploy coredns -n kube-system --replicas=1', 'kubectl wait --for=condition=Ready pod -n kube-system -l k8s-app=kube-dns --timeout=60s', 'kubectl rollout restart deploy/api -n inventory', 'kubectl rollout status deploy/api -n inventory'] }],
    constraints: [TWO_REPLICAS, k8sConstraint('db-host-name', 'The api still finds the database by its Service name (DB_HOST=db), not by a hard-coded IP address.', (st) => {
      const env = find(st, 'Deployment', 'inventory', 'api')?.spec.template.spec.containers?.[0]?.env ?? [];
      const h = env.find((e: { name: string }) => e.name === 'DB_HOST')?.value;
      return h === 'db' || h === 'db.inventory' || h === 'db.inventory.svc.cluster.local' ? null : `DB_HOST is ${h ?? 'unset'}.`;
    })],
    concepts: ['k8s.networking', 'dns.resolution'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'k8s-oomkilled',
    title: 'Right-sizing',
    difficulty: 'intermediate',
    ticket: 'The inventory API answers 503 or nothing since the "resource right-sizing" change: memory limits were "aligned with the actual usage graphs" for every Deployment in the namespace.',
    briefing: BRIEFING,
    goals: [K8S_API_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployK8sInventory(world);
      change(world, '20-db.yaml', (s) => s.replace('            memory: 256Mi\n', '            memory: 32Mi     # right-sizing (FIN-77): usage graph shows ~30Mi\n'));
    },
    rootCauses: ['k8s-oom-limit'],
    candidates: CANDIDATES,
    feedback: {
      'k8s-selector-mismatch': 'The selectors match; the api pods are not Ready because their database is down.',
      'k8s-target-port': 'The Service is unchanged.',
      'k8s-readiness-probe': 'The api\'s probe is right: /health answers 503 because the database is unreachable. Follow the dependency.',
      'k8s-missing-secret': 'The containers start.',
      'k8s-dns-down': '"db" resolves (the API logs show connection attempts to its ClusterIP); the database itself keeps dying.',
      'k8s-bad-image': 'postgres:16 starts: its log shows "database system is ready to accept connections" before it dies.',
      'k8s-node-notready': NOT.node,
      'k8s-pending-resources': NOT.pending,
      'dns-wrong-record': NOT.dns,
    },
    hints: [
      'Follow the dependency: the api pods are not Ready (their /health needs the database). kubectl get pods -n inventory: what does the db pod do?',
      'The db pod restarts again and again. kubectl describe pod -n inventory -l app=db → Last State: Terminated, Reason: OOMKilled, Exit Code: 137. Compare its memory limit with what PostgreSQL needs.',
      'Give the database a realistic limit again (e.g. 256Mi) in /srv/k8s/inventory/20-db.yaml and kubectl apply -f it. Keep a limit: removing it would let one pod use the whole node.',
    ],
    explanation: {
      rootCause: 'The db container\'s memory limit was lowered to 32Mi. PostgreSQL needs more than that to start and work (shared buffers, connections), so the kernel\'s OOM killer ends it inside its cgroup.',
      manifestation: 'The database starts, is killed (OOMKilled, exit 137) and restarts with a growing back-off; the api\'s /health answers 503, its readiness probe fails, the api Service loses its endpoints, and users get errors or refusals.',
      evidence: 'kubectl get pods → db CrashLoopBackOff; kubectl describe pod (db) → Last State: Terminated, Reason: OOMKilled, Exit Code: 137, Limits: memory 32Mi; the api pods 0/1 with "Readiness probe failed: HTTP probe failed with statuscode: 503".',
      prevention: 'Size limits from peak usage plus headroom (not an average graph), change one service at a time and watch restarts (RESTARTS column, OOMKilled) after the change.',
    },
    solution: [{ host: 'kube01', commands: [`sed -i 's/memory: 32Mi .*/memory: 256Mi/' ${K8S_APP_DIR}/20-db.yaml`, `kubectl apply -f ${K8S_APP_DIR}/20-db.yaml`, 'kubectl rollout status deploy/db -n inventory', 'kubectl rollout restart deploy/api -n inventory', 'kubectl rollout status deploy/api -n inventory'] }],
    constraints: [TWO_REPLICAS, k8sConstraint('db-limit', 'The db container keeps a memory limit (64Mi or more).', (st) => {
      const lim = find(st, 'Deployment', 'inventory', 'db')?.spec.template.spec.containers?.[0]?.resources?.limits?.memory;
      if (!lim) return 'The db container has no memory limit any more.';
      const m = /^(\d+)(Mi|Gi)$/.exec(String(lim));
      return m && Number(m[1]) * (m[2] === 'Gi' ? 1024 : 1) >= 64 ? null : `The db memory limit (${lim}) is still too small.`;
    })],
    concepts: ['k8s.workloads'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'k8s-bad-image',
    title: 'Release 1.5',
    difficulty: 'beginner',
    ticket: 'The release job for inventory 1.5 ran "kubectl set image deploy/api api=corp/inventory:1.5" an hour ago and has been waiting on "kubectl rollout status" since. The developers say the 1.5 build failed and was never published; 1.4 is the current release.',
    briefing: BRIEFING,
    goals: [rolledOut('api'), K8S_API_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployK8sInventory(world);
      world.clock += 1800_000;
      kubeTick(world);
      script(world, 'kube01', ['kubectl set image deploy/api -n inventory api=corp/inventory:1.5'], 10_000);
      for (let i = 0; i < 6; i++) { world.clock += 600_000; kubeTick(world); }
    },
    rootCauses: ['k8s-bad-image'],
    candidates: CANDIDATES,
    feedback: {
      'k8s-selector-mismatch': 'Users are served by the old pods; the problem is the new one.',
      'k8s-target-port': 'The Service works for the old pods.',
      'k8s-readiness-probe': 'The new container never started, so its probe never ran.',
      'k8s-missing-secret': 'The kubelet is still trying to pull the image; it has not got as far as the container\'s configuration.',
      'k8s-dns-down': 'The old pods reach the database by name.',
      'k8s-oom-limit': 'Nothing was killed.',
      'k8s-node-notready': NOT.node,
      'k8s-pending-resources': 'The new pod is scheduled (it has a node); it is waiting for its image.',
      'dns-wrong-record': NOT.dns,
    },
    hints: [
      'kubectl get pods -n inventory: a new pod in ImagePullBackOff beside the two old ones. kubectl describe it: the Events show why the pull fails.',
      '"failed to resolve reference "docker.io/corp/inventory:1.5": not found": the tag does not exist. The rollout cannot finish, and its progress deadline passed (kubectl describe deploy api: ProgressDeadlineExceeded).',
      'Go back to the working release: kubectl rollout undo deploy/api -n inventory (or set the image to corp/inventory:1.4), then kubectl rollout status deploy/api -n inventory. Update 30-api.yaml if it says 1.5.',
    ],
    explanation: {
      rootCause: 'The Deployment was updated to corp/inventory:1.5, an image tag that was never pushed to the registry.',
      manifestation: 'The new pod cannot pull its image (ErrImagePull, then ImagePullBackOff); the rolling update keeps the old pods, so users are fine, but the rollout never completes and passes its progress deadline.',
      evidence: 'kubectl get pods → ImagePullBackOff; kubectl describe pod → Failed to pull image "corp/inventory:1.5": … not found; kubectl rollout status → waiting / exceeded its progress deadline; kubectl rollout history → revision 2 is the 1.5 change.',
      prevention: 'Deploy only images the pipeline built and pushed (by digest, or after checking the tag exists); keep rollout status with a timeout in the release job and roll back automatically when it fails.',
    },
    solution: [{ host: 'kube01', commands: ['kubectl rollout undo deploy/api -n inventory', 'kubectl rollout status deploy/api -n inventory'] }],
    constraints: [TWO_REPLICAS, k8sConstraint('api-image', 'The api runs the published release corp/inventory:1.4.', (st) => {
      const img = find(st, 'Deployment', 'inventory', 'api')?.spec.template.spec.containers?.[0]?.image;
      return img === 'corp/inventory:1.4' ? null : `The api Deployment uses ${img}.`;
    })],
    concepts: ['k8s.workloads'],
  },
];
