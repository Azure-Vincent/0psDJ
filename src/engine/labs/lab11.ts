// Lab 11: Applications on Kubernetes. Run the inventory application on the
// k3s cluster: give alice her own kubeconfig, create the namespace and the
// database Secret, deploy PostgreSQL and the API with probes and resources,
// publish the API on a NodePort, practise a failed release and its rollback,
// drain a node for maintenance without an outage, and prove that everything
// comes back after a reboot of both nodes.

import { mkdir, writeFile } from '../fs';
import { buildKubeLab } from '../lab/kubeLab';
import { API_SVC_YAML, API_YAML, DB_YAML, K8S_DB_PASSWORD, NS_YAML } from '../scenarios/kubeScenarios';
import { b64decode, find, isPodReady, kubeTick, list, loadStore, type KObj } from '../sim/k8s';
import type { World } from '../types';
import { NO, OK, printfTo, probe } from './engine';
import type { GuidedLab, LabCheck } from './types';

const DIR = '/srv/k8s/inventory';

/** The cluster with the team's manifests handed over in /srv/k8s/inventory (nothing deployed yet). */
export function buildLab11World(): World {
  const w = buildKubeLab();
  const h = w.hosts.kube01;
  for (const d of ['/srv', '/srv/k8s', DIR]) if (!h.fs[d]) mkdir(h, d, w.clock);
  writeFile(h, `${DIR}/00-namespace.yaml`, NS_YAML, w.clock);
  writeFile(h, `${DIR}/20-db.yaml`, DB_YAML, w.clock);
  writeFile(h, `${DIR}/30-api.yaml`, API_YAML, w.clock);
  writeFile(h, `${DIR}/README`, 'Inventory on Kubernetes (CHG-4131).\n00-namespace.yaml, 20-db.yaml, 30-api.yaml: from the development team.\nThe Secret (inventory-db, key: password) and the api Service are created by operations.\n', w.clock);
  return w;
}

const store = (w: World) => { const c = structuredClone(w); kubeTick(c); return loadStore(c); };
const readyPods = (st: ReturnType<typeof loadStore>, app: string) => list(st, 'Pod', 'inventory').filter((p) => p.metadata.labels?.app === app && isPodReady(p));

const aliceKubectl: LabCheck = {
  id: 'alice-kubectl', description: 'alice runs kubectl on kube01 with her own kubeconfig (~/.kube/config, mode 600, owned by alice)',
  check(w) {
    const f = w.hosts.kube01.fs['/home/alice/.kube/config'];
    if (!f) return NO('/home/alice/.kube/config does not exist.');
    if (f.owner !== 'alice' || (f.mode & 0o077) !== 0) return NO(`~/.kube/config must belong to alice with mode 600 (it holds her credentials): owner ${f.owner}, mode ${(f.mode & 0o777).toString(8)}.`);
    const r = probe(w, 'kube01', 'alice', 'kubectl get nodes');
    return r.code === 0 && /kube02 +Ready/.test(r.output) ? OK('kubectl get nodes works for alice.') : NO(`kubectl get nodes as alice:\n${r.output}`);
  },
};

const nsSecret: LabCheck = {
  id: 'ns-secret', description: `The namespace inventory exists with the Secret inventory-db (key password = ${K8S_DB_PASSWORD})`,
  check(w) {
    const st = store(w);
    if (!find(st, 'Namespace', '', 'inventory')) return NO('There is no namespace "inventory".');
    const s = find(st, 'Secret', 'inventory', 'inventory-db');
    if (!s) return NO('There is no Secret inventory-db in the namespace inventory.');
    const pw = s.data?.password;
    if (!pw) return NO('The Secret has no key "password".');
    return b64decode(pw) === K8S_DB_PASSWORD ? OK('Secret inventory-db holds the database password.') : NO(`The password in the Secret is "${b64decode(pw)}".`);
  },
};

const dbUp: LabCheck = {
  id: 'db-up', description: 'The db Deployment is Ready, with a memory limit, and the db Service has an endpoint on 5432',
  check(w) {
    const st = store(w);
    const d = find(st, 'Deployment', 'inventory', 'db');
    if (!d) return NO('No Deployment db in the namespace inventory.');
    if (!d.spec.template.spec.containers?.[0]?.resources?.limits?.memory) return NO('The db container has no memory limit.');
    if (!readyPods(st, 'db').length) return NO('The db pod is not Ready (kubectl get pods -n inventory; describe it).');
    const ep = find(st, 'Endpoints', 'inventory', 'db') as KObj & { subsets?: { addresses?: unknown[]; ports?: { port: number }[] }[] };
    return ep?.subsets?.[0]?.addresses?.length && ep.subsets[0].ports?.[0]?.port === 5432 ? OK('db is Ready and its Service has an endpoint.') : NO('The db Service has no endpoint on 5432 (kubectl get endpoints -n inventory).');
  },
};

const apiUp: LabCheck = {
  id: 'api-up', description: 'The api Deployment runs 2 Ready replicas, spread over both nodes, with a readiness probe and the password from the Secret',
  check(w) {
    const st = store(w);
    const d = find(st, 'Deployment', 'inventory', 'api');
    if (!d) return NO('No Deployment api in the namespace inventory.');
    const c = d.spec.template.spec.containers?.[0];
    if (!c?.readinessProbe) return NO('The api container has no readiness probe.');
    const pw = (c.env ?? []).find((e: { name: string }) => e.name === 'DB_PASSWORD');
    if (!pw?.valueFrom?.secretKeyRef) return NO('DB_PASSWORD must come from the Secret (valueFrom.secretKeyRef), not a plain value.');
    const pods = readyPods(st, 'api');
    if (pods.length < 2) return NO(`${pods.length} of 2 api pods are Ready.`);
    const nodes = new Set(pods.map((p) => p.spec.nodeName));
    return nodes.size >= 2 ? OK(`2 Ready api pods on ${[...nodes].join(' and ')}.`) : NO('Both api pods run on the same node: one node failure would take the API down.');
  },
};

const published: LabCheck = {
  id: 'published', description: 'From ws01, http://kube01.corp.lab:30800/health and http://kube02.corp.lab:30800/health answer 200',
  check(w) {
    for (const n of ['kube01', 'kube02']) {
      const r = probe(w, 'ws01', 'alice', `curl -sS -o /dev/null -w '%{http_code}' -m 10 http://${n}.corp.lab:30800/health`);
      if (r.output.trim() !== '200') return NO(`${n}.corp.lab:30800/health: ${r.output.trim() || 'no answer'}`);
    }
    return OK('Both nodes publish the API on 30800.');
  },
};

const rolledBack: LabCheck = {
  id: 'rolled-back', description: 'The failed 1.5 release was rolled back: the api runs corp/inventory:1.4, fully rolled out, with the 1.5 attempt in its history',
  check(w) {
    const st = store(w);
    const d = find(st, 'Deployment', 'inventory', 'api');
    if (!d) return NO('No Deployment api.');
    const rss = list(st, 'ReplicaSet', 'inventory').filter((r) => r.metadata.ownerReferences?.some((o) => o.uid === d.metadata.uid));
    if (!rss.some((r) => r.spec.template.spec.containers?.[0]?.image === 'corp/inventory:1.5')) return NO('The history has no 1.5 release: set the image to corp/inventory:1.5 first (kubectl set image), and watch it fail.');
    if (d.spec.template.spec.containers?.[0]?.image !== 'corp/inventory:1.4') return NO(`The api runs ${d.spec.template.spec.containers?.[0]?.image}.`);
    const r = probe(w, 'kube01', 'root', 'kubectl rollout status deploy/api -n inventory --timeout=10s');
    return /successfully rolled out/.test(r.output) ? OK('Back on 1.4, rollout complete.') : NO(r.output);
  },
};

const maintained: LabCheck = {
  id: 'maintained', description: 'kube02 was drained for maintenance and is schedulable again (uncordoned)',
  check(w) {
    const st = store(w);
    const n = find(st, 'Node', '', 'kube02');
    if (!st.events.some((e) => e.kind === 'Node' && e.name === 'kube02' && e.reason === 'NodeNotSchedulable')) return NO('kube02 has not been drained (cordoned) yet: kubectl drain kube02.');
    return n && !n.spec.unschedulable ? OK('kube02 was drained and accepts pods again.') : NO('kube02 is still cordoned (SchedulingDisabled): kubectl uncordon kube02.');
  },
};

const KUBECONFIG_CMDS = ['mkdir -p /home/alice/.kube', 'cp /etc/rancher/k3s/k3s.yaml /home/alice/.kube/config', 'chown -R alice:alice /home/alice/.kube', 'chmod 600 /home/alice/.kube/config'];

export const LAB11: GuidedLab = {
  id: 'lab11',
  title: 'Lab 11: Applications on Kubernetes',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Run the inventory application on the k3s cluster: kubeconfig access, a namespace and a Secret, the database and the API with probes and resources, a NodePort Service, a failed release and its rollback, a node drained for maintenance without an outage, and a reboot test.',
  brief: `The inventory application moves from dock01 to the new **k3s cluster** (CHG-4131): **kube01** (10.0.20.90, server and worker) and **kube02** (10.0.20.91, worker). The development team handed over its manifests in **${DIR}** on kube01: a namespace, the database (**db**, postgres:16) and the API (**api**, corp/inventory:1.4, 2 replicas). Operations must provide the rest.

The change record sets these rules:

- alice administers the cluster from kube01 with her own kubeconfig;
- the database password **${K8S_DB_PASSWORD}** lives in a Secret, **inventory-db** (key **password**), never in a manifest;
- the API is published to the office on port **30800** of both nodes;
- one node may fail, or be maintained, without an outage;
- everything comes back by itself after a reboot.`,
  objectives: [
    'Use a kubeconfig: what it contains, why the admin one is root-only, and how to give a user their own copy.',
    'Create a namespace and a Secret, and reference the Secret from a Deployment instead of writing the password into it.',
    'Deploy with kubectl apply and verify each layer: pods Ready, endpoints, the Service from the office.',
    'Understand rolling updates and readiness: why a bad release does not cause an outage, and how to roll back.',
    'Drain a node for maintenance and see the pods move, then return it to service.',
  ],
  prerequisites: [
    { label: 'Kubernetes', link: 'lesson/kubernetes/what' },
    { label: 'Docker and container troubleshooting', link: 'lesson/docker/what' },
    { label: 'Databases (PostgreSQL)', link: 'lesson/database/what' },
  ],
  setupNote: `This lab uses the k3s cluster **kube01** and **kube02** on the server network (Debian 12, k3s ${'v1.30.6+k3s1'}, the images already in the nodes' containerd stores). The manifests are in **${DIR}** on kube01; nothing of the application runs yet.`,
  terminals: [
    { hostId: 'kube01', user: 'root', label: 'kube01 (root)', banner: `kube01: k3s server, logged in as root. The manifests: ls ${DIR}. Try: kubectl get nodes, kubectl get pods -A.` },
    { hostId: 'kube01', user: 'alice', label: 'kube01 (alice)', banner: 'kube01, logged in as alice (sudo password kube01-alice).' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01: the office\'s view. Try: curl -sS -i http://kube01.corp.lab:30800/health.' },
    { hostId: 'kube02', user: 'root', label: 'kube02 (root)', banner: 'kube02: k3s agent (worker), root. Try: systemctl status k3s-agent, crictl ps.' },
  ],
  build: buildLab11World,
  steps: [
    {
      id: 'access', title: 'A kubeconfig for alice',
      objective: 'Let **alice** run `kubectl` on kube01 with her own kubeconfig (**~/.kube/config**, owned by alice, mode 600).',
      background: 'kubectl finds the API server and the credentials in a **kubeconfig** file: `$KUBECONFIG`, else `~/.kube/config`; k3s\'s kubectl falls back to the admin file **/etc/rancher/k3s/k3s.yaml**. That file holds a client certificate with full admin rights, so k3s creates it **mode 600**, root only. Giving alice a copy gives her the same rights: a decision, not a convenience (in larger clusters each person gets their own certificate or an OIDC login, and RBAC limits what they may do).',
      tasks: [
        'As alice on kube01: `kubectl get nodes` → the WARN and "permission denied" on /etc/rancher/k3s/k3s.yaml.',
        `As root: ${KUBECONFIG_CMDS.map((c) => `\`${c}\``).join(', ')}.`,
        'As alice: `kubectl get nodes` (both Ready) and `kubectl config view` (the server and the omitted credentials).',
      ],
      hints: ['chmod 600: the file is a password in all but name.', 'If kubectl still reads the root file, check `echo $KUBECONFIG` and that the copy is in /home/alice/.kube/config.'],
      checks: [aliceKubectl],
      solution: [{ host: 'kube01', user: 'root', commands: KUBECONFIG_CMDS }],
      learn: [{ label: 'Kubernetes: how it works', link: 'lesson/kubernetes/internals' }, { label: 'kubeconfig', link: 'reference?id=file:kubeconfig' }],
      concepts: ['k8s.workloads', 'linux.permissions'],
    },
    {
      id: 'secret', title: 'Namespace and Secret',
      objective: `Create the namespace **inventory** (from 00-namespace.yaml) and the Secret **inventory-db** with the key **password** = ${K8S_DB_PASSWORD}.`,
      background: 'A **namespace** groups an application\'s objects (and their names: "db" in inventory is not "db" in another namespace). A **Secret** holds sensitive values for pods; the Deployments refer to it by name and key. Its data is only **base64-encoded**, not encrypted: anyone who can read Secrets in the namespace can read the password, and a Secret written into a YAML file in Git is a leaked password. Creating it from the command line keeps it out of the manifests.',
      tasks: [
        `\`kubectl apply -f ${DIR}/00-namespace.yaml\`, then \`kubectl get ns\`.`,
        `\`kubectl create secret generic inventory-db -n inventory --from-literal=password=${K8S_DB_PASSWORD}\``,
        '`kubectl get secret inventory-db -n inventory -o yaml`: decode the value with `echo VALUE | base64 -d` to see why base64 is not protection.',
      ],
      hints: ['Forgot -n inventory? The Secret went into default: `kubectl delete secret inventory-db` and create it again in the right namespace.'],
      checks: [nsSecret],
      solution: [{ host: 'kube01', user: 'root', commands: [`kubectl apply -f ${DIR}/00-namespace.yaml`, `kubectl create secret generic inventory-db -n inventory --from-literal=password=${K8S_DB_PASSWORD}`] }],
      learn: [{ label: 'Kubernetes: configuration', link: 'lesson/kubernetes/config' }],
      concepts: ['k8s.workloads'],
    },
    {
      id: 'db', title: 'The database',
      objective: 'Deploy **db** (20-db.yaml): the PostgreSQL pod Ready, with a memory limit, and the **db** Service with an endpoint on 5432.',
      background: 'The Deployment asks for one PostgreSQL pod with **strategy Recreate** (never two database pods at once), takes POSTGRES_PASSWORD from the Secret, and sets **requests** (what the scheduler reserves on a node) and a **limit** (the most it may use: beyond it the kernel kills it, OOMKilled). The **Service db** gives it a stable name and virtual IP (ClusterIP) inside the cluster; its **endpoints** are the Ready pods its selector matches. A **readiness probe** (here a TCP connect to 5432) decides when the pod is Ready.',
      tasks: [
        `Read ${DIR}/20-db.yaml, then \`kubectl apply -f ${DIR}/20-db.yaml\`.`,
        '`kubectl get pods -n inventory -o wide` (repeat until 1/1 Running) and `kubectl describe pod -n inventory -l app=db` (Events, Limits).',
        '`kubectl get svc,endpoints -n inventory`: the db Service and its endpoint POD_IP:5432.',
      ],
      hints: ['ContainerConfigError? The Secret\'s name or key does not match the one in the Deployment.', 'The Service is not the pod: deleting the pod gives a new IP, the Service keeps its ClusterIP and follows.'],
      checks: [dbUp],
      solution: [{ host: 'kube01', user: 'root', commands: [`kubectl apply -f ${DIR}/20-db.yaml`, 'kubectl rollout status deploy/db -n inventory'] }],
      learn: [{ label: 'Kubernetes: workloads', link: 'lesson/kubernetes/internals' }],
      concepts: ['k8s.workloads', 'k8s.networking'],
    },
    {
      id: 'api', title: 'The API',
      objective: 'Deploy **api** (30-api.yaml): 2 Ready replicas on different nodes, with a readiness probe on /health and DB_PASSWORD from the Secret.',
      background: 'The API finds the database by the Service name **db** (CoreDNS resolves db.inventory.svc.cluster.local) and answers **/health** with 200 only when it reaches it. The readiness probe asks that path: a pod that cannot reach its database gets no traffic. The scheduler spreads the two replicas over the nodes, so one node can fail without an outage.',
      tasks: [
        `\`kubectl apply -f ${DIR}/30-api.yaml\`, then \`kubectl rollout status deploy/api -n inventory\`.`,
        '`kubectl get pods -n inventory -o wide`: two api pods, one per node. `kubectl logs -n inventory deploy/api`: "Connected to PostgreSQL at db:5432".',
        'From a debug pod: `kubectl run dbg -n inventory --image=busybox:1.36 -- sleep 3600`, then `kubectl exec -n inventory dbg -- nslookup db` and `kubectl exec -n inventory dbg -- nc -zv -w 2 db 5432` (the Service name, then the database port). Delete it afterwards.',
      ],
      hints: ['0/1 Running: describe the pod; the readiness probe\'s message says what /health returned.', 'CrashLoopBackOff: kubectl logs --previous shows why gunicorn exited.'],
      checks: [apiUp],
      solution: [{ host: 'kube01', user: 'root', commands: [`kubectl apply -f ${DIR}/30-api.yaml`, 'kubectl rollout status deploy/api -n inventory'] }],
      learn: [{ label: 'Kubernetes: probes and rollouts', link: 'lesson/kubernetes/internals' }],
      concepts: ['k8s.workloads', 'k8s.networking'],
    },
    {
      id: 'publish', title: 'Publish the API',
      objective: 'Create the Service **api** of type **NodePort**: port 80, targetPort 8000, nodePort **30800**, so that the office reaches the API on both nodes.',
      background: 'A **NodePort** Service opens the same port (30000–32767) on **every node**: kube-proxy DNATs traffic to NODE_IP:30800 to a Ready pod, wherever it runs (on kube02, traffic for a pod on kube01 is forwarded over the flannel route). **port** is the Service\'s own port (on its ClusterIP), **targetPort** the port in the pods, **nodePort** the one on the nodes. k3s here has no load balancer: in production a load balancer or the reverse proxy would sit in front of the NodePorts.',
      tasks: [
        `Write ${DIR}/31-api-svc.yaml (nano, as root):\n\n\`\`\`\n${API_SVC_YAML}\`\`\``,
        `\`kubectl apply -f ${DIR}/31-api-svc.yaml\`, \`kubectl get svc,endpoints -n inventory\`.`,
        'From ws01: `curl -sS -i http://kube01.corp.lab:30800/health` and the same on kube02. On kube01: `nft list table ip kube-proxy` (the DNAT rules).',
      ],
      hints: ['Refused? kubectl get endpoints api -n inventory: <none> means the selector matches no Ready pod; an endpoint with the wrong port means targetPort is wrong.'],
      checks: [published],
      solution: [{ host: 'kube01', user: 'root', commands: [printfTo(API_SVC_YAML, `${DIR}/31-api-svc.yaml`), `kubectl apply -f ${DIR}/31-api-svc.yaml`] }],
      learn: [{ label: 'Kubernetes: Services', link: 'lesson/kubernetes/internals' }, { label: 'Ticket: every pod is Running', link: 'troubleshoot/k8s-selector-mismatch' }],
      concepts: ['k8s.networking', 'net.nat'],
    },
    {
      id: 'release', title: 'A failed release, and the rollback',
      objective: 'Release **corp/inventory:1.5** (its build failed and was never published), watch the rollout stall without an outage, and roll back to 1.4.',
      background: 'Changing the pod template (here the image) makes the Deployment create a new **ReplicaSet** and replace pods gradually (**RollingUpdate**: maxSurge 25% rounded up, maxUnavailable 25% rounded down: for 2 replicas, one extra new pod and none removed until it is Ready). A new pod that cannot pull its image never becomes Ready, so the old pods keep serving: the users notice nothing, but the rollout never finishes and passes its **progress deadline** (600 s). `kubectl rollout undo` makes the previous ReplicaSet\'s template current again.',
      tasks: [
        '`kubectl set image deploy/api -n inventory api=corp/inventory:1.5`, then `kubectl get pods -n inventory` (ErrImagePull / ImagePullBackOff) and `kubectl describe pod` on the new pod.',
        'From ws01: `curl -sS http://kube01.corp.lab:30800/health` still answers. `kubectl rollout status deploy/api -n inventory --timeout=30s` times out.',
        '`kubectl rollout history deploy/api -n inventory`, then `kubectl rollout undo deploy/api -n inventory` and `kubectl rollout status deploy/api -n inventory`.',
      ],
      hints: ['The manifest still says 1.4: kubectl set image changed only the cluster. That is why releases belong in the files (or a pipeline) too.'],
      checks: [rolledBack, published],
      solution: [{ host: 'kube01', user: 'root', commands: ['kubectl set image deploy/api -n inventory api=corp/inventory:1.5', 'kubectl rollout status deploy/api -n inventory --timeout=30s', 'kubectl rollout undo deploy/api -n inventory', 'kubectl rollout status deploy/api -n inventory'] }],
      learn: [{ label: 'Kubernetes: rollouts', link: 'lesson/kubernetes/operate' }, { label: 'Ticket: release 1.5', link: 'troubleshoot/k8s-bad-image' }],
      concepts: ['k8s.workloads'],
    },
    {
      id: 'maintenance', title: 'Node maintenance',
      objective: 'Drain **kube02** for maintenance while the API keeps answering, then return it to service (uncordon).',
      background: '`kubectl drain` first **cordons** the node (no new pods are scheduled there), then evicts its pods: their Deployments recreate them on the other node. With two replicas and a readiness probe, the API keeps answering throughout. After the maintenance, `kubectl uncordon` makes the node schedulable again; running pods are **not** moved back automatically.',
      tasks: [
        '`kubectl get pods -n inventory -o wide`, then `kubectl drain kube02` and `kubectl get nodes` (SchedulingDisabled).',
        'From ws01, during the drain: `curl -sS http://kube01.corp.lab:30800/health`. `kubectl get pods -n inventory -o wide`: everything on kube01 now.',
        '`kubectl uncordon kube02`. Optional: `kubectl rollout restart deploy/api -n inventory` to spread the API over both nodes again.',
      ],
      hints: ['drain refuses pods without a controller (a bare debug pod): delete your dbg pod first, or use --force knowing it is deleted for good.'],
      checks: [maintained, published],
      solution: [{ host: 'kube01', user: 'root', commands: ['kubectl delete pod dbg -n inventory --ignore-not-found', 'kubectl drain kube02', 'kubectl uncordon kube02', 'kubectl rollout restart deploy/api -n inventory', 'kubectl rollout status deploy/api -n inventory'] }],
      learn: [{ label: 'Kubernetes: operate', link: 'lesson/kubernetes/operate' }],
      concepts: ['k8s.workloads'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Restart both nodes (and every other machine) and confirm everything above still holds.',
      background: 'A reboot removes every container. At boot k3s starts, the kubelet finds the pods bound to its node in the datastore and starts their containers again (the RESTARTS column counts them), kube-proxy rewrites its rules, and the Services follow the new pod IPs. What was only done by hand outside the cluster\'s objects (a container started with crictl, a runtime firewall rule) is gone.',
      tasks: ['Run "Check" on this step: it restarts every machine on a copy of the lab and re-runs all checks.'],
      hints: ['If only the reboot test fails, compare `kubectl get pods -n inventory -o wide` before and after, and the Events of the pods that do not come back.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Safe configuration change', link: 'reference?id=proc:safe-config-change' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
};

void readyPods;
