// Kubernetes (k3s) operation and troubleshooting. Example output is the
// simulator's: a k3s v1.30.6+k3s1 cluster of two Debian 12 nodes on the server
// VLAN, kube01 (10.0.20.90, server: control plane and workloads) and kube02
// (10.0.20.91, agent), flannel host-gw (pods 10.42.0.0/24 and 10.42.1.0/24),
// Services in 10.43.0.0/16, CoreDNS at 10.43.0.10 and kube-proxy in nftables
// mode. kubeadm and the managed services (EKS, AKS, GKE) are noted.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';
import { INVENTORY_MANIFEST } from '../reference/k8sRefs';

const DB_MANIFEST = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: db
spec:
  replicas: 1
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
            cpu: 250m
            memory: 256Mi
          limits:
            memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: db
spec:
  selector:
    app: db
  ports:
  - port: 5432
    targetPort: 5432`;

// --- Operate & recover guide ---------------------------------------------------------

export const KUBERNETES_GUIDE: ServiceGuide = {
  purpose:
    'Kubernetes runs containers on a group of machines (**nodes**) and keeps them in the state you asked for. You do not start containers yourself: you send the **API server** a description ("two pods of corp/inventory:1.4 with this configuration, reachable on port 30080"), and **controllers** create, place, restart and replace pods until reality matches it. On each node the **kubelet** runs the pods through containerd, **kube-proxy** turns Services into NAT rules and the **CNI** plugin (flannel) connects the pod networks. In the lab, k3s packages all of this: `k3s.service` on kube01 (control plane and workloads) and `k3s-agent.service` on kube02. When "the application in Kubernetes is down", the cause is at one of a few stages (API and nodes, scheduling, image and configuration, the process itself, readiness, Service and endpoints, DNS, the node network), and each has its own command.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Declarative operation of containerised applications on several machines: you keep the desired state in files (manifests), the cluster keeps the running state equal to them. It replaces failed pods (self-healing), places them on nodes with room (scheduling), replaces versions gradually and can go back (rolling updates and rollbacks), and gives every application a stable name and address (Services and cluster DNS) although pods come and go.' },
    { q: 'How does it work internally?', a: 'Everything is an **object** stored by the **API server** in a datastore (etcd; in k3s by default SQLite through kine). **Controllers** watch objects and act: the Deployment controller creates a ReplicaSet per pod-template version, the ReplicaSet controller creates pods, the **scheduler** binds each new pod to a node, the endpoints controller lists the Ready pods behind each Service. On the chosen node the **kubelet** sees the pod, asks containerd to pull the image and start the container, runs the probes and reports status back to the API server. No component talks to another directly: they all read and write objects through the API server.' },
    { q: 'Which protocols does it use?', a: 'HTTPS with client certificates or tokens for the Kubernetes API (kubectl, kubelets, controllers, kube-proxy all use it); gRPC over a Unix socket between the kubelet and containerd (CRI); plain IP routing between pod subnets (flannel host-gw) or VXLAN encapsulation (flannel\'s default); netfilter DNAT for Services; DNS (UDP/TCP 53) from pods to CoreDNS; HTTPS to registries for image pulls.' },
    { q: 'Which ports and transport?', a: 'API server **TCP 6443** on kube01 (kubectl, agents). Kubelet **TCP 10250** on every node (logs, exec, metrics: the API server connects to it). **NodePorts TCP/UDP 30000–32767** on every node for Services of type NodePort. flannel VXLAN would use **UDP 8472** between nodes; the lab uses host-gw (routes only, nodes on one subnet). Inside the cluster: ClusterIPs from 10.43.0.0/16 (virtual, no socket), CoreDNS on 10.43.0.10:53, pods on their own IPs (10.42.x.y) and container ports.' },
    { q: 'Which processes and OS components implement it?', a: 'In k3s one binary: `k3s server` (kube01, k3s.service) contains the API server, scheduler, controller manager, kine/SQLite, plus the node parts; `k3s agent` (kube02, k3s-agent.service) contains the kubelet, kube-proxy and flannel. Both start an embedded **containerd**, with one `containerd-shim-runc-v2` per pod. CoreDNS runs as a pod in kube-system. Kernel: namespaces and cgroups (containers), the `cni0` bridge and veth pairs, routes, nftables (kube-proxy\'s `table ip kube-proxy`). With kubeadm the same components are separate: kubelet as a systemd unit, the control plane as static pods (kube-apiserver, etcd, kube-scheduler, kube-controller-manager), kube-proxy as a DaemonSet.' },
    { q: 'Which other services does it depend on?', a: 'On the nodes: systemd, time synchronisation (certificates and leader election), DNS for kube01.corp.lab, the host firewall allowing 6443, 10250 and the NodePort range, kernel features (cgroups v2, br_netfilter, IP forwarding), disk space in /var/lib/rancher (images, logs). For applications: registries reachable from the nodes (or images already present), and whatever the applications themselves need (the inventory pods need the db Service).' },
    { q: 'How do requests travel?', a: 'Client → `kube01.corp.lab:30080` → kube-proxy\'s **DNAT** rule on kube01 rewrites it to a Ready pod, e.g. `10.42.1.4:8000` → kube01 routes 10.42.1.0/24 **via 10.0.20.91** (flannel host-gw) → kube02 → `cni0` bridge → the pod\'s veth → gunicorn on port 8000. Inside the cluster the inventory pod resolves `db` through CoreDNS (search `default.svc.cluster.local`) to the db Service\'s ClusterIP, and kube-proxy on its node DNATs that to the db pod\'s IP:5432. A Service without Ready endpoints gets a **reject** rule instead: connection refused.' },
    { q: 'How do authentication and authorisation work?', a: 'Every API request is authenticated (client certificate in the kubeconfig, a bearer token such as a ServiceAccount token, or a cloud plugin) and then authorised by **RBAC** (Roles and ClusterRoles bound to users, groups or ServiceAccounts). The k3s admin kubeconfig `/etc/rancher/k3s/k3s.yaml` is cluster-admin: keep it root-only (0600). Pods get a ServiceAccount token mounted at `/var/run/secrets/kubernetes.io/serviceaccount`. Secrets are base64-encoded, not encrypted, unless encryption at rest is enabled (k3s: `secrets-encryption: true`).' },
    { q: 'How does it start at boot?', a: '`k3s.service` and `k3s-agent.service` are enabled by the install script. On start, k3s starts containerd, the control plane (server) and the kubelet; the kubelet restarts the pods assigned to its node from the API server\'s records. Workloads are not "started" by anyone: their Deployments still exist, so the controllers and kubelets bring them back.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If a **container** exits, the kubelet restarts it with a growing back-off (CrashLoopBackOff). If a **pod** or its **node** disappears, its ReplicaSet creates a replacement elsewhere (after the node has been NotReady for about 5 minutes). If **k3s on kube01** (the control plane) stops, running containers keep running and serving, but nothing can be changed, nothing is rescheduled, and kubectl gets "connection refused". If **k3s-agent on kube02** stops, kube02 becomes **NotReady** and its pods are eventually replaced on kube01.' },
  ],
  ports: [
    { port: '6443', proto: 'TCP (HTTPS)', purpose: 'Kubernetes API server on kube01: kubectl, agents, controllers' },
    { port: '10250', proto: 'TCP (HTTPS)', purpose: 'Kubelet API on every node: logs, exec, metrics (from the API server)' },
    { port: '30000–32767', proto: 'TCP/UDP', purpose: 'NodePort Services on every node address (inventory: 30080)' },
    { port: '8472', proto: 'UDP', purpose: 'flannel VXLAN between nodes (not used with the lab\'s host-gw backend)' },
    { port: '53 on 10.43.0.10', proto: 'UDP/TCP', purpose: 'Cluster DNS (CoreDNS, Service kube-dns) for pods' },
    { port: '10.43.0.1:443', proto: 'TCP (HTTPS)', purpose: 'The kubernetes Service: the API server as seen from pods' },
  ],
  processes: [
    { name: 'k3s server (k3s.service)', platform: 'kube01', role: 'API server, scheduler, controller manager, datastore (SQLite via kine), plus kubelet, kube-proxy and flannel for kube01 itself' },
    { name: 'k3s agent (k3s-agent.service)', platform: 'kube02', role: 'kubelet, kube-proxy and flannel; joins the server at https://kube01.corp.lab:6443 with the node token' },
    { name: 'containerd + containerd-shim-runc-v2', platform: 'Every node (started by k3s)', role: 'Container runtime behind the kubelet (CRI); one shim per pod. Inspect with crictl.' },
    { name: 'CoreDNS (pod, Deployment coredns)', platform: 'kube-system namespace', role: 'Cluster DNS behind the kube-dns Service 10.43.0.10' },
    { name: 'kubectl', platform: 'kube01 (root), ws01 (alice), any admin workstation', role: 'API client: reads and writes objects; changes nothing on the nodes directly' },
    { name: 'kube-apiserver, etcd, kube-scheduler, kube-controller-manager, kubelet, kube-proxy', platform: 'kubeadm clusters', role: 'The same components as separate processes: kubelet as a systemd unit, the control plane as static pods in /etc/kubernetes/manifests' },
  ],
  dependencies: {
    title: 'What "http://kube01.corp.lab:30080/health answers" depends on (top needs everything below it)',
    caption: 'Check each layer with its own command: kubectl get/describe/logs for pods, kubectl get ep for the Service, kubectl exec for DNS and the in-cluster path, nft and ip route on the nodes for kube-proxy and flannel, systemctl/journalctl for k3s itself.',
    rows: [
      { label: 'Clients', nodes: [{ id: 'client', label: 'ws01 browser / curl', sub: 'kube01:30080', kind: 'client' }, { id: 'admin', label: 'kubectl (alice)', sub: '~/.kube/config', kind: 'client' }] },
      { label: 'Node network', nodes: [{ id: 'fw', label: 'Firewalls', sub: '30000–32767, 6443', kind: 'network' }, { id: 'nodeport', label: 'kube-proxy', sub: 'NodePort DNAT (nft)', kind: 'network' }, { id: 'dns', label: 'CoreDNS', sub: 'kube-dns 10.43.0.10', kind: 'service' }] },
      { label: 'Service', nodes: [{ id: 'svc', label: 'Service inventory', sub: 'selector app=inventory', kind: 'service' }, { id: 'ep', label: 'Endpoints', sub: 'Ready pods only', kind: 'data' }] },
      { label: 'Pods', nodes: [{ id: 'pod', label: 'inventory pods', sub: ':8000, readiness /health', kind: 'service' }, { id: 'cfg', label: 'ConfigMap + Secret', sub: 'DB_HOST, DB_PASSWORD', kind: 'data' }, { id: 'db', label: 'db Service + pod', sub: 'postgres :5432', kind: 'service' }] },
      { label: 'Node', nodes: [{ id: 'kubelet', label: 'kubelet + containerd', sub: 'k3s / k3s-agent', kind: 'os' }, { id: 'cni', label: 'cni0 + flannel', sub: 'routes 10.42.x.0/24', kind: 'network' }, { id: 'img', label: 'Images', sub: 'containerd store', kind: 'data' }] },
      { label: 'Control plane', nodes: [{ id: 'api', label: 'API server', sub: 'kube01:6443', kind: 'os' }, { id: 'ctrl', label: 'Scheduler + controllers', sub: 'k3s server', kind: 'os' }, { id: 'store', label: 'Datastore', sub: 'SQLite (kine)', kind: 'data' }] },
    ],
    edges: [
      ['client', 'fw'], ['fw', 'nodeport'], ['nodeport', 'svc'], ['svc', 'ep'], ['ep', 'pod'], ['pod', 'cfg'], ['pod', 'db'], ['pod', 'dns'],
      ['pod', 'kubelet'], ['pod', 'cni'], ['kubelet', 'img'], ['kubelet', 'api'], ['nodeport', 'api', 'watches'], ['ep', 'ctrl'], ['admin', 'api'], ['ctrl', 'api'], ['api', 'store'],
    ],
  },
  sequence: {
    title: 'ws01 requests http://kube01.corp.lab:30080/health; the Ready pod chosen runs on kube02',
    caption: 'k3s v1.30 lab: kube-proxy in nftables mode on both nodes, flannel host-gw, CoreDNS on kube01 (10.42.0.2) behind 10.43.0.10.',
    lanes: [{ id: 'c', label: 'ws01', sub: 'curl' }, { id: 'k1', label: 'kube01', sub: '10.0.20.90, kube-proxy' }, { id: 'k2', label: 'kube02', sub: '10.0.20.91, cni0' }, { id: 'p', label: 'inventory pod', sub: '10.42.1.4:8000' }, { id: 'd', label: 'CoreDNS', sub: '10.43.0.10' }, { id: 'db', label: 'db pod', sub: 'postgres :5432' }],
    steps: [
      { from: 'c', to: 'k1', label: 'TCP SYN 10.0.20.90:30080', note: 'No Ready endpoints → kube-proxy\'s reject rule → "Couldn\'t connect to server" (refused). A firewall dropping the NodePort range → timeout.' },
      { from: 'k1', to: 'k2', label: 'DNAT → 10.42.1.4:8000, routed via 10.0.20.91', note: 'flannel host-gw: kube01 has the route 10.42.1.0/24 via 10.0.20.91. kube02 NotReady or the route missing → timeout.' },
      { from: 'k2', to: 'p', label: 'cni0 → veth → pod eth0, GET /health', note: 'targetPort not the port the app listens on → the pod answers RST: refused although the Service has endpoints.' },
      { from: 'p', to: 'd', label: 'A? db.default.svc.cluster.local', note: 'CoreDNS scaled to 0 → "no servers could be reached"; the app cannot find its database.' },
      { from: 'd', to: 'p', label: 'db = 10.43.215.134 (ClusterIP)' },
      { from: 'p', to: 'db', label: 'TCP 10.43.215.134:5432 → DNAT to the db pod', note: 'db has no Ready pod → refused; /health answers 503 and the readiness probe takes the inventory pods out of the Service.' },
      { from: 'db', to: 'p', label: 'query result' },
      { from: 'p', to: 'c', label: 'HTTP/1.1 200 {"status":"ok","database":"ok"}' },
    ],
  },
  files: [
    { path: '/etc/rancher/k3s/k3s.yaml', platform: 'kube01 (k3s server)', kind: 'auth', perms: 'root:root 0600', contains: 'The cluster-admin kubeconfig: server https://127.0.0.1:6443, the cluster CA, a client certificate and key.', accessed: 'Written by k3s at each start; read by kubectl, crictl and `k3s` subcommands on kube01.', problems: 'Non-root users get `WARN[0000] Unable to read /etc/rancher/k3s/k3s.yaml …` and `permission denied`. Do not chmod it world-readable: it is full control of the cluster. Give people their own kubeconfig instead.' },
    { path: '/etc/rancher/k3s/config.yaml', platform: 'kube01 and kube02', kind: 'config', perms: 'root:root 0600 (contains a token on agents)', contains: 'Server: write-kubeconfig-mode, tls-san (kube01.corp.lab), flannel-backend: host-gw, disable: traefik, servicelb, metrics-server, local-storage. Agent: server URL and token-file.', accessed: 'When k3s / k3s-agent starts.', problems: 'YAML errors stop k3s from starting. An add-on removed from `disable` is installed at the next start. cluster-cidr and service-cidr cannot be changed on an existing cluster.' },
    { path: '~/.kube/config', platform: 'ws01 (/home/alice/.kube/config), admin workstations', kind: 'auth', perms: 'user 0600', contains: 'Clusters, users (credentials) and contexts; current-context.', accessed: 'By every kubectl command.', problems: 'Server 127.0.0.1 copied from the server → connection refused; a server name missing from the certificate → x509 error; the wrong current context → commands go to another cluster or namespace.' },
    { path: '/var/lib/rancher/k3s/server/', platform: 'kube01', kind: 'data', perms: 'root 0700', contains: '`db/` (the datastore: every object), `tls/` (cluster CA and certificates), `node-token` (join token for agents), `manifests/` (add-ons k3s applies at start, e.g. coredns.yaml).', accessed: 'Continuously by k3s server.', problems: 'Losing it loses the cluster\'s state: back it up (`k3s etcd-snapshot` with embedded etcd, or copy db/ with k3s stopped for SQLite). The node-token lets any machine join as a node: protect it.' },
    { path: '/var/lib/rancher/k3s/agent/containerd/', platform: 'Every node', kind: 'data', perms: 'root 0700', contains: 'containerd\'s images and container filesystems.', accessed: 'By containerd on pulls and container starts.', problems: 'A full disk triggers DiskPressure: the kubelet evicts pods and stops new ones. Clean images with `crictl rmi --prune` on a real node, never by deleting files.' },
    { path: '/var/log/pods/<ns>_<pod>_<uid>/<container>/N.log', platform: 'Every node', kind: 'log', contains: 'Each container\'s stdout/stderr (what `kubectl logs` shows), one file per restart.', accessed: 'Written by the runtime; read by kubectl logs and log shippers.', problems: 'Only on the pod\'s node, and deleted with the pod: a pod replaced by a rollout takes its logs with it.' },
    { path: '/etc/systemd/system/k3s.service, k3s-agent.service', platform: 'kube01, kube02 (the simulator shows /lib/systemd/system)', kind: 'unit', perms: 'root:root 0644', contains: 'ExecStart=/usr/local/bin/k3s server (or agent), Restart=always, KillMode=process, Delegate=yes.', accessed: 'At boot and on daemon-reload.', problems: '`KillMode=process` is why stopping k3s leaves the containers running. To stop everything on a node use `/usr/local/bin/k3s-killall.sh` (real installs).' },
    { path: 'journal: journalctl -u k3s / -u k3s-agent', platform: 'kube01, kube02', kind: 'log', contains: 'Messages of all embedded components: API server, scheduler, kubelet, containerd, flannel.', accessed: 'Continuously.', problems: 'Very verbose on real clusters: filter with `--since` and grep for `level=error` or `E1102`-style klog lines. Application output is not here: use kubectl logs.' },
  ],
  management: [
    {
      platform: 'kube01 / kube02 (k3s nodes, as root)',
      tasks: [
        { task: 'Is k3s running?', command: 'systemctl status k3s\njournalctl -u k3s -n 20', explain: 'On kube01. On kube02 the unit is k3s-agent. `failed` → read the journal lines.', sim: true },
        { task: 'Restart the control plane or an agent', command: 'systemctl restart k3s', explain: 'Restarts the API server, scheduler, controllers and the kubelet on kube01. Running containers keep running (KillMode=process).', risk: 'kubectl and every controller are unavailable for some seconds; changes made meanwhile fail. Rarely the right fix for an application problem.', sim: true },
        { task: 'Nodes and their health', command: 'kubectl get nodes -o wide\nkubectl describe node kube02', explain: 'STATUS Ready / NotReady / SchedulingDisabled; Conditions; the pods on the node and their requests.', sim: true },
        { task: 'Everything in a namespace, or all namespaces', command: 'kubectl get all\nkubectl get pods -A -o wide', explain: 'Pods, Services, Deployments and ReplicaSets; -A includes kube-system (CoreDNS).', sim: true },
        { task: 'Containers and images on this node', command: 'crictl ps -a\ncrictl images', explain: 'What containerd really runs on this node, also when the API server is down.', sim: true },
        { task: 'Service rules and pod routes on this node', command: 'nft list table ip kube-proxy\nip route', explain: 'One dnat rule per Service port and NodePort (reject when no endpoints); routes to the other node\'s pod subnet via its node address.', sim: true },
      ],
    },
    {
      platform: 'Workloads (kubectl on kube01 as root, or on ws01 as alice)',
      tasks: [
        { task: 'Status of an application', command: 'kubectl get deploy,rs,pods,svc,ep -l app=inventory\nkubectl rollout status deploy/inventory', explain: 'READY 2/2, pods 1/1 Running, endpoints listing the pod IPs.', sim: true },
        { task: 'Why is a pod not Ready?', command: 'kubectl describe pod -l app=inventory\nkubectl logs deploy/inventory --tail 20', explain: 'Events at the bottom of describe; the application\'s own messages in logs (add --previous for a crashed container).', sim: true },
        { task: 'Apply a change from the manifest', command: 'kubectl apply -f inventory.yaml\nkubectl rollout status deploy/inventory', explain: 'The file is the source of truth; apply shows created / configured / unchanged per object.', risk: 'A changed pod template replaces every pod of the Deployment (rolling update).', sim: true },
        { task: 'Roll back a bad version', command: 'kubectl rollout history deploy/inventory\nkubectl rollout undo deploy/inventory', explain: 'Returns to the previous pod template as a new revision.', risk: 'Only the template: ConfigMaps, Secrets and data are not rolled back. Fix the manifest too.', sim: true },
        { task: 'Restart all pods of a Deployment', command: 'kubectl rollout restart deploy/inventory', explain: 'A rolling replacement; the usual way to make pods re-read a changed ConfigMap or Secret used as environment variables.', sim: true },
        { task: 'Scale', command: 'kubectl scale deploy/inventory --replicas=3', explain: 'More or fewer pods; 0 stops the application without deleting it.', risk: 'The next apply of a manifest with `replicas:` resets it.', sim: true },
        { task: 'Configuration and secrets', command: 'kubectl get cm,secret\nkubectl create secret generic inventory-db --from-literal=password=CHANGE-ME', explain: 'Pods reference them by name in the same namespace.', risk: 'Secret values are base64, readable by anyone who may get secrets; never commit them to git.', sim: true },
        { task: 'Debug pod with network tools', command: 'kubectl run dbg --image=busybox:1.36 -- sleep 3600\nkubectl exec dbg -- nslookup inventory\nkubectl delete pod dbg', explain: 'Tests DNS and Services from inside the cluster with wget, nslookup and nc.', sim: true },
        { task: 'Which cluster and namespace am I using?', command: 'kubectl config current-context\nkubectl config get-contexts', explain: 'Check before deleting anything: the most damaging kubectl mistakes happen in the wrong context.', sim: true },
      ],
    },
    {
      platform: 'Node maintenance',
      tasks: [
        { task: 'Take a node out of service', command: 'kubectl drain kube02\nkubectl get pods -o wide', explain: 'Cordons the node and evicts its pods; their controllers recreate them on kube01.', risk: 'Single-replica workloads (the db) have an outage while they move; bare pods block the drain (use --force only if losing them is fine).', sim: true },
        { task: 'Return it', command: 'kubectl uncordon kube02', explain: 'Scheduling allowed again. Existing pods do not move back by themselves; new or restarted pods are spread again.', sim: true },
      ],
    },
    {
      platform: 'kubeadm and managed clusters (EKS, AKS, GKE)',
      tasks: [
        { task: 'Control plane health (kubeadm)', command: 'kubectl get pods -n kube-system\nsudo crictl ps --name kube-apiserver\njournalctl -u kubelet -n 50', explain: 'The control plane runs as static pods from /etc/kubernetes/manifests; the kubelet is a systemd unit. Certificates expire after one year: `kubeadm certs check-expiration`.' },
        { task: 'Credentials for a managed cluster', command: 'aws eks update-kubeconfig --region eu-central-1 --name prod\naz aks get-credentials --resource-group rg-prod --name aks-prod\ngcloud container clusters get-credentials prod --region europe-west1', explain: 'Writes a context into ~/.kube/config that gets tokens from the cloud CLI. The control plane is the provider\'s: you see no API server processes, only nodes.' },
      ],
    },
  ],
  actions: [
    { action: 'kubectl apply -f (changed template)', when: 'Any change to image, environment, probes, resources, ports of a Deployment.', effect: 'New ReplicaSet; pods replaced gradually within maxSurge/maxUnavailable; old pods serve until new ones are Ready.', risk: 'A broken new version stalls the rollout (old pods keep serving) but a version that passes readiness and fails later goes out everywhere. Watch `rollout status`, keep `rollout undo` ready.' },
    { action: 'kubectl rollout restart deploy/NAME', when: 'Pods must re-read ConfigMaps/Secrets used as environment variables, or a leak needs a fresh start.', effect: 'Every pod replaced by a rolling update; nothing else changes.', risk: 'Briefly fewer Ready pods; with replicas: 1 a short outage.' },
    { action: 'kubectl delete pod POD', when: 'One pod is stuck and its controller will replace it.', effect: 'The ReplicaSet creates a new pod (new name, new IP), possibly on another node.', risk: 'A bare pod (kubectl run) is gone for good. Deleting a pod of a broken Deployment just produces another broken pod.' },
    { action: 'kubectl scale --replicas=0 / N', when: 'Stop an application without deleting it; add capacity.', effect: 'Pods removed or added; Services lose or gain endpoints.', risk: 'Scaling a shared component (CoreDNS) to 0 breaks every application\'s name resolution.' },
    { action: 'kubectl drain NODE / uncordon NODE', when: 'Before rebooting or patching a node.', effect: 'Node unschedulable; its pods evicted and recreated elsewhere if they fit.', risk: 'Outage for single-replica workloads; pods Pending if the other node lacks room. Forgetting uncordon wastes the node.' },
    { action: 'systemctl restart k3s / k3s-agent', when: 'After changing /etc/rancher/k3s/config.yaml, certificate rotation, a hung component.', effect: 'Control plane (server) or kubelet/kube-proxy (agent) restart; containers keep running.', risk: 'API unavailable for some seconds (server). A config error keeps k3s down: check `journalctl -u k3s` immediately.' },
    { action: 'reboot a node', when: 'Kernel updates.', effect: 'Its pods stop; after it is NotReady for about 5 minutes they are recreated elsewhere. k3s starts at boot and the node rejoins.', risk: 'Without drain, the 5-minute wait is an outage for pods only on that node. Rebooting kube01 also takes the control plane away.' },
  ],
  workflow: [
    { question: 'Can I reach the API server, and are the nodes Ready?', why: 'Every kubectl command goes through the API server. If it does not answer, nothing else can be checked with kubectl; if a node is NotReady, its pods are in doubt.', command: 'kubectl get nodes', healthy: 'NAME     STATUS   ROLES                  AGE   VERSION\nkube01   Ready    control-plane,master   3d    v1.30.6+k3s1\nkube02   Ready    <none>                 3d    v1.30.6+k3s1', broken: '"The connection to the server kube01.corp.lab:6443 was refused" → k3s on kube01 is down (`systemctl status k3s`) or the kubeconfig names the wrong server. "permission denied" on /etc/rancher/k3s/k3s.yaml → you are not root: use your own kubeconfig. `NotReady` → the kubelet on that node stopped reporting (k3s-agent down, node off, network).', next: 'Ready → step 2. NotReady → step 8.', sim: true },
    { question: 'What state are the pods in, and where?', why: 'STATUS tells you which stage failed: scheduling, start, the process, or readiness. -o wide adds the IP and the node.', command: 'kubectl get pods -o wide', healthy: 'inventory-lrhb8fpb8-ddbx7   1/1     Running   0          23s   10.42.1.3   kube02   <none>           <none>\ninventory-lrhb8fpb8-rw52l   1/1     Running   0          23s   10.42.0.3   kube01   <none>           <none>', broken: '`Pending` → not scheduled (step 3, FailedScheduling). `ContainerCreating` for long, `CreateContainerConfigError`, `ImagePullBackOff` → the kubelet cannot start it (step 3). `CrashLoopBackOff`, RESTARTS growing → the process exits (step 4). `0/1 Running` → readiness probe fails (step 3).', next: 'All 1/1 Running but unreachable → step 5.', sim: true },
    { question: 'What does Kubernetes say about it (Events)?', why: 'The scheduler and the kubelet record why they could not do something as Events on the pod. describe shows them at the bottom, newest last.', command: 'kubectl describe pod -l app=inventory', healthy: 'Normal    Scheduled   …  default-scheduler   Successfully assigned default/inventory-… to kube02\nNormal    Started     …  kubelet             Started container inventory', broken: '`FailedScheduling … 0/2 nodes are available: 2 Insufficient memory` → requests too large. `Error: configmap "inventory-config" not found` / `secret "inventory-db" not found` → create it in this namespace. `Failed to pull image "corp/inventory:1.5" … not found` → wrong tag. `Readiness probe failed: HTTP probe failed with statuscode: 404` → wrong probe path; `503` → the app reports itself unhealthy (database). Last State `OOMKilled`, Exit Code 137 → memory limit too low.', next: 'Fix the manifest or create the missing object; for crashes → step 4.', sim: true },
    { question: 'What did the application say before it exited?', why: 'A crash loop is the program exiting; its own output says why. The current container may not have written anything yet, so read the previous one.', command: 'kubectl logs deploy/inventory --tail 20\nkubectl logs inventory-ggm2ndpfw-qvrzf --previous', healthy: '[INFO] Listening at: http://0.0.0.0:8000 (1)\n[INFO] Connected to PostgreSQL at db:5432 as inventory', broken: '`Is the server running on that host and accepting TCP/IP connections?` then `Worker failed to boot.` → the database is unreachable (db pods, db Service, DNS). A missing variable or a stack trace → configuration. Nothing at all and Exit Code 137 → killed (OOM), not an application error.', next: 'Database or name problems → steps 5 and 6.', sim: true },
    { question: 'Does the Service have the right endpoints?', why: 'A Service forwards only to Ready pods that match its selector, on its targetPort. Endpoints show the result of both.', command: 'kubectl get svc inventory -o wide\nkubectl get ep inventory\nkubectl get pods -l app=inventory --show-labels', healthy: 'inventory   NodePort   10.43.88.113   <none>   80:30080/TCP   87s   app=inventory\ninventory   10.42.1.3:8000,10.42.0.3:8000   24s', broken: '`<none>` with Ready pods → the selector does not match the pods\' labels (typo). `<none>` with 0/1 pods → readiness (step 3). Endpoints on a port the app does not listen on (`:8080` while gunicorn listens on 8000) → wrong targetPort: refused although endpoints exist.', next: 'Correct the Service (selector, targetPort) in the manifest and apply.', sim: true },
    { question: 'Do names resolve and does the Service answer from inside the cluster?', why: 'Testing from a pod uses the same DNS and path as the application and separates "DNS" from "Service" from "outside path".', command: 'kubectl run dbg --image=busybox:1.36 -- sleep 3600\nkubectl exec dbg -- nslookup inventory\nkubectl exec dbg -- wget -qO- http://inventory/health', healthy: 'Name:\tinventory.default.svc.cluster.local\nAddress: 10.43.67.69\n{"status":"ok","database":"ok"}', broken: '`;; no servers could be reached` → CoreDNS not running: `kubectl get deploy coredns -n kube-system`, `kubectl get ep kube-dns -n kube-system`. Name resolves but wget fails → the Service (step 5). Works inside but not from ws01 → the node path or a firewall (step 7).', next: 'Scale CoreDNS back up or fix the Service; then step 7.', sim: true },
    { question: 'Does the path through the node work?', why: 'A NodePort is a DNAT rule written by kube-proxy on each node; the chosen pod may be on the other node, reached through flannel\'s route.', command: 'nft list table ip kube-proxy\nip route\ncurl -sS http://kube01.corp.lab:30080/health', healthy: 'ip daddr 10.0.20.90 tcp dport 30080 dnat to 10.42.1.4:8000 comment "default/inventory"\n10.42.1.0/24 via 10.0.20.91 dev eth0\n{"status":"ok","database":"ok"}', broken: '`reject comment "default/inventory"` instead of dnat → no endpoints (step 5). Missing route to the other pod subnet → that node is not part of the cluster network (k3s-agent down). Timeout from ws01 only → a firewall between the client VLAN and the nodes.', next: 'Node problems → step 8.', sim: true },
    { question: 'Is the node itself healthy?', why: 'A node whose kubelet stopped reporting is NotReady; its pods are replaced only after about five minutes.', command: 'kubectl describe node kube02\nsystemctl status k3s-agent\njournalctl -u k3s-agent -n 20', healthy: 'Ready            True    KubeletReady                 kubelet is posting ready status\nActive: active (running)', broken: 'Ready Unknown / NotReady → k3s-agent stopped or the node is unreachable (run the systemctl/journalctl lines on kube02). MemoryPressure / DiskPressure True → the kubelet evicts pods. Unschedulable true → cordoned (uncordon after maintenance).', next: 'Start k3s-agent, free resources, uncordon; then re-check from step 1.', sim: true },
  ],
  failures: [
    { symptom: 'Pod stays Pending', causes: ['Requests larger than what any node has free: `0/2 nodes are available: 2 Insufficient memory` (or cpu)', 'nodeSelector/affinity matching no node: `2 node(s) didn\'t match Pod\'s node affinity/selector`', 'All suitable nodes cordoned or tainted, or NotReady'], diagnose: ['kubectl describe pod POD', 'kubectl describe node kube01', 'kubectl get nodes --show-labels'], fix: 'Lower the requests to what the application really needs, correct the selector or label a node (`kubectl label node kube02 disk=ssd`), uncordon, or add capacity.', verify: 'The pod gets a Scheduled event and a node in `kubectl get pods -o wide`.' },
    { symptom: 'ImagePullBackOff / ErrImagePull', causes: ['Tag does not exist (`corp/inventory:1.5 … not found`)', 'Registry unreachable from the nodes (DNS, proxy, firewall)', 'Private registry without imagePullSecrets'], diagnose: ['kubectl describe pod POD', 'crictl images (on the node)', 'kubectl get deploy NAME -o jsonpath={.spec.template.spec.containers[0].image}'], fix: 'Correct the image in the manifest and apply, or `kubectl rollout undo`. For private registries add an imagePullSecret.', verify: 'Pods Running with the intended image; `kubectl rollout status` completes.' },
    { symptom: 'CreateContainerConfigError or ContainerCreating with FailedMount', causes: ['A ConfigMap or Secret referenced by env/envFrom does not exist (`Error: secret "inventory-db" not found`)', 'A key missing in it', 'A volume\'s ConfigMap/Secret missing (`MountVolume.SetUp failed for volume "conf" : configmap "nginx-conf" not found`)', 'Created in another namespace'], diagnose: ['kubectl describe pod POD', 'kubectl get cm,secret', 'kubectl get secret inventory-db -o yaml'], fix: 'Create the object (with the right keys) in the pod\'s namespace. The kubelet retries by itself; no pod deletion needed.', verify: 'The pod reaches Running; `kubectl exec POD -- printenv DB_HOST` shows the value.' },
    { symptom: 'CrashLoopBackOff, RESTARTS growing', causes: ['The application exits: missing or wrong configuration, dependency unreachable', 'Wrong command or arguments', 'A liveness probe killing a slow but healthy app', 'OOMKilled (see next)'], diagnose: ['kubectl logs POD --previous', 'kubectl describe pod POD', 'kubectl get svc,ep'], fix: 'Fix what the log names (configuration, the database Service), correct command/args, loosen the liveness probe (periodSeconds, failureThreshold, or a startupProbe on real clusters). Then apply.', verify: 'RESTARTS stops growing; logs show the normal start-up lines.' },
    { symptom: 'Last State: Terminated, Reason: OOMKilled, Exit Code: 137', causes: ['limits.memory below what the process needs (corp/inventory needs about 120Mi; a 64Mi limit kills it at start)', 'A memory leak reaching the limit over time'], diagnose: ['kubectl describe pod POD', 'kubectl get pod POD -o yaml'], fix: 'Raise limits.memory (and requests) to measured needs, or fix the leak. Exit code 137 = 128 + 9 (SIGKILL).', verify: 'No new OOMKilled in describe; RESTARTS constant.' },
    { symptom: 'Pods 0/1 Running, Service without endpoints', causes: ['Readiness probe path or port wrong (`HTTP probe failed with statuscode: 404`)', 'The application reports itself unhealthy (`statuscode: 503`: inventory\'s /health when the database is unreachable)'], diagnose: ['kubectl describe pod POD', 'kubectl logs POD', 'kubectl get ep NAME'], fix: 'Correct the probe in the manifest (path /health, port 8000), or fix the dependency the application reports.', verify: 'Pods 1/1; endpoints list them.' },
    { symptom: 'NodePort or ClusterIP refused, `kubectl get ep` shows `<none>` although pods are 1/1 Running', causes: ['The Service selector does not match the pods\' labels (app=inventry vs app=inventory)'], diagnose: ['kubectl get svc NAME -o wide', 'kubectl get pods --show-labels', 'nft list table ip kube-proxy'], fix: 'Correct the selector in the Service manifest and apply. (kube-proxy replaces its reject rule with a dnat rule within seconds.)', verify: 'kubectl get ep lists pod IPs; curl gets 200.' },
    { symptom: 'Refused although endpoints exist', causes: ['targetPort is not the port the container listens on (endpoints `10.42.1.4:8080`, gunicorn on 8000)', 'The application listens on 127.0.0.1 inside the pod'], diagnose: ['kubectl describe svc NAME', 'kubectl logs deploy/NAME --tail 20', 'kubectl exec dbg -- nc -zv POD-IP 8000'], fix: 'Set targetPort to the container port (or a named port) and apply; make the application listen on 0.0.0.0.', verify: 'curl through the Service and the NodePort returns 200.' },
    { symptom: 'Names do not resolve in pods ("no servers could be reached"), ClusterIPs still work', causes: ['CoreDNS scaled to 0, crashing or Pending', 'kube-dns Service without endpoints'], diagnose: ['kubectl get deploy,pods -n kube-system', 'kubectl get ep kube-dns -n kube-system', 'kubectl exec dbg -- nslookup kubernetes.default'], fix: '`kubectl scale deploy coredns -n kube-system --replicas=1` (or fix why it crashes); in k3s the manifest in /var/lib/rancher/k3s/server/manifests restores it at the next k3s start.', verify: 'nslookup from a pod answers with the ClusterIP.' },
    { symptom: 'A node is NotReady', causes: ['k3s-agent stopped or crashed on that node', 'Node down or unreachable from kube01', 'Disk or memory exhausted'], diagnose: ['kubectl describe node kube02', 'systemctl status k3s-agent (on kube02)', 'journalctl -u k3s-agent -n 50 (on kube02)'], fix: 'Start the agent, fix the network or free disk; pods return to the node only when rescheduled.', verify: 'kubectl get nodes shows Ready; pods spread again after new rollouts.' },
    { symptom: 'kubectl: "The connection to the server … was refused" or permission denied', causes: ['k3s.service on kube01 stopped or failed', 'kubeconfig server address wrong (127.0.0.1 copied to a workstation)', 'Non-root user using /etc/rancher/k3s/k3s.yaml'], diagnose: ['systemctl status k3s (on kube01)', 'journalctl -u k3s -n 50', 'kubectl config view'], fix: 'Start/repair k3s; correct the kubeconfig\'s server; give users their own kubeconfig rather than loosening k3s.yaml\'s mode.', verify: 'kubectl get nodes answers from kube01 and ws01.' },
  ],
  verification: [
    { check: 'Nodes Ready', command: 'kubectl get nodes', expect: 'kube01 and kube02 Ready, none SchedulingDisabled after maintenance' },
    { check: 'System pods healthy', command: 'kubectl get pods -n kube-system', expect: 'coredns-… 1/1 Running, RESTARTS not growing' },
    { check: 'Application rolled out', command: 'kubectl rollout status deploy/inventory', expect: 'deployment "inventory" successfully rolled out' },
    { check: 'Service has Ready endpoints on the right port', command: 'kubectl get ep inventory', expect: 'inventory   10.42.1.3:8000,10.42.0.3:8000' },
    { check: 'Name resolution from pods', command: 'kubectl exec dbg -- nslookup inventory', expect: 'Name:\tinventory.default.svc.cluster.local' },
    { check: 'Reachable from the client network through both nodes', command: 'curl -s http://kube01.corp.lab:30080/health; curl -s http://kube02.corp.lab:30080/health', expect: '{"status":"ok","database":"ok"} twice' },
    { check: 'Manifest and cluster agree', command: 'kubectl apply -f inventory.yaml', expect: 'deployment.apps/inventory unchanged\nservice/inventory unchanged' },
  ],
  refIds: [
    'kubectl-get', 'kubectl-describe', 'kubectl-logs', 'kubectl-exec', 'kubectl-apply', 'kubectl-rollout', 'kubectl-scale', 'kubectl-expose', 'kubectl-drain', 'crictl',
    'file:k3s-yaml', 'file:kubeconfig', 'file:k3s-config', 'file:k8s-manifest', 'file:pod-logs',
    'proc:k8s-pod-not-running', 'proc:k8s-service-unreachable', 'proc:k8s-rollout-rollback',
    'docker', 'docker-logs', 'systemctl', 'journalctl', 'curl', 'nft', 'ip', 'dig', 'file:resolv.conf', 'proc:safe-config-change',
  ],
};

// --- Lesson -------------------------------------------------------------------------

export const KUBERNETES_LESSON: Lesson = {
  id: 'kubernetes',
  moduleId: 'E',
  title: 'Kubernetes (k3s) operation and troubleshooting',
  level: 'intermediate',
  summary: 'How the API server, controllers, scheduler, kubelet, kube-proxy and CoreDNS turn a manifest into running pods behind a Service, and how to find why a pod is not Running and Ready or a Service answers nobody, from kubectl get and describe down to the node\'s NAT rules and routes.',
  concepts: ['k8s.workloads', 'k8s.networking', 'docker.lifecycle', 'docker.networking', 'net.nat', 'dns.resolution', 'svc.systemd'],

  what: `
With [Docker](#/lesson/docker/what) you started each container yourself on one host. **Kubernetes** (often written **k8s**) takes a description ("two copies of corp/inventory:1.4, with this configuration, reachable on port 30080") and decides which machine runs each copy.

The machines are called **nodes**. The lab has two, running **k3s**, a compact Kubernetes distribution packaged as a single program:
- **kube01** runs the **control plane** (it stores the description and makes decisions) and also runs application containers.
- **kube02** is a **worker** ("agent" in k3s): it only runs containers.

### Problems it solves
- **Updating without downtime.** A new version replaces the old copies a few at a time, continuing only while the new copies pass their health checks. A broken version stops the update while the old copies keep serving; one command rolls back.
- **Configuration as files.** The application (copies, configuration, network entry point) is described in YAML files kept in git, so the cluster can be rebuilt from them.

### Desired state and controllers
You store a **desired state** in the cluster's database through the **API server**. **Controllers** (small control loops) keep comparing it with what is running and fix any difference. A deleted or restarted pod is therefore rebuilt from the same description: to fix a broken pod, fix the **manifest**.

:::practice
Q: A colleague deletes a crashing pod of the inventory Deployment, and a new pod with a different name appears and crashes in the same way. Why?
A: The Deployment's **desired state** still asks for that pod. Its ReplicaSet creates a replacement from the same pod template, with the same problem. Fix the template (the manifest), not the pod.
Q: What do you change to run three copies of the application instead of two?
A: The desired state: \`replicas: 3\` in the Deployment (in the manifest, then \`kubectl apply\`), or \`kubectl scale deploy/inventory --replicas=3\`. The controllers create the extra pod.
:::

### The pieces
**Control plane** (inside \`k3s.service\` on kube01):
- **API server** (port 6443): every client and component reads and writes objects through it; it checks each request (who you are, what you may do, whether the object is valid).
- **Datastore**: stores the objects (etcd in most clusters; SQLite by default in k3s).
- **Scheduler**: picks a node for each new pod, based on free resources and rules.
- **Controller manager**: the control loops (Deployments, ReplicaSets, Endpoints, nodes …).

**Every node** (inside \`k3s.service\` on kube01 and \`k3s-agent.service\` on kube02):
- **kubelet**: starts the pods assigned to this node, runs their health checks, restarts crashed containers and reports back.
- **Container runtime** (**containerd**, the runtime Docker also uses underneath): pulls images and runs containers.
- **kube-proxy**: turns Services into NAT rules in the node's firewall (nftables in the lab).
- **CNI plugin** (**flannel**): gives each pod an IP address and connects the pod networks of the nodes.

**kubectl** is the command-line client. It only talks to the API server, never to a node directly.

:::practice
Q: kubectl on ws01 says "The connection to the server kube01.corp.lab:6443 was refused", but the inventory application still answers in the browser. How is that possible?
A: kubectl talks to the **API server** (control plane), which is down. The pods already running on the nodes are run by the **kubelets and containerd**, which keep them running. Nothing can be changed or rescheduled until the API server is back.
Q: Which component chooses the node a new pod runs on, and which one actually starts its container?
A: The **scheduler** chooses the node; the **kubelet** on that node starts the container through containerd.
:::

### The objects you will use
- **Pod**: one or more containers that share an IP address. Disposable: a replacement has a new name and IP.
- **Deployment** → **ReplicaSet** → **Pods**: a Deployment holds the pod template and the number of copies. It creates one ReplicaSet per template version, which keeps that many pods running.
- **Service**: a stable virtual IP, port and DNS name in front of the pods it **selects**. **Endpoints** list the pods currently behind it (only the Ready ones).
- **ConfigMap** and **Secret**: configuration and passwords, given to pods as environment variables or files.
- **Namespace**: a named group of objects (\`default\`, \`kube-system\` where CoreDNS runs). Names only need to be unique within a namespace.
- **Labels and selectors**: labels are key=value tags (\`app=inventory\`); selectors pick objects by label. Services and Deployments find their pods only through labels.

:::practice
Q: Which object makes sure that two inventory pods exist at all times: the Deployment, the ReplicaSet or the Service?
A: The **ReplicaSet** (created and managed by the Deployment). The Service only sends traffic to the pods; it does not create them.
Q: How does a Service know which pods belong to it?
A: Through its **selector**: it picks every pod whose labels match (for example \`app=inventory\`), and lists the Ready ones as its endpoints.
:::

### How it connects to earlier lessons
- A pod is a set of [containers](#/lesson/docker/internals) started by containerd, with namespaces and cgroups.
- Each pod is attached by a veth pair to a [Linux bridge](#/lesson/netif/what) (\`cni0\`) on its node. The nodes route each other's pod subnets with ordinary routes.
- A Service is [destination NAT](#/lesson/nat/what): kube-proxy writes DNAT rules into [nftables](#/lesson/nftables/what). Pods find Services through DNS.
- k3s itself is a [systemd service](#/lesson/systemd/what) on each node.

:::practice
Q: A Service's ClusterIP 10.43.67.69 is on no interface of any machine. Which earlier-lesson mechanism makes connections to it work?
A: **DNAT**: kube-proxy's nftables rules on each node rewrite the destination 10.43.67.69:80 to a pod's IP and port before routing.
Q: How do you check whether k3s itself is running on kube02?
A: Like any systemd service: \`systemctl status k3s-agent\` (on kube01 the unit is \`k3s\`), and \`journalctl -u k3s-agent\` for its messages.
:::

### Where you meet it
Internal platforms that host many small applications, CI/CD systems, vendor products delivered as "Helm charts", and every major cloud (Amazon EKS, Azure AKS, Google GKE).

### In the lab
> The cluster: **k3s v1.30.6+k3s1** on **kube01** (10.0.20.90, server, sw01 port swp24) and **kube02** (10.0.20.91, agent, swp25), Debian 12, server VLAN 20, DNS names kube01.corp.lab and kube02.corp.lab. flannel **host-gw**: pod subnets **10.42.0.0/24** (kube01, \`cni0\` 10.42.0.1) and **10.42.1.0/24** (kube02); Services from **10.43.0.0/16** (\`kubernetes\` 10.43.0.1:443, CoreDNS \`kube-dns\` **10.43.0.10**). k3s's Traefik, ServiceLB, metrics-server and local-storage are disabled: no Ingress, no LoadBalancer IPs, no \`kubectl top\`, no persistent volumes.
>
> Root on kube01 uses kubectl directly (admin kubeconfig \`/etc/rancher/k3s/k3s.yaml\`, mode 0600); on **ws01**, alice has her own \`~/.kube/config\` for https://kube01.corp.lab:6443. Images: nginx:1.25, postgres:16, corp/inventory:1.4 (gunicorn on port 8000; needs DB_HOST, DB_USER, DB_PASSWORD; \`/health\` returns 200 when the database is reachable, 503 otherwise) and busybox:1.36 (sleep, echo, wget, nslookup, nc).
>
> Simulated: the main \`kubectl\` commands (get, describe, logs, exec, apply, scale, set image, rollout, cordon, drain), \`crictl\`, scheduling (requests, nodeSelector, taints), image pulls, ConfigMaps and Secrets, crash back-off, OOM kills, probes, kube-proxy's nftables rules, CoreDNS, flannel routes. Not simulated: load balancing (a Service always uses its first Ready endpoint), kubectl edit, patch, port-forward and explain, NetworkPolicy, DaemonSets, Jobs, autoscaling, Helm.
`,

  internals: `
### 1. From \`kubectl apply\` to a running pod
\`kubectl apply -f inventory.yaml\` on kube01:
1. kubectl reads its kubeconfig (\`/etc/rancher/k3s/k3s.yaml\` for root on kube01), and sends the objects to the **API server** over HTTPS.
2. The API server **authenticates** the client certificate, **authorises** the request (RBAC), **validates** the objects (fields, types, selector vs labels) and **stores** them. Nothing is stored if validation fails, so a typo cannot break what is running.
3. The **Deployment controller** sees a new Deployment and creates a **ReplicaSet** named \`inventory-<hash>\`; the **ReplicaSet controller** creates two **pods** \`inventory-<hash>-<suffix>\`, still without a node (\`Pending\`).
4. The **scheduler** picks a node for each pod (it spreads copies of one Deployment across nodes) and writes the choice into the pod.
5. The **kubelet** on that node sees the pod: \`ContainerCreating\`. It pulls the image if it is missing, prepares environment variables and volumes from ConfigMaps and Secrets, has containerd create the pod's network namespace (an IP from the node's pod subnet) and start the container.
6. The kubelet runs the **readiness probe**; when it succeeds the pod is \`1/1 Running\`, and the **endpoints controller** adds it to the Service's endpoints. kube-proxy on every node updates its rules.

:::practice
Q: \`kubectl apply\` fails with "strict decoding error: unknown field". Does the application keep running with its previous version?
A: **Yes.** The API server validates before storing; a rejected object is not stored at all, so nothing changes in the cluster.
Q: A pod shows \`Pending\` and its describe output has no "Scheduled" event. Which component has not done its job yet, and where do you read why?
A: The **scheduler**. Its reason is the **FailedScheduling** event in \`kubectl describe pod\` (for example "0/2 nodes are available: 2 Insufficient memory").
:::

### 2. Labels and selectors
Objects are tied together only by labels, never by names:
- A **Deployment's** \`spec.selector.matchLabels\` must match \`spec.template.metadata.labels\`; otherwise the API server refuses it: \`selector\` does not match template \`labels\`.
- A **Service's** \`spec.selector\` picks pods by label. If it matches nothing (\`app: inventry\`), the Service is created without complaint, but \`kubectl get ep\` shows \`<none>\` and every connection is refused.
- Compare them with \`kubectl get svc NAME -o wide\` (SELECTOR column) and \`kubectl get pods --show-labels\`.

:::practice
Q: Why does the API server reject a Deployment whose selector does not match its template labels, but accept a Service whose selector matches no pod?
A: A Deployment that cannot select its own pods would create pods forever; that is always a mistake. A Service may legitimately be created before its pods exist, so an empty selection is allowed (and shows as endpoints \`<none>\`).
Q: Which two commands show whether a Service's selector matches the pods' labels?
A: \`kubectl get svc NAME -o wide\` (the SELECTOR column) and \`kubectl get pods --show-labels\`.
:::

### 3. Pod networking: cni0 and flannel
Every pod gets its own IP address from its node's **pod subnet**: kube01 hands out 10.42.0.x, kube02 10.42.1.x. On each node the CNI plugin connects pods to the bridge **cni0** (10.42.0.1 on kube01) with a veth pair, exactly as Docker connects containers to docker0. Every pod can reach every other pod directly, without NAT, on its own IP.

To reach the other node's pods, flannel with the **host-gw** backend adds ordinary routes: kube01 has \`10.42.1.0/24 via 10.0.20.91 dev eth0\`, kube02 has \`10.42.0.0/24 via 10.0.20.90\`. This works only when the nodes share one Layer-2 network (as in VLAN 20). flannel's default **VXLAN** backend instead wraps pod traffic in UDP port 8472 so it can cross routers.

:::practice
Q: On kube01, \`ip route\` shows \`10.42.1.0/24 via 10.0.20.91 dev eth0\`. Which pods does this route reach, and who added it?
A: The pods on **kube02** (its pod subnet 10.42.1.0/24). **flannel** (host-gw backend) added it.
Q: A pod on kube01 at 10.42.0.5 connects to a pod on kube02 at 10.42.1.4. Is the source address translated?
A: **No.** Pod-to-pod traffic is routed with the pod IPs unchanged; Kubernetes requires that every pod can reach every pod without NAT.
:::

### 4. Services, Endpoints and kube-proxy
Pods are replaced all the time, so clients use a **Service** instead:
- **ClusterIP** (the default type): a virtual IP from 10.43.0.0/16, reachable from pods and nodes. \`port\` is the Service's port, **\`targetPort\`** is the port the container listens on.
- **NodePort**: additionally a port from **30000–32767** on **every** node's address. \`kube01.corp.lab:30080\` and \`kube02.corp.lab:30080\` both work, whichever node the pods run on.
- **LoadBalancer**: a NodePort plus an external address from a cloud or a load-balancer add-on (disabled in the lab).
- **Endpoints**: the IP:targetPort of every **Ready** pod the selector matches. Not-Ready pods are left out.

**kube-proxy** on each node turns this into nftables rules (\`nft list table ip kube-proxy\`): \`ip daddr 10.43.67.69 tcp dport 80 dnat to 10.42.1.4:8000\` for the ClusterIP and \`ip daddr 10.0.20.90 tcp dport 30080 dnat to 10.42.1.4:8000\` for the NodePort. When a Service has **no endpoints**, kube-proxy writes a **reject** rule instead: clients get "connection refused" immediately.

The request path for \`curl http://kube01.corp.lab:30080/health\` from ws01: kube01's eth0 → kube-proxy's **DNAT** to a Ready pod (perhaps 10.42.1.4:8000 on kube02) → kube01 routes 10.42.1.0/24 to 10.0.20.91 → kube02's **cni0** → the pod's veth → gunicorn on port 8000. (Real kube-proxy also source-NATs this traffic so the answer comes back through kube01, and chooses a random endpoint for each new connection; the lab always uses the first Ready one.)

:::practice
Q: A NodePort Service's endpoints are \`<none>\`. What does a client connecting to the NodePort get, and why that and not a timeout?
A: **Connection refused**: kube-proxy installs a **reject** rule for Services without endpoints, which answers immediately.
Q: The endpoints are \`10.42.1.4:8080,10.42.0.3:8080\` but the application logs "Listening at: http://0.0.0.0:8000". What is wrong?
A: The Service's **targetPort** is 8080; it must be **8000**, the port the container listens on. Traffic is DNATed to a port where nothing listens, so connections are refused although endpoints exist.
:::

### 5. Cluster DNS
**CoreDNS** runs as a Deployment in \`kube-system\` behind the Service \`kube-dns\` at **10.43.0.10**. Every Service gets a name \`SERVICE.NAMESPACE.svc.cluster.local\`. A pod's \`/etc/resolv.conf\` (written by the kubelet) is:

\`\`\`
search default.svc.cluster.local svc.cluster.local cluster.local corp.lab
nameserver 10.43.0.10
options ndots:5
\`\`\`

so a pod in \`default\` finds the database simply as \`db\`, and a Service in another namespace as \`db.shop\`. Names CoreDNS does not own (\`ns1.corp.lab\`) are forwarded to the node's resolvers. **ndots:5** means a name with fewer than five dots is tried with each search suffix first, which is why one lookup can produce several queries.

If CoreDNS has no Ready pod (scaled to 0, crashing), every name lookup from a pod times out (\`;; no servers could be reached\`) while connections to ClusterIPs and pod IPs still work. Applications that connect by name fail all at once.

:::practice
Q: A pod in the namespace \`shop\` must reach the Service \`db\` in \`default\`. Which short name works?
A: \`db.default\` (or the full \`db.default.svc.cluster.local\`). Plain \`db\` would be searched as \`db.shop.svc.cluster.local\` first.
Q: \`kubectl exec dbg -- nslookup inventory\` times out, but \`wget\` to the inventory Service's ClusterIP works. What do you check?
A: **CoreDNS**: \`kubectl get deploy coredns -n kube-system\` (replicas, Ready) and \`kubectl get ep kube-dns -n kube-system\`. The Service path works; only DNS is missing.
:::

### 6. Probes: readiness and liveness
The kubelet runs **probes** (an HTTP GET, a TCP connect or a command) against each container:
- **readinessProbe**: "may this pod receive traffic now?" While it fails, the pod shows \`0/1 Running\` and is removed from the Service's endpoints. It is **not** restarted. The inventory probe \`httpGet /health port 8000\` fails with 503 while the database is unreachable, so users get "refused" instead of errors from a half-working pod.
- **livenessProbe**: "is this container stuck?" After \`failureThreshold\` (default 3) failures in a row the kubelet kills and restarts the container: "Container web failed liveness probe, will be restarted".
- Defaults: \`periodSeconds: 10\`, \`timeoutSeconds: 1\`, \`failureThreshold: 3\`. A liveness probe that is too strict, or that checks a dependency such as the database, turns a slow day into a restart storm.

:::practice
Q: The database is down for maintenance. Should the inventory pods' liveness probe check /health (which tests the database)?
A: **No.** Restarting the inventory containers does not bring the database back; they would restart in a loop. Check the dependency in the **readiness** probe (stop sending traffic) and keep liveness to "is the process responding" (for example a TCP check on 8000).
Q: Pods show \`0/1 Running\` and describe says "Readiness probe failed: HTTP probe failed with statuscode: 404". Is the application crashing?
A: **No.** It runs and answers, but the probe asks for a path it does not serve (404). Correct the probe's path; the pods are kept out of the Service until it passes.
:::

### 7. Resources, QoS and OOMKilled
Each container can declare:
- **requests** (\`cpu: 100m\`, \`memory: 128Mi\`): what the scheduler reserves on a node. A pod is placed only on a node where the requests still fit (in the lab each node has 2 CPUs and about 3.9 GiB). If none has room: \`Pending\`, FailedScheduling "0/2 nodes are available: 2 Insufficient memory".
- **limits** (\`memory: 256Mi\`): enforced by cgroups at run time. Above the CPU limit the container is **throttled** (slow); above the memory limit the kernel **kills** it: Last State \`OOMKilled\`, Exit Code **137** (128 + SIGKILL), and the kubelet restarts it (CrashLoopBackOff if it keeps happening).
- **QoS class** (shown by describe): **Guaranteed** (requests = limits for CPU and memory), **Burstable** (some requests or limits), **BestEffort** (none: first to be evicted when a node runs short of memory).

\`100m\` CPU means 0.1 CPU ("millicores"); \`Mi\` and \`Gi\` are binary units (1Mi = 1024 × 1024 bytes).

:::practice
Q: A pod is Pending with "0/2 nodes are available: 2 Insufficient memory". Its container requests 8Gi. Will raising its memory **limit** help?
A: **No.** The scheduler uses **requests**, not limits. Lower the request to what the application really needs (or add bigger nodes).
Q: Describe shows Last State: Terminated, Reason: OOMKilled, Exit Code: 137, with \`limits: memory: 64Mi\`. What happened and what is the fix?
A: The process needed more than **64Mi**, so the kernel killed it (137 = 128 + 9, SIGKILL). Raise \`limits.memory\` (and the request) to the measured need, or fix the memory use.
:::

### 8. Configuration: ConfigMaps and Secrets
Pods get configuration from **ConfigMaps** (plain settings) and **Secrets** (passwords, keys), as environment variables (\`env\` with \`valueFrom\`, or \`envFrom\` for all keys) or as files in a volume. Both must exist **in the pod's namespace** before the container can start:
- Missing for environment variables → \`CreateContainerConfigError\`, event "Error: secret "inventory-db" not found".
- Missing for a volume → \`ContainerCreating\` with **FailedMount**: MountVolume.SetUp failed for volume "conf" : configmap "nginx-conf" not found.

The kubelet retries on its own: once you create the object, the pod starts. Environment variables are read **once**, at container start: after changing a ConfigMap, run \`kubectl rollout restart\`.

**Secrets are not encrypted by default.** Their values are only **base64-encoded** (\`czNjcmV0\` is "s3cret"). Anyone allowed to read Secrets in a namespace can read the passwords, and they sit in the datastore in clear form unless encryption at rest is enabled (k3s: \`secrets-encryption: true\`). Restrict access with RBAC and keep Secret values out of git.

:::practice
Q: \`kubectl get secret inventory-db -o yaml\` shows \`password: czNjcmV0\`. Is that encrypted?
A: **No**, it is only **base64-encoded** ("s3cret"). Anyone who may read Secrets in that namespace can decode it.
Q: You created the missing Secret \`inventory-db\` while the pods showed CreateContainerConfigError. Do you have to delete the pods?
A: **No.** The kubelet keeps retrying; the pods start by themselves once the Secret exists in their namespace.
:::

### 9. Rollouts and rollbacks
Changing a Deployment's pod template (image, environment, probes, resources) starts a **rolling update**: a new ReplicaSet is scaled up while the old one is scaled down, within **maxSurge** (extra pods allowed, default 25 %, rounded up) and **maxUnavailable** (missing pods allowed, default 25 %, rounded down). With 2 replicas that is one extra pod and none missing: old pods are removed only when new ones are Ready.

If the new pods never become Ready (\`ImagePullBackOff\` for a tag that does not exist, a crash, a failing readiness probe), the rollout **stalls** and the old pods keep serving. \`kubectl rollout status\` waits and finally reports "exceeded its progress deadline" (\`progressDeadlineSeconds\`, 600 s). Kubernetes does **not** roll back by itself: \`kubectl rollout undo deploy/inventory\` brings back the previous template as a new revision (\`kubectl rollout history\`).

:::practice
Q: After \`kubectl set image deploy/inventory inventory=corp/inventory:1.5\`, one new pod shows ImagePullBackOff and both old pods are still 1/1 Running. Are users affected?
A: **Not yet.** The rollout stalls at the first new pod; maxUnavailable keeps the old pods serving. Undo the rollout or correct the tag.
Q: Does \`kubectl rollout undo\` also restore the ConfigMap you changed at the same time?
A: **No.** It restores only the Deployment's pod template. ConfigMaps, Secrets and data must be reverted separately.
:::

### 10. Scheduling, nodes, cordon and drain
The scheduler filters nodes (enough free **requests**, matching **nodeSelector**/affinity, no **taint** the pod does not tolerate, not **cordoned**, Ready) and then prefers spreading copies across nodes. Each refusal appears in the FailedScheduling event, for example "2 node(s) didn't match Pod's node affinity/selector".

The kubelet reports to the API server every few seconds. If it stops (k3s-agent stopped, node off), the node becomes **NotReady**; after about five minutes its pods are evicted and recreated on the other node.

For maintenance you do it on purpose: \`kubectl cordon kube02\` (no new pods: \`Ready,SchedulingDisabled\`), \`kubectl drain kube02\` (cordon and evict its pods, so they are recreated on kube01), patch and reboot, then \`kubectl uncordon kube02\`. A Deployment with one replica (like the lab's database) is down while its pod moves.

:::practice
Q: You must reboot kube02 for a kernel update. Which commands come before and after the reboot?
A: Before: \`kubectl drain kube02\` (cordon and evict the pods). After it is back and Ready: \`kubectl uncordon kube02\`.
Q: \`kubectl get nodes\` shows kube02 as \`NotReady\`. What is the first thing to check on kube02?
A: Whether the agent runs: \`systemctl status k3s-agent\` and \`journalctl -u k3s-agent\`. NotReady means its kubelet stopped reporting.
:::
`,

  deployment: [
    {
      id: 'k3s',
      platform: 'k3s on Debian 12 (the lab: kube01 server + kube02 agent)',
      summary: 'Install a two-node k3s cluster the way kube01 and kube02 were built: a server with its options in /etc/rancher/k3s/config.yaml, an agent joined with the node token, and a kubeconfig for an administrator\'s workstation. The installation steps run on real Debian 12 VMs; the checks at the end also work in the simulator.',
      prerequisites: ['Two Debian 12 VMs with 2 vCPU and 4 GiB RAM each, static addresses on one VLAN (10.0.20.90, 10.0.20.91), DNS names kube01.corp.lab and kube02.corp.lab, synchronised time.', 'Outbound HTTPS to get.k3s.io and github.com (or a mirror) for the installer and the binary, and to registries for images.', 'Firewall: TCP 6443 to kube01 from kube02 and from admin workstations; TCP 10250 between the nodes; TCP 30000–32767 from client networks to the nodes (for NodePorts).'],
      steps: [
        { title: 'Write the server configuration first', command: 'sudo mkdir -p /etc/rancher/k3s\nsudo tee /etc/rancher/k3s/config.yaml <<\'EOF\'\nwrite-kubeconfig-mode: "0600"\ntls-san:\n  - kube01.corp.lab\nflannel-backend: host-gw\ndisable:\n  - traefik\n  - servicelb\n  - metrics-server\n  - local-storage\nEOF', what: 'k3s reads this file at every start, as if the options were command-line flags.', why: 'The admin kubeconfig stays root-only; the API certificate also covers kube01.corp.lab so workstations can connect by name; host-gw uses plain routes (nodes on one subnet); the add-ons the lab does not use are left out. The network backend is hard to change later, so decide before installing.', expected: '(no output)', simulated: false },
        { title: 'Install the server', command: 'curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.30.6+k3s1 sh -', what: 'Downloads the k3s binary, creates links for kubectl, crictl and ctr, writes and starts k3s.service, and writes /etc/rancher/k3s/k3s.yaml.', why: 'Pinning the version keeps the cluster on a known release (and the same on every node). Read the script first in production; it runs as root.', expected: '[INFO]  Using v1.30.6+k3s1 as release\n[INFO]  Downloading hash https://github.com/k3s-io/k3s/releases/download/v1.30.6+k3s1/sha256sum-amd64.txt\n[INFO]  Installing k3s to /usr/local/bin/k3s\n[INFO]  Creating /usr/local/bin/kubectl symlink to k3s\n[INFO]  systemd: Creating service file /etc/systemd/system/k3s.service\n[INFO]  systemd: Enabling k3s unit\n[INFO]  systemd: Starting k3s', simulated: false },
        { title: 'Check the server', command: 'systemctl status k3s\nkubectl get nodes\nkubectl get pods -n kube-system', what: 'The unit runs, kube01 is Ready, CoreDNS is Running.', why: 'Prove the control plane works before adding nodes.', expected: '● k3s.service - Lightweight Kubernetes\n     Active: active (running) since …\nNAME     STATUS   ROLES                  AGE   VERSION\nkube01   Ready    control-plane,master   1m    v1.30.6+k3s1\nNAME                      READY   STATUS    RESTARTS   AGE\ncoredns-ld9vtwwvv-hgfcw   1/1     Running   0          1m', simulated: true },
        { title: 'Read the join token', command: 'sudo cat /var/lib/rancher/k3s/server/node-token', what: 'The secret an agent presents to join the cluster.', why: 'Anyone with it can add a node (and see the cluster\'s secrets from that node): treat it like a password.', expected: 'K10f4b2c9d1e8a7b6…::server:3c9e2b7a1f6d4e8c', simulated: false },
        { title: 'Install the agent on kube02', command: 'curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.30.6+k3s1 K3S_URL=https://kube01.corp.lab:6443 K3S_TOKEN=\'K10f4b2c9…::server:3c9e2b7a…\' sh -', what: 'Same installer; K3S_URL makes it install k3s-agent.service and join that server.', why: 'Equivalent: put `server:` and `token-file:` in kube02\'s /etc/rancher/k3s/config.yaml (as the lab does) so the token is not in the shell history.', expected: '[INFO]  systemd: Creating service file /etc/systemd/system/k3s-agent.service\n[INFO]  systemd: Enabling k3s-agent unit\n[INFO]  systemd: Starting k3s-agent', simulated: false },
        { title: 'Verify the cluster', command: 'kubectl get nodes -o wide\nip route', what: 'Both nodes Ready with their internal IPs; kube01 has the route to kube02\'s pod subnet.', why: 'A node that is NotReady or a missing route means pods on the two nodes cannot reach each other.', expected: 'NAME     STATUS   ROLES                  AGE   VERSION        INTERNAL-IP   …\nkube01   Ready    control-plane,master   5m    v1.30.6+k3s1   10.0.20.90    …\nkube02   Ready    <none>                 1m    v1.30.6+k3s1   10.0.20.91    …\n10.42.1.0/24 via 10.0.20.91 dev eth0', simulated: true },
        { title: 'Give an administrator access from a workstation', command: '# on ws01, as alice:\nmkdir -p ~/.kube && chmod 700 ~/.kube\nscp root@kube01.corp.lab:/etc/rancher/k3s/k3s.yaml ~/.kube/config\nsed -i \'s#https://127.0.0.1:6443#https://kube01.corp.lab:6443#\' ~/.kube/config\nchmod 600 ~/.kube/config', what: 'A copy of the admin kubeconfig with the server address changed to the node\'s name.', why: '127.0.0.1 only works on kube01 itself; kube01.corp.lab is in the certificate thanks to tls-san. This copy is full cluster-admin: in production give each person their own certificate or OIDC login with RBAC roles, so access can be limited and revoked.', expected: '(no output)', simulated: false },
        { title: 'Verify from the workstation', command: 'kubectl config view\nkubectl get nodes', what: 'kubectl on ws01 uses alice\'s kubeconfig against https://kube01.corp.lab:6443.', why: 'Proves name resolution, the firewall on 6443 and the certificate.', expected: '    server: https://kube01.corp.lab:6443\n…\nkube01   Ready    control-plane,master   …\nkube02   Ready    <none>                 …', simulated: true },
      ],
    },
    {
      id: 'app',
      platform: 'Deploy the inventory application with kubectl (works in the simulator)',
      summary: 'A database Deployment and Service, the inventory Deployment with probes and resources, and a NodePort Service on 30080. Configuration comes from a ConfigMap, the password from a Secret. Run as root on kube01 (or as alice on ws01). Note: the lab has no persistent volumes, so the database\'s data lives only as long as its pod: fine for learning, never for production.',
      prerequisites: ['The cluster from the previous guide (or the lab), kubectl access.', 'The images corp/inventory:1.4 and postgres:16 available to the nodes.'],
      steps: [
        { title: 'Configuration and password', command: 'kubectl create configmap inventory-config --from-literal=DB_HOST=db --from-literal=DB_USER=inventory\nkubectl create secret generic inventory-db --from-literal=password=Inv-2611-db', what: 'Creates the ConfigMap (host and user) and the Secret (password) in the default namespace.', why: 'Pods that reference them do not start until they exist. Keeping the password out of the manifest keeps it out of git.', expected: 'configmap/inventory-config created\nsecret/inventory-db created', simulated: true },
        { title: 'Write db.yaml', command: DB_MANIFEST, what: 'A one-replica postgres Deployment whose password comes from the same Secret, and a ClusterIP Service named db (so the application finds it as "db").', why: 'Pods reach each other through Services, never through pod IPs, which change with every replacement.', expected: '' },
        { title: 'Write inventory.yaml', command: INVENTORY_MANIFEST, what: 'Two inventory pods with configuration from the ConfigMap and Secret, a readiness probe on /health, a liveness probe on the TCP port, requests and a memory limit; a NodePort Service 80 → 8000, node port 30080.', why: 'The selector and template labels must match; targetPort must be the port gunicorn listens on (8000). The readiness probe keeps pods out of the Service while the database is unreachable.', expected: '' },
        { title: 'Apply both', command: 'kubectl apply -f db.yaml\nkubectl apply -f inventory.yaml', what: 'Sends the objects to the API server.', why: 'Validation errors (selector, field names, nodePort range) appear here and nothing is stored.', expected: 'deployment.apps/db created\nservice/db created\ndeployment.apps/inventory created\nservice/inventory created', simulated: true },
        { title: 'Wait for the rollout', command: 'kubectl rollout status deploy/inventory\nkubectl get pods -o wide', what: 'Waits until both inventory pods are Ready.', why: 'Ready means the readiness probe passed: the application reached its database.', expected: 'Waiting for deployment "inventory" rollout to finish: 0 of 2 updated replicas are available...\ndeployment "inventory" successfully rolled out\nNAME                        READY   STATUS    RESTARTS   AGE   IP          NODE   …\ndb-x84j8bbbn-w9qls          1/1     Running   0          24s   10.42.1.2   kube02 …\ninventory-lrhb8fpb8-ddbx7   1/1     Running   0          23s   10.42.1.3   kube02 …\ninventory-lrhb8fpb8-rw52l   1/1     Running   0          23s   10.42.0.3   kube01 …', simulated: true },
        { title: 'Check the Service', command: 'kubectl get svc,ep', what: 'The ClusterIPs, the NodePort mapping 80:30080 and the endpoints.', why: 'Endpoints with both pod IPs on port 8000 prove selector, readiness and targetPort.', expected: 'NAME                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE\nservice/db           ClusterIP   10.43.215.134   <none>        5432/TCP       25s\nservice/inventory    NodePort    10.43.88.113    <none>        80:30080/TCP   24s\n…\nNAME                   ENDPOINTS                       AGE\nendpoints/db           10.42.1.2:5432                  25s\nendpoints/inventory    10.42.1.3:8000,10.42.0.3:8000   24s', simulated: true },
        { title: 'Test from a client', command: 'curl -s http://kube01.corp.lab:30080/health\ncurl -s http://kube02.corp.lab:30080/health', what: 'From ws01, through both nodes\' NodePort.', why: 'The end-to-end proof: client network, firewall, kube-proxy, flannel, pod and database.', expected: '{"status":"ok","database":"ok"}\n{"status":"ok","database":"ok"}', simulated: true },
      ],
    },
    {
      id: 'kubeadm-managed',
      platform: 'kubeadm and managed Kubernetes (EKS, AKS, GKE): for reference',
      summary: '**kubeadm** builds an upstream Kubernetes cluster from separate components: you install a container runtime (containerd) and the kubelet package on every node yourself, `kubeadm init` creates the control plane as static pods (etcd, kube-apiserver, scheduler, controller manager) and you must install a CNI plugin (Calico, Cilium, flannel) before pods get networking. Certificates expire after a year unless the cluster is upgraded or they are renewed. **Managed services** (Amazon EKS, Azure AKS, Google GKE) run the control plane for you: you never see its processes, upgrades are a button or a CLI call, nodes are VM groups, LoadBalancer Services get cloud load balancers, and authentication goes through the cloud\'s identity system. kubectl, the objects and the troubleshooting in this lesson are the same everywhere.',
      prerequisites: ['kubeadm: Linux VMs with containerd, kubelet/kubeadm/kubectl packages from pkgs.k8s.io, swap handled, ports 6443, 2379–2380, 10250 open.', 'Managed: a cloud account and its CLI (aws, az, gcloud).'],
      steps: [
        { title: 'kubeadm: create the control plane', command: 'sudo kubeadm init --pod-network-cidr=10.244.0.0/16 --control-plane-endpoint=k8s-api.corp.lab:6443', what: 'Generates certificates, writes static pod manifests to /etc/kubernetes/manifests and prints the join command.', why: 'A control-plane endpoint name (a load balancer or DNS name) allows adding control-plane nodes later.', expected: 'Your Kubernetes control-plane has initialized successfully!\n…\nkubeadm join k8s-api.corp.lab:6443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:…' },
        { title: 'kubeadm: install a CNI plugin, join workers', command: 'kubectl apply -f calico.yaml\nsudo kubeadm join k8s-api.corp.lab:6443 --token … --discovery-token-ca-cert-hash sha256:…', what: 'Pod networking, then worker nodes.', why: 'Without a CNI plugin, nodes stay NotReady and CoreDNS stays Pending.', expected: 'This node has joined the cluster' },
        { title: 'Managed: get credentials', command: 'aws eks update-kubeconfig --region eu-central-1 --name prod\naz aks get-credentials --resource-group rg-prod --name aks-prod\ngcloud container clusters get-credentials prod --region europe-west1', what: 'Adds a context to ~/.kube/config that obtains tokens from the cloud CLI.', why: 'Access is governed by the cloud\'s identity (IAM, Entra ID) mapped to Kubernetes RBAC.', expected: 'Added new context arn:aws:eks:eu-central-1:…:cluster/prod to /home/alice/.kube/config' },
      ],
    },
  ],

  configIntro: `
Kubernetes configuration lives at three levels, and each takes effect at a different moment:
- **The nodes** (\`/etc/rancher/k3s/config.yaml\`, the systemd units): read when k3s or k3s-agent starts. Changes need \`systemctl restart k3s\`.
- **The client** (\`~/.kube/config\`, or \`/etc/rancher/k3s/k3s.yaml\` for root on kube01): read by every kubectl command. It decides which cluster, which user and which namespace you work with.
- **The objects** (manifests such as \`inventory.yaml\`): stored by the API server when you \`kubectl apply\`, and acted on by the controllers within seconds. A changed pod template replaces the pods; a changed ConfigMap reaches environment variables only when the pods restart.

### Manifests are the source of truth
Keep every object in a YAML file (in git) and change it there, then \`kubectl apply -f\`. \`kubectl get deploy inventory -o yaml\` shows what is stored, including the fields Kubernetes added (defaults, status). Commands such as \`kubectl scale\` and \`kubectl set image\` change the stored object but not your file: the next apply of the file sets it back. Use them for emergencies, then update the file.

:::practice
Q: Someone ran \`kubectl scale deploy/inventory --replicas=4\` during a busy day. The next morning a colleague runs \`kubectl apply -f inventory.yaml\` (which says \`replicas: 2\`). How many pods are there now?
A: **Two.** apply sets the stored object to what the file says. Change the file if four should stay.
Q: You changed \`flannel-backend\` in /etc/rancher/k3s/config.yaml. When does it take effect?
A: Only when k3s restarts (\`systemctl restart k3s\`), and some options (the network backend, cluster-cidr, service-cidr) are not meant to change on an existing cluster at all.
:::
`,

  configFiles: [
    {
      platform: 'k3s server (kube01)',
      items: [
        { path: '/etc/rancher/k3s/config.yaml', purpose: 'Server options: kubeconfig mode, tls-san, flannel backend, disabled add-ons.' },
        { path: '/etc/rancher/k3s/k3s.yaml', purpose: 'Admin kubeconfig (root only, 0600).' },
        { path: '/var/lib/rancher/k3s/server/db/', purpose: 'The datastore: every object of the cluster.' },
        { path: '/var/lib/rancher/k3s/server/node-token', purpose: 'Join token for agents.' },
        { path: '/var/lib/rancher/k3s/server/manifests/', purpose: 'Add-on manifests k3s applies at start (coredns.yaml …).' },
        { path: '/etc/systemd/system/k3s.service', purpose: 'The unit written by the installer.' },
      ],
    },
    {
      platform: 'k3s agent (kube02)',
      items: [
        { path: '/etc/rancher/k3s/config.yaml', purpose: 'server: https://kube01.corp.lab:6443, token-file.' },
        { path: '/etc/rancher/k3s/token', purpose: 'The join token (0600).' },
        { path: '/etc/systemd/system/k3s-agent.service', purpose: 'The agent unit.' },
      ],
    },
    {
      platform: 'Every node',
      items: [
        { path: '/var/lib/rancher/k3s/agent/containerd/', purpose: 'Images and container filesystems.' },
        { path: '/var/log/pods/', purpose: 'Container logs (what kubectl logs reads).' },
      ],
    },
    {
      platform: 'Clients and applications',
      items: [
        { path: '~/.kube/config', purpose: 'kubectl clusters, users and contexts (ws01: alice).' },
        { path: 'inventory.yaml, db.yaml', purpose: 'The application\'s manifests (Deployments, Services), kept in git.' },
      ],
    },
  ],

  directives: [
    { name: 'spec.replicas', compiledDefault: '1', recommended: '2 or more for anything users depend on', explanation: 'How many pods the Deployment keeps running. With one, every rollout, drain or crash is an outage.', security: 'More replicas than the nodes can hold leave pods Pending.' },
    { name: 'spec.selector.matchLabels / template.metadata.labels', compiledDefault: 'none (required)', recommended: 'One stable label such as app: inventory, identical in both', explanation: 'How the Deployment finds its pods. The selector cannot be changed after creation.', security: 'A mismatch is rejected: `selector` does not match template `labels`.' },
    { name: 'Service spec.selector', compiledDefault: 'none', recommended: 'The same label as the pod template', explanation: 'Which pods receive the Service\'s traffic.', security: 'A typo is accepted silently: endpoints <none>, connections refused.' },
    { name: 'Service ports: port / targetPort / nodePort', compiledDefault: 'targetPort = port; nodePort random in 30000–32767', recommended: 'targetPort = the containerPort (or its name); a fixed nodePort only when clients need a known port', explanation: 'port is on the ClusterIP; targetPort is where the container listens; nodePort is on every node.', security: 'A NodePort is open on every node address: restrict the range with the host or network firewall.' },
    { name: 'readinessProbe', compiledDefault: 'none (Ready as soon as the container starts)', recommended: 'httpGet on a health endpoint that checks what the pod needs to serve', explanation: 'Failing → 0/1, removed from endpoints, not restarted.', security: 'Without it, pods receive traffic before they can serve, and rollouts proceed with broken versions.' },
    { name: 'livenessProbe', compiledDefault: 'none', recommended: 'A cheap check of the process itself (TCP port, /livez); generous thresholds', explanation: 'Failing failureThreshold times → container restarted.', security: 'Checking dependencies in liveness causes restart storms when the dependency is down.' },
    { name: 'resources.requests', compiledDefault: 'none (BestEffort)', recommended: 'Measured normal use (cpu: 100m, memory: 128Mi for inventory)', explanation: 'What the scheduler reserves on a node.', security: 'Too high → Pending; none → pods packed onto a node and evicted first under pressure.' },
    { name: 'resources.limits.memory', compiledDefault: 'unlimited', recommended: 'Above peak use (256Mi for inventory, which needs about 120Mi)', explanation: 'cgroup memory limit; exceeded → OOMKilled, exit 137.', security: 'Without limits one pod can exhaust the node\'s memory and affect every other pod.' },
    { name: 'strategy.rollingUpdate.maxSurge / maxUnavailable', compiledDefault: '25% / 25%', recommended: 'Defaults; maxUnavailable: 0 for small replica counts', explanation: 'How many extra / missing pods a rollout may have.', security: 'A high maxUnavailable lets a broken version take more capacity down at once.' },
    { name: 'progressDeadlineSeconds', compiledDefault: '600', recommended: 'Default, or the real start-up time plus a margin', explanation: 'After this long without progress, the Deployment reports ProgressDeadlineExceeded.', security: 'Kubernetes does not roll back automatically; alert on stalled rollouts.' },
    { name: 'image tag', compiledDefault: 'latest if omitted', recommended: 'An explicit version (corp/inventory:1.4) or a digest', explanation: 'Which image the kubelet pulls; imagePullPolicy defaults to IfNotPresent for tagged images, Always for :latest.', security: ':latest makes rollbacks meaningless and nodes may run different versions.' },
    { name: 'k3s write-kubeconfig-mode', compiledDefault: '0600', distroDefault: '0600', recommended: '0600', explanation: 'File mode of /etc/rancher/k3s/k3s.yaml.', security: '0644 gives every local user cluster-admin.' },
    { name: 'k3s secrets-encryption', compiledDefault: 'false', recommended: 'true for production', explanation: 'Encrypts Secret values in the datastore.', security: 'Without it Secrets are stored base64-encoded only.' },
    { name: 'k3s disable / flannel-backend', compiledDefault: 'all add-ons enabled; vxlan', distroDefault: 'lab: traefik, servicelb, metrics-server, local-storage disabled; host-gw', recommended: 'Disable what you replace; host-gw only with nodes on one L2 network', explanation: 'Which packaged components k3s installs and how pod traffic crosses nodes.', security: 'Fewer components, fewer exposed services; VXLAN traffic (UDP 8472) is not encrypted.' },
  ],

  operateIntro: `
### Change through the manifest, watch the rollout
1. Edit the manifest (image tag, environment, probe, resources) and keep the old version (git).
2. \`kubectl apply -f inventory.yaml\`: the API server validates before storing.
3. \`kubectl rollout status deploy/inventory\` and \`kubectl get pods\`: new pods must become Ready.
4. If they do not: \`kubectl describe pod\` and \`kubectl logs --previous\` for the reason, then \`kubectl rollout undo deploy/inventory\` and correct the file.

Prefer the narrowest action: restart one Deployment (\`kubectl rollout restart\`) rather than k3s, and drain one node rather than stopping the cluster. Before deleting anything, check where you are: \`kubectl config current-context\` and the namespace.

:::practice
Q: A new image passes \`kubectl apply\` but its pods stay 0/1. What do you run to go back while you investigate?
A: \`kubectl rollout undo deploy/inventory\` (then \`kubectl rollout status\` to confirm), and correct the manifest so the next apply does not bring the broken version back.
Q: Why is \`systemctl restart k3s\` the wrong reaction to one application's crashing pods?
A: It restarts the control plane (and kube01's kubelet) for everyone and does not change the pods' description, so the pods crash again. Find the cause with describe and logs and fix the manifest.
:::

### Node maintenance
Before patching or rebooting a node, move its pods: \`kubectl drain kube02\` evicts them (they are recreated on kube01) and cordons the node. Check that everything is Running elsewhere, do the work, wait for \`Ready\`, then \`kubectl uncordon kube02\`. Pods do not move back on their own; they spread again at the next rollout.

Restarting **k3s** on kube01 interrupts the API for some seconds but leaves running containers alone. Stopping **k3s-agent** on a node makes it NotReady; its pods keep running until Kubernetes evicts them after about five minutes.

:::practice
Q: After maintenance, \`kubectl get nodes\` shows \`kube02   Ready,SchedulingDisabled\`. What was forgotten?
A: \`kubectl uncordon kube02\`. The node is healthy but still cordoned, so no new pods are placed on it.
Q: \`kubectl drain kube02\` stops with "cannot delete Pods declare no controller". What does that mean?
A: Some pods on kube02 were created directly (\`kubectl run\`), with no Deployment to recreate them. Draining would lose them: delete or recreate them under a Deployment, or use \`--force\` if losing them is acceptable.
:::
`,

  troubleshootingIntro: `
### Work from the object outwards
Kubernetes already records most answers; the skill is to read them in a fixed order and stop at the first check that fails:

1. **Cluster access and nodes.** \`kubectl get nodes\`. "connection refused" → the API server (k3s on kube01). NotReady → that node's agent.
2. **Pod status.** \`kubectl get pods -o wide\`: Pending, ContainerCreating, CreateContainerConfigError, ImagePullBackOff, CrashLoopBackOff, 0/1 Running, each points at a different stage.
3. **Events.** \`kubectl describe pod\` (bottom section): FailedScheduling, Failed (missing ConfigMap/Secret, image pull), FailedMount, Unhealthy (probes), BackOff; Last State with Reason and Exit Code.
4. **The application's output.** \`kubectl logs\`, and \`--previous\` for a container that crashed.
5. **Inside the pod.** \`kubectl exec … -- nslookup / wget / nc / cat /etc/resolv.conf\` (a busybox debug pod has the tools).
6. **The Service.** \`kubectl get ep\`: \`<none>\` (selector or readiness), or the wrong port (targetPort).
7. **The node.** \`nft list table ip kube-proxy\` (dnat or reject), \`ip route\` (flannel), \`systemctl status k3s-agent\`, \`journalctl -u k3s-agent\`.

:::practice
Q: Pods are 1/1 Running, but \`curl http://kube01.corp.lab:30080/\` from ws01 is refused. Which step comes next?
A: The **Service**: \`kubectl get ep inventory\`. Running and Ready pods with endpoints \`<none>\` mean the selector does not match; endpoints on the wrong port mean the targetPort is wrong.
Q: \`kubectl logs mypod\` says the container "is waiting to start: CrashLoopBackOff". How do you see why it crashed?
A: \`kubectl logs mypod --previous\` (the output of the last terminated container), and \`kubectl describe pod mypod\` for Last State (Reason, Exit Code).
:::

### Reading pod status
- **Pending**: no node yet. The scheduler's reason is in the FailedScheduling event ("0/2 nodes are available: 2 Insufficient cpu", "didn't match Pod's node affinity/selector").
- **ContainerCreating** (more than a few seconds): pulling a large image, or a volume cannot be mounted (FailedMount).
- **CreateContainerConfigError**: a ConfigMap, Secret or key used for environment variables is missing.
- **ErrImagePull / ImagePullBackOff**: the image cannot be pulled; describe shows the registry's message ("not found").
- **CrashLoopBackOff**: the container exits again and again; RESTARTS "2 (6s ago)" grows, the wait between attempts doubles from 10 seconds up to 5 minutes.
- **0/1 Running**: the process runs, the readiness probe fails; no traffic.
- **Exit Code 137 with OOMKilled**: memory limit. **Exit Code 1**: the application reported an error.

:::practice
Q: RESTARTS shows "5 (2m ago)" and STATUS CrashLoopBackOff. Why does nothing seem to happen for minutes at a time?
A: The **back-off**: after each crash the kubelet waits longer (10 s, doubling up to 5 minutes) before the next start. The pod is waiting, not hanging.
Q: A pod has been ContainerCreating for two minutes and describe shows "MountVolume.SetUp failed for volume "conf" : configmap "nginx-conf" not found". What do you do?
A: Create the ConfigMap \`nginx-conf\` in the pod's namespace (or correct the name in the manifest). The kubelet retries the mount and starts the container.
:::

### Workaround versus fix
Some actions make the symptom go away without fixing anything: deleting the pod (the controller recreates it identically), restarting k3s, raising every limit, making /etc/rancher/k3s/k3s.yaml readable for everyone, removing the readiness probe so the Service gets endpoints, or exposing a pod with a new Service instead of correcting the old selector. The fix is the specific field that is wrong, changed in the manifest and applied: the selector, targetPort, probe path, image tag, request or limit, or the missing ConfigMap or Secret.

:::practice
Q: Removing the readiness probe makes the Service get endpoints again. Why is that a workaround and not a fix?
A: The probe was reporting a real problem (wrong path, or the application cannot reach its database). Without it, users are sent to pods that cannot serve them, and broken rollouts are no longer stopped.
Q: alice cannot use kubectl on kube01 because /etc/rancher/k3s/k3s.yaml is 0600. Why not chmod it 644?
A: That file is **cluster-admin**: 644 gives every local user full control of the cluster. Give alice her own kubeconfig (as on ws01) with the rights she needs.
:::
`,

  errorMap: [
    { message: 'ImagePullBackOff / Failed to pull image "corp/inventory:1.5": rpc error: code = NotFound desc = failed to pull and unpack image "docker.io/corp/inventory:1.5": … not found', layer: 'Image', meaning: 'The tag does not exist in the registry (or the registry is unreachable / needs credentials); the kubelet waits and retries.', firstCheck: 'kubectl describe pod POD; check the tag; kubectl rollout undo deploy/NAME' },
    { message: 'CrashLoopBackOff, RESTARTS "2 (6s ago)", Back-off restarting failed container', layer: 'Application process', meaning: 'The container keeps exiting; the kubelet restarts it with a growing delay.', firstCheck: 'kubectl logs POD --previous; kubectl describe pod POD (Last State)' },
    { message: 'CreateContainerConfigError / Error: secret "inventory-db" not found', layer: 'Configuration', meaning: 'A Secret or ConfigMap (or a key) referenced for environment variables is missing in the pod\'s namespace.', firstCheck: 'kubectl get cm,secret; kubectl describe pod POD' },
    { message: 'FailedMount: MountVolume.SetUp failed for volume "conf" : configmap "nginx-conf" not found', layer: 'Configuration (volumes)', meaning: 'A ConfigMap or Secret used as a volume is missing; the pod stays ContainerCreating.', firstCheck: 'kubectl describe pod POD; kubectl get cm' },
    { message: 'Last State: Terminated, Reason: OOMKilled, Exit Code: 137', layer: 'Resources', meaning: 'The container exceeded limits.memory and the kernel killed it.', firstCheck: 'kubectl describe pod POD (Limits); raise the limit or fix the memory use' },
    { message: 'FailedScheduling: 0/2 nodes are available: 2 Insufficient memory. preemption: 0/2 nodes are available: 2 Preemption is not helpful for scheduling.', layer: 'Scheduling', meaning: 'No node has enough unreserved memory for the pod\'s requests (or: didn\'t match node affinity/selector, untolerated taint, unschedulable).', firstCheck: 'kubectl describe pod POD; kubectl describe node kube01 (Allocated resources)' },
    { message: 'Readiness probe failed: HTTP probe failed with statuscode: 404 (or 503)', layer: 'Readiness', meaning: '404: the probe asks for a path the app does not serve. 503: the app reports itself unhealthy (inventory: database unreachable). The pod is 0/1 and has no traffic.', firstCheck: 'kubectl describe pod POD; kubectl get ep NAME' },
    { message: 'Liveness probe failed: … / Container web failed liveness probe, will be restarted', layer: 'Liveness', meaning: 'The kubelet restarts the container after repeated failures.', firstCheck: 'kubectl describe pod POD; check the probe\'s port and thresholds' },
    { message: 'curl: (7) Failed to connect to kube01.corp.lab port 30080 … Couldn\'t connect to server, with endpoints <none>', layer: 'Service', meaning: 'No Ready pod matches the Service: kube-proxy rejects the connection. Selector typo, or pods not Ready.', firstCheck: 'kubectl get ep NAME; kubectl get svc NAME -o wide; kubectl get pods --show-labels' },
    { message: 'Connection refused with endpoints present (e.g. 10.42.1.4:8080)', layer: 'Service ports', meaning: 'targetPort is not the port the container listens on.', firstCheck: 'kubectl describe svc NAME; kubectl logs deploy/NAME (listening port)' },
    { message: ';; communications error to 10.43.0.10#53: timed out / ;; no servers could be reached (in a pod)', layer: 'Cluster DNS', meaning: 'CoreDNS is not running or kube-dns has no endpoints; ClusterIPs still work.', firstCheck: 'kubectl get deploy coredns -n kube-system; kubectl get ep kube-dns -n kube-system' },
    { message: 'The Deployment "web" is invalid: spec.template.metadata.labels: Invalid value: map[string]string{"app":"webb"}: `selector` does not match template `labels`', layer: 'API validation', meaning: 'The Deployment\'s selector must match its pod template labels; nothing was stored.', firstCheck: 'Compare spec.selector.matchLabels with spec.template.metadata.labels in the manifest' },
    { message: 'Error from server (BadRequest): … strict decoding error: unknown field "spec.template.spec.containers[0].imagePullPolicyy"', layer: 'API validation', meaning: 'A misspelled or misplaced field; nothing was stored.', firstCheck: 'Fix the field name or indentation in the manifest' },
    { message: 'The connection to the server kube01.corp.lab:6443 was refused - did you specify the right host or port?', layer: 'API server / kubeconfig', meaning: 'k3s on kube01 is not running, or the kubeconfig points at the wrong address (127.0.0.1 off the server).', firstCheck: 'systemctl status k3s (kube01); kubectl config view' },
    { message: 'WARN[0000] Unable to read /etc/rancher/k3s/k3s.yaml … error loading config file "/etc/rancher/k3s/k3s.yaml": open /etc/rancher/k3s/k3s.yaml: permission denied', layer: 'Client credentials', meaning: 'A non-root user on a k3s server without their own kubeconfig.', firstCheck: 'ls -l /etc/rancher/k3s/k3s.yaml; use a personal ~/.kube/config' },
    { message: 'error: deployment "inventory" exceeded its progress deadline', layer: 'Rollout', meaning: 'New pods did not become available within progressDeadlineSeconds; old pods keep serving.', firstCheck: 'kubectl get pods; kubectl describe pod NEW-POD; kubectl rollout undo' },
    { message: 'kube02   NotReady', layer: 'Node', meaning: 'The kubelet on kube02 stopped reporting (k3s-agent down, node unreachable).', firstCheck: 'systemctl status k3s-agent and journalctl -u k3s-agent on kube02' },
  ],

  scenarioIds: ['k8s-selector-mismatch', 'k8s-target-port', 'k8s-readiness-path', 'k8s-missing-secret', 'k8s-coredns-scaled-down', 'k8s-oomkilled', 'k8s-bad-image'],
  assessmentId: 'kubernetes',
  references: [
    { title: 'Kubernetes documentation: Concepts overview (components, objects)', url: 'https://kubernetes.io/docs/concepts/overview/' },
    { title: 'Kubernetes documentation: Deployments', url: 'https://kubernetes.io/docs/concepts/workloads/controllers/deployment/' },
    { title: 'Kubernetes documentation: Service', url: 'https://kubernetes.io/docs/concepts/services-networking/service/' },
    { title: 'Kubernetes documentation: DNS for Services and Pods', url: 'https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/' },
    { title: 'Kubernetes documentation: Configure Liveness, Readiness and Startup Probes', url: 'https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/' },
    { title: 'Kubernetes documentation: Resource Management for Pods and Containers', url: 'https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/' },
    { title: 'Kubernetes documentation: Secrets (and good practices)', url: 'https://kubernetes.io/docs/concepts/configuration/secret/' },
    { title: 'Kubernetes documentation: Debug Pods / Debug Services', url: 'https://kubernetes.io/docs/tasks/debug/debug-application/' },
    { title: 'Kubernetes documentation: Safely Drain a Node', url: 'https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/' },
    { title: 'K3s documentation: Quick-Start Guide and Configuration Options', url: 'https://docs.k3s.io/quick-start' },
    { title: 'K3s documentation: Networking (flannel backends, ports)', url: 'https://docs.k3s.io/networking/basic-network-options' },
    { title: 'Kubernetes documentation: Creating a cluster with kubeadm', url: 'https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/' },
  ],
  guide: KUBERNETES_GUIDE,
};

// --- Primer -------------------------------------------------------------------------

export const KUBERNETES_PRIMER: Primer = {
  oneLiner: '**Kubernetes** runs containers on a group of machines from a written description: you say what should run, and it keeps it running, restarts what fails, replaces versions gradually, and gives each application one stable address.',
  analogy: `
A restaurant kitchen with an order board. The **order board** (the API server) shows what should be on the pass at all times: "two portions of inventory, made to this recipe". The **head chef** (the controllers) keeps comparing the board with the pass and has another portion made whenever one is missing or spoilt. The **expediter** (the scheduler) decides which **cooking station** (node) makes it, depending on free burners (CPU and memory requests). The **station cook** (the kubelet) cooks it with the station's equipment (containerd) and tastes it before it goes out (the readiness probe).

Guests never talk to a cook: they order at **counter 30080** (a Service), which hands them any portion that passed tasting. If a station closes, its portions are made again at the other one.

Where the comparison stops: the head chef never fixes the recipe. A recipe that burns every time is cooked again and again (CrashLoopBackOff) until someone corrects the order on the board (the manifest).`,
  ideas: [
    {
      title: 'Desired state',
      explain: 'You store a description in the cluster; controllers make reality match it, again and again. You fix problems by changing the description, not the running containers.',
      example: '`kubectl apply -f inventory.yaml` stores "Deployment inventory, replicas: 2". Delete one of its pods and a new one appears within seconds.',
    },
    {
      title: 'Pods, ReplicaSets and Deployments',
      explain: 'A pod is one or more containers with one IP. A Deployment keeps N identical pods through a ReplicaSet and replaces them gradually when the template changes.',
      example: '`kubectl get deploy,rs,pods` on kube01 shows deployment.apps/inventory 2/2, replicaset.apps/inventory-lrhb8fpb8 and two pods inventory-lrhb8fpb8-…, one on kube01 (10.42.0.3) and one on kube02 (10.42.1.3).',
    },
    {
      title: 'Labels, Services and Endpoints',
      explain: 'A Service is a stable address in front of the pods its selector matches. Only Ready pods become its endpoints, and kube-proxy NATs connections to them.',
      example: '`kubectl get ep inventory` shows `10.42.1.3:8000,10.42.0.3:8000`; `curl http://kube01.corp.lab:30080/health` from ws01 reaches one of them. A selector typo shows `<none>` and the connection is refused.',
    },
    {
      title: 'Probes',
      explain: 'The kubelet checks each container: readiness decides whether it gets traffic, liveness whether it must be restarted.',
      example: 'With the database scaled to 0, the inventory pods show `0/1 Running` and describe says `Readiness probe failed: HTTP probe failed with statuscode: 503`; the Service has no endpoints until the database is back.',
    },
    {
      title: 'Configuration, Secrets and resources',
      explain: 'ConfigMaps and Secrets feed settings and passwords to pods; requests reserve CPU and memory on a node, limits cap them.',
      example: 'Without the Secret inventory-db the pods show `CreateContainerConfigError`; with `limits: memory: 64Mi` corp/inventory is OOMKilled (exit 137) because it needs about 120Mi.',
    },
    {
      title: 'Cluster DNS',
      explain: 'CoreDNS gives every Service a name; pods search their own namespace first, so a short name like `db` works.',
      example: '`kubectl exec dbg -- nslookup inventory` answers `inventory.default.svc.cluster.local` → 10.43.67.69 from the DNS server 10.43.0.10.',
    },
  ],
  walkthrough: {
    title: 'From kubectl apply to a page served through the Service',
    intro: 'As root on kube01, after creating the ConfigMap, the Secret and the db Deployment.',
    steps: [
      { label: 'Stored', detail: 'kubectl sends the two objects to the API server, which checks and stores them.', show: '$ kubectl apply -f inventory.yaml\ndeployment.apps/inventory created\nservice/inventory created' },
      { label: 'Pods created and placed', detail: 'The Deployment controller creates a ReplicaSet, which creates two pods; the scheduler puts one on each node.', show: '$ kubectl get pods -o wide\ninventory-lrhb8fpb8-ddbx7   0/1   ContainerCreating   0   1s   <none>   kube02\ninventory-lrhb8fpb8-rw52l   0/1   ContainerCreating   0   1s   <none>   kube01' },
      { label: 'Started and Ready', detail: 'Each kubelet starts the container with DB_HOST, DB_USER (ConfigMap) and DB_PASSWORD (Secret). gunicorn connects to the database, /health returns 200, the readiness probe passes.', show: '$ kubectl rollout status deploy/inventory\ndeployment "inventory" successfully rolled out' },
      { label: 'Endpoints', detail: 'The endpoints controller lists the two Ready pods behind the Service; kube-proxy writes DNAT rules on both nodes.', show: '$ kubectl get ep inventory\nNAME        ENDPOINTS                       AGE\ninventory   10.42.1.3:8000,10.42.0.3:8000   24s' },
      { label: 'Served', detail: 'From ws01, kube01:30080 is DNATed to a pod (perhaps on kube02, reached through flannel\'s route), which answers.', show: '$ curl -s http://kube01.corp.lab:30080/health\n{"status":"ok","database":"ok"}' },
    ],
  },
  misconceptions: [
    { myth: 'Deleting a broken pod fixes it.', truth: 'Its controller recreates it from the same template, with the same problem. Find the cause with describe and logs, then fix the manifest.' },
    { myth: 'A Running pod is serving traffic.', truth: 'Only **Ready** pods (READY 1/1) are endpoints. `0/1 Running` means the process runs but its readiness probe fails, so the Service sends it nothing.' },
    { myth: 'Secrets are encrypted.', truth: 'By default they are only base64-encoded; anyone allowed to read Secrets can decode them. Encryption at rest and RBAC must be configured.' },
    { myth: 'If kubectl cannot reach the API server, the applications are down.', truth: 'Running pods keep running on the nodes without the control plane; you just cannot change or reschedule anything until it is back.' },
    { myth: 'A pod\'s IP address is a good address to configure in another application.', truth: 'Pod IPs change with every replacement. Use the Service name (db, inventory) and its stable ClusterIP.' },
  ],
  checks: [
    { q: 'Which object keeps a fixed number of identical pods running?', a: 'A ReplicaSet (created and managed by a Deployment).' },
    { q: 'What does `<none>` in `kubectl get ep` mean?', a: 'No Ready pod matches the Service\'s selector: selector typo, or the pods are not Ready.' },
    { q: 'Which command shows why a pod is Pending or cannot start?', a: '`kubectl describe pod POD`: read the Events at the bottom (FailedScheduling, Failed, FailedMount, Unhealthy).' },
    { q: 'What is the DNS name of the Service db in the namespace default?', a: 'db.default.svc.cluster.local (pods in default can use just db).' },
    { q: 'What do Exit Code 137 and Reason OOMKilled mean?', a: 'The container exceeded its memory limit and the kernel killed it (128 + 9, SIGKILL).' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const KUBERNETES_ASSESSMENT: Assessment = {
  id: 'kubernetes',
  title: 'Kubernetes (k3s) knowledge check',
  questions: [
    {
      id: 'k8s-q-apply-chain',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/kubernetes/internals', 'lesson/kubernetes/what'],
      prompt: 'Order what happens after `kubectl apply -f inventory.yaml` until the new pods receive traffic through the Service.',
      items: ['The API server authenticates, validates and stores the Deployment', 'The Deployment controller creates a ReplicaSet', 'The ReplicaSet controller creates the pods', 'The scheduler binds each pod to a node', 'The kubelet on that node has containerd start the container', 'The readiness probe succeeds', 'The endpoints controller adds the pod to the Service\'s endpoints'],
      concepts: ['k8s.workloads'],
      explanation: 'Every component works through the API server: controllers create objects, the scheduler writes the node, the kubelet starts what is bound to its node, and only Ready pods are added to endpoints (which kube-proxy then turns into DNAT rules).',
    },
    {
      id: 'k8s-q-crashloop-exhibit',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/kubernetes/troubleshoot', 'lesson/kubernetes/internals'],
      prompt: 'The inventory pods keep restarting. What is the most likely cause, and what should you look at next?',
      exhibit: '$ kubectl get pods\nNAME                        READY   STATUS             RESTARTS     AGE\ndb-7w95gqnng-v5txs          0/1     CrashLoopBackOff   2 (11s ago)  46s\ninventory-ggm2ndpfw-4nfhn   0/1     CrashLoopBackOff   2 (0s ago)   43s\ninventory-ggm2ndpfw-qvrzf   0/1     CrashLoopBackOff   2 (0s ago)   43s\n$ kubectl logs deploy/inventory --tail 4\nFound 2 pods, using pod/inventory-ggm2ndpfw-qvrzf\n\tIs the server running on that host and accepting TCP/IP connections?\n[2026-10-19 08:38:51 +0000] [1] [ERROR] Shutting down: Master\n[2026-10-19 08:38:51 +0000] [1] [ERROR] Reason: Worker failed to boot.',
      options: [
        { text: 'The application cannot reach its database, which is itself crashing: investigate the db pod first (`kubectl logs db-7w95gqnng-v5txs --previous`, `kubectl describe pod`)', correct: true },
        { text: 'The inventory image does not exist', misconception: 'A missing image shows ErrImagePull / ImagePullBackOff, and the container would never have produced log lines.' },
        { text: 'The readiness probe is wrong', misconception: 'A failing readiness probe gives 0/1 Running without restarts; these containers exit.' },
        { text: 'Delete the inventory pods so they are recreated', misconception: 'The ReplicaSet recreates them identically, and they fail again while the database is down.' },
      ],
      concepts: ['k8s.workloads', 'docker.lifecycle'],
      explanation: 'CrashLoopBackOff means the process exits repeatedly. The application\'s log says it cannot connect to PostgreSQL, and the db pod is crashing too: fix the dependency (here, the db Deployment) first. kubectl logs --previous shows the db container\'s last output.',
    },
    {
      id: 'k8s-q-selector-exhibit',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/kubernetes/internals', 'lesson/kubernetes/troubleshoot'],
      prompt: 'Users get "Couldn\'t connect to server" on port 30080. Based on the exhibit, what is wrong?',
      exhibit: '$ kubectl get pods --show-labels\nNAME                        READY   STATUS    RESTARTS   AGE   LABELS\ninventory-lrhb8fpb8-ddbx7   1/1     Running   0          5m    app=inventory,pod-template-hash=lrhb8fpb8\ninventory-lrhb8fpb8-rw52l   1/1     Running   0          5m    app=inventory,pod-template-hash=lrhb8fpb8\n$ kubectl get svc inventory -o wide\nNAME        TYPE       CLUSTER-IP     EXTERNAL-IP   PORT(S)        AGE   SELECTOR\ninventory   NodePort   10.43.88.113   <none>        80:30080/TCP   5m    app=inventry\n$ kubectl get ep inventory\nNAME        ENDPOINTS   AGE\ninventory   <none>      5m',
      options: [
        { text: 'The Service\'s selector (app=inventry) matches no pod, so it has no endpoints and kube-proxy rejects the connections; correct the selector in the manifest and apply', correct: true },
        { text: 'The pods are not Ready', misconception: 'Both pods are 1/1 Running, i.e. Ready.' },
        { text: 'The NodePort is outside the allowed range', misconception: '30080 is inside 30000–32767; an invalid nodePort would have been rejected at apply time.' },
        { text: 'kube-proxy has crashed on kube01', misconception: 'Endpoints are computed by the control plane from the selector; `<none>` here is explained by the selector alone. kube-proxy is correctly installing a reject rule.' },
      ],
      concepts: ['k8s.networking'],
      explanation: 'A Service with a selector that matches nothing is valid but empty: endpoints `<none>`, and kube-proxy writes a reject rule (connection refused). Compare the SELECTOR column with the pods\' LABELS.',
    },
    {
      id: 'k8s-q-targetport',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/kubernetes/internals'],
      prompt: 'The Service has endpoints, yet connections through it are refused. Which change fixes it?',
      exhibit: '$ kubectl get ep inventory\nNAME        ENDPOINTS                       AGE\ninventory   10.42.1.4:8080,10.42.0.3:8080   4s\n$ kubectl logs deploy/inventory --tail 2\nFound 2 pods, using pod/inventory-ggm2ndpfw-wrhkh\n[2026-10-19 08:38:27 +0000] [1] [INFO] Listening at: http://0.0.0.0:8000 (1)',
      options: [
        { text: 'Set the Service\'s targetPort to 8000 (the port the container listens on) and apply', correct: true },
        { text: 'Set the Service\'s port to 8000', misconception: '`port` is the ClusterIP\'s port clients use; the DNAT destination is the targetPort.' },
        { text: 'Change the application to listen on 0.0.0.0', misconception: 'It already listens on 0.0.0.0, just on 8000 instead of 8080.' },
        { text: 'Restart kube-proxy', misconception: 'Its rules correctly send traffic to the endpoints\' port 8080, where nothing listens.' },
      ],
      concepts: ['k8s.networking', 'net.nat'],
      explanation: 'Endpoints are IP:targetPort of the Ready pods. kube-proxy DNATs to exactly that, so a wrong targetPort produces refused connections although the selector and readiness are fine.',
    },
    {
      id: 'k8s-q-probes',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/kubernetes/internals', 'lesson/kubernetes/config'],
      prompt: 'Which statements about readiness and liveness probes are correct? (Select all that apply.)',
      options: [
        { text: 'A failing readiness probe removes the pod from the Service\'s endpoints without restarting it', correct: true },
        { text: 'A liveness probe that fails failureThreshold times in a row makes the kubelet restart the container', correct: true },
        { text: 'Checking the database in the readiness probe is reasonable; checking it in the liveness probe risks restart loops when the database is down', correct: true },
        { text: 'A pod without a readiness probe never receives traffic', misconception: 'Without a readiness probe a pod counts as Ready as soon as its container runs, often too early.' },
        { text: 'Readiness failures increase the RESTARTS counter', misconception: 'Only container restarts (crashes, liveness kills) count; a not-Ready pod shows 0/1 Running.' },
      ],
      concepts: ['k8s.workloads', 'k8s.networking'],
      explanation: 'Readiness controls traffic, liveness controls restarts. Keep liveness about the process itself; put dependency checks in readiness.',
    },
    {
      id: 'k8s-q-missing-secret',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/kubernetes/internals', 'lesson/kubernetes/troubleshoot'],
      prompt: 'New inventory pods show `CreateContainerConfigError` and describe ends with `Warning   Failed   3s   kubelet   Error: secret "inventory-db" not found`. What is the right fix?',
      options: [
        { text: 'Create the Secret inventory-db with the key password in the pods\' namespace; the kubelet then starts the containers by itself', correct: true },
        { text: 'Delete the pods so they are recreated', misconception: 'New pods have the same reference and fail the same way until the Secret exists.' },
        { text: 'Pull the image again on both nodes', misconception: 'The image is not the problem; the container cannot be created without its environment.' },
        { text: 'Restart k3s on kube01', misconception: 'The control plane is fine; the object the pod refers to is missing.' },
      ],
      concepts: ['k8s.workloads'],
      explanation: 'Environment variables from a missing Secret or ConfigMap block container creation. Secrets are namespaced: one in another namespace does not help. The kubelet retries on its own once it exists.',
    },
    {
      id: 'k8s-q-coredns',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/kubernetes/internals', 'lesson/kubernetes/troubleshoot'],
      prompt: 'Suddenly every application in the cluster fails to reach its database by name. From a debug pod:',
      exhibit: '$ kubectl exec dbg -- nslookup db\n;; communications error to 10.43.0.10#53: timed out\n;; communications error to 10.43.0.10#53: timed out\n;; no servers could be reached\n\n$ kubectl exec dbg -- nc -zv 10.43.26.222 5432\nConnection to 10.43.26.222 (10.43.26.222) 5432 port [tcp/*] succeeded!',
      options: [
        { text: 'Cluster DNS is down: check `kubectl get deploy coredns -n kube-system` and `kubectl get ep kube-dns -n kube-system`, and scale CoreDNS back up or fix why it fails', correct: true },
        { text: 'The db Service has no endpoints', misconception: 'The connection to the db ClusterIP on 5432 succeeds; only the name lookup fails.' },
        { text: 'The node\'s /etc/resolv.conf on kube01 is wrong', misconception: 'Pods use 10.43.0.10 (CoreDNS), written by the kubelet; the node\'s resolver is only CoreDNS\'s upstream for external names.' },
        { text: 'flannel\'s routes are missing', misconception: 'Pod-to-Service traffic works (nc succeeded); a routing problem would break it too.' },
      ],
      concepts: ['k8s.networking', 'dns.resolution'],
      explanation: 'Names fail while ClusterIPs work: the DNS server (CoreDNS behind kube-dns 10.43.0.10) is missing. Scaled to 0 or crashing CoreDNS affects every application at once.',
    },
    {
      id: 'k8s-q-rollout-stuck',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/kubernetes/internals', 'lesson/kubernetes/operate'],
      prompt: 'After `kubectl set image deploy/inventory inventory=corp/inventory:1.5`, what is the situation and the best immediate action?',
      exhibit: '$ kubectl get pods\nNAME                        READY   STATUS             RESTARTS   AGE\ninventory-ggm2ndpfw-cfplj   1/1     Running            0          46s\ninventory-ggm2ndpfw-wrhkh   1/1     Running            0          46s\ninventory-qk7lrb9tt-4rgkj   0/1     ImagePullBackOff   0          11s\n$ kubectl rollout status deploy/inventory --timeout=10s\nWaiting for deployment "inventory" rollout to finish: 1 out of 2 new replicas have been updated...\nerror: timed out waiting for the condition',
      options: [
        { text: 'The new image cannot be pulled; the rollout is stalled while the two old pods keep serving. Run `kubectl rollout undo deploy/inventory` (then correct the tag in the manifest)', correct: true },
        { text: 'The application is down; restart k3s to retry the pull', misconception: 'The old pods are 1/1 Running and still serving; a k3s restart does not make a missing tag appear.' },
        { text: 'Delete the two old pods so the new version can start', misconception: 'Their replacements would also use the broken template: you would cause the outage the rollout strategy is preventing.' },
        { text: 'Wait: Kubernetes rolls back automatically after the progress deadline', misconception: 'It only marks the Deployment as ProgressDeadlineExceeded; rollback is your decision.' },
      ],
      concepts: ['k8s.workloads'],
      explanation: 'With maxUnavailable 25 % of 2 (rounded down to 0), no old pod is removed until a new one is Ready. Undo restores the previous template; describe on the new pod shows the registry\'s "not found".',
    },
    {
      id: 'k8s-q-oom',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/kubernetes/internals'],
      prompt: 'A container\'s Last State shows `Reason: OOMKilled`. Which Exit Code does describe show next to it?',
      accept: ['137'],
      placeholder: 'number',
      concepts: ['k8s.workloads', 'docker.lifecycle'],
      explanation: '137 = 128 + 9: the kernel killed the process with SIGKILL because it exceeded its cgroup memory limit (limits.memory).',
    },
    {
      id: 'k8s-q-scheduling',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/kubernetes/internals'],
      prompt: 'A report pod stays Pending. Its container has `requests: memory: 8Gi` and `limits: memory: 8Gi`; describe shows `0/2 nodes are available: 2 Insufficient memory. preemption: 0/2 nodes are available: 2 Preemption is not helpful for scheduling.` Each node has about 3.9 GiB. What fixes it?',
      options: [
        { text: 'Lower the memory request (and limit) to what the job really needs, or add a node large enough', correct: true },
        { text: 'Remove only the limit', misconception: 'The scheduler places pods by their requests; removing the limit leaves the 8Gi request.' },
        { text: 'Cordon kube01 so it goes to kube02', misconception: 'kube02 is not bigger; cordoning only removes a candidate.' },
        { text: 'Restart the kubelets so they report more memory', misconception: 'Allocatable memory is a property of the node, not of the kubelet\'s state.' },
      ],
      concepts: ['k8s.workloads'],
      explanation: 'Requests are reservations the scheduler must fit into a node\'s allocatable resources. No node offers 8Gi, so the pod can never be scheduled until the request shrinks or capacity grows.',
    },
    {
      id: 'k8s-q-secrets',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/kubernetes/internals', 'lesson/kubernetes/config'],
      prompt: 'Which statements about Kubernetes Secrets in a default k3s installation are true? (Select all that apply.)',
      options: [
        { text: 'The values are base64-encoded, which anyone can decode', correct: true },
        { text: 'Anyone allowed to get Secrets in a namespace can read the passwords in it', correct: true },
        { text: 'Encryption at rest must be enabled explicitly (k3s: secrets-encryption)', correct: true },
        { text: 'A Secret in kube-system can be used by pods in default', misconception: 'Secrets, like ConfigMaps, are only usable by pods in their own namespace.' },
        { text: 'Committing a Secret manifest to git is safe because the values are encoded', misconception: 'Encoding is not protection: the password is in git for everyone with repository access.' },
      ],
      concepts: ['k8s.workloads'],
      explanation: 'Base64 is an encoding, not encryption. Protect Secrets with RBAC, encryption at rest and by keeping their values out of version control (sealed or external secret stores).',
    },
    {
      id: 'k8s-q-api-down',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/kubernetes/what', 'lesson/kubernetes/operate'],
      prompt: 'From ws01, `kubectl get pods` prints `The connection to the server kube01.corp.lab:6443 was refused - did you specify the right host or port?`, but `curl http://kube02.corp.lab:30080/health` still returns 200. What is the most likely situation?',
      options: [
        { text: 'k3s.service on kube01 (the API server) is stopped or failing; the pods keep running without it. Check `systemctl status k3s` and `journalctl -u k3s` on kube01', correct: true },
        { text: 'All pods have stopped and the curl answer comes from a cache', misconception: 'NodePort answers come from a running pod; there is no cache in that path.' },
        { text: 'alice\'s kubeconfig has expired; run chmod 644 on /etc/rancher/k3s/k3s.yaml', misconception: '"connection refused" is a TCP-level answer: nothing listens on 6443. Credentials problems give 401/403 errors, and loosening k3s.yaml is never the fix.' },
        { text: 'kube02 is NotReady', misconception: 'kube02 answers on its NodePort; a NotReady node would not explain the API server refusing connections.' },
      ],
      concepts: ['k8s.workloads', 'svc.systemd'],
      explanation: 'The control plane and the workloads are independent at run time: kubelets and containerd keep pods running and kube-proxy keeps its rules while the API server is down. Nothing can be changed or rescheduled until k3s is back.',
    },
  ],
};
