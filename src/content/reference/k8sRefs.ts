// Reference entries for Kubernetes (k3s v1.30 on Debian 12): the kubectl
// subcommands an administrator uses every day, crictl on the nodes, the k3s
// and kubeconfig files, a Deployment + Service manifest, the pod log files,
// the procedures for a pod that does not run, a Service nobody can reach and
// a rollout that has to be rolled back, and the glossary terms of the lesson.
// Example output is the simulator's (kube01/kube02, k3s v1.30.6+k3s1).

import type { CommandRef, FileRef, GlossaryEntry, Procedure } from '../types';

const K8S_SERVICES = ['Kubernetes'];

export const K8S_COMMAND_REFS: CommandRef[] = [
  {
    id: 'kubectl-get', name: 'kubectl get', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'List objects and their one-line status: pods, deployments, replicasets, services, endpoints, nodes, namespaces, configmaps, secrets, events. The first command of every Kubernetes investigation.',
    syntax: 'kubectl get TYPE[,TYPE…] [NAME] [-n NS | -A] [-l KEY=VALUE] [-o wide|yaml|json|name|jsonpath=EXPR] [--show-labels]',
    args: [
      { arg: 'TYPE', meaning: 'pods (po), deployments (deploy), replicasets (rs), services (svc), endpoints (ep), nodes (no), namespaces (ns), configmaps (cm), secrets, events, all' },
      { arg: '-n NS / -A', meaning: 'One namespace (default: the context\'s, usually "default") / all namespaces' },
      { arg: '-l app=inventory', meaning: 'Only objects whose labels match the selector' },
      { arg: '-o wide', meaning: 'Extra columns: pod IP and node, a Service\'s selector, node addresses and runtime' },
      { arg: '-o yaml / -o json', meaning: 'The whole stored object, including status' },
      { arg: '-o jsonpath={.spec.clusterIP}', meaning: 'One field, for scripts' },
      { arg: '--show-labels', meaning: 'Add a LABELS column (compare with a Service\'s selector)' },
    ],
    example: { command: 'kubectl get pods -o wide', output: 'NAME                        READY   STATUS    RESTARTS   AGE   IP          NODE     NOMINATED NODE   READINESS GATES\ndb-x84j8bbbn-w9qls          1/1     Running   0          24s   10.42.1.2   kube02   <none>           <none>\ninventory-lrhb8fpb8-ddbx7   1/1     Running   0          23s   10.42.1.3   kube02   <none>           <none>\ninventory-lrhb8fpb8-rw52l   1/1     Running   0          23s   10.42.0.3   kube01   <none>           <none>' },
    interpretation: 'READY is ready containers / containers. STATUS is the pod phase or the reason a container waits: Pending (not scheduled yet), ContainerCreating, Running, CrashLoopBackOff, ImagePullBackOff, CreateContainerConfigError, Error, Completed. RESTARTS "2 (6s ago)" means the container has been restarted twice, the last time 6 seconds ago. `0/1 Running` means the process runs but the readiness probe fails, so the pod receives no Service traffic. For endpoints, `<none>` means no Ready pod matches the Service\'s selector.',
    limitations: 'Simulated: the types listed above, -o wide|yaml|json|name|jsonpath, -l, -A, -n, --show-labels. Not simulated: --watch (run the command again), --field-selector (ignored), custom-columns, CRDs.',
    errors: [
      { message: 'No resources found in default namespace.', meaning: 'Nothing of that type in this namespace: the objects may be in another one (-n, -A).' },
      { message: 'Error from server (NotFound): deployments.apps "nope" not found', meaning: 'No object with that name in this namespace.' },
      { message: 'error: the server doesn\'t have a resource type "frobs"', meaning: 'A typo in the type, or a type (CRD) not installed in this cluster.' },
      { message: 'The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?', meaning: 'The API server (k3s on kube01) is not running or not reachable at the kubeconfig\'s server address.' },
    ],
    permissions: 'A kubeconfig with credentials allowed (RBAC) to list that type. On kube01, root reads /etc/rancher/k3s/k3s.yaml (mode 0600).',
    compat: 'kubectl should be within one minor version of the API server (v1.29–v1.31 for a v1.30 cluster).',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['Pod not running', 'Service unreachable', 'Node NotReady'],
  },
  {
    id: 'kubectl-describe', name: 'kubectl describe', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Show one object in readable form with its related information and, most importantly, its **Events**: scheduling decisions, image pulls, probe failures, back-offs, missing ConfigMaps and Secrets.',
    syntax: 'kubectl describe TYPE NAME | TYPE -l SELECTOR [-n NS]',
    args: [
      { arg: 'pod NAME', meaning: 'Node, IP, container State / Last State (Reason, Exit Code), Ready, Restart Count, probes, environment sources, QoS class, Events' },
      { arg: 'deploy NAME', meaning: 'Replicas (desired | updated | total | available), strategy, template, Conditions, old and new ReplicaSets, scaling events' },
      { arg: 'svc NAME', meaning: 'Selector, Type, IP, Port, TargetPort, NodePort and the Endpoints' },
      { arg: 'node NAME', meaning: 'Conditions (Ready, MemoryPressure …), taints, capacity and allocatable, the pods on it and their requests' },
    ],
    example: { command: 'kubectl describe pod -l app=inventory | tail -4', output: '  Normal    Pulled      51s    kubelet             Container image "corp/inventory:1.4" already present on machine\n  Normal    Created     51s    kubelet             Created container inventory\n  Normal    Started     51s    kubelet             Started container inventory\n  Warning   Unhealthy   23s    kubelet             Readiness probe failed: HTTP probe failed with statuscode: 503' },
    interpretation: 'Read the Events from the bottom up: the last Warning usually names the problem in plain words (FailedScheduling with the scheduler\'s reason, Failed with "configmap … not found", Failed to pull image, Unhealthy with the probe\'s result, BackOff). For a crashed container, Last State shows Reason (Error, OOMKilled) and Exit Code (1, 137).',
    limitations: 'Events are kept for about an hour on a real cluster. Simulated for pods, deployments, replicasets, services, nodes and the other types the lab has.',
    errors: [
      { message: 'Error from server (NotFound): pods "web" not found', meaning: 'Wrong name or namespace. Pods made by a Deployment have generated names: use -l app=… or `kubectl get pods` first.' },
    ],
    permissions: 'get/list on the object and on events.',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['Pod not running', 'Pending', 'CrashLoopBackOff', 'ImagePullBackOff'],
  },
  {
    id: 'kubectl-logs', name: 'kubectl logs', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Print what a container wrote to stdout/stderr: the application\'s own explanation of why it fails. `--previous` shows the output of the last container that crashed.',
    syntax: 'kubectl logs POD | deploy/NAME [-c CONTAINER] [--previous] [--tail N] [-n NS]',
    args: [
      { arg: 'POD or deploy/NAME', meaning: 'A pod by name, or one pod of a Deployment (kubectl picks one and says which)' },
      { arg: '--previous (-p)', meaning: 'The log of the previous, terminated container: what it said before it crashed' },
      { arg: '-c CONTAINER', meaning: 'The container, for pods with more than one' },
      { arg: '--tail N', meaning: 'Only the last N lines' },
    ],
    example: { command: 'kubectl logs deploy/inventory --tail 4', output: 'Found 2 pods, using pod/inventory-ggm2ndpfw-qvrzf\n[2026-10-19 08:38:51 +0000] [7] [INFO] Worker exiting (pid: 7)\n[2026-10-19 08:38:51 +0000] [1] [ERROR] Worker (pid:7) exited with code 3\n[2026-10-19 08:38:51 +0000] [1] [ERROR] Shutting down: Master\n[2026-10-19 08:38:51 +0000] [1] [ERROR] Reason: Worker failed to boot.' },
    interpretation: 'The first error after start-up is the cause; the last lines are often only the consequence. A pod that never started (Pending, ContainerCreating, CreateContainerConfigError, ImagePullBackOff) has no log: use describe instead.',
    limitations: 'Simulated: POD, deploy/NAME, -c, --previous, --tail. Not simulated: -f, --since, -l selectors.',
    errors: [
      { message: 'Error from server (BadRequest): container "pg" in pod "pg" is waiting to start: CrashLoopBackOff', meaning: 'The current container is waiting for its next restart: add --previous.' },
      { message: 'Error from server (BadRequest): previous terminated container "pg" in pod "pg" not found', meaning: 'No earlier container exists (yet): the pod has not restarted.' },
    ],
    permissions: 'get on pods/log.',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['CrashLoopBackOff', 'Application error'],
  },
  {
    id: 'kubectl-exec', name: 'kubectl exec', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Run a command inside a running container: read its resolv.conf and environment, test names and connections from the pod\'s own network namespace.',
    syntax: 'kubectl exec POD | deploy/NAME [-c CONTAINER] -- COMMAND [ARGS…]',
    args: [
      { arg: '--', meaning: 'Everything after it is the command to run in the container' },
      { arg: 'sh -c "…"', meaning: 'A small shell script (pipes, &&) inside the container' },
      { arg: '-it … -- sh', meaning: 'An interactive shell (real clusters; not simulated)' },
    ],
    example: { command: 'kubectl exec dbg -- nslookup inventory', output: 'Server:\t\t10.43.0.10\nAddress:\t10.43.0.10#53\n\nName:\tinventory.default.svc.cluster.local\nAddress: 10.43.67.69' },
    interpretation: 'A test from inside a pod uses the same DNS (10.43.0.10, search default.svc.cluster.local …) and the same network path as the application. Images often lack tools: run a busybox:1.36 debug pod (`kubectl run dbg --image=busybox:1.36 -- sleep 3600`) with wget, nslookup and nc.',
    limitations: 'Simulated: single commands and sh -c. No interactive shells, no kubectl debug or ephemeral containers.',
    errors: [
      { message: 'error: unable to upgrade connection: container not found ("inventory")', meaning: 'The container is not running (crashed, waiting): there is nothing to exec into.' },
      { message: 'OCI runtime exec failed: exec failed: … "curl": executable file not found in $PATH', meaning: 'The image does not contain that tool: use a debug pod.' },
    ],
    permissions: 'create on pods/exec: effectively shell access to the application and its secrets.',
    risks: 'Changes made inside a container are lost when it is replaced, and they make it differ from its manifest. Use exec to look, not to fix.',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['Service unreachable', 'DNS failure in pod'],
  },
  {
    id: 'kubectl-apply', name: 'kubectl apply / create', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Send desired state to the API server: `apply -f` creates or updates the objects in a YAML file; `create` makes single objects from the command line (deployment, namespace, configmap, secret generic).',
    syntax: 'kubectl apply -f FILE | kubectl create deployment NAME --image=IMAGE [--replicas=N] [--port=P] | create namespace NS | create configmap NAME --from-literal=K=V… | create secret generic NAME --from-literal=K=V… [--dry-run=client -o yaml]',
    args: [
      { arg: '-f FILE', meaning: 'A manifest; several objects separated by ---' },
      { arg: '--dry-run=client -o yaml', meaning: 'Print the object instead of creating it: a starting point for a manifest' },
      { arg: '--from-literal=KEY=VALUE / --from-file=PATH', meaning: 'Data for a ConfigMap or Secret' },
    ],
    example: { command: 'kubectl apply -f inventory.yaml', output: 'deployment.apps/inventory created\nservice/inventory created' },
    interpretation: '"created", "configured" (changed) or "unchanged" per object. The API server validates before storing anything: a rejected object is not stored at all, so the old version keeps running.',
    limitations: 'Simulated: apply -f / create -f with Pod, Deployment, ReplicaSet, Service, ConfigMap, Secret and Namespace; the create generators listed. Not simulated: server-side apply, kustomize (-k), Helm, CRDs.',
    errors: [
      { message: 'The Deployment "web" is invalid: spec.template.metadata.labels: Invalid value: map[string]string{"app":"webb"}: `selector` does not match template `labels`', meaning: 'The Deployment would not own the pods it creates: make the selector and the template labels equal.' },
      { message: 'Error from server (BadRequest): error when creating "b.yaml": Deployment in version "v1" cannot be handled as a Deployment: strict decoding error: unknown field "spec.template.spec.containers[0].imagePullPolicyy"', meaning: 'A misspelled or misplaced field.' },
      { message: 'error: resource mapping not found for name: "web" namespace: "" from "c.yaml": no matches for kind "Deployment" in version "v1"', meaning: 'Wrong apiVersion: Deployments are apps/v1.' },
      { message: 'Error from server (NotFound): error when creating "d.yaml": namespaces "shop" not found', meaning: 'Create the namespace first.' },
      { message: 'The Service "web" is invalid: spec.ports[0].nodePort: Invalid value: 8080: provided port is not in the valid range. The range of valid ports is 30000-32767', meaning: 'NodePorts come from 30000–32767.' },
      { message: 'error: error parsing f.yaml: error converting YAML to JSON: yaml: line 8: found character that cannot start any token', meaning: 'A tab or broken indentation in the YAML.' },
    ],
    permissions: 'create/update/patch on the types in the file.',
    risks: 'apply changes running workloads: a new image or environment triggers a rolling update of every pod of that Deployment.',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['Deploy fails'],
  },
  {
    id: 'kubectl-rollout', name: 'kubectl rollout / set image', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Follow, inspect, undo and restart Deployment rollouts. `kubectl set image` starts a rollout to a new image.',
    syntax: 'kubectl set image deploy/NAME CONTAINER=IMAGE | kubectl rollout status|history|undo|restart deploy/NAME [--timeout=60s] [--to-revision=N]',
    args: [
      { arg: 'status [--timeout=D]', meaning: 'Wait until the new ReplicaSet is complete and available (exit 1 on timeout or progress deadline)' },
      { arg: 'history', meaning: 'Revisions (one per template change)' },
      { arg: 'undo [--to-revision=N]', meaning: 'Go back to the previous (or a given) template: itself a new rollout' },
      { arg: 'restart', meaning: 'Replace every pod by a rolling update without changing anything else' },
    ],
    example: { command: 'kubectl rollout status deploy/inventory --timeout=10s', output: 'Waiting for deployment "inventory" rollout to finish: 1 out of 2 new replicas have been updated...\nerror: timed out waiting for the condition' },
    interpretation: 'A stuck rollout means new pods do not become Ready (bad image, crash, failing readiness probe). Because of maxUnavailable, the old pods keep serving meanwhile. After progressDeadlineSeconds (600 s) the Deployment reports `exceeded its progress deadline`; Kubernetes does not roll back by itself.',
    limitations: 'Simulated: status, history, undo, restart; set image. No pause/resume, no change-cause annotations.',
    errors: [
      { message: 'error: deployment "inventory" exceeded its progress deadline', meaning: 'No progress for progressDeadlineSeconds: find why the new pods are not Ready, or undo.' },
    ],
    permissions: 'patch on deployments.',
    risks: 'restart replaces every pod (briefly fewer serving pods); undo rolls back the template only, not ConfigMaps, Secrets or databases.',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['Rollout stuck', 'ImagePullBackOff after update'],
  },
  {
    id: 'kubectl-scale', name: 'kubectl scale', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Change the number of replicas of a Deployment (or ReplicaSet).',
    syntax: 'kubectl scale deploy/NAME --replicas=N [-n NS]',
    args: [{ arg: '--replicas=N', meaning: 'The new desired number of pods (0 stops the workload but keeps its definition)' }],
    example: { command: 'kubectl scale deploy coredns -n kube-system --replicas=0', output: 'deployment.apps/coredns scaled' },
    interpretation: 'The Deployment controller creates or deletes pods until the count matches. Scaling to 0 is how a workload is stopped without deleting it; scaling CoreDNS to 0 breaks name resolution for every pod.',
    limitations: 'Simulated for Deployments and ReplicaSets. No autoscaling (HPA).',
    permissions: 'patch on deployments/scale.',
    risks: 'A later `kubectl apply` of a manifest with `replicas:` sets the count back.',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['Capacity', 'DNS failure in pod'],
  },
  {
    id: 'kubectl-expose', name: 'kubectl expose', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Create a Service for a Deployment or pod, using its labels as the selector.',
    syntax: 'kubectl expose deploy/NAME --port=PORT [--target-port=CONTAINERPORT] [--type=ClusterIP|NodePort] [--name=SVC]',
    args: [
      { arg: '--port', meaning: 'The Service\'s port (on the ClusterIP)' },
      { arg: '--target-port', meaning: 'The container port traffic is sent to (default: same as --port)' },
      { arg: '--type=NodePort', meaning: 'Also open a port 30000–32767 on every node (chosen at random unless set in a manifest)' },
    ],
    example: { command: 'kubectl expose deploy db --port=5432', output: 'service/db exposed' },
    interpretation: 'Check the result with `kubectl get ep NAME`: the endpoints must list pod IPs with the port the application really listens on.',
    limitations: 'Simulated. LoadBalancer Services get no external IP in the lab (servicelb disabled).',
    errors: [{ message: 'error: couldn\'t find port via --port flag or introspection', meaning: 'The pod template declares no containerPort: give --port.' }],
    permissions: 'create on services.',
    services: K8S_SERVICES, protocols: ['TCP'], symptoms: ['Service unreachable'],
  },
  {
    id: 'kubectl-drain', name: 'kubectl cordon / drain / uncordon', platform: 'Linux', category: 'Kubernetes', simulator: 'kubectl',
    purpose: 'Take a node out of service for maintenance: cordon stops new pods being scheduled there, drain also evicts the pods on it so their controllers recreate them elsewhere, uncordon allows scheduling again.',
    syntax: 'kubectl cordon NODE | kubectl drain NODE [--ignore-daemonsets] [--force] | kubectl uncordon NODE',
    args: [
      { arg: '--ignore-daemonsets', meaning: 'Leave DaemonSet pods (they would be recreated on the same node anyway)' },
      { arg: '--force', meaning: 'Also delete pods without a controller (they are gone for good)' },
    ],
    example: { command: 'kubectl drain kube02', output: 'node/kube02 cordoned\nevicting pod default/db-x84j8bbbn-29x5d\nevicting pod default/inventory-rxk9tjhbv-2jnr8\npod/db-x84j8bbbn-29x5d evicted\npod/inventory-rxk9tjhbv-2jnr8 evicted\nnode/kube02 drained' },
    interpretation: 'The node shows `Ready,SchedulingDisabled` until uncordoned. Evicted pods are recreated on the remaining nodes, if they fit. A Deployment with one replica (like a single database pod) has an outage while its pod moves.',
    limitations: 'Simulated (no PodDisruptionBudgets).',
    errors: [{ message: 'error: unable to drain node "kube02" due to error: cannot delete Pods declare no controller (use --force to override): default/pg, default/oom, continuing command...', meaning: 'Bare pods (kubectl run) would be lost: delete or recreate them under a Deployment, or --force.' }],
    permissions: 'patch on nodes, create on pods/eviction.',
    risks: 'Draining the last node with room for the pods leaves them Pending. Always uncordon after maintenance.',
    services: K8S_SERVICES, protocols: ['HTTPS'], symptoms: ['Node maintenance'],
  },
  {
    id: 'crictl', name: 'crictl', platform: 'Linux', category: 'Kubernetes', simulator: 'crictl',
    purpose: 'Talk to the node\'s container runtime (containerd) directly through the CRI: which pods and containers really run on this node, their images and logs. Useful when the API server is down or kubectl shows something unexpected.',
    syntax: 'crictl ps [-a] | crictl pods | crictl images | crictl logs CONTAINER-ID',
    args: [
      { arg: 'ps [-a]', meaning: 'Running containers (-a: also exited ones) with their pod' },
      { arg: 'pods', meaning: 'Pod sandboxes on this node' },
      { arg: 'images', meaning: 'Images in containerd\'s store on this node' },
      { arg: 'logs ID', meaning: 'A container\'s log, by the ID from crictl ps' },
    ],
    example: { command: 'crictl ps', output: 'CONTAINER       IMAGE           CREATED   STATE     NAME        ATTEMPT   POD ID          POD\n5796d7c188a2f   c69fa2e9cbf5f   51s ago   Running   coredns     0         96e044c5c120b   coredns-ld9vtwwvv-hgfcw\nc074d1cd22400   7c4e0b19a2f35   16s ago   Running   inventory   0         2e5e260f5610a   inventory-ggm2ndpfw-wrhkh' },
    interpretation: 'Shows only this node. ATTEMPT counts restarts of the container. An image missing from `crictl images` on a node is pulled when a pod needs it there.',
    limitations: 'Simulated: ps [-a], pods, images, logs ID (as root on kube01 and kube02). Not simulated: inspect, exec, rmi, stats.',
    permissions: 'root (the containerd socket /run/k3s/containerd/containerd.sock).',
    risks: 'Stopping or removing containers behind the kubelet\'s back only makes it start them again: change the objects in the API instead.',
    compat: 'k3s ships crictl as a link to the k3s binary (`k3s crictl`).',
    services: K8S_SERVICES, protocols: ['CRI'], symptoms: ['API server down', 'Pod not running'],
  },
];

export const INVENTORY_MANIFEST = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: inventory
  labels:
    app: inventory
spec:
  replicas: 2
  selector:
    matchLabels:
      app: inventory          # must match the template's labels
  template:
    metadata:
      labels:
        app: inventory        # what the Service selects
    spec:
      containers:
      - name: inventory
        image: corp/inventory:1.4
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: inventory-config   # DB_HOST, DB_USER
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: inventory-db
              key: password
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          periodSeconds: 10
        livenessProbe:
          tcpSocket:
            port: 8000
          periodSeconds: 20
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            memory: 256Mi
---
apiVersion: v1
kind: Service
metadata:
  name: inventory
spec:
  type: NodePort
  selector:
    app: inventory
  ports:
  - port: 80            # the ClusterIP's port
    targetPort: 8000    # the container's port
    nodePort: 30080     # on every node`;

export const K8S_FILE_REFS: FileRef[] = [
  {
    id: 'file:k3s-yaml', path: '/etc/rancher/k3s/k3s.yaml', platform: 'k3s server (kube01)', kind: 'auth',
    services: K8S_SERVICES,
    purpose: 'The cluster-admin kubeconfig that k3s writes on the server: the API server address, the cluster CA and a client certificate with full rights.',
    contents: 'apiVersion: v1, kind: Config; clusters[].cluster.server (https://127.0.0.1:6443) and certificate-authority-data; users[].user.client-certificate-data and client-key-data; contexts and current-context.',
    accessed: 'Written by k3s at every start; read by kubectl, crictl and k3s subcommands on kube01 when KUBECONFIG is not set.',
    permissions: 'root:root 0600 (write-kubeconfig-mode "0600" in config.yaml).',
    problems: 'A non-root user gets `WARN[0000] Unable to read /etc/rancher/k3s/k3s.yaml, please start server with --write-kubeconfig-mode or --write-kubeconfig-group to modify kube config permissions` and `permission denied`. Do not make it world-readable: it is full admin access. Copied to a workstation, its server must be changed from 127.0.0.1 to kube01.corp.lab (a name in the certificate\'s tls-san).',
    example: 'apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTi…\n    server: https://127.0.0.1:6443\n  name: default\ncontexts:\n- context:\n    cluster: default\n    user: default\n  name: default\ncurrent-context: default\nkind: Config\nusers:\n- name: default\n  user:\n    client-certificate-data: LS0tLS1CRUdJTi…\n    client-key-data: LS0tLS1CRUdJTi…',
    relatedCommands: ['kubectl-get', 'crictl'],
  },
  {
    id: 'file:kubeconfig', path: '~/.kube/config (or $KUBECONFIG)', platform: 'Any kubectl client (ws01: /home/alice/.kube/config)', kind: 'auth',
    services: K8S_SERVICES,
    purpose: 'A user\'s kubectl configuration: which clusters exist, which credentials to use and which context (cluster + user + namespace) is current.',
    contents: 'clusters (server URL, CA), users (client certificate/key, token, or an exec plugin such as `aws eks get-token`), contexts (cluster, user, optional namespace), current-context.',
    accessed: 'By every kubectl command. `kubectl config view` prints it with secrets replaced by DATA+OMITTED; `kubectl config set-context --current --namespace=NS` changes the default namespace.',
    permissions: 'The user, 0600 (in a 0700 ~/.kube): it contains credentials.',
    problems: 'Wrong server (127.0.0.1 copied from the server) → connection refused; a name not in the API certificate → x509 errors; wrong current context → commands go to another cluster or namespace (the most dangerous mistake: check `kubectl config current-context` before deleting anything).',
    example: 'apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: DATA+OMITTED\n    server: https://kube01.corp.lab:6443\n  name: default\ncontexts:\n- context:\n    cluster: default\n    user: alice\n  name: default\ncurrent-context: default\nkind: Config\nusers:\n- name: alice\n  user:\n    client-certificate-data: DATA+OMITTED\n    client-key-data: DATA+OMITTED',
    relatedCommands: ['kubectl-get'],
  },
  {
    id: 'file:k3s-config', path: '/etc/rancher/k3s/config.yaml', platform: 'k3s server and agents', kind: 'config',
    services: K8S_SERVICES,
    purpose: 'k3s start-up options as YAML instead of command-line flags: on the server the kubeconfig mode, extra certificate names, the flannel backend and the add-ons to leave out; on an agent the server URL and the join token.',
    contents: 'Server (kube01): write-kubeconfig-mode: "0600", tls-san: [kube01.corp.lab], flannel-backend: host-gw, disable: [traefik, servicelb, metrics-server, local-storage]. Agent (kube02): server: https://kube01.corp.lab:6443, token-file: /etc/rancher/k3s/token. Optional: cluster-cidr (10.42.0.0/16), service-cidr (10.43.0.0/16), node-label, node-taint.',
    accessed: 'When k3s.service / k3s-agent.service starts (systemctl restart k3s).',
    permissions: 'root:root 0600 when it contains a token.',
    problems: 'A YAML error stops k3s from starting (journalctl -u k3s). cluster-cidr and service-cidr cannot be changed on an existing cluster. Removing an entry from disable installs that add-on at the next start. A wrong token or server URL on an agent: the node never joins (journalctl -u k3s-agent).',
    example: '# k3s server configuration (CHG-4120)\nwrite-kubeconfig-mode: "0600"\ntls-san:\n  - kube01.corp.lab\nflannel-backend: host-gw\ndisable:\n  - traefik\n  - servicelb\n  - metrics-server\n  - local-storage',
    relatedCommands: ['systemctl', 'journalctl'],
  },
  {
    id: 'file:k8s-manifest', path: 'inventory.yaml (a manifest, kept in git)', platform: 'Any Kubernetes cluster', kind: 'config',
    services: K8S_SERVICES,
    purpose: 'The desired state of an application: here a Deployment (pods, image, configuration, probes, resources) and a NodePort Service in front of it.',
    contents: 'One YAML document per object, separated by ---. Each has apiVersion, kind, metadata (name, namespace, labels) and spec. In the Deployment: replicas, selector.matchLabels (must equal template.metadata.labels), template.spec.containers[] (image, ports, env/envFrom, readinessProbe, livenessProbe, resources). In the Service: type, selector (must match the pods\' labels), ports (port, targetPort = the container port, nodePort 30000–32767).',
    accessed: 'Only when someone runs `kubectl apply -f`: the API server stores the objects and the controllers act on them.',
    permissions: 'Ordinary file; never put Secret values in it if it goes into git.',
    problems: 'A selector that matches no pod (Service: endpoints <none>; Deployment: rejected). targetPort different from the port the container listens on (connections refused although endpoints exist). A readiness path the application does not serve (pods 0/1, no endpoints). Tabs in YAML. Editing the live object with kubectl edit makes it drift from the file.',
    example: INVENTORY_MANIFEST,
    relatedCommands: ['kubectl-apply', 'kubectl-get', 'kubectl-rollout'],
  },
  {
    id: 'file:pod-logs', path: '/var/log/pods/<namespace>_<pod>_<uid>/<container>/<restart>.log', platform: 'Every node (kubelet)', kind: 'log',
    services: K8S_SERVICES,
    purpose: 'Where the kubelet stores the stdout/stderr of each container running on that node: what `kubectl logs` reads back through the API server.',
    contents: 'One directory per pod (for example `default_inventory-ggm2ndpfw-4nfhn_5e327d87-…`), one subdirectory per container, one file per restart (0.log, 1.log …) in the CRI log format (timestamp, stream, flag, text).',
    accessed: 'Written continuously by the container runtime; read by kubectl logs and by log shippers (Fluent Bit, Promtail, Vector) running on each node.',
    permissions: 'root:root; directories 0755, files 0640.',
    problems: 'Only on the node where the pod runs (check `kubectl get pod -o wide`). Deleted when the pod is deleted: a pod replaced by a rollout takes its logs with it, so ship logs centrally. Rotated by the kubelet (containerLogMaxSize, 10Mi by default).',
    example: '$ ls /var/log/pods\ndefault_inventory-ggm2ndpfw-wrhkh_2e5e260f-5610-aabd-6644-341f299c9c1d  kube-system_coredns-ld9vtwwvv-hgfcw_96e044c5-c120-b34a-2dd7-8b2b21581491',
    relatedCommands: ['kubectl-logs', 'crictl'],
  },
];

export const K8S_PROCEDURES: Procedure[] = [
  {
    id: 'proc:k8s-pod-not-running', title: 'A pod is not Running and Ready', platform: 'Kubernetes (k3s v1.30)',
    services: K8S_SERVICES,
    symptoms: ['Pending', 'ContainerCreating', 'CrashLoopBackOff', 'ImagePullBackOff', 'CreateContainerConfigError', 'OOMKilled', '0/1 Running'],
    purpose: 'Find out which stage a pod is stuck in (scheduling, start, running, readiness) and read the reason Kubernetes already recorded.',
    steps: [
      { title: 'Which pods, which status, which node?', command: 'kubectl get pods -o wide', why: 'STATUS names the stage: Pending = not scheduled; ContainerCreating / CreateContainerConfigError / ImagePullBackOff = the kubelet cannot start it; CrashLoopBackOff = it starts and dies; 0/1 Running = it runs but is not Ready.' },
      { title: 'Read the Events', command: 'kubectl describe pod POD', why: 'The last Warning names the cause: FailedScheduling (resources, nodeSelector, taints, cordoned nodes), Failed (configmap/secret not found, failed to pull image), FailedMount, Unhealthy (probe), BackOff. Last State gives Reason and Exit Code (OOMKilled 137, Error 1).' },
      { title: 'Read what the application said', command: 'kubectl logs POD --previous\nkubectl logs POD', why: 'For CrashLoopBackOff, the previous container\'s output explains the exit (missing variable, database unreachable).' },
      { title: 'Compare with what was intended', command: 'kubectl get deploy NAME -o yaml\nkubectl get cm,secret', why: 'Image tag, environment sources, probe path and port, resources: the manifest may not be what you think was deployed.' },
      { title: 'Check the nodes', command: 'kubectl get nodes\nkubectl describe node kube02', why: 'NotReady or SchedulingDisabled nodes, and the requests already allocated, explain Pending pods.' },
      { title: 'Fix the cause in the manifest and apply it', command: 'kubectl apply -f inventory.yaml\nkubectl rollout status deploy/inventory', why: 'Create the missing ConfigMap/Secret, correct the image, the probe, the limits. Deleting the pod only gives you a new pod with the same problem.' },
    ],
    risks: 'Deleting pods or raising limits blindly hides the cause. Do not give a crashing application more replicas: they all crash.',
    verify: '`kubectl get pods` shows every pod 1/1 Running with RESTARTS not growing; `kubectl get ep` lists them.',
  },
  {
    id: 'proc:k8s-service-unreachable', title: 'A Service (or NodePort) is unreachable', platform: 'Kubernetes (k3s v1.30, kube-proxy nftables mode)',
    services: K8S_SERVICES,
    symptoms: ['Connection refused', 'Timeout', 'Name does not resolve in pod'],
    purpose: 'Follow the path client → NodePort → kube-proxy DNAT → endpoint → container port, and the name → CoreDNS → ClusterIP path, until one step fails.',
    steps: [
      { title: 'Does the Service have endpoints?', command: 'kubectl get svc inventory -o wide\nkubectl get ep inventory', why: '`<none>` means no Ready pod matches the selector: compare the selector with `kubectl get pods --show-labels`, and check that the pods are Ready.' },
      { title: 'Are the endpoint ports the ones the application listens on?', command: 'kubectl describe svc inventory\nkubectl logs deploy/inventory --tail 5', why: 'TargetPort must be the container port (gunicorn: "Listening at: http://0.0.0.0:8000"). A wrong targetPort gives endpoints but refused connections.' },
      { title: 'Test from inside the cluster', command: 'kubectl run dbg --image=busybox:1.36 -- sleep 3600\nkubectl exec dbg -- nslookup inventory\nkubectl exec dbg -- wget -qO- http://inventory/health', why: 'Separates DNS (nslookup), the Service (wget by name) and the outside path (NodePort).' },
      { title: 'Is DNS working?', command: 'kubectl get pods -n kube-system -l k8s-app=kube-dns\nkubectl get ep kube-dns -n kube-system', why: '"no servers could be reached" from nslookup in a pod while the ClusterIP works → CoreDNS is not running or has no endpoints.' },
      { title: 'Did kube-proxy write the rules?', command: 'nft list table ip kube-proxy', why: 'A dnat rule per Service port and NodePort when there are endpoints; a reject rule when there are none (that is the "connection refused").' },
      { title: 'Test from outside', command: 'curl -sS http://kube01.corp.lab:30080/health', why: 'Then from the client network: a timeout points at a firewall between client and node (TCP 30000–32767 must be allowed to the nodes).' },
    ],
    risks: 'Opening the whole NodePort range to everyone, or switching off the host firewall, to "test" leaves it open.',
    verify: 'The endpoints list the Ready pods with the right port, and curl from a client gets HTTP 200.',
  },
  {
    id: 'proc:k8s-rollout-rollback', title: 'Roll out a new version and roll it back', platform: 'Kubernetes (Deployments)',
    services: K8S_SERVICES,
    symptoms: ['Rollout stuck', 'New version broken'],
    purpose: 'Change an application\'s image safely, watch the rollout, and go back to the previous version when the new pods do not become Ready.',
    steps: [
      { title: 'Record the current state', command: 'kubectl rollout history deploy/inventory\nkubectl get deploy inventory -o jsonpath={.spec.template.spec.containers[0].image}', why: 'Know the revision and image you would go back to.' },
      { title: 'Start the rollout', command: 'kubectl set image deploy/inventory inventory=corp/inventory:1.5', why: 'Or change the tag in the manifest (preferred: the file stays the truth) and `kubectl apply -f`.' },
      { title: 'Watch it', command: 'kubectl rollout status deploy/inventory --timeout=120s\nkubectl get pods', why: 'New pods must become Ready; the old ones are removed only as new ones become available.' },
      { title: 'Find out why it is stuck', command: 'kubectl describe pod -l app=inventory\nkubectl logs POD --previous', why: 'ImagePullBackOff (tag does not exist), CrashLoopBackOff (new version fails), 0/1 Running (readiness probe).' },
      { title: 'Roll back', command: 'kubectl rollout undo deploy/inventory\nkubectl rollout status deploy/inventory', why: 'Restores the previous pod template as a new revision. Then correct the manifest so the next apply does not reintroduce the broken version.' },
    ],
    risks: 'undo restores only the pod template: changed ConfigMaps, Secrets and database migrations are not rolled back. `kubectl apply` of an uncorrected manifest re-applies the bad version.',
    verify: '`kubectl rollout status` says "successfully rolled out", the image is the intended one, and the application answers through its Service.',
  },
];

export const K8S_GLOSSARY: GlossaryEntry[] = [
  { term: 'Kubernetes', definition: 'An orchestrator: you tell its API server the desired state (which containers, how many, with what configuration), and its controllers keep the cluster in that state on a group of nodes, replacing failed pods and rolling out new versions. Abbreviated k8s.', related: ['k3s', 'Pod', 'Deployment (Kubernetes)', 'Control plane'] },
  { term: 'k3s', definition: 'A lightweight, certified Kubernetes distribution packaged as one binary: the server (API server, scheduler, controllers, datastore) and agents (kubelet, containerd, flannel, kube-proxy). Installed with get.k3s.io; units k3s.service and k3s-agent.service.', related: ['Kubernetes', 'kubeconfig'] },
  { term: 'Control plane', definition: 'The parts of Kubernetes that decide: the API server (the only component that talks to the datastore), the datastore (etcd or, in k3s, SQLite/kine), the scheduler and the controller manager. On kube01 they run inside k3s.service.', related: ['Kubernetes', 'kubelet'] },
  { term: 'kubelet', definition: 'The agent on every node: it watches the API server for pods bound to its node, has the container runtime (containerd) start them, runs their probes, restarts crashed containers and reports status. Without it the node becomes NotReady.', related: ['Control plane', 'Readiness probe'] },
  { term: 'Pod', definition: 'The smallest unit Kubernetes runs: one or more containers sharing one IP address (from the node\'s pod subnet, 10.42.x.y in the lab) and volumes. Pods are disposable: a replaced pod has a new name and a new IP.', related: ['Deployment (Kubernetes)', 'Service (Kubernetes)'] },
  { term: 'ReplicaSet', definition: 'A controller object that keeps N identical pods running (those matching its selector). Created and managed by a Deployment; each pod template version gets its own ReplicaSet.', related: ['Deployment (Kubernetes)', 'Pod'] },
  { term: 'Deployment (Kubernetes)', definition: 'The usual object for a stateless application: a pod template, a replica count and a rollout strategy. Changing the template creates a new ReplicaSet and replaces pods gradually (rolling update); `kubectl rollout undo` goes back.', related: ['ReplicaSet', 'Rolling update'] },
  { term: 'Service (Kubernetes)', definition: 'A stable virtual IP (ClusterIP, from 10.43.0.0/16 in the lab), DNS name and port in front of the pods its selector matches. kube-proxy translates connections to it to one of the Ready pods. Types: ClusterIP, NodePort, LoadBalancer.', related: ['Endpoints', 'ClusterIP', 'NodePort', 'kube-proxy'] },
  { term: 'ClusterIP', definition: 'The virtual address of a Service, reachable only from pods and nodes. No interface has it: kube-proxy\'s DNAT rules on each node rewrite it to a pod IP.', related: ['Service (Kubernetes)', 'kube-proxy'] },
  { term: 'NodePort', definition: 'A Service type that also opens one port (30000–32767) on every node\'s address and forwards it to the Service: how clients outside the cluster reach it without a load balancer (http://kube01.corp.lab:30080/).', related: ['Service (Kubernetes)', 'kube-proxy'] },
  { term: 'Endpoints', definition: 'The list of Ready pod IPs and ports behind a Service, maintained by the endpoints controller from the Service\'s selector. `<none>` means no Ready pod matches, and connections to the Service are refused.', related: ['Service (Kubernetes)', 'Label selector', 'Readiness probe'] },
  { term: 'Label selector', definition: 'A set of key=value labels (app=inventory) that picks objects: Services select pods, Deployments and ReplicaSets select the pods they own. A typo in a selector silently matches nothing.', related: ['Endpoints', 'Deployment (Kubernetes)'] },
  { term: 'kube-proxy', definition: 'The component on each node that turns Services into packet rules (in the lab: nftables, table ip kube-proxy): DNAT from ClusterIP:port and NodePort to a pod IP:targetPort, and reject when a Service has no endpoints.', related: ['ClusterIP', 'NodePort', 'DNAT'] },
  { term: 'CoreDNS', definition: 'The cluster DNS server, a Deployment in kube-system behind the kube-dns Service (10.43.0.10). It answers SERVICE.NAMESPACE.svc.cluster.local for pods and forwards other names to the node\'s resolvers.', related: ['Service (Kubernetes)', 'DNS'] },
  { term: 'CNI (flannel)', definition: 'The Container Network Interface plugin gives each pod an interface and IP on the node\'s bridge (cni0) and makes pod subnets reachable between nodes. k3s uses flannel; with the host-gw backend it adds plain routes (10.42.1.0/24 via 10.0.20.91).', related: ['Pod', 'Linux bridge'] },
  { term: 'ConfigMap', definition: 'Non-secret configuration (key/value pairs or files) that pods use as environment variables or mounted files. A pod referring to a missing ConfigMap does not start (CreateContainerConfigError or FailedMount).', related: ['Secret (Kubernetes)'] },
  { term: 'Secret (Kubernetes)', definition: 'Like a ConfigMap, for passwords and keys. Values are only base64-encoded, not encrypted, in the API and (unless encryption at rest is configured) in the datastore: anyone who can read Secrets in a namespace can read the passwords.', related: ['ConfigMap'] },
  { term: 'Namespace (Kubernetes)', definition: 'A named group of objects (default, kube-system, shop …): names are unique per namespace, permissions and quotas can be set per namespace, and DNS names include it. Not a Linux namespace and not a network boundary by itself.', related: ['Kubernetes'] },
  { term: 'Readiness probe', definition: 'A check the kubelet runs periodically (HTTP GET, TCP connect or a command); while it fails, the pod is 0/1 and removed from the Service\'s endpoints, but not restarted.', related: ['Liveness probe', 'Endpoints'] },
  { term: 'Liveness probe', definition: 'A check whose repeated failure makes the kubelet kill and restart the container ("failed liveness probe, will be restarted"). Too strict a liveness probe causes restart loops under load.', related: ['Readiness probe', 'CrashLoopBackOff'] },
  { term: 'Requests and limits', definition: 'Per-container resources. Requests (cpu: 100m, memory: 128Mi) are reserved by the scheduler on a node; limits are enforced by cgroups: CPU above the limit is throttled, memory above it gets the container OOMKilled (exit 137). They decide the QoS class (Guaranteed, Burstable, BestEffort).', related: ['OOMKilled', 'Pod'] },
  { term: 'OOMKilled', definition: 'The container was killed by the kernel because it used more memory than its limit: Last State Terminated, Reason OOMKilled, Exit Code 137 (128 + SIGKILL).', related: ['Requests and limits', 'CrashLoopBackOff'] },
  { term: 'CrashLoopBackOff', definition: 'A container keeps exiting and the kubelet waits longer before each restart (10 s, doubling up to 5 minutes). Not a cause in itself: read `kubectl logs --previous` and Last State.', related: ['Liveness probe', 'OOMKilled'] },
  { term: 'ImagePullBackOff', definition: 'The kubelet could not pull the image (tag does not exist, registry unreachable, credentials missing) and waits before trying again. ErrImagePull is the first failure; describe shows the registry\'s message.', related: ['Rolling update'] },
  { term: 'Rolling update', definition: 'How a Deployment replaces pods: new ReplicaSet scaled up, old one scaled down, within maxSurge (extra pods) and maxUnavailable (missing pods), default 25 % each. If new pods never become Ready the rollout stalls and the old pods keep serving.', related: ['Deployment (Kubernetes)', 'ImagePullBackOff'] },
  { term: 'kubeconfig', definition: 'kubectl\'s configuration file (~/.kube/config, $KUBECONFIG, or /etc/rancher/k3s/k3s.yaml on a k3s server): API server URL, CA, user credentials and contexts.', related: ['k3s'] },
  { term: 'Cordon and drain', definition: 'Node maintenance: cordon marks a node unschedulable (Ready,SchedulingDisabled); drain also evicts its pods so their controllers recreate them on other nodes; uncordon returns it to service.', related: ['Taint'] },
  { term: 'Taint', definition: 'A mark on a node (key=value:NoSchedule) that keeps pods off it unless they have a matching toleration. Used for control-plane nodes, special hardware and node problems (node.kubernetes.io/unreachable).', related: ['Cordon and drain'] },
];
