import { describe, expect, it } from 'vitest';
import { buildKubeLab } from '../src/engine/lab/kubeLab';
import { writeFile } from '../src/engine/fs';
import { age } from '../src/engine/shell/cmdKube';
import { cpuMilli, memMi } from '../src/engine/sim/k8s';
import { Lab } from './helpers';

// One cluster build is shared (a few seconds); each test copies it.
const BASE = buildKubeLab();
const lab = () => new Lab(structuredClone(BASE));
const k = (l: Lab, c: string) => l.run('kube01', 'root', c);
const put = (l: Lab, path: string, text: string) => writeFile(l.world.hosts.kube01, path, text, l.world.clock);

const WEB = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.25
        ports:
        - containerPort: 80
        readinessProbe:
          httpGet:
            path: /
            port: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: NodePort
  selector:
    app: web
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30080
`;

describe('the k3s cluster', () => {
  it('has two Ready nodes, CoreDNS running and the kubernetes and kube-dns Services', () => {
    const l = lab();
    expect(k(l, 'kubectl get nodes').output).toMatch(/^NAME +STATUS +ROLES +AGE +VERSION\nkube01 +Ready +control-plane,master +\S+ +v1\.30\.6\+k3s1\nkube02 +Ready +<none> /);
    expect(k(l, 'kubectl get pods -n kube-system').output).toMatch(/^coredns-\w+-\w{5} +1\/1 +Running +0 /m);
    expect(k(l, 'kubectl get svc -A').output).toMatch(/default +kubernetes +ClusterIP +10\.43\.0\.1 +<none> +443\/TCP/);
    expect(k(l, 'kubectl get svc -A').output).toMatch(/kube-system +kube-dns +ClusterIP +10\.43\.0\.10 +<none> +53\/UDP,53\/TCP,9153\/TCP/);
    expect(l.run('ws01', 'alice', 'kubectl get nodes').code).toBe(0);
    expect(l.run('ws01', 'alice', 'getent hosts kube02.corp.lab').output).toMatch(/^10\.0\.20\.91 /);
  });

  it('non-root users need their own kubeconfig; kube02 has no admin kubeconfig', () => {
    const l = lab();
    expect(l.run('kube01', 'alice', 'kubectl get pods').output).toMatch(/WARN\[0000\] Unable to read \/etc\/rancher\/k3s\/k3s\.yaml.*\nerror: error loading config file "\/etc\/rancher\/k3s\/k3s\.yaml": open \/etc\/rancher\/k3s\/k3s\.yaml: permission denied$/);
    expect(l.run('kube02', 'root', 'kubectl get pods').output).toMatch(/The connection to the server localhost:8080 was refused/);
    expect(l.run('srv01', 'alice', 'kubectl get pods').code).toBe(127);
  });

  it('kubectl from ws01 fails like the real client when the API server is unreachable', () => {
    const l = lab();
    k(l, 'systemctl stop k3s');
    expect(l.run('ws01', 'alice', 'kubectl get pods').output).toMatch(/The connection to the server kube01\.corp\.lab:6443 was refused - did you specify the right host or port\?$/);
  });
});

describe('Deployments, ReplicaSets and Pods', () => {
  it('apply creates a Deployment whose pods are spread, become Ready and are published by the Service', () => {
    const l = lab();
    put(l, '/root/web.yaml', WEB);
    expect(k(l, 'kubectl apply -f web.yaml').output).toBe('deployment.apps/web created\nservice/web created');
    expect(k(l, 'kubectl get pods').output).toMatch(/ContainerCreating/);
    k(l, 'sleep 5');
    const pods = k(l, 'kubectl get pods -o wide').output;
    expect(pods.match(/1\/1 +Running/g)?.length).toBe(2);
    expect(pods).toMatch(/kube01/);
    expect(pods).toMatch(/kube02/);
    expect(k(l, 'kubectl get deploy web').output).toMatch(/^web +2\/2 +2 +2 /m);
    expect(k(l, 'kubectl get ep web').output).toMatch(/^web +10\.42\.\d\.\d+:80,10\.42\.\d\.\d+:80 /m);
    expect(l.run('ws01', 'alice', 'curl -s http://kube01.corp.lab:30080/').output).toMatch(/Welcome to nginx!/);
    expect(l.run('ws01', 'alice', 'curl -s http://kube02.corp.lab:30080/').output).toMatch(/Welcome to nginx!/);
    expect(k(l, 'kubectl apply -f web.yaml').output).toBe('deployment.apps/web unchanged\nservice/web unchanged');
  });

  it('reaches Services by name from pods (CoreDNS) and by ClusterIP from the node (kube-proxy DNAT)', () => {
    const l = lab();
    k(l, 'kubectl create deployment web --image=nginx:1.25 --port=80');
    k(l, 'kubectl expose deployment web --port=80');
    k(l, 'kubectl run dbg --image=busybox:1.36 -- sleep 3600');
    k(l, 'sleep 6');
    expect(k(l, 'kubectl exec dbg -- nslookup web').output).toMatch(/Name:\s+web\.default\.svc\.cluster\.local\nAddress: 10\.43\.\d+\.\d+/);
    expect(k(l, 'kubectl exec dbg -- wget -qO- http://web').output).toMatch(/Welcome to nginx!/);
    const ip = k(l, 'kubectl get svc web -o jsonpath={.spec.clusterIP}').output;
    expect(ip).toMatch(/^10\.43\.\d+\.\d+$/);
    expect(k(l, `curl -s http://${ip}/`).output).toMatch(/Welcome to nginx!/);
    expect(k(l, 'nft list table ip kube-proxy').output).toMatch(new RegExp(`ip daddr ${ip.replace(/\./g, '\\.')} tcp dport 80 dnat to 10\\.42\\.\\d\\.\\d+:80 comment "default/web"`));
    // Without CoreDNS, names stop resolving but the ClusterIP still works.
    expect(k(l, 'kubectl scale deploy coredns -n kube-system --replicas=0').output).toBe('deployment.apps/coredns scaled');
    expect(k(l, 'kubectl exec dbg -- nslookup web').output).toMatch(/no servers could be reached/);
    expect(k(l, `kubectl exec dbg -- wget -qO- http://${ip}`).output).toMatch(/Welcome to nginx!/);
  });

  it('a bad image stalls the rollout (ImagePullBackOff), the old pods keep serving, and rollout undo restores it', () => {
    const l = lab();
    k(l, 'kubectl create deployment web --image=nginx:1.25 --replicas=2');
    k(l, 'sleep 5');
    expect(k(l, 'kubectl set image deploy/web nginx=nginx:1.99').output).toBe('deployment.apps/web image updated');
    k(l, 'sleep 10');
    const pods = k(l, 'kubectl get pods').output;
    expect(pods).toMatch(/0\/1 +ImagePullBackOff/);
    expect(pods.match(/1\/1 +Running/g)?.length).toBe(2);
    expect(k(l, 'kubectl describe pod -l app=web').output).toMatch(/Failed to pull image "nginx:1\.99": rpc error: code = NotFound desc = failed to pull and unpack image "docker\.io\/library\/nginx:1\.99"/);
    const st = k(l, 'kubectl rollout status deploy/web --timeout=20s');
    expect(st.code).toBe(1);
    expect(st.output).toMatch(/Waiting for deployment "web" rollout to finish: 1 out of 2 new replicas have been updated\.\.\.\nerror: timed out waiting for the condition$/);
    expect(k(l, 'kubectl rollout undo deploy/web').output).toBe('deployment.apps/web rolled back');
    expect(k(l, 'kubectl rollout status deploy/web').output).toBe('deployment "web" successfully rolled out');
    expect(k(l, 'kubectl rollout history deploy/web').output).toMatch(/REVISION +CHANGE-CAUSE\n2 +<none>\n3 +<none>/);
  });

  it('a crashing container goes into CrashLoopBackOff with growing back-off and --previous logs', () => {
    const l = lab();
    k(l, 'kubectl run crash --image=busybox:1.36 -- sh -c "echo starting; exit 1"');
    k(l, 'sleep 40');
    expect(k(l, 'kubectl get pod crash').output).toMatch(/^crash +0\/1 +CrashLoopBackOff +2 \(\d+s ago\) /m);
    expect(k(l, 'kubectl logs crash --previous').output).toBe('starting');
    const d = k(l, 'kubectl describe pod crash').output;
    expect(d).toMatch(/Last State: +Terminated\n +Reason: +Error\n +Exit Code: +1/);
    expect(d).toMatch(/Warning +BackOff +\S+ \(x3 over \S+\) +kubelet +Back-off restarting failed container/);
  });

  it('missing ConfigMaps and Secrets block the start; an OOM kill shows as OOMKilled', () => {
    const l = lab();
    put(l, '/root/app.yaml', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n  containers:\n  - name: app\n    image: nginx:1.25\n    envFrom:\n    - configMapRef:\n        name: app-config\n');
    k(l, 'kubectl apply -f app.yaml');
    k(l, 'sleep 5');
    expect(k(l, 'kubectl get pod app').output).toMatch(/0\/1 +CreateContainerConfigError/);
    expect(k(l, 'kubectl describe pod app').output).toMatch(/Warning +Failed +\S+ +kubelet +Error: configmap "app-config" not found/);
    k(l, 'kubectl create configmap app-config --from-literal=MODE=prod');
    k(l, 'sleep 5');
    expect(k(l, 'kubectl get pod app').output).toMatch(/1\/1 +Running/);
    expect(k(l, 'kubectl exec app -- printenv MODE').output).toBe('prod');
    put(l, '/root/db.yaml', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: db\nspec:\n  containers:\n  - name: postgres\n    image: postgres:16\n    env:\n    - name: POSTGRES_PASSWORD\n      value: x\n    resources:\n      limits:\n        memory: 32Mi\n');
    k(l, 'kubectl apply -f db.yaml');
    k(l, 'sleep 20');
    expect(k(l, 'kubectl describe pod db').output).toMatch(/Last State: +Terminated\n +Reason: +OOMKilled\n +Exit Code: +137/);
  });

  it('a readiness probe that fails keeps the pod out of the Service: connections are refused', () => {
    const l = lab();
    put(l, '/root/web.yaml', WEB.replace('path: /\n', 'path: /healthz\n'));
    k(l, 'kubectl apply -f web.yaml');
    k(l, 'sleep 15');
    expect(k(l, 'kubectl get pods').output).toMatch(/0\/1 +Running/);
    expect(k(l, 'kubectl get ep web').output).toMatch(/^web +<none> /m);
    expect(k(l, 'kubectl describe pod -l app=web').output).toMatch(/Readiness probe failed: HTTP probe failed with statuscode: 404/);
    expect(l.run('ws01', 'alice', 'curl -sS http://kube01.corp.lab:30080/').output).toMatch(/Couldn't connect to server/);
  });

  it('a liveness probe that fails restarts the container', () => {
    const l = lab();
    put(l, '/root/live.yaml', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: live\nspec:\n  containers:\n  - name: web\n    image: nginx:1.25\n    livenessProbe:\n      tcpSocket:\n        port: 8080\n      periodSeconds: 5\n');
    k(l, 'kubectl apply -f live.yaml');
    k(l, 'sleep 30');
    const d = k(l, 'kubectl describe pod live').output;
    expect(d).toMatch(/Liveness probe failed: dial tcp 10\.42\.\d\.\d+:8080: connect: connection refused/);
    expect(d).toMatch(/Container web failed liveness probe, will be restarted/);
    expect(Number(/Restart Count: +(\d+)/.exec(d)?.[1])).toBeGreaterThan(0);
  });

  it('a pod requesting more than any node has stays Pending with the scheduler\'s reason', () => {
    const l = lab();
    put(l, '/root/big.yaml', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: big\nspec:\n  containers:\n  - name: big\n    image: nginx:1.25\n    resources:\n      requests:\n        memory: 8Gi\n');
    k(l, 'kubectl apply -f big.yaml');
    expect(k(l, 'kubectl get pod big').output).toMatch(/0\/1 +Pending/);
    expect(k(l, 'kubectl describe pod big').output).toMatch(/FailedScheduling +\S+ +default-scheduler +0\/2 nodes are available: 2 Insufficient memory\. preemption: 0\/2 nodes are available: 2 Preemption is not helpful for scheduling\./);
  });

  it('a stopped agent makes its node NotReady; cordon and drain move pods away', () => {
    const l = lab();
    l.run('kube02', 'root', 'systemctl stop k3s-agent');
    k(l, 'sleep 30');
    expect(k(l, 'kubectl get nodes').output).toMatch(/^kube02 +NotReady +<none>/m);
    l.run('kube02', 'root', 'systemctl start k3s-agent');
    k(l, 'kubectl create deployment web --image=nginx:1.25 --replicas=2');
    k(l, 'sleep 5');
    const out = k(l, 'kubectl drain kube02').output;
    expect(out).toMatch(/^node\/kube02 cordoned\nevicting pod default\/web-/);
    expect(out).toMatch(/node\/kube02 drained$/);
    k(l, 'sleep 5');
    expect(k(l, 'kubectl get nodes').output).toMatch(/^kube02 +Ready,SchedulingDisabled/m);
    expect(k(l, 'kubectl get pods -o wide').output).not.toMatch(/kube02/);
    expect(k(l, 'kubectl uncordon kube02').output).toBe('node/kube02 uncordoned');
  });
});

describe('admission: the API server\'s validation messages', () => {
  it('rejects a selector that does not match the template, unknown fields, wrong apiVersion and a missing namespace', () => {
    const l = lab();
    put(l, '/root/a.yaml', WEB.split('---')[0].replace('      labels:\n        app: web\n    spec', '      labels:\n        app: webb\n    spec'));
    expect(k(l, 'kubectl apply -f a.yaml').output).toBe('The Deployment "web" is invalid: spec.template.metadata.labels: Invalid value: map[string]string{"app":"webb"}: `selector` does not match template `labels`');
    put(l, '/root/b.yaml', WEB.split('---')[0].replace('        ports:', '        imagePullPolicyy: Always\n        ports:'));
    expect(k(l, 'kubectl apply -f b.yaml').output).toBe('Error from server (BadRequest): error when creating "b.yaml": Deployment in version "v1" cannot be handled as a Deployment: strict decoding error: unknown field "spec.template.spec.containers[0].imagePullPolicyy"');
    put(l, '/root/c.yaml', WEB.split('---')[0].replace('apps/v1', 'v1'));
    expect(k(l, 'kubectl apply -f c.yaml').output).toMatch(/^error: resource mapping not found for name: "web" namespace: "" from "c\.yaml": no matches for kind "Deployment" in version "v1"\nensure CRDs are installed first$/);
    put(l, '/root/d.yaml', WEB.split('---')[1].replace('  name: web\n', '  name: web\n  namespace: shop\n'));
    expect(k(l, 'kubectl apply -f d.yaml').output).toBe('Error from server (NotFound): error when creating "d.yaml": namespaces "shop" not found');
    put(l, '/root/e.yaml', WEB.split('---')[1].replace('30080', '8080'));
    expect(k(l, 'kubectl apply -f e.yaml').output).toBe('The Service "web" is invalid: spec.ports[0].nodePort: Invalid value: 8080: provided port is not in the valid range. The range of valid ports is 30000-32767');
    put(l, '/root/f.yaml', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: f\nspec:\n  containers:\n  - name: f\n\timage: nginx\n');
    expect(k(l, 'kubectl apply -f f.yaml').output).toMatch(/^error: error parsing f\.yaml: error converting YAML to JSON: yaml: line 8: found character that cannot start any token$/);
  });

  it('get errors and empty lists read like kubectl', () => {
    const l = lab();
    expect(k(l, 'kubectl get pods').output).toBe('No resources found in default namespace.');
    expect(k(l, 'kubectl get deploy nope').output).toBe('Error from server (NotFound): deployments.apps "nope" not found');
    expect(k(l, 'kubectl get frobs').output).toBe('error: the server doesn\'t have a resource type "frobs"');
  });
});

describe('helpers', () => {
  it('formats ages like kubectl and parses quantities', () => {
    expect(age(45_000)).toBe('45s');
    expect(age(5 * 60_000 + 12_000)).toBe('5m12s');
    expect(age(45 * 60_000)).toBe('45m');
    expect(age(3 * 3600_000 + 45 * 60_000)).toBe('3h45m');
    expect(age(30 * 3600_000)).toBe('30h');
    expect(age(3 * 86400_000 + 3600_000)).toBe('3d1h');
    expect(cpuMilli('250m')).toBe(250);
    expect(cpuMilli('1.5')).toBe(1500);
    expect(memMi('1Gi')).toBe(1024);
    expect(Math.round(memMi('128M'))).toBe(122);
  });
});
