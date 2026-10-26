// Docker and container troubleshooting. Example output is representative of
// Docker Engine 27.3 and Docker Compose v2.29 on Ubuntu 24.04 LTS (iptables
// backend, userland proxy enabled); the sandbox and tickets use the simulated
// dock01 (Debian 12, Docker Engine 26, nftables). RHEL 9 and Windows noted.

import type { Assessment, Lesson, ServiceGuide } from '../types';

const COMPOSE_EXAMPLE = `services:
  web:
    image: registry.corp.lab/inventory-web:1.4.2
    ports:
      - "8080:8000"            # host 8080 -> container 8000 (all host addresses)
    environment:
      DATABASE_URL: postgresql://inventory:\${DB_PASSWORD}@db:5432/inventory
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8000/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    mem_limit: 512m

  db:
    image: postgres:16
    environment:
      POSTGRES_USER: inventory
      POSTGRES_DB: inventory
      POSTGRES_PASSWORD: \${DB_PASSWORD:?DB_PASSWORD must be set in .env}
    volumes:
      - dbdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U inventory -d inventory"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  dbdata:`;

// --- Operate & recover guide ---------------------------------------------------------

export const DOCKER_GUIDE: ServiceGuide = {
  purpose:
    'Docker Engine runs applications as **containers**: ordinary Linux processes isolated with namespaces (their own filesystem view, network stack, process tree, hostname) and limited with cgroups, started from **images** that bundle the application with its userland. The service you manage on the host is the Docker daemon (`dockerd`, unit `docker.service`), which delegates container execution to `containerd` and `runc`, builds the networks (bridges, veth pairs, NAT rules) and stores images, volumes and logs under `/var/lib/docker`. When "the container is broken", the cause is in one of a few places: the process inside it, its configuration (image, command, environment), its storage, its network path (bridge, DNS, published port, host firewall), its resource limits, or the daemon itself, and each has its own command to look at it.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Packaging and running applications reproducibly: the same image runs on a laptop, a test VM and production. Many isolated services share one host kernel without separate VMs, with explicit, versioned configuration (`compose.yaml`) and fast replacement (recreate a container from a new image instead of patching it in place).' },
    { q: 'How does it work internally?', a: 'The `docker` CLI is only a client: it sends REST API calls to `/var/run/docker.sock`. **dockerd** handles images, networks, volumes and the API, and asks **containerd** (separate service, `containerd.service`) to run containers. For each container containerd starts a **containerd-shim-runc-v2** process, which calls **runc** to create the namespaces and cgroups and exec the container\'s main process (PID 1 inside it); runc then exits and the shim stays as the parent, so containers keep running even while dockerd restarts if `live-restore` is enabled. Images are stacks of read-only **layers**; the overlay2 storage driver merges them with a per-container writable layer under `/var/lib/docker/overlay2`.' },
    { q: 'Which protocols does it use?', a: 'HTTP over a Unix socket (or TCP/TLS on 2376 if configured) for the Docker API; HTTPS to registries (Docker Hub `registry-1.docker.io`, private registries) for image pulls; plain Linux networking for containers: Ethernet bridges, veth pairs, IP routing and netfilter NAT (iptables or nftables backends); the embedded DNS server at `127.0.0.11` on user-defined networks.' },
    { q: 'Which ports and transport?', a: 'The daemon itself listens on no TCP port by default, only on the Unix socket. Containers listen on whatever their application uses **inside their own network namespace**. A port is reachable from outside the host only if it is **published** (`-p 8080:8000` / `ports:`): Docker adds a DNAT rule (host 8080 → container IP:8000) and, with the userland proxy enabled, a `docker-proxy` process listening on the host port.' },
    { q: 'Which processes and OS components implement it?', a: '`dockerd` (docker.service, socket-activated through docker.socket), `containerd` (containerd.service), one `containerd-shim-runc-v2` per container, `runc` (short-lived), `docker-proxy` per published port and address family, the Linux kernel (namespaces, cgroups v2, overlayfs, bridge, veth, netfilter), and the Compose v2 plugin (`docker compose`, a CLI plugin, not a daemon).' },
    { q: 'Which other services does it depend on?', a: 'Kernel features (overlayfs, cgroups v2, bridge, iptables/nftables), `net.ipv4.ip_forward=1` (Docker sets it), disk space in `/var/lib/docker`, DNS servers from the host\'s resolv.conf (or `dns` in daemon.json) for containers, network access (and proxy settings) to registries for pulls, and the host firewall not conflicting with Docker\'s chains. Applications inside containers depend on each other (web → db) and on external services exactly as they would on a VM.' },
    { q: 'How do requests travel?', a: 'Client → host IP:8080 → netfilter PREROUTING → **DOCKER** chain DNAT to 172.18.0.3:8000 → FORWARD (through **DOCKER-USER** first, then Docker\'s own chains) → bridge `br-xxxx` → veth pair → the container\'s eth0 → the application socket, which must listen on `0.0.0.0` (not 127.0.0.1) **inside** the container. Replies are un-NATed on the way back. Connections from the host itself to `127.0.0.1:8080` go through `docker-proxy` instead. Between containers on the same user-defined network, names are resolved by the embedded DNS (`127.0.0.11`) and traffic goes directly across the bridge, to the **container** port (5432), not a published port.' },
    { q: 'How do authentication and authorisation work?', a: 'Access to the API is access to root: anyone who can write to `/var/run/docker.sock` (root and members of the `docker` group) can start a privileged container that mounts `/` from the host. Registry authentication uses `docker login`, which stores credentials in `~/.docker/config.json` (base64, not encrypted, unless a credential helper is configured). Inside containers, processes run as root by default unless the image or `--user` says otherwise; that UID maps to the same UID on the host unless user-namespace remapping or rootless mode is used, which matters for bind-mount permissions.' },
    { q: 'How does it start at boot?', a: '`docker.service` is enabled by the package (Ubuntu/Debian) or with `systemctl enable --now docker` (RHEL). When dockerd starts, it restores networks and starts containers according to their **restart policy**: `always` and `unless-stopped` (unless the user stopped it) come back; `no` and `on-failure` containers that were running do not. Compose has no boot service of its own: it relies on the restart policies of the containers it created.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'If **the container\'s main process** exits, the container stops (Exited (code)); the restart policy may restart it, with an increasing delay that produces a restart loop if it keeps failing. If **dockerd** crashes or is restarted, all containers are stopped unless `"live-restore": true` is set in daemon.json, in which case they keep running and dockerd reattaches when it returns. If **containerd** stops, containers keep running under their shims, but no new ones can start.' },
  ],
  ports: [
    { port: '/var/run/docker.sock', proto: 'Unix socket', purpose: 'Docker API (root / docker group only). Never expose 2375/tcp without TLS.' },
    { port: '2376', proto: 'TCP (TLS)', purpose: 'Optional remote Docker API with mutual TLS (off by default)' },
    { port: 'published (e.g. 8080)', proto: 'TCP/UDP', purpose: 'Host port DNATed to a container port; docker-proxy listens when the userland proxy is enabled' },
    { port: '443 (outbound)', proto: 'TCP', purpose: 'Registry access for pulls/pushes (Docker Hub, registry.corp.lab)' },
    { port: '53 via 127.0.0.11', proto: 'UDP/TCP', purpose: 'Embedded DNS inside containers on user-defined networks' },
  ],
  processes: [
    { name: 'dockerd', platform: 'Linux (docker.service)', role: 'Docker daemon: API, images, networks, volumes, logging drivers, restart policies' },
    { name: 'containerd', platform: 'Linux (containerd.service)', role: 'Container runtime manager used by dockerd (namespace "moby")' },
    { name: 'containerd-shim-runc-v2', platform: 'Linux', role: 'One per container: parent of the container\'s PID 1, keeps stdio and exit status, survives dockerd restarts' },
    { name: 'runc', platform: 'Linux', role: 'OCI runtime: creates namespaces/cgroups and execs the main process, then exits' },
    { name: 'docker-proxy', platform: 'Linux', role: 'Userland proxy per published port: serves connections from the host itself (localhost) and hairpin cases' },
    { name: 'docker (CLI), docker compose (plugin)', platform: 'Linux, Windows, macOS', role: 'Clients: talk to the daemon over the socket; Compose turns compose.yaml into API calls' },
    { name: 'Docker Desktop (com.docker.backend, WSL2 VM)', platform: 'Windows 10/11, macOS', role: 'Runs dockerd inside a Linux VM (WSL2 on Windows); the Windows CLI talks to it through a named pipe' },
  ],
  dependencies: {
    title: 'What "the web app in a container answers" depends on (top needs everything below it)',
    caption: 'Work from the daemon up, or from the client down, but check each layer with its own command: systemctl/journalctl, docker ps/inspect/logs, docker exec, docker network inspect, iptables/ss and curl.',
    rows: [
      { label: 'Client', nodes: [{ id: 'client', label: 'Office client', sub: 'dock01:8080', kind: 'client' }] },
      { label: 'Host network', nodes: [{ id: 'fw', label: 'Host firewall', sub: 'DOCKER-USER, ufw', kind: 'network' }, { id: 'nat', label: 'Published port', sub: 'DNAT + docker-proxy', kind: 'network' }] },
      { label: 'Container', nodes: [{ id: 'app', label: 'App process', sub: 'listens 0.0.0.0:8000', kind: 'service' }, { id: 'env', label: 'Config + env', sub: 'compose.yaml, .env', kind: 'data' }, { id: 'dep', label: 'db container', sub: 'healthy, port 5432', kind: 'service' }] },
      { label: 'Engine', nodes: [{ id: 'bridge', label: 'Bridge network', sub: 'br-*, veth, 127.0.0.11', kind: 'network' }, { id: 'vol', label: 'Volumes / mounts', sub: 'UID, SELinux label', kind: 'data' }, { id: 'img', label: 'Image', sub: 'pulled from registry', kind: 'data' }] },
      { label: 'Daemon', nodes: [{ id: 'dockerd', label: 'dockerd', sub: 'docker.service', kind: 'os' }, { id: 'ctrd', label: 'containerd', sub: 'shim + runc', kind: 'os' }, { id: 'disk', label: '/var/lib/docker', sub: 'overlay2, free space', kind: 'os' }] },
    ],
    edges: [
      ['client', 'fw'], ['fw', 'nat'], ['nat', 'app'], ['app', 'env'], ['app', 'dep'], ['app', 'bridge'], ['dep', 'vol'], ['app', 'img'],
      ['nat', 'dockerd'], ['bridge', 'dockerd'], ['vol', 'disk'], ['img', 'disk'], ['dockerd', 'ctrd'],
    ],
  },
  sequence: {
    title: 'ws01 opens http://dock01:8080/ (web container talks to db)',
    caption: 'Docker Engine 27 on Ubuntu 24.04, Compose project "inventory" on the user-defined network inventory_default (172.18.0.0/16).',
    lanes: [{ id: 'c', label: 'ws01', sub: 'browser' }, { id: 'h', label: 'dock01', sub: 'netfilter, 10.0.20.40' }, { id: 'w', label: 'web', sub: '172.18.0.3:8000' }, { id: 'n', label: '127.0.0.11', sub: 'embedded DNS' }, { id: 'd', label: 'db', sub: '172.18.0.2:5432' }],
    steps: [
      { from: 'c', to: 'h', label: 'TCP SYN 10.0.20.40:8080', note: 'Port not published → no DNAT → host RST → "Connection refused". DROP in DOCKER-USER → timeout.' },
      { from: 'h', to: 'w', label: 'DNAT → 172.18.0.3:8000', note: 'App listening on 127.0.0.1 inside the container, or on another port → container RST → refused (from localhost via docker-proxy: "Empty reply").' },
      { from: 'w', to: 'c', label: 'SYN-ACK (reverse NAT)' },
      { from: 'c', to: 'w', label: 'GET / HTTP/1.1' },
      { from: 'w', to: 'n', label: 'A? db', note: 'On the default bridge there is no name resolution between containers: "Name or service not known".' },
      { from: 'n', to: 'w', label: 'db = 172.18.0.2' },
      { from: 'w', to: 'd', label: 'TCP 5432 (container port)', note: 'db still initialising → "Connection refused"; use depends_on: condition: service_healthy.' },
      { from: 'd', to: 'w', label: 'query result' },
      { from: 'w', to: 'c', label: 'HTTP/1.1 200 OK' },
    ],
  },
  files: [
    { path: '/etc/docker/daemon.json', platform: 'Linux (Windows Server: C:\\ProgramData\\docker\\config\\daemon.json)', kind: 'config', perms: 'root:root 0644', contains: 'Daemon settings in JSON: `log-driver`, `log-opts` (`max-size`, `max-file`), `dns`, `bip`, `default-address-pools`, `live-restore`, `registry-mirrors`, `proxies`, `data-root`, `iptables`, `userland-proxy`.', accessed: 'When dockerd starts; a subset (debug, labels, live-restore, registry mirrors, insecure registries, concurrency limits) on `systemctl reload docker` (SIGHUP).', problems: 'Invalid JSON or an option also given as a dockerd flag in the unit → dockerd will not start: "unable to configure the Docker daemon with file /etc/docker/daemon.json: invalid character ...". Validate with `sudo dockerd --validate --config-file /etc/docker/daemon.json`. Logging and DNS defaults apply only to containers **created** afterwards.' },
    { path: '/var/lib/docker/', platform: 'Linux', kind: 'data', perms: 'root:root 0710', contains: '`overlay2/` (image layers and container writable layers), `image/`, `volumes/<name>/_data` (named volumes), `containers/<id>/` (config, hostconfig, logs, resolv.conf, hosts), `network/`, `buildkit/`.', accessed: 'Continuously by dockerd.', problems: 'Full filesystem → pulls fail ("no space left on device"), databases in volumes crash, logs stop. Never delete files here by hand: use `docker system df` and the prune commands. Moving it requires `data-root` in daemon.json with the daemon stopped.' },
    { path: '/var/run/docker.sock (/run/docker.sock)', platform: 'Linux', kind: 'runtime', perms: 'root:docker 0660', contains: 'The Docker API Unix socket, created by docker.socket.', accessed: 'By every docker/compose command, and by any container that mounts it (Traefik, Portainer, CI runners).', problems: 'Not in the docker group → "permission denied while trying to connect to the Docker daemon socket". Missing → "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?". Mounting it into a container gives that container root on the host.' },
    { path: '/var/lib/docker/containers/<id>/<id>-json.log', platform: 'Linux (json-file driver)', kind: 'log', perms: 'root 0640', contains: 'The container\'s stdout/stderr as JSON lines (what `docker logs` shows).', accessed: 'Written continuously by dockerd; read by `docker logs`.', problems: 'With the default json-file driver and no `max-size`, the file grows **without limit** and fills the disk. Configure `log-opts` in daemon.json (new containers) or per service in compose.yaml. Deleted with the container on recreate: save logs before `docker compose up -d` if you need them.' },
    { path: 'compose.yaml (+ .env) in the project directory', platform: 'Any (Compose v2)', kind: 'config', perms: 'readable by the deploying user; .env often contains secrets: 0600', contains: 'Services, images, ports, environment, volumes, networks, healthchecks, depends_on, restart policies. `.env` provides variables for **interpolation** (`${DB_PASSWORD}`) in compose.yaml; it is not passed into containers unless referenced or listed with `env_file:`.', accessed: 'Each time a `docker compose` command runs in that directory (project name = directory name unless `COMPOSE_PROJECT_NAME`/`-p`).', problems: 'Editing compose.yaml or .env does nothing until `docker compose up -d` recreates the affected containers. A variable missing from .env becomes an empty string with only a warning (`The "DB_PASSWORD" variable is not set. Defaulting to a blank string.`) unless written as `${VAR:?message}`. Running compose from another directory creates a second project.' },
    { path: '/usr/lib/systemd/system/docker.service, docker.socket', platform: 'Ubuntu 24.04, RHEL 9', kind: 'unit', perms: 'root:root 0644', contains: '`ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock`, `Restart=always`, start limits, `After=network-online.target docker.socket firewalld.service containerd.service`.', accessed: 'At boot and on daemon-reload.', problems: 'Overrides (proxy variables, extra flags) belong in `/etc/systemd/system/docker.service.d/*.conf` via `systemctl edit docker`, followed by `daemon-reload` and a daemon restart. A flag in the unit that is also in daemon.json stops dockerd from starting ("the following directives are specified both as a flag and in the configuration file").' },
    { path: '/etc/systemd/system/docker.service.d/http-proxy.conf', platform: 'Linux', kind: 'config', perms: 'root:root 0644', contains: '`[Service]` `Environment="HTTP_PROXY=http://proxy.corp.lab:3128"` `"HTTPS_PROXY=..."` `"NO_PROXY=localhost,127.0.0.1,registry.corp.lab"`.', accessed: 'When docker.service starts.', problems: 'Pulls go through **dockerd**, not your shell: `export https_proxy` in your terminal does not help `docker pull`. Since Engine 23 the same can be set as `"proxies"` in daemon.json.' },
    { path: '~/.docker/config.json', platform: 'Linux, Windows (%USERPROFILE%\\.docker), macOS', kind: 'auth', perms: 'user 0600', contains: 'Registry credentials from `docker login` (base64 `auths` entries or a `credsStore` helper), CLI proxy settings for containers, current context.', accessed: 'By the CLI for pulls/pushes and every command (context).', problems: 'Pull as root (sudo) uses /root/.docker/config.json, not yours: "pull access denied ... may require \'docker login\'". Credentials are only obfuscated: protect the file or use a credential helper.' },
    { path: 'journal: journalctl -u docker / -u containerd', platform: 'Linux', kind: 'log', contains: 'Daemon messages: start-up errors, daemon.json problems, image pull errors, network/iptables setup, container events with `level=error`.', accessed: 'Continuously.', problems: 'Container application output is **not** here with the default json-file driver: use `docker logs`. With `log-driver: journald` it is (`journalctl CONTAINER_NAME=web`).' },
  ],
  management: [
    {
      platform: 'Ubuntu / Debian',
      tasks: [
        { task: 'Is the daemon running?', command: 'systemctl status docker\nsystemctl status containerd', explain: 'Look for `Active: active (running)`, `TriggeredBy: docker.socket`, the dockerd command line and the docker-proxy children. `failed` → read the journal lines shown.' },
        { task: 'Start / stop / restart the daemon', command: 'sudo systemctl start docker\nsudo systemctl restart docker\nsudo systemctl stop docker docker.socket', explain: 'Stopping only docker.service leaves docker.socket listening, so the next docker command starts the daemon again. Stop both to keep it down.', risk: 'Restart/stop stops **every container on the host** (unless live-restore), interrupting all services on it. Prefer restarting a single container.' },
        { task: 'Reload the daemon configuration', command: 'sudo systemctl reload docker', explain: 'Sends SIGHUP: applies the reloadable daemon.json options (debug, labels, live-restore, registry mirrors, insecure registries, concurrency) without stopping containers. Other options (storage, network defaults, log driver) need a restart, and container defaults only affect new containers.' },
        { task: 'Enable / disable at boot', command: 'sudo systemctl enable --now docker containerd\nsystemctl is-enabled docker', explain: 'Containers come back at boot only if the daemon is enabled **and** the containers have restart policy always or unless-stopped.' },
        { task: 'Failed units and why the daemon did not start', command: 'systemctl --failed\njournalctl -u docker -b --no-pager | tail -n 30\nsudo dockerd --validate --config-file /etc/docker/daemon.json', explain: 'Typical causes: invalid daemon.json, flag/config conflict, storage driver problem, data-root missing, a full disk.' },
        { task: 'Dependencies', command: 'systemctl list-dependencies docker\nsystemctl cat docker', explain: 'docker.service requires docker.socket and wants containerd.service and network-online.target; `cat` shows drop-ins (proxy settings).' },
        { task: 'Daemon logs', command: 'journalctl -u docker --since "30 min ago"\njournalctl -u docker -f', explain: 'Pull errors, network setup errors and container exits seen by the daemon.' },
        { task: 'Container status', command: 'docker ps -a\ndocker inspect --format \'{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}\' web', explain: 'STATUS column: Up, Up (healthy/unhealthy), Restarting (code), Exited (code), Created, Dead.' },
        { task: 'Container logs', command: 'docker logs --tail 50 web\ndocker logs --since 10m -f web', explain: 'stdout/stderr of the main process. The first error lines after a start usually explain an immediate exit.' },
        { task: 'Restart one container', command: 'docker restart web', explain: 'Stop (SIGTERM, then SIGKILL after 10 s) and start the **same** container: same config, same writable layer, same environment.', risk: 'Brief outage of that service only. Does not apply changes made to compose.yaml, .env or the image.' },
        { task: 'Disk usage and cleanup', command: 'docker system df\ndocker image prune\ndocker builder prune', explain: 'Shows reclaimable space; the prune commands remove dangling images and build cache.', risk: '`docker system prune -a --volumes` deletes all unused images **and unused volumes**: a stopped database\'s data volume counts as unused. Never run it blindly on a server.' },
      ],
    },
    {
      platform: 'RHEL 9 / Rocky / Alma',
      tasks: [
        { task: 'Docker CE on RHEL', command: 'systemctl status docker\nsudo systemctl enable --now docker', explain: 'Same unit names as Ubuntu; the package does **not** enable the service automatically on RHEL.' },
        { task: 'Podman (RHEL default)', command: 'podman ps -a\npodman logs web\nsystemctl --user status container-web.service', explain: 'Podman has no daemon: each container is a child of the podman process or of a systemd unit (Quadlet `.container` files in `/etc/containers/systemd/`). `podman-docker` provides a `docker` command alias. Rootless containers run as the user and use slirp4netns/pasta networking.' },
        { task: 'SELinux denials for bind mounts', command: 'sudo ausearch -m avc -ts recent\nls -Z /srv/inventory', explain: 'Permission denied inside a container with correct UNIX permissions → SELinux label. Mount with `:z` (shared) or `:Z` (private to that container).', risk: 'Never use `:Z` on system or home directories: it relabels them for one container and breaks other services.' },
        { task: 'firewalld interaction', command: 'sudo firewall-cmd --get-active-zones\nsudo iptables -t nat -L DOCKER -n', explain: 'Docker puts its bridges in a firewalld zone named `docker`. Published ports are reachable even if the port is not opened in firewalld. Docker re-applies its rules when firewalld reloads; if published ports stop working after a firewalld change, check the DOCKER nat chain before restarting the daemon.' },
      ],
    },
    {
      platform: 'Docker Compose v2',
      tasks: [
        { task: 'Status of the project', command: 'docker compose ps\ndocker compose ps -a', explain: 'Run in the project directory (or with `-p inventory`). Shows service, state, health and published ports.' },
        { task: 'Logs', command: 'docker compose logs --tail 50 web\ndocker compose logs -f --since 5m', explain: 'Interleaved logs of all or selected services.' },
        { task: 'Effective configuration', command: 'docker compose config', explain: 'Prints compose.yaml after merging override files and interpolating .env: the ground truth of what Compose will deploy. Missing variables show up as empty values and warnings.' },
        { task: 'Apply changes (recreate)', command: 'docker compose up -d\ndocker compose up -d --force-recreate web', explain: 'Compares the desired configuration with the running containers and **recreates** only the services that changed (new container, new writable layer, new IP). Named volumes are kept.', risk: 'A short outage per recreated service; anything written inside the container outside volumes is lost.' },
        { task: 'Restart without changes', command: 'docker compose restart web', explain: 'Restarts the existing containers. Does **not** pick up compose.yaml or .env changes (the documentation says so explicitly).' },
        { task: 'Update images', command: 'docker compose pull\ndocker compose up -d', explain: 'Pull new images for the configured tags, then recreate the services whose image changed.' },
        { task: 'Stop / remove', command: 'docker compose stop\ndocker compose down', explain: '`stop` keeps containers; `down` removes containers and the project network but keeps named volumes.', risk: '`docker compose down -v` also deletes named volumes: the database is gone.' },
      ],
    },
    {
      platform: 'Windows 10/11 (Docker Desktop) and Windows Server',
      tasks: [
        { task: 'Docker Desktop status', command: 'docker version\ndocker context ls\nwsl -l -v', explain: 'The engine runs in the `docker-desktop` WSL2 distribution; the CLI shows `Server: Docker Desktop`. Restart from the tray icon (Restart) or Troubleshoot menu.', risk: 'Restarting Docker Desktop or `wsl --shutdown` stops every container and every WSL distribution.' },
        { task: 'Windows Server container host', command: 'Get-Service docker\nRestart-Service docker\nGet-WinEvent -LogName Application -MaxEvents 30 | Where-Object ProviderName -eq docker', explain: 'Windows Server runs **Windows** containers with Mirantis Container Runtime or Docker CE static binaries (service `docker`), or containerd with nerdctl. dockerd logs to the Application event log.', risk: 'Restart-Service docker stops all containers on that host.' },
      ],
    },
    {
      platform: 'pfSense',
      tasks: [
        { task: 'Not applicable', command: '(none)', explain: 'pfSense (FreeBSD) does not run Docker. It matters only as the network path: rules/NAT in front of the Docker host, and DNS for names such as registry.corp.lab.' },
      ],
    },
  ],
  actions: [
    { action: 'docker restart web / docker compose restart web', when: 'The process is stuck or you need it to re-read files on a mounted volume; configuration has not changed.', effect: 'Same container (same ID, config, environment, writable layer) is stopped (SIGTERM, SIGKILL after the timeout) and started. IP usually stays the same.', risk: 'Short outage of that one service. Changes to compose.yaml, .env or the image are **not** applied, which is the most common surprise.' },
    { action: 'docker compose up -d (recreate), --force-recreate', when: 'After changing compose.yaml, .env, the image tag, ports, environment or limits; after `docker compose pull`.', effect: 'Old container removed, new one created from the image with the new config: new ID, new writable layer, possibly new IP. Named volumes and bind mounts are kept.', risk: 'Data written inside the container (not in a volume) is lost; the old container\'s `docker logs` disappear. Test with `docker compose config` first and keep the previous compose.yaml/tag for rollback.' },
    { action: 'systemctl reload docker', when: 'After changing reloadable daemon.json options (debug, registry mirrors, insecure registries, live-restore).', effect: 'dockerd re-reads those options; containers keep running.', risk: 'Low, but most network/storage/logging options are not reloadable and silently need a restart or container recreation.' },
    { action: 'systemctl restart docker', when: 'After non-reloadable daemon.json or unit changes (dns, bip, address pools, data-root, proxy drop-in), or a hung daemon.', effect: 'All containers are stopped and started again according to their restart policies (unless `live-restore: true`), networks and NAT rules are rebuilt.', risk: 'Outage of **every** container on the host, including ones owned by other teams. Containers with restart policy `no` stay down. Schedule it, and validate daemon.json first or the daemon will not come back.' },
    { action: 'ip link / netplan apply / NetworkManager restart on the host', when: 'Host network configuration changes only.', effect: 'Host addresses and routes change; Docker\'s bridges and NAT rules normally remain.', risk: 'Disconnects SSH; can conflict with Docker bridges if the new host network overlaps 172.17.0.0/16 or the default address pools.' },
    { action: 'reboot the host', when: 'Kernel updates, or to prove that services come back by themselves.', effect: 'dockerd starts at boot and starts containers with restart policy always / unless-stopped.', risk: 'Services started by hand with `docker run` without a restart policy, or with `docker compose up` in the foreground, do not return.' },
  ],
  workflow: [
    { question: 'Is the daemon running and can I talk to it?', why: 'Every docker command talks to the daemon through its socket. If dockerd is down or you lack permission, nothing else can be checked.', command: 'systemctl is-active docker\ndocker info --format \'{{.ServerVersion}}\'', healthy: 'active\n27.3.1', broken: '"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" → daemon down: `journalctl -u docker -b`. "permission denied while trying to connect to the Docker daemon socket" → your user is not in the docker group (use sudo, or log out and in after usermod).', next: 'Running → step 2.' },
    { question: 'What state is the container in?', why: 'Running, restarting in a loop, or exited with an error code are very different problems. inspect also shows whether it was killed for memory.', command: 'docker ps -a\ndocker inspect --format \'{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}\' inventory-web-1', healthy: 'running exit=0 oom=false restarts=0', broken: '`exited exit=1` → the application failed (step 3). `exit=127` → command not found; `126` → not executable; `125` → docker could not create/start it. `exit=137 oom=true` → killed by the OOM killer (memory limit); `137 oom=false` → SIGKILL (docker kill, stop timeout). `139` → segfault. `143` → SIGTERM. `Restarting` with a growing RestartCount → restart loop.', next: 'Not running → step 3 (logs). Running but unreachable → step 5.' },
    { question: 'What did the process say before it stopped?', why: 'A container usually stops because its program exited, and the program says why in its own output, which Docker keeps as the container log.', command: 'docker logs --tail 50 inventory-web-1\ndocker compose logs --tail 50 db', healthy: '[2026-10-21 09:12:03 +0000] [1] [INFO] Listening at: http://0.0.0.0:8000 (1)', broken: '`KeyError: \'DATABASE_URL\'` / "must specify POSTGRES_PASSWORD" → missing environment (step 4). "Permission denied" on a path under a mount → volume ownership/SELinux (step 7). `exec: "gunicorn": executable file not found in $PATH` → wrong image or CMD. A container that runs `bash` or a one-shot script with no foreground process simply exits 0.', next: 'Fix configuration and **recreate** (`docker compose up -d`); restarting would reuse the broken config.' },
    { question: 'Is the configuration what I think it is?', why: 'What is running may differ from what you think you deployed: an old image tag, a missing variable, a wrong port mapping.', command: 'docker compose config\ndocker inspect --format \'{{json .Config.Env}}\' inventory-web-1\ndocker inspect --format \'{{json .Config.Cmd}} {{json .HostConfig.PortBindings}}\' inventory-web-1', healthy: '["DATABASE_URL=postgresql://inventory:****@db:5432/inventory", ...]\n["gunicorn","-b","0.0.0.0:8000","app:app"] {"8000/tcp":[{"HostIp":"","HostPort":"8080"}]}', broken: 'An empty value (`DATABASE_URL=postgresql://inventory:@db...`) → the variable was missing from .env. The running container has old values while compose.yaml has new ones → it was restarted, not recreated. Port binding to the wrong container port (`80/tcp` while the app listens on 8000).', next: 'Correct compose.yaml/.env, `docker compose up -d`, re-check.' },
    { question: 'Does the app answer inside the container, and on which address?', why: 'Testing from inside the container separates "the app does not work" from "the path to the app does not work". An app listening only on 127.0.0.1 inside the container cannot be reached through a published port.', command: 'docker exec inventory-web-1 ss -tlnp\ndocker exec inventory-web-1 curl -sS -o /dev/null -w \'%{http_code}\\n\' http://localhost:8000/healthz', healthy: 'LISTEN 0 2048 0.0.0.0:8000 0.0.0.0:* users:(("gunicorn",pid=1,fd=5))\n200', broken: '`127.0.0.1:8000` → the app accepts only connections from inside the container: published traffic arrives on eth0 and is refused. Nothing listening → app not started. (Minimal images may lack ss/curl: use `docker exec web cat /proc/net/tcp` or a debug container on the same network namespace: `docker run --rm --network container:inventory-web-1 nicolaka/netshoot ss -tlnp`.)', next: 'Listening on 0.0.0.0 and answering → step 6.' },
    { question: 'Is the port published, and does the host path work?', why: 'A published port is a NAT rule from the host to the container. The host must have it, and nothing else may already use the port.', command: 'docker port inventory-web-1\nsudo ss -tlnp | grep 8080\nsudo iptables -t nat -L DOCKER -n\ncurl -sS -o /dev/null -w \'%{http_code}\\n\' http://10.0.20.40:8080/', healthy: '8000/tcp -> 0.0.0.0:8080\n8000/tcp -> [::]:8080\nLISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("docker-proxy",pid=2210,fd=7))\nDNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 to:172.18.0.3:8000\n200', broken: 'No output from `docker port` → not published (`ports:` missing or `expose:` only). Published as `127.0.0.1:8080` → only local clients. Works locally but not from ws01 → a DROP in **DOCKER-USER** or an upstream firewall (ufw/firewalld rules do not apply to published ports, but DOCKER-USER does). "Bind for 0.0.0.0:8080 failed: port is already allocated" at start → another container or process owns 8080.', next: 'Fix the mapping and recreate; check DOCKER-USER with `sudo iptables -L DOCKER-USER -n -v`.' },
    { question: 'Can the container reach its dependencies (network and DNS)?', why: 'Containers find each other by name through Docker\'s built-in DNS, which only exists on user-defined networks.', command: 'docker network inspect inventory_default --format \'{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\\n"}}{{end}}\'\ndocker exec inventory-web-1 getent hosts db\ndocker exec inventory-web-1 cat /etc/resolv.conf', healthy: 'inventory-db-1 172.18.0.2/16\ninventory-web-1 172.18.0.3/16\n172.18.0.2      db\nnameserver 127.0.0.11\noptions ndots:0', broken: 'The two containers on different networks (two Compose projects, or one started with `docker run` on the default bridge) → no route/name between them. On the default bridge, `/etc/resolv.conf` is a copy of the host\'s and container names do not resolve. External names failing (`Temporary failure in name resolution`) → the host\'s DNS servers are unusable from containers (loopback-only resolver; Docker then falls back to 8.8.8.8, which cannot resolve internal names) → set `"dns": ["10.0.10.53"]` in daemon.json.', next: 'Attach to the same network (`networks:` in compose, `docker network connect`), fix DNS, recreate.' },
    { question: 'Are resources, storage and health OK?', why: 'A full disk, too little memory, or a failing health check can stop or restart containers even when everything else is right.', command: 'docker stats --no-stream\ndocker system df\ndf -h /var/lib/docker\ndocker inspect --format \'{{json .State.Health}}\' inventory-web-1', healthy: 'inventory-web-1   0.42%   187.3MiB / 512MiB   36.58% ...\n/dev/sda2  60G  21G  37G  37% /\n{"Status":"healthy","FailingStreak":0,"Log":[...]}', broken: 'MEM USAGE at the LIMIT and `OOMKilled: true` → raise the limit or fix the leak. `/var/lib/docker` at 100% → images, build cache or unrotated json logs (`du -sh /var/lib/docker/containers/*/*-json.log`). Health `unhealthy` with the check\'s output in `Log` → the check command fails (wrong URL/port, tool missing in the image).', next: 'Fix the cause, then verify with the full checklist.' },
  ],
  failures: [
    { symptom: 'Container exits immediately (Exited (0) or Exited (1) seconds after start)', causes: ['The main process finished: a shell or one-shot command with nothing in the foreground (`docker run -d ubuntu:24.04`)', 'The application crashed on start-up: missing environment variable, unreachable dependency, bad config file', 'Wrong CMD/ENTRYPOINT (exit 127 "executable file not found in $PATH", 126 "permission denied")'], diagnose: ['docker ps -a', 'docker logs --tail 50 <name>', 'docker inspect --format \'{{.State.ExitCode}} {{json .Config.Cmd}} {{json .Config.Env}}\' <name>', 'docker compose config'], fix: 'Give the container a long-running foreground process; supply the missing variables in compose.yaml/.env (use `${VAR:?msg}` to fail loudly); correct the command or image. Then `docker compose up -d` to recreate.', verify: 'docker ps shows Up for more than a minute; docker logs shows the listening message.' },
    { symptom: 'Restarting (1) ... / RestartCount keeps increasing', causes: ['Restart policy always/unless-stopped/on-failure around a process that fails every time', 'Dependency not ready (database still initialising) and the app does not retry', 'OOM kill on start (exit 137, OOMKilled true)'], diagnose: ['docker inspect --format \'{{.RestartCount}} {{.State.ExitCode}} {{.State.OOMKilled}}\' <name>', 'docker logs --tail 100 <name>', 'docker events --since 10m --filter container=<name>'], fix: 'Fix the underlying error found in the logs; add `depends_on: condition: service_healthy` with a real healthcheck on the dependency; raise the memory limit if justified. Use `on-failure:5` for jobs so a broken one stops instead of looping.', verify: 'RestartCount stays constant; docker events shows no new die events.' },
    { symptom: 'Port not reachable: "Connection refused" from clients, "Empty reply from server" or "Connection reset by peer" from the host', causes: ['Port not published, or published to the wrong container port', 'Application listens on 127.0.0.1 inside the container', 'Published only on 127.0.0.1 (`127.0.0.1:8080:8000`)', 'Container on the host but on a different port than clients use'], diagnose: ['docker port <name>', 'docker inspect --format \'{{json .HostConfig.PortBindings}}\' <name>', 'docker exec <name> ss -tlnp', 'sudo iptables -t nat -L DOCKER -n'], fix: 'Make the app listen on 0.0.0.0 inside the container (e.g. `gunicorn -b 0.0.0.0:8000`), publish `HOST:CONTAINER` with the port the app really uses, and recreate.', verify: 'curl from another host returns 200.' },
    { symptom: 'Published port reachable from everywhere despite "ufw deny 8080" / firewalld', causes: ['Published ports are DNATed in PREROUTING and forwarded through FORWARD; ufw/firewalld INPUT rules are never consulted'], diagnose: ['sudo iptables -t nat -L DOCKER -n', 'sudo iptables -L DOCKER-USER -n -v', 'sudo ufw status verbose'], fix: 'Publish only where needed (`127.0.0.1:8080:8000` behind a reverse proxy) or filter in the **DOCKER-USER** chain, e.g. `sudo iptables -I DOCKER-USER -i eth0 ! -s 10.0.10.0/24 -p tcp -m conntrack --ctorigdstport 8080 -j DROP` (persist it with your firewall tooling).', verify: 'nc -zv from an unauthorised network times out; from the office it connects.' },
    { symptom: 'Container cannot resolve names: "Temporary failure in name resolution" / "Name or service not known"', causes: ['Containers on the default bridge addressing each other by name (no embedded DNS there)', 'Host uses a loopback resolver (systemd-resolved 127.0.0.53, dnsmasq); Docker substitutes upstream servers or falls back to 8.8.8.8, which cannot see internal zones or is blocked by the firewall', 'Containers on different networks'], diagnose: ['docker exec <name> cat /etc/resolv.conf', 'docker exec <name> getent hosts db', 'docker network inspect <network>', 'resolvectl status (on the host)'], fix: 'Put cooperating containers on one user-defined network (Compose does this per project); set `"dns": ["10.0.10.53"]` in daemon.json (restart docker, recreate containers) or `dns:` per service.', verify: 'docker exec <name> getent hosts db and an internal name both resolve.' },
    { symptom: 'Permission denied writing to a mounted directory', causes: ['Bind-mounted host directory owned by root while the container runs as UID 999/1000', 'SELinux on RHEL blocks container_t from the host directory\'s label', 'Mounted read-only (`:ro`)'], diagnose: ['docker exec <name> id', 'ls -ln /srv/inventory/data', 'docker inspect --format \'{{json .Mounts}}\' <name>', 'sudo ausearch -m avc -ts recent (RHEL)'], fix: 'chown the host directory to the container\'s numeric UID (`sudo chown -R 999:999 /srv/inventory/data`), or use a named volume (Docker initialises it with the image\'s ownership). On RHEL add `:z`/`:Z` to the bind mount. Do not "fix" it with chmod 777 or by running the container as root.', verify: 'docker logs shows no permission errors; files appear with the expected owner.' },
    { symptom: 'Image pull fails', causes: ['`toomanyrequests: You have reached your unauthenticated pull rate limit` (Docker Hub)', '`manifest for nginx:1.99 not found: manifest unknown` (tag does not exist, or not for this CPU architecture)', '`pull access denied ... may require \'docker login\'` (private repo, or logged in as a different user than the one running the command, e.g. sudo)', 'Timeouts / DNS errors because the **daemon** has no proxy configuration'], diagnose: ['docker pull <image> (read the exact error)', 'journalctl -u docker --since "10 min ago"', 'systemctl show docker -p Environment', 'docker info --format \'{{.RegistryConfig.Mirrors}} {{.HTTPProxy}}\''], fix: 'Authenticate (`docker login`) or use a registry mirror/pull-through cache; fix the tag; configure the daemon proxy (systemd drop-in or daemon.json "proxies") and restart docker.', verify: 'docker pull <image> completes.' },
    { symptom: 'Disk full: "no space left on device", containers crash, database corrupt', causes: ['Unrotated json-file container logs', 'Accumulated images and build cache', 'A volume growing (database, uploads)'], diagnose: ['df -h /var/lib/docker', 'docker system df -v', 'sudo du -sh /var/lib/docker/containers/*/*-json.log | sort -h | tail'], fix: 'Configure `log-opts` `max-size`/`max-file` (new containers; recreate the noisy one), remove unused images and build cache with `docker image prune -a` / `docker builder prune` after checking what they remove, move data-root or grow the disk. Be careful with `--volumes`.', verify: 'docker system df shows space reclaimed; df below 80%.' },
  ],
  verification: [
    { check: 'Daemon active and enabled', command: 'systemctl is-active docker; systemctl is-enabled docker', expect: 'active\nenabled' },
    { check: 'All services up and healthy', command: 'docker compose ps', expect: 'Every service "Up ... (healthy)", none Restarting' },
    { check: 'Configuration is the intended one', command: 'docker compose config | diff - deployed-compose.yaml', expect: 'No unexpected differences; no empty variables' },
    { check: 'Published only where intended', command: 'docker port inventory-web-1; sudo ss -tlnp | grep docker-proxy', expect: '8000/tcp -> 0.0.0.0:8080 (or 127.0.0.1:8080 behind a reverse proxy)' },
    { check: 'Reachable from a client network', command: 'curl -sS -o /dev/null -w \'%{http_code}\\n\' http://dock01.corp.lab:8080/', expect: '200' },
    { check: 'Logs rotated and disk healthy', command: 'docker inspect --format \'{{json .HostConfig.LogConfig}}\' inventory-web-1; docker system df', expect: '{"Type":"json-file","Config":{"max-file":"3","max-size":"10m"}} and reasonable reclaimable space' },
    { check: 'Survives a daemon restart / reboot', command: 'docker inspect --format \'{{.HostConfig.RestartPolicy.Name}}\' inventory-web-1 inventory-db-1', expect: 'unless-stopped (or always) for every long-running service' },
  ],
  refIds: ['docker', 'docker-compose', 'docker-inspect', 'docker-logs', 'docker-network', 'systemctl', 'journalctl', 'ss', 'curl', 'iptables', 'nft', 'ufw', 'firewall-cmd', 'file:daemon.json', 'file:var-lib-docker', 'file:compose-yaml', 'file:docker-sock', 'file:container-logs', 'proc:docker-recreate', 'proc:docker-daemon-restart', 'proc:compose-change', 'proc:safe-config-change', 'proc:rollback'],
};

// --- Lesson -------------------------------------------------------------------------

export const DOCKER_LESSON: Lesson = {
  id: 'docker',
  moduleId: 'E',
  title: 'Docker and container troubleshooting',
  level: 'intermediate',
  summary: 'How the Docker daemon, containerd, images, volumes, bridge networks and published ports fit together, how to find why a container exits or cannot be reached, and when to restart a container, recreate it, or (rarely) restart the daemon.',
  concepts: ['docker.lifecycle', 'docker.networking', 'net.nat', 'fw.path', 'dns.resolution', 'linux.permissions', 'svc.systemd', 'svc.listening', 'logs.journal', 'ops.recovery'],

  what: `
**Docker** runs applications in **containers**. A container packages an application together with everything it needs to run (libraries, language runtime, configuration), so it runs the same way on any Docker host.

A container is **not** a virtual machine. A VM runs a complete operating system with its own kernel. A container is an ordinary Linux process (plus its child processes) that shares the host's kernel, but the kernel shows it a separate, private view of the system:
- **Namespaces** give the process its own view: its own filesystem (mount table and root directory), its own network stack (interfaces, addresses, ports), its own process IDs, hostname and inter-process communication.
- **cgroups** (control groups) limit how much memory, CPU and how many processes it may use.

Its files come from an **image**: a stack of read-only **layers** containing the application and its userland (libraries, interpreter), with a thin writable layer added for each container. Because nothing else is started, a container starts in a second or two.

### Problems it solves
- **"Works on my machine."** The image carries the exact dependencies, so the same artefact runs in development, test and production.
- **Density and speed.** Dozens of isolated services on one host, started in seconds, without one VM each.
- **Declarative deployment.** \`compose.yaml\` describes services, ports, volumes and networks; deploying a new version means pulling a new image tag and recreating the container.

### The pieces
- **docker** (CLI) → **/var/run/docker.sock** → **dockerd** (the Docker Engine daemon, \`docker.service\`) → **containerd** (\`containerd.service\`) → **containerd-shim-runc-v2** (one per container) → **runc** (creates the namespaces and starts the process).
- **Images and layers** (overlay2 under \`/var/lib/docker\`), pulled from **registries** such as Docker Hub or \`registry.corp.lab\`.
- **Volumes** (managed by Docker, survive container removal) and **bind mounts** (a host directory mapped in).
- **Networks**: the default bridge \`docker0\` (172.17.0.0/16), **user-defined bridges** (with built-in DNS), \`host\`, \`none\`, \`macvlan\`.
- **Docker Compose v2** (\`docker compose\`): a CLI plugin that creates the containers, networks and volumes of a multi-service application from \`compose.yaml\`.

### How it connects to earlier lessons
Container networking reuses what you already know. Each container gets a virtual interface and an IP address on a Linux bridge (a [virtual switch](#/lesson/netif/what)); the host [routes and NATs](#/lesson/nat/what) container traffic to the outside; a "published port" is a DNAT rule from a host port to the container's port; and Docker adds its rules to the host [firewall](#/lesson/nftables/what). Containers are started and supervised by the Docker daemon, which itself is a [systemd service](#/lesson/systemd/what).

### Where you meet it
Internal web applications, CI runners, monitoring stacks (Prometheus/Grafana), reverse proxies, databases for development, vendor appliances shipped as images. As an infrastructure administrator you often do not own the application, but you own the host, its network and firewall, and you are the one asked why "the container is up but nobody can reach it".

> Output in this lesson is representative of **Docker Engine 27.3** and **Docker Compose v2.29** on **Ubuntu 24.04 LTS** (iptables backend, userland proxy enabled), on the lab's container host \`dock01\` (10.0.20.40). Docker Engine 28 changed some firewall chains (it adds a DOCKER-FORWARD chain), but DOCKER-USER and the behaviour described here remain.
>
> The **sandbox and the tickets** use the simulated **dock01**: Debian 12 with Docker Engine 26 and the **nftables** backend (dockerd's rules appear as \`table ip nat\` and \`table ip filter\` in \`nft list ruleset\`, next to your own \`table inet filter\`). Simulated: \`docker run/ps/logs/inspect/exec/start/stop/rm/port/network/pull/info\`, \`docker compose up/down/ps/logs/config\`, published ports (DNAT and docker-proxy), the default bridge and user-defined networks with embedded DNS, restart policies across reboots, \`/etc/docker/daemon.json\` and the docker group. The images are nginx:1.25, postgres:16 and the team's corp/inventory:1.4. Not simulated: building images, healthchecks, resource limits, volumes' contents, ufw and Podman.
`,

  internals: `
### 1. From \`docker run\` to a process
\`docker run -d --name web -p 8080:8000 registry.corp.lab/inventory-web:1.4.2\`:
1. The CLI sends API calls over \`/var/run/docker.sock\`. If the image is missing, dockerd **pulls** it: resolves the registry name, authenticates, downloads the manifest for the host's CPU architecture, then each layer.
2. dockerd **creates** the container (state \`created\`): config, writable layer, network endpoint, mounts, \`/etc/hosts\`, \`/etc/resolv.conf\`.
3. dockerd asks **containerd** to start it; containerd starts a **shim**, which runs **runc**: new namespaces, cgroup limits, pivot into the image's root filesystem, exec the **ENTRYPOINT/CMD** as PID 1. runc exits; the shim remains the parent (state \`running\`).
4. For \`-p\`, dockerd installs NAT rules and starts \`docker-proxy\`.

### 2. Lifecycle and exit codes
States: **created → running → (paused) → exited**, plus **restarting** (restart policy waiting to start it again) and **dead** (removal failed). **A container lives exactly as long as its main process.** If PID 1 exits, the container is \`Exited (code)\`. The code tells you who ended it:
- **0**: the process finished normally (a shell with no input, a one-shot script). Not a crash, but no service either.
- **1** (or other small numbers): the application reported an error. Read \`docker logs\`.
- **125**: Docker itself failed to create/start the container (bad option, port already allocated).
- **126**: the command exists but cannot be executed (permissions, wrong format).
- **127**: the command was not found (\`exec: "gunicorn": executable file not found in $PATH\`).
- **137** = 128 + 9 (**SIGKILL**): the kernel **OOM killer** (\`docker inspect\` shows \`"OOMKilled": true\`) or \`docker kill\`, or \`docker stop\` after the 10-second grace period.
- **139** = 128 + 11 (SIGSEGV): the program crashed.
- **143** = 128 + 15 (SIGTERM): stopped by \`docker stop\` and the process died from the signal.

**Restart policies**: \`no\` (default), \`on-failure[:N]\` (non-zero exit, at most N times), \`always\` (also after daemon restart), \`unless-stopped\` (like always, but not if you stopped it manually). Restarts use an increasing delay (doubling from 100 ms, capped at one minute), so a failing container shows \`Restarting (1) 14 seconds ago\`: a **restart loop**. The policy hides crashes; it does not fix them.

### 3. Images, layers and storage
An image is an ordered list of read-only layers (one per Dockerfile instruction that changes files). overlay2 mounts them as **lowerdirs** with the container's **upperdir** on top. Writing to a file copies it up into the writable layer, which is **deleted when the container is removed or recreated**. Anything that must survive goes into a **volume** or bind mount.
- **Named volume** (\`dbdata:/var/lib/postgresql/data\`): stored in \`/var/lib/docker/volumes/<name>/_data\`; when empty, Docker copies the image's content and ownership into it at first use. Survives \`docker compose down\` (but not \`down -v\`).
- **Bind mount** (\`/srv/inventory/uploads:/app/uploads\`): the host directory as is, with host ownership. The container process's UID (e.g. 999 for postgres, 1000 for many apps, 0 by default) must be allowed to write it: UIDs are **numbers**, shared between host and container unless user-namespace remapping or rootless mode is used.
- **SELinux** (RHEL/Fedora, enforcing): container processes run as \`container_t\` and may only access files labelled \`container_file_t\`. Mount with \`:z\` (relabel, shareable) or \`:Z\` (relabel, private to this container); never on \`/home\`, \`/etc\` or \`/var\`.
- **Read-only**: \`:ro\` on a mount, or \`--read-only\` for the whole root filesystem.

### 4. Networking
- **Default bridge** (\`docker0\`, 172.17.0.0/16): what \`docker run\` uses without \`--network\`. Containers get an IP and outbound NAT, but **no name resolution between containers**; \`/etc/resolv.conf\` is a filtered copy of the host's.
- **User-defined bridge** (\`docker network create\`, and every Compose project's \`<project>_default\`): Linux bridge \`br-<id>\`, its own subnet (172.18.0.0/16, ...), and an **embedded DNS server at 127.0.0.11** that resolves container and service names (\`db\`) and forwards other queries to the host's upstream servers.
- **host**: no network namespace; the app binds directly on the host's interfaces (no \`-p\` needed or possible). **none**: loopback only. **macvlan**: the container gets its own MAC/IP on the physical LAN (the host itself cannot talk to it over that interface by default).
- Each container is attached by a **veth pair**: one end is \`eth0\` inside the container, the other (\`vethXXXX\`) is a port of the bridge on the host (\`ip -br link\`, \`bridge link\`).
- Docker enables \`net.ipv4.ip_forward\` and sets the iptables FORWARD policy to **DROP**, which affects a host that also routes other traffic.
- Address conflicts: if 172.17.0.0/16 or Docker's pools (172.17–172.31, 192.168.x) overlap a real corporate or VPN network, the host routes those destinations into a bridge. Set \`bip\` and \`default-address-pools\` in daemon.json.

### 5. Port publishing and the firewall
\`-p 8080:8000\` (\`ports: ["8080:8000"]\`, host:container) creates:
- a **DNAT** rule in the nat table's **DOCKER** chain (reached from PREROUTING and OUTPUT): \`tcp dpt:8080 to:172.18.0.3:8000\`;
- accept rules in the filter table's FORWARD path, after the **DOCKER-USER** chain, which Docker creates empty for **your** rules;
- a **docker-proxy** process listening on 0.0.0.0:8080 and [::]:8080 (for connections from the host itself and hairpin traffic).

Because DNATed traffic is **forwarded**, not delivered to the host, it never passes the INPUT chain where **ufw** and many hand-written rules live: **published ports bypass ufw** (and firewalld's zone rules). To restrict: publish to a specific address (\`127.0.0.1:8080:8000\` for a local reverse proxy, \`10.0.20.40:8080:8000\` for one interface), or add rules in DOCKER-USER (matching the original port with \`-m conntrack --ctorigdstport 8080\`, because by then the destination port is already 8000).

The application must listen on **0.0.0.0 inside the container**. If it listens on 127.0.0.1, it works with \`docker exec ... curl localhost\` and its HEALTHCHECK passes, but published traffic arriving on the container's eth0 is refused.

### 6. DNS inside containers
- Default bridge: Docker copies the host's \`/etc/resolv.conf\`, removing loopback nameservers (they are not reachable from the container's namespace). On Ubuntu with **systemd-resolved** (\`nameserver 127.0.0.53\`), Docker reads the real upstream servers from \`/run/systemd/resolve/resolv.conf\` instead. If no usable server remains, Docker falls back to **8.8.8.8 and 8.8.4.4**, which cannot resolve internal names such as \`registry.corp.lab\` and may be blocked by the corporate firewall.
- User-defined networks: \`nameserver 127.0.0.11\`; the embedded server answers container names and forwards the rest to the upstream servers determined the same way.
- Fix: \`"dns": ["10.0.10.53"]\` in daemon.json (restart docker, recreate containers) or \`dns:\` per service.

### 7. Resource limits
\`--memory 512m\` / \`mem_limit\` sets the cgroup memory limit; exceeding it triggers the kernel OOM killer inside that cgroup: exit 137, \`OOMKilled: true\`, and a kernel log line (\`journalctl -k | grep -i oom\`). \`--cpus 1.5\` throttles CPU (slow, not killed). Without limits, one container can exhaust the whole host's memory and the host OOM killer picks a victim, possibly dockerd or a database.

### 8. Logs
With the default **json-file** driver, stdout/stderr go to \`/var/lib/docker/containers/<id>/<id>-json.log\` and \`docker logs\` reads them back (\`--tail\`, \`--since\`, \`-f\`, \`-t\`). There is **no rotation by default**: set \`"log-opts": {"max-size": "10m", "max-file": "3"}\` in daemon.json (applies to new containers) or use the \`local\` driver. The logs are deleted with the container, so recreate destroys them. Applications that log to files inside the container instead of stdout are invisible to \`docker logs\`.

`,

  deployment: [
    {
      id: 'ubuntu',
      platform: 'Ubuntu 24.04 / Debian 12 (Docker CE from the official repository)',
      summary: 'Install Docker Engine and the Compose plugin from download.docker.com (the distribution\'s `docker.io` package is older and packaged differently). On Debian replace `ubuntu` with `debian` in the URLs. Run on a real VM.',
      prerequisites: ['Ubuntu 22.04/24.04 or Debian 12, 64-bit, with sudo and outbound HTTPS (or a proxy).', 'Console access in case firewall changes lock you out.', 'At least 20 GB free for /var/lib/docker on a server.'],
      steps: [
        { title: 'Remove conflicting distribution packages', command: 'for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove -y $pkg; done', what: 'Removes unofficial/older packages that conflict with docker-ce and containerd.io.', why: 'Mixing distribution and upstream packages leads to version conflicts and two different containerd installations.', expected: 'Package \'docker.io\' is not installed, so not removed\n...' },
        { title: 'Add Docker\'s apt repository', command: 'sudo apt-get update && sudo apt-get install -y ca-certificates curl\nsudo install -m 0755 -d /etc/apt/keyrings\nsudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc\nsudo chmod a+r /etc/apt/keyrings/docker.asc\necho "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null', what: 'Installs Docker\'s signing key and the repository for this release (noble on 24.04).', why: 'The `signed-by` option ties the key to this repository only.', expected: '(no output)' },
        { title: 'Install Engine, CLI, containerd, Buildx and Compose', command: 'sudo apt-get update\nsudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin', what: 'Installs the daemon, CLI, containerd and the `docker compose` plugin. On Debian/Ubuntu the service is enabled and started automatically.', why: 'Compose v2 is a CLI plugin (`docker compose`, with a space); the old Python `docker-compose` v1 is end-of-life.', expected: 'Setting up docker-ce (5:27.3.1-1~ubuntu.24.04~noble) ...\nCreated symlink /etc/systemd/system/multi-user.target.wants/docker.service → /usr/lib/systemd/system/docker.service.' },
        { title: 'Configure the daemon before running workloads', command: 'sudo tee /etc/docker/daemon.json <<\'EOF\'\n{\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "10m", "max-file": "3" },\n  "dns": ["10.0.10.53"],\n  "default-address-pools": [ { "base": "172.30.0.0/16", "size": 24 } ],\n  "live-restore": true\n}\nEOF\nsudo dockerd --validate --config-file /etc/docker/daemon.json && sudo systemctl restart docker', what: 'Log rotation, internal DNS for containers, address pools that do not overlap the corporate network, and containers that survive daemon restarts.', why: 'These defaults only apply to containers created afterwards, so set them before deploying anything. Validating first prevents a daemon that will not start.', expected: 'configuration OK' },
        { title: 'Verify', command: 'sudo docker run --rm hello-world\ndocker compose version\nsystemctl status docker --no-pager', what: 'Pulls and runs a test image; prints the Compose version.', why: 'Proves registry access, the runtime chain and the plugin.', expected: 'Hello from Docker!\nThis message shows that your installation appears to be working correctly.\n...\nDocker Compose version v2.29.7' },
        { title: 'Decide who may use Docker', command: 'sudo usermod -aG docker alice\n# alice must log out and in again', what: 'Lets alice use the socket without sudo.', why: '**The docker group is root-equivalent**: `docker run -v /:/host` gives full control of the host. Grant it only to people who would get sudo anyway; consider rootless Docker for others.', expected: '(no output)' },
        { title: 'Remember the firewall interaction', command: 'sudo ufw status verbose\nsudo iptables -L DOCKER-USER -n', what: 'Shows ufw rules and the (initially empty) DOCKER-USER chain.', why: 'Published ports bypass ufw. Publish to 127.0.0.1 behind a reverse proxy, or filter in DOCKER-USER.', expected: 'Chain DOCKER-USER (1 references)\ntarget     prot opt source               destination\nRETURN     all  --  0.0.0.0/0            0.0.0.0/0' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky 9 / Alma 9 (Docker CE or Podman)',
      summary: 'RHEL ships **Podman** (daemonless, rootless-capable, `podman` commands largely compatible with `docker`) as its supported container engine; Docker CE is available from Docker\'s own repository and is supported by Docker, not Red Hat. The networking, SELinux and firewalld notes apply to both.',
      prerequisites: ['RHEL-compatible 9.x with sudo and access to download.docker.com (or the RHEL AppStream repos for Podman).', 'SELinux enforcing (leave it on).'],
      steps: [
        { title: 'Option A: Podman (default on RHEL)', command: 'sudo dnf install -y podman podman-docker\npodman run --rm registry.access.redhat.com/ubi9/ubi-minimal echo ok', what: 'Installs Podman and a `docker` command shim.', why: 'No daemon to restart, rootless by default for normal users, systemd integration through Quadlet (`/etc/containers/systemd/*.container`).', expected: 'ok' },
        { title: 'Option B: Docker CE repository', command: 'sudo dnf remove -y podman buildah runc\nsudo dnf -y install dnf-plugins-core\nsudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo\nsudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin', what: 'Removes conflicting packages and installs Docker CE.', why: 'Podman/runc packages conflict with containerd.io.', expected: 'Complete!' },
        { title: 'Enable and start (not automatic on RHEL)', command: 'sudo systemctl enable --now docker\nsystemctl is-active docker', what: 'Enables the service at boot and starts it now.', why: 'Unlike Debian/Ubuntu, the RPM does not start the daemon.', expected: 'Created symlink /etc/systemd/system/multi-user.target.wants/docker.service → /usr/lib/systemd/system/docker.service.\nactive' },
        { title: 'SELinux labels for bind mounts', command: 'docker run -d --name web -v /srv/web/html:/usr/share/nginx/html:ro,z -p 8080:80 nginx:1.27', what: '`z` relabels the host directory `container_file_t` so containers may read it.', why: 'Without it nginx logs `open() "/usr/share/nginx/html/index.html" failed (13: Permission denied)` even though the UNIX permissions are fine.', expected: '(container ID)' },
        { title: 'firewalld', command: 'sudo firewall-cmd --get-active-zones\nsudo firewall-cmd --zone=docker --list-all', what: 'Docker places its bridge interfaces in the `docker` zone.', why: 'Published ports are reachable regardless of the public zone\'s services. Restrict with a specific host IP in the port mapping or DOCKER-USER rules.', expected: 'docker\n  interfaces: docker0 br-3f1e2a9c7b10\npublic\n  interfaces: ens192' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows 10/11 (Docker Desktop) and Windows Server 2019/2022',
      summary: '**Windows 10/11**: Docker Desktop runs the Linux engine in a WSL2 VM; Linux containers behave as described in this lesson, but published ports are forwarded from Windows (localhost) into the VM, and host paths are crossed through WSL file sharing (slow and permission-translated). Docker Desktop requires a paid subscription for larger organisations (more than 250 employees or USD 10 million revenue). **Windows Server**: Docker Desktop is not supported; Windows Server runs **Windows containers** (process or Hyper-V isolation) with Mirantis Container Runtime, Docker CE static binaries, or containerd + nerdctl. Linux containers on Windows Server are not a supported production setup, and Windows container images must match the host OS build for process isolation.',
      prerequisites: ['Windows 10 22H2 / Windows 11 with virtualisation enabled in firmware, WSL2 installed (`wsl --install`).', 'Windows Server 2019/2022 with the Containers feature for Windows containers.'],
      steps: [
        { title: 'Install Docker Desktop (Windows 10/11)', command: 'winget install -e --id Docker.DockerDesktop', what: 'Installs Docker Desktop with the WSL2 backend.', why: 'The supported way to run Linux containers on a Windows client.', expected: 'Successfully installed' },
        { title: 'Verify the engine', command: 'docker version\nwsl -l -v', what: 'The Server section reports Docker Desktop; WSL lists the docker-desktop distribution.', why: 'If `docker version` shows only a Client section, the engine VM is not running.', expected: 'Server: Docker Desktop 4.34.3 (170107)\n Engine:\n  Version:          27.2.0\n...\n  NAME              STATE           VERSION\n* Ubuntu            Running         2\n  docker-desktop    Running         2' },
        { title: 'Windows Server: Containers feature', command: 'Install-WindowsFeature -Name Containers\nRestart-Computer', what: 'Enables the Windows container platform before installing a runtime (Mirantis Container Runtime, Docker CE binaries, or containerd).', why: 'Windows containers use the host\'s Windows kernel: images such as `mcr.microsoft.com/windows/servercore:ltsc2022` must match the host version for process isolation.', expected: 'Success Restart Needed Exit Code      Feature Result\n------- -------------- ---------      --------------\nTrue    Yes            SuccessRest... {Containers}' },
      ],
    },
    {
      id: 'compose',
      platform: 'Docker Compose v2: web + database with healthchecks',
      summary: 'A two-service project (`/srv/inventory/compose.yaml` and `.env`). The web container waits for a **healthy** database, publishes one port, and keeps data in a named volume.',
      prerequisites: ['Docker Engine with the compose plugin (`docker compose version`).', 'A project directory owned by the deploying admin; `.env` mode 0600.'],
      steps: [
        { title: 'Write compose.yaml', command: COMPOSE_EXAMPLE, what: 'Defines the services, the published port (8080 → 8000), environment, healthchecks, startup order, restart policy, memory limit and a named volume.', why: '`depends_on: condition: service_healthy` delays web until pg_isready succeeds; plain `depends_on` only waits for the container to **start**. `${DB_PASSWORD:?...}` makes Compose refuse to deploy without the variable instead of silently using an empty password.', expected: '' },
        { title: 'Write .env', command: 'cat > .env <<\'EOF\'\nCOMPOSE_PROJECT_NAME=inventory\nDB_PASSWORD=change-me-to-a-long-random-value\nEOF\nchmod 600 .env', what: 'Variables used for interpolation in compose.yaml, and the project name.', why: '.env is read from the project directory when you run `docker compose`; it is not copied into containers automatically.', expected: '' },
        { title: 'Check the effective configuration', command: 'docker compose config', what: 'Prints the merged, interpolated configuration.', why: 'Catches YAML errors, missing variables and wrong ports before anything is deployed.', expected: 'name: inventory\nservices:\n  db:\n    environment:\n      POSTGRES_DB: inventory\n      POSTGRES_PASSWORD: change-me-to-a-long-random-value\n...' },
        { title: 'Deploy', command: 'docker compose up -d\ndocker compose ps', what: 'Creates the network `inventory_default`, the volume `inventory_dbdata` and both containers, in dependency order.', why: '`-d` runs in the background; containers keep running after you log out and come back at boot through their restart policy.', expected: '[+] Running 4/4\n ✔ Network inventory_default    Created    0.1s\n ✔ Volume "inventory_dbdata"    Created    0.0s\n ✔ Container inventory-db-1     Healthy    6.3s\n ✔ Container inventory-web-1    Started    6.5s\nNAME              IMAGE                                   COMMAND                  SERVICE   CREATED          STATUS                    PORTS\ninventory-db-1    postgres:16                             "docker-entrypoint.s…"   db        10 seconds ago   Up 9 seconds (healthy)    5432/tcp\ninventory-web-1   registry.corp.lab/inventory-web:1.4.2   "gunicorn -b 0.0.0.0…"   web       10 seconds ago   Up 3 seconds (health: starting)   0.0.0.0:8080->8000/tcp, [::]:8080->8000/tcp' },
        { title: 'Change something safely', command: 'cp compose.yaml compose.yaml.bak\n# edit compose.yaml (e.g. new image tag)\ndocker compose config >/dev/null && docker compose up -d\ndocker compose ps', what: 'Recreates only the services whose configuration changed.', why: '`docker compose restart` would not apply the change. Keep the old file (or use git) so rollback is `cp compose.yaml.bak compose.yaml && docker compose up -d`.', expected: '[+] Running 2/2\n ✔ Container inventory-db-1   Healthy    0.6s\n ✔ Container inventory-web-1  Started    1.4s' },
      ],
    },
    {
      id: 'pfsense',
      platform: 'pfSense',
      summary: 'Not applicable: pfSense (FreeBSD-based) does not run Docker containers. It is relevant as the network in front of the Docker host: firewall rules and port forwards to the host\'s **published** ports, and DNS (DNS Resolver host overrides) for names like `registry.corp.lab` that containers and the daemon must resolve.',
      prerequisites: [],
      steps: [],
    },
  ],

  configIntro: `
Docker configuration lives at three levels, and each level takes effect at a different moment:
- **Daemon** (\`/etc/docker/daemon.json\`, systemd drop-ins): read when dockerd starts; a few keys on reload. Defaults such as log rotation and DNS apply only to containers **created** afterwards.
- **Container / service** (\`docker run\` options or \`compose.yaml\` + \`.env\`): fixed when the container is **created**. Changing compose.yaml does nothing until \`docker compose up -d\` recreates the container.
- **Image** (Dockerfile: ENTRYPOINT, CMD, USER, EXPOSE, HEALTHCHECK): defaults that compose.yaml can override. \`EXPOSE\` is documentation only; it does not publish anything.

Always check what is really in effect: \`docker compose config\` for the project, \`docker inspect\` for a running container, \`docker info\` for the daemon.
`,

  configFiles: [
    {
      platform: 'Linux (Ubuntu/Debian, RHEL)',
      items: [
        { path: '/etc/docker/daemon.json', purpose: 'Daemon options: logging, DNS, address pools, live-restore, mirrors, proxies, data-root.' },
        { path: '/etc/systemd/system/docker.service.d/*.conf', purpose: 'Unit overrides, e.g. HTTP(S)_PROXY for pulls.' },
        { path: '/usr/lib/systemd/system/docker.service, docker.socket', purpose: 'Vendor units (do not edit).' },
        { path: '/var/lib/docker/', purpose: 'Images (overlay2), containers, volumes, networks, build cache.' },
        { path: '/var/lib/docker/containers/<id>/<id>-json.log', purpose: 'Container stdout/stderr (json-file driver).' },
        { path: '/var/run/docker.sock', purpose: 'API socket (root:docker 0660).' },
        { path: '/etc/containerd/config.toml', purpose: 'containerd configuration (rarely changed for Docker).' },
        { path: '~/.docker/config.json', purpose: 'Registry credentials and CLI settings per user.' },
      ],
    },
    {
      platform: 'Compose project',
      items: [
        { path: 'compose.yaml (or docker-compose.yml)', purpose: 'Services, ports, volumes, networks, healthchecks.' },
        { path: 'compose.override.yaml', purpose: 'Merged automatically if present: a common source of "where does this setting come from?".' },
        { path: '.env', purpose: 'Interpolation variables and COMPOSE_PROJECT_NAME.' },
      ],
    },
    {
      platform: 'Windows',
      items: [
        { path: '%USERPROFILE%\\.docker\\config.json', purpose: 'CLI and credentials (Docker Desktop).' },
        { path: 'Docker Desktop Settings > Docker Engine', purpose: 'Edits the engine\'s daemon.json inside the VM.' },
        { path: 'C:\\ProgramData\\docker\\config\\daemon.json', purpose: 'Daemon configuration on Windows Server container hosts.' },
      ],
    },
  ],

  directives: [
    { name: 'log-driver / log-opts (daemon.json, logging: in compose)', compiledDefault: 'json-file, no rotation', recommended: 'json-file with max-size 10m, max-file 3 (or the local driver)', explanation: 'Where container stdout/stderr go and how big the files may grow.', security: 'Unbounded logs fill /var/lib/docker and take every container on the host down. Logs may contain secrets: restrict access to the host.' },
    { name: 'live-restore', compiledDefault: 'false', recommended: 'true on single hosts (not with Swarm)', explanation: 'Keeps containers running while dockerd is stopped or restarted (e.g. during an engine upgrade).', security: 'Reduces outages from daemon maintenance; networking changes still require container recreation.' },
    { name: 'dns', compiledDefault: 'From the host resolv.conf (fallback 8.8.8.8, 8.8.4.4)', recommended: 'Internal DNS servers', explanation: 'DNS servers written into containers (or used upstream by the embedded DNS).', security: 'The public fallback leaks internal query names and fails for internal zones.' },
    { name: 'bip / default-address-pools', compiledDefault: 'docker0 172.17.0.1/16; pools 172.17–172.31.0.0/16 and 192.168.0.0/16 (/20 subnets)', recommended: 'A dedicated, unused range', explanation: 'Subnets used for docker0 and new networks.', security: 'Overlap with real networks makes those destinations unreachable from the host (traffic goes into a bridge).' },
    { name: 'ports (HOST:CONTAINER)', compiledDefault: 'none published', recommended: 'Publish only what clients need; bind to 127.0.0.1 behind a reverse proxy', explanation: '`"8080:8000"` = host 8080 on all addresses → container 8000. `"127.0.0.1:8080:8000"` restricts to the host. `expose:` publishes nothing.', security: 'Published ports bypass ufw/firewalld rules; filter with DOCKER-USER or a specific host IP.' },
    { name: 'restart', compiledDefault: 'no', recommended: 'unless-stopped for services; on-failure:N for jobs', explanation: 'Whether Docker restarts the container after exit or daemon restart.', security: 'always/unless-stopped hide crash loops; monitor RestartCount.' },
    { name: 'healthcheck', compiledDefault: 'From the image (HEALTHCHECK), often none', recommended: 'A real check of the service (HTTP endpoint, pg_isready)', explanation: 'Runs a command **inside** the container at intervals; status starting/healthy/unhealthy. Docker itself does not restart unhealthy containers.', security: 'A check against localhost does not prove the published port or external path works.' },
    { name: 'depends_on: condition', compiledDefault: 'service_started', recommended: 'service_healthy for databases', explanation: 'Start order in Compose. service_healthy waits for the dependency\'s healthcheck.', security: 'Applications should still retry connections; depends_on only applies at `up` time.' },
    { name: 'mem_limit / --memory, cpus / --cpus', compiledDefault: 'unlimited', recommended: 'Limits sized from docker stats', explanation: 'cgroup limits. Exceeding memory → OOM kill (exit 137).', security: 'Without limits one container can exhaust the host.' },
    { name: 'user / USER', compiledDefault: 'root (UID 0) unless the image sets USER', recommended: 'A non-root UID matching volume ownership', explanation: 'The UID the main process runs as; determines access to bind mounts.', security: 'Root in a container is root on the host if it escapes or if dangerous mounts/capabilities are given.' },
    { name: 'volumes / bind mount options :ro, :z, :Z', compiledDefault: 'read-write, no relabel', recommended: ':ro where possible; :z on SELinux hosts for shared content', explanation: 'Mount mode and SELinux relabelling.', security: ':Z on a system directory relabels it for one container and breaks the host.' },
  ],

  operateIntro: `
### Before you restart or recreate
- Before recreating a broken container, save its evidence: \`docker logs web > web-$(date +%F-%H%M).log\` and \`docker inspect web > web-inspect.json\`.
- Never "clean up" with \`docker system prune -a --volumes\` or \`docker compose down -v\` on a server without knowing which volumes hold data.

`,
  troubleshootingIntro: `
### Work layer by layer, and stop at the first check that fails
"The container is broken" can mean many things. The checks below go from the Docker daemon itself, through the container and the program inside it, out to the network path and the host's resources. Each layer depends on the ones before it.

1. **The daemon.** \`systemctl status docker\` and \`journalctl -u docker\` show whether dockerd runs and why it may have failed. If \`docker ps\` does not work at all, nothing else can be checked.
2. **The container's state.** \`docker ps -a\` lists containers, including stopped ones. \`docker inspect\` shows the details: Status, ExitCode, OOMKilled (killed for using too much memory), RestartCount and Health.
3. **What the program said.** \`docker logs --tail 50\` shows the program's own output. The first error after it started is usually the cause.
4. **The configuration.** \`docker compose config\` prints the fully resolved compose file, and \`docker inspect\` shows what is actually running (Env, Cmd, PortBindings, Mounts). Compare what you think you deployed with what really runs.
5. **Inside the container.** \`docker exec <c> ss -tlnp\` (is the program listening, and on which address?), \`curl localhost:<port>\`, \`getent hosts db\` (can it resolve its dependencies?), \`cat /etc/resolv.conf\`, \`id\` (which user does it run as?).
6. **The path from the host.** \`docker port\` and \`ss -tlnp\` show the published ports; \`iptables -t nat -L DOCKER -n\` and \`iptables -L DOCKER-USER -n -v\` show Docker's NAT and filter rules. Then test with curl from the host and from another machine.
7. **Resources.** \`docker stats\` (CPU and memory), \`docker system df\` and \`df -h\` (disk), \`journalctl -k | grep -i oom\` (the kernel killing processes for lack of memory). \`docker events\` gives a timeline of die, oom and health_status events.

### Workaround versus fix
Some changes make the symptom disappear but create a security problem: running the container with \`--network host\`, as root, with \`chmod 777\` on a volume, with \`--privileged\`, or switching off the host firewall. The real fix is the specific setting that was wrong: the listen address, the port mapping, the network, the user ID or SELinux label, or the missing environment variable.

`,

  errorMap: [
    { message: 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?', layer: 'Daemon', meaning: 'dockerd is not running (or DOCKER_HOST points elsewhere).', firstCheck: 'systemctl status docker; journalctl -u docker -b' },
    { message: 'permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock', layer: 'Authorisation', meaning: 'Your user cannot write the socket (not in the docker group, or group not yet active in this session).', firstCheck: 'id; ls -l /var/run/docker.sock' },
    { message: 'unable to configure the Docker daemon with file /etc/docker/daemon.json: ...', layer: 'Daemon configuration', meaning: 'Invalid JSON or a conflicting/unknown option; dockerd does not start.', firstCheck: 'sudo dockerd --validate --config-file /etc/docker/daemon.json' },
    { message: 'Exited (137) ... / "OOMKilled": true', layer: 'Resources', meaning: 'Killed by SIGKILL; with OOMKilled true, the memory limit was exceeded.', firstCheck: 'docker inspect --format \'{{.State.OOMKilled}}\'; docker stats; journalctl -k | grep -i oom' },
    { message: 'exec: "gunicorn": executable file not found in $PATH (exit 127)', layer: 'Image / command', meaning: 'The CMD/ENTRYPOINT names a program that does not exist in the image.', firstCheck: 'docker inspect --format \'{{json .Config.Cmd}}\'; check the image tag' },
    { message: 'Bind for 0.0.0.0:8080 failed: port is already allocated', layer: 'Port publishing', meaning: 'Another container or host process already uses host port 8080.', firstCheck: 'sudo ss -tlnp | grep :8080; docker ps --filter publish=8080' },
    { message: 'curl: (52) Empty reply from server / (56) Recv failure: Connection reset by peer (from the Docker host)', layer: 'Container listener', meaning: 'docker-proxy accepted the connection but could not connect to the container port: app not listening on that port or only on 127.0.0.1.', firstCheck: 'docker exec <c> ss -tlnp; docker port <c>' },
    { message: 'Temporary failure in name resolution / getaddrinfo EAI_AGAIN (inside a container)', layer: 'Container DNS', meaning: 'No usable DNS server from the container (fallback to blocked public DNS, or wrong upstream).', firstCheck: 'docker exec <c> cat /etc/resolv.conf; daemon.json "dns"' },
    { message: 'could not translate host name "db" to address: Name or service not known', layer: 'Container networking', meaning: 'The containers are not on the same user-defined network (or on the default bridge).', firstCheck: 'docker network inspect <net>; docker inspect --format \'{{json .NetworkSettings.Networks}}\' <c>' },
    { message: 'mkdir: cannot create directory ...: Permission denied / (13: Permission denied) on a mounted path', layer: 'Volumes / permissions', meaning: 'Container UID cannot write the host directory, or SELinux label missing (RHEL).', firstCheck: 'docker exec <c> id; ls -ln <host dir>; ausearch -m avc -ts recent' },
    { message: 'The "DB_PASSWORD" variable is not set. Defaulting to a blank string.', layer: 'Compose configuration', meaning: 'A variable used in compose.yaml is missing from .env/the environment.', firstCheck: 'docker compose config; cat .env (in the project directory)' },
    { message: 'toomanyrequests: You have reached your unauthenticated pull rate limit.', layer: 'Registry', meaning: 'Docker Hub pull rate limit for anonymous/free users reached.', firstCheck: 'docker login; use a mirror or internal registry' },
    { message: 'manifest for nginx:1.99 not found: manifest unknown: manifest unknown', layer: 'Registry', meaning: 'The tag does not exist (typo) or not for this architecture.', firstCheck: 'docker manifest inspect nginx:1.99; check tags in the registry' },
    { message: 'no space left on device', layer: 'Storage', meaning: '/var/lib/docker (or a volume\'s filesystem) is full.', firstCheck: 'df -h /var/lib/docker; docker system df' },
  ],

  scenarioIds: ['docker-port-localhost', 'docker-renamed-service', 'docker-forward-drop', 'docker-port-taken', 'docker-no-restart', 'docker-daemon-json'],
  assessmentId: 'docker',
  references: [
    { title: 'Docker Docs: Docker Engine overview', url: 'https://docs.docker.com/engine/' },
    { title: 'Docker Docs: Install Docker Engine on Ubuntu', url: 'https://docs.docker.com/engine/install/ubuntu/' },
    { title: 'Docker Docs: Install Docker Engine on RHEL', url: 'https://docs.docker.com/engine/install/rhel/' },
    { title: 'Docker Docs: Networking overview and bridge network driver', url: 'https://docs.docker.com/engine/network/' },
    { title: 'Docker Docs: Packet filtering and firewalls (DOCKER-USER, ufw)', url: 'https://docs.docker.com/engine/network/packet-filtering-firewalls/' },
    { title: 'Docker Docs: Start containers automatically (restart policies)', url: 'https://docs.docker.com/engine/containers/start-containers-automatically/' },
    { title: 'Docker Docs: Configure logging drivers / JSON File logging driver', url: 'https://docs.docker.com/engine/logging/drivers/json-file/' },
    { title: 'Docker Docs: Live restore', url: 'https://docs.docker.com/engine/daemon/live-restore/' },
    { title: 'Docker Docs: Compose file reference', url: 'https://docs.docker.com/reference/compose-file/' },
    { title: 'Docker Docs: Docker Hub usage and rate limits', url: 'https://docs.docker.com/docker-hub/usage/' },
    { title: 'Red Hat: Building, running, and managing containers (Podman) on RHEL 9', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/index' },
    { title: 'Microsoft Learn: Windows containers documentation', url: 'https://learn.microsoft.com/virtualization/windowscontainers/' },
  ],
  guide: DOCKER_GUIDE,
  caseStudyIds: ['docker-unreachable'],
  objectives: ['200-301:1.12', 'N10-009:5.3', 'N10-009:5.5'],
};

// --- Assessment -------------------------------------------------------------------------

export const DOCKER_ASSESSMENT: Assessment = {
  id: 'docker',
  title: 'Docker and container troubleshooting knowledge check',
  questions: [
    {
      id: 'docker-q-chain',
      kind: 'order',
      level: 'beginner',
      prompt: 'Order the components a `docker run` request passes through, from the command you type to the container\'s process.',
      items: ['docker CLI', '/var/run/docker.sock', 'dockerd', 'containerd', 'containerd-shim-runc-v2', 'runc', 'container main process (PID 1)'],
      concepts: ['docker.lifecycle'],
      explanation: 'The CLI is an API client of dockerd over the Unix socket; dockerd delegates execution to containerd, which starts one shim per container; the shim runs runc to create namespaces/cgroups and exec the main process, then remains its parent.',
    },
    {
      id: 'docker-q-137',
      kind: 'single',
      level: 'intermediate',
      prompt: 'The worker container keeps restarting. What is the most likely cause?',
      exhibit: '$ docker inspect --format \'{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}\' worker\nrestarting exit=137 oom=true restarts=14\n$ docker inspect --format \'{{.HostConfig.Memory}}\' worker\n268435456',
      options: [
        { text: 'The process exceeds its 256 MiB memory limit and is killed by the OOM killer', correct: true },
        { text: 'The command is not found in the image', misconception: 'That is exit code 127 and the container would never run long enough to use memory.' },
        { text: 'An administrator keeps running docker stop', misconception: 'docker stop can produce 137 after the grace period, but OOMKilled would be false.' },
        { text: 'The Docker daemon is restarting', misconception: 'A daemon restart affects all containers and does not set OOMKilled on one of them.' },
      ],
      concepts: ['docker.lifecycle'],
      explanation: '137 = 128 + 9 (SIGKILL). OOMKilled true confirms the cgroup memory limit (268435456 bytes = 256 MiB) was exceeded. Raise the limit if justified, or fix the memory use; the restart policy only turns it into a loop.',
    },
    {
      id: 'docker-q-exit-codes',
      kind: 'text',
      level: 'beginner',
      prompt: 'A container exits immediately with `exec: "gunicorn": executable file not found in $PATH`. Which exit code does `docker ps -a` show?',
      accept: ['127'],
      placeholder: 'number',
      concepts: ['docker.lifecycle'],
      explanation: '127 means "command not found" (126: found but not executable; 125: Docker could not create or start the container).',
    },
    {
      id: 'docker-q-restart-vs-recreate',
      kind: 'single',
      level: 'intermediate',
      prompt: 'You added a missing `API_KEY` to `.env` and referenced it in compose.yaml, then ran `docker compose restart web`. The app still says `API_KEY is not set`. Why?',
      options: [
        { text: 'restart reuses the existing container with its original environment; `docker compose up -d` is needed to recreate it with the new configuration', correct: true },
        { text: '.env files are only read at boot', misconception: '.env is read every time a docker compose command runs, but only operations that create containers apply it.' },
        { text: 'The daemon must be restarted to read .env', misconception: 'The daemon never reads .env; Compose (the client) interpolates it. Restarting the daemon would stop every container on the host for nothing.' },
        { text: 'Environment variables cannot be changed after the image is built', misconception: 'Environment is container configuration, not image content; recreating the container applies new values.' },
      ],
      concepts: ['docker.lifecycle', 'ops.recovery'],
      explanation: 'A container\'s environment, ports, mounts and command are fixed at creation. `docker compose up -d` detects the changed configuration and recreates only the affected service; named volumes are kept.',
    },
    {
      id: 'docker-q-localhost-bind',
      kind: 'single',
      level: 'advanced',
      prompt: 'The container is Up (healthy) but clients cannot reach the app. What is wrong?',
      exhibit: '$ docker port inventory-web-1\n8000/tcp -> 0.0.0.0:8080\n8000/tcp -> [::]:8080\n$ curl http://127.0.0.1:8080/\ncurl: (52) Empty reply from server\n$ docker exec inventory-web-1 ss -tlnp\nState  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0      2048       127.0.0.1:8000      0.0.0.0:*     users:(("gunicorn",pid=1,fd=5))',
      options: [
        { text: 'The application listens on 127.0.0.1 inside the container, so traffic arriving on the container\'s eth0 is refused; it must listen on 0.0.0.0', correct: true },
        { text: 'The port is not published', misconception: 'docker port shows 8080 → 8000 published on all addresses.' },
        { text: 'ufw is blocking port 8080', misconception: 'ufw does not see DNATed published traffic, and the test from the host itself also fails.' },
        { text: 'The healthcheck is broken, so Docker blocks traffic', misconception: 'Docker never blocks traffic based on health. The healthcheck passes precisely because it connects to localhost inside the container.' },
      ],
      concepts: ['docker.networking', 'svc.listening'],
      explanation: 'Each container has its own network namespace: its 127.0.0.1 is not the host\'s. Published traffic is DNATed to the container\'s bridge IP, where nothing listens. Change the bind address (e.g. `gunicorn -b 0.0.0.0:8000`) and recreate.',
    },
    {
      id: 'docker-q-ufw-bypass',
      kind: 'multi',
      level: 'advanced',
      prompt: 'An admin ran `ufw deny 5432` but the database container published with `-p 5432:5432` is still reachable from the whole network. Which statements are correct? (Select all that apply.)',
      options: [
        { text: 'Published ports are DNATed and forwarded, so ufw\'s INPUT rules never see that traffic', correct: true },
        { text: 'Rules in the DOCKER-USER chain are evaluated before Docker\'s own forwarding rules and can restrict it', correct: true },
        { text: 'Publishing as 127.0.0.1:5432:5432 (or not publishing at all and using the Compose network) limits exposure', correct: true },
        { text: 'Running `ufw reload` makes the deny rule apply to containers', misconception: 'Reloading does not change where the rules are evaluated.' },
        { text: 'Disabling iptables in Docker ("iptables": false) is the recommended fix', misconception: 'That breaks container networking (no NAT, no published ports) and is not the documented approach.' },
      ],
      concepts: ['docker.networking', 'fw.path', 'net.nat'],
      explanation: 'Docker documents this explicitly: use DOCKER-USER for filtering, or bind published ports to a specific address. Better still, other containers reach the database over the user-defined network without publishing it at all.',
    },
    {
      id: 'docker-q-dns',
      kind: 'single',
      level: 'intermediate',
      prompt: 'On Ubuntu 24.04, containers can resolve public names but not `registry.corp.lab`. The host itself resolves it. What is the best fix?',
      exhibit: '$ docker run --rm busybox cat /etc/resolv.conf\nnameserver 8.8.8.8\nnameserver 8.8.4.4',
      options: [
        { text: 'Set "dns": ["10.0.10.53"] in /etc/docker/daemon.json, restart Docker in a maintenance window, and recreate the containers', correct: true },
        { text: 'Add registry.corp.lab to the host\'s /etc/hosts', misconception: 'Containers on bridge networks do not use the host\'s /etc/hosts. It would be a workaround at best.' },
        { text: 'Run every container with --network host', misconception: 'That removes network isolation and port management to work around a DNS setting.' },
        { text: 'Restart systemd-resolved', misconception: 'The host resolver works; Docker could not use any of its upstream servers and fell back to Google DNS, which cannot see corp.lab.' },
      ],
      concepts: ['docker.networking', 'dns.resolution'],
      explanation: '8.8.8.8/8.8.4.4 is Docker\'s fallback when it finds no usable (non-loopback) nameserver for containers. Configure internal DNS for containers explicitly. DNS settings apply to containers created after the change.',
    },
    {
      id: 'docker-q-default-bridge',
      kind: 'single',
      level: 'beginner',
      prompt: 'Two containers were started with plain `docker run` (no --network). The app container cannot connect to `db:5432`: "Name or service not known". Why?',
      options: [
        { text: 'The default bridge network has no embedded DNS, so container names do not resolve; use a user-defined network', correct: true },
        { text: 'Port 5432 must be published with -p for containers to talk to each other', misconception: 'Container-to-container traffic uses the container port directly over the bridge; publishing is only for access from outside the host.' },
        { text: 'The db container must be started first', misconception: 'Start order would cause "connection refused", not a name resolution error.' },
      ],
      concepts: ['docker.networking', 'dns.resolution'],
      explanation: 'Only user-defined networks (including every Compose project\'s default network) provide the embedded DNS server at 127.0.0.11 that resolves container and service names.',
    },
    {
      id: 'docker-q-volume-perms',
      kind: 'multi',
      level: 'intermediate',
      prompt: 'On a RHEL 9 host, nginx in a container logs `open() "/usr/share/nginx/html/index.html" failed (13: Permission denied)` for a bind mount `/srv/web/html`. `ls -l` shows the files world-readable. Which are reasonable next steps? (Select all that apply.)',
      options: [
        { text: 'Check for SELinux denials with `ausearch -m avc -ts recent`', correct: true },
        { text: 'Add `:z` (or `:ro,z`) to the bind mount so the directory is labelled for container access', correct: true },
        { text: 'Disable SELinux (setenforce 0) permanently', misconception: 'That removes a protection for the whole host to fix one label.' },
        { text: 'chmod -R 777 /srv/web/html', misconception: 'UNIX permissions are already sufficient; SELinux labels are evaluated separately. 777 adds risk without fixing the cause.' },
      ],
      concepts: ['linux.permissions', 'docker.lifecycle'],
      explanation: 'With correct UNIX modes, "Permission denied" on RHEL points at SELinux: container_t may only read container_file_t. :z relabels the directory (shared); :Z makes it private to one container. Never relabel system directories.',
    },
    {
      id: 'docker-q-daemon-restart',
      kind: 'single',
      level: 'intermediate',
      prompt: 'One of six application containers on dock01 is unhealthy. A colleague proposes `sudo systemctl restart docker`. What is the main objection?',
      options: [
        { text: 'It stops every container on the host (unless live-restore is enabled), causing an outage of all six services to fix one', correct: true },
        { text: 'It deletes all volumes', misconception: 'Restarting the daemon does not delete volumes or containers.' },
        { text: 'It recreates the containers from new images', misconception: 'It restarts existing containers according to their restart policies; it does not pull or recreate.' },
        { text: 'There is no objection; it is the standard first step', misconception: 'The standard first steps are reading the health log and container logs, then restarting or recreating only the affected container.' },
      ],
      concepts: ['docker.lifecycle', 'ops.recovery', 'svc.systemd'],
      explanation: 'Match the action to the scope of the problem: inspect (`docker inspect --format \'{{json .State.Health}}\'`, `docker logs`), then restart or recreate that one container. A daemon restart is for daemon-level changes, in a window.',
    },
    {
      id: 'docker-q-pull',
      kind: 'single',
      level: 'beginner',
      prompt: '`docker pull nginx:1.27` on a server behind the corporate proxy times out, although `curl https://registry-1.docker.io/v2/` works in your shell where `https_proxy` is exported. Why?',
      options: [
        { text: 'The pull is performed by dockerd, which does not inherit your shell\'s proxy variables; configure a systemd drop-in or "proxies" in daemon.json', correct: true },
        { text: 'You need to run docker login first', misconception: 'Anonymous pulls of public images work without login (subject to rate limits) and would fail with an auth error, not a timeout.' },
        { text: 'The tag does not exist', misconception: 'That gives "manifest unknown" quickly, not a timeout.' },
      ],
      concepts: ['docker.lifecycle', 'svc.systemd'],
      explanation: 'The CLI only asks the daemon to pull. dockerd runs from systemd with its own environment: set HTTP(S)_PROXY/NO_PROXY in /etc/systemd/system/docker.service.d/http-proxy.conf (daemon-reload + restart) or in daemon.json "proxies".',
    },
  ],
};
