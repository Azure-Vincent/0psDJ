// Container tickets on dock01: the inventory application (corp/inventory API
// and PostgreSQL) deployed with Docker Compose in /srv/inventory and published
// on port 8000. Each ticket breaks it the way it breaks in production: a port
// published on loopback, a renamed service, a host firewall that drops
// forwarded traffic, a leftover container on the port, no restart policy, and
// a daemon.json typo.

import { mkdir, writeFile } from '../fs';
import { listContainers } from '../sim/docker';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, HttpGoal, Scenario } from './types';

export const INVENTORY_DIR = '/srv/inventory';
export const DB_PASSWORD = 'Inv-Db-2026';

export const INVENTORY_COMPOSE = `# Inventory application (CHG-2210): web API and its PostgreSQL database.
# Users reach it at http://inventory.corp.lab:8000/ ; the database is internal.
services:
  db:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: \${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
  app:
    image: corp/inventory:1.4
    restart: unless-stopped
    depends_on:
      - db
    environment:
      DB_HOST: db
      DB_PASSWORD: \${DB_PASSWORD}
    ports:
      - "8000:8000"
volumes:
  pgdata:
`;

/** Write the project and start it (docker compose up -d), as the team deployed it. */
export function deployInventory(world: World, compose = INVENTORY_COMPOSE): void {
  const h = world.hosts.dock01;
  const t = world.clock;
  if (!h.fs[INVENTORY_DIR]) mkdir(h, INVENTORY_DIR, t);
  writeFile(h, `${INVENTORY_DIR}/compose.yaml`, compose, t);
  writeFile(h, `${INVENTORY_DIR}/.env`, `DB_PASSWORD=${DB_PASSWORD}\n`, t, { mode: 0o600 });
  script(world, 'dock01', [`cd ${INVENTORY_DIR} && docker compose up -d`], 30_000);
}

export const INVENTORY_CHECK: HttpGoal = {
  kind: 'http', fromHost: 'ws01', fromUser: 'alice', url: 'http://inventory.corp.lab:8000/health',
  description: 'From ws01, http://inventory.corp.lab:8000/health answers 200 (the API is up and connected to its database).',
};

/** The database stays internal: nothing publishes PostgreSQL's port on the host. */
function dbNotPublished(): Constraint {
  return {
    id: 'db-not-published', required: true,
    description: 'PostgreSQL is not published on dock01 (no host port maps to 5432): only the app may reach the database.',
    check(world) {
      const bad = listContainers(world.hosts.dock01).filter((c) => c.state.status === 'running' && c.ports.some((p) => p.ctrPort === 5432));
      return bad.length
        ? { id: this.id, ok: false, required: true, message: `${bad.map((c) => c.name).join(', ')} publishes 5432 on the host.` }
        : { id: this.id, ok: true, required: true, message: 'The database is only reachable on the project network.' };
    },
  };
}

const BRIEFING = [
  'dock01 (10.0.20.40) runs Docker Engine 26. The inventory application is a Docker Compose project in /srv/inventory: services "app" (corp/inventory:1.4, gunicorn on 8000) and "db" (postgres:16), with the password in /srv/inventory/.env.',
  'Users open http://inventory.corp.lab:8000/ (inventory.corp.lab is a CNAME for dock01). /health answers 200 only when the app is connected to its database.',
  'Work as root on dock01: docker compose ps / logs / config in /srv/inventory, docker ps -a, docker inspect, docker exec, nft list ruleset, journalctl -u docker.',
  'Fixes must survive a reboot of dock01. Keep the database internal (do not publish 5432) and keep dock01\'s firewall restrictive where it has one.',
];

const TERMINALS = [
  { hostId: 'dock01', user: 'root', label: 'dock01 console (root)', banner: 'dock01 console, logged in as root. Docker Engine 26.1, Compose v2.27. Project: cd /srv/inventory. Try: docker compose ps -a, docker compose logs app, docker ps -a, docker inspect, journalctl -u docker.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01: a user\'s view. Try: curl -sS -i http://inventory.corp.lab:8000/health, nc -zv dock01.corp.lab 8000.' },
];

const CANDIDATES = ['docker-port-loopback', 'docker-service-name', 'docker-host-forward-drop', 'docker-port-conflict', 'docker-no-restart-policy', 'docker-daemon-config', 'dns-wrong-record', 'routing-server-gateway'];

const NOT = {
  dns: 'inventory.corp.lab resolves to dock01 (10.0.20.40): getent hosts inventory.corp.lab on ws01.',
  route: 'dock01 answers ping and SSH from ws01: the network path and the return route are fine.',
};

export const CONTAINER_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'docker-port-localhost',
    title: 'It works on the server',
    difficulty: 'beginner',
    ticket: 'Users: "http://inventory.corp.lab:8000 does not load" (connection refused). The developer: "Works for me: curl localhost:8000 on dock01 answers. I only tightened the port mapping in compose.yaml."',
    briefing: BRIEFING,
    goals: [INVENTORY_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployInventory(world, INVENTORY_COMPOSE.replace('      - "8000:8000"\n', '      - "127.0.0.1:8000:8000"   # only on this machine until testing is done\n'));
    },
    rootCauses: ['docker-port-loopback'],
    candidates: CANDIDATES,
    feedback: {
      'docker-service-name': 'The app is up and connected to its database: docker compose ps shows it running, and curl localhost:8000/health on dock01 answers 200.',
      'docker-host-forward-drop': 'dock01 has Debian\'s accept-all ruleset, and the client gets a refusal (RST), not a timeout.',
      'docker-port-conflict': 'docker compose up started both containers; nothing else uses port 8000.',
      'docker-no-restart-policy': 'Both services have restart: unless-stopped, and nothing was rebooted.',
      'docker-daemon-config': 'dockerd is running: docker commands work.',
      'dns-wrong-record': NOT.dns,
      'routing-server-gateway': NOT.route,
    },
    hints: [
      '"Connection refused" from ws01 but an answer on dock01 itself: something listens, but only on an address ws01 cannot use. On dock01: ss -tlnp | grep 8000, docker ps (PORTS column).',
      '127.0.0.1:8000->8000/tcp: the port is published on the loopback address only, so docker-proxy listens on 127.0.0.1 and no DNAT rule matches traffic to 10.0.20.40. Look at ports: in /srv/inventory/compose.yaml.',
      'Publish it on all addresses: "8000:8000" (or "10.0.20.40:8000:8000"), then docker compose up -d in /srv/inventory: Compose recreates the app container with the new mapping.',
    ],
    explanation: {
      rootCause: 'The port mapping was changed to "127.0.0.1:8000:8000". Docker then binds the published port to the loopback address only: the DNAT rule matches only traffic addressed to 127.0.0.1, and docker-proxy listens on 127.0.0.1:8000.',
      manifestation: 'curl localhost:8000 on dock01 works; every other machine gets "connection refused" because nothing listens on 10.0.20.40:8000.',
      evidence: 'docker ps → 127.0.0.1:8000->8000/tcp; ss -tlnp → docker-proxy on 127.0.0.1:8000; nft list table ip nat → "ip daddr 127.0.0.1 … dnat to 172.18.0.3:8000"; compose.yaml ports line.',
      prevention: 'Test from another machine (where users are), not from the host; review port mappings: "127.0.0.1:" is the right choice for internal-only services (like a database admin UI), not for the user-facing one.',
    },
    solution: [{ host: 'dock01', commands: [`sed -i 's/"127.0.0.1:8000:8000"/"8000:8000"/' ${INVENTORY_DIR}/compose.yaml`, `cd ${INVENTORY_DIR} && docker compose up -d`] }],
    constraints: [dbNotPublished()],
    concepts: ['docker.networking'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'docker-renamed-service',
    title: 'Restarting (3)',
    difficulty: 'intermediate',
    ticket: 'The inventory site is down since this morning\'s redeploy. A teammate: "I only cleaned up compose.yaml (renamed the database service to postgres, it is clearer) and redeployed with docker compose down / up -d. Both containers were created without errors."',
    briefing: BRIEFING,
    goals: [INVENTORY_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployInventory(world);
      world.clock += 3600_000;
      const renamed = INVENTORY_COMPOSE.replace('\n  db:\n', '\n  postgres:\n').replace('      - db\n', '      - postgres\n');
      writeFile(world.hosts.dock01, `${INVENTORY_DIR}/compose.yaml`, renamed, world.clock);
      script(world, 'dock01', [`cd ${INVENTORY_DIR} && docker compose down`, `cd ${INVENTORY_DIR} && docker compose up -d`], 20_000);
    },
    rootCauses: ['docker-service-name'],
    candidates: CANDIDATES,
    feedback: {
      'docker-port-loopback': 'The mapping is "8000:8000"; the app simply is not running long enough to listen.',
      'docker-host-forward-drop': 'Nothing listens on 8000 (the app keeps crashing), so the client is refused; the firewall is Debian\'s default.',
      'docker-port-conflict': 'No other container uses port 8000; compose created both containers.',
      'docker-no-restart-policy': 'The policy is unless-stopped; that is why the app keeps restarting instead of staying down.',
      'docker-daemon-config': 'dockerd is running.',
      'dns-wrong-record': 'The name that fails is "db", inside the container (the app\'s log), not inventory.corp.lab.',
      'routing-server-gateway': NOT.route,
    },
    hints: [
      'docker compose ps -a: the app is "Restarting". A container that restarts in a loop is a process that exits at start: read docker compose logs app.',
      '"could not translate host name "db" to address": the app looks for its database by the name "db" (DB_HOST in its environment). On a Compose network, containers find each other by service name: which names exist now? docker compose config, docker exec inventory-postgres-1 getent hosts db.',
      'Make the names agree: rename the service back to db (and the depends_on entry), or set DB_HOST: postgres. Then docker compose up -d (add --remove-orphans if a container of the old name is left).',
    ],
    explanation: {
      rootCause: 'The database service was renamed from "db" to "postgres", but the app still connects to DB_HOST=db. Compose registers each container under its service name in the network\'s embedded DNS (127.0.0.11): "db" no longer exists.',
      manifestation: 'The app exits at start with psycopg2\'s "could not translate host name "db" to address" (gunicorn: "Worker failed to boot", exit 3); with restart: unless-stopped Docker restarts it again and again: "Restarting (3)". Nothing listens on 8000.',
      evidence: 'docker compose ps -a → app Restarting (3); docker compose logs app → the psycopg2 error; docker compose config → service "postgres", DB_HOST: db; docker exec inventory-postgres-1 getent hosts db → no answer.',
      prevention: 'Treat service names as an interface: rename them together with every reference (DB_HOST, depends_on, links), and check docker compose logs right after a deploy, not only docker compose ps.',
    },
    solution: [{ host: 'dock01', commands: [`sed -i 's/^  postgres:$/  db:/; s/^      - postgres$/      - db/' ${INVENTORY_DIR}/compose.yaml`, `cd ${INVENTORY_DIR} && docker compose up -d --remove-orphans`] }],
    constraints: [dbNotPublished()],
    concepts: ['docker.networking', 'docker.lifecycle'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'docker-forward-drop',
    title: 'Hardened after the patch reboot',
    difficulty: 'advanced',
    ticket: 'Since last night\'s patch reboot of dock01 the inventory site times out. Security applied the standard server firewall template before the reboot: "port 8000 is explicitly allowed in the input chain, so it cannot be the firewall". docker ps shows both containers up.',
    briefing: BRIEFING,
    goals: [INVENTORY_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployInventory(world);
      world.clock += 3600_000;
      writeFile(world.hosts.dock01, '/etc/nftables.conf', `#!/usr/sbin/nft -f
# Standard server firewall template (SEC-114)

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		tcp dport 22 accept
		# inventory application (CHG-2210)
		tcp dport 8000 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`, world.clock, { mode: 0o755 });
      world.clock += 8 * 3600_000;
      bootHost(world, world.hosts.dock01);
    },
    rootCauses: ['docker-host-forward-drop'],
    candidates: CANDIDATES,
    feedback: {
      'docker-port-loopback': 'docker ps shows 0.0.0.0:8000->8000/tcp.',
      'docker-service-name': 'Both containers are up and the app is connected: curl localhost:8000/health on dock01 answers 200.',
      'docker-port-conflict': 'The app container started and publishes 8000.',
      'docker-no-restart-policy': 'Both containers came back after the reboot (restart: unless-stopped).',
      'docker-daemon-config': 'dockerd is running.',
      'dns-wrong-record': NOT.dns,
      'routing-server-gateway': 'SSH to dock01 from ws01 works, so the return path is fine; only the published port is silent.',
    },
    hints: [
      'A timeout, not a refusal: something drops the packets. The input chain allows 8000, yet it times out. Where does a packet to a published port really go? nft list ruleset: look at Docker\'s "ip nat" table and every chain with "hook forward".',
      'Docker DNATs the connection to the container (172.18.0.x), so the kernel FORWARDS it: it never passes the input chain. The template\'s "chain forward { policy drop; }" drops it before Docker\'s own FORWARD chain can accept it (any base chain that drops, wins).',
      'Let Docker\'s FORWARD chain decide: set the template\'s forward chain to policy accept (keep input policy drop), then systemctl restart nftables and systemctl restart docker (restarting nftables flushes Docker\'s rules until dockerd re-creates them).',
    ],
    explanation: {
      rootCause: 'The firewall template has "chain forward { type filter hook forward …; policy drop; }". Traffic to a published port is DNATed to the container and forwarded through the bridge, so the input rule for 8000 never applies, and the template\'s forward chain drops it even though Docker\'s own FORWARD chain accepts it.',
      manifestation: 'From other machines the published port times out; SSH and ping work; on dock01, curl localhost:8000 works (local traffic is not forwarded). It started at the reboot because only then was the new nftables.conf loaded.',
      evidence: 'nft list ruleset → inet filter forward policy drop, ip nat DOCKER dnat rule for 8000, ip filter FORWARD with the DOCKER accept; tcpdump on dock01 shows SYNs on eth0 but none on the br- interface; journal shows the reboot.',
      prevention: 'On Docker hosts, filter forwarded container traffic in Docker\'s DOCKER-USER chain or leave forward to Docker; remember that published ports bypass input rules. Test firewall changes from a client before scheduling the reboot that loads them.',
    },
    solution: [{ host: 'dock01', commands: [
      "sed -i '/chain forward {/,/}/ s/policy drop;/policy accept;/' /etc/nftables.conf",
      'nft -c -f /etc/nftables.conf && systemctl restart nftables',
      'systemctl restart docker',
    ] }],
    constraints: [firewallStillRestrictive('dock01'), dbNotPublished()],
    concepts: ['docker.networking', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'docker-port-taken',
    title: 'Something else answers',
    difficulty: 'intermediate',
    ticket: 'Monitoring: http://inventory.corp.lab:8000/health returns 404 Not Found. A teammate tried a new front page in a test container yesterday and then redeployed the app: "docker compose up -d printed an error, but I thought it was a warning."',
    briefing: BRIEFING,
    goals: [INVENTORY_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployInventory(world);
      world.clock += 3600_000;
      script(world, 'dock01', [
        `cd ${INVENTORY_DIR} && docker compose down`,
        'docker run -d --name frontpage-test --restart always -p 8000:80 nginx:1.25',
        `cd ${INVENTORY_DIR} && docker compose up -d`,
      ], 30_000);
    },
    rootCauses: ['docker-port-conflict'],
    candidates: CANDIDATES,
    feedback: {
      'docker-port-loopback': 'The port answers from ws01 (with a 404): it is published on all addresses.',
      'docker-service-name': 'The app never started at all: it is "Created", not restarting; the error is about the port.',
      'docker-host-forward-drop': 'The request gets an HTTP answer: nothing is dropped.',
      'docker-no-restart-policy': 'Nothing rebooted; the app container was created but could not start.',
      'docker-daemon-config': 'dockerd is running.',
      'dns-wrong-record': 'The answer comes from dock01 (the 404 page is nginx\'s, served by dock01 on 8000).',
      'routing-server-gateway': NOT.route,
    },
    hints: [
      '404 means a web server answered, just not the inventory API (Server: nginx in the headers, not gunicorn). Who owns port 8000 on dock01? docker ps -a (PORTS column).',
      'frontpage-test publishes 8000 and has restart: always; inventory-app-1 is "Created": docker compose up -d failed with "Bind for 0.0.0.0:8000 failed: port is already allocated".',
      'Remove the test container (docker rm -f frontpage-test; with restart: always a plain stop would come back after a reboot), then docker compose up -d in /srv/inventory.',
    ],
    explanation: {
      rootCause: 'A test container (nginx, restart: always) was left publishing host port 8000. When the project was redeployed, Docker could not bind 8000 for the app: "Bind for 0.0.0.0:8000 failed: port is already allocated". The app container stayed "Created".',
      manifestation: 'Port 8000 answers, but with nginx\'s 404 for /health: the wrong service answers, which is easy to misread as an application error.',
      evidence: 'curl -i shows "Server: nginx/1.25.5" and 404; docker ps -a → frontpage-test 0.0.0.0:8000->80/tcp, inventory-app-1 Created; docker compose up -d prints the bind error.',
      prevention: 'Read docker compose up output (errors are not warnings); use separate ports or hosts for tests and remove test containers (docker rm -f) when done.',
    },
    solution: [{ host: 'dock01', commands: ['docker rm -f frontpage-test', `cd ${INVENTORY_DIR} && docker compose up -d`] }],
    constraints: [dbNotPublished()],
    concepts: ['docker.lifecycle'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'docker-no-restart',
    title: 'Gone after the patch reboot',
    difficulty: 'beginner',
    ticket: 'After last night\'s patch reboot of dock01 the inventory site is refused. "Docker is running and the containers are still there, docker ps -a shows them."',
    briefing: BRIEFING,
    goals: [INVENTORY_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployInventory(world, INVENTORY_COMPOSE.replace(/^    restart: unless-stopped\n/gm, ''));
      world.clock += 8 * 3600_000;
      bootHost(world, world.hosts.dock01);
    },
    rootCauses: ['docker-no-restart-policy'],
    candidates: CANDIDATES,
    feedback: {
      'docker-port-loopback': 'Nothing listens on 8000 at all (ss -tlnp): the containers are not running.',
      'docker-service-name': 'The app is not crash-looping; it is simply stopped ("Exited").',
      'docker-host-forward-drop': 'The client is refused, not timed out; dock01 has Debian\'s default ruleset.',
      'docker-port-conflict': 'No container publishes 8000.',
      'docker-daemon-config': 'dockerd started after the reboot: docker commands work.',
      'dns-wrong-record': NOT.dns,
      'routing-server-gateway': NOT.route,
    },
    hints: [
      'docker ps -a: both containers are "Exited" since the reboot. What tells Docker to start a container again at boot?',
      "docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' inventory-app-1 → no. Without a restart policy, containers stay stopped after dockerd restarts (and so after every reboot).",
      'Add restart: unless-stopped to both services in compose.yaml and run docker compose up -d (the containers are recreated with the policy). The verification reboots dock01.',
    ],
    explanation: {
      rootCause: 'The services have no restart policy (the default is "no"). When dockerd stops at shutdown it stops the containers, and at boot it starts only containers whose policy is always or unless-stopped.',
      manifestation: 'Everything works until the first reboot; afterwards the containers are "Exited (0)", nothing listens on 8000 and clients are refused. docker compose up -d fixes it until the next reboot.',
      evidence: "docker ps -a → Exited; docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' → no; compose.yaml has no restart: lines; journalctl -b shows the reboot.",
      prevention: 'Give every long-running service restart: unless-stopped (or always), and include a reboot in the acceptance test of a new deployment.',
    },
    solution: [{ host: 'dock01', commands: [`sed -i 's/^\\(    image: .*\\)$/\\1\\n    restart: unless-stopped/' ${INVENTORY_DIR}/compose.yaml`, `cd ${INVENTORY_DIR} && docker compose up -d`] }],
    constraints: [dbNotPublished()],
    concepts: ['docker.lifecycle'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'docker-daemon-json',
    title: 'One comma',
    difficulty: 'beginner',
    ticket: 'The inventory site is refused. A teammate configured log rotation for Docker (/etc/docker/daemon.json) and restarted it: "now every docker command says the daemon is not running".',
    briefing: BRIEFING,
    goals: [INVENTORY_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployInventory(world);
      world.clock += 3600_000;
      writeFile(world.hosts.dock01, '/etc/docker/daemon.json', '{\n  "log-driver": "json-file",\n  "log-opts": {\n    "max-size": "10m",\n    "max-file": "3",\n  }\n}\n', world.clock);
      script(world, 'dock01', ['systemctl restart docker'], 30_000);
    },
    rootCauses: ['docker-daemon-config'],
    candidates: CANDIDATES,
    feedback: {
      'docker-port-loopback': 'No containers run at all: dockerd itself is down.',
      'docker-service-name': 'The containers are not crashing; the daemon that runs them is not running.',
      'docker-host-forward-drop': 'Refused, not timed out; and dockerd is down.',
      'docker-port-conflict': 'dockerd is not running, so no container can be started.',
      'docker-no-restart-policy': 'The services have restart: unless-stopped; they will come back as soon as dockerd starts.',
      'dns-wrong-record': NOT.dns,
      'routing-server-gateway': NOT.route,
    },
    hints: [
      '"Cannot connect to the Docker daemon": the containers are not the problem, dockerd is. systemctl status docker, journalctl -u docker -n 20.',
      '"unable to configure the Docker daemon with file /etc/docker/daemon.json: invalid character \'}\' looking for beginning of object key string": JSON does not allow a comma after the last item.',
      'Remove the trailing comma after "max-file": "3", then systemctl start docker. The containers (restart: unless-stopped) come back by themselves.',
    ],
    explanation: {
      rootCause: '/etc/docker/daemon.json has a trailing comma after the last log option. dockerd parses it at start, fails and exits, so the restart left Docker down, and every container with it.',
      manifestation: 'All containers are down (clients refused); every docker command fails with "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?".',
      evidence: 'systemctl status docker → failed; journalctl -u docker → "unable to configure the Docker daemon with file /etc/docker/daemon.json: invalid character \'}\' looking for beginning of object key string".',
      prevention: 'Validate before restarting (dockerd --validate --config-file /etc/docker/daemon.json, or python3 -m json.tool), and change daemon settings in a maintenance window: a dockerd restart stops every container (unless live-restore is on).',
    },
    solution: [{ host: 'dock01', commands: ['sed -i \'s/"max-file": "3",/"max-file": "3"/\' /etc/docker/daemon.json', 'systemctl start docker'] }],
    constraints: [dbNotPublished()],
    concepts: ['docker.lifecycle', 'svc.systemd'],
  },
];
