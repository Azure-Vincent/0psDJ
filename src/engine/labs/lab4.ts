// Lab 4: Containerized Application. Take over the inventory application from
// the developers and run it properly on dock01: delegate Docker to the admin,
// configure the daemon before any workload, review and fix the Compose project
// (an internal database published to the network, no restart policy, a secret
// in the wrong place), deploy it, harden the host firewall without breaking the
// published port, and prove it all survives a reboot.

import { mkdir, readFile, writeFile } from '../fs';
import { buildSshLab } from '../lab/sshLab';
import { checkGoal, firewallStillRestrictive } from '../scenarios/engine';
import { DB_PASSWORD, INVENTORY_CHECK, INVENTORY_COMPOSE, INVENTORY_DIR } from '../scenarios/containerScenarios';
import { loadProject, projectContainers } from '../sim/compose';
import { daemonConfig } from '../sim/docker';
import type { World } from '../types';
import { probe } from './engine';
import type { GuidedLab, LabCheck } from './types';

const OK = (detail: string) => ({ ok: true, detail });
const NO = (detail: string) => ({ ok: false, detail });

/** compose.yaml as the development team handed it over (DEV-881). */
export const LAB4_DEV_COMPOSE = `# Inventory application, as handed over by the development team (DEV-881).
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: \${DB_PASSWORD}
    # published so we can debug with psql from our laptops
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
  app:
    image: corp/inventory:1.4
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

export const LAB4_DAEMON_JSON = `{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "dns": ["10.0.10.53"],
  "live-restore": true
}
`;

export const LAB4_NFT = `#!/usr/sbin/nft -f
# dock01 host firewall (CHG-2214). Docker manages its own tables (ip nat,
# ip filter): restart docker after reloading this file.

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
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export function buildLab4World(): World {
  const world = buildSshLab();
  const h = world.hosts.dock01;
  const t = world.clock;
  mkdir(h, INVENTORY_DIR, t);
  writeFile(h, `${INVENTORY_DIR}/compose.yaml`, LAB4_DEV_COMPOSE, t);
  world.clock += 5 * 60_000;
  return world;
}

/** A file's contents as a printf command line (for the reference solution). */
const printfTo = (text: string, path: string) => `printf '${text.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')}' > ${path}`;

const project = (w: World) => loadProject(w.hosts.dock01, INVENTORY_DIR);

// ---------------------------------------------------------------- checks

const aliceDocker: LabCheck = {
  id: 'alice-docker', description: 'dock01: alice can use the Docker CLI without sudo (member of the docker group)',
  check(w) {
    const r = probe(w, 'dock01', 'alice', 'docker ps');
    return r.code === 0 ? OK('alice: docker ps works.') : NO(r.output.split('\n')[0] || `docker ps exited ${r.code}`);
  },
};

const daemonOk: LabCheck = {
  id: 'daemon-json', description: '/etc/docker/daemon.json is valid, sets the internal DNS server 10.0.10.53, log rotation and live-restore, and dockerd is running with it',
  check(w) {
    const h = w.hosts.dock01;
    const text = readFile(h, '/etc/docker/daemon.json');
    if (!text) return NO('/etc/docker/daemon.json does not exist: the daemon runs with its defaults.');
    const { config, error } = daemonConfig(h);
    if (error) return NO(error);
    if (h.services.docker?.state !== 'active') return NO('docker.service is not active: restart it after changing daemon.json.');
    if (!config.dns?.includes('10.0.10.53')) return NO(`"dns" is ${config.dns ? JSON.stringify(config.dns) : 'not set'}: containers would fall back to public resolvers.`);
    if (!config.liveRestore) return NO('"live-restore" is not true: restarting dockerd would stop every container.');
    const j = JSON.parse(text) as { 'log-opts'?: Record<string, string> };
    if (!j['log-opts']?.['max-size']) return NO('No "log-opts" with "max-size": container logs grow without limit.');
    return OK(`dns ${config.dns.join(', ')}, live-restore, log-opts max-size ${j['log-opts']['max-size']}.`);
  },
};

const envFile: LabCheck = {
  id: 'env-file', description: `${INVENTORY_DIR}/.env holds DB_PASSWORD (from the change record) and is readable by its owner only (0600)`,
  check(w) {
    const n = w.hosts.dock01.fs[`${INVENTORY_DIR}/.env`];
    if (!n || n.type !== 'file') return NO(`${INVENTORY_DIR}/.env does not exist: \${DB_PASSWORD} would be blank.`);
    if (!new RegExp(`^\\s*DB_PASSWORD=${DB_PASSWORD}\\s*$`, 'm').test(n.content ?? '')) return NO('.env does not set DB_PASSWORD to the password in the change record.');
    if ((n.mode & 0o077) !== 0) return NO(`.env is mode ${(n.mode & 0o777).toString(8).padStart(4, '0')}: anyone on dock01 can read the database password.`);
    return OK('.env: DB_PASSWORD set, mode 0600.');
  },
};

const composeReviewed: LabCheck = {
  id: 'compose-reviewed', description: 'compose.yaml is valid, the database publishes no port, the app publishes 8000, and both services restart unless stopped',
  check(w) {
    const p = project(w);
    if ('error' in p) return NO(p.error.split('\n')[0]);
    const db = p.services.find((s) => s.name === 'db');
    const app = p.services.find((s) => s.name === 'app');
    if (!db || !app) return NO(`Services: ${p.services.map((s) => s.name).join(', ')}; expected db and app.`);
    if (db.ports.length) return NO(`db still publishes ${db.ports.map((b) => `${b.hostPort}:${b.ctrPort}`).join(', ')}: PostgreSQL would be reachable from the whole network.`);
    if (!app.ports.some((b) => b.hostPort === 8000 && b.ctrPort === 8000)) return NO('app does not publish 8000:8000.');
    const noRestart = p.services.filter((s) => s.restart !== 'unless-stopped' && s.restart !== 'always');
    if (noRestart.length) return NO(`${noRestart.map((s) => s.name).join(', ')}: restart policy "${noRestart[0].restart}": the service would not come back after a reboot.`);
    if (p.warnings.length) return NO(p.warnings[0]);
    return OK('db: no published ports; app: 8000:8000; restart: unless-stopped.');
  },
};

const deployed: LabCheck = {
  id: 'deployed', description: 'The project "inventory" runs: containers inventory-db-1 and inventory-app-1 are up',
  check(w) {
    const cs = projectContainers(w.hosts.dock01, 'inventory');
    if (!cs.length) return NO('No containers for the project "inventory" (docker compose up -d in /srv/inventory).');
    const down = ['db', 'app'].filter((s) => !cs.some((c) => c.name === `inventory-${s}-1` && c.state.status === 'running'));
    if (down.length) return NO(`Not running: ${down.map((s) => `inventory-${s}-1`).join(', ')} (docker compose ps -a, docker compose logs).`);
    const pub = cs.filter((c) => c.ports.some((b) => b.ctrPort === 5432));
    if (pub.length) return NO('The running database container still publishes 5432: recreate it with docker compose up -d.');
    return OK('inventory-db-1 and inventory-app-1: running.');
  },
};

const reachable: LabCheck = {
  id: 'reachable', description: 'From ws01, http://inventory.corp.lab:8000/health answers 200 (the app is connected to its database)',
  check(w) {
    const r = checkGoal(w, INVENTORY_CHECK);
    return r.ok ? OK('GET /health: 200 {"status":"ok","database":"ok"}.') : NO(r.lines.filter(Boolean).slice(-2).join(' '));
  },
};

const dbClosed: LabCheck = {
  id: 'db-closed', description: 'From ws01, PostgreSQL (dock01:5432) is not reachable',
  check(w) {
    const r = probe(w, 'ws01', 'alice', 'nc -zv -w 2 dock01.corp.lab 5432');
    return r.code !== 0 ? OK('nc dock01 5432: no connection.') : NO('ws01 connects to dock01:5432: the database is published.');
  },
};

const hostFirewall: LabCheck = {
  id: 'host-firewall', description: 'dock01\'s host firewall drops unsolicited input by default and allows SSH',
  check(w) {
    const c = firewallStillRestrictive('dock01').check(w);
    if (!c.ok) return NO(c.message);
    const r = probe(w, 'ws01', 'alice', 'nc -zv -w 2 dock01.corp.lab 22');
    return r.code === 0 ? OK('input policy drop; SSH (22) open.') : NO('ws01 cannot reach SSH on dock01: the firewall must keep tcp dport 22.');
  },
};

// ---------------------------------------------------------------- the lab

export const LAB4: GuidedLab = {
  id: 'lab4',
  title: 'Lab 4: Containerized Application',
  level: 'intermediate',
  duration: '45–75 min',
  summary: 'Take over a Docker Compose application from its developers and run it as a service: delegate Docker access, configure the daemon, review and fix the project (published database, missing restart policy, the secret), deploy it, harden the host firewall without breaking the published port, and prove it survives a reboot.',
  brief: `The development team hands over the **inventory** application (DEV-881): a Compose project in **${INVENTORY_DIR}** with two services, **app** (corp/inventory:1.4, a gunicorn API on port 8000) and **db** (postgres:16). It must be available to the office at **http://inventory.corp.lab:8000/** (a CNAME for dock01). The change record CHG-2214 gives the database password, **${DB_PASSWORD}**, and the rules: alice administers Docker on dock01 without sudo; containers use the internal DNS server and rotated logs; the database is never reachable from the network; dock01 keeps a default-deny host firewall; and everything comes back by itself after a reboot.`,
  objectives: [
    'Delegate Docker access with the docker group, knowing that it is root-equivalent.',
    'Configure dockerd through /etc/docker/daemon.json before deploying workloads, and validate it.',
    'Review a compose.yaml: published ports, restart policies, and secrets kept in a protected .env.',
    'Deploy with docker compose up -d and verify each layer: containers, logs, the published port from a client.',
    'Understand how published ports pass the host firewall (DNAT and the forward path), and why restarting nftables removes Docker\'s rules.',
  ],
  prerequisites: [
    { label: 'Docker and container troubleshooting', link: 'lesson/docker/what' },
    { label: 'Host firewalls with nftables', link: 'lesson/nftables/what' },
    { label: 'NAT and port forwarding', link: 'lesson/nat/what' },
  ],
  setupNote: `This lab uses **dock01** (10.0.20.40, Debian 12, Docker Engine 26 with the images already pulled) on the server network. The developers' project is in **${INVENTORY_DIR}**; nothing is running yet.`,
  terminals: [
    { hostId: 'dock01', user: 'root', label: 'dock01 console (root)', banner: 'dock01 console (hypervisor), logged in as root. Debian 12, Docker Engine 26.1. The developers\' project: cat /srv/inventory/compose.yaml.' },
    { hostId: 'dock01', user: 'alice', label: 'dock01 (alice)', banner: 'dock01, logged in as alice (sudo password dock01-alice). Edit files with nano.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01: the office\'s view. Try: curl -sS -i http://inventory.corp.lab:8000/health, nc -zv dock01.corp.lab 5432.' },
  ],
  build: buildLab4World,
  steps: [
    {
      id: 'access', title: 'Let alice administer Docker',
      objective: 'Allow **alice** to run `docker` commands on dock01 without sudo.',
      background: 'The docker CLI talks to dockerd over the Unix socket **/var/run/docker.sock** (owner root, group **docker**, mode 0660). Only root and members of the docker group can use it. Membership is **root-equivalent**: `docker run -v /:/host` mounts the host\'s whole filesystem into a container where the user is root. Grant it only to people who would get sudo anyway, exactly as the change record does for alice.',
      tasks: [
        'As alice on dock01: `docker ps` → permission denied. Look at the socket: `ls -l /var/run/docker.sock`, and at `id`.',
        'As root: `usermod -aG docker alice`, then `getent group docker`.',
        'As alice: `docker ps` (an empty list) and `docker images` (the three images the team uses).',
      ],
      hints: ['On a real system alice must log out and in again before the new group applies to her shell (or use `newgrp docker`).', '`-a` matters: without it usermod replaces alice\'s supplementary groups.'],
      checks: [aliceDocker],
      solution: [{ host: 'dock01', user: 'root', commands: ['usermod -aG docker alice'] }],
      learn: [{ label: 'Docker: how it works', link: 'lesson/docker/internals' }],
      concepts: ['linux.permissions', 'docker.lifecycle'],
    },
    {
      id: 'daemon', title: 'Configure the daemon before any workload',
      objective: 'Create **/etc/docker/daemon.json** with the internal DNS server **10.0.10.53**, json-file log rotation (max-size 10m, max-file 3) and **live-restore**, and restart dockerd with it.',
      background: 'dockerd reads daemon.json only when it starts, and settings such as `dns` and `log-opts` are copied into each container **when it is created**: a container created before the change keeps the old values until it is recreated. That is why the daemon is configured first. A single JSON syntax error stops dockerd from starting, and with it every container on the host: validate the file before restarting. `live-restore` keeps containers running while dockerd itself is restarted or upgraded.',
      tasks: [
        `Write the file (nano /etc/docker/daemon.json as root):\n\n\`\`\`\n${LAB4_DAEMON_JSON}\`\`\``,
        '`systemctl restart docker`, then `systemctl status docker` and `journalctl -u docker -n 5`.',
        'Check what the daemon uses: `docker info` (Live Restore Enabled: true).',
      ],
      hints: ['If docker does not start: `journalctl -u docker` names the JSON error and its position. No trailing commas in JSON.', 'Containers that already exist do not pick up dns or log-opts: recreate them.'],
      checks: [daemonOk],
      solution: [{ host: 'dock01', user: 'root', commands: [printfTo(LAB4_DAEMON_JSON, '/etc/docker/daemon.json'), 'systemctl restart docker'] }],
      learn: [{ label: 'Docker: configuration', link: 'lesson/docker/config' }],
      concepts: ['svc.systemd', 'dns.resolution'],
    },
    {
      id: 'review', title: 'Review the Compose project',
      objective: `Fix the developers' **compose.yaml** for production: the database must not publish any port, both services restart **unless-stopped**, and the password comes from **${INVENTORY_DIR}/.env** (DB_PASSWORD=${DB_PASSWORD}, mode 0600).`,
      background: 'Every entry under `ports:` is published on **all of the host\'s addresses** and passes the host firewall (it is DNATed and forwarded, not delivered to the host\'s input chain). The app reaches the database by its service name **db** on the project network `inventory_default`, so the database needs no published port at all. Without a `restart:` policy a container that exits, or a host that reboots, leaves the service down. `${DB_PASSWORD}` is **interpolated** from `.env` in the project directory when you run `docker compose`; a missing variable becomes an empty string with only a warning, which PostgreSQL refuses.',
      tasks: [
        `\`cd ${INVENTORY_DIR}\` and \`docker compose config\`: note the WARN about DB_PASSWORD and the published 5432.`,
        'Edit compose.yaml: remove the `ports:` of **db**, add `restart: unless-stopped` to both services.',
        `Create .env: \`echo 'DB_PASSWORD=${DB_PASSWORD}' > .env\` and \`chmod 600 .env\`.`,
        '`docker compose config` again: no warning, the password filled in, no published port on db.',
      ],
      hints: ['YAML is indentation-sensitive: `restart:` sits at the same level as `image:` under each service.', 'Keep the comment-free reference in mind: the app needs DB_HOST=db and the same DB_PASSWORD as the database.'],
      checks: [composeReviewed, envFile],
      solution: [{ host: 'dock01', user: 'root', commands: [
        printfTo(INVENTORY_COMPOSE, `${INVENTORY_DIR}/compose.yaml`),
        `echo 'DB_PASSWORD=${DB_PASSWORD}' > ${INVENTORY_DIR}/.env`,
        `chmod 600 ${INVENTORY_DIR}/.env`,
      ] }],
      learn: [{ label: 'Docker: configuration (ports, restart, .env)', link: 'lesson/docker/config' }, { label: 'Ticket: published on loopback', link: 'troubleshoot/docker-port-localhost' }],
      concepts: ['docker.networking', 'net.nat'],
    },
    {
      id: 'deploy', title: 'Deploy and test from the office',
      objective: 'Start the project with `docker compose up -d` and prove that the office reaches **http://inventory.corp.lab:8000/health** while the database stays unreachable.',
      background: 'Compose creates the network **inventory_default** (a user-defined bridge with Docker\'s embedded DNS at 127.0.0.11, which resolves `db`), the volume **inventory_pgdata**, then the containers in dependency order. Publishing 8000 adds a DNAT rule to dockerd\'s `ip nat` table and starts a **docker-proxy** listening on the host. Test each layer: the containers, their logs, the port on the host, then the path from a client.',
      tasks: [
        `\`cd ${INVENTORY_DIR} && docker compose up -d\`, then \`docker compose ps\` and \`docker compose logs app\`.`,
        'On dock01: `ss -tlnp | grep 8000` (docker-proxy) and `nft list table ip nat` (the DNAT rule).',
        'From ws01: `curl -sS -i http://inventory.corp.lab:8000/health` (200) and `nc -zv -w 2 dock01.corp.lab 5432` (no connection).',
      ],
      hints: ['If app is "Restarting": `docker compose logs app` shows psycopg2\'s reason (name, password or connection).', 'A container keeps the configuration it was created with: after editing compose.yaml run `docker compose up -d` again (not restart).'],
      checks: [deployed, reachable, dbClosed],
      solution: [{ host: 'dock01', user: 'root', commands: [`cd ${INVENTORY_DIR} && docker compose up -d`] }],
      learn: [{ label: 'Docker: troubleshooting', link: 'lesson/docker/troubleshoot' }, { label: 'docker compose', link: 'reference?id=docker-compose' }],
      concepts: ['docker.lifecycle', 'docker.networking'],
    },
    {
      id: 'firewall', title: 'Harden the host firewall',
      objective: 'Give dock01 a persistent default-deny input policy that allows only SSH (and ICMP), and keep the inventory site working for the office.',
      background: 'Traffic to a published port is **DNATed** in prerouting to the container\'s address and then **forwarded** onto the bridge: it never reaches the input chain, so "allow 8000 in input" is neither needed nor sufficient, and a forward chain with **policy drop** in your own table blocks it (in nftables a packet must be accepted by every base chain on its hook). dockerd keeps its rules in its own tables, `ip nat` and `ip filter`. `/etc/nftables.conf` starts with **flush ruleset**: loading it removes Docker\'s tables, and published ports stop working until dockerd recreates them (`systemctl restart docker`). At boot, nftables starts before docker, so the order is right.',
      tasks: [
        `Write /etc/nftables.conf (nano, as root):\n\n\`\`\`\n${LAB4_NFT}\`\`\``,
        '`systemctl restart nftables`, then from ws01 `curl -m 5 http://inventory.corp.lab:8000/health`: it times out. `nft list tables` shows why.',
        '`systemctl restart docker` and `nft list tables` (inet filter, ip nat, ip filter). From ws01 the site answers again.',
      ],
      hints: ['Do not add a forward policy of drop to your table unless you also accept the traffic Docker forwards.', 'Keep `tcp dport 22 accept`, or you lose SSH the moment the file is loaded.'],
      checks: [hostFirewall, reachable, dbClosed],
      solution: [{ host: 'dock01', user: 'root', commands: [printfTo(LAB4_NFT, '/etc/nftables.conf'), 'systemctl restart nftables', 'systemctl restart docker'] }],
      learn: [{ label: 'Host firewalls with nftables', link: 'lesson/nftables/internals' }, { label: 'Ticket: hardened after the patch reboot', link: 'troubleshoot/docker-forward-drop' }],
      concepts: ['fw.path', 'net.nat'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Restart every machine and confirm everything above still holds.',
      background: 'At boot nftables loads /etc/nftables.conf, then dockerd starts, recreates its tables and starts the containers whose restart policy is `always` or `unless-stopped` (and was not stopped by hand). Anything done only at runtime (a container started without a policy, a firewall rule added with `nft add`) is gone.',
      tasks: ['Run "Check" on this step: it restarts every machine on a copy of the lab and re-runs all checks.'],
      hints: ['If only the reboot test fails, look at the restart policies (`docker inspect -f \'{{.HostConfig.RestartPolicy.Name}}\'`) and at /etc/nftables.conf.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Safe configuration change', link: 'reference?id=proc:safe-config-change' }],
      concepts: ['ops.recovery'],
      afterReboot: true,
    },
  ],
};
