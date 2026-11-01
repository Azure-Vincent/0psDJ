// Integrated Lab 5: Deploy a Containerized Business Application. Builds on the
// Containerized Application lab (Docker access, the daemon, reviewing and
// deploying the Compose project, the host firewall) and adds what users and
// operations need around it: publication through the company's reverse
// proxy and a check that the data lives in a volume. The incident: a
// "clean-up" of compose.yaml renames the database service the app depends on.

import { readFile } from '../../fs';
import { APPS_CHECK, proxiedNginxConf } from '../../scenarios/proxyScenarios';
import { checkGoal } from '../../scenarios/engine';
import { NO, OK, printfTo } from '../engine';
import { LAB4 } from '../lab4';
import type { GuidedLab, LabCheck } from '../types';
import { cmdCheck, hop } from './common';
import { reuseStep, ticketFault } from './tickets';

const viaProxy: LabCheck = {
  id: 'proxy', description: 'From ws01, http://apps.corp.lab/inventory/health answers 200 through the reverse proxy on srv01 (proxy_pass to dock01:8000)',
  check(w) {
    const conf = readFile(w.hosts.srv01, '/etc/nginx/nginx.conf') ?? '';
    if (!/server_name apps\.corp\.lab;[\s\S]*location \/inventory\/ \{[\s\S]*proxy_pass http:\/\/(dock01(\.corp\.lab)?|10\.0\.20\.40):8000\//.test(conf)) return NO('srv01\'s /etc/nginx/nginx.conf has no apps.corp.lab server block that proxies /inventory/ to http://dock01.corp.lab:8000/.');
    const r = checkGoal(w, APPS_CHECK);
    return r.ok ? OK('The application is published through the reverse proxy.') : NO(r.lines.filter(Boolean).slice(-2).join(' '));
  },
};

const dataVolume: LabCheck = cmdCheck('volume', 'The database keeps its data in the named volume inventory_pgdata (it survives docker compose down/up)', 'dock01', 'root', 'docker volume ls', (o) => (/inventory_pgdata/.test(o) ? null : 'There is no volume inventory_pgdata: the database files would be lost with the container.'), 'The data lives in a volume, not in the container.');

export const ILAB5: GuidedLab = {
  id: 'ilab5',
  title: 'Integrated Lab 5: Deploy a Containerized Business Application',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Run the inventory application in containers the way operations needs it: Docker access without root, a daemon configured before any workload, a reviewed Compose project (no published database, restart policies, secrets), the host firewall, the app published through the company\'s reverse proxy, and data in a volume. Then find out why the application keeps restarting after a teammate "cleaned up" the project.',
  brief: `${LAB4.brief}

Afterwards, publish it the way every internal application is published: through the reverse proxy on **srv01** at **http://apps.corp.lab/inventory/** (proxying to dock01:8000), so users never need to know which host or port runs it.`,
  objectives: [
    ...LAB4.objectives,
    'Publish a container through a reverse proxy and follow a request through DNS, the proxy, the published port and the container network to the database.',
    'Diagnose a container that keeps restarting from its logs and the Compose project.',
  ],
  prerequisites: [...LAB4.prerequisites, { label: 'Web servers and reverse proxies', link: 'lesson/webproxy/what' }],
  setupNote: LAB4.setupNote,
  terminals: [
    ...LAB4.terminals,
    ...(LAB4.terminals.some((t) => t.hostId === 'srv01') ? [] : [{ hostId: 'srv01', user: 'root', label: 'srv01 (reverse proxy)', banner: 'srv01 (root): nginx, the company reverse proxy. Try: cat /etc/nginx/nginx.conf, nginx -t, tail /var/log/nginx/error.log.' }]),
  ],
  build: LAB4.build,
  steps: [
    reuseStep(LAB4, 'access'),
    reuseStep(LAB4, 'daemon', {
      commands: [{ host: 'dock01', command: 'systemctl restart docker', what: 'Restarts dockerd so it reads /etc/docker/daemon.json.', why: 'Daemon settings (log rotation, DNS for containers, live-restore) apply only at start; with "live-restore" running containers survive later daemon restarts.', where: '/etc/docker/daemon.json', success: 'No output; docker info shows the settings.', verify: 'docker info (Logging Driver, Live Restore Enabled); a typo in the JSON makes dockerd fail to start: journalctl -u docker.' }],
    }),
    reuseStep(LAB4, 'review'),
    reuseStep(LAB4, 'deploy', {
      commands: [{ host: 'dock01', command: 'docker compose up -d', what: 'Creates the project\'s network, volume and containers, and starts them in the background.', why: 'Compose turns the reviewed file into running containers on their own network, where "db" resolves to the database container.', where: '/srv/inventory/compose.yaml (+ .env); docker compose ps shows the state.', success: 'Network, volume and containers "Created/Started".', verify: 'docker compose ps (Up, not Restarting), docker compose logs app, curl from a client.' }],
    }),
    reuseStep(LAB4, 'firewall'),
    {
      id: 'proxy', title: 'Publish it through the reverse proxy',
      objective: 'http://apps.corp.lab/inventory/ reaches the application through nginx on srv01.',
      background: 'Users and other applications should not depend on which host and port runs a service. The company\'s **reverse proxy** (nginx on srv01, name apps.corp.lab) receives the request and opens **its own connection** to the backend (dock01:8000). For that, every link must work: DNS for apps.corp.lab, nginx\'s configuration, name resolution of the upstream **from srv01**, the published port on dock01, dock01\'s firewall for traffic **from srv01**, and the app\'s own connection to its database.\n\nWith `proxy_pass http://dock01.corp.lab:8000/;` (trailing slash), the /inventory/ prefix is replaced by /: the app receives /health, not /inventory/health.',
      tasks: [
        'On srv01: add a server block for `server_name apps.corp.lab;` with `location /inventory/ { proxy_pass http://dock01.corp.lab:8000/; proxy_set_header Host $host; }` inside http { } of /etc/nginx/nginx.conf.',
        '`nginx -t`, then `systemctl reload nginx`.',
        'From ws01: `curl -s http://apps.corp.lab/inventory/health`. On errors: 502 (nothing answers on the upstream port), 504 (the upstream does not answer in time: a firewall?), 404 (the URI mapping).',
      ],
      hints: ['curl the backend directly from srv01 (curl -s http://dock01.corp.lab:8000/health) to split the problem in two.', 'nginx resolves upstream names when it loads its configuration: if dock01.corp.lab did not resolve, the reload would fail.'],
      checks: [viaProxy],
      solution: [{ host: 'srv01', user: 'root', commands: [printfTo(proxiedNginxConf(), '/etc/nginx/nginx.conf'), 'nginx -t', 'systemctl reload nginx'] }],
      commands: [
        { host: 'ws01', command: 'curl -s http://apps.corp.lab/inventory/health', what: 'Requests the application\'s health endpoint through the proxy, as a user would.', why: 'It exercises every link: DNS, the proxy, the upstream connection, the container and its database.', success: 'A 200 answer from the application (it reports its database connection).', verify: '502/504/404 each point at a different link: see the background.' },
      ],
      learn: [{ label: 'Reverse proxies', link: 'lesson/webproxy/internals' }, { label: 'nginx.conf', link: 'reference?id=file:nginx-conf' }],
      concepts: ['web.proxy', 'docker.networking'],
    },
    {
      id: 'verify', title: 'Verify the application end to end, and after a reboot', stage: 'verify',
      objective: 'Users reach the application through the proxy, the application reaches its database, the data lives in a volume, the database is not reachable from the office, and all of it survives a reboot.',
      background: 'Containers add their own failure modes after a reboot: no restart policy (gone), the daemon not enabled, published ports that a host firewall filters. Verify through the front door (the proxy) and the internals (volumes, ports).',
      tasks: ['From ws01: `curl -s http://apps.corp.lab/inventory/health`; `nc -z -w 3 dock01.corp.lab 5432` must fail.', 'On dock01: `docker compose ps`, `docker volume ls`.', 'Run the check (reboots every machine on a copy and repeats every check).'],
      hints: ['If the app is gone after the reboot: restart policies (docker compose ps after a reboot).'],
      checks: [viaProxy, dataVolume],
      solution: [],
      learn: [{ label: 'Containers (Docker)', link: 'lesson/docker/operate' }],
      concepts: ['docker.lifecycle'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 5,
    scenario: {
      organisation: 'corp.lab: the development team built an inventory application (API + PostgreSQL) and hands it over to operations.',
      situation: 'The Compose project is on dock01, as the developers left it: the database published to the whole network, no restart policy, the password in the file. Nothing runs yet.',
      goal: 'The inventory application running reliably in containers, reachable at http://apps.corp.lab/inventory/, with its data safe and its database closed to the network.',
      whyItMatters: 'Containers do not remove dependencies, they add layers: the image, the container network and its DNS, volumes, published ports, the host firewall, the daemon, and the proxy in front. Each is a place where "the app is down" can come from.',
    },
    technologies: ['Docker Engine and daemon.json', 'Docker Compose (services, networks, volumes, restart policies, .env)', 'Container DNS (service names)', 'PostgreSQL in a container', 'nftables and published ports', 'nginx reverse proxy'],
    systems: [
      { host: 'dock01', role: 'Docker host (10.0.20.40): the inventory project in /srv/inventory' },
      { host: 'srv01', role: 'Reverse proxy (nginx) for apps.corp.lab' },
      { host: 'ws01', role: 'alice: a user in the office, and the administrator' },
      { host: 'ns1', role: 'DNS: inventory.corp.lab and apps.corp.lab' },
    ],
    startingState: [
      'dock01: Docker installed with defaults; the project files in /srv/inventory as delivered (published database, no restart policy, the password in compose.yaml).',
      'srv01: nginx serves the intranet; there is no apps.corp.lab server block yet.',
      'dock01\'s firewall: Debian\'s default (nothing configured).',
    ],
    tools: [
      { command: 'docker compose up -d / ps / logs / config', platform: 'Linux', use: 'Deploy and inspect the project', refId: 'docker-compose' },
      { command: 'docker inspect, docker network inspect', platform: 'Linux', use: 'Container addresses, networks, restart policies', refId: 'docker-inspect' },
      { command: 'docker logs CONTAINER', platform: 'Linux', use: 'Why a container exits or restarts', refId: 'docker-logs' },
      { command: 'docker volume ls', platform: 'Linux', use: 'Where the data lives', refId: 'docker' },
      { command: 'nginx -t, systemctl reload nginx', platform: 'Linux', use: 'The reverse proxy', refId: 'nginx' },
      { command: 'curl -s, nc -z -w 3', platform: 'Linux', use: 'Test each link: proxy, published port, database port', refId: 'curl' },
      { command: 'nft list ruleset', platform: 'Linux', use: 'Host firewall and Docker\'s own rules', refId: 'nft' },
    ],
    dependencies: {
      explanation: `A user's request to http://apps.corp.lab/inventory/health travels:

1. **DNS**: apps.corp.lab → srv01.
2. **nginx on srv01** matches the server_name and location, and opens a new connection to the **upstream** dock01.corp.lab:8000 (resolved by srv01).
3. **dock01's firewall** must let srv01 in; Docker's **published port** forwards 8000 to the app container.
4. **The app container** connects to **db** on the project network: Docker's embedded DNS resolves the **service name** to the database container.
5. **The database container** stores its files in the **volume** pgdata.

The application has dependencies the user never sees (4 and 5). When /health fails, follow the chain from the outside in: proxy → published port → container state and logs → database.`,
      paths: [
        {
          id: 'user', label: 'alice opens http://apps.corp.lab/inventory/health',
          nodes: [
            hop('dns', 'apps.corp.lab resolves', 'CNAME to srv01 in the corp.lab zone.', 'ws01', 'alice', 'getent hosts apps.corp.lab', (o, c) => c === 0 && /apps\.corp\.lab/.test(o)),
            hop('proxy', 'The proxy answers', 'nginx on srv01 listens on 80.', 'ws01', 'alice', 'nc -z -w 3 apps.corp.lab 80', (_o, c) => c === 0),
            hop('upstream', 'The proxy reaches the backend', 'srv01 → dock01:8000 (firewall, published port).', 'srv01', 'root', 'curl -s -m 5 http://dock01.corp.lab:8000/health', (o, c) => c === 0 && o.trim() !== ''),
            hop('app', 'The app answers through the proxy', 'The full path, including the app\'s database connection.', 'ws01', 'alice', 'curl -s -m 5 http://apps.corp.lab/inventory/health', (o, c) => c === 0 && !/50\d|404/.test(o.split('\n')[0] ?? '') && o.trim() !== ''),
          ],
        },
        {
          id: 'containers', label: 'inside dock01: the app and its database',
          nodes: [
            hop('running', 'Both containers run', 'docker compose ps: Up, not Restarting.', 'dock01', 'root', 'docker ps', (o) => /inventory-app-1/.test(o) && /inventory-db-1/.test(o) && !/Restarting/.test(o)),
            hop('volume', 'The data volume exists', 'pgdata: the database files outside the container.', 'dock01', 'root', 'docker volume ls', (o) => /inventory_pgdata/.test(o)),
            hop('db-closed', 'The database is not published', 'Only the app talks to it, over the project network.', 'ws01', 'alice', 'nc -z -w 3 dock01.corp.lab 5432', (_o, c) => c !== 0),
          ],
        },
      ],
    },
    mistakes: [
      'Leaving "ports: 5432:5432" on the database: Docker publishes it past the host firewall to every network.',
      'No restart policy: everything works until the host reboots.',
      'Fixing a restarting container with docker restart, without reading its logs.',
      'Renaming a Compose service without changing the clients that use its name (DB_HOST).',
      'Testing only on dock01 (curl localhost:8000): the proxy, DNS and firewall are not tested at all.',
    ],
    verification: 'The checks inspect Docker\'s real state (containers, restart policies, published ports, volumes, the daemon\'s settings) and test from the outside (from ws01 and through the proxy on srv01). The final check reboots every machine on a copy and repeats them. The incident is repaired when the application answers again after a reboot.',
    fault: ticketFault('docker-renamed-service', {
      title: 'The inventory application keeps restarting',
      report: 'Users (09:15): "http://apps.corp.lab/inventory/ shows 502 Bad Gateway." A teammate: "I only cleaned up compose.yaml (renamed the database service to postgres, it is clearer) and redeployed with docker compose down and up. The database is running fine."',
    }),
    review: [
      { id: 'q1', question: 'The app container cannot find its database after the database service was renamed from "db" to "postgres". Why?', choices: ['The app connects to the service name in DB_HOST ("db"), which no longer exists on the project network', 'Renaming deletes the volume', 'The host firewall blocks the new name', 'nginx caches the old container'], answer: 0, explanation: 'Docker\'s embedded DNS resolves service names on the project network. A client configured with the old name gets "could not translate host name".', concepts: ['docker.networking'] },
      { id: 'q2', question: 'Why remove "ports: 5432:5432" from the database service?', choices: ['Published ports bypass the host\'s input rules and expose the database to every network; the app reaches it over the project network anyway', 'PostgreSQL cannot run with a published port', 'It disables the volume', 'Compose forbids two published ports'], answer: 0, explanation: 'Docker inserts NAT and forward rules for published ports. Containers on the same project network talk directly; nothing outside needs 5432.', concepts: ['docker.networking'] },
      { id: 'q3', question: 'Through the proxy you get 502 Bad Gateway. What does that tell you?', choices: ['nginx works, but its connection to the upstream failed (nothing listening, or refused)', 'DNS for apps.corp.lab is wrong', 'The browser has no network', 'The database volume is full'], answer: 0, explanation: '502 is generated by the proxy: it reached its own configuration and failed on the upstream. 504 would mean the upstream did not answer in time.', concepts: ['web.proxy'] },
      { id: 'q4', question: 'Where is the database\'s data after "docker compose down" and "up"?', choices: ['In the named volume pgdata, which down keeps (unless -v)', 'Lost: containers are recreated', 'In the image', 'On srv01'], answer: 0, explanation: 'Containers are disposable; the volume is not removed by down unless you add -v.', concepts: ['docker.lifecycle'] },
      { id: 'q5', question: 'A container shows "Restarting (1) 5 seconds ago". What is the first thing to look at?', choices: ['docker logs of that container: why its process exits', 'docker restart it again', 'Reboot the host', 'The proxy\'s configuration'], answer: 0, explanation: 'The restart policy keeps restarting a process that exits; its own log says why (here: the database name does not resolve).', concepts: ['docker.lifecycle'] },
    ],
    after: ['docker', 'webproxy', 'database', 'nftables'],
  },
};

