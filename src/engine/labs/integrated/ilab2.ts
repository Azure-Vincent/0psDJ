// Integrated Lab 2: Deploy and Secure a Linux Web Server. A new server, web03,
// must serve the intranet "intranet.corp.lab" and be administered remotely.
// The page only reaches people when DNS, the web server's configuration, file
// permissions, the host firewall and the service manager all agree; SSH must
// be key-only and reachable from the office only.

import { mkdir, readFile, writeFile } from '../../fs';
import { buildSshLab } from '../../lab/sshLab';
import { script } from '../../scenarios/engine';
import type { World } from '../../types';
import { NO, OK, printfTo, probe } from '../engine';
import type { GuidedLab, LabCheck } from '../types';
import { addServer, cmdCheck, evidence, hop } from './common';

export const WEB03_IP = '10.0.20.13';
export const WEB03_ALICE = 'web03-alice';

export const WEB03_NGINX = `user www-data;
worker_processes auto;
http {
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
    }
}
`;

/** Debian's nftables.conf after the installer's "server" profile: SSH from anywhere, nothing else. */
export const WEB03_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const PAGE = '<!doctype html>\n<title>corp.lab intranet</title>\n<h1>corp.lab intranet</h1>\n<p>Phone list, forms and the canteen menu.</p>\n';

export function buildIlab2World(): World {
  const w = buildSshLab();
  addServer(w, {
    id: 'web03', ip: WEB03_IP, port: 'swp23', mac: '52:54:00:3b:00:0d', portMac: '52:54:00:5e:00:17', alias: 'web03 (intranet)',
    role: 'Intranet web server (new)', services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'nginx'], nft: WEB03_NFT, alicePassword: WEB03_ALICE,
  }, (h, t) => {
    mkdir(h, '/etc/nginx', t);
    writeFile(h, '/etc/nginx/nginx.conf', WEB03_NGINX, t);
    for (const d of ['/var/www', '/var/www/html']) if (!h.fs[d]) mkdir(h, d, t);
    writeFile(h, '/var/www/html/index.nginx-debian.html', '<!DOCTYPE html>\n<title>Welcome to nginx!</title>\n<h1>Welcome to nginx!</h1>\n', t);
    // The web team copied the site as alice: her umask and mode 0700 on the directory.
    if (!h.fs['/srv']) mkdir(h, '/srv', t);
    mkdir(h, '/srv/intranet', t, { mode: 0o700, owner: 'alice', group: 'alice' });
    writeFile(h, '/srv/intranet/index.html', PAGE, t, { mode: 0o600, owner: 'alice', group: 'alice' });
  });
  w.clock += 5 * 60_000;
  return w;
}

// ---------------------------------------------------------------- checks

const dnsNames: LabCheck = {
  id: 'dns', description: 'web03.corp.lab (A 10.0.20.13) and intranet.corp.lab (CNAME web03) resolve for every client',
  check(w) {
    const z = readFile(w.hosts.ns1, '/etc/bind/db.corp.lab') ?? '';
    if (!/^web03\s+(IN\s+)?A\s+10\.0\.20\.13\s*$/m.test(z)) return NO('The corp.lab zone has no "web03 IN A 10.0.20.13" record.');
    if (!/^intranet\s+(IN\s+)?CNAME\s+web03(\.corp\.lab\.)?\s*$/m.test(z)) return NO('The corp.lab zone has no "intranet IN CNAME web03" record: users should use the service name, not the server name.');
    if (Number(/(\d+)\s*;\s*serial/i.exec(z)?.[1] ?? 0) <= 2026101901) return NO('The serial was not increased.');
    const r = probe(w, 'ws01', 'alice', 'getent hosts intranet.corp.lab');
    if (!/^10\.0\.20\.13\s/m.test(r.output)) return NO(`intranet.corp.lab does not resolve for clients yet (named-checkzone, rndc reload).\n${evidence('ws01', 'alice', 'getent hosts intranet.corp.lab', r.output, r.code)}`);
    return OK('Both names resolve.');
  },
};

const siteServed: LabCheck = {
  id: 'site', description: 'nginx on web03 serves /srv/intranet for intranet.corp.lab (configuration checked, reloaded, files readable by www-data)',
  check(w) {
    const conf = readFile(w.hosts.web03, '/etc/nginx/nginx.conf') ?? '';
    if (!/root\s+\/srv\/intranet\/?\s*;/.test(conf)) return NO('/etc/nginx/nginx.conf does not serve /srv/intranet (root /srv/intranet;).');
    if (!/server_name[^;]*\bintranet\.corp\.lab\b/.test(conf)) return NO('The server block has no "server_name intranet.corp.lab": name the site it serves.');
    if (w.hosts.web03.services.nginx?.state !== 'active') return NO('nginx is not running on web03 (nginx -t; journalctl -u nginx).');
    const r = probe(w, 'web03', 'root', 'curl -s http://127.0.0.1/');
    if (!/corp\.lab intranet/.test(r.output)) {
      const log = (readFile(w.hosts.web03, '/var/log/nginx/error.log') ?? '').trim().split('\n').pop() ?? '';
      return NO(`web03 does not serve the intranet page (yet): ${/403/.test(r.output) ? '403 Forbidden. The worker runs as www-data: can it enter /srv/intranet and read index.html?' : 'reload nginx after changing its configuration.'}${log ? `\nerror.log: ${log}` : ''}\n${evidence('web03', 'root', 'curl -s http://127.0.0.1/', r.output, r.code)}`);
    }
    const perm = w.hosts.web03.fs['/srv/intranet'];
    if (perm && (perm.mode & 0o002)) return NO('/srv/intranet is world-writable: anyone on web03 could change the site. 755 is enough.');
    return OK('nginx serves the intranet page.');
  },
};

const firewallOk: LabCheck = {
  id: 'firewall', description: 'web03\'s firewall (persistent): HTTP from the internal networks (10.0.0.0/8), SSH only from the office (10.0.10.0/24)',
  check(w) {
    const nft = readFile(w.hosts.web03, '/etc/nftables.conf') ?? '';
    if (!/dport\s+(80|\{[^}]*\b80\b[^}]*\})/.test(nft)) return NO('/etc/nftables.conf on web03 does not open TCP 80.');
    const fromWs = probe(w, 'ws01', 'alice', `curl -sI -m 5 http://${WEB03_IP}/`);
    if (!/^HTTP\/1\.1 (200|404|403)/.test(fromWs.output)) return NO(`ws01 cannot reach web03 on port 80.\n${evidence('ws01', 'alice', `curl -sI -m 5 http://${WEB03_IP}/`, fromWs.output, fromWs.code)}`);
    const fromDev = probe(w, 'dev01', 'root', `curl -sI -m 5 http://${WEB03_IP}/`);
    if (!/^HTTP\/1\.1 /.test(fromDev.output)) return NO('dev01 (VLAN 30, 10.0.30.25) cannot reach the intranet: allow HTTP from all internal networks (10.0.0.0/8).');
    const sshDev = probe(w, 'dev01', 'root', `nc -z -w 3 ${WEB03_IP} 22`);
    if (sshDev.code === 0) return NO('SSH on web03 is reachable from VLAN 30 (dev01): allow TCP 22 from 10.0.10.0/24 only.');
    const sshWs = probe(w, 'ws01', 'alice', `nc -z -w 3 ${WEB03_IP} 22`);
    if (sshWs.code !== 0) return NO('SSH on web03 is no longer reachable from the office (ws01): keep TCP 22 open for 10.0.10.0/24.');
    return OK('HTTP for the company, SSH for the office only.');
  },
};

const sshKeys: LabCheck = {
  id: 'ssh', description: 'alice logs in to web03 from ws01 with her key; password logins and root logins are refused',
  check(w) {
    const k = probe(w, 'ws01', 'alice', 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new web03.corp.lab hostname');
    if (!/^web03$/m.test(k.output)) return NO(`alice cannot log in with her key yet (ssh-copy-id from ws01).\n${evidence('ws01', 'alice', 'ssh -o BatchMode=yes web03.corp.lab hostname', k.output, k.code)}`);
    const p = probe(w, 'ws01', 'alice', 'ssh -o PubkeyAuthentication=no -o BatchMode=yes -o StrictHostKeyChecking=accept-new web03.corp.lab true');
    if (!/Permission denied \(publickey\)/.test(p.output)) return NO(`sshd on web03 still offers password authentication: set PasswordAuthentication no (sshd -t, then reload ssh).\n${evidence('ws01', 'alice', 'ssh -o PubkeyAuthentication=no web03.corp.lab', p.output, p.code)}`);
    const all = Object.entries(w.hosts.web03.fs).filter(([path]) => path === '/etc/ssh/sshd_config' || path.startsWith('/etc/ssh/sshd_config.d/')).map(([, n]) => n.content ?? '').join('\n');
    if (!/^\s*PermitRootLogin\s+no\b/m.test(all)) return NO('Set PermitRootLogin no: administrators log in as themselves and use sudo.');
    return OK('Key-only SSH for alice; no root logins.');
  },
};

const pageByName: LabCheck[] = [
  cmdCheck('page-ws01', 'From ws01, http://intranet.corp.lab shows the intranet page', 'ws01', 'alice', 'curl -s -m 5 http://intranet.corp.lab/', (o) => (/corp\.lab intranet/.test(o) ? null : 'The intranet page does not load by name from the office.'), 'DNS, firewall and nginx work together.'),
  cmdCheck('nginx-enabled', 'nginx starts at boot on web03', 'web03', 'root', 'systemctl is-enabled nginx', (o) => (/^enabled/m.test(o) ? null : 'nginx is not enabled: after a reboot the site would be down.'), 'Enabled.'),
];

// ---------------------------------------------------------------- the lab

const NGINX_DONE = `user www-data;
worker_processes auto;
http {
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name intranet.corp.lab web03.corp.lab;
        root /srv/intranet;
        index index.html;
    }
}
`;
const NFT_DONE = WEB03_NFT.replace('\t\ttcp dport 22 accept\n', '\t\t# SSH for the administrators in the office only (CHG-3102)\n\t\tip saddr 10.0.10.0/24 tcp dport 22 accept\n\t\t# The intranet for every internal network\n\t\tip saddr 10.0.0.0/8 tcp dport 80 accept\n');

export const ILAB2: GuidedLab = {
  id: 'ilab2',
  title: 'Integrated Lab 2: Deploy and Secure a Linux Web Server',
  level: 'beginner',
  duration: '45–75 min',
  summary: 'Put a new intranet server into service: DNS names, an nginx site whose files the web server can actually read, a host firewall that lets the company in and keeps SSH for the office, key-only SSH administration, and a site that survives a reboot. Then find out why the intranet is down after a "small" configuration change.',
  brief: `The intranet moves to its own server, **web03** (${WEB03_IP}, VLAN 20). Debian 12 and nginx are installed; the web team copied the site to **/srv/intranet**. Make it a production service (CHG-3102):

- Users open **http://intranet.corp.lab**; the server itself is **web03.corp.lab**.
- nginx must serve /srv/intranet for that name.
- The firewall: HTTP for every internal network (10.0.0.0/8), SSH only from the office (10.0.10.0/24).
- Administration over SSH with keys only: alice (from ws01) uses her key; no passwords, no root logins. Her initial password on web03 is \`${WEB03_ALICE}\`.
- Everything must still work after a reboot.`,
  objectives: [
    'Publish a service under a service name (CNAME) and a server name (A).',
    'Configure an nginx site and read its error log; fix file permissions for the worker user.',
    'Write a host firewall that matches who needs what (HTTP for all, SSH for the office).',
    'Set up key-based SSH and disable passwords without locking yourself out.',
    'Tell "the command worked" from "the service works", and diagnose a failed restart from the journal.',
  ],
  prerequisites: [
    { label: 'SSH', link: 'lesson/ssh/what' },
    { label: 'systemd services', link: 'lesson/systemd/what' },
    { label: 'Host firewalls (nftables)', link: 'lesson/nftables/what' },
    { label: 'TCP, UDP and DNS', link: 'lesson/transport/what' },
  ],
  setupNote: `This lab adds **web03** (${WEB03_IP}) on sw01 port swp23 (VLAN 20). It is running, but has no DNS name yet.`,
  terminals: [
    { hostId: 'web03', user: 'root', label: 'web03 console (root)', banner: 'web03 console (root). nginx serves Debian\'s default page; the site is in /srv/intranet. Try: systemctl status nginx, nginx -t, ls -ld /srv/intranet, ss -tlnp, nft list ruleset.' },
    { hostId: 'ns1', user: 'root', label: 'ns1 (DNS)', banner: 'ns1 (root): BIND, zone file /etc/bind/db.corp.lab. Try: named-checkzone corp.lab /etc/bind/db.corp.lab, rndc reload.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice, office)', banner: 'ws01 (alice), a workstation in the office. Try: getent hosts intranet.corp.lab, curl -s http://intranet.corp.lab/, ssh web03.corp.lab.' },
    { hostId: 'dev01', user: 'root', label: 'dev01 (VLAN 30)', banner: 'dev01 (root), a machine in the development VLAN (10.0.30.25): it may use the intranet but not SSH to web03.' },
  ],
  build: buildIlab2World,
  steps: [
    {
      id: 'dns', title: 'Names for the server and the service',
      objective: 'web03.corp.lab and intranet.corp.lab resolve to 10.0.20.13 for every client.',
      background: 'Users should type a **service name** (intranet.corp.lab), not a server name: when the service moves, only the CNAME changes. The server itself gets an **A record** (web03.corp.lab). A CNAME points at a name, never at an address.',
      tasks: [
        'On ns1: back up the zone, then add `web03   IN A    10.0.20.13` and `intranet IN CNAME web03`, and increase the serial.',
        '`named-checkzone corp.lab /etc/bind/db.corp.lab`, then `rndc reload`.',
        'From ws01: `getent hosts intranet.corp.lab`.',
      ],
      hints: ['A relative name in the zone (web03) means web03.corp.lab; "web03.corp.lab" without the final dot would become web03.corp.lab.corp.lab.'],
      checks: [dnsNames],
      solution: [{ host: 'ns1', user: 'root', commands: ['cp -a /etc/bind/db.corp.lab /root/db.corp.lab.bak', "sed -i 's/2026101901 ; serial/2026110201 ; serial/' /etc/bind/db.corp.lab", "printf 'web03   IN A    10.0.20.13\\nintranet IN CNAME web03\\n' >> /etc/bind/db.corp.lab", 'named-checkzone corp.lab /etc/bind/db.corp.lab', 'rndc reload'] }],
      commands: [
        { host: 'ns1', command: 'named-checkzone corp.lab /etc/bind/db.corp.lab', what: 'Loads the zone file as named would and reports errors.', why: 'One typo makes the whole zone fail to load: every corp.lab name would stop resolving.', where: '/etc/bind/db.corp.lab', success: '"loaded serial …" and "OK".', verify: 'After rndc reload: getent hosts intranet.corp.lab on a client.' },
      ],
      learn: [{ label: 'DNS records', link: 'lesson/transport/internals' }, { label: 'Zone changes', link: 'reference?id=proc:bind-zone-change' }],
      concepts: ['dns.zone', 'dns.resolution'],
    },
    {
      id: 'site', title: 'Serve the site (and let nginx read it)',
      objective: 'nginx on web03 serves /srv/intranet for intranet.corp.lab.',
      background: 'nginx reads **/etc/nginx/nginx.conf** (on a full Debian install also sites-enabled/; here everything is in nginx.conf). A `server` block says which names (**server_name**) it answers and where the files are (**root**). Always check with `nginx -t` before `systemctl reload nginx`: a reload with a broken file is refused and the old configuration keeps running.\n\nThe master process runs as root, but the **workers that read files run as www-data**. They need **x** on every directory of the path and **r** on the files. The site was copied with mode 0700/0600 for alice: nginx answers **403 Forbidden** and logs the reason in /var/log/nginx/error.log.',
      tasks: [
        'Look: `systemctl status nginx`, `curl -s http://localhost/` (the default page), `ls -ld /srv/intranet /srv/intranet/index.html`.',
        'In /etc/nginx/nginx.conf: `server_name intranet.corp.lab web03.corp.lab;`, `root /srv/intranet;`, `index index.html;`. Then `nginx -t` and `systemctl reload nginx`.',
        '`curl -s http://127.0.0.1/`: if it says 403, read `tail -n 3 /var/log/nginx/error.log`, then `chmod 755 /srv/intranet` and `chmod 644 /srv/intranet/index.html`.',
      ],
      hints: ['"(13: Permission denied)" in error.log is about the worker user www-data, not root.', 'chmod -R 777 "works" but lets anyone change the site: give read (and x on directories) only.'],
      checks: [siteServed],
      solution: [{ host: 'web03', user: 'root', commands: [printfTo(NGINX_DONE, '/etc/nginx/nginx.conf'), 'nginx -t', 'systemctl reload nginx', 'chmod 755 /srv/intranet', 'chmod 644 /srv/intranet/index.html', 'curl -s http://127.0.0.1/'] }],
      commands: [
        { host: 'web03', command: 'nginx -t', what: 'Parses the configuration and reports the first error with file and line.', why: 'A reload with an invalid file is refused; a restart with one leaves the service stopped.', where: '/etc/nginx/nginx.conf (and the files it includes).', success: '"syntax is ok" and "test is successful".', verify: 'systemctl reload nginx, then curl the site.' },
        { host: 'web03', command: 'tail -n 3 /var/log/nginx/error.log', what: 'Shows nginx\'s own errors: files it could not open, upstreams it could not reach.', why: 'A 403 or 500 page says that something failed; the error log says what.', where: '/var/log/nginx/error.log (access.log has one line per request).', success: 'Lines like: open() "/srv/intranet/index.html" failed (13: Permission denied).', verify: 'After the fix, the same request returns 200 and adds no new error line.' },
      ],
      learn: [{ label: 'Web servers (nginx)', link: 'lesson/webproxy/what' }, { label: 'nginx.conf', link: 'reference?id=file:nginx-conf' }, { label: 'namei (path permissions)', link: 'reference?id=namei' }],
      concepts: ['linux.permissions', 'svc.systemd'],
    },
    {
      id: 'firewall', title: 'Open HTTP, close SSH to the office',
      objective: 'web03\'s firewall lets every internal network reach HTTP, and only the office reach SSH; the rules are in /etc/nftables.conf.',
      background: 'The installer\'s firewall allows SSH from anywhere and nothing else: the web server answers locally but nobody else gets through (connections **time out**, because the policy drops silently). Decide per service **who** needs it: the intranet is for everyone inside (10.0.0.0/8); administration only from the office (10.0.10.0/24).\n\nIf you are logged in over SSH while you change SSH rules, keep the console open: a mistake would lock you out.',
      tasks: [
        'From ws01: `curl -sI -m 5 http://10.0.20.13/` times out. On web03: `nft list ruleset`.',
        'In /etc/nftables.conf replace `tcp dport 22 accept` with `ip saddr 10.0.10.0/24 tcp dport 22 accept` and add `ip saddr 10.0.0.0/8 tcp dport 80 accept`.',
        '`nft -c -f /etc/nftables.conf`, then `nft -f /etc/nftables.conf`. Test from ws01 (HTTP and SSH) and from dev01 (HTTP yes, `nc -z -w 3 10.0.20.13 22` no).',
      ],
      hints: ['A timeout means a silent drop somewhere in the path; "connection refused" means the host answered that nothing listens.'],
      checks: [firewallOk],
      solution: [{ host: 'web03', user: 'root', commands: [printfTo(NFT_DONE, '/etc/nftables.conf'), 'nft -c -f /etc/nftables.conf', 'nft -f /etc/nftables.conf'] }],
      commands: [
        { host: 'web03', command: 'nft -f /etc/nftables.conf', what: 'Replaces the running ruleset with the file (it begins with flush ruleset).', why: 'The file is what is loaded at boot: editing it and loading it keeps runtime and boot identical.', where: '/etc/nftables.conf, loaded by nftables.service.', success: 'No output.', verify: 'Test from each kind of client: allowed ones connect, others time out.' },
      ],
      learn: [{ label: 'Firewall rules', link: 'lesson/nftables/config' }, { label: 'nft', link: 'reference?id=nft' }],
      concepts: ['fw.stateful', 'fw.path'],
    },
    {
      id: 'ssh', title: 'Key-only SSH administration',
      objective: 'alice logs in from ws01 with her key; sshd on web03 refuses passwords and root.',
      background: 'Passwords can be guessed and phished; a key cannot be typed into the wrong page. `ssh-copy-id` uses one last password login to append alice\'s public key to ~/.ssh/authorized_keys on web03. Then **PasswordAuthentication no** and **PermitRootLogin no** (in a drop-in under /etc/ssh/sshd_config.d/).\n\n**Order matters**: test the key login in a second session before you disable passwords, and check with `sshd -t` before reloading. A reload keeps existing sessions.',
      tasks: [
        'On ws01 (alice): `ssh-copy-id web03.corp.lab` (accept the host key, then alice\'s web03 password), then `ssh -o BatchMode=yes web03.corp.lab hostname`.',
        'On web03: `printf \'PasswordAuthentication no\\nPermitRootLogin no\\n\' > /etc/ssh/sshd_config.d/10-hardening.conf`, `sshd -t`, `systemctl reload ssh`.',
        'From ws01: `ssh -o PubkeyAuthentication=no web03.corp.lab` must now say "Permission denied (publickey)".',
      ],
      hints: ['If the key login does not work, keep passwords on and look at /var/log/auth.log (or journalctl -u ssh) on web03.'],
      checks: [sshKeys],
      solution: [
        { host: 'ws01', user: 'alice', commands: ['ssh-copy-id web03.corp.lab'], answers: ['yes', WEB03_ALICE] },
        { host: 'web03', user: 'root', commands: ["printf 'PasswordAuthentication no\\nPermitRootLogin no\\n' > /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t', 'systemctl reload ssh'] },
      ],
      commands: [
        { host: 'ws01', command: 'ssh-copy-id web03.corp.lab', what: 'Logs in (with a password, one last time) and appends your public key to ~/.ssh/authorized_keys on the server, with the right permissions.', why: 'Key authentication needs the public key on the server; doing it by hand often gets the modes wrong (StrictModes then ignores the file).', where: 'Server: ~alice/.ssh/authorized_keys; client: ~/.ssh/id_ed25519(.pub).', success: '"Number of key(s) added: 1".', verify: 'ssh -o BatchMode=yes web03.corp.lab hostname answers without asking anything.' },
        { host: 'web03', command: 'sshd -t', what: 'Checks the sshd configuration (including the drop-ins) without touching the running daemon.', why: 'A broken sshd_config makes the next restart fail, and then nobody can log in.', where: '/etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf', success: 'No output.', verify: 'Try both methods from a client after systemctl reload ssh.' },
      ],
      learn: [{ label: 'SSH authentication', link: 'lesson/ssh/internals' }, { label: 'sshd -t', link: 'reference?id=sshd-t' }, { label: 'Safe sshd restart', link: 'reference?id=proc:sshd-safe-restart' }],
      concepts: ['ssh.userauth', 'ssh.authorized-keys'],
    },
    {
      id: 'verify', title: 'Verify as a user, and after a reboot', stage: 'verify',
      objective: 'The intranet works by name from the office, nginx starts at boot, and every check passes after all machines restart.',
      background: '`systemctl reload nginx` returning 0 does not mean users can see the page. Test the whole chain the way a user does (name → network → firewall → nginx → files), then reboot: a service that was started by hand but not **enabled**, or a firewall rule that was only added at runtime, would be gone.',
      tasks: ['From ws01: `curl -s http://intranet.corp.lab/`.', 'On web03: `systemctl is-enabled nginx`, `ss -tlnp`.', 'Run the check: it reboots every machine on a copy and runs all checks again.'],
      hints: ['If the page fails only after the reboot: is nginx enabled? Is the firewall rule in the file?'],
      checks: pageByName,
      solution: [],
      learn: [{ label: 'systemd units', link: 'lesson/systemd/internals' }],
      concepts: ['svc.systemd', 'svc.listening'],
      afterReboot: true,
    },
  ],
  integrated: {
    number: 2,
    scenario: {
      organisation: 'corp.lab: the intranet (phone list, forms, the canteen menu) moves off the old shared server.',
      situation: 'web03 was installed yesterday: Debian, nginx with its default page, the site copied to /srv/intranet. Nobody can reach it, and the security team wants it locked down before it goes live.',
      goal: 'The intranet at http://intranet.corp.lab for every internal network, administered over key-only SSH from the office.',
      whyItMatters: 'Most web outages are not nginx bugs: a missing DNS record, a file the worker cannot read, a firewall that drops, a service that is not enabled. Seeing all of them on one server teaches where to look.',
    },
    technologies: ['DNS (A and CNAME records)', 'nginx', 'Linux file permissions', 'nftables host firewall', 'SSH keys and sshd hardening', 'systemd (enable, reload, journal)'],
    systems: [
      { host: 'web03', role: `New intranet server ${WEB03_IP} (nginx, sshd, nftables)` },
      { host: 'ns1', role: 'DNS for corp.lab (10.0.10.53)' },
      { host: 'ws01', role: 'alice\'s workstation in the office (10.0.10.25), with her SSH key' },
      { host: 'dev01', role: 'A machine in the development VLAN (10.0.30.25): may browse, may not administer' },
    ],
    startingState: [
      'web03 runs nginx with Debian\'s default page (root /var/www/html); the site is in /srv/intranet, mode 0700, owned by alice.',
      'Firewall: SSH from anywhere, everything else dropped.',
      'sshd: Debian defaults (passwords allowed); alice has a password but no authorized key.',
      'DNS: no record for web03 or intranet.',
    ],
    tools: [
      { command: 'systemctl status / reload / is-enabled nginx', platform: 'Linux', use: 'Service state, applying configuration, start at boot', refId: 'systemctl' },
      { command: 'nginx -t', platform: 'Linux', use: 'Check the configuration before reloading', refId: 'nginx' },
      { command: 'ls -ld, namei -l /srv/intranet/index.html', platform: 'Linux', use: 'Permissions along a path', refId: 'namei' },
      { command: 'ss -tlnp', platform: 'Linux', use: 'Which process listens on which port', refId: 'ss' },
      { command: 'nft list ruleset, nft -c -f, nft -f', platform: 'Linux', use: 'Host firewall', refId: 'nft' },
      { command: 'curl -sI, curl -s -H "Host: …"', platform: 'Linux', use: 'Test the site as a client (and a specific server_name)', refId: 'curl' },
      { command: 'ssh-copy-id, sshd -t, ssh -v', platform: 'Linux', use: 'Keys, configuration check, client-side debugging', refId: 'ssh-v' },
      { command: 'journalctl -u nginx, tail /var/log/nginx/error.log', platform: 'Linux', use: 'Why a start failed / why a request failed', refId: 'journalctl' },
      { command: 'Test-NetConnection web03 -Port 80', platform: 'Windows', use: 'The same reachability test from a Windows client', refId: 'tnc' },
    ],
    dependencies: {
      explanation: `For alice's browser to show the intranet, in order:

1. **DNS**: intranet.corp.lab → (CNAME) web03.corp.lab → 10.0.20.13.
2. **Routing**: ws01 → rtr01 → VLAN 20 (already works).
3. **Host firewall** on web03: TCP 80 allowed from her network.
4. **A listening service**: nginx running (and enabled, so it comes back after a reboot), listening on port 80.
5. **The right site**: a server block for that name, with root /srv/intranet.
6. **Readable files**: the worker (www-data) can traverse the directories and read the file.

Administration is a separate chain: DNS → firewall (TCP 22 from the office) → sshd → key authentication.

A failure at step 3 looks like a **timeout**; at step 4 like **connection refused**; at steps 5–6 like an **HTTP error** (404, 403). The symptom tells you which layer to inspect.`,
      paths: [
        {
          id: 'ws01-intranet', label: 'alice (ws01) opens http://intranet.corp.lab',
          nodes: [
            hop('dns', 'Name resolves', 'intranet.corp.lab → web03.corp.lab → 10.0.20.13 (ns1).', 'ws01', 'alice', 'getent hosts intranet.corp.lab', (o) => /^10\.0\.20\.13\s/m.test(o)),
            hop('ping', 'web03 answers on the network', 'Routing through rtr01; ICMP allowed by web03\'s firewall.', 'ws01', 'alice', `ping -c 1 -W 2 ${WEB03_IP}`, (_o, c) => c === 0),
            hop('port', 'Port 80 open', 'web03\'s firewall lets TCP 80 in and nginx listens.', 'ws01', 'alice', `nc -z -w 3 ${WEB03_IP} 80`, (_o, c) => c === 0),
            hop('http', 'HTTP 200', 'nginx finds a server block and a readable file.', 'ws01', 'alice', 'curl -sI -m 5 http://intranet.corp.lab/', (o) => /^HTTP\/1\.1 200/.test(o)),
            hop('content', 'The intranet page', 'The right root: /srv/intranet, not the default page.', 'ws01', 'alice', 'curl -s -m 5 http://intranet.corp.lab/', (o) => /corp\.lab intranet/.test(o)),
          ],
        },
        {
          id: 'ws01-ssh', label: 'alice administers web03 over SSH',
          nodes: [
            hop('dns', 'web03.corp.lab resolves', 'The A record.', 'ws01', 'alice', 'getent hosts web03.corp.lab', (o) => /^10\.0\.20\.13\s/m.test(o)),
            hop('port', 'Port 22 open from the office', 'Firewall: TCP 22 from 10.0.10.0/24; sshd listens.', 'ws01', 'alice', `nc -z -w 3 ${WEB03_IP} 22`, (_o, c) => c === 0),
            hop('key', 'Key login', 'alice\'s public key in ~/.ssh/authorized_keys on web03.', 'ws01', 'alice', 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new web03.corp.lab hostname', (o) => /^web03$/m.test(o)),
          ],
        },
      ],
    },
    mistakes: [
      '`chmod -R 777` on the web root: it "works", and lets anyone on the server change the site.',
      'Disabling passwords before testing the key login (and losing the only way in).',
      'Reloading nginx without `nginx -t`, or restarting it with a broken file (the site goes down).',
      'Opening port 80 with `nft add rule` only: gone after the next reboot.',
      'Forgetting `systemctl enable`: the site works until the first reboot.',
    ],
    verification: 'The checks look at the running machines: DNS answers from a client, nginx serving the page for the right name, connections from the office and from VLAN 30, SSH logins with and without keys. The final check reboots everything and runs every check again. The incident is repaired when the site loads by name again after a reboot, with nginx\'s configuration valid.',
    fault: {
      title: 'The intranet is down after "a small change"',
      report: 'Reception (Tuesday 08:05): "The intranet does not load: the browser says it cannot connect." A colleague from the web team (Monday evening): "Security wants HTTPS everywhere, so I started on web03: I added the HTTPS listener and restarted nginx. The certificate request is still with the PKI team. It was late, I did not check the result."',
      inject(w) {
        const h = w.hosts.web03;
        writeFile(h, '/etc/nginx/nginx.conf', (readFile(h, '/etc/nginx/nginx.conf') ?? '').replace(/(listen \[::\]:80 default_server;\n)/, '$1        listen 443 ssl;\n'), w.clock);
        script(w, 'web03', ['systemctl restart nginx']);
      },
      rootCauses: ['web-config-error'],
      candidates: ['web-config-error', 'web-not-running', 'web-file-permissions', 'firewall-drop', 'dns-wrong-record', 'listen-loopback', 'service-not-enabled', 'routing-server-gateway'],
      hints: [
        '"Cannot connect" is not a 403 or a 404: is anything listening on port 80? `ss -tlnp` on web03; `nc -z -w 3 10.0.20.13 80` from ws01.',
        '`systemctl status nginx` and `journalctl -u nginx -n 10`: why did the restart fail? `nginx -t` names the file and line.',
        'An "ssl" listener needs a certificate and key. Until the certificate exists, remove (or comment out) the listen 443 line, `nginx -t`, then `systemctl start nginx`. Restarting again without a change does nothing.',
      ],
      checks: [
        cmdCheck('nginx-t', 'nginx\'s configuration on web03 is valid', 'web03', 'root', 'nginx -t', (_o, c) => (c === 0 ? null : 'nginx -t still reports an error.'), 'Configuration valid.'),
        ...pageByName,
      ],
      solution: [{ host: 'web03', user: 'root', commands: ["sed -i '/^        listen 443 ssl;$/d' /etc/nginx/nginx.conf", 'nginx -t', 'systemctl start nginx'] }],
      explanation: {
        rootCause: 'A "listen 443 ssl" directive without ssl_certificate and ssl_certificate_key is invalid: nginx refuses the whole configuration. The restart stopped the old nginx and the new one did not start, so nothing listens on port 80 either.',
        evidence: 'ws01: curl "Failed to connect … Connection refused" (not a timeout: the host answers, nothing listens); web03: systemctl status nginx failed; journalctl -u nginx and nginx -t: no "ssl_certificate" is defined for the "listen ... ssl" directive in /etc/nginx/nginx.conf:7; ss -tlnp shows no :80.',
        lesson: 'Check (nginx -t) before applying, prefer reload (which keeps the old configuration on error) to restart, and look at the result after every change. Repeated restarts never fix a configuration error.',
      },
      concepts: ['svc.systemd', 'logs.journal'],
    },
    review: [
      { id: 'q1', question: 'From ws01, curl to web03 port 80 "times out". On web03, curl http://localhost/ works. Which layer do you inspect first?', choices: ['web03\'s firewall (a silent drop)', 'nginx\'s server_name', 'The file permissions in /srv/intranet', 'The DNS record'], answer: 0, explanation: 'Locally the service works, so nginx, its files and its name are fine. A timeout from outside is a drop on the way: here web03\'s default-drop firewall.', concepts: ['fw.path'] },
      { id: 'q2', question: 'nginx returns 403 for /srv/intranet/index.html although root can read the file. Why?', choices: ['The workers run as www-data, which cannot traverse or read the files', 'nginx always refuses files outside /var/www', 'The firewall blocks the file', 'The CNAME points to the wrong server'], answer: 0, explanation: 'The master runs as root, the workers that serve requests as www-data. They need x on every directory in the path and r on the file; error.log says "(13: Permission denied)".', concepts: ['linux.permissions'] },
      { id: 'q3', question: 'Why add "intranet IN CNAME web03" instead of only an A record for intranet?', choices: ['The service name then follows the server: moving the service changes one record', 'CNAMEs are faster to resolve', 'nginx requires a CNAME for server_name', 'A records cannot point into VLAN 20'], answer: 0, explanation: 'Users and bookmarks keep the service name; only the CNAME target changes when the service moves to another server.', concepts: ['dns.zone'] },
      { id: 'q4', question: 'Which order is safe when you switch SSH to keys only?', choices: ['Install the key, test a key login in a second session, then disable passwords (sshd -t, reload)', 'Disable passwords, reload sshd, then copy the key', 'Restart sshd first so the key is loaded', 'Disable root, then reboot to test'], answer: 0, explanation: 'Once passwords are off, ssh-copy-id cannot log in any more. Keep a working session while testing, and check the configuration before reloading.', concepts: ['ssh.userauth'] },
      { id: 'q5', question: 'After adding an HTTPS listener and "systemctl restart nginx", even plain HTTP is down, and a second restart does not help. What does that tell you?', choices: ['nginx fails to start: read the reason (journalctl -u nginx, nginx -t) and fix it', 'The firewall needs a restart too', 'The server needs a reboot', 'DNS caches the old address'], answer: 0, explanation: 'A deterministic failure repeats on every restart. The journal and nginx -t give the file and line; only fixing the cause helps.', concepts: ['svc.systemd', 'logs.journal'] },
    ],
    after: ['ssh', 'systemd', 'nftables', 'webproxy'],
  },
};

