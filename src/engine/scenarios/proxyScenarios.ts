// Reverse-proxy tickets: srv01's nginx publishes the inventory API (on dock01)
// as http://apps.corp.lab/inventory/. Each ticket breaks the path between the
// proxy and its upstream: a wrong port (502), the location prefix leaking to the
// backend (404 from the app), an upstream name that does not resolve (nginx
// down after a reboot), a backend firewall that only allows the office (504),
// and https:// to a plain-HTTP backend (502).

import { readFile, writeFile } from '../fs';
import { SRV01_NGINX_CONF } from '../lab/pkiLab';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import { deployInventory } from './containerScenarios';
import { script } from './engine';
import type { Constraint, HttpGoal, Scenario } from './types';

export const APPS_UPSTREAM = 'http://dock01.corp.lab:8000/';

/** The apps.corp.lab server block on srv01 (CHG-2230). */
export function appsServerBlock(proxyPass = APPS_UPSTREAM): string {
  return `    # Internal applications behind the reverse proxy (CHG-2230)
    server {
        listen 80;
        server_name apps.corp.lab;
        location /inventory/ {
            proxy_pass ${proxyPass};
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
`;
}

/** srv01's nginx.conf with the apps.corp.lab block added before the closing brace of http { }. */
export const proxiedNginxConf = (proxyPass = APPS_UPSTREAM) => SRV01_NGINX_CONF.replace(/}\n$/, `${appsServerBlock(proxyPass)}}\n`);

/** Deploy the inventory app on dock01 and publish it through srv01's nginx. */
export function deployProxy(world: World, proxyPass = APPS_UPSTREAM): void {
  deployInventory(world);
  writeFile(world.hosts.srv01, '/etc/nginx/nginx.conf', proxiedNginxConf(proxyPass), world.clock);
  script(world, 'srv01', ['systemctl reload nginx']);
}

export const APPS_CHECK: HttpGoal = {
  kind: 'http', fromHost: 'ws01', fromUser: 'alice', url: 'http://apps.corp.lab/inventory/health',
  description: 'From ws01, http://apps.corp.lab/inventory/health answers 200 through the reverse proxy on srv01.',
};

const WWW_CHECK: HttpGoal = {
  kind: 'http', fromHost: 'ws01', fromUser: 'alice', url: 'https://www.corp.lab/',
  description: 'From ws01, the intranet site https://www.corp.lab/ (same nginx on srv01) answers 200.',
};

/** The fix must keep the documented design: apps.corp.lab proxies /inventory/ to the API on dock01. */
function proxyStillUsed(): Constraint {
  return {
    id: 'proxy-config', required: true,
    description: 'apps.corp.lab keeps proxying /inventory/ to the inventory API on dock01 (do not replace the proxy with a redirect or static files).',
    check(world) {
      const conf = readFile(world.hosts.srv01, '/etc/nginx/nginx.conf') ?? '';
      const ok = /server_name apps\.corp\.lab;[\s\S]*location \/inventory\/ \{[\s\S]*proxy_pass http:\/\/(dock01(\.corp\.lab)?|10\.0\.20\.40):8000\//.test(conf);
      return { id: this.id, ok, required: true, message: ok ? 'apps.corp.lab proxies /inventory/ to dock01:8000.' : 'The apps.corp.lab server block no longer proxies /inventory/ to dock01:8000/.' };
    },
  };
}

/** dock01's forward filter must stay restrictive (the office plus the proxy, not everybody). */
function dockForwardRestrictive(): Constraint {
  return {
    id: 'dock01-forward-policy', required: true,
    description: 'dock01 keeps a forward chain with policy drop and source-specific accept rules (allow the proxy, do not open port 8000 to everyone).',
    check(world) {
      const chains = world.hosts.dock01.nft.tables.filter((t) => t.name === 'filter' && t.family === 'inet').flatMap((t) => t.chains);
      const fwd = chains.find((c) => c.base?.hook === 'forward');
      if (!fwd || fwd.base!.policy !== 'drop') return { id: this.id, ok: false, required: true, message: 'dock01: the forward chain of table inet filter is gone or its policy is not drop: every network can now reach the published ports.' };
      const blanket = fwd.rules.find((r) => r.verdict?.kind === 'accept' && !r.matches.some((m) => m.kind === 'addr' || m.kind === 'ctstate'));
      if (blanket) return { id: this.id, ok: false, required: true, message: `dock01: forward rule handle ${blanket.handle} accepts traffic from any source.` };
      return { id: this.id, ok: true, required: true, message: 'dock01: forward policy drop with source-specific rules.' };
    },
  };
}

const DOCK01_ACL_NFT = `#!/usr/sbin/nft -f
# dock01 host firewall (SEC-120): only the office may use the applications.

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
		# inventory API: office clients (SEC-120)
		ip saddr 10.0.10.0/24 tcp dport 8000 accept
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const BRIEFING = [
  'srv01 (10.0.20.10) runs nginx 1.22: the intranet site https://www.corp.lab/ and, since CHG-2230, the reverse proxy http://apps.corp.lab/ (apps is a CNAME for srv01). Its server block in /etc/nginx/nginx.conf proxies /inventory/ to the inventory API on dock01 (http://dock01.corp.lab:8000/, a Docker Compose project in /srv/inventory).',
  'The API answers GET /health with 200 when it is connected to its database. It is also reachable directly at http://inventory.corp.lab:8000/ (the developers use that).',
  'Evidence on srv01: /var/log/nginx/error.log and access.log, nginx -t, journalctl -u nginx. On dock01: docker compose logs app (which paths reach the app), nft list ruleset.',
  'Fixes must survive a reboot. Keep apps.corp.lab a reverse proxy to dock01:8000 and keep the firewalls restrictive.',
];

const TERMINALS = [
  { hostId: 'srv01', user: 'root', label: 'srv01 console (root)', banner: 'srv01 console (the reverse proxy), logged in as root. Try: tail /var/log/nginx/error.log, nginx -t, systemctl status nginx, curl -sS -i http://dock01.corp.lab:8000/health.' },
  { hostId: 'dock01', user: 'root', label: 'dock01 console (root)', banner: 'dock01 console (the backend), logged in as root. Try: cd /srv/inventory && docker compose ps, docker compose logs app, nft list ruleset.' },
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01: a user\'s view. Try: curl -sS -i http://apps.corp.lab/inventory/health.' },
];

const CANDIDATES = ['proxy-upstream-port', 'proxy-uri-rewrite', 'proxy-upstream-unresolvable', 'proxy-backend-acl', 'proxy-upstream-scheme', 'web-not-running', 'dns-wrong-record', 'docker-port-loopback', 'firewall-drop'];

const NOT = {
  dns: 'apps.corp.lab resolves to srv01 and the answer comes from srv01\'s nginx (Server: nginx/1.22.1).',
  web: 'nginx on srv01 is running and answers: the error page is its own.',
  loopback: 'docker ps on dock01 shows 0.0.0.0:8000->8000/tcp, and the API answers from ws01 directly.',
  firewall: 'srv01 accepts port 80 (nginx answers); the problem is behind the proxy.',
};

const TICKETS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'proxy-bad-gateway',
    title: '502 Bad Gateway',
    difficulty: 'beginner',
    ticket: 'Since the proxy configuration was copied from the staging template this morning, http://apps.corp.lab/inventory/ answers "502 Bad Gateway". The developers: "The app is fine, http://inventory.corp.lab:8000/health works from my desk."',
    briefing: BRIEFING,
    goals: [APPS_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployProxy(world, 'http://dock01.corp.lab:8080/');
    },
    rootCauses: ['proxy-upstream-port'],
    candidates: CANDIDATES,
    feedback: {
      'proxy-uri-rewrite': 'The request never reaches the app: error.log shows the connection to the upstream itself was refused.',
      'proxy-upstream-unresolvable': 'nginx is running and resolved dock01.corp.lab (error.log names 10.0.20.40).',
      'proxy-backend-acl': 'The answer is immediate (a refusal, RST), not a 504 after a minute.',
      'proxy-upstream-scheme': 'proxy_pass uses http://; error.log shows "Connection refused", not an SSL handshake error.',
      'web-not-running': NOT.web,
      'dns-wrong-record': NOT.dns,
      'docker-port-loopback': NOT.loopback,
      'firewall-drop': NOT.firewall,
    },
    hints: [
      '502 means nginx could not get an answer from its upstream. The reason is in the proxy\'s error log: tail /var/log/nginx/error.log on srv01.',
      '"connect() failed (111: Connection refused) … upstream: "http://10.0.20.40:8080/health"": nothing listens on 8080 on dock01. Which port does the app publish? docker compose ps on dock01, or ss -tlnp.',
      'Fix proxy_pass in the apps.corp.lab block (http://dock01.corp.lab:8000/), test with nginx -t and apply with systemctl reload nginx.',
    ],
    explanation: {
      rootCause: 'proxy_pass points at port 8080 (the staging template\'s value); the inventory API is published on 8000.',
      manifestation: 'nginx accepts the client\'s request, opens its own TCP connection from srv01 to 10.0.20.40:8080 and gets a RST: it answers 502 Bad Gateway at once.',
      evidence: 'error.log: "connect() failed (111: Connection refused) while connecting to upstream … upstream: "http://10.0.20.40:8080/health""; docker compose ps on dock01: 0.0.0.0:8000->8000/tcp; curl from srv01 to :8000 works.',
      prevention: 'Test a proxy change from the proxy host itself first (curl the upstream URL from srv01), then through the proxy; keep environment-specific values (ports, hosts) out of copied templates.',
    },
    solution: [{ host: 'srv01', commands: ['sed -i \'s#proxy_pass http://dock01.corp.lab:8080/;#proxy_pass http://dock01.corp.lab:8000/;#\' /etc/nginx/nginx.conf', 'systemctl reload nginx'] }],
    constraints: [proxyStillUsed()],
    concepts: ['web.proxy'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'proxy-prefix-404',
    title: 'Every page is 404',
    difficulty: 'intermediate',
    ticket: 'After a colleague "cleaned up" the proxy configuration, every page under http://apps.corp.lab/inventory/ answers 404 Not Found. nginx -t is happy, nginx is running, and the error log is empty.',
    briefing: BRIEFING,
    goals: [APPS_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployProxy(world, 'http://dock01.corp.lab:8000');
    },
    rootCauses: ['proxy-uri-rewrite'],
    candidates: CANDIDATES,
    feedback: {
      'proxy-upstream-port': 'The proxy reaches the app (it is the app that answers 404, in JSON); a wrong port would give 502.',
      'proxy-upstream-unresolvable': 'nginx is running and the request reaches the backend.',
      'proxy-backend-acl': 'The answer comes immediately and from the app; nothing times out.',
      'proxy-upstream-scheme': 'proxy_pass uses http:// and the backend answers.',
      'web-not-running': NOT.web,
      'dns-wrong-record': NOT.dns,
      'docker-port-loopback': NOT.loopback,
      'firewall-drop': NOT.firewall,
    },
    hints: [
      'Look at the 404\'s body: curl -sS -i http://apps.corp.lab/inventory/health from ws01. Is that nginx\'s error page, or the application\'s?',
      'The body is JSON ({"detail":"Not found."}): the request reached the app, with a path it does not know. Which path? docker compose logs app on dock01 shows the requests it received.',
      'The app received /inventory/health. With proxy_pass http://dock01.corp.lab:8000; (no URI part) nginx passes the original path unchanged; with http://dock01.corp.lab:8000/ it replaces the matched prefix /inventory/ with /. Add the slash, nginx -t, systemctl reload nginx.',
    ],
    explanation: {
      rootCause: 'proxy_pass lost its trailing slash ("http://dock01.corp.lab:8000"). Without a URI part nginx forwards the full original URI (/inventory/health); the app only knows /health.',
      manifestation: 'Every request reaches the app and gets the app\'s 404. nginx has nothing to log as an error: from its point of view the upstream answered normally.',
      evidence: 'The 404 body is JSON, not nginx\'s HTML; docker compose logs app shows "GET /inventory/health"; access.log on srv01 shows 404 with no error.log line.',
      prevention: 'Know the proxy_pass URI rule (with a URI: prefix replaced; without: URI passed as is) and test a deep path, not only /, after every proxy change.',
    },
    solution: [{ host: 'srv01', commands: ['sed -i \'s#proxy_pass http://dock01.corp.lab:8000;#proxy_pass http://dock01.corp.lab:8000/;#\' /etc/nginx/nginx.conf', 'systemctl reload nginx'] }],
    constraints: [proxyStillUsed()],
    concepts: ['web.proxy'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'proxy-host-not-found',
    title: 'Everything on srv01 is down after the reboot',
    difficulty: 'intermediate',
    ticket: 'Monday, after the weekend\'s patch reboot of srv01, neither https://www.corp.lab/ nor http://apps.corp.lab/inventory/ loads ("connection refused"). On Friday a colleague moved the inventory API to a new name and reloaded nginx; "it was all fine on Friday evening".',
    briefing: BRIEFING,
    goals: [APPS_CHECK, WWW_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployProxy(world);
      world.clock += 3600_000;
      // Friday: the new name has a typo; the reload fails and the old configuration keeps running.
      writeFile(world.hosts.srv01, '/etc/nginx/nginx.conf', proxiedNginxConf('http://inventory-api.corp.lab:8000/'), world.clock);
      script(world, 'srv01', ['systemctl reload nginx']);
      world.clock += 60 * 3600_000;
      bootHost(world, world.hosts.srv01);
    },
    rootCauses: ['proxy-upstream-unresolvable'],
    candidates: CANDIDATES,
    feedback: {
      'proxy-upstream-port': 'nginx does not even start, so no upstream is contacted.',
      'proxy-uri-rewrite': 'nginx does not even start, so no request reaches the backend.',
      'proxy-backend-acl': 'Clients are refused by srv01 itself; nothing reaches dock01.',
      'proxy-upstream-scheme': 'nginx does not start; the error is about a host name, not TLS.',
      'web-not-running': 'True as a symptom (nothing listens on 80/443), but why did nginx not start? journalctl -u nginx gives the reason.',
      'dns-wrong-record': 'apps.corp.lab and www.corp.lab resolve to srv01; srv01 refuses the connections.',
      'docker-port-loopback': 'The backend is not involved yet: srv01 refuses the connection.',
      'firewall-drop': 'A refusal (RST) is the kernel answering "nothing listens", not a firewall drop (that would time out).',
    },
    hints: [
      'Both sites fail with "connection refused": nothing listens on srv01. systemctl status nginx, then journalctl -u nginx -n 20.',
      '"[emerg] host not found in upstream "inventory-api.corp.lab:8000"": nginx resolves every proxy_pass host name when it loads the configuration, and refuses to start if one fails. getent hosts inventory-api.corp.lab on srv01.',
      'Friday\'s reload failed with the same error, so nginx kept running the old configuration until the reboot. Use a name that exists (dock01.corp.lab, the inventory host), nginx -t, then systemctl start nginx.',
    ],
    explanation: {
      rootCause: 'proxy_pass names inventory-api.corp.lab, which does not exist in DNS. nginx resolves upstream names at load time; "host not found in upstream" is fatal, so nginx does not start, taking every site on srv01 down.',
      manifestation: 'On Friday the reload failed and nginx kept serving with the previous configuration (a failed reload is harmless at that moment, so nobody noticed). The reboot started nginx from the broken file: nothing listens on 80 or 443.',
      evidence: 'systemctl status nginx: failed; journalctl -u nginx: "[emerg] host not found in upstream "inventory-api.corp.lab:8000" in /etc/nginx/nginx.conf:…", also on Friday ("Reload failed for nginx.service"); getent hosts inventory-api.corp.lab returns nothing.',
      prevention: 'Always run nginx -t before a reload and read the result (systemctl reload reports failure, but the old configuration keeps running). Create DNS records before referencing them; for upstreams that may not resolve at boot, use an IP or a resolver with a variable in proxy_pass.',
    },
    solution: [{ host: 'srv01', commands: ['sed -i \'s#inventory-api.corp.lab#dock01.corp.lab#\' /etc/nginx/nginx.conf', 'systemctl start nginx'] }],
    constraints: [proxyStillUsed()],
    concepts: ['web.proxy', 'dns.resolution'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'proxy-gateway-timeout',
    title: '504 after a minute',
    difficulty: 'advanced',
    ticket: 'Since security applied firewall standard SEC-120 to dock01, http://apps.corp.lab/inventory/ spins for a minute and then shows "504 Gateway Time-out". Security: "the office is explicitly allowed to the inventory API; I tested http://inventory.corp.lab:8000/health from my desk and it works".',
    briefing: BRIEFING,
    goals: [APPS_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployProxy(world);
      world.clock += 3600_000;
      writeFile(world.hosts.dock01, '/etc/nftables.conf', DOCK01_ACL_NFT, world.clock, { mode: 0o755 });
      script(world, 'dock01', ['systemctl restart nftables', 'systemctl restart docker'], 5_000);
    },
    rootCauses: ['proxy-backend-acl'],
    candidates: CANDIDATES,
    feedback: {
      'proxy-upstream-port': 'A wrong port is refused at once (502); here the connection attempt times out.',
      'proxy-uri-rewrite': 'The request never reaches the app (error.log: "upstream timed out … while connecting").',
      'proxy-upstream-unresolvable': 'nginx is running and resolved dock01 (10.0.20.40 in error.log).',
      'proxy-upstream-scheme': 'proxy_pass uses http://; the TCP connection itself does not complete.',
      'web-not-running': NOT.web,
      'dns-wrong-record': NOT.dns,
      'docker-port-loopback': NOT.loopback,
      'firewall-drop': 'Close: it is a firewall drop, but on dock01 and only for the proxy\'s address. srv01 accepts the client.',
    },
    hints: [
      '504 = nginx gave up waiting for the upstream (proxy_connect_timeout, 60 s). error.log on srv01: "upstream timed out (110: Connection timed out) while connecting to upstream".',
      'The API works from ws01 but not from srv01: test from the proxy host itself, nc -zv -w 3 dock01.corp.lab 8000 on srv01. Who is the client of a proxied connection?',
      'dock01\'s forward chain accepts 10.0.10.0/24 only; proxied connections come from srv01 (10.0.20.10). Allow it (ip saddr { 10.0.10.0/24, 10.0.20.10 } or a second rule) in /etc/nftables.conf, then systemctl restart nftables and systemctl restart docker (the flush removes Docker\'s tables).',
    ],
    explanation: {
      rootCause: 'dock01\'s new forward filter accepts port 8000 only from the office network 10.0.10.0/24. A reverse proxy opens its own connection: the API sees srv01 (10.0.20.10) as the client, and its SYNs are dropped.',
      manifestation: 'nginx retries the connect until proxy_connect_timeout (60 s) and answers 504 Gateway Time-out. Direct tests from an office PC work, which makes the firewall look fine.',
      evidence: 'error.log: "upstream timed out (110: Connection timed out) while connecting to upstream"; nc from srv01 to dock01:8000 times out while it works from ws01; nft list chain inet filter forward on dock01 shows the source restriction.',
      prevention: 'When an application is published through a proxy, the backend\'s firewall must allow the proxy (and usually only the proxy). Test access rules from the machine that really connects.',
    },
    solution: [{ host: 'dock01', commands: ['sed -i \'s#ip saddr 10.0.10.0/24 tcp dport 8000 accept#ip saddr { 10.0.10.0/24, 10.0.20.10 } tcp dport 8000 accept#\' /etc/nftables.conf', 'systemctl restart nftables', 'systemctl restart docker'] }],
    constraints: [proxyStillUsed(), dockForwardRestrictive()],
    concepts: ['web.proxy', 'fw.path'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'proxy-tls-upstream',
    title: 'TLS everywhere',
    difficulty: 'intermediate',
    ticket: 'Following the audit finding "internal traffic must be encrypted", the proxy now talks to the inventory API over HTTPS. Since then http://apps.corp.lab/inventory/ answers "502 Bad Gateway". The API itself is unchanged.',
    briefing: BRIEFING,
    goals: [APPS_CHECK],
    terminals: TERMINALS,
    setup(world) {
      deployProxy(world, 'https://dock01.corp.lab:8000/');
    },
    rootCauses: ['proxy-upstream-scheme'],
    candidates: CANDIDATES,
    feedback: {
      'proxy-upstream-port': 'The TCP connection to 8000 succeeds; error.log reports an SSL handshake failure, not a refusal.',
      'proxy-uri-rewrite': 'The request never reaches the app: the TLS handshake fails first.',
      'proxy-upstream-unresolvable': 'nginx is running and resolved dock01.',
      'proxy-backend-acl': 'The answer is immediate, and the connection is established.',
      'web-not-running': NOT.web,
      'dns-wrong-record': NOT.dns,
      'docker-port-loopback': NOT.loopback,
      'firewall-drop': NOT.firewall,
    },
    hints: [
      'error.log on srv01: "SSL_do_handshake() failed (SSL: error:0A00010B:SSL routines::wrong version number) while SSL handshaking to upstream".',
      '"wrong version number" means the other side did not answer with TLS: it is plain HTTP. From srv01: curl -v https://dock01.corp.lab:8000/health versus curl -sS http://dock01.corp.lab:8000/health.',
      'The API only speaks HTTP. Proxy to http://dock01.corp.lab:8000/ (encrypting this hop needs TLS on the backend first: a certificate on the API or a TLS-terminating sidecar). nginx -t, systemctl reload nginx.',
    ],
    explanation: {
      rootCause: 'proxy_pass was changed to https://, but the API (gunicorn on 8000) only speaks plain HTTP. nginx starts a TLS handshake and receives an HTTP error response instead of a ServerHello.',
      manifestation: 'Every request gets 502 Bad Gateway immediately.',
      evidence: 'error.log: "SSL_do_handshake() failed (SSL: … wrong version number) while SSL handshaking to upstream"; curl -v https://dock01.corp.lab:8000/ from srv01 fails with the same OpenSSL error, http:// works.',
      prevention: 'Encrypting a hop is a change on both ends: enable TLS on the backend first, then switch the proxy (and add proxy_ssl_verify with the right CA so it is not just encryption without authentication).',
    },
    solution: [{ host: 'srv01', commands: ['sed -i \'s#proxy_pass https://dock01.corp.lab:8000/;#proxy_pass http://dock01.corp.lab:8000/;#\' /etc/nginx/nginx.conf', 'systemctl reload nginx'] }],
    constraints: [proxyStillUsed()],
    concepts: ['web.proxy', 'tls.pki'],
  },
];

/** Users have been trying the site before the ticket was opened: their requests are in the proxy's logs. */
function usersTried(world: World): void {
  script(world, 'ws01', ['curl -s -o /dev/null -m 90 http://apps.corp.lab/inventory/', 'curl -s -o /dev/null -m 90 http://apps.corp.lab/inventory/health'], 120_000);
}

export const PROXY_SCENARIOS: Scenario[] = TICKETS.map((t) => ({ ...t, setup(world: World) { t.setup(world); usersTried(world); } }));
