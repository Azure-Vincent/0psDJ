// Web servers and reverse proxies (nginx). Examples follow the lab: srv01
// (Debian 12, nginx 1.22.1) publishes http://apps.corp.lab/inventory/ in front
// of the inventory API on dock01:8000; the sandbox and the tickets run there.
// RHEL 9 (SELinux), Windows (IIS + ARR) and pfSense (HAProxy) differences noted.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

const APPS_BLOCK = `server {
    listen 80;
    server_name apps.corp.lab;

    location /inventory/ {
        proxy_pass http://dock01.corp.lab:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
}`;

// --- Operate & recover guide ---------------------------------------------------------

export const WEBPROXY_GUIDE: ServiceGuide = {
  purpose:
    'A **reverse proxy** is a web server that answers clients on behalf of other servers: it accepts the HTTP(S) request, chooses a backend ("upstream") from the URL or host name, opens **its own** connection to that backend, and relays the answer. It gives many applications one name and one TLS certificate, hides the backends from the network, and is where access logs, timeouts and load balancing live. nginx is the most common one on Linux (unit `nginx.service`); the same ideas apply to Apache `mod_proxy`, HAProxy, Traefik and IIS with Application Request Routing.',
  architecture: [
    { q: 'What does it accomplish?', a: 'One public entry point (apps.corp.lab, port 80/443) for several internal applications; TLS terminated in one place; backends that only need to accept connections from the proxy; central logging, rate limits and maintenance pages; spreading load over several backend servers (an **upstream** group).' },
    { q: 'How does it work internally?', a: 'nginx\'s master process (root) reads `nginx.conf`, **resolves every upstream host name once**, opens the listening sockets and starts worker processes (www-data). A worker accepts the client connection, picks the `server` block (address, port, Host header) and the `location` (exact match, else longest prefix), then for `proxy_pass` opens a new TCP connection to the upstream address, sends the request with a rewritten URI and headers, reads the response and streams it back.' },
    { q: 'Which protocols does it use?', a: 'HTTP/1.1 or HTTP/2 with TLS towards clients; HTTP/1.0 by default towards upstreams (`proxy_http_version 1.1` for keep-alive and WebSockets), optionally HTTPS (`proxy_pass https://…`, with `proxy_ssl_verify` to authenticate the backend). DNS at load time for upstream names.' },
    { q: 'Which ports and transport?', a: 'Listens on TCP 80/443 (whatever `listen` says). Upstream connections leave **from the proxy host** with an ephemeral source port to the backend\'s port (8000 here): the backend sees the proxy\'s address, not the client\'s.' },
    { q: 'Which processes and OS components implement it?', a: '`nginx: master process /usr/sbin/nginx` (root: config, sockets, signals) and `nginx: worker process` (www-data: requests). systemd unit `nginx.service`; `ExecStartPre=/usr/sbin/nginx -t -q` refuses to start an invalid configuration.' },
    { q: 'Which other services does it depend on?', a: 'DNS (upstream names at start/reload), the network path and the **backend\'s firewall** from the proxy to every upstream, the backend applications themselves, TLS certificates and keys, and on RHEL the SELinux boolean `httpd_can_network_connect`.' },
    { q: 'How do requests travel?', a: 'Client → apps.corp.lab:80 (srv01) → nginx picks server apps.corp.lab and location /inventory/ → new TCP connection srv01 → 10.0.20.40:8000 → `GET /health` with `Host: apps.corp.lab` and `X-Forwarded-For: 10.0.10.25` → the API answers 200 → nginx relays it, adding its own `Server` header, and logs one access.log line.' },
    { q: 'How do authentication and authorisation work?', a: 'nginx can require client authentication itself (`auth_basic`, client certificates, `auth_request` to an SSO service) or pass it through. The backend should trust **only the proxy**: allow its address in the backend firewall, and trust `X-Forwarded-For` only from it (otherwise a client can forge its source address).' },
    { q: 'How does it start at boot?', a: '`nginx.service` is enabled by the Debian package. At start it runs `nginx -t`, and every upstream name must resolve: a name that does not exist (or DNS that is not up yet) makes the **whole** nginx fail to start, taking every site on that server down.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Every site on the proxy goes down at once (connection refused) even though the backends are fine; systemd restarts it only if `Restart=` is configured (Debian\'s unit does not). If a **backend** dies, nginx stays up and answers 502 (refused) or 504 (no answer) for that location only.' },
  ],
  ports: [
    { port: '80', proto: 'TCP', purpose: 'HTTP from clients (often only a redirect to HTTPS)' },
    { port: '443', proto: 'TCP (TLS)', purpose: 'HTTPS from clients; TLS terminates here' },
    { port: 'upstream (e.g. 8000)', proto: 'TCP', purpose: 'Outbound from the proxy host to each backend; must be allowed by the backend\'s firewall' },
    { port: '53 (outbound)', proto: 'UDP/TCP', purpose: 'Resolving upstream names at start and reload' },
  ],
  processes: [
    { name: 'nginx: master process', platform: 'Linux (nginx.service)', role: 'Reads and validates the configuration, resolves upstream names, binds the listening sockets, starts/replaces workers on reload (SIGHUP)' },
    { name: 'nginx: worker process', platform: 'Linux', role: 'Handles client connections and opens the upstream connections (runs as www-data on Debian, nginx on RHEL)' },
    { name: 'httpd (mod_proxy)', platform: 'RHEL / Debian (apache2)', role: 'Apache as a reverse proxy: ProxyPass / ProxyPassReverse' },
    { name: 'w3wp.exe + ARR / URL Rewrite', platform: 'Windows Server (IIS)', role: 'Application Request Routing with URL Rewrite rules forwards requests to backends' },
    { name: 'haproxy', platform: 'pfSense package, Linux', role: 'TCP/HTTP load balancer and reverse proxy; on pfSense configured under Services > HAProxy' },
  ],
  dependencies: {
    title: 'What "http://apps.corp.lab/inventory/ answers" depends on (top needs everything below it)',
    caption: 'Check from the client towards the backend, and test each hop from the machine that really makes it: the proxy is the client of the backend.',
    rows: [
      { label: 'Client', nodes: [{ id: 'client', label: 'ws01 browser', sub: 'apps.corp.lab:80', kind: 'client' }, { id: 'dns', label: 'DNS', sub: 'apps → srv01', kind: 'network' }] },
      { label: 'Proxy', nodes: [{ id: 'nginx', label: 'nginx on srv01', sub: 'server + location', kind: 'service' }, { id: 'conf', label: 'nginx.conf', sub: 'proxy_pass, Host', kind: 'data' }, { id: 'updns', label: 'Upstream names', sub: 'resolved at load', kind: 'network' }] },
      { label: 'Path', nodes: [{ id: 'fw', label: 'Backend firewall', sub: 'allows the proxy', kind: 'network' }] },
      { label: 'Backend', nodes: [{ id: 'app', label: 'Inventory API', sub: 'dock01:8000', kind: 'service' }, { id: 'db', label: 'Database', sub: 'db:5432', kind: 'data' }] },
    ],
    edges: [['client', 'dns'], ['client', 'nginx'], ['nginx', 'conf'], ['nginx', 'updns'], ['nginx', 'fw'], ['fw', 'app'], ['app', 'db']],
  },
  sequence: {
    title: 'ws01 opens http://apps.corp.lab/inventory/health through srv01',
    caption: 'nginx 1.22 on srv01 (Debian 12), upstream dock01.corp.lab:8000 resolved to 10.0.20.40 when nginx started.',
    lanes: [{ id: 'c', label: 'ws01', sub: '10.0.10.25' }, { id: 'p', label: 'srv01 nginx', sub: '10.0.20.10:80' }, { id: 'b', label: 'dock01', sub: '10.0.20.40:8000' }],
    steps: [
      { from: 'c', to: 'p', label: 'TCP + GET /inventory/health Host: apps.corp.lab', note: 'nginx not running (e.g. "host not found in upstream" at start) → connection refused for every site on srv01.' },
      { from: 'p', to: 'b', label: 'TCP SYN from 10.0.20.10', note: 'RST → 502 at once ("connect() failed (111: Connection refused)"). No answer → 504 after proxy_connect_timeout ("upstream timed out (110)").' },
      { from: 'b', to: 'p', label: 'SYN-ACK' },
      { from: 'p', to: 'b', label: 'GET /health Host: apps.corp.lab', note: 'proxy_pass with a URI ("…:8000/") replaces the prefix /inventory/; without one the backend receives /inventory/health.' },
      { from: 'b', to: 'p', label: 'HTTP/1.1 200 OK (JSON)' },
      { from: 'p', to: 'c', label: 'HTTP/1.1 200 OK, Server: nginx', note: 'access.log: client 10.0.10.25, status 200. The backend\'s own log shows 10.0.20.10.' },
    ],
  },
  files: [
    { path: '/etc/nginx/nginx.conf', platform: 'Debian 12, RHEL 9', kind: 'config', perms: 'root:root 0644', contains: 'Global settings (user, worker_processes), the `http { }` block, and on Debian `include /etc/nginx/sites-enabled/*;`. In this lab every server block, including `apps.corp.lab`, is in this one file.', accessed: 'By `nginx -t`, at start, and at every reload (SIGHUP): the master re-reads and re-resolves everything, then replaces the workers.', problems: 'One `[emerg]` anywhere (a typo, a missing certificate, an upstream name that does not resolve) stops nginx from starting, so every site on the server is down. A failed **reload** keeps the old configuration running: the error stays hidden until the next restart.' },
    { path: '/etc/nginx/sites-available/, sites-enabled/ (conf.d/*.conf on RHEL)', platform: 'Debian (RHEL: /etc/nginx/conf.d)', kind: 'config-dir', perms: 'root:root 0644', contains: 'One file per site; Debian enables a site with a symlink in sites-enabled.', accessed: 'Included from nginx.conf at load time.', problems: 'A forgotten `default` site with `default_server` answers requests for unknown names; editing sites-available without the symlink changes nothing.' },
    { path: '/var/log/nginx/access.log', platform: 'Linux', kind: 'log', perms: 'www-data:adm 0640', contains: 'One line per request: client address, time, request line, **status**, bytes, referrer, user agent. With `$upstream_status` and `$upstream_response_time` in a custom log_format it also shows what the backend answered.', accessed: 'Written by the workers after each request; rotated daily by logrotate.', problems: 'A 404 here can be nginx\'s or the backend\'s: compare with the backend\'s log, or look at the response body (nginx\'s HTML page vs the application\'s JSON).' },
    { path: '/var/log/nginx/error.log', platform: 'Linux', kind: 'log', perms: 'www-data:adm 0640', contains: 'Why a request failed: `connect() failed (111: Connection refused) while connecting to upstream`, `upstream timed out (110: …)`, `SSL_do_handshake() failed`, `no live upstreams`, permission errors, with `client`, `server`, `request`, **`upstream`** (the exact address and URI nginx used) and `host`.', accessed: 'Written by the workers when a request fails; also start-up errors on some systems.', problems: 'The most useful file for a 502/504, and the first one people forget. Start-up errors go to the journal (`journalctl -u nginx`).' },
    { path: 'journal: journalctl -u nginx', platform: 'Linux', kind: 'log', contains: '`nginx -t` failures at start and reload (`[emerg] host not found in upstream …`), "Reload failed for nginx.service".', accessed: 'At every start, stop and reload.', problems: 'systemctl reload prints a failure, but nginx keeps running with the previous configuration: read it.' },
    { path: '/lib/systemd/system/nginx.service', platform: 'Debian 12', kind: 'unit', perms: 'root:root 0644', contains: '`ExecStartPre=/usr/sbin/nginx -t -q -g \'daemon on; master_process on;\'`, `ExecStart=/usr/sbin/nginx …`, `ExecReload=/usr/sbin/nginx -g \'daemon on; master_process on;\' -s reload`.', accessed: 'By systemd at start/reload.', problems: 'No `Restart=`: a crashed nginx stays down. Add a drop-in if you want automatic restarts.' },
  ],
  management: [
    {
      platform: 'Debian / Ubuntu (nginx)',
      tasks: [
        { task: 'Is nginx running and listening?', command: 'systemctl status nginx\nss -tlnp', explain: 'Look for `active (running)` and `nginx` on :80 and :443. "failed" → `journalctl -u nginx -n 20` gives the [emerg] line.', sim: true },
        { task: 'Test the configuration', command: 'nginx -t', explain: 'Parses the whole configuration, loads certificates and **resolves every upstream name**, exactly as a start would. Run it before every reload.', sim: true },
        { task: 'Apply a configuration change', command: 'nginx -t && systemctl reload nginx', explain: 'Reload starts new workers with the new configuration; open connections finish on the old ones. No outage.', risk: 'If the test fails, reload fails too, and nginx keeps the old configuration: your change is not live.', sim: true },
        { task: 'Why does the proxy return 502/504?', command: 'tail -n 20 /var/log/nginx/error.log', explain: 'The `upstream:` field shows the exact address, port and URI nginx used; the message tells refused (111), timed out (110), no route (113), TLS failure or premature close.', sim: true },
        { task: 'Test the upstream from the proxy itself', command: 'curl -sS -i http://dock01.corp.lab:8000/health\nnc -zv -w 3 dock01.corp.lab 8000', explain: 'The proxy is the client of the backend: a test from your PC proves nothing about the path from srv01 (different source address, firewall rules and routes).', sim: true },
        { task: 'Which name does the upstream resolve to?', command: 'getent hosts dock01.corp.lab', explain: 'nginx resolved this at its last start/reload. If DNS changed since, reload nginx to pick up the new address.', sim: true },
        { task: 'Access log of the proxy', command: 'tail -n 20 /var/log/nginx/access.log', explain: 'Status per request as the client saw it.', sim: true },
      ],
    },
    {
      platform: 'RHEL 9 (nginx, SELinux)',
      tasks: [
        { task: 'Allow nginx to connect to backends', command: 'getsebool httpd_can_network_connect\nsudo setsebool -P httpd_can_network_connect on', explain: 'With SELinux enforcing, `httpd_t` may not open outbound connections to arbitrary ports: every proxied request gets 502 with `connect() to 10.0.20.40:8000 failed (13: Permission denied) while connecting to upstream`.' },
        { task: 'SELinux denials', command: 'sudo ausearch -m avc -ts recent | grep nginx', explain: 'Shows `avc: denied { name_connect }` for the backend port.' },
        { task: 'firewalld', command: 'sudo firewall-cmd --add-service=http --add-service=https --permanent && sudo firewall-cmd --reload', explain: 'Open 80/443 on the proxy; the backend needs a rich rule allowing only the proxy\'s address.' },
      ],
    },
    {
      platform: 'Windows Server (IIS + ARR)',
      tasks: [
        { task: 'Reverse proxy with ARR', command: 'Install-WindowsFeature Web-Server\n# install Application Request Routing 3.0 and URL Rewrite, then:\nSet-WebConfigurationProperty -PSPath IIS:\\ -Filter system.webServer/proxy -Name enabled -Value $true', explain: 'IIS proxies with a URL Rewrite rule whose action is `Rewrite` to `http://backend:8000/{R:1}`. Failed upstream connections show as 502.3 (Bad Gateway) and timeouts as 502.3 with error code 0x80072ee2 in the failed-request trace.' },
      ],
    },
    {
      platform: 'pfSense (HAProxy package)',
      tasks: [
        { task: 'Reverse proxy on the firewall', command: 'Services > HAProxy > Backend (servers dock01:8000, health check) and Frontend (listen WAN:443, ACL host = apps.corp.lab, use backend)', explain: 'HAProxy marks a backend DOWN when its health check fails and answers **503 Service Unavailable** ("No server is available to handle this request") instead of nginx\'s 502/504.' },
      ],
    },
  ],
  actions: [
    { action: 'nginx -t', when: 'Before every reload or restart, and after DNS changes that affect upstream names.', effect: 'Parses everything, loads certificates, resolves upstreams. Changes nothing.', risk: 'None.' },
    { action: 'systemctl reload nginx', when: 'After a configuration change that passed nginx -t.', effect: 'New workers with the new configuration (and freshly resolved upstream addresses); no dropped connections.', risk: 'If the configuration is invalid the reload fails and the **old** configuration keeps running: check the result.' },
    { action: 'systemctl restart nginx', when: 'Changes reload cannot apply (rare), a stuck master, after an upgrade.', effect: 'Stops all workers, starts again from the files on disk.', risk: 'If the configuration is invalid nginx stays **down** and every site on the server with it. Always nginx -t first.' },
    { action: 'Change the backend, not the proxy', when: 'The error log shows the upstream refusing or timing out.', effect: 'Fix the application, its port mapping or its firewall; the proxy recovers on the next request (no reload needed).', risk: 'Changing proxy_pass to "make it work" (pointing at another port or host) can expose the wrong service.' },
  ],
  workflow: [
    { question: 'Does the client reach the proxy, and who answers?', why: 'First find out whether the client reaches the proxy at all, and who answers: nginx (a 502 or 504) or the application (its own error page).', command: 'curl -sS -i http://apps.corp.lab/inventory/health', healthy: 'HTTP/1.1 200 OK\nServer: nginx/1.22.1\n...\n{"status":"ok","database":"ok"}', broken: '`Couldn\'t connect to server` (nginx down) → step 2. `502 Bad Gateway` / `504 Gateway Time-out` (nginx up, upstream failed) → step 3. A 404 or 500 whose body is the application\'s (JSON) → the backend answered: step 5.', next: 'Read the status and the body: nginx\'s HTML error page and the application\'s own errors point to different layers.', sim: true },
    { question: 'Is nginx running, and why not?', why: 'If nginx itself is down or failed to start, no request gets anywhere. nginx refuses to start when an upstream name cannot be resolved or the configuration is invalid.', command: 'systemctl status nginx\njournalctl -u nginx -n 20\nnginx -t', healthy: 'active (running)\nnginx: configuration file /etc/nginx/nginx.conf test is successful', broken: '`[emerg] host not found in upstream "NAME:PORT"`: an upstream name does not resolve. Certificate errors, `bind() … (98: Address already in use)`.', next: 'Fix the configuration, nginx -t, then systemctl start nginx.', sim: true },
    { question: 'What did nginx try, and what happened?', why: 'nginx writes the exact backend address it tried, and why it failed, to error.log. That is far more precise than the status code.', command: 'tail -n 5 /var/log/nginx/error.log', healthy: '(nothing new for this request)', broken: '`connect() failed (111: Connection refused)` → nothing listens at upstream: "…" (wrong port, app down). `upstream timed out (110: Connection timed out) while connecting` → packets dropped (backend firewall). `SSL_do_handshake() failed … wrong version number` → https:// to a plain-HTTP backend.', next: 'The `upstream:` field is the exact target: test it from the proxy (step 4).', sim: true },
    { question: 'Does the upstream answer from the proxy host?', why: 'The second connection starts on the proxy machine, so test from there. A backend firewall may allow your workstation but not the proxy.', command: 'nc -zv -w 3 dock01.corp.lab 8000\ncurl -sS -i http://dock01.corp.lab:8000/health', healthy: 'Connection to dock01.corp.lab (10.0.20.40) 8000 port [tcp/*] succeeded!\nHTTP/1.1 200 OK', broken: 'Refused: the backend is down or on another port. Timed out while the same test works from a client PC: the backend firewall allows the clients but not the proxy.', next: 'Fix the backend or its firewall (allow the proxy\'s address), not the client side.', sim: true },
    { question: 'Which URI and Host does the backend receive?', why: 'proxy_pass can rewrite the path, and the Host header may change on the way. The backend\'s own log shows what it really received.', command: 'grep -n -e location -e proxy_pass -e proxy_set_header /etc/nginx/nginx.conf', healthy: 'location /inventory/ {\nproxy_pass http://dock01.corp.lab:8000/;\nproxy_set_header Host $host;', broken: '`proxy_pass http://dock01.corp.lab:8000;` (no URI): the backend receives /inventory/health and answers 404. A missing `proxy_set_header Host` sends `Host: dock01.corp.lab:8000`, which name-based backends may not serve.', next: 'Compare with the backend\'s own log (docker compose logs app on dock01).', sim: true },
  ],
  failures: [
    { symptom: '502 Bad Gateway immediately', causes: ['proxy_pass names the wrong port or host (nothing listens there)', 'The backend application is down or crashing', 'https:// in proxy_pass for a plain-HTTP backend', 'RHEL: SELinux denies httpd_t network connections (13: Permission denied)'], diagnose: ['tail /var/log/nginx/error.log (message and upstream: field)', 'curl the upstream URL from the proxy host', 'getsebool httpd_can_network_connect (RHEL)'], fix: 'Point proxy_pass at the real port/scheme, start the backend, or set the SELinux boolean. nginx -t && systemctl reload nginx after a proxy change.', verify: 'curl -sS -o /dev/null -w "%{http_code}\\n" http://apps.corp.lab/inventory/health → 200' },
    { symptom: '504 Gateway Time-out after a delay', causes: ['A firewall between proxy and backend drops the proxy\'s packets (often: only the client network is allowed)', 'The backend accepts but answers slower than proxy_read_timeout'], diagnose: ['error.log: "upstream timed out (110) while connecting" (firewall) or "while reading response header" (slow app)', 'nc -zv -w 3 BACKEND PORT from the proxy and from a client'], fix: 'Allow the proxy\'s address on the backend; for slow responses fix the app or raise proxy_read_timeout deliberately.', verify: 'The same curl through the proxy answers within a second.' },
    { symptom: 'Every site on the server is down after a restart or reboot', causes: ['nginx refuses to start: an upstream host name does not resolve (or DNS was not reachable at boot)', 'Another [emerg]: certificate, syntax'], diagnose: ['systemctl status nginx; journalctl -u nginx -n 20', 'nginx -t', 'getent hosts NAME'], fix: 'Correct the name (or create the DNS record), nginx -t, systemctl start nginx. Consider IP addresses or `resolver` + variables for upstreams that may be unresolvable at boot.', verify: 'systemctl is-active nginx; both sites answer.' },
    { symptom: '404 (or the wrong page) only through the proxy', causes: ['proxy_pass URI rule: without a trailing URI the location prefix reaches the backend', 'Host header: the backend serves a different virtual host for the proxy\'s Host', 'A different server block catches the request (server_name, default_server)'], diagnose: ['Look at the 404 body (nginx HTML or application JSON)', 'The backend\'s access log: which path and Host arrived', 'nginx -T / the server_name and location lines'], fix: 'Add (or remove) the URI part in proxy_pass, set proxy_set_header Host as the backend expects, fix server_name.', verify: 'Deep paths, not only /, work through the proxy.' },
  ],
  verification: [
    { check: 'Configuration valid and active', command: 'nginx -t && systemctl is-active nginx', expect: 'test is successful\nactive' },
    { check: 'Proxied path works from a client', command: 'curl -sS -o /dev/null -w \'%{http_code}\\n\' http://apps.corp.lab/inventory/health', expect: '200' },
    { check: 'No new upstream errors', command: 'tail -n 5 /var/log/nginx/error.log', expect: 'No connect()/timed out lines for the current time' },
    { check: 'Backend reachable from the proxy only (by design)', command: 'nc -zv -w 3 dock01.corp.lab 8000', expect: 'succeeded from srv01; the backend firewall decides who else may connect' },
    { check: 'Survives a restart', command: 'systemctl restart nginx && systemctl is-active nginx', expect: 'active (upstream names resolve at boot)' },
  ],
  refIds: ['nginx', 'file:nginx-conf', 'curl', 'nc', 'ss', 'systemctl', 'journalctl', 'nft', 'docker-compose', 'proc:safe-config-change', 'proc:rollback'],
};

// --- Lesson -------------------------------------------------------------------------

export const WEBPROXY_LESSON: Lesson = {
  id: 'webproxy',
  moduleId: 'F',
  title: 'Web servers and reverse proxies (nginx)',
  level: 'intermediate',
  summary: 'How nginx chooses a server block and location, forwards a request to an upstream with proxy_pass, and what 502, 504 and "host not found in upstream" tell you about where the path broke.',
  concepts: ['web.proxy', 'tcp.handshake', 'dns.resolution', 'svc.listening', 'fw.path', 'svc.systemd'],

  what: `
A **web server** answers HTTP requests, either from files on disk (static content) or by handing the request to an application. A **reverse proxy** is a web server placed **in front of** other servers: clients only ever talk to the proxy, and the proxy forwards each request to the right server behind it (the **backend**, or **upstream**) and passes the answer back.

Think of a hotel reception desk: guests only talk to the receptionist, who passes each request to the right department and brings back the answer. The guest never needs to know where the kitchen is.

Every request through a proxy is really two separate connections: client to proxy, and proxy to backend. Each one needs DNS, a route, open firewalls and a listening service ([Transport and DNS](#/lesson/transport/what)), and with HTTPS also a valid certificate ([TLS](#/lesson/tls/what)). Most proxy troubleshooting comes down to finding out which of the two connections is broken.

### Problems it solves
- **One name, many applications.** \`apps.corp.lab/inventory/\`, \`/wiki/\`, \`/grafana/\` can live on different machines and ports, behind one host name and one TLS certificate.
- **Backends stay private.** Only the proxy needs to reach the application servers; their firewalls can allow the proxy and nothing else.
- **One place for HTTP policy.** TLS, redirects, access logs, rate limits, maintenance pages, client authentication.
- **Load balancing and maintenance.** An \`upstream\` group spreads requests over several backends and skips one that refuses connections.

### Where you meet it
In front of almost every internal web application, container platform and API: nginx, Apache \`mod_proxy\`, HAProxy, Traefik, IIS with ARR, cloud load balancers. When "the website is down", the question is always **which hop**: the client to the proxy, or the proxy to the backend.

> In the lab, **srv01** (10.0.20.10, nginx 1.22.1 on Debian 12) serves the intranet site and, as \`apps.corp.lab\` (a CNAME for srv01), proxies \`/inventory/\` to the inventory API on **dock01** (10.0.20.40:8000, a Docker Compose project). The sandbox and the five tickets run there. Simulated: server and location selection (exact and prefix locations), \`proxy_pass\` with and without a URI, \`upstream\` groups (tried in order), \`proxy_set_header Host\`, \`proxy_connect_timeout\`, load-time resolution of upstream names, the proxy's own TCP connection (so firewalls, routes and refusals apply to it), 502/504 pages and nginx's error.log lines. Not simulated: regex locations, \`proxy_read_timeout\` and slow backends, buffering, caching, WebSockets, HTTP/2, \`sites-enabled\` includes and SELinux.
`,

  internals: `
### 1. Choosing the server block and the location
nginx first picks a **server** block from the address and port the connection arrived on, then by the **Host** header (\`server_name\`); if no name matches, the \`default_server\` for that port (or the first block) answers. Inside it, it picks a **location** for the URI: an exact match (\`location = /health\`) wins, otherwise the **longest matching prefix** (\`location /inventory/\` beats \`location /\`). Regex locations (\`~\`) are checked after prefixes in real nginx.

:::practice
Q: A server block has \`location /\` and \`location /api/\`. Which handles \`/api/v2/users\`, and which handles \`/apiary\`?
A: \`/api/v2/users\` → **location /api/** (the longest matching prefix). \`/apiary\` does not start with "/api/" (the slash matters), so → **location /**.
Q: A request arrives with \`Host: unknown.corp.lab\` on port 80, and no server_name matches. Which server block answers?
A: The **default_server** for port 80, or the first server block for that port if none is marked default.
:::

### 2. proxy_pass and the URI rule
\`proxy_pass\` turns the location into a proxy. What the backend receives depends on whether the URL has a **URI part**:

| location | proxy_pass | client asks | backend receives |
|---|---|---|---|
| \`/inventory/\` | \`http://dock01:8000/\` | \`/inventory/health\` | \`/health\` (prefix replaced by "/") |
| \`/inventory/\` | \`http://dock01:8000\` | \`/inventory/health\` | \`/inventory/health\` (unchanged) |
| \`/inventory/\` | \`http://dock01:8000/api/\` | \`/inventory/items\` | \`/api/items\` |

Anything after a \`?\` (the **query string**, such as \`?id=7&sort=name\`) is not part of the matched prefix and is passed on unchanged: a request for \`/inventory/health?full=1\` reaches the backend of the first row as \`/health?full=1\`.

A missing or extra slash is the most common cause of "everything is 404 behind the proxy".

:::practice
Q: \`location /reports/ { proxy_pass http://app01:9000; }\` (no URI part). Which path does the backend receive for \`/reports/2026/q3\`?
A: **/reports/2026/q3**, unchanged: without a URI part, the original URI is passed as is.
Q: \`location /shop/ { proxy_pass http://app02:8080/store/; }\`. Which path does the backend receive for \`/shop/cart?id=4\`?
A: **/store/cart?id=4**: the matched prefix /shop/ is replaced by /store/, and the query string is kept.
:::

### 3. Headers
By default nginx sends \`Host: $proxy_host\` (the upstream's name and port, e.g. \`dock01.corp.lab:8000\`) and HTTP/1.0. Most applications want the name the client used: \`proxy_set_header Host $host;\`. The client's address is lost on the new connection, so the proxy adds \`X-Forwarded-For\` (and \`X-Forwarded-Proto\` for http/https); the backend must trust these headers **only from the proxy**.

:::practice
Q: An application behind nginx builds links to \`http://dock01.corp.lab:8000/...\`, which users cannot reach. Which directive fixes it?
A: \`proxy_set_header Host $host;\`. By default nginx sends the upstream's name and port as Host, so the application thinks that is its public name.
Q: Why must a backend trust X-Forwarded-For only when the request comes from the proxy?
A: Anyone can send that header. A client connecting directly could claim any address and bypass address-based rules or poison logs.
:::

### 4. Upstream names are resolved once
When nginx starts or reloads, the master process resolves every host name in \`proxy_pass\` and \`upstream\` blocks with the system resolver and keeps the addresses. Consequences:
- A name that does not resolve is fatal: \`[emerg] host not found in upstream "inventory-api.corp.lab:8000"\`. \`nginx -t\` fails, a **reload** fails (the old configuration keeps running), a **start** fails (nothing listens: every site on that server is down).
- If the backend's address changes in DNS, nginx keeps the old address until the next reload.
- (With \`resolver 10.0.10.53;\` and a variable in proxy_pass, nginx resolves at request time instead.)

:::practice
Q: A backend moved to a new IP address and its DNS record was updated an hour ago. Requests through nginx still go to the old address. Why, and what is the quickest fix?
A: nginx resolved the name when it last **started or reloaded** and kept the address. \`nginx -t && systemctl reload nginx\` makes it resolve again.
Q: Why can a typo in one upstream host name take down every site on a reverse proxy after a reboot?
A: At start, a name that does not resolve is **fatal** ("host not found in upstream"), so nginx does not start at all and nothing listens for any site.
:::

### 5. The proxy's own connection
For each request nginx opens a **new TCP connection from the proxy host** to the upstream address. Everything you know about TCP applies to that hop, with the proxy as the client:
- **RST** (nothing listens, wrong port, app down) → **502 Bad Gateway** at once; error.log: \`connect() failed (111: Connection refused) while connecting to upstream\`.
- **No answer** (a firewall drops the proxy's SYNs) → nginx retries until \`proxy_connect_timeout\` (60 s by default) → **504 Gateway Time-out**; error.log: \`upstream timed out (110: Connection timed out) while connecting to upstream\`.
- **ICMP unreachable** → 502, \`(113: No route to host)\`.
- Connected, but the backend speaks another protocol: \`https://\` to plain HTTP → 502, \`SSL_do_handshake() failed (… wrong version number)\`; the backend closes without answering → 502, \`upstream prematurely closed connection\`.

The backend's firewall sees **srv01's address**, not the user's: a rule that allows the office network lets users test the backend directly while the proxy is blocked.

:::practice
Q: error.log shows \`connect() failed (113: No route to host) while connecting to upstream\`. Which status does the user get, and what do you check?
A: **502**. Something returned ICMP unreachable for the proxy's connection: check the route from the proxy host to the backend and any firewall that **rejects** (rather than drops) it.
Q: A backend answers in 2 seconds when tested from your desktop, but through the proxy users get 504 after a minute. Name the first thing to check.
A: Whether the backend's **firewall allows the proxy host's address**. The proxy connects from its own address, not yours; dropped SYNs from it end in 504 after proxy_connect_timeout.
:::

### 6. Upstream groups
\`upstream inventory { server 10.0.20.40:8000; server 10.0.20.41:8000; }\` with \`proxy_pass http://inventory/;\` spreads requests (round robin by default) and moves to the next server when a connection fails (\`proxy_next_upstream\`). A server that fails \`max_fails\` times is skipped for \`fail_timeout\`; when all are down nginx logs \`no live upstreams\` and answers 502. In the simulator the servers are tried in order.

:::practice
Q: An upstream group has two servers and one is down. What do users see?
A: Usually nothing: nginx moves the failed request to the other server (proxy_next_upstream) and skips the dead one for fail_timeout.
Q: What does the error.log message \`no live upstreams\` mean?
A: Every server in the group is currently marked as failed, so nginx answers **502** without trying.
:::

### 7. Who answered?
A 404 or 500 through the proxy may come from nginx or from the application. nginx's own errors are small HTML pages (\`<center>nginx/1.22.1</center>\`) and usually have an error.log line; the application's have its own body (JSON here) and appear in the backend's log. A \`502\`/\`504\` with nginx's page and an error.log line is the proxy speaking about the upstream. A backend that is itself a gateway (another proxy, an API gateway) can also return its own 502 or 504; nginx passes it through with that backend's body and logs nothing in error.log.

:::practice
Q: Through the proxy you get \`500 Internal Server Error\` with a JSON body \`{"error":"database unavailable"}\`. Who produced it, and where do you look next?
A: The **backend application** (its own JSON body). Look at the application's log and its database connection, not at nginx.
Q: You get a 504 Gateway Time-out through the proxy. How do you tell whether nginx produced it or the backend did?
A: Read the **body** and nginx's error.log. nginx's own 504 is its small HTML page with an "upstream timed out" line in error.log. A backend that is itself a gateway (another proxy, an API gateway) can return its own 504, which nginx passes through unchanged with that backend's body and no such error.log line.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu 24.04 (nginx)',
      summary: 'Install nginx, add a server block that proxies a path to an internal application, and verify each hop. Steps marked simulated work on srv01 in the sandbox (where the inventory API already runs on dock01).',
      prerequisites: ['A server with sudo, DNS name for the site (apps.corp.lab → the proxy).', 'The backend application reachable from the proxy (test it first).'],
      steps: [
        { title: 'Install nginx', command: 'sudo apt install -y nginx\nsystemctl status nginx', what: 'Installs nginx with Debian\'s layout (sites-available/sites-enabled) and starts it.', why: 'The package enables the unit and serves the default page on :80.', expected: 'Active: active (running)' },
        { title: 'Test the backend from the proxy host', command: 'curl -sS -i http://dock01.corp.lab:8000/health', what: 'Proves that the proxy host can reach the upstream (name, route, firewall, application).', why: 'The proxy is the backend\'s client: test from where the connection will really start.', expected: 'HTTP/1.1 200 OK\nServer: gunicorn\n...\n{"status":"ok","database":"ok"}', simulated: true },
        { title: 'Add the server block', command: APPS_BLOCK, what: 'apps.corp.lab on port 80; /inventory/ proxied to the API with the prefix replaced (trailing slash), the client\'s Host and address passed on, and a short connect timeout so a dead backend fails fast.', why: 'In production put it in /etc/nginx/sites-available/apps.corp.lab and symlink it into sites-enabled (in the lab it goes in /etc/nginx/nginx.conf, inside http { }).', expected: '' },
        { title: 'Test and reload', command: 'nginx -t && systemctl reload nginx', what: 'Validates the whole configuration, including resolving dock01.corp.lab, then applies it without dropping connections.', why: 'A failed reload keeps the old configuration: never assume it worked.', expected: 'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful', simulated: true },
        { title: 'Test through the proxy', command: 'curl -sS -i http://apps.corp.lab/inventory/health\ntail -n 1 /var/log/nginx/access.log', what: 'The client\'s view, then the proxy\'s log line for it.', why: 'Test a deep path, not only /: the URI rule only shows there.', expected: 'HTTP/1.1 200 OK\nServer: nginx/1.22.1\n...\n10.0.10.25 - - [...] "GET /inventory/health HTTP/1.1" 200 32 "-" "curl/7.88.1"', simulated: true },
        { title: 'Restrict the backend to the proxy', command: '# on dock01, in /etc/nftables.conf (forward chain, Docker published port)\nip saddr 10.0.20.10 tcp dport 8000 accept', what: 'Only the proxy may reach the API port.', why: 'Users then cannot bypass the proxy\'s TLS, logging and access control, and X-Forwarded-For can be trusted.', expected: '' },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 / Rocky 9 (nginx with SELinux)',
      summary: 'Same configuration in /etc/nginx/conf.d/apps.conf. SELinux blocks nginx\'s outbound connections to non-HTTP ports until the boolean is set.',
      prerequisites: ['RHEL 9 with SELinux enforcing (leave it on).'],
      steps: [
        { title: 'Install and open the firewall', command: 'sudo dnf install -y nginx\nsudo systemctl enable --now nginx\nsudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload', what: 'Installs, enables and starts nginx (not automatic on RHEL) and opens 80/443.', why: 'RHEL packages do not start services on install.', expected: 'success' },
        { title: 'Allow proxying under SELinux', command: 'sudo setsebool -P httpd_can_network_connect on', what: 'Lets processes labelled httpd_t (nginx) connect to any TCP port.', why: 'Without it every proxied request is 502 with "(13: Permission denied) while connecting to upstream" and an AVC denial.', expected: '' },
      ],
    },
    {
      id: 'windows',
      platform: 'Windows Server 2022 (IIS + Application Request Routing)',
      summary: 'IIS becomes a reverse proxy with the ARR 3.0 and URL Rewrite modules: enable the proxy at server level, then a rewrite rule per site forwards matching URLs to the backend.',
      prerequisites: ['IIS (Web-Server role), ARR 3.0 and URL Rewrite 2.1 installed from Microsoft.'],
      steps: [
        { title: 'Enable the ARR proxy', command: 'Set-WebConfigurationProperty -PSPath IIS:\\ -Filter system.webServer/proxy -Name enabled -Value $true', what: 'Turns on proxying for the server.', why: 'Without it rewrite rules to other hosts return 404.', expected: '' },
        { title: 'Add a rewrite rule', command: '<rule name="inventory" stopProcessing="true">\n  <match url="^inventory/(.*)" />\n  <action type="Rewrite" url="http://dock01.corp.lab:8000/{R:1}" />\n</rule>', what: 'web.config of the site: /inventory/x is forwarded to the API as /x.', why: 'The capture group plays the role of nginx\'s URI replacement.', expected: '' },
      ],
    },
    {
      id: 'pfsense',
      platform: 'pfSense (HAProxy package)',
      summary: 'On pfSense the reverse proxy is the HAProxy package: a backend (servers + health check) and a frontend (address/port, host ACLs). It is often used to publish internal web servers on the WAN with one certificate.',
      prerequisites: ['System > Package Manager: haproxy installed.'],
      steps: [
        { title: 'Backend', command: 'Services > HAProxy > Backend > Add: name inventory, server dock01 10.0.20.40:8000, health check HTTP GET /health', what: 'Defines where requests go and how HAProxy decides a server is up.', why: 'A failing health check takes the server out of rotation: clients get 503 instead of waiting.', expected: '' },
        { title: 'Frontend', command: 'Services > HAProxy > Frontend > Add: listen WAN address :443 (SSL offloading, certificate), ACL host matches apps.corp.lab → backend inventory', what: 'Accepts client connections and picks the backend.', why: 'Also needs a firewall rule allowing 443 to the WAN address.', expected: '' },
      ],
    },
  ],

  configIntro: `
A reverse proxy's configuration has three parts, and each fails differently:
- **Where clients arrive**: \`listen\` and \`server_name\` (which server block answers). Wrong here → the wrong site, or nothing listening.
- **What is forwarded where**: \`location\` + \`proxy_pass\` (+ \`upstream\` groups). Wrong here → 502/504 or the backend's 404.
- **How**: headers (\`proxy_set_header\`), timeouts, TLS to the upstream. Wrong here → subtle failures (redirects to the wrong host, slow failures, TLS errors).

Everything is read at start/reload: run \`nginx -t\` first, read the result of the reload, and check \`systemctl is-active nginx\` after a restart.
`,

  configFiles: [
    {
      platform: 'Debian / Ubuntu',
      items: [
        { path: '/etc/nginx/nginx.conf', purpose: 'Main file: http { } settings and includes (in the lab: every server block).' },
        { path: '/etc/nginx/sites-available/, sites-enabled/', purpose: 'One file per site; enabled by symlink.' },
        { path: '/var/log/nginx/access.log, error.log', purpose: 'Per-request log; why requests failed (upstream errors).' },
      ],
    },
    {
      platform: 'RHEL',
      items: [
        { path: '/etc/nginx/conf.d/*.conf', purpose: 'Site files included from nginx.conf.' },
        { path: 'SELinux boolean httpd_can_network_connect', purpose: 'Must be on for proxying to arbitrary ports.' },
      ],
    },
    {
      platform: 'Windows (IIS)',
      items: [
        { path: '%SystemRoot%\\System32\\inetsrv\\config\\applicationHost.config', purpose: 'Server-level proxy settings (ARR).' },
        { path: '<site root>\\web.config', purpose: 'URL Rewrite rules of the site.' },
      ],
    },
  ],

  directives: [
    { name: 'proxy_pass URL', compiledDefault: '(none)', recommended: 'http://name:port/ with a trailing slash when the location has a prefix to strip', explanation: 'Where the location forwards to. With a URI part the matched prefix is replaced by it; without one the original URI is passed unchanged.', security: 'Pointing a location at the wrong host/port can publish an internal admin interface.' },
    { name: 'proxy_set_header Host', compiledDefault: '$proxy_host (the upstream name:port)', recommended: '$host', explanation: 'The Host header the backend receives. Applications build redirects and absolute links from it.', security: 'Backends that serve several names pick the virtual host from it.' },
    { name: 'proxy_set_header X-Forwarded-For', compiledDefault: 'not sent', recommended: '$proxy_add_x_forwarded_for', explanation: 'Passes the client address (the backend otherwise sees the proxy\'s).', security: 'Trust it only from the proxy; clients can send their own X-Forwarded-For.' },
    { name: 'proxy_connect_timeout', compiledDefault: '60s', recommended: '2s–5s on a LAN', explanation: 'How long nginx waits for the TCP connection to the upstream; then 504 (or the next upstream server).', security: 'Long timeouts tie up workers when a backend is unreachable.' },
    { name: 'proxy_read_timeout', compiledDefault: '60s', recommended: 'What the slowest legitimate request needs', explanation: 'How long nginx waits between two reads from the upstream; then 504 "upstream timed out … while reading response header".', security: 'Raising it hides slow backends; fix the backend first.' },
    { name: 'upstream { server …; }', compiledDefault: 'round robin, max_fails=1, fail_timeout=10s', recommended: 'At least two servers for availability; health checks (nginx Plus, HAProxy) where possible', explanation: 'A named group of backends used as proxy_pass http://NAME/.', security: 'All servers must be equally trusted and patched.' },
    { name: 'resolver + variable in proxy_pass', compiledDefault: 'names resolved once at load', recommended: 'Use when backend addresses change (containers, cloud)', explanation: 'With `resolver 10.0.10.53 valid=30s;` and `set $up dock01.corp.lab; proxy_pass http://$up:8000;` nginx resolves at request time and starts even if the name does not resolve yet.', security: 'The resolver must be trusted: a spoofed answer redirects traffic.' },
  ],

  operateIntro: `
### Before you change a proxy
- Test the upstream **from the proxy host** before editing (curl the exact URL proxy_pass will use).
- Keep a copy (\`cp nginx.conf nginx.conf.bak\`), run \`nginx -t\`, then reload, then test through the proxy with a deep path.
- A restart turns any latent configuration error into an outage of **every site** on the server; prefer reload, and check \`systemctl is-active nginx\` after reboots.

:::practice
Q: You are about to point a location at a new backend. What do you test first, and from which machine?
A: The exact upstream URL that proxy_pass will use, with curl **from the proxy host** (that is where the second connection starts).
Q: Why prefer \`systemctl reload nginx\` over restart after editing the configuration?
A: A reload validates first and keeps the old workers if the file is broken. A restart turns a configuration error into an outage of **every site** on the server.
:::

`,
  troubleshootingIntro: `
### Which hop is broken?
A request through a proxy makes two trips: client to proxy, then proxy to backend. The error you see tells you which trip failed, and who is speaking: a 502 or 504 comes from the proxy, describing its trip to the backend; a 404 or 500 with the application's page comes from the backend itself.

1. **Client to proxy.** Run \`curl -i\` from the client. "Couldn't connect" means the problem is the proxy itself: nginx is down, listening on another port, or a firewall in front of the proxy blocks it.
2. **The proxy's verdict.** A 502 or 504 is nginx reporting a problem with the backend. The reason, and the exact backend address it tried, are written in nginx's **error.log**.
3. **Proxy to backend.** Repeat the test **from the proxy machine** (\`nc -zv\`, \`curl\`), because that is where the second connection starts. Refused: the backend's port is wrong or the application is down. Timed out: a firewall that allows clients but not the proxy.
4. **What the backend received.** The backend's own log shows the path and Host header that actually arrived, which may differ from what the client sent (because of the proxy_pass URI rule or the Host header).

:::practice
Q: \`curl -i http://apps.corp.lab/wiki/\` from a client prints "Couldn't connect to server". Which hop is broken?
A: The **first** one, client to proxy: nginx is down, listening elsewhere, or a firewall in front of the proxy blocks it. The backend has not been involved yet.
Q: Through the proxy you get 502. From the proxy machine, \`nc -zv 10.0.20.41 9000\` says "Connection refused". What is wrong?
A: Nothing listens on the **backend's** port 9000: the application is down or proxy_pass names the wrong port.
:::

### Status codes from a proxy
| Code | Who answers | Meaning |
|---|---|---|
| 502 Bad Gateway | the proxy | It could not get a valid response: connection refused, no route, a TLS failure, or the connection closed |
| 504 Gateway Time-out | the proxy | The backend did not accept or answer in time |
| 503 | the proxy (HAProxy, maintenance page) or the app | No backend available, or the application says it is unavailable |
| 404, 500 with the app's own page | the backend | The request arrived; the application rejected it |

:::practice
Q: A request returns 404 with the application's own JSON body. Did the request reach the backend?
A: **Yes.** The backend answered: the path it received does not exist there (often because of the proxy_pass URI rule). Check the backend's log for the path that arrived.
Q: Which status does nginx return when the backend accepted no connection within proxy_connect_timeout?
A: **504 Gateway Time-out**.
:::

`,

  errorMap: [
    { message: 'connect() failed (111: Connection refused) while connecting to upstream', layer: 'Proxy → backend', meaning: 'Nothing listens on the upstream address/port (wrong port, app down).', firstCheck: 'The upstream: field; ss -tlnp / docker compose ps on the backend; curl from the proxy' },
    { message: 'upstream timed out (110: Connection timed out) while connecting to upstream', layer: 'Proxy → backend (path)', meaning: 'SYNs from the proxy get no answer: a firewall drops them (often only clients are allowed).', firstCheck: 'nc -zv -w 3 BACKEND PORT from the proxy vs from a client; backend nft ruleset' },
    { message: 'upstream timed out (110: Connection timed out) while reading response header from upstream', layer: 'Backend application', meaning: 'Connected, but the app took longer than proxy_read_timeout.', firstCheck: 'The backend\'s logs and load; time a direct request' },
    { message: '[emerg] host not found in upstream "NAME:PORT" in /etc/nginx/nginx.conf:LINE', layer: 'Proxy configuration / DNS', meaning: 'An upstream name does not resolve at load time: nginx will not start (reload keeps the old config).', firstCheck: 'getent hosts NAME on the proxy; nginx -t' },
    { message: 'SSL_do_handshake() failed (SSL: error:0A00010B:SSL routines::wrong version number) while SSL handshaking to upstream', layer: 'Proxy → backend (protocol)', meaning: 'proxy_pass https:// to a backend that speaks plain HTTP.', firstCheck: 'curl -v http:// and https:// to the backend from the proxy' },
    { message: 'connect() to 10.0.20.40:8000 failed (13: Permission denied) while connecting to upstream', layer: 'SELinux (RHEL)', meaning: 'httpd_can_network_connect is off.', firstCheck: 'getsebool httpd_can_network_connect; ausearch -m avc -ts recent' },
    { message: 'no live upstreams while connecting to upstream', layer: 'Upstream group', meaning: 'Every server in the upstream group failed recently and is temporarily skipped.', firstCheck: 'Earlier error.log lines for each server' },
    { message: 'upstream prematurely closed connection while reading response header from upstream', layer: 'Backend', meaning: 'The backend accepted and closed without an HTTP answer (crash, wrong protocol, worker killed).', firstCheck: 'The backend\'s logs at that time' },
  ],

  scenarioIds: ['proxy-bad-gateway', 'proxy-prefix-404', 'proxy-host-not-found', 'proxy-gateway-timeout', 'proxy-tls-upstream'],
  assessmentId: 'webproxy',
  references: [
    { title: 'nginx documentation: ngx_http_proxy_module (proxy_pass, timeouts, headers)', url: 'https://nginx.org/en/docs/http/ngx_http_proxy_module.html' },
    { title: 'nginx documentation: ngx_http_upstream_module', url: 'https://nginx.org/en/docs/http/ngx_http_upstream_module.html' },
    { title: 'nginx documentation: How nginx processes a request (server and location selection)', url: 'https://nginx.org/en/docs/http/request_processing.html' },
    { title: 'nginx documentation: location directive', url: 'https://nginx.org/en/docs/http/ngx_http_core_module.html#location' },
    { title: 'Red Hat: Configuring NGINX as a reverse proxy (RHEL 9)', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/deploying_web_servers_and_reverse_proxies/setting-up-and-configuring-nginx_deploying-web-servers-and-reverse-proxies' },
    { title: 'Microsoft Learn: Reverse proxy with URL Rewrite and Application Request Routing', url: 'https://learn.microsoft.com/iis/extensions/url-rewrite-module/reverse-proxy-with-url-rewrite-v2-and-application-request-routing' },
    { title: 'RFC 9110: HTTP Semantics (502, 503, 504; Forwarded headers in RFC 7239)', url: 'https://www.rfc-editor.org/rfc/rfc9110' },
  ],
  guide: WEBPROXY_GUIDE,
  objectives: ['N10-009:1.2', 'N10-009:1.4', 'N10-009:5.3'],
};

// --- Primer -------------------------------------------------------------------------

export const WEBPROXY_PRIMER: Primer = {
  oneLiner: 'A **reverse proxy** answers clients for other servers: it receives the request, opens **its own** connection to the right backend, and passes the answer back. When it cannot reach the backend it says so itself: **502 Bad Gateway** (refused or broken) or **504 Gateway Time-out** (no answer).',
  analogy: `
A hotel reception desk. Guests only ever talk to the receptionist (the proxy). When a guest asks for room service, the receptionist phones the kitchen (the backend) **from the desk phone** and relays the answer.

If the kitchen line is busy or wrong ("nobody at that extension") the receptionist answers at once: "the kitchen cannot take orders" (**502**). If the phone just rings and rings, the guest waits until the receptionist gives up (**504**). And if the kitchen only accepts calls from guest rooms, a guest calling from their room gets through while the receptionist never does: test from where the call really starts.`,
  ideas: [
    {
      title: 'Two connections, two clients',
      explain: 'The client connects to the proxy; the proxy makes a **new** connection to the backend. For the backend, the proxy is the client: its address, its routes, its firewall rules.',
      example: 'ws01 → srv01:80 (nginx) and then srv01 (10.0.20.10) → dock01:8000. dock01\'s log shows 10.0.20.10, not ws01. A firewall on dock01 that allows only 10.0.10.0/24 lets ws01 test the API directly while the proxy times out.',
    },
    {
      title: 'location and proxy_pass decide where a request goes',
      explain: 'nginx picks the server block by Host header, then the location with the longest matching prefix. With `proxy_pass http://host:port/;` (a URI part) the prefix is replaced; without it the path is passed as is.',
      example: '`location /inventory/ { proxy_pass http://dock01.corp.lab:8000/; }`: /inventory/health reaches the API as /health. Drop the final slash and the API receives /inventory/health and answers 404.',
    },
    {
      title: '502 and 504 are the proxy talking about the backend',
      explain: 'The proxy is up and received your request. 502 = the backend refused or answered nonsense; 504 = it did not answer in time. The reason is in the proxy\'s error.log, with the exact upstream address.',
      example: '`tail /var/log/nginx/error.log` on srv01: `connect() failed (111: Connection refused) while connecting to upstream, … upstream: "http://10.0.20.40:8080/health"`: port 8080 is wrong, the API is on 8000.',
    },
    {
      title: 'Names are resolved when nginx loads',
      explain: 'nginx looks up every upstream host name at start and reload. If one does not resolve, nginx refuses to start: every site on that server goes down, not just one.',
      example: 'A typo `inventory-api.corp.lab` in proxy_pass: `nginx -t` says `host not found in upstream "inventory-api.corp.lab:8000"`. The reload fails quietly (the old config keeps running) and the next reboot takes www.corp.lab down too.',
    },
  ],
  walkthrough: {
    title: 'Following one request through the proxy',
    steps: [
      { label: 'Client to proxy', detail: '`curl -sS -i http://apps.corp.lab/inventory/health` on ws01. The `Server: nginx` header and the status tell you the proxy answered.' },
      { label: 'Proxy picks the route', detail: 'Server block apps.corp.lab, location /inventory/, proxy_pass http://dock01.corp.lab:8000/ (resolved to 10.0.20.40 at start).' },
      { label: 'Proxy to backend', detail: 'srv01 opens TCP to 10.0.20.40:8000 and sends `GET /health` with `Host: apps.corp.lab`. Test this hop yourself from srv01: `curl -sS http://dock01.corp.lab:8000/health`.' },
      { label: 'Backend answers', detail: 'The API answers 200 with JSON; nginx relays it and writes one line to /var/log/nginx/access.log.' },
      { label: 'When it fails', detail: 'Read /var/log/nginx/error.log on srv01: refused (111), timed out (110), TLS error or host not found each point to a different fix.' },
    ],
  },
  misconceptions: [
    { myth: '502 Bad Gateway means the proxy is broken.', truth: 'The proxy is working: it is reporting that the **backend** refused or failed. Look behind it.' },
    { myth: 'If the backend works from my PC, the proxy can reach it too.', truth: 'The proxy connects from its own address; firewalls, routes and ACLs may treat it differently. Test from the proxy host.' },
    { myth: 'systemctl reload nginx applied my change.', truth: 'Only if the configuration is valid. A failed reload keeps the old configuration running; run nginx -t and read the result.' },
  ],
  checks: [
    { q: 'The proxy answers 504 after a minute. Which hop and what kind of problem?', a: 'Proxy → backend: the connection attempt got no answer (packets dropped, typically a firewall), until proxy_connect_timeout (60 s by default).' },
    { q: 'Where do you find the exact upstream address and the reason for a 502?', a: 'In the proxy\'s error.log (/var/log/nginx/error.log): the message and the upstream: field.' },
    { q: '`location /app/ { proxy_pass http://b:8000; }` and the client asks /app/x. What does the backend receive?', a: '/app/x: without a URI part in proxy_pass the original path is passed unchanged.' },
    { q: 'Why can one typo in a proxy_pass host name take down every site on the server?', a: 'nginx resolves upstream names at start; "host not found in upstream" is fatal, so nginx does not start at all.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const WEBPROXY_ASSESSMENT: Assessment = {
  id: 'webproxy',
  title: 'Web servers and reverse proxies knowledge check',
  questions: [
    {
      id: 'webproxy-q-order',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/webproxy/internals'],
      prompt: 'Order what happens when ws01 requests http://apps.corp.lab/inventory/health through srv01.',
      items: ['ws01 resolves apps.corp.lab to srv01 and connects to port 80', 'nginx picks the server block apps.corp.lab', 'nginx picks location /inventory/', 'nginx opens a TCP connection from srv01 to 10.0.20.40:8000', 'the API receives GET /health and answers 200', 'nginx relays the answer and writes access.log'],
      concepts: ['web.proxy'],
      explanation: 'Server block (address, port, Host) first, then location (longest prefix), then a new upstream connection from the proxy host; the answer goes back through nginx, which logs it.',
    },
    {
      id: 'webproxy-q-502',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/webproxy/internals'],
      prompt: 'Users get "502 Bad Gateway" from the proxy immediately. What is the most likely cause?',
      exhibit: '2026/10/19 08:34:00 [error] 433#433: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 10.0.10.25, server: apps.corp.lab, request: "GET /inventory/health HTTP/1.1", upstream: "http://10.0.20.40:8080/health", host: "apps.corp.lab"',
      options: [
        { text: 'Nothing listens on 10.0.20.40:8080: proxy_pass names the wrong port, or the app is down', correct: true },
        { text: 'A firewall drops the proxy\'s packets', misconception: 'A drop gives no answer: that is a timeout (110) and a 504, not a refusal (111).' },
        { text: 'apps.corp.lab does not resolve on the client', misconception: 'The request reached nginx (it logged it); the failure is between nginx and its upstream.' },
        { text: 'The proxy\'s TLS certificate expired', misconception: 'The client used http, and the error is about the upstream connection.' },
      ],
      concepts: ['web.proxy', 'tcp.handshake'],
      explanation: '111 is ECONNREFUSED: the backend host answered the SYN with a RST because no process listens on that port. Check the upstream: field against the port the application really uses.',
    },
    {
      id: 'webproxy-q-uri',
      kind: 'text',
      level: 'intermediate',
      learn: ['lesson/webproxy/internals'],
      prompt: 'With `location /inventory/ { proxy_pass http://dock01.corp.lab:8000/; }`, which path does the backend receive for a client request to `/inventory/items?page=2`?',
      accept: ['/items?page=2'],
      placeholder: '/...',
      concepts: ['web.proxy'],
      explanation: 'proxy_pass has a URI part ("/"), so the matched prefix /inventory/ is replaced by "/"; the query string is kept.',
    },
    {
      id: 'webproxy-q-504',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/webproxy/internals'],
      prompt: 'http://inventory.corp.lab:8000/health works from every office PC, but through the proxy on srv01 the same API answers 504 after 60 seconds. What do you check first?',
      options: [
        { text: 'The backend\'s firewall: does it allow connections from the proxy\'s address (10.0.20.10)?', correct: true },
        { text: 'The proxy\'s DNS: does it resolve apps.corp.lab?', misconception: 'Clients resolve apps.corp.lab, and the request clearly reached nginx (it answered 504).' },
        { text: 'The API\'s database connection', misconception: 'Office PCs get answers from the same API, so the application and its database work.' },
        { text: 'Raise proxy_read_timeout', misconception: 'The connection itself is not established (timeout while connecting); a longer read timeout changes nothing.' },
      ],
      concepts: ['web.proxy', 'fw.path'],
      explanation: 'The proxy connects from its own address. A backend firewall that allows only the client network lets direct tests pass while the proxy\'s SYNs are dropped, which nginx reports as 504 after proxy_connect_timeout.',
    },
    {
      id: 'webproxy-q-reload',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/webproxy/internals'],
      prompt: 'An upstream host name in nginx.conf was mistyped and `systemctl reload nginx` was run on Friday. Which statements are true? (choose all that apply)',
      options: [
        { text: 'The reload failed and nginx kept serving with the previous configuration', correct: true },
        { text: 'nginx -t reports "host not found in upstream"', correct: true },
        { text: 'After the next reboot nginx will not start, so every site on that server is down', correct: true },
        { text: 'Only the location with the typo returns errors after the reboot', misconception: 'The [emerg] is fatal for the whole configuration: nginx does not start at all.' },
      ],
      concepts: ['web.proxy', 'svc.systemd'],
      explanation: 'Upstream names are resolved when the configuration is loaded. A failed reload keeps the old workers; a start with the broken file fails completely.',
    },
    {
      id: 'webproxy-q-who',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/webproxy/internals'],
      prompt: 'Through the proxy you get `HTTP/1.1 404 Not Found` with `Server: nginx/1.22.1` and the body `{"detail":"Not found."}`. Who decided the request does not exist?',
      options: [
        { text: 'The backend application (the body is its JSON); nginx only replaced the Server header', correct: true },
        { text: 'nginx, because the Server header says nginx', misconception: 'A proxy sets its own Server header on relayed answers; nginx\'s own 404 is an HTML page.' },
        { text: 'The client\'s browser cache', misconception: 'curl does not cache, and the status came from the server side.' },
      ],
      concepts: ['web.proxy'],
      explanation: 'Look at the body and at the backend\'s log: the request reached the app with a path it does not know, typically because of the proxy_pass URI rule.',
    },
  ],
};
