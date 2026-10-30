// HTTP and TLS on top of the TCP model: nginx picks a server block (by address,
// port and Host/SNI), serves files from its root with the right status codes,
// and presents the certificate chain it loaded at start/reload. Bulk transfers
// push real full-size segments through the network, so MTU problems show up
// exactly where they do in practice: small requests work, large responses stall.

import { canAccess, canTraverse, mkdir, readFile, writeFile } from '../fs';
import type { Host, UserAccount, World } from '../types';
import { allListeners, type NginxLoaded, type NginxLoadedLocation, type NginxLoadedServer } from './services';
import { keyIdFor, makeCert } from './pki';
import { type ConnectErrno, tcpConnect, type TcpConn } from './tcp';

export const NGINX_VERSION = 'nginx/1.22.1';

/** The page Debian's nginx package installs as /var/www/html/index.nginx-debian.html. */
export const NGINX_WELCOME = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`;

const WWW_DATA: UserAccount = { name: 'www-data', uid: 33, gid: 33, primaryGroup: 'www-data', groups: [], home: '/var/www', shell: '/usr/sbin/nologin', gecos: 'www-data', password: null };

const REASON: Record<number, string> = { 200: 'OK', 301: 'Moved Permanently', 302: 'Found', 400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error', 502: 'Bad Gateway', 504: 'Gateway Time-out' };

const MIME: Record<string, string> = {
  html: 'text/html', htm: 'text/html', txt: 'text/plain', css: 'text/css', js: 'application/javascript', json: 'application/json',
  crt: 'application/x-x509-ca-cert', der: 'application/x-x509-ca-cert', pem: 'application/x-x509-ca-cert', iso: 'application/octet-stream',
  png: 'image/png', jpg: 'image/jpeg', svg: 'image/svg+xml', zip: 'application/zip',
};

export interface HttpResponse {
  status: number;
  reason: string;
  headers: [string, string][];
  body: string;
  /** Body length in bytes (files may be larger than the text the simulator stores). */
  size: number;
  binary: boolean;
}

function errorPage(status: number, title = `${status} ${REASON[status]}`, extra = ''): string {
  return `<html>\n<head><title>${title}</title></head>\n<body>\n<center><h1>${status} ${REASON[status]}</h1></center>\n${extra}<hr><center>${NGINX_VERSION}</center>\n</body>\n</html>\n`;
}

/** The server block nginx uses for a connection to localAddr:port with this Host header / SNI name. */
export function selectServer(loaded: NginxLoaded | null | undefined, localAddr: string, port: number, name?: string): NginxLoadedServer | undefined {
  const v6 = localAddr.includes(':');
  const candidates = (loaded?.servers ?? []).filter((s) => s.listens.some((l) => l.port === port && (l.addr === localAddr || (!v6 && l.addr === '0.0.0.0') || (v6 && l.addr === '::'))));
  const n = name?.toLowerCase().replace(/:\d+$/, '');
  return (n ? candidates.find((s) => s.names.some((x) => x.toLowerCase() === n || (x.startsWith('*.') && n.endsWith(x.slice(1))))) : undefined)
    ?? candidates.find((s) => s.listens.some((l) => l.port === port && l.def))
    ?? candidates[0];
}

/** Does this server block terminate TLS on `port`? */
export const isTlsPort = (s: NginxLoadedServer | undefined, port: number) => !!s?.listens.some((l) => l.port === port && l.ssl);

function httpDate(ms: number): string {
  return new Date(Math.floor(ms)).toUTCString();
}

/** The web server configuration of a Windows host running IIS (W3SVC): one site on port 80. */
export function iisLoaded(host: Host): NginxLoaded | null {
  if (host.win?.services.W3SVC?.status !== 'Running') return null;
  return { binds: [{ addr: '0.0.0.0', port: 80 }], servers: [{ listens: [{ addr: '0.0.0.0', port: 80, ssl: false, def: true }], names: [], root: 'C:\\inetpub\\wwwroot', index: ['Default.htm', 'Default.asp', 'index.htm', 'index.html', 'iisstart.htm', 'default.aspx'] }] };
}

const PF_WEB_KEY = keyIdFor('pfsense-webgui:fw01');
/** pfSense's webConfigurator certificate: self-signed, created at installation. */
export const PF_WEB_CERT = makeCert({
  subject: [['C', 'US'], ['ST', 'State'], ['L', 'Locality'], ['O', 'pfSense webConfigurator Self-Signed Certificate'], ['CN', 'pfSense-6718a2c01e2f4']],
  issuer: [['C', 'US'], ['ST', 'State'], ['L', 'Locality'], ['O', 'pfSense webConfigurator Self-Signed Certificate'], ['CN', 'pfSense-6718a2c01e2f4']],
  notBefore: Date.parse('2026-09-01T00:00:00Z'), notAfter: Date.parse('2027-10-04T00:00:00Z'), san: ['DNS:pfSense-6718a2c01e2f4'], ca: false, keyId: PF_WEB_KEY, signer: PF_WEB_KEY,
});

/** pfSense's webConfigurator (nginx): HTTPS with the login page, HTTP redirected to HTTPS. */
export function pfWebLoaded(host: Host): NginxLoaded | null {
  if (host.kind !== 'pfsense') return null;
  return {
    binds: [{ addr: '0.0.0.0', port: 443 }, { addr: '0.0.0.0', port: 80 }],
    servers: [
      { listens: [{ addr: '0.0.0.0', port: 443, ssl: true, def: true }], names: [], root: '/usr/local/www', index: ['index.html'], tls: { chain: [PF_WEB_CERT], keyId: PF_WEB_KEY, certPath: '/var/etc/cert.crt' } },
      { listens: [{ addr: '0.0.0.0', port: 80, ssl: false, def: true }], names: [], root: '/usr/local/www', index: ['index.html'], ret: { code: 301, target: 'https://$host$request_uri' } },
    ],
  };
}

/** IIS 10 answering a request: files under C:\\inetpub\\wwwroot (case-insensitive), IIS error pages. */
function handleIisRequest(host: Host, s: NginxLoadedServer, req: { method: string; path: string; now: number }): HttpResponse {
  const base: [string, string][] = [['Server', 'Microsoft-IIS/10.0'], ['Date', httpDate(req.now)]];
  const page = (status: number, body: string): HttpResponse => ({ status, reason: REASON[status], body, size: body.length, binary: false, headers: [['Content-Type', 'text/html'], ...base, ['Content-Length', String(body.length)]] });
  const lookup = new Map(Object.keys(host.fs).map((k) => [k.toLowerCase(), k]));
  const clean = decodeURIComponent(req.path.split('?')[0]).replace(/\/+/g, '/');
  let key = lookup.get(`${s.root}${clean.replace(/\//g, '\\')}`.replace(/\\$/, '').toLowerCase());
  if (key && host.fs[key].type === 'dir') key = s.index.map((i) => lookup.get(`${key}\\${i}`.toLowerCase())).find((k) => k && host.fs[k].type === 'file');
  if (!key || host.fs[key].type !== 'file') {
    return page(404, '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n<html xmlns="http://www.w3.org/1999/xhtml">\n<head>\n<title>404 - File or directory not found.</title>\n</head>\n<body>\n<div id="header"><h1>Server Error</h1></div>\n<div id="content">\n <div class="content-container"><fieldset>\n  <h2>404 - File or directory not found.</h2>\n  <h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>\n </fieldset></div>\n</div>\n</body>\n</html>\n');
  }
  const node = host.fs[key];
  const ext = /\.([a-z0-9]+)$/i.exec(key)?.[1]?.toLowerCase() ?? '';
  const type = MIME[ext] ?? 'application/octet-stream';
  const size = node.size ?? node.content.length;
  return {
    status: 200, reason: 'OK', body: node.content, size, binary: !/^(text|application\/(json|javascript))/.test(type),
    headers: [['Content-Type', type], ['Last-Modified', httpDate(node.mtime)], ['Accept-Ranges', 'bytes'], ['ETag', `"${Math.floor(node.mtime / 1000).toString(16)}:0"`], ...base, ['Content-Length', String(size)]],
  };
}

/**
 * Extensions registered by other simulators: docker-proxy forwards a published
 * port to its container, and application servers inside containers (gunicorn)
 * answer HTTP themselves.
 */
export { httpHooks } from './httpHooks';
import { httpHooks } from './httpHooks';

/** The server that answers HTTP on host:port: through docker-proxy to the container when the port is a published one. */
export function httpBackend(world: World, host: Host, port: number, localAddr: string): { host: Host; port: number; local: string; proxyFrom?: string } {
  const l = allListeners(host).find((x) => x.port === port && x.proto === 'tcp');
  if (l?.process !== 'docker-proxy') return { host, port, local: localAddr };
  const b = httpHooks.proxy?.(world, host, port);
  if (!b) return { host, port, local: localAddr };
  // docker-proxy opens its own connection: the container sees the bridge gateway as the client.
  const gw = b.host.routes.find((r) => r.dest === 'default')?.via;
  return { host: b.host, port: b.port, local: b.host.ifaces.find((i) => i.name === 'eth0')?.address ?? localAddr, proxyFrom: gw };
}

export interface HttpRequestInfo {
  method: string; path: string; hostHeader: string; plainOnTls: boolean; now: number;
  /** Client address and User-Agent: when given, nginx writes its access log (and error log on failures). */
  client?: { ip: string; ua: string };
  /** Proxies already passed (a proxy_pass loop ends with a 500 instead of recursing forever). */
  hops?: number;
}

const pad2 = (n: number) => String(n).padStart(2, '0');
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function appendLog(host: Host, path: string, line: string, now: number): void {
  if (!host.fs['/var/log/nginx']) mkdir(host, '/var/log/nginx', now, { mode: 0o755, owner: 'root', group: 'adm' });
  const prev = readFile(host, path) ?? '';
  writeFile(host, path, prev + line + '\n', now, host.fs[path] ? undefined : { mode: 0o640, owner: 'www-data', group: 'adm' });
}

/** nginx's access.log (combined format) and error.log lines for a request. */
function logRequest(host: Host, req: HttpRequestInfo, r: HttpResponse, error?: string, server = '', upstream?: string): void {
  if (!req.client) return;
  const d = new Date(Math.floor(req.now));
  const access = `${pad2(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())} +0000`;
  const bytes = req.method === 'HEAD' ? 0 : r.size;
  appendLog(host, '/var/log/nginx/access.log', `${req.client.ip} - - [${access}] "${req.method} ${req.path} HTTP/1.1" ${r.status} ${bytes} "-" "${req.client.ua}"`, req.now);
  if (error) {
    const stamp = `${d.getUTCFullYear()}/${pad2(d.getUTCMonth() + 1)}/${pad2(d.getUTCDate())} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
    const pid = host.services.nginx?.pid ?? 0;
    appendLog(host, '/var/log/nginx/error.log', `${stamp} [error] ${pid + 1}#${pid + 1}: *1 ${error}, client: ${req.client.ip}, server: ${server}, request: "${req.method} ${req.path} HTTP/1.1"${upstream ? `, upstream: "${upstream}"` : ''}, host: "${req.hostHeader}"`, req.now);
  }
}

/** nginx answering one request (GET/HEAD) for `path` on server block `s`. */
export function handleRequest(host: Host, s: NginxLoadedServer, req: HttpRequestInfo, world?: World): HttpResponse {
  if (host.kind === 'windows') return handleIisRequest(host, s, req);
  const out = nginxRequest(host, s, req, world);
  logRequest(host, req, out.res, out.error, s.names[0] ?? '', out.upstream);
  return out.res;
}

/** nginx's location choice: an exact match, else the longest matching prefix. */
function matchLocation(locs: NginxLoadedLocation[] | undefined, uri: string): NginxLoadedLocation | undefined {
  if (!locs) return undefined;
  return locs.find((l) => l.exact && l.prefix === uri)
    ?? locs.filter((l) => !l.exact && uri.startsWith(l.prefix)).sort((a, b) => b.prefix.length - a.prefix.length)[0];
}

const UPSTREAM_ERR: Partial<Record<ConnectErrno, string>> = {
  ECONNREFUSED: 'connect() failed (111: Connection refused) while connecting to upstream',
  EHOSTUNREACH: 'connect() failed (113: No route to host) while connecting to upstream',
  ENETUNREACH: 'connect() failed (101: Network is unreachable) while connecting to upstream',
  ETIMEDOUT: 'upstream timed out (110: Connection timed out) while connecting to upstream',
};

/**
 * proxy_pass: nginx opens its own TCP connection from this host to the upstream
 * address it resolved at load time, sends the request with the rewritten URI and
 * Host header, and relays the answer (502/504 and an error.log line when it cannot).
 */
function proxyRequest(world: World, host: Host, loc: NginxLoadedLocation, req: HttpRequestInfo, page: (status: number, body: string) => HttpResponse, base: [string, string][]): { res: HttpResponse; error?: string; upstream?: string } {
  const p = loc.proxy!;
  if ((req.hops ?? 0) >= 4) return { res: page(500, errorPage(500)), error: 'rewrite or internal redirection cycle while processing proxy_pass' };
  const [pathOnly, query] = [req.path.split('?')[0], req.path.includes('?') ? req.path.slice(req.path.indexOf('?')) : ''];
  const upPath = p.uri === undefined ? req.path : (loc.exact ? p.uri : p.uri + pathOnly.slice(loc.prefix.length)) + query;
  const hostHdr = p.hostTemplate.replace('$proxy_host', p.proxyHost).replace('$http_host', req.hostHeader).replace('$host', req.hostHeader.replace(/:\d+$/, ''));
  let fail = { status: 502, error: '', upstream: '' };
  for (const t of p.targets) {
    const upstream = `${p.scheme}://${t.ip}:${t.port}${upPath}`;
    const c = tcpConnect(world, host, t.ip, t.port, { timeoutMs: p.connectTimeoutMs });
    if (!c.ok) {
      fail = { status: c.errno === 'ETIMEDOUT' ? 504 : 502, error: UPSTREAM_ERR[c.errno] ?? `connect() failed while connecting to upstream`, upstream };
      continue;
    }
    const conn = c.conn;
    const backend = httpBackend(world, conn.server, conn.sv.localPort, conn.sv.local);
    const server = backend.host;
    const listener = allListeners(server).find((l) => l.proto === 'tcp' && l.port === backend.port);
    const app = listener ? httpHooks.apps[listener.process] : undefined;
    const loaded = server.services.nginx?.state === 'active' ? (server.services.nginx.loaded as NginxLoaded) : iisLoaded(server);
    const tlsSock = !!loaded?.servers?.some((x) => isTlsPort(x, backend.port));
    if (!app && listener?.process !== 'nginx' && listener?.service !== 'W3SVC') {
      conn.close('server');
      fail = { status: 502, error: 'upstream prematurely closed connection while reading response header from upstream', upstream };
      continue;
    }
    if (p.scheme === 'https' && !tlsSock) {
      conn.close('client');
      fail = { status: 502, error: 'SSL_do_handshake() failed (SSL: error:0A00010B:SSL routines::wrong version number) while SSL handshaking to upstream', upstream };
      continue;
    }
    const ureq: HttpRequestInfo = { method: req.method, path: upPath, hostHeader: hostHdr, plainOnTls: p.scheme === 'http' && tlsSock, now: world.clock, client: { ip: backend.proxyFrom ?? conn.sv.peer, ua: req.client?.ua ?? '' }, hops: (req.hops ?? 0) + 1 };
    conn.send('c2s', 90 + upPath.length + hostHdr.length, { protocol: p.scheme === 'https' ? 'TLS' : 'DATA', info: `${req.method} ${upPath} HTTP/1.0 Host: ${hostHdr}`, fields: [] });
    const r = app ? app(world, server, ureq) : handleRequest(server, selectServer(loaded, backend.local, backend.port, hostHdr)!, ureq, world);
    conn.send('s2c', 200 + Math.min(r.size, 1200), { protocol: p.scheme === 'https' ? 'TLS' : 'DATA', info: `HTTP/1.1 ${r.status} ${r.reason}`, fields: [] });
    conn.close('client');
    // nginx sends its own Server, Date and Connection headers and relays the rest.
    const relayed = r.headers.filter(([k]) => k !== 'Server' && k !== 'Date' && k !== 'Connection');
    return { res: { ...r, headers: [...base.map(([k, v]): [string, string] => [k, k === 'Date' ? httpDate(world.clock) : v]), ...relayed, ['Connection', 'keep-alive']] } };
  }
  return { res: page(fail.status, errorPage(fail.status)), error: fail.error, upstream: fail.upstream };
}

function nginxRequest(host: Host, s: NginxLoadedServer, req: HttpRequestInfo, world?: World): { res: HttpResponse; error?: string; upstream?: string } {
  const base: [string, string][] = [['Server', host.kind === 'container' ? 'nginx/1.25.5' : NGINX_VERSION], ['Date', httpDate(req.now)]];
  const page = (status: number, body: string, more: [string, string][] = [], close = false): HttpResponse => ({
    status, reason: REASON[status], body, size: body.length, binary: false,
    headers: [...base, ['Content-Type', 'text/html'], ['Content-Length', String(body.length)], ['Connection', close ? 'close' : 'keep-alive'], ...more],
  });
  if (req.plainOnTls) {
    return { res: page(400, errorPage(400, '400 The plain HTTP request was sent to HTTPS port', '<center>The plain HTTP request was sent to HTTPS port</center>\n'), [], true) };
  }
  if (s.ret) {
    const target = s.ret.target.replace('$host', req.hostHeader.replace(/:\d+$/, '')).replace('$server_name', s.names[0] ?? '').replace('$request_uri', req.path);
    return { res: page(s.ret.code, errorPage(s.ret.code), target ? [['Location', target]] : []) };
  }
  const clean = decodeURIComponent(req.path.split('?')[0]).replace(/\/+/g, '/');
  const loc = matchLocation(s.locations, clean);
  if (loc?.proxy && world) return proxyRequest(world, host, loc, req, (st, body) => page(st, body), base);
  let fsPath = (s.root === '/' ? '' : s.root) + clean;
  let node = host.fs[fsPath.replace(/\/$/, '') || '/'];
  if (node?.type === 'dir') {
    if (!clean.endsWith('/')) return { res: page(301, errorPage(301), [['Location', `http://${req.hostHeader}${clean}/`]]) };
    const dir = fsPath.replace(/\/$/, '');
    const idx = s.index.map((i) => `${dir}/${i}`).find((p) => host.fs[p]?.type === 'file');
    if (!idx) return { res: page(403, errorPage(403)), error: `directory index of "${dir}/" is forbidden` };
    fsPath = idx;
    node = host.fs[idx];
  }
  if (!node || node.type !== 'file') return { res: page(404, errorPage(404)), error: `open() "${fsPath}" failed (2: No such file or directory)` };
  if (!canTraverse(host, fsPath, WWW_DATA)) return { res: page(403, errorPage(403)), error: `"${fsPath}" is forbidden (13: Permission denied)` };
  if (!canAccess(node, WWW_DATA, 'r')) return { res: page(403, errorPage(403)), error: `open() "${fsPath}" failed (13: Permission denied)` };
  const size = node.size ?? node.content.length;
  const ext = /\.([a-z0-9]+)$/i.exec(fsPath)?.[1]?.toLowerCase() ?? '';
  const type = MIME[ext] ?? 'application/octet-stream';
  const etag = `"${Math.floor(node.mtime / 1000).toString(16)}-${size.toString(16)}"`;
  return { res: {
    status: 200, reason: 'OK', body: node.content, size, binary: node.size !== undefined || !/^(text|application\/(json|javascript))/.test(type),
    headers: [...base, ['Content-Type', type], ['Content-Length', String(size)], ['Last-Modified', httpDate(node.mtime)], ['Connection', 'keep-alive'], ['ETag', etag], ['Accept-Ranges', 'bytes']],
  } };
}

/** Size of the response header block on the wire. */
export function headerBytes(r: HttpResponse): number {
  return `HTTP/1.1 ${r.status} ${r.reason}\r\n`.length + r.headers.reduce((n, [k, v]) => n + k.length + v.length + 4, 0) + 2;
}

/** Simulated link rate used to account time for the part of a large body not pushed segment by segment. */
const BYTES_PER_MS = 12_500; // 100 Mbit/s

/**
 * Send a response body of `size` bytes. The first 64 KiB travel as real segments (enough for every
 * path-MTU effect to show), the rest is accounted for in time and sequence numbers only.
 */
export function sendBulk(conn: TcpConn, dir: 'c2s' | 's2c', size: number, info: string, protocol: 'DATA' | 'TLS' = 'DATA'): boolean {
  const real = Math.min(size, 65_536);
  const r = conn.send(dir, real, { protocol, info, fields: [], encrypted: protocol === 'TLS' });
  if (!r.ok) return false;
  const rest = size - real;
  if (rest > 0) {
    conn.world.clock += rest / BYTES_PER_MS;
    conn.skip(dir, rest);
  }
  return true;
}
