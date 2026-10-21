// HTTP and TLS on top of the TCP model: nginx picks a server block (by address,
// port and Host/SNI), serves files from its root with the right status codes,
// and presents the certificate chain it loaded at start/reload. Bulk transfers
// push real full-size segments through the network, so MTU problems show up
// exactly where they do in practice: small requests work, large responses stall.

import { canAccess, canTraverse } from '../fs';
import type { Host, UserAccount } from '../types';
import type { NginxLoaded, NginxLoadedServer } from './services';
import type { TcpConn } from './tcp';

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

const REASON: Record<number, string> = { 200: 'OK', 301: 'Moved Permanently', 302: 'Found', 400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found' };

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

/** nginx answering one request (GET/HEAD) for `path` on server block `s`. */
export function handleRequest(host: Host, s: NginxLoadedServer, req: { method: string; path: string; hostHeader: string; plainOnTls: boolean; now: number }): HttpResponse {
  const base: [string, string][] = [['Server', NGINX_VERSION], ['Date', httpDate(req.now)]];
  const page = (status: number, body: string, more: [string, string][] = [], close = false): HttpResponse => ({
    status, reason: REASON[status], body, size: body.length, binary: false,
    headers: [...base, ['Content-Type', 'text/html'], ['Content-Length', String(body.length)], ['Connection', close ? 'close' : 'keep-alive'], ...more],
  });
  if (req.plainOnTls) {
    return page(400, errorPage(400, '400 The plain HTTP request was sent to HTTPS port', '<center>The plain HTTP request was sent to HTTPS port</center>\n'), [], true);
  }
  if (s.ret) {
    const target = s.ret.target.replace('$host', req.hostHeader.replace(/:\d+$/, '')).replace('$server_name', s.names[0] ?? '').replace('$request_uri', req.path);
    return page(s.ret.code, errorPage(s.ret.code), target ? [['Location', target]] : []);
  }
  const clean = decodeURIComponent(req.path.split('?')[0]).replace(/\/+/g, '/');
  let fsPath = (s.root === '/' ? '' : s.root) + clean;
  let node = host.fs[fsPath.replace(/\/$/, '') || '/'];
  if (node?.type === 'dir') {
    if (!clean.endsWith('/')) return page(301, errorPage(301), [['Location', `http://${req.hostHeader}${clean}/`]]);
    const dir = fsPath.replace(/\/$/, '');
    const idx = s.index.map((i) => `${dir}/${i}`).find((p) => host.fs[p]?.type === 'file');
    if (!idx) return page(403, errorPage(403));
    fsPath = idx;
    node = host.fs[idx];
  }
  if (!node || node.type !== 'file') return page(404, errorPage(404));
  if (!canTraverse(host, fsPath, WWW_DATA) || !canAccess(node, WWW_DATA, 'r')) return page(403, errorPage(403));
  const size = node.size ?? node.content.length;
  const ext = /\.([a-z0-9]+)$/i.exec(fsPath)?.[1]?.toLowerCase() ?? '';
  const type = MIME[ext] ?? 'application/octet-stream';
  const etag = `"${Math.floor(node.mtime / 1000).toString(16)}-${size.toString(16)}"`;
  return {
    status: 200, reason: 'OK', body: node.content, size, binary: node.size !== undefined || !/^(text|application\/(json|javascript))/.test(type),
    headers: [...base, ['Content-Type', type], ['Content-Length', String(size)], ['Last-Modified', httpDate(node.mtime)], ['Connection', 'keep-alive'], ['ETag', etag], ['Accept-Ranges', 'bytes']],
  };
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
