// nginx.conf subset: server blocks with listen (ssl, default_server), server_name,
// root, index and the ssl_certificate / ssl_certificate_key pair; prefix and exact
// locations with proxy_pass, proxy_set_header Host and proxy_connect_timeout; and
// upstream blocks. Line numbers are kept so that errors read like `nginx -t`.

export interface NginxListen { addr: string; port: number; ssl: boolean; def: boolean; line: number }

export interface NginxServer {
  listens: NginxListen[];
  names: string[];
  root: string;
  index: string[];
  cert?: { path: string; line: number };
  key?: { path: string; line: number };
  /** `return CODE [URL]` at server level (e.g. an HTTP -> HTTPS redirect). */
  ret?: { code: number; target: string };
  locations: NginxLocation[];
  line: number;
}

export interface NginxLocation {
  /** URI prefix (or the exact URI with `=`). Regex locations are not modelled. */
  prefix: string;
  exact: boolean;
  proxyPass?: { url: string; line: number };
  /** proxy_set_header Host VALUE (nginx's default is $proxy_host). */
  hostHeader?: string;
  /** proxy_connect_timeout in milliseconds (default 60 s). */
  connectTimeoutMs?: number;
  line: number;
}

export interface NginxUpstream { name: string; servers: { spec: string; line: number }[]; line: number }

/** nginx time value: "5", "5s", "500ms", "1m". */
export function nginxTime(v: string): number | undefined {
  const m = /^(\d+)(ms|s|m)?$/.exec(v);
  if (!m) return undefined;
  return Number(m[1]) * (m[2] === 'ms' ? 1 : m[2] === 'm' ? 60_000 : 1000);
}

/** upstream NAME { server HOST:PORT; ... } blocks (inside http). */
export function parseNginxUpstreams(text: string): NginxUpstream[] {
  const ups: NginxUpstream[] = [];
  let cur: NginxUpstream | null = null;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    const open = /^upstream\s+(\S+)\s*\{$/.exec(line);
    if (open) { cur = { name: open[1], servers: [], line: i + 1 }; ups.push(cur); return; }
    if (!cur) return;
    if (line === '}') { cur = null; return; }
    const m = /^server\s+(\S+?)(\s[^;]*)?;$/.exec(line);
    if (m) (cur as NginxUpstream).servers.push({ spec: m[1], line: i + 1 });
  });
  return ups;
}

/** Parse the listen spec of a directive ("443", "[::]:443", "10.0.20.10:80"); null if the port is invalid. */
export function parseListenSpec(spec: string): { addr: string; port: number } | null {
  let addr = '0.0.0.0';
  let portStr = spec;
  const v6 = /^\[(.*)\]:(\d+)$/.exec(spec);
  if (v6) { addr = v6[1] || '::'; portStr = v6[2]; }
  else if (spec.includes(':')) [addr, portStr] = spec.split(':');
  const port = Number(portStr);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? { addr, port } : null;
}

export function parseNginxServers(text: string): NginxServer[] {
  const servers: NginxServer[] = [];
  let cur: NginxServer | null = null;
  let depth = 0;
  let serverDepth = -1;
  let loc: NginxLocation | null = null;
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    if (/^server\s*\{$/.test(line)) {
      depth++;
      serverDepth = depth;
      cur = { listens: [], names: [], root: '/var/www/html', index: ['index.html', 'index.htm', 'index.nginx-debian.html'], locations: [], line: i + 1 };
      servers.push(cur);
      return;
    }
    const lm = /^location\s+(=\s*|\^~\s*)?(\/\S*)\s*\{$/.exec(line);
    if (lm && cur && depth === serverDepth) {
      depth++;
      loc = { prefix: lm[2], exact: (lm[1] ?? '').trim() === '=', line: i + 1 };
      (cur as NginxServer).locations.push(loc);
      return;
    }
    if (line.endsWith('{')) { depth++; return; }
    if (line === '}') {
      if (depth === serverDepth) { cur = null; serverDepth = -1; }
      if (loc && depth === serverDepth + 1) loc = null;
      depth--;
      return;
    }
    if (loc && cur && depth === serverDepth + 1) {
      const l: NginxLocation = loc;
      const [d, ...a] = line.replace(/;$/, '').split(/\s+/);
      if (d === 'proxy_pass' && a[0]) l.proxyPass = { url: a[0], line: i + 1 };
      if (d === 'proxy_set_header' && a[0]?.toLowerCase() === 'host' && a[1]) l.hostHeader = a[1];
      if (d === 'proxy_connect_timeout' && a[0]) l.connectTimeoutMs = nginxTime(a[0]);
      return;
    }
    if (!cur || depth !== serverDepth) return;
    const s: NginxServer = cur;
    const [name, ...args] = line.replace(/;$/, '').split(/\s+/);
    switch (name) {
      case 'listen': {
        const spec = args[0] ? parseListenSpec(args[0]) : null;
        if (spec) s.listens.push({ ...spec, ssl: args.includes('ssl'), def: args.includes('default_server'), line: i + 1 });
        break;
      }
      case 'server_name': s.names.push(...args); break;
      case 'root': if (args[0]) s.root = args[0].replace(/\/$/, '') || '/'; break;
      case 'index': s.index = args; break;
      case 'ssl_certificate': if (args[0]) s.cert = { path: args[0], line: i + 1 }; break;
      case 'ssl_certificate_key': if (args[0]) s.key = { path: args[0], line: i + 1 }; break;
      case 'return': if (args[0]) s.ret = { code: Number(args[0]), target: args.slice(1).join(' ') }; break;
    }
  });
  return servers;
}
