// nginx.conf subset: server blocks with listen (ssl, default_server), server_name,
// root, index and the ssl_certificate / ssl_certificate_key pair. Line numbers
// are kept so that errors read like `nginx -t`.

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
  line: number;
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
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    if (/^server\s*\{$/.test(line)) {
      depth++;
      serverDepth = depth;
      cur = { listens: [], names: [], root: '/var/www/html', index: ['index.html', 'index.htm', 'index.nginx-debian.html'], line: i + 1 };
      servers.push(cur);
      return;
    }
    if (line.endsWith('{')) { depth++; return; }
    if (line === '}') {
      if (depth === serverDepth) { cur = null; serverDepth = -1; }
      depth--;
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
