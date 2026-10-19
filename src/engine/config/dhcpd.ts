// ISC dhcpd.conf parser (subset): global and subnet-scoped options,
// subnet/netmask declarations with range, host declarations with
// hardware ethernet / fixed-address, lease times, authoritative.
// Error messages follow dhcpd's "<file> line N: <message>" format.

import { parseCidr, parseIp } from '../net/ip';

export interface DhcpOptions {
  routers?: string[];
  domainNameServers?: string[];
  domainName?: string;
}

export interface DhcpSubnet {
  network: string;
  prefix: number;
  range?: [string, string];
  options: DhcpOptions;
  line: number;
}

export interface DhcpHost {
  name: string;
  mac?: string;
  fixedAddress?: string;
}

export interface DhcpdConfig {
  options: DhcpOptions;
  defaultLeaseTime: number;
  maxLeaseTime: number;
  authoritative: boolean;
  subnets: DhcpSubnet[];
  hosts: DhcpHost[];
}

export class DhcpConfigError extends Error {}

interface Tok { t: string; line: number }

function tokenize(text: string): Tok[] {
  const out: Tok[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '');
    const re = /"[^"]*"|[{};,]|[^\s{};,"]+/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line))) out.push({ t: m[0], line: i + 1 });
  });
  return out;
}

function maskToPrefix(mask: string): number | null {
  const n = parseIp(mask);
  if (n === null) return null;
  const bits = n.toString(2).padStart(32, '0');
  if (!/^1*0*$/.test(bits)) return null;
  return bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
}

export function parseDhcpdConf(text: string, file = '/etc/dhcp/dhcpd.conf'): DhcpdConfig {
  const toks = tokenize(text);
  let i = 0;
  const cfg: DhcpdConfig = { options: {}, defaultLeaseTime: 43200, maxLeaseTime: 86400, authoritative: false, subnets: [], hosts: [] };
  const err = (line: number, msg: string): never => {
    throw new DhcpConfigError(`${file} line ${line}: ${msg}`);
  };
  const peek = () => toks[i];
  const next = (): Tok => toks[i++] ?? err(toks[toks.length - 1]?.line ?? 1, 'unexpected end of file');
  const semi = () => {
    const t = next();
    if (t.t !== ';') err(t.line, 'semicolon expected.');
  };
  const ip = (t: Tok) => (parseIp(t.t) !== null ? t.t : err(t.line, `${t.t}: host address expected`));
  const list = (): string[] => {
    const vals: string[] = [ip(next())];
    while (peek()?.t === ',') { i++; vals.push(ip(next())); }
    return vals;
  };
  const option = (opts: DhcpOptions) => {
    const name = next();
    switch (name.t) {
      case 'routers': opts.routers = list(); break;
      case 'domain-name-servers': opts.domainNameServers = list(); break;
      case 'domain-name': {
        const v = next();
        if (!v.t.startsWith('"')) err(v.line, 'expecting string.');
        opts.domainName = v.t.slice(1, -1);
        break;
      }
      case 'subnet-mask': case 'broadcast-address': case 'ntp-servers': list(); break;
      default: err(name.line, `unknown option dhcp.${name.t}`);
    }
    semi();
  };
  const block = (onStmt: (t: Tok) => void) => {
    const open = next();
    if (open.t !== '{') err(open.line, 'expecting left brace.');
    while (peek() && peek()!.t !== '}') onStmt(next());
    if (!peek()) err(open.line, 'expecting right brace.');
    i++;
  };
  while (i < toks.length) {
    const t = next();
    switch (t.t) {
      case 'option': option(cfg.options); break;
      case 'default-lease-time': cfg.defaultLeaseTime = Number(next().t); semi(); break;
      case 'max-lease-time': cfg.maxLeaseTime = Number(next().t); semi(); break;
      case 'authoritative': cfg.authoritative = true; semi(); break;
      case 'ddns-update-style': case 'log-facility': next(); semi(); break;
      case 'subnet': {
        const net = ip(next());
        if (next().t !== 'netmask') err(t.line, 'expecting netmask');
        const maskTok = next();
        const prefix = maskToPrefix(ip(maskTok)) ?? err(maskTok.line, `${maskTok.t}: invalid netmask`);
        const c = parseCidr(`${net}/${prefix}`)!;
        if (parseIp(net) !== c.network) err(t.line, `subnet ${net} netmask ${maskTok.t}: bad subnet number/mask combination.`);
        const sub: DhcpSubnet = { network: net, prefix, options: {}, line: t.line };
        block((s) => {
          if (s.t === 'range') {
            const a = ip(next());
            const b = ip(next());
            semi();
            for (const x of [a, b]) if (!parseCidr(`${net}/${prefix}`) || ((parseIp(x)! >>> (32 - prefix)) !== (c.network >>> (32 - prefix)))) err(s.line, `bad range, address ${x} not in subnet ${net} netmask ${maskTok.t}`);
            sub.range = [a, b];
          } else if (s.t === 'option') option(sub.options);
          else if (s.t === 'default-lease-time' || s.t === 'max-lease-time') { next(); semi(); }
          else err(s.line, `expecting a declaration`);
        });
        cfg.subnets.push(sub);
        break;
      }
      case 'host': {
        const h: DhcpHost = { name: next().t };
        block((s) => {
          if (s.t === 'hardware') {
            if (next().t !== 'ethernet') err(s.line, 'expecting hardware type');
            const m = next();
            if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(m.t)) err(m.line, 'expecting a hardware address');
            h.mac = m.t.toLowerCase();
            semi();
          } else if (s.t === 'fixed-address') { h.fixedAddress = ip(next()); semi(); }
          else if (s.t === 'option') option({});
          else err(s.line, `expecting a declaration`);
        });
        cfg.hosts.push(h);
        break;
      }
      default:
        err(t.line, `expecting a parameter or declaration`);
    }
  }
  return cfg;
}

export interface Lease {
  ip: string;
  mac: string;
  hostname: string;
  starts: number;
  ends: number;
  state: 'active' | 'free';
}

const LEASE_RE = /lease (\d+\.\d+\.\d+\.\d+) \{([^}]*)\}/g;

function parseDate(s: string): number {
  // "1 2026/10/19 08:00:00" (weekday, UTC)
  const m = /\d (\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})/.exec(s);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : 0;
}

export function formatLeaseDate(ms: number): string {
  const d = new Date(Math.floor(ms));
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCDay()} ${d.getUTCFullYear()}/${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

/** Parse dhcpd.leases; later entries for the same address win (append-only file, as in dhcpd). */
export function parseLeases(text: string): Lease[] {
  const byIp = new Map<string, Lease>();
  let m: RegExpExecArray | null;
  LEASE_RE.lastIndex = 0;
  while ((m = LEASE_RE.exec(text))) {
    const body = m[2];
    byIp.set(m[1], {
      ip: m[1],
      mac: (/hardware ethernet ([0-9a-f:]+);/i.exec(body)?.[1] ?? '').toLowerCase(),
      hostname: /client-hostname "([^"]*)";/.exec(body)?.[1] ?? '',
      starts: parseDate(/starts ([^;]+);/.exec(body)?.[1] ?? ''),
      ends: parseDate(/ends ([^;]+);/.exec(body)?.[1] ?? ''),
      state: /binding state active/.test(body) ? 'active' : 'free',
    });
  }
  return [...byIp.values()];
}

export function formatLease(l: Lease): string {
  return `lease ${l.ip} {\n  starts ${formatLeaseDate(l.starts)};\n  ends ${formatLeaseDate(l.ends)};\n  binding state ${l.state};\n  hardware ethernet ${l.mac};\n${l.hostname ? `  client-hostname "${l.hostname}";\n` : ''}}\n`;
}
