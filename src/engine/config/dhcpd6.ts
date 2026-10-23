// ISC dhcpd6.conf parser (subset used by `dhcpd -6`): lease times, preferred
// lifetime, dhcp6.name-servers / dhcp6.domain-search, subnet6 declarations with
// range6, and host declarations (host-identifier option dhcp6.client-id or
// hardware ethernet, fixed-address6). Errors follow dhcpd's "<file> line N:" format.
// Also the dhcpd6.leases format (ia-na blocks keyed by IAID + client DUID).

import { canonicalIp6, inCidr6, parseCidr6, parseIp6 } from '../net/ip6';
import { DhcpConfigError, formatLeaseDate } from './dhcpd';

export interface Dhcp6Options {
  nameServers?: string[];
  domainSearch?: string[];
}

export interface Dhcp6Subnet {
  /** Canonical prefix, e.g. "2001:db8:30::/64". */
  prefix: string;
  range?: [string, string];
  options: Dhcp6Options;
  line: number;
}

export interface Dhcp6Host {
  name: string;
  /** Client DUID as colon-separated hex (host-identifier option dhcp6.client-id). */
  duid?: string;
  mac?: string;
  fixedAddress?: string;
}

export interface Dhcpd6Config {
  options: Dhcp6Options;
  /** Valid lifetime of assigned addresses (seconds). */
  defaultLeaseTime: number;
  maxLeaseTime: number;
  /** Preferred lifetime; dhcpd uses 5/8 of default-lease-time when it is not set. */
  preferredLifetime?: number;
  subnets: Dhcp6Subnet[];
  hosts: Dhcp6Host[];
}

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

const HEX_ID = /^[0-9a-f]{1,2}(:[0-9a-f]{1,2})+$/i;

export function parseDhcpd6Conf(text: string, file = '/etc/dhcp/dhcpd6.conf'): Dhcpd6Config {
  const toks = tokenize(text);
  let i = 0;
  const cfg: Dhcpd6Config = { options: {}, defaultLeaseTime: 43200, maxLeaseTime: 86400, subnets: [], hosts: [] };
  const err = (line: number, msg: string): never => {
    throw new DhcpConfigError(`${file} line ${line}: ${msg}`);
  };
  const peek = () => toks[i];
  const next = (): Tok => toks[i++] ?? err(toks[toks.length - 1]?.line ?? 1, 'unexpected end of file');
  const semi = () => {
    const t = next();
    if (t.t !== ';') err(t.line, 'semicolon expected.');
  };
  const seconds = (v: Tok) => (/^\d+$/.test(v.t) ? Number(v.t) : err(v.line, 'expecting number.'));
  const ip6 = (t: Tok) => (parseIp6(t.t) !== null ? canonicalIp6(t.t)! : err(t.line, `${t.t}: expecting IPv6 address`));
  const option = (opts: Dhcp6Options) => {
    const name = next();
    switch (name.t) {
      case 'dhcp6.name-servers': {
        const vals = [ip6(next())];
        while (peek()?.t === ',') { i++; vals.push(ip6(next())); }
        opts.nameServers = vals;
        break;
      }
      case 'dhcp6.domain-search': {
        const vals: string[] = [];
        do {
          if (vals.length) i++;
          const v = next();
          if (!v.t.startsWith('"')) err(v.line, 'expecting string.');
          vals.push(v.t.slice(1, -1));
        } while (peek()?.t === ',');
        opts.domainSearch = vals;
        break;
      }
      case 'dhcp6.info-refresh-time': case 'dhcp6.preference': case 'dhcp6.rapid-commit': next(); break;
      default:
        if (name.t.startsWith('dhcp6.') || !name.t.includes('.')) err(name.line, `unknown option ${name.t.includes('.') ? name.t : `dhcp6.${name.t}`}`);
        // An IPv4 option such as "domain-name-servers" in dhcpd6.conf is a classic mistake.
        err(name.line, `unknown option ${name.t}`);
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
      case 'option':
        if (peek() && !peek()!.t.startsWith('dhcp6.') && ['domain-name-servers', 'domain-name', 'routers'].includes(peek()!.t)) {
          err(peek()!.line, `${peek()!.t} is an IPv4 (DHCPv4) option; dhcpd -6 uses dhcp6.name-servers and dhcp6.domain-search`);
        }
        option(cfg.options);
        break;
      case 'default-lease-time': cfg.defaultLeaseTime = seconds(next()); semi(); break;
      case 'max-lease-time': cfg.maxLeaseTime = seconds(next()); semi(); break;
      case 'preferred-lifetime': cfg.preferredLifetime = seconds(next()); semi(); break;
      case 'authoritative': semi(); break;
      case 'ddns-update-style': case 'log-facility': next(); semi(); break;
      case 'subnet': err(t.line, 'subnet declarations are for DHCPv4 (dhcpd.conf); use subnet6 PREFIX/LEN in dhcpd6.conf'); break;
      case 'subnet6': {
        const pt = next();
        const c = parseCidr6(pt.t);
        if (!c || !pt.t.includes('/')) err(pt.line, `${pt.t}: expecting IPv6 prefix`);
        const prefix = `${canonicalIp6(pt.t.split('/')[0])}/${c!.prefix}`;
        const sub: Dhcp6Subnet = { prefix, options: {}, line: t.line };
        block((s) => {
          if (s.t === 'range6') {
            const a = ip6(next());
            const b = ip6(next());
            semi();
            for (const x of [a, b]) if (!inPrefix6(x, prefix)) err(s.line, `range6 address ${x} is not in subnet6 ${prefix}`);
            sub.range = [a, b];
          } else if (s.t === 'option') option(sub.options);
          else if (s.t === 'default-lease-time' || s.t === 'max-lease-time' || s.t === 'preferred-lifetime') { next(); semi(); }
          else if (s.t === 'range') err(s.line, 'range is for DHCPv4; use range6 in a subnet6 declaration');
          else err(s.line, 'expecting a declaration');
        });
        cfg.subnets.push(sub);
        break;
      }
      case 'host': {
        const h: Dhcp6Host = { name: next().t };
        block((s) => {
          if (s.t === 'host-identifier') {
            if (next().t !== 'option' || next().t !== 'dhcp6.client-id') err(s.line, 'expecting "option dhcp6.client-id"');
            const v = next();
            if (!HEX_ID.test(v.t)) err(v.line, 'expecting colon-separated hexadecimal octets');
            h.duid = v.t.toLowerCase().split(':').map((x) => x.padStart(2, '0')).join(':');
            semi();
          } else if (s.t === 'hardware') {
            if (next().t !== 'ethernet') err(s.line, 'expecting hardware type');
            const m = next();
            if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(m.t)) err(m.line, 'expecting a hardware address');
            h.mac = m.t.toLowerCase();
            semi();
          } else if (s.t === 'fixed-address6') { h.fixedAddress = ip6(next()); semi(); }
          else if (s.t === 'fixed-address') err(s.line, 'fixed-address is for DHCPv4; use fixed-address6');
          else if (s.t === 'option') option({});
          else err(s.line, 'expecting a declaration');
        });
        cfg.hosts.push(h);
        break;
      }
      default:
        err(t.line, 'expecting a parameter or declaration');
    }
  }
  return cfg;
}

/** Is `addr` inside `prefix` ("2001:db8:30::/64")? */
export function inPrefix6(addr: string, prefix: string): boolean {
  const c = parseCidr6(prefix);
  return !!c && parseIp6(addr) !== null && inCidr6(addr, c);
}

// ---------------------------------------------------------------- dhcpd6.leases

export interface Lease6 {
  /** IAID (4 octets, hex "00:e7:00:2a") and client DUID (hex), together the ia-na key. */
  iaid: string;
  duid: string;
  address: string;
  cltt: number;
  ends: number;
  preferred: number;
  valid: number;
  state: 'active' | 'released' | 'expired';
}

const hexBytes = (h: string) => h.split(':').filter(Boolean).map((x) => parseInt(x, 16));

/** ISC writes binary keys as C-style strings: printable ASCII as is, everything else as \ooo. */
export function escapeBinary(bytes: number[]): string {
  return bytes.map((b) => (b >= 0x20 && b < 0x7f && b !== 0x22 && b !== 0x5c ? String.fromCharCode(b) : `\\${b.toString(8).padStart(3, '0')}`)).join('');
}

function unescapeBinary(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && /^[0-7]{3}$/.test(s.slice(i + 1, i + 4))) { out.push(parseInt(s.slice(i + 1, i + 4), 8)); i += 3; }
    else if (s[i] === '\\') { out.push(s.charCodeAt(i + 1)); i++; }
    else out.push(s.charCodeAt(i));
  }
  return out;
}

const hex = (bytes: number[]) => bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');

function parseLeaseDate(s: string): number {
  const m = /\d (\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})/.exec(s);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : 0;
}

/** Parse dhcpd6.leases; later entries for the same IA win (append-only file). */
export function parseLeases6(text: string): Lease6[] {
  const byKey = new Map<string, Lease6>();
  const re = /ia-na "((?:[^"\\]|\\.)*)" \{([\s\S]*?)\n\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const key = unescapeBinary(m[1]);
    const body = m[2];
    const addr = /iaaddr (\S+) \{/.exec(body)?.[1];
    if (!addr || key.length < 5) continue;
    // The IAID is stored in host byte order (little-endian on x86) ahead of the DUID.
    const iaid = hex(key.slice(0, 4).reverse());
    const duid = hex(key.slice(4));
    const state = /binding state (\w+);/.exec(body)?.[1];
    byKey.set(`${iaid}|${duid}`, {
      iaid, duid, address: canonicalIp6(addr) ?? addr,
      cltt: parseLeaseDate(/cltt ([^;]+);/.exec(body)?.[1] ?? ''),
      ends: parseLeaseDate(/ends ([^;]+);/.exec(body)?.[1] ?? ''),
      preferred: Number(/preferred-life (\d+);/.exec(body)?.[1] ?? 0),
      valid: Number(/max-life (\d+);/.exec(body)?.[1] ?? 0),
      state: state === 'active' ? 'active' : state === 'released' ? 'released' : 'expired',
    });
  }
  return [...byKey.values()];
}

export function formatLease6(l: Lease6): string {
  const key = escapeBinary([...hexBytes(l.iaid).reverse(), ...hexBytes(l.duid)]);
  return `ia-na "${key}" {\n  cltt ${formatLeaseDate(l.cltt)};\n  iaaddr ${l.address} {\n    binding state ${l.state};\n    preferred-life ${l.preferred};\n    max-life ${l.valid};\n    ends ${formatLeaseDate(l.ends)};\n  }\n}\n`;
}
