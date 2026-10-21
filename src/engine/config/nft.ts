// A faithful subset of nftables: tables, base/regular chains, rule matching,
// counters, log, accept/drop/reject/jump/return verdicts, and the text formats
// used by `nft list ruleset` and /etc/nftables.conf.
//
// Supported match expressions:
//   ip saddr|daddr [!=] <addr|cidr|{set}>      ip protocol <proto|{set}>
//   meta l4proto <proto|{set}>                 tcp|udp sport|dport [!=] <port|range|{set}>
//   ct state <state[,state]|{set}>             iif|oif|iifname|oifname <name|{set}>
//   icmp type <type|{set}>                     ip6 saddr|daddr [!=] <addr|cidr|{set}>
//   icmpv6 type <type|{set}>                   ip6 nexthdr <proto|{set}>
//   meta nfproto ipv4|ipv6
// Families: "ip" tables see IPv4 only, "ip6" tables IPv6 only, "inet" both.
// "ip ..." matches never match IPv6 packets and vice versa.

import { inCidr, parseCidr, parseIp } from '../net/ip';
import { inCidr6, parseCidr6 } from '../net/ip6';

export type Family = 'inet' | 'ip' | 'ip6';
export type Hook = 'input' | 'forward' | 'output' | 'prerouting' | 'postrouting';

export type MatchExpr =
  | { kind: 'addr'; family?: 4 | 6; field: 'saddr' | 'daddr'; negate: boolean; values: string[] }
  | { kind: 'l4proto'; via: 'ip protocol' | 'meta l4proto' | 'ip6 nexthdr'; negate: boolean; values: string[] }
  | { kind: 'nfproto'; values: ('ipv4' | 'ipv6')[] }
  | { kind: 'port'; proto: 'tcp' | 'udp' | 'th'; field: 'sport' | 'dport'; negate: boolean; values: string[] }
  | { kind: 'ctstate'; values: string[] }
  | { kind: 'iface'; field: 'iif' | 'oif' | 'iifname' | 'oifname'; negate: boolean; values: string[] }
  | { kind: 'icmptype'; v6?: boolean; values: string[] }
  | { kind: 'tcpflags'; values: string[] };

export type Verdict =
  | { kind: 'accept' }
  | { kind: 'drop' }
  | { kind: 'reject'; with: RejectType }
  | { kind: 'jump'; chain: string }
  | { kind: 'return' }
  | { kind: 'masquerade' }
  | { kind: 'snat' | 'dnat'; addr: string; port?: number };

export type RejectType = 'default' | 'tcp-reset' | 'port-unreachable' | 'admin-prohibited' | 'host-unreachable' | 'net-unreachable';

export interface Rule {
  handle: number;
  matches: MatchExpr[];
  counter: { packets: number; bytes: number } | null;
  log: { prefix: string } | null;
  verdict: Verdict | null;
  comment?: string;
  /** "tcp option maxseg size set rt mtu | N": MSS clamping (non-terminal statement). */
  setMss?: number | 'rt mtu';
}

export interface Chain {
  name: string;
  base: { type: string; hook: Hook; priority: number; policy: 'accept' | 'drop' } | null;
  rules: Rule[];
  handle: number;
}

export interface Table {
  family: Family;
  name: string;
  chains: Chain[];
  handle: number;
}

export interface Ruleset {
  tables: Table[];
  nextHandle: number;
}

export function emptyRuleset(): Ruleset {
  return { tables: [], nextHandle: 1 };
}

// ---------------------------------------------------------------------------
// Tokenising and parsing
// ---------------------------------------------------------------------------

export class NftError extends Error {}

export function tokenizeNft(s: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"') {
      const j = s.indexOf('"', i + 1);
      if (j < 0) throw new NftError('unterminated string');
      out.push(s.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    if (c === '{') {
      const j = s.indexOf('}', i);
      if (j < 0) throw new NftError("syntax error, unexpected end of file, expecting '}'");
      out.push(s.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    if (c === ';') { out.push(';'); i++; continue; }
    let j = i;
    while (j < s.length && !/[\s;]/.test(s[j])) j++;
    out.push(s.slice(i, j));
    i = j;
  }
  return out;
}

function setValues(tok: string): string[] {
  if (tok.startsWith('{')) {
    return tok.slice(1, -1).split(',').map((v) => unquote(v.trim())).filter(Boolean);
  }
  return tok.split(',').map(unquote);
}

function unquote(s: string): string {
  return s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s;
}

const PROTOS = ['tcp', 'udp', 'icmp', 'ipv6-icmp', 'sctp', 'gre', 'esp', 'ah'];
/** nft accepts "icmpv6" as an alias and lists it as "ipv6-icmp". */
const protoName = (v: string) => (v === 'icmpv6' ? 'ipv6-icmp' : v);
const ICMPV6_TYPES = ['destination-unreachable', 'packet-too-big', 'time-exceeded', 'parameter-problem', 'echo-request', 'echo-reply', 'mld-listener-query', 'mld-listener-report', 'nd-router-solicit', 'nd-router-advert', 'nd-neighbor-solicit', 'nd-neighbor-advert', 'nd-redirect'];
const CT_STATES = ['new', 'established', 'related', 'invalid', 'untracked'];
const ICMP_TYPES = ['echo-reply', 'destination-unreachable', 'echo-request', 'time-exceeded', 'redirect', 'parameter-problem'];
const SERVICE_PORTS: Record<string, number> = { ssh: 22, http: 80, https: 443, domain: 53, ntp: 123, smtp: 25, rdp: 3389, 'ms-wbt-server': 3389, ldap: 389, kerberos: 88 };

function validatePort(v: string): string {
  if (SERVICE_PORTS[v] !== undefined) return String(SERVICE_PORTS[v]);
  const m = /^(\d+)(?:-(\d+))?$/.exec(v);
  if (!m || Number(m[1]) > 65535 || (m[2] && Number(m[2]) > 65535)) throw new NftError(`Could not resolve service: ${v}`);
  return v;
}

/** Parse the expression part of a rule ("tcp dport 22 counter accept"). */
export function parseRuleExpr(text: string, handle: number): Rule {
  const toks = tokenizeNft(text).filter((t) => t !== ';');
  const rule: Rule = { handle, matches: [], counter: null, log: null, verdict: null };
  let i = 0;
  const next = () => {
    const t = toks[i++];
    if (t === undefined) throw new NftError('syntax error, unexpected end of rule');
    return t;
  };
  const negation = () => {
    if (toks[i] === '!=') { i++; return true; }
    if (toks[i] === '==') i++;
    return false;
  };
  while (i < toks.length) {
    const t = next();
    if (rule.verdict && t !== 'comment') throw new NftError(`syntax error, unexpected ${t}`);
    switch (t) {
      case 'ip': {
        const f = next();
        if (f === 'saddr' || f === 'daddr') {
          const neg = negation();
          const vals = setValues(next());
          for (const v of vals) if (!parseCidr(v)) throw new NftError(`Could not resolve hostname: ${v}`);
          rule.matches.push({ kind: 'addr', field: f, negate: neg, values: vals });
        } else if (f === 'protocol') {
          const neg = negation();
          const vals = setValues(next());
          for (const v of vals) if (!PROTOS.includes(v)) throw new NftError(`syntax error, unexpected ${v}`);
          rule.matches.push({ kind: 'l4proto', via: 'ip protocol', negate: neg, values: vals });
        } else throw new NftError(`syntax error, unexpected ${f}`);
        break;
      }
      case 'ip6': {
        const f = next();
        if (f === 'saddr' || f === 'daddr') {
          const neg = negation();
          const vals = setValues(next());
          for (const v of vals) if (!parseCidr6(v)) throw new NftError(`Could not resolve hostname: ${v}`);
          rule.matches.push({ kind: 'addr', family: 6, field: f, negate: neg, values: vals });
        } else if (f === 'nexthdr') {
          const neg = negation();
          const vals = setValues(next()).map(protoName);
          for (const v of vals) if (!PROTOS.includes(v)) throw new NftError(`syntax error, unexpected ${v}`);
          rule.matches.push({ kind: 'l4proto', via: 'ip6 nexthdr', negate: neg, values: vals });
        } else throw new NftError(`syntax error, unexpected ${f}`);
        break;
      }
      case 'meta': {
        const f = next();
        if (f === 'nfproto') {
          const vals = setValues(next());
          for (const v of vals) if (v !== 'ipv4' && v !== 'ipv6') throw new NftError(`syntax error, unexpected ${v}`);
          rule.matches.push({ kind: 'nfproto', values: vals as ('ipv4' | 'ipv6')[] });
          break;
        }
        if (f !== 'l4proto') throw new NftError(`syntax error, unexpected ${f}`);
        const neg = negation();
        const vals = setValues(next()).map(protoName);
        for (const v of vals) if (!PROTOS.includes(v)) throw new NftError(`syntax error, unexpected ${v}`);
        rule.matches.push({ kind: 'l4proto', via: 'meta l4proto', negate: neg, values: vals });
        break;
      }
      case 'tcp':
      case 'udp':
      case 'th': {
        const f = next();
        if (t === 'tcp' && f === 'flags') {
          // "tcp flags syn", "tcp flags { syn, rst }", "tcp flags & (syn|rst) == syn"
          let v = next();
          if (v === '&') {
            next();
            if (toks[i] === '==') i++;
            v = next();
          }
          const vals = setValues(v).map((x) => x.replace(/[()]/g, ''));
          for (const x of vals) if (!['syn', 'ack', 'fin', 'rst', 'psh', 'urg'].includes(x)) throw new NftError(`syntax error, unexpected ${x}`);
          rule.matches.push({ kind: 'tcpflags', values: vals });
          break;
        }
        if (t === 'tcp' && f === 'option') {
          for (const want of ['maxseg', 'size', 'set']) {
            const got = next();
            if (got !== want) throw new NftError(`syntax error, unexpected ${got}, expecting ${want}`);
          }
          const v = next();
          if (v === 'rt') {
            if (next() !== 'mtu') throw new NftError('syntax error, unexpected end of rule, expecting mtu');
            rule.setMss = 'rt mtu';
          } else {
            const n = Number(v);
            if (!Number.isInteger(n) || n < 1 || n > 65535) throw new NftError(`syntax error, unexpected ${v}`);
            rule.setMss = n;
          }
          break;
        }
        if (f !== 'sport' && f !== 'dport') throw new NftError(`syntax error, unexpected ${f}`);
        const neg = negation();
        const vals = setValues(next()).map(validatePort);
        rule.matches.push({ kind: 'port', proto: t, field: f, negate: neg, values: vals });
        break;
      }
      case 'ct': {
        const f = next();
        if (f !== 'state') throw new NftError(`syntax error, unexpected ${f}`);
        const vals = setValues(next());
        for (const v of vals) if (!CT_STATES.includes(v)) throw new NftError(`syntax error, unexpected ${v}`);
        rule.matches.push({ kind: 'ctstate', values: vals });
        break;
      }
      case 'iif':
      case 'oif':
      case 'iifname':
      case 'oifname': {
        const neg = negation();
        rule.matches.push({ kind: 'iface', field: t, negate: neg, values: setValues(next()) });
        break;
      }
      case 'icmp': {
        const f = next();
        if (f !== 'type') throw new NftError(`syntax error, unexpected ${f}`);
        const vals = setValues(next());
        for (const v of vals) if (!ICMP_TYPES.includes(v)) throw new NftError(`syntax error, unexpected ${v}`);
        rule.matches.push({ kind: 'icmptype', values: vals });
        break;
      }
      case 'icmpv6': {
        const f = next();
        if (f !== 'type') throw new NftError(`syntax error, unexpected ${f}`);
        const vals = setValues(next());
        for (const v of vals) if (!ICMPV6_TYPES.includes(v)) throw new NftError(`syntax error, unexpected ${v}`);
        rule.matches.push({ kind: 'icmptype', v6: true, values: vals });
        break;
      }
      case 'counter': {
        rule.counter = { packets: 0, bytes: 0 };
        if (toks[i] === 'packets') {
          i++;
          rule.counter.packets = Number(next());
          if (toks[i] === 'bytes') { i++; rule.counter.bytes = Number(next()); }
        }
        break;
      }
      case 'log': {
        rule.log = { prefix: '' };
        while (toks[i] === 'prefix' || toks[i] === 'level' || toks[i] === 'flags') {
          const k = next();
          const v = next();
          if (k === 'prefix') rule.log.prefix = unquote(v);
        }
        break;
      }
      case 'comment':
        rule.comment = unquote(next());
        break;
      case 'accept':
      case 'drop':
        rule.verdict = { kind: t };
        break;
      case 'return':
        rule.verdict = { kind: 'return' };
        break;
      case 'jump':
      case 'goto':
        rule.verdict = { kind: 'jump', chain: next() };
        break;
      case 'masquerade':
        rule.verdict = { kind: 'masquerade' };
        break;
      case 'snat':
      case 'dnat': {
        if (toks[i] === 'ip') i++;
        if (next() !== 'to') throw new NftError(`syntax error, expecting to`);
        const target = next();
        const m = /^(\d+\.\d+\.\d+\.\d+)(?::(\d+))?$/.exec(target);
        if (!m) throw new NftError(`Could not resolve hostname: ${target}`);
        rule.verdict = { kind: t, addr: m[1], port: m[2] ? Number(m[2]) : undefined };
        break;
      }
      case 'reject': {
        let w: RejectType = 'default';
        if (toks[i] === 'with') {
          i++;
          const a = next();
          if (a === 'tcp') {
            if (next() !== 'reset') throw new NftError('syntax error, expecting reset');
            w = 'tcp-reset';
          } else if (a === 'icmp' || a === 'icmpx' || a === 'icmpv6') {
            if (next() !== 'type') throw new NftError('syntax error, expecting type');
            const ty = next();
            const map: Record<string, RejectType> = {
              'port-unreachable': 'port-unreachable',
              'admin-prohibited': 'admin-prohibited',
              'host-unreachable': 'host-unreachable',
              'net-unreachable': 'net-unreachable',
              // ICMPv6 names (RFC 4443 codes 0, 3)
              'no-route': 'net-unreachable',
              'addr-unreachable': 'host-unreachable',
            };
            if (!map[ty]) throw new NftError(`syntax error, unexpected ${ty}`);
            w = map[ty];
          } else throw new NftError(`syntax error, unexpected ${a}`);
        }
        rule.verdict = { kind: 'reject', with: w };
        break;
      }
      default:
        throw new NftError(`syntax error, unexpected ${t}`);
    }
  }
  return rule;
}

const PRIORITY_NAMES: Record<string, number> = { raw: -300, mangle: -150, dstnat: -100, filter: 0, security: 50, srcnat: 100 };

function parseChainSpec(text: string): Chain['base'] {
  // "type filter hook input priority filter; policy drop;"
  const m = /type\s+(\w+)\s+hook\s+(\w+)\s+priority\s+([\w-]+)\s*;?\s*(?:policy\s+(accept|drop)\s*;?)?/.exec(text);
  if (!m) return null;
  const pr = PRIORITY_NAMES[m[3]] ?? Number(m[3]);
  if (Number.isNaN(pr)) throw new NftError(`unknown priority ${m[3]}`);
  return { type: m[1], hook: m[2] as Hook, priority: pr, policy: (m[4] as 'accept' | 'drop') ?? 'accept' };
}

/**
 * Parse a ruleset file (the format written by `nft list ruleset` and read by
 * `nft -f`). Returns a new ruleset; `flush ruleset` lines reset what came before.
 */
export function parseRulesetFile(text: string, file = '/etc/nftables.conf'): Ruleset {
  const rs = emptyRuleset();
  let table: Table | null = null;
  let chain: Chain | null = null;
  const lines = text.split('\n');
  lines.forEach((raw, idx) => {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) return;
    const fail = (msg: string): never => {
      throw new NftError(`${file}:${idx + 1}:1-${raw.length}: Error: ${msg}`);
    };
    try {
      if (line === 'flush ruleset') {
        rs.tables = [];
        return;
      }
      let m = /^table\s+(inet|ip|ip6)\s+(\S+)\s*\{$/.exec(line);
      if (m) {
        if (table) fail('syntax error, unexpected table');
        table = { family: m[1] as Family, name: m[2], chains: [], handle: rs.nextHandle++ };
        rs.tables.push(table);
        return;
      }
      m = /^chain\s+(\S+)\s*\{$/.exec(line);
      if (m) {
        if (!table || chain) fail('syntax error, unexpected chain');
        chain = { name: m[1], base: null, rules: [], handle: rs.nextHandle++ };
        table!.chains.push(chain);
        return;
      }
      if (line === '}') {
        if (chain) chain = null;
        else if (table) table = null;
        else fail("syntax error, unexpected '}'");
        return;
      }
      if (line.startsWith('type ')) {
        if (!chain) fail('syntax error, unexpected type');
        chain!.base = parseChainSpec(line);
        if (!chain!.base) fail('syntax error in chain specification');
        return;
      }
      if (line.startsWith('policy ')) {
        const p = /^policy\s+(accept|drop)/.exec(line);
        if (!chain || !chain.base || !p) fail('syntax error, unexpected policy');
        chain!.base!.policy = p![1] as 'accept' | 'drop';
        return;
      }
      if (!chain) fail(`syntax error, unexpected ${line.split(/\s+/)[0]}`);
      chain!.rules.push(parseRuleExpr(line, rs.nextHandle++));
    } catch (e) {
      if (e instanceof NftError && !e.message.startsWith(file)) fail(e.message);
      throw e;
    }
  });
  if (chain || table) throw new NftError(`${file}:${lines.length}:1: Error: syntax error, unexpected end of file`);
  return rs;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function fmtSet(vals: string[], quote = false): string {
  const v = vals.map((x) => (quote ? `"${x}"` : x));
  return v.length === 1 ? v[0] : `{ ${v.join(', ')} }`;
}

export function renderMatch(m: MatchExpr): string {
  const neg = (b: boolean) => (b ? '!= ' : '');
  switch (m.kind) {
    case 'addr': return `${m.family === 6 ? 'ip6' : 'ip'} ${m.field} ${neg(m.negate)}${fmtSet(m.values)}`;
    case 'nfproto': return `meta nfproto ${fmtSet(m.values)}`;
    case 'l4proto': return `${m.via} ${neg(m.negate)}${fmtSet(m.values)}`;
    case 'port': return `${m.proto} ${m.field} ${neg(m.negate)}${fmtSet(m.values)}`;
    case 'ctstate': return `ct state ${m.values.join(',')}`;
    case 'iface': return `${m.field} ${neg(m.negate)}${fmtSet(m.values, true)}`;
    case 'icmptype': return `${m.v6 ? 'icmpv6' : 'icmp'} type ${fmtSet(m.values)}`;
    case 'tcpflags': return `tcp flags ${m.values.length === 1 ? m.values[0] : `& (${m.values.join(' | ')}) == ${m.values[0]}`}`;
  }
}

export function renderRule(r: Rule, withHandle = false): string {
  const parts = r.matches.map(renderMatch);
  if (r.counter) parts.push(`counter packets ${r.counter.packets} bytes ${r.counter.bytes}`);
  if (r.log) parts.push(r.log.prefix ? `log prefix "${r.log.prefix}"` : 'log');
  if (r.setMss !== undefined) parts.push(`tcp option maxseg size set ${r.setMss}`);
  if (r.verdict) {
    const v = r.verdict;
    if (v.kind === 'reject') {
      const w: Record<RejectType, string> = {
        default: 'reject',
        'tcp-reset': 'reject with tcp reset',
        'port-unreachable': 'reject with icmpx type port-unreachable',
        'admin-prohibited': 'reject with icmpx type admin-prohibited',
        'host-unreachable': 'reject with icmpx type host-unreachable',
        'net-unreachable': 'reject with icmpx type net-unreachable',
      };
      parts.push(w[v.with]);
    } else if (v.kind === 'jump') parts.push(`jump ${v.chain}`);
    else if (v.kind === 'snat' || v.kind === 'dnat') parts.push(`${v.kind} to ${v.addr}${v.port ? ':' + v.port : ''}`);
    else parts.push(v.kind);
  }
  if (r.comment) parts.push(`comment "${r.comment}"`);
  return parts.join(' ') + (withHandle ? ` # handle ${r.handle}` : '');
}

const PRIORITY_LABEL: Record<number, string> = { 0: 'filter', [-300]: 'raw', [-150]: 'mangle', [-100]: 'dstnat', 100: 'srcnat', 50: 'security' };

export function renderChain(c: Chain, withHandle = false, indent = '\t'): string {
  const out: string[] = [];
  out.push(`${indent}chain ${c.name} {${withHandle ? ` # handle ${c.handle}` : ''}`);
  if (c.base) {
    out.push(`${indent}\ttype ${c.base.type} hook ${c.base.hook} priority ${PRIORITY_LABEL[c.base.priority] ?? c.base.priority}; policy ${c.base.policy};`);
  }
  for (const r of c.rules) out.push(`${indent}\t${renderRule(r, withHandle)}`);
  out.push(`${indent}}`);
  return out.join('\n');
}

export function renderRuleset(rs: Ruleset, withHandle = false): string {
  return rs.tables
    .map((t) => {
      const chains = t.chains.map((c) => renderChain(c, withHandle)).join('\n\n');
      return `table ${t.family} ${t.name} {${withHandle ? ` # handle ${t.handle}` : ''}\n${chains}\n}`;
    })
    .join('\n');
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export interface PacketContext {
  /** Address family of the packet (default 4). */
  family?: 4 | 6;
  src: string;
  dst: string;
  proto: 'tcp' | 'udp' | 'icmp';
  sport?: number;
  dport?: number;
  icmpType?: string;
  iif?: string;
  oif?: string;
  ctState: 'new' | 'established' | 'related' | 'untracked';
  len: number;
  /** TCP flags of the packet (lowercase). */
  tcpFlags?: string[];
  /** Set by an evaluated "tcp option maxseg size set ..." statement. */
  setMss?: number | 'rt mtu';
}

export interface EvalResult {
  verdict: 'accept' | 'drop' | 'reject';
  /** Set when a NAT chain rule matched (masquerade / snat / dnat). */
  nat?: Extract<Verdict, { kind: 'masquerade' | 'snat' | 'dnat' }>;
  rejectWith?: RejectType;
  /** Description of the deciding rule or policy, for logs/teaching. */
  decidedBy: { table: string; chain: string; rule: Rule | null; policy: boolean } | null;
  logs: string[]; // log prefixes triggered
}

function matchOne(m: MatchExpr, p: PacketContext): boolean {
  const fam = p.family ?? 4;
  switch (m.kind) {
    case 'addr': {
      // "ip saddr" only applies to IPv4 packets, "ip6 saddr" only to IPv6 (even with "!=").
      if ((m.family ?? 4) !== fam) return false;
      const ip = m.field === 'saddr' ? p.src : p.dst;
      const hit = m.values.some((v) => (fam === 6 ? inCidr6(ip, parseCidr6(v)!) : inCidr(ip, parseCidr(v)!)));
      return m.negate ? !hit : hit;
    }
    case 'nfproto':
      return m.values.includes(fam === 6 ? 'ipv6' : 'ipv4');
    case 'l4proto': {
      if (m.via === 'ip protocol' && fam !== 4) return false;
      if (m.via === 'ip6 nexthdr' && fam !== 6) return false;
      const name = p.proto === 'icmp' && fam === 6 ? 'ipv6-icmp' : p.proto;
      const hit = m.values.includes(name);
      return m.negate ? !hit : hit;
    }
    case 'port': {
      if (m.proto === 'th' ? p.proto === 'icmp' : p.proto !== m.proto) return false;
      const port = m.field === 'sport' ? p.sport : p.dport;
      if (port === undefined) return false;
      const hit = m.values.some((v) => {
        const [a, b] = v.split('-').map(Number);
        return b === undefined ? port === a : port >= a && port <= b;
      });
      return m.negate ? !hit : hit;
    }
    case 'ctstate':
      return m.values.includes(p.ctState);
    case 'tcpflags':
      return p.proto === 'tcp' && m.values.some((f) => (p.tcpFlags ?? []).includes(f));
    case 'iface': {
      const name = m.field.startsWith('i') ? p.iif : p.oif;
      const hit = name !== undefined && m.values.includes(name);
      return m.negate ? !hit : hit;
    }
    case 'icmptype':
      return p.proto === 'icmp' && (fam === 6) === !!m.v6 && p.icmpType !== undefined && m.values.includes(p.icmpType);
  }
}

function familyApplies(f: Family, p: PacketContext): boolean {
  const fam = p.family ?? 4;
  return f === 'inet' || (f === 'ip' && fam === 4) || (f === 'ip6' && fam === 6);
}

/**
 * Evaluate a packet against every base chain registered on `hook`, in priority
 * order. Mutates rule counters (just like the kernel).
 */
export interface ExplainStep {
  table: string;
  chain: string;
  handle: number | null;
  text: string;
  matched: boolean;
  outcome: string;
}

export function evaluate(rs: Ruleset, hook: Hook, p: PacketContext, steps?: ExplainStep[]): EvalResult {
  const logs: string[] = [];
  const bases: { table: Table; chain: Chain }[] = [];
  for (const t of rs.tables) {
    if (!familyApplies(t.family, p)) continue;
    for (const c of t.chains) if (c.base && c.base.hook === hook && c.base.type === 'filter') bases.push({ table: t, chain: c });
  }
  bases.sort((a, b) => a.chain.base!.priority - b.chain.base!.priority);
  let last: EvalResult['decidedBy'] = null;

  for (const { table, chain } of bases) {
    const r = runChain(table, chain, p, logs, 0, steps);
    if (r.verdict === 'drop' || r.verdict === 'reject') {
      return { verdict: r.verdict, rejectWith: r.rejectWith, decidedBy: r.decidedBy, logs };
    }
    last = r.decidedBy;
  }
  return { verdict: 'accept', decidedBy: last, logs };
}

function runChain(table: Table, chain: Chain, p: PacketContext, logs: string[], depth: number, steps?: ExplainStep[]): EvalResult & { returned?: boolean } {
  const tname = `${table.family} ${table.name}`;
  for (const rule of chain.rules) {
    const hit = rule.matches.every((m) => matchOne(m, p));
    if (steps) {
      const v = rule.verdict;
      steps.push({
        table: tname, chain: chain.name, handle: rule.handle, text: renderRule(rule), matched: hit,
        outcome: !hit ? 'no match, continue' : !v ? 'match (counter/log only), continue' : v.kind === 'jump' ? `match, jump to ${v.chain}` : v.kind === 'return' ? 'match, return' : `match → ${v.kind}`,
      });
    }
    if (!hit) continue;
    if (rule.counter) {
      rule.counter.packets += 1;
      rule.counter.bytes += p.len;
    }
    if (rule.log) logs.push(rule.log.prefix);
    if (rule.setMss !== undefined) p.setMss = rule.setMss;
    const v = rule.verdict;
    if (!v) continue;
    const decided = { table: `${table.family} ${table.name}`, chain: chain.name, rule, policy: false };
    if (v.kind === 'accept') return { verdict: 'accept', decidedBy: decided, logs };
    if (v.kind === 'drop') return { verdict: 'drop', decidedBy: decided, logs };
    if (v.kind === 'reject') return { verdict: 'reject', rejectWith: v.with, decidedBy: decided, logs };
    if (v.kind === 'return') break;
    if (v.kind === 'masquerade' || v.kind === 'snat' || v.kind === 'dnat') return { verdict: 'accept', decidedBy: decided, logs, nat: v };
    if (v.kind === 'jump' && depth < 16) {
      const target = table.chains.find((c) => c.name === v.chain);
      if (target) {
        const r = runChain(table, target, p, logs, depth + 1, steps);
        if (!r.returned) return r;
      }
    }
  }
  if (!chain.base) return { verdict: 'accept', decidedBy: null, logs, returned: true };
  steps?.push({ table: tname, chain: chain.name, handle: null, text: `policy ${chain.base.policy}`, matched: true, outcome: `end of chain → policy ${chain.base.policy}` });
  return {
    verdict: chain.base.policy,
    decidedBy: { table: `${table.family} ${table.name}`, chain: chain.name, rule: null, policy: true },
    logs,
  };
}

// ---------------------------------------------------------------------------
// Mutation helpers used by the `nft` command
// ---------------------------------------------------------------------------

export function findChain(rs: Ruleset, family: string, table: string, chain: string): Chain | undefined {
  return rs.tables.find((t) => t.family === family && t.name === table)?.chains.find((c) => c.name === chain);
}

export function cloneRuleset(rs: Ruleset): Ruleset {
  return JSON.parse(JSON.stringify(rs));
}

export function isValidAddress(s: string): boolean {
  return parseIp(s) !== null;
}

/** Evaluate without touching counters, returning every rule considered (for teaching tools). */
export function explainPacket(rs: Ruleset, hook: Hook, p: PacketContext): { result: EvalResult; steps: ExplainStep[] } {
  const steps: ExplainStep[] = [];
  const result = evaluate(cloneRuleset(rs), hook, p, steps);
  return { result, steps };
}

/**
 * Evaluate the NAT base chains (type nat) on a hook for the FIRST packet of a
 * flow. Returns the matching translation, if any. Later packets of the flow are
 * translated from the NAT table, not by re-evaluating rules (as in the kernel).
 */
export function evaluateNat(rs: Ruleset, hook: 'prerouting' | 'postrouting', p: PacketContext): { nat: NonNullable<EvalResult['nat']>; rule: Rule; table: string; chain: string } | null {
  const bases: { table: Table; chain: Chain }[] = [];
  for (const t of rs.tables) {
    if (!familyApplies(t.family, p)) continue;
    for (const c of t.chains) if (c.base && c.base.hook === hook && c.base.type === 'nat') bases.push({ table: t, chain: c });
  }
  bases.sort((a, b) => a.chain.base!.priority - b.chain.base!.priority);
  for (const { table, chain } of bases) {
    const r = runChain(table, chain, p, [], 0);
    if (r.nat && r.decidedBy?.rule) return { nat: r.nat, rule: r.decidedBy.rule, table: `${table.family} ${table.name}`, chain: chain.name };
  }
  return null;
}
