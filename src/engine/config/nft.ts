// A faithful subset of nftables: tables, base/regular chains, rule matching,
// counters, log, accept/drop/reject/jump/return verdicts, and the text formats
// used by `nft list ruleset` and /etc/nftables.conf.
//
// Supported match expressions:
//   ip saddr|daddr [!=] <addr|cidr|{set}>      ip protocol <proto|{set}>
//   meta l4proto <proto|{set}>                 tcp|udp sport|dport [!=] <port|range|{set}>
//   ct state <state[,state]|{set}>             iif|oif|iifname|oifname <name|{set}>
//   icmp type <type|{set}>                     ip6 ... (parsed; never matches IPv4 traffic)

import { inCidr, parseCidr, parseIp } from '../net/ip';

export type Family = 'inet' | 'ip' | 'ip6';
export type Hook = 'input' | 'forward' | 'output' | 'prerouting' | 'postrouting';

export type MatchExpr =
  | { kind: 'addr'; field: 'saddr' | 'daddr'; negate: boolean; values: string[] }
  | { kind: 'ip6' ; text: string }
  | { kind: 'l4proto'; via: 'ip protocol' | 'meta l4proto'; negate: boolean; values: string[] }
  | { kind: 'port'; proto: 'tcp' | 'udp'; field: 'sport' | 'dport'; negate: boolean; values: string[] }
  | { kind: 'ctstate'; values: string[] }
  | { kind: 'iface'; field: 'iif' | 'oif' | 'iifname' | 'oifname'; negate: boolean; values: string[] }
  | { kind: 'icmptype'; values: string[] };

export type Verdict =
  | { kind: 'accept' }
  | { kind: 'drop' }
  | { kind: 'reject'; with: RejectType }
  | { kind: 'jump'; chain: string }
  | { kind: 'return' };

export type RejectType = 'default' | 'tcp-reset' | 'port-unreachable' | 'admin-prohibited' | 'host-unreachable' | 'net-unreachable';

export interface Rule {
  handle: number;
  matches: MatchExpr[];
  counter: { packets: number; bytes: number } | null;
  log: { prefix: string } | null;
  verdict: Verdict | null;
  comment?: string;
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

const PROTOS = ['tcp', 'udp', 'icmp', 'icmpv6', 'sctp', 'gre', 'esp', 'ah'];
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
        const neg = negation();
        const v = next();
        rule.matches.push({ kind: 'ip6', text: `ip6 ${f} ${neg ? '!= ' : ''}${v}` });
        break;
      }
      case 'meta': {
        const f = next();
        if (f !== 'l4proto') throw new NftError(`syntax error, unexpected ${f}`);
        const neg = negation();
        const vals = setValues(next());
        rule.matches.push({ kind: 'l4proto', via: 'meta l4proto', negate: neg, values: vals });
        break;
      }
      case 'tcp':
      case 'udp': {
        const f = next();
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
      case 'reject': {
        let w: RejectType = 'default';
        if (toks[i] === 'with') {
          i++;
          const a = next();
          if (a === 'tcp') {
            if (next() !== 'reset') throw new NftError('syntax error, expecting reset');
            w = 'tcp-reset';
          } else if (a === 'icmp' || a === 'icmpx') {
            if (next() !== 'type') throw new NftError('syntax error, expecting type');
            const ty = next();
            const map: Record<string, RejectType> = {
              'port-unreachable': 'port-unreachable',
              'admin-prohibited': 'admin-prohibited',
              'host-unreachable': 'host-unreachable',
              'net-unreachable': 'net-unreachable',
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
    case 'addr': return `ip ${m.field} ${neg(m.negate)}${fmtSet(m.values)}`;
    case 'ip6': return m.text;
    case 'l4proto': return `${m.via} ${neg(m.negate)}${fmtSet(m.values)}`;
    case 'port': return `${m.proto} ${m.field} ${neg(m.negate)}${fmtSet(m.values)}`;
    case 'ctstate': return `ct state ${m.values.join(',')}`;
    case 'iface': return `${m.field} ${neg(m.negate)}${fmtSet(m.values, true)}`;
    case 'icmptype': return `icmp type ${fmtSet(m.values)}`;
  }
}

export function renderRule(r: Rule, withHandle = false): string {
  const parts = r.matches.map(renderMatch);
  if (r.counter) parts.push(`counter packets ${r.counter.packets} bytes ${r.counter.bytes}`);
  if (r.log) parts.push(r.log.prefix ? `log prefix "${r.log.prefix}"` : 'log');
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
  src: string;
  dst: string;
  proto: 'tcp' | 'udp' | 'icmp';
  sport?: number;
  dport?: number;
  icmpType?: string;
  iif?: string;
  oif?: string;
  ctState: 'new' | 'established' | 'related';
  len: number;
}

export interface EvalResult {
  verdict: 'accept' | 'drop' | 'reject';
  rejectWith?: RejectType;
  /** Description of the deciding rule or policy, for logs/teaching. */
  decidedBy: { table: string; chain: string; rule: Rule | null; policy: boolean } | null;
  logs: string[]; // log prefixes triggered
}

function matchOne(m: MatchExpr, p: PacketContext): boolean {
  switch (m.kind) {
    case 'addr': {
      const ip = m.field === 'saddr' ? p.src : p.dst;
      const hit = m.values.some((v) => inCidr(ip, parseCidr(v)!));
      return m.negate ? !hit : hit;
    }
    case 'ip6':
      return false;
    case 'l4proto': {
      const hit = m.values.includes(p.proto);
      return m.negate ? !hit : hit;
    }
    case 'port': {
      if (p.proto !== m.proto) return false;
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
    case 'iface': {
      const name = m.field.startsWith('i') ? p.iif : p.oif;
      const hit = name !== undefined && m.values.includes(name);
      return m.negate ? !hit : hit;
    }
    case 'icmptype':
      return p.proto === 'icmp' && p.icmpType !== undefined && m.values.includes(p.icmpType);
  }
}

function familyApplies(f: Family): boolean {
  return f === 'inet' || f === 'ip';
}

/**
 * Evaluate a packet against every base chain registered on `hook`, in priority
 * order. Mutates rule counters (just like the kernel).
 */
export function evaluate(rs: Ruleset, hook: Hook, p: PacketContext): EvalResult {
  const logs: string[] = [];
  const bases: { table: Table; chain: Chain }[] = [];
  for (const t of rs.tables) {
    if (!familyApplies(t.family)) continue;
    for (const c of t.chains) if (c.base && c.base.hook === hook && c.base.type === 'filter') bases.push({ table: t, chain: c });
  }
  bases.sort((a, b) => a.chain.base!.priority - b.chain.base!.priority);
  let last: EvalResult['decidedBy'] = null;

  for (const { table, chain } of bases) {
    const r = runChain(table, chain, p, logs, 0);
    if (r.verdict === 'drop' || r.verdict === 'reject') {
      return { verdict: r.verdict, rejectWith: r.rejectWith, decidedBy: r.decidedBy, logs };
    }
    last = r.decidedBy;
  }
  return { verdict: 'accept', decidedBy: last, logs };
}

function runChain(table: Table, chain: Chain, p: PacketContext, logs: string[], depth: number): EvalResult & { returned?: boolean } {
  for (const rule of chain.rules) {
    if (!rule.matches.every((m) => matchOne(m, p))) continue;
    if (rule.counter) {
      rule.counter.packets += 1;
      rule.counter.bytes += p.len;
    }
    if (rule.log) logs.push(rule.log.prefix);
    const v = rule.verdict;
    if (!v) continue;
    const decided = { table: `${table.family} ${table.name}`, chain: chain.name, rule, policy: false };
    if (v.kind === 'accept') return { verdict: 'accept', decidedBy: decided, logs };
    if (v.kind === 'drop') return { verdict: 'drop', decidedBy: decided, logs };
    if (v.kind === 'reject') return { verdict: 'reject', rejectWith: v.with, decidedBy: decided, logs };
    if (v.kind === 'return') break;
    if (v.kind === 'jump' && depth < 16) {
      const target = table.chains.find((c) => c.name === v.chain);
      if (target) {
        const r = runChain(table, target, p, logs, depth + 1);
        if (!r.returned) return r;
      }
    }
  }
  if (!chain.base) return { verdict: 'accept', decidedBy: null, logs, returned: true };
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
