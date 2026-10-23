// A Wireshark display-filter subset for the Packet Lab:
//   protocols: eth arp ip ipv6 icmp icmpv6 tcp udp dns ssh dhcp vlan
//   fields:    ip.addr ip.src ip.dst ipv6.addr ipv6.src ipv6.dst tcp.port
//              tcp.srcport tcp.dstport udp.port tcp.flags.syn tcp.flags.ack
//              tcp.flags.reset tcp.flags.fin icmp.type icmp.code icmpv6.type
//              vlan.id tcp.len frame.number
//   operators: == != > < >= <=, and/&&, or/||, not/!, parentheses

import { canonicalIp6 } from './net/ip6';
import type { CapturedFrame } from './types';

type Node =
  | { t: 'and' | 'or'; a: Node; b: Node }
  | { t: 'not'; a: Node }
  | { t: 'proto'; name: string }
  | { t: 'cmp'; field: string; op: string; value: string };

const PROTOS = ['eth', 'arp', 'ip', 'ipv6', 'icmp', 'icmpv6', 'tcp', 'udp', 'dns', 'ssh', 'dhcp', 'dhcpv6', 'tls', 'http', 'vlan', 'kerberos'];
const FIELDS = ['ip.addr', 'ip.src', 'ip.dst', 'ipv6.addr', 'ipv6.src', 'ipv6.dst', 'icmpv6.type', 'vlan.id', 'ipv6.hlim', 'tcp.port', 'tcp.srcport', 'tcp.dstport', 'udp.port', 'udp.srcport', 'udp.dstport', 'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.reset', 'tcp.flags.fin', 'tcp.flags.push', 'icmp.type', 'icmp.code', 'tcp.len', 'frame.number', 'ip.ttl'];

export class FilterError extends Error {}

function tokenize(s: string): string[] {
  const re = /\s*(&&|\|\||==|!=|>=|<=|[()!<>]|[A-Za-z0-9_.:\-/]+)/y;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  let i = 0;
  while (i < s.length) {
    re.lastIndex = i;
    m = re.exec(s);
    if (!m) {
      if (/^\s+$/.test(s.slice(i))) break;
      throw new FilterError(`Unexpected "${s.slice(i, i + 8)}"`);
    }
    out.push(m[1]);
    i = re.lastIndex;
  }
  return out;
}

export function parseFilter(s: string): Node | null {
  if (!s.trim()) return null;
  const toks = tokenize(s);
  let i = 0;
  const peek = () => toks[i];
  const take = () => toks[i++];
  const orExpr = (): Node => {
    let a = andExpr();
    while (peek() === 'or' || peek() === '||') { take(); a = { t: 'or', a, b: andExpr() }; }
    return a;
  };
  const andExpr = (): Node => {
    let a = unary();
    while (peek() === 'and' || peek() === '&&') { take(); a = { t: 'and', a, b: unary() }; }
    return a;
  };
  const unary = (): Node => {
    if (peek() === 'not' || peek() === '!') { take(); return { t: 'not', a: unary() }; }
    if (peek() === '(') {
      take();
      const n = orExpr();
      if (take() !== ')') throw new FilterError('Missing ")"');
      return n;
    }
    const w = take();
    if (w === undefined) throw new FilterError('Unexpected end of filter');
    if (PROTOS.includes(w)) return { t: 'proto', name: w };
    if (FIELDS.includes(w)) {
      const op = take();
      if (!['==', '!=', '>', '<', '>=', '<=', 'eq', 'ne'].includes(op ?? '')) {
        if (w.startsWith('tcp.flags.') && op === undefined) return { t: 'cmp', field: w, op: '==', value: '1' };
        throw new FilterError(`Expected a comparison after "${w}"`);
      }
      const value = take();
      if (value === undefined) throw new FilterError(`Missing value after "${w} ${op}"`);
      return { t: 'cmp', field: w, op: op === 'eq' ? '==' : op === 'ne' ? '!=' : op, value };
    }
    throw new FilterError(`"${w}" is neither a field nor a protocol (supported: ${[...PROTOS, ...FIELDS].join(', ')})`);
  };
  const n = orExpr();
  if (i < toks.length) throw new FilterError(`Unexpected "${toks[i]}"`);
  return n;
}

function fieldValues(f: CapturedFrame, field: string, index: number): (string | number)[] {
  const v6 = !!f.ip && f.ip.src.includes(':');
  const p4 = v6 ? undefined : f.ip;
  const p6 = v6 ? f.ip : undefined;
  if (field === 'ipv6.addr') return p6 ? [p6.src, p6.dst] : [];
  if (field === 'ipv6.src') return p6 ? [p6.src] : [];
  if (field === 'ipv6.dst') return p6 ? [p6.dst] : [];
  if (field === 'ipv6.hlim') return p6 ? [p6.ttl] : [];
  if (field === 'icmpv6.type') return p6?.icmp ? [p6.icmp.type] : [];
  if (field === 'vlan.id') return f.vlan !== undefined ? [f.vlan] : [];
  if (field.startsWith('ip.') || field.startsWith('icmp.')) {
    if (!p4) return [];
  }
  const p = f.ip;
  const t = p?.tcp;
  const u = p?.udp;
  switch (field) {
    case 'frame.number': return [index + 1];
    case 'ip.addr': return p ? [p.src, p.dst] : [];
    case 'ip.src': return p ? [p.src] : [];
    case 'ip.dst': return p ? [p.dst] : [];
    case 'ip.ttl': return p ? [p.ttl] : [];
    case 'tcp.port': return t ? [t.sport, t.dport] : [];
    case 'tcp.srcport': return t ? [t.sport] : [];
    case 'tcp.dstport': return t ? [t.dport] : [];
    case 'udp.port': return u ? [u.sport, u.dport] : [];
    case 'udp.srcport': return u ? [u.sport] : [];
    case 'udp.dstport': return u ? [u.dport] : [];
    case 'tcp.len': return t ? [t.len] : [];
    case 'tcp.flags.syn': return t ? [t.flags.includes('SYN') ? 1 : 0] : [];
    case 'tcp.flags.ack': return t ? [t.flags.includes('ACK') ? 1 : 0] : [];
    case 'tcp.flags.reset': return t ? [t.flags.includes('RST') ? 1 : 0] : [];
    case 'tcp.flags.fin': return t ? [t.flags.includes('FIN') ? 1 : 0] : [];
    case 'tcp.flags.push': return t ? [t.flags.includes('PSH') ? 1 : 0] : [];
    case 'icmp.type': return p?.icmp ? [p.icmp.type] : [];
    case 'icmp.code': return p?.icmp ? [p.icmp.code] : [];
    default: return [];
  }
}

function cmp(a: string | number, op: string, bRaw: string): boolean {
  const b = typeof a === 'string' && a.includes(':') ? canonicalIp6(bRaw) ?? bRaw : bRaw;
  const an = typeof a === 'number' ? a : NaN;
  const bn = Number(b);
  const numeric = !Number.isNaN(an) && !Number.isNaN(bn);
  switch (op) {
    case '==': return numeric ? an === bn : String(a) === b;
    case '!=': return numeric ? an !== bn : String(a) !== b;
    case '>': return numeric && an > bn;
    case '<': return numeric && an < bn;
    case '>=': return numeric && an >= bn;
    case '<=': return numeric && an <= bn;
  }
  return false;
}

export function matchFilter(node: Node | null, f: CapturedFrame, index: number): boolean {
  if (!node) return true;
  switch (node.t) {
    case 'and': return matchFilter(node.a, f, index) && matchFilter(node.b, f, index);
    case 'or': return matchFilter(node.a, f, index) || matchFilter(node.b, f, index);
    case 'not': return !matchFilter(node.a, f, index);
    case 'proto':
      switch (node.name) {
        case 'eth': return true;
        case 'arp': return !!f.arp;
        case 'ip': return !!f.ip && !f.ip.src.includes(':');
        case 'ipv6': return !!f.ip && f.ip.src.includes(':');
        case 'icmp': return f.ip?.proto === 'icmp' && !f.ip.src.includes(':');
        case 'icmpv6': return f.ip?.proto === 'icmp' && f.ip.src.includes(':');
        case 'vlan': return f.vlan !== undefined;
        case 'tcp': return f.ip?.proto === 'tcp';
        case 'udp': return f.ip?.proto === 'udp';
        case 'dns': return f.ip?.app?.protocol === 'DNS';
        case 'ssh': return f.ip?.app?.protocol === 'SSH';
        case 'dhcp': return f.ip?.app?.protocol === 'DHCP';
        case 'dhcpv6': return f.ip?.app?.protocol === 'DHCPv6';
        case 'tls': return f.ip?.app?.protocol === 'TLS';
        case 'kerberos': return f.ip?.app?.protocol === 'KRB5';
        case 'http': return f.ip?.app?.protocol === 'DATA' && (f.ip.tcp?.sport === 80 || f.ip.tcp?.dport === 80);
      }
      return false;
    case 'cmp': {
      const vals = fieldValues(f, node.field, index);
      // Wireshark semantics: "!=" on multi-valued fields means "no value equals"
      if (node.op === '!=') return vals.length > 0 && vals.every((v) => cmp(v, '!=', node.value));
      return vals.some((v) => cmp(v, node.op, node.value));
    }
  }
}
