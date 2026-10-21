// tcpdump-style one-line rendering of captured frames.
import type { CapturedFrame, Packet } from '../types';

function ts(ms: number): string {
  const d = new Date(Math.floor(ms));
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  const micro = Math.floor((ms % 1000) * 1000);
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(micro, 6)}`;
}

function tcpFlags(flags: string[]): string {
  let s = '';
  if (flags.includes('SYN')) s += 'S';
  if (flags.includes('FIN')) s += 'F';
  if (flags.includes('RST')) s += 'R';
  if (flags.includes('PSH')) s += 'P';
  if (flags.includes('ACK')) s += '.';
  return s;
}

function describeIcmp6(p: Packet): string {
  const i = p.icmp!;
  const pre = `IP6 ${p.src} > ${p.dst}: ICMP6, `;
  switch (i.type) {
    case 128: return `${pre}echo request, id ${i.id}, seq ${i.seq}, length ${(i.size ?? 56) + 8}`;
    case 129: return `${pre}echo reply, id ${i.id}, seq ${i.seq}, length ${(i.size ?? 56) + 8}`;
    case 2: return `${pre}packet too big, mtu ${i.mtu}, length 1240`;
    case 133: return `${pre}router solicitation, length 16`;
    case 134: return `${pre}router advertisement, length ${24 + 32 * (i.nd?.prefixes?.length ?? 0) + (i.nd?.rdnss?.length ? 24 : 0) + 8}`;
    case 135: return `${pre}neighbor solicitation, who has ${i.nd?.target}, length 32`;
    case 136: return `${pre}neighbor advertisement, tgt is ${i.nd?.target}, length 32`;
    case 3: return `${pre}time exceeded in-transit, length 88`;
    case 1: {
      const q = i.quoted;
      const what = i.code === 0 ? `unreachable route ${q?.dst}` : i.code === 1 ? `unreachable prohibited ${q?.dst}` : i.code === 4 ? `unreachable port, ${q?.dst} ${q?.proto} port ${q?.dport}` : `unreachable address ${q?.dst}`;
      return `${pre}destination unreachable, ${what}, length 88`;
    }
    default: return `${pre}type ${i.type}, length 32`;
  }
}

export function describeIp(p: Packet, isn?: { a: number; b: number }): string {
  const v6 = p.src.includes(':');
  if (v6 && p.icmp) return describeIcmp6(p);
  return describeIp4Style(p, isn, v6 ? 'IP6' : 'IP');
}

function describeIp4Style(p: Packet, isn: { a: number; b: number } | undefined, IP: string): string {
  if (p.tcp) {
    const t = p.tcp;
    const rel = (n: number, base?: number) => (base === undefined ? n : (n - base) >>> 0);
    const seqBase = isn ? (t.flags.includes('SYN') ? undefined : isn.a) : undefined;
    const ackBase = isn ? isn.b : undefined;
    let seq = '';
    if (t.flags.includes('SYN')) seq = `, seq ${t.seq}`;
    else if (t.len > 0) seq = `, seq ${rel(t.seq, seqBase)}:${rel(t.seq + t.len, seqBase)}`;
    else if (!t.flags.includes('RST') || t.flags.includes('ACK')) seq = t.flags.includes('FIN') ? `, seq ${rel(t.seq, seqBase)}` : '';
    const ack = t.flags.includes('ACK') ? `, ack ${t.flags.includes('SYN') || ackBase === undefined ? t.ack : rel(t.ack, ackBase)}` : '';
    const opts = t.flags.includes('SYN') ? `, options [mss ${/MSS=(\d+)/.exec(t.options ?? '')?.[1] ?? 1460},sackOK,TS val 1520034 ecr 0,nop,wscale 7]` : '';
    return `${IP} ${p.src}.${t.sport} > ${p.dst}.${t.dport}: Flags [${tcpFlags(t.flags)}]${seq}${ack}, win ${t.window}${opts}, length ${t.len}`;
  }
  if (p.udp) {
    if (p.app?.protocol === 'DHCP') {
      const mac = p.app.fields.find((f) => f.name === 'Client MAC (chaddr)')?.value ?? '';
      return `${IP} ${p.src}.${p.udp.sport} > ${p.dst}.${p.udp.dport}: BOOTP/DHCP, ${p.udp.sport === 68 ? `Request from ${mac}` : 'Reply'}, length ${p.udp.len}`;
    }
    if (p.app?.protocol === 'DNS') {
      const info = p.app.info;
      const id = /0x([0-9a-f]{4})/.exec(info)?.[1];
      const idn = id ? parseInt(id, 16) : 0;
      const qm = /(AAAA|A) (\S+)$/.exec(info);
      const qtype = qm?.[1] ?? 'A';
      const q = qm?.[2] ?? '';
      if (info.startsWith('Standard query response')) {
        const answers = p.app.fields.filter((f) => f.name === 'Answer').map((f) => f.value.split(' ').slice(3).join(' '));
        const rcode = /refused/.test(info) ? 'Refused' : /nxdomain/.test(info) ? 'NXDomain' : /servfail/.test(info) ? 'ServFail' : '';
        return `${IP} ${p.src}.${p.udp.sport} > ${p.dst}.${p.udp.dport}: ${idn}*${rcode ? ' ' + rcode : ''}- ${answers.length}/0/0 ${answers.join(', ')} (${p.udp.len})`;
      }
      return `${IP} ${p.src}.${p.udp.sport} > ${p.dst}.${p.udp.dport}: ${idn}+ ${qtype}? ${q}. (${p.udp.len})`;
    }
    return `${IP} ${p.src}.${p.udp.sport} > ${p.dst}.${p.udp.dport}: UDP, length ${p.udp.len}`;
  }
  if (p.icmp) {
    const i = p.icmp;
    if (i.type === 8) return `IP ${p.src} > ${p.dst}: ICMP echo request, id ${i.id}, seq ${i.seq}, length ${(i.size ?? 56) + 8}`;
    if (i.type === 0) return `IP ${p.src} > ${p.dst}: ICMP echo reply, id ${i.id}, seq ${i.seq}, length ${(i.size ?? 56) + 8}`;
    if (i.type === 11) return `IP ${p.src} > ${p.dst}: ICMP time exceeded in-transit, length 36`;
    if (i.type === 3 && i.quoted) {
      const q = i.quoted;
      if (i.code === 3) return `IP ${p.src} > ${p.dst}: ICMP ${q.dst} ${q.proto} port ${q.dport} unreachable, length 36`;
      if (i.code === 4) return `IP ${p.src} > ${p.dst}: ICMP ${q.dst} unreachable - need to frag (mtu ${i.mtu}), length 556`;
      if (i.code === 13) return `IP ${p.src} > ${p.dst}: ICMP host ${q.dst} unreachable - admin prohibited filter, length 36`;
      if (i.code === 1) return `IP ${p.src} > ${p.dst}: ICMP host ${q.dst} unreachable, length 36`;
      if (i.code === 0) return `IP ${p.src} > ${p.dst}: ICMP net ${q.dst} unreachable, length 36`;
    }
    return `IP ${p.src} > ${p.dst}: ICMP type ${i.type} code ${i.code}`;
  }
  return `IP ${p.src} > ${p.dst}`;
}

export function formatFrame(f: CapturedFrame, opts: { isn?: { a: number; b: number }; ether?: boolean } = {}): string {
  const inner = f.arp ? 'ARP (0x0806)' : f.ip?.src.includes(':') ? 'IPv6 (0x86dd)' : 'IPv4 (0x0800)';
  const eth = !opts.ether ? '' : f.vlan !== undefined
    ? `${f.srcMac} > ${f.dstMac}, ethertype 802.1Q (0x8100), vlan ${f.vlan}, p 0, ethertype ${inner}, `
    : `${f.srcMac} > ${f.dstMac}, `;
  if (f.arp) {
    const a = f.arp;
    return a.op === 'request'
      ? `${ts(f.time)} ${eth}ARP, Request who-has ${a.targetIp} tell ${a.senderIp}, length 28`
      : `${ts(f.time)} ${eth}ARP, Reply ${a.senderIp} is-at ${a.senderMac}, length 28`;
  }
  return `${ts(f.time)} ${eth}${describeIp(f.ip!, opts.isn)}`;
}
