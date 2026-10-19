// libpcap file writer (https://wiki.wireshark.org/Development/LibpcapFileFormat).
// Builds Ethernet II (optionally 802.1Q-tagged) / IPv4 / IPv6 / TCP / UDP /
// ICMP / ICMPv6 (incl. Neighbor Discovery) / ARP frames with valid checksums
// from the simulator's captured frames so learners can open the synthetic
// capture in Wireshark.

import { parseIp } from './net/ip';
import { ip6Bytes } from './net/ip6';
import type { CapturedFrame, Packet } from './types';
import { seededBytes, utf8 } from './util/sha256';

function mac(s: string): number[] {
  return s.split(':').map((x) => parseInt(x, 16));
}

function ipBytes(s: string): number[] {
  if (s.includes(':')) return ip6Bytes(s);
  const n = parseIp(s) ?? 0;
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
}

function u16(n: number): number[] {
  return [(n >> 8) & 255, n & 255];
}

function u32(n: number): number[] {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
}

export function checksum(bytes: number[]): number {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2) sum += (bytes[i] << 8) + (bytes[i + 1] ?? 0);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function payloadOf(p: Packet, len: number): number[] {
  if (p.app?.bytes && p.app.bytes.length === len) return [...p.app.bytes];
  if (p.app?.protocol === 'DATA' && len > 0) {
    const text = utf8(p.app.info + '\r\n');
    return Array.from({ length: len }, (_, i) => text[i] ?? 0x20);
  }
  return [...seededBytes(`payload:${p.id}`, len)];
}

/** Checksum pseudo-header: RFC 793 for IPv4, RFC 8200 §8.1 for IPv6. */
function pseudo(p: Packet, proto: number, len: number): number[] {
  const src = ipBytes(p.src);
  const dst = ipBytes(p.dst);
  return p.src.includes(':') ? [...src, ...dst, ...u32(len), 0, 0, 0, proto] : [...src, ...dst, 0, proto, ...u16(len)];
}

/** ICMPv6 message body (RFC 4443, RFC 4861 options). */
function icmp6Body(p: Packet): number[] {
  const i = p.icmp!;
  const nd = i.nd;
  const lla = (type: number, m?: string) => (m ? [type, 1, ...mac(m)] : []);
  switch (i.type) {
    case 133: return [0, 0, 0, 0, ...lla(1, nd?.lladdr)];
    case 135: return [0, 0, 0, 0, ...ip6Bytes(nd?.target ?? '::'), ...lla(1, nd?.lladdr)];
    case 136: {
      const f = nd?.flags ?? '';
      const flags = (f.includes('router') ? 0x80 : 0) | (f.includes('solicited') ? 0x40 : 0) | (f.includes('override') ? 0x20 : 0);
      return [flags, 0, 0, 0, ...ip6Bytes(nd?.target ?? '::'), ...lla(2, nd?.lladdr)];
    }
    case 134: {
      const out = [64, 0, ...u16(nd?.routerLifetime ?? 0), ...u32(0), ...u32(0), ...lla(1, nd?.lladdr)];
      for (const pr of nd?.prefixes ?? []) {
        const [a, len] = pr.prefix.split('/');
        out.push(3, 4, Number(len), 0x80 | (pr.autonomous ? 0x40 : 0), ...u32(pr.valid), ...u32(14400), 0, 0, 0, 0, ...ip6Bytes(a));
      }
      if (nd?.rdnss?.length) out.push(25, 1 + 2 * nd.rdnss.length, 0, 0, ...u32(600), ...nd.rdnss.flatMap((d) => ip6Bytes(d)));
      return out;
    }
    default:
      if (i.quoted) {
        const q = i.quoted;
        const qproto = q.proto === 'tcp' ? 6 : q.proto === 'udp' ? 17 : 58;
        const qip = [0x60, 0, 0, 0, ...u16(8), qproto, 63, ...ipBytes(q.src), ...ipBytes(q.dst)];
        return [0, 0, 0, 0, ...qip, ...u16(q.sport ?? 0), ...u16(q.dport ?? 0), 0, 0, 0, 0];
      }
      return [...u16(i.id ?? 0), ...u16(i.seq ?? 0), ...Array.from({ length: 56 }, (_, k) => (k + 0x10) & 255)];
  }
}

function l4(p: Packet): number[] {
  if (p.tcp) {
    const t = p.tcp;
    const syn = t.flags.includes('SYN');
    const options = syn
      ? [2, 4, ...u16(1460), 4, 2, 8, 10, ...u32(1520034), ...u32(0), 1, 3, 3, 7]
      : [1, 1, 8, 10, ...u32(1520034 + (p.id % 1000)), ...u32(901234)];
    const hdrLen = 20 + options.length;
    const flags = (t.flags.includes('FIN') ? 1 : 0) | (t.flags.includes('SYN') ? 2 : 0) | (t.flags.includes('RST') ? 4 : 0) | (t.flags.includes('PSH') ? 8 : 0) | (t.flags.includes('ACK') ? 16 : 0);
    const payload = payloadOf(p, t.len);
    const seg = [...u16(t.sport), ...u16(t.dport), ...u32(t.seq), ...u32(t.ack), (hdrLen / 4) << 4, flags, ...u16(t.window), 0, 0, 0, 0, ...options, ...payload];
    const c = checksum([...pseudo(p, 6, seg.length), ...seg]);
    seg[16] = c >> 8;
    seg[17] = c & 255;
    return seg;
  }
  if (p.udp) {
    const payload = payloadOf(p, p.udp.len);
    const seg = [...u16(p.udp.sport), ...u16(p.udp.dport), ...u16(8 + payload.length), 0, 0, ...payload];
    const c = checksum([...pseudo(p, 17, seg.length), ...seg]) || 0xffff;
    seg[6] = c >> 8;
    seg[7] = c & 255;
    return seg;
  }
  const i = p.icmp!;
  if (p.src.includes(':')) {
    const msg = [i.type, i.code, 0, 0, ...icmp6Body(p)];
    const c = checksum([...pseudo(p, 58, msg.length), ...msg]);
    msg[2] = c >> 8;
    msg[3] = c & 255;
    return msg;
  }
  let body: number[];
  if (i.quoted) {
    // Quoted original IP header + first 8 bytes of its payload (RFC 792).
    const q = i.quoted;
    const qproto = q.proto === 'tcp' ? 6 : q.proto === 'udp' ? 17 : 1;
    const qip = [0x45, 0, ...u16(60), 0, 0, 0x40, 0, 63, qproto, 0, 0, ...ipBytes(q.src), ...ipBytes(q.dst)];
    const qc = checksum(qip);
    qip[10] = qc >> 8;
    qip[11] = qc & 255;
    body = [0, 0, 0, 0, ...qip, ...u16(q.sport ?? 0), ...u16(q.dport ?? 0), 0, 0, 0, 0];
  } else {
    body = [...u16(i.id ?? 0), ...u16(i.seq ?? 0), ...Array.from({ length: 56 }, (_, k) => (k + 0x10) & 255)];
  }
  const msg = [i.type, i.code, 0, 0, ...body];
  const c = checksum(msg);
  msg[2] = c >> 8;
  msg[3] = c & 255;
  return msg;
}

export function frameBytes(f: CapturedFrame): Uint8Array {
  const tag = f.vlan !== undefined ? [0x81, 0x00, ...u16(f.vlan & 0x0fff)] : [];
  if (f.arp) {
    const a = f.arp;
    return new Uint8Array([
      ...mac(f.dstMac), ...mac(f.srcMac), ...tag, 0x08, 0x06,
      0, 1, 0x08, 0x00, 6, 4, ...u16(a.op === 'request' ? 1 : 2),
      ...mac(a.senderMac), ...ipBytes(a.senderIp), ...mac(a.targetMac), ...ipBytes(a.targetIp),
      ...new Array(18).fill(0), // pad to 60 bytes
    ]);
  }
  const p = f.ip!;
  const seg = l4(p);
  if (p.src.includes(':')) {
    const nh = p.proto === 'tcp' ? 6 : p.proto === 'udp' ? 17 : 58;
    const ip6 = [0x60, 0, 0, 0, ...u16(seg.length), nh, p.ttl, ...ipBytes(p.src), ...ipBytes(p.dst)];
    return new Uint8Array([...mac(f.dstMac), ...mac(f.srcMac), ...tag, 0x86, 0xdd, ...ip6, ...seg]);
  }
  const proto = p.proto === 'tcp' ? 6 : p.proto === 'udp' ? 17 : 1;
  const ip = [0x45, 0, ...u16(20 + seg.length), ...u16(p.id & 0xffff), 0x40, 0, p.ttl, proto, 0, 0, ...ipBytes(p.src), ...ipBytes(p.dst)];
  const c = checksum(ip);
  ip[10] = c >> 8;
  ip[11] = c & 255;
  const frame = [...mac(f.dstMac), ...mac(f.srcMac), ...tag, 0x08, 0x00, ...ip, ...seg];
  while (frame.length < 60) frame.push(0);
  return new Uint8Array(frame);
}

export function buildPcap(frames: CapturedFrame[]): Uint8Array {
  const parts: number[] = [];
  const le32 = (n: number) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
  const le16 = (n: number) => [n & 255, (n >> 8) & 255];
  parts.push(...le32(0xa1b2c3d4), ...le16(2), ...le16(4), ...le32(0), ...le32(0), ...le32(65535), ...le32(1));
  for (const f of frames) {
    const bytes = frameBytes(f);
    const sec = Math.floor(f.time / 1000);
    const usec = Math.floor((f.time % 1000) * 1000);
    parts.push(...le32(sec), ...le32(usec), ...le32(bytes.length), ...le32(bytes.length), ...bytes);
  }
  return new Uint8Array(parts);
}
