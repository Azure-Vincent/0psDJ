// Trace recording: the protocol simulators emit an ordered list of events
// (packets with their hop-by-hop path, plus host-internal operations such as
// "sshd checks authorized_keys"). The sequence-diagram UI, the packet lab and
// PCAP export are all driven by the same events, so what the learner sees is
// exactly what the engine computed.

import type { ArpPacket, Packet } from '../types';
import type { HopRecord } from './network';

export type Phase =
  | 'ARP'
  | 'DNS'
  | 'DHCP'
  | 'TCP'
  | 'SSH transport'
  | 'SSH key exchange'
  | 'SSH authentication'
  | 'SSH session'
  | 'ICMP'
  | 'Teardown';

export interface EndpointState {
  tcp?: string;
  ssh?: string;
  crypto?: string;
}

export interface TraceEvent {
  id: number;
  time: number;
  kind: 'packet' | 'arp' | 'internal';
  from: string;
  to: string;
  via: string[];
  packet?: Packet;
  arp?: ArpPacket;
  hops?: HopRecord[];
  outcome?: string; // delivered / dropped at X / rejected ...
  delivered?: boolean;
  phase: Phase;
  title: string;
  detail: string;
  /** Per-host state *after* this event (keyed by host id). */
  state: Record<string, EndpointState>;
}

export class Recorder {
  events: TraceEvent[] = [];
  private seq = 0;
  private inflight: TraceEvent[] = [];
  phase: Phase = 'TCP';
  current: Record<string, EndpointState> = {};

  private snapshot(): Record<string, EndpointState> {
    return JSON.parse(JSON.stringify(this.current));
  }

  setState(host: string, s: Partial<EndpointState>): void {
    this.current[host] = { ...this.current[host], ...s };
    // apply to the most recent event so it reflects the state after it
    const last = this.events[this.events.length - 1];
    if (last) last.state = this.snapshot();
  }

  beginPacket(time: number, from: string, packet: Packet): TraceEvent {
    const ev: TraceEvent = {
      id: ++this.seq, time, kind: 'packet', from, to: from, via: [], packet,
      phase: packet.proto === 'icmp' ? 'ICMP' : this.phase,
      title: defaultTitle(packet), detail: '', state: this.snapshot(),
    };
    this.events.push(ev);
    this.inflight.push(ev);
    return ev;
  }

  endPacket(ev: TraceEvent, to: string, via: string[], hops: HopRecord[], delivered: boolean, outcome: string): void {
    ev.to = to;
    ev.via = via;
    ev.hops = hops;
    ev.delivered = delivered;
    ev.outcome = outcome;
    this.inflight = this.inflight.filter((e) => e !== ev);
  }

  arp(time: number, from: string, to: string, arp: ArpPacket): void {
    const ev: TraceEvent = {
      id: ++this.seq, time, kind: 'arp', from, to, via: [], arp, phase: 'ARP', delivered: true,
      title: arp.op === 'request' ? `ARP: who has ${arp.targetIp}? tell ${arp.senderIp}` : `ARP: ${arp.senderIp} is at ${arp.senderMac}`,
      detail: arp.op === 'request'
        ? `Before an IPv4 packet can be put in an Ethernet frame, the sender needs the next hop's MAC address. ${arp.senderIp} broadcasts (ff:ff:ff:ff:ff:ff) an ARP request on the local segment. ARP never crosses a router.`
        : `The owner of ${arp.senderIp} replies directly (unicast) with its MAC address. Both sides now cache the mapping (see "ip neigh").`,
      state: this.snapshot(),
    };
    // ARP happens before the frame that needed it is transmitted.
    const pending = this.inflight[this.inflight.length - 1];
    const idx = pending ? this.events.indexOf(pending) : -1;
    if (idx >= 0) this.events.splice(idx, 0, ev);
    else this.events.push(ev);
  }

  /** Attach a teaching title/explanation to the event that carried packet `id`. */
  describe(packetId: number, title: string, detail: string): void {
    const e = this.events.find((x) => x.kind === 'packet' && x.packet?.id === packetId);
    if (!e) return;
    e.title = title;
    e.detail = detail + (e.delivered ? '' : `\n\nThis packet did NOT reach its destination: ${e.outcome}.`);
  }

  internal(time: number, host: string, title: string, detail: string, phase?: Phase): TraceEvent {
    const ev: TraceEvent = {
      id: ++this.seq, time, kind: 'internal', from: host, to: host, via: [],
      phase: phase ?? this.phase, title, detail, state: this.snapshot(),
    };
    this.events.push(ev);
    return ev;
  }
}

export function defaultTitle(p: Packet): string {
  if (p.app) return p.app.info;
  if (p.tcp) return `TCP ${p.tcp.sport} → ${p.tcp.dport} [${p.tcp.flags.join(', ')}] Seq=${p.tcp.seq} Ack=${p.tcp.ack} Len=${p.tcp.len}`;
  if (p.udp) return `UDP ${p.udp.sport} → ${p.udp.dport} Len=${p.udp.len}`;
  if (p.icmp) return `ICMP ${p.icmp.description}`;
  return 'IP';
}

let active: Recorder | null = null;

export function activeRecorder(): Recorder | null {
  return active;
}

export function withRecorder<T>(rec: Recorder | null, fn: () => T): T {
  const prev = active;
  active = rec;
  try {
    return fn();
  } finally {
    active = prev;
  }
}
