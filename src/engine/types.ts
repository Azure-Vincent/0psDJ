// Core data model for the infrastructure simulator.
//
// Design rule: persistent configuration lives in the virtual filesystem (the same
// files a real administrator would edit), while runtime state (addresses, routes,
// loaded firewall ruleset, running services) lives on the Host object. Runtime
// state is rebuilt from files at boot, so "works now but not after reboot" faults
// are modelled faithfully.

import type { Ruleset } from './config/nft';

export interface FileNode {
  type: 'file' | 'dir';
  mode: number; // permission bits, e.g. 0o644
  owner: string;
  group: string;
  content: string;
  mtime: number;
}

export interface UserAccount {
  name: string;
  uid: number;
  gid: number;
  primaryGroup: string;
  groups: string[];
  home: string;
  shell: string;
  gecos: string;
  /** Plain-text password for the simulation only; null = no password set (locked). */
  password: string | null;
}

export interface Interface {
  name: string;
  mac: string;
  segment: string | null; // L2 segment id (null for loopback)
  address: string | null;
  prefix: number | null;
  up: boolean;
}

export interface Route {
  dest: string; // CIDR or 'default'
  via?: string;
  dev: string;
  proto: 'kernel' | 'static' | 'boot';
  src?: string;
}

export interface Neighbor {
  ip: string;
  dev: string;
  mac: string | null;
  state: 'REACHABLE' | 'STALE' | 'FAILED';
}

export type ServiceState = 'active' | 'inactive' | 'failed';

export interface ServiceRuntime {
  state: ServiceState;
  enabled: boolean;
  since: number;
  pid: number | null;
  /** Service-specific snapshot of the configuration loaded at (re)start. */
  loaded: unknown;
  result: string; // systemd "Result:" e.g. success, exit-code
}

export interface LogEntry {
  time: number;
  host: string;
  ident: string; // syslog identifier: sshd, systemd, kernel, named ...
  pid: number | null;
  unit: string | null; // systemd unit, used by journalctl -u
  priority: 'err' | 'warning' | 'notice' | 'info' | 'debug';
  message: string;
}

export interface ConntrackEntry {
  proto: 'tcp' | 'udp' | 'icmp';
  src: string;
  dst: string;
  sport: number;
  dport: number;
  state: string;
  time: number;
}

export interface NatTuple {
  src: string;
  sport: number;
  dst: string;
  dport: number;
}

/** One translated flow: the original tuple and the tuple after translation (original direction). */
export interface NatEntry {
  proto: 'tcp' | 'udp' | 'icmp';
  orig: NatTuple;
  trans: NatTuple;
  kind: string; // e.g. "masquerade", "dnat", "dnat+masquerade"
  rule: string;
  time: number;
}

export interface Host {
  id: string;
  hostname: string;
  domain: string;
  osName: string;
  kind: 'linux' | 'router';
  role: string;
  users: Record<string, UserAccount>;
  fs: Record<string, FileNode>;
  ifaces: Interface[];
  routes: Route[];
  neighbors: Neighbor[];
  nft: Ruleset;
  conntrack: ConntrackEntry[];
  /** NAT translations (kept with conntrack in the real kernel). */
  nat: NatEntry[];
  ipForward: boolean;
  services: Record<string, ServiceRuntime>;
  journal: LogEntry[];
  capture: CapturedFrame[];
  nextPid: number;
  bootTime: number;
}

export interface Segment {
  id: string;
  name: string;
  cidr: string;
  vlan?: number;
}

export interface World {
  name: string;
  hosts: Record<string, Host>;
  segments: Record<string, Segment>;
  /** Simulated wall clock, milliseconds since the Unix epoch. */
  clock: number;
  /** Monotonic counter used for packet ids, ephemeral ports and ISNs (keeps runs deterministic). */
  counter: number;
  /** Open interactive SSH sessions (so `ss` can show ESTAB sockets on both ends). */
  sessions?: OpenSession[];
}

export interface OpenSession {
  clientHostId: string;
  serverHostId: string;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  user: string;
  pid: number;
}

// ---------------------------------------------------------------------------
// Packets
// ---------------------------------------------------------------------------

export type L4Proto = 'tcp' | 'udp' | 'icmp';

export interface TcpHeader {
  sport: number;
  dport: number;
  seq: number;
  ack: number;
  flags: TcpFlag[];
  window: number;
  /** Payload length in bytes. */
  len: number;
  options?: string;
}
export type TcpFlag = 'SYN' | 'ACK' | 'FIN' | 'RST' | 'PSH';

export interface UdpHeader {
  sport: number;
  dport: number;
  len: number;
}

export interface IcmpHeader {
  type: number;
  code: number;
  description: string;
  id?: number;
  seq?: number;
  /** For ICMP errors: summary of the offending datagram. */
  quoted?: { proto: L4Proto; src: string; dst: string; sport?: number; dport?: number };
}

export interface AppLayer {
  protocol: 'DNS' | 'SSH' | 'DATA' | 'DHCP';
  /** Short Wireshark-style "Info" text. */
  info: string;
  /** Decoded protocol fields visible to an observer. */
  fields: { name: string; value: string }[];
  /** True when the payload is encrypted and fields are NOT visible on the wire. */
  encrypted?: boolean;
  /** Raw payload bytes for PCAP export. */
  bytes?: Uint8Array;
}

export interface Packet {
  id: number;
  src: string;
  dst: string;
  ttl: number;
  proto: L4Proto;
  tcp?: TcpHeader;
  udp?: UdpHeader;
  icmp?: IcmpHeader;
  app?: AppLayer;
}

export interface ArpPacket {
  op: 'request' | 'reply';
  senderIp: string;
  senderMac: string;
  targetIp: string;
  targetMac: string; // 00:00:00:00:00:00 in requests
}

/** A frame as observed on a specific host interface (what tcpdump would show there). */
export interface CapturedFrame {
  time: number;
  host: string;
  iface: string;
  dir: 'in' | 'out';
  srcMac: string;
  dstMac: string;
  ip?: Packet;
  arp?: ArpPacket;
}
