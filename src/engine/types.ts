// Core data model for the infrastructure simulator.
//
// Design rule: persistent configuration lives in the virtual filesystem (the same
// files a real administrator would edit), while runtime state (addresses, routes,
// loaded firewall ruleset, running services) lives on the Host object. Runtime
// state is rebuilt from files at boot, so "works now but not after reboot" faults
// are modelled faithfully.

import type { Ruleset } from './config/nft';
import type { PfRuntime } from './pf/model';
import type { WinState } from './win/model';

export interface FileNode {
  type: 'file' | 'dir';
  mode: number; // permission bits, e.g. 0o644
  owner: string;
  group: string;
  content: string;
  mtime: number;
  /** Nominal size in bytes for large/binary files whose bytes the simulator does not store. */
  size?: number;
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
  /** Account expiry as a day number (days since 1970-01-01, the 8th field of /etc/shadow); undefined/null/-1 = never. */
  expires?: number | null;
}

export interface Addr6 {
  address: string;
  prefix: number;
  scope: 'link' | 'global' | 'host';
  /** kernel = link-local / loopback, static = configured, ra = SLAAC from a router advertisement. */
  origin: 'kernel' | 'static' | 'ra' | 'dhcp6';
  /** Remaining valid lifetime for SLAAC addresses (seconds at the time of assignment). */
  validLft?: number;
}

export interface Interface {
  name: string;
  mac: string;
  segment: string | null; // L2 segment (broadcast domain) id; null = not attached / loopback
  address: string | null;
  prefix: number | null;
  up: boolean;
  /** IPv6 addresses (link-local is added automatically when the interface comes up). */
  addrs6?: Addr6[];
  /** 802.1Q VLAN sub-interface (e.g. eth3.30 on eth3, VLAN id 30). */
  vlan?: { parent: string; id: number };
  /** Segment used when the interface is not cabled to a switch (fixed links such as the WAN). */
  staticSegment?: string | null;
  /** Maximum IP packet size on this link (default 1500; loopback 65536). */
  mtu?: number;
  /** dhclient's binding for this interface (RFC 2131 timers, absolute clock values in ms). */
  dhcp?: DhcpBinding;
  /** Virtual interface created at runtime with `ip link add … type dummy` (gone after a reboot). */
  kind?: 'dummy';
  /** dhclient found no server and sleeps; it tries again at this time (ms). */
  dhcpRetryAt?: number;
  /** DHCPv6 lease held by dhclient -6 on this interface. */
  dhcp6?: Dhcp6Binding;
  /** dhclient -6 has no lease and solicits again at this time (ms). */
  dhcp6RetryAt?: number;
  /** PIDs of the dhclient (-4) and dhclient -6 processes running for this interface. */
  dhcpPid?: number;
  dhcp6Pid?: number;
  /** net.ipv6.conf.IF.autoconf: false = no SLAAC addresses from router advertisements (default on). */
  autoconf6?: boolean;
}

export interface Dhcp6Binding {
  /** Link-local address and DUID of the server that granted the lease. */
  server: string;
  serverDuid: string;
  address: string;
  iaid: string;
  preferred: number;
  valid: number;
  obtained: number;
  /** T1: RENEW (to the server that granted the lease). */
  renewAt: number;
  /** T2: REBIND (to any server). */
  rebindAt: number;
  expires: number;
  state: 'bound' | 'renewing' | 'rebinding';
  /** Next retransmission while RENEWING or REBINDING (ms). */
  nextTry?: number;
}

export interface DhcpBinding {
  server: string;
  leaseTime: number;
  obtained: number;
  /** T1: unicast renewal to the server that granted the lease. */
  renewAt: number;
  /** T2: broadcast rebinding to any server. */
  rebindAt: number;
  expires: number;
  /** Next retransmission while RENEWING or REBINDING (ms). */
  nextTry?: number;
  state: 'bound' | 'renewing' | 'rebinding';
}

/** A cable between two interfaces (e.g. a host NIC and a switch port). */
export interface Link {
  a: { host: string; iface: string };
  b: { host: string; iface: string };
}

/** Runtime state of a VLAN-aware Linux bridge (the switch). */
export interface BridgeState {
  name: string;
  vlanAware: boolean;
  /** Per member port: VLANs carried, PVID (VLAN for untagged ingress) and VLANs sent untagged. */
  ports: Record<string, { vids: number[]; pvid: number | null; untagged: number[] }>;
  /** Learned MAC addresses (forwarding database), per VLAN. */
  fdb?: { mac: string; port: string; vlan: number }[];
}

export interface Route {
  dest: string; // CIDR or 'default'
  via?: string;
  dev: string;
  proto: 'kernel' | 'static' | 'boot' | 'ra';
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
  /** systemctl mask: /etc/systemd/system/UNIT is a link to /dev/null; the unit cannot be started or enabled. */
  masked?: boolean;
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
  kind: 'linux' | 'router' | 'switch' | 'windows' | 'pfsense';
  /** Windows hosts: configuration (registry) and runtime state (services, event logs). */
  win?: WinState;
  /** pfSense runtime: the loaded pf ruleset (configuration is /conf/config.xml). */
  pf?: PfRuntime;
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
  /** IPv6 routes (dest 'default' = ::/0). */
  routes6?: Route[];
  /** net.ipv6.conf.all.forwarding */
  ip6Forward?: boolean;
  /** Present on switches: the VLAN-aware bridge. */
  bridge?: BridgeState | null;
  services: Record<string, ServiceRuntime>;
  journal: LogEntry[];
  capture: CapturedFrame[];
  nextPid: number;
  bootTime: number;
  /** System clock error in ms (host time = world.clock + clockOffset). Kept across reboots, like the RTC. */
  clockOffset?: number;
  /** Path MTU learned from ICMP "fragmentation needed"/"packet too big" (destination -> MTU). Runtime only. */
  pmtu?: Record<string, number>;
}

export interface Segment {
  id: string;
  name: string;
  cidr: string;
  /** IPv6 prefix, if the segment is dual-stack. */
  cidr6?: string;
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
  /** Cabling between host interfaces and switch ports. */
  links?: Link[];
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
  /** Next-hop MTU in "fragmentation needed" (ICMP 3/4) and "packet too big" (ICMPv6 2) errors. */
  mtu?: number;
  /** Echo payload size in bytes (ping -s; default 56). */
  size?: number;
  /** IPv6 Neighbor Discovery fields (RFC 4861). */
  nd?: { target?: string; lladdr?: string; prefixes?: { prefix: string; autonomous: boolean; onLink?: boolean; valid: number }[]; rdnss?: string[]; routerLifetime?: number; flags?: string; managed?: boolean; other?: boolean };
}

export interface AppLayer {
  protocol: 'DNS' | 'SSH' | 'DATA' | 'DHCP' | 'DHCPv6' | 'TLS' | 'KRB5' | 'KADMIN' | 'RDP';
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
  /** IPv4 Don't Fragment bit. TCP sets it (path MTU discovery); ping only with -M do. IPv6 routers never fragment. */
  df?: boolean;
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
  /** 802.1Q tag when the frame is tagged on this interface (trunk ports, parent of a VLAN sub-interface). */
  vlan?: number;
  ip?: Packet;
  arp?: ArpPacket;
}
