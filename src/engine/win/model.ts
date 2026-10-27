// Windows Server hosts. A Windows machine shares the simulator's network stack
// (interfaces, routes, ARP, TCP/UDP) with the Linux hosts; what differs lives in
// host.win: persistent configuration (what Windows keeps in the registry:
// services' start types, Windows Defender Firewall profiles and rules, adapter
// IP settings, the RDP switches) and runtime state (service status, event logs).
// At boot the configuration is applied: addresses and routes are set, services
// with start type Automatic start, and the firewall is compiled into the
// packet filter the network engine evaluates.

import { parseRuleExpr, type Rule, type Ruleset } from '../config/nft';
import { networkOf } from '../net/ip';
import { linkLocalFromMac } from '../net/ip6';
import type { Host, World } from '../types';
import type { ZoneRecord } from '../config/zone';
import type { CachedTicket } from '../config/krb5';
import { domainBoot } from './ad';
import { timeSync } from './kerberos';
import { recomputeL2 } from '../sim/l2';

export type FwProfile = 'Domain' | 'Private' | 'Public';
export const FW_PROFILES: FwProfile[] = ['Domain', 'Private', 'Public'];

export interface WinFwRule {
  /** Unique rule name (Name in PowerShell), e.g. "RemoteDesktop-UserMode-In-TCP". */
  name: string;
  displayName: string;
  group: string;
  description?: string;
  direction: 'Inbound' | 'Outbound';
  action: 'Allow' | 'Block';
  enabled: boolean;
  /** 'Any' or a list of profiles. */
  profiles: 'Any' | FwProfile[];
  protocol: 'TCP' | 'UDP' | 'ICMPv4' | 'ICMPv6' | 'Any';
  /** 'Any' or port numbers/ranges as strings. */
  localPort: 'Any' | string[];
  /** 'Any', 'LocalSubnet', or addresses/CIDRs. */
  remoteAddress: 'Any' | string[];
  /** The sender's port (TCP/UDP); unset means Any. */
  remotePort?: 'Any' | string[];
  /** This computer's address the packet is sent to (or from, outbound); unset means Any. */
  localAddress?: 'Any' | string[];
  /** ICMP "type:code" (e.g. "8" = echo request). */
  icmpType?: string;
  /** Inbound: the program that owns the listening socket ("System" for kernel listeners such as http.sys). */
  program?: string;
  /** Rules created by an administrator (PolicyStoreSourceType Local) vs. shipped defaults. */
  builtIn?: boolean;
  /** Set on rules that came from Group Policy: "ad.corp.lab\\GPO name" (PolicyStoreSource). */
  gpo?: string;
}

/** Per-profile settings (Get-NetFirewallProfile). */
export interface FwProfileSettings {
  enabled: boolean;
  defaultInbound: 'Block' | 'Allow';
  defaultOutbound: 'Block' | 'Allow';
  /** Write dropped packets to pfirewall.log. */
  logBlocked: boolean;
  /** Write allowed connections to pfirewall.log. */
  logAllowed?: boolean;
  /** pfirewall.log size limit (LogMaxSizeKilobytes, default 4096). */
  logMaxKb?: number;
  /** Merge local rules with policy rules (false: only rules from Group Policy count). Group Policy setting. */
  allowLocalRules?: boolean;
}

export type StartType = 'Automatic' | 'AutomaticDelayedStart' | 'Manual' | 'Disabled';

export interface WinService {
  name: string;
  displayName: string;
  startType: StartType;
  status: 'Running' | 'Stopped';
  /** Image name of the hosting process (svchost.exe for shared services). */
  process: string;
  pid: number | null;
  dependsOn: string[];
  /** Cannot be stopped (protected services such as mpssvc). */
  protected?: boolean;
}

export interface WinAdapter {
  /** InterfaceAlias, also the simulator interface name. */
  alias: string;
  ifIndex: number;
  description: string;
  dhcp: boolean;
  address: string | null;
  prefix: number | null;
  gateway: string | null;
  dns: string[];
  dnsSuffix: string;
  /** Network location of the connection: selects the firewall profile. */
  category: FwProfile;
}

export interface WinEvent {
  time: number;
  log: string;
  id: number;
  level: 'Information' | 'Warning' | 'Error';
  provider: string;
  message: string;
  recordId: number;
}

export type RegValue = string | number;

export interface WinState {
  productName: string;
  build: string;
  workgroup: string;
  firewall: { profiles: Record<FwProfile, FwProfileSettings>; rules: WinFwRule[] };
  services: Record<string, WinService>;
  adapters: WinAdapter[];
  /** A small part of the registry: HKLM paths → values. */
  registry: Record<string, Record<string, RegValue>>;
  events: WinEvent[];
  nextRecord: number;
  /** Port RDP listens on, read when TermService starts. */
  rdpPort?: number;
  /** Installed roles and features (Get-WindowsFeature names). */
  features?: string[];
  /** Active Directory database: present on a domain controller. */
  ad?: AdState;
  /** DNS Server role (zones and forwarders). */
  dnsServer?: DnsServerState;
  /** Domain membership in effect (set at boot from pendingDomain). */
  domain?: DomainMembership;
  /** Join (or, with null, leave) that takes effect at the next restart. */
  pendingDomain?: DomainMembership | null;
  /** Domain principals in local groups ("CORP\\Domain Admins" in Administrators). */
  localDomainMembers?: Record<string, string[]>;
  /** Runtime: a domain controller was reachable at boot, so the Domain firewall profile applies. */
  domainNetwork?: boolean;
  /** Group Policy state of this computer (what the last processing applied). */
  gp?: GpState;
  /** Kerberos ticket caches of the logon sessions (LSA), by logon id; runtime only. */
  krb?: Record<string, WinKrbSession>;
  /** The Windows Time service's last synchronisation. */
  timeSync?: { ok: boolean; at: number; source: string };
  /** Mapped network drives (net use), per session of the console user. */
  smbMappings?: { local: string; remote: string; user: string; server: string; share: string }[];
}

/** What Group Policy processing left on a computer (for gpresult and to undo it next time). */
export interface GpState {
  /** When policy was last processed, and from which DC. */
  appliedAt?: number;
  fromDc?: string;
  /** Applied GPOs, lowest precedence first. */
  applied: string[];
  /** GPOs in scope that did not apply, with gpresult's reason. */
  filtered: { name: string; reason: string }[];
  /** Registry values written from policy (removed again when the GPO no longer applies). */
  registry: { key: string; valueName: string }[];
  /** Firewall rules delivered by policy. */
  rules: WinFwRule[];
  /** Firewall profile settings delivered by policy (they override the local ones). */
  profiles?: Partial<Record<FwProfile, Partial<FwProfileSettings>>>;
  /** The computer's security groups as of its last start (its Kerberos ticket): security filtering uses these. */
  token?: string[];
  /** The last processing error (gpupdate / event 1058, 1006, 1055, 1129). */
  lastError?: string;
}

export interface AdUser {
  sam: string;
  name: string;
  enabled: boolean;
  password: string;
  lockedOut: boolean;
  badCount: number;
  description: string;
  rid: number;
  lastLogon?: number;
  /** servicePrincipalName (service accounts). */
  spns?: string[];
}

export interface AdGroup {
  name: string;
  scope: 'Global' | 'DomainLocal' | 'Universal';
  category: 'Security' | 'Distribution';
  description: string;
  /** sAMAccountNames of users, computers (NAME$) or groups. */
  members: string[];
  rid: number;
}

export interface AdComputer {
  name: string;
  dnsHostName: string;
  /** Machine account password; must match the member's copy (the secure channel). */
  password: string;
  enabled: boolean;
  os: string;
  dc?: boolean;
  rid: number;
  /** Container DN (an OU); default CN=Computers, or OU=Domain Controllers for a DC. */
  ou?: string;
  /** servicePrincipalName; unset means the defaults Windows registers at join or promotion. */
  spns?: string[];
}

/** An organizational unit (DN as created, e.g. "OU=Servers,DC=ad,DC=corp,DC=lab"). */
export interface AdOu {
  dn: string;
  name: string;
  description: string;
  /** Block Inheritance: links of parent containers do not apply (unless enforced). */
  blockInheritance: boolean;
  protected: boolean;
}

export type GpPermission = 'GpoRead' | 'GpoApply' | 'GpoEdit' | 'GpoEditDeleteModifySecurity';

/** A Group Policy Object: the container in AD plus its files in SYSVOL (computer configuration only). */
export interface Gpo {
  /** GUID without braces, upper case. */
  id: string;
  name: string;
  status: 'AllSettingsEnabled' | 'UserSettingsDisabled' | 'ComputerSettingsDisabled' | 'AllSettingsDisabled';
  description: string;
  /** Administrative-template (registry policy) values: Set-GPRegistryValue. Keys are "HKLM\\Software\\Policies\\...". */
  registry: { key: string; valueName: string; type: 'DWord' | 'String' | 'ExpandString' | 'QWord'; value: string | number }[];
  /** Windows Defender Firewall rules in the GPO (New-NetFirewallRule -PolicyStore DOMAIN\\GPO). */
  firewallRules: WinFwRule[];
  /** Windows Defender Firewall profile settings in the GPO (Set-NetFirewallProfile -PolicyStore DOMAIN\\GPO). */
  firewallProfiles?: Partial<Record<FwProfile, Partial<FwProfileSettings>>>;
  /** Security settings (password and lockout policy) that only the default GPOs carry here. */
  securitySettings?: boolean;
  /** Security filtering and delegation: trustee → permission. */
  permissions: Record<string, GpPermission>;
  computerVersion: number;
  created: number;
  modified: number;
}

export interface GpLink { gpoId: string; enabled: boolean; enforced: boolean }

export interface AdState {
  domain: string;
  netbios: string;
  domainSid: string;
  users: Record<string, AdUser>;
  groups: Record<string, AdGroup>;
  computers: Record<string, AdComputer>;
  lockoutThreshold: number;
  nextRid: number;
  /** Organizational units by lower-case DN. */
  ous?: Record<string, AdOu>;
  /** Group Policy Objects by id. */
  gpos?: Record<string, Gpo>;
  /** gPLink of each container (domain or OU), by lower-case DN, in link order (1 = highest). */
  gpLinks?: Record<string, GpLink[]>;
}

export interface DnsServerState {
  zones: { origin: string; records: ZoneRecord[]; serial: number; dsIntegrated: boolean }[];
  forwarders: string[];
}

export interface DomainMembership {
  domain: string;
  netbios: string;
  machinePassword: string;
}

export const TS_KEY = 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server';
export const RDP_TCP_KEY = 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp';

/** Which listening sockets each service opens while running. */
const SERVICE_PORTS: Record<string, { proto: 'tcp' | 'udp'; port: number | 'rdp' }[]> = {
  TermService: [{ proto: 'tcp', port: 'rdp' }, { proto: 'udp', port: 'rdp' }],
  LanmanServer: [{ proto: 'tcp', port: 445 }],
  WinRM: [{ proto: 'tcp', port: 5985 }],
  W3SVC: [{ proto: 'tcp', port: 80 }],
  W32Time: [{ proto: 'udp', port: 123 }],
  RpcSs: [{ proto: 'tcp', port: 135 }],
  DNS: [{ proto: 'udp', port: 53 }, { proto: 'tcp', port: 53 }],
  NTDS: [{ proto: 'tcp', port: 389 }, { proto: 'udp', port: 389 }, { proto: 'tcp', port: 636 }, { proto: 'tcp', port: 3268 }],
  Kdc: [{ proto: 'udp', port: 88 }, { proto: 'tcp', port: 88 }, { proto: 'tcp', port: 464 }, { proto: 'udp', port: 464 }],
  ADWS: [{ proto: 'tcp', port: 9389 }],
};

/** A logon session's Kerberos tickets, as klist shows them. */
export interface WinKrbSession {
  logonId: string;
  /** Client principal (alice@AD.CORP.LAB, WIN01$@AD.CORP.LAB). */
  client: string;
  tickets: (CachedTicket & { kdc: string })[];
}

export function isWindows(host: Host | undefined): boolean {
  return host?.kind === 'windows' && !!host.win;
}

export function winEvent(world: World, host: Host, log: string, id: number, provider: string, message: string, level: WinEvent['level'] = 'Information'): void {
  const w = host.win!;
  w.events.push({ time: world.clock, log, id, level, provider, message, recordId: w.nextRecord++ });
  if (w.events.length > 3000) w.events.splice(0, w.events.length - 3000);
}

/** Group Policy's Terminal Services key: when it sets fDenyTSConnections, it wins over the local setting. */
export const TS_POLICY_KEY = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services';

export function rdpEnabled(host: Host): boolean {
  const reg = host.win!.registry;
  const policyKey = Object.keys(reg).find((k) => k.toLowerCase() === TS_POLICY_KEY.toLowerCase());
  const policy = policyKey ? reg[policyKey]?.fDenyTSConnections : undefined;
  return Number(policy ?? reg[TS_KEY]?.fDenyTSConnections ?? 1) === 0;
}

/** Listening sockets of running Windows services. */
export function winListeners(host: Host): { proto: 'tcp' | 'udp'; addr: string; port: number; process: string; pid: number; service: string }[] {
  const w = host.win;
  if (!w) return [];
  const out: ReturnType<typeof winListeners> = [];
  for (const s of Object.values(w.services)) {
    if (s.status !== 'Running' || s.pid === null) continue;
    for (const p of SERVICE_PORTS[s.name] ?? []) {
      if (s.name === 'TermService' && !rdpEnabled(host)) continue;
      const port = p.port === 'rdp' ? w.rdpPort ?? 3389 : p.port;
      // http.sys (IIS, WinRM) and the SMB server run in the kernel: netstat shows them as System, PID 4.
      const kernel = ['W3SVC', 'WinRM', 'LanmanServer'].includes(s.name);
      for (const addr of ['0.0.0.0', '::']) out.push({ proto: p.proto, addr, port, process: kernel ? 'System' : s.process, pid: kernel ? 4 : s.pid, service: s.name });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Windows Defender Firewall → packet filter
// ---------------------------------------------------------------------------

export const WF_TABLE = 'WindowsDefenderFirewall';

/** The firewall profile in force (the category of the first connected adapter). */
export function activeProfile(host: Host): FwProfile {
  // Network Location Awareness: a domain member that can reach a DC uses the Domain profile.
  if (host.win!.domainNetwork) return 'Domain';
  return host.win!.adapters[0]?.category ?? 'Public';
}

/** A profile's settings in force: the local ones, overridden by whatever Group Policy set (ActiveStore). */
export function effectiveProfile(host: Host, name: FwProfile): FwProfileSettings {
  const local = host.win!.firewall.profiles[name];
  const gp = host.win!.gp?.profiles?.[name] ?? {};
  const out = { ...local };
  for (const [k, v] of Object.entries(gp)) if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  return out;
}

function ruleApplies(r: WinFwRule, profile: FwProfile): boolean {
  return r.enabled && (r.profiles === 'Any' || r.profiles.includes(profile));
}

/** Full image path of a listener's process, as a firewall rule's Program names it. */
export function listenerImage(process: string): string {
  return process === 'System' ? 'System' : `C:\\Windows\\System32\\${process}.exe`;
}

/** Normalise a program path for comparison (%SystemRoot%, %windir%, case). */
export function normalProgram(p: string): string {
  return p.replace(/%(systemroot|windir)%/gi, 'C:\\Windows').toLowerCase();
}

/** "10.0.0.0/16", "LocalSubnet" → an nft address set (IPv4 only; undefined: Any; null: nothing left to match). */
function addrSet(host: Host, list: 'Any' | string[] | undefined): string | null | undefined {
  if (!list || list === 'Any') return undefined;
  const addrs = list.flatMap((a) => {
    if (a.toLowerCase() === 'localsubnet') return host.win!.adapters.filter((x) => x.address && x.prefix !== null).map((x) => networkOf(x.address!, x.prefix!));
    // IPv4 addresses and prefixes; IPv6, ranges and keywords such as Internet match no IPv4 packet here.
    return /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(a) ? [a] : [];
  });
  return addrs.length ? `{ ${addrs.join(', ')} }` : null;
}

// Keywords: RPC = the dynamic RPC range, RPCEPMap = the endpoint mapper (135).
const portExpr = (list: string[]) => list.map((p) => (/^rpc$/i.test(p) ? '49152-65535' : /^rpcepmap$/i.test(p) ? '135' : p)).filter((p) => /^\d+(-\d+)?$/.test(p));

const inRange = (port: number, spec: string) => {
  const [a, b] = spec.split('-').map(Number);
  return port >= a && port <= (b ?? a);
};

/**
 * Local ports an inbound Program rule can match. The program condition is the
 * owner of the listening socket: a port where another program listens is left
 * out; a port where nothing listens stays in (the packet would be refused by
 * TCP anyway). With LocalPort Any, only the program's own ports count.
 */
function programPorts(host: Host, r: WinFwRule, ports: string[] | null): string[] | null {
  const want = normalProgram(r.program!);
  if (want === 'any') return ports;
  const protos = r.protocol === 'TCP' ? ['tcp'] : r.protocol === 'UDP' ? ['udp'] : ['tcp', 'udp'];
  const ls = winListeners(host).filter((l) => protos.includes(l.proto));
  const mine = (port: number) => ls.some((l) => l.port === port && normalProgram(listenerImage(l.process)) === want);
  const other = (port: number) => ls.some((l) => l.port === port && normalProgram(listenerImage(l.process)) !== want);
  if (!ports) return [...new Set(ls.filter((l) => mine(l.port)).map((l) => String(l.port)))];
  const out: string[] = [];
  for (const spec of ports) {
    const taken = [...new Set(ls.filter((l) => inRange(l.port, spec) && other(l.port) && !mine(l.port)).map((l) => l.port))].sort((a, b) => a - b);
    if (!taken.length) { out.push(spec); continue; }
    // Split the range around the ports other programs own.
    const [a, b0] = spec.split('-').map(Number);
    const b = b0 ?? a;
    let from = a;
    for (const t of taken) {
      if (t > from) out.push(t - 1 > from ? `${from}-${t - 1}` : String(from));
      from = t + 1;
    }
    if (from <= b) out.push(b > from ? `${from}-${b}` : String(from));
  }
  return out;
}

function ruleMatchText(host: Host, r: WinFwRule): string | null {
  const parts: string[] = [];
  const inbound = r.direction === 'Inbound';
  // Inbound: the remote side is the source; outbound: the destination.
  const remote = addrSet(host, r.remoteAddress);
  if (remote === null) return null;
  if (remote) parts.push(`ip ${inbound ? 'saddr' : 'daddr'} ${remote}`);
  const local = addrSet(host, r.localAddress);
  if (local === null) return null;
  if (local) parts.push(`ip ${inbound ? 'daddr' : 'saddr'} ${local}`);
  let lports: string[] | null = r.localPort === 'Any' ? null : portExpr(r.localPort);
  if (lports && !lports.length) lports = null;
  if (r.program && inbound) {
    lports = programPorts(host, r, lports);
    if (lports && !lports.length) return null;
  }
  const rports = !r.remotePort || r.remotePort === 'Any' ? null : portExpr(r.remotePort);
  if (r.protocol === 'TCP' || r.protocol === 'UDP') {
    const p = r.protocol.toLowerCase();
    // Local port: the destination of inbound packets, the source of outbound ones.
    if (lports) parts.push(`${p} ${inbound ? 'dport' : 'sport'} { ${lports.join(', ')} }`);
    if (rports?.length) parts.push(`${p} ${inbound ? 'sport' : 'dport'} { ${rports.join(', ')} }`);
    if (!lports && !rports?.length) parts.push(`meta l4proto ${p}`);
  } else if (r.protocol === 'ICMPv4') {
    const t = r.icmpType?.split(':')[0];
    const names: Record<string, string> = { 0: 'echo-reply', 3: 'destination-unreachable', 8: 'echo-request', 11: 'time-exceeded' };
    parts.push(t && names[t] ? `icmp type ${names[t]}` : 'meta l4proto icmp');
  } else if (r.protocol === 'ICMPv6') {
    const t = r.icmpType?.split(':')[0];
    const names: Record<string, string> = { 1: 'destination-unreachable', 2: 'packet-too-big', 128: 'echo-request', 129: 'echo-reply' };
    parts.push(t && names[t] ? `icmpv6 type ${names[t]}` : 'meta l4proto ipv6-icmp');
  } else if (lports) {
    // Protocol Any with a program: the program's ports, TCP and UDP.
    parts.push(`meta l4proto { tcp, udp } th dport { ${lports.join(', ')} }`);
  }
  return parts.join(' ');
}

/**
 * Compile the firewall into the ruleset the network engine evaluates. Block rules
 * win over allow rules; with the profile off every packet is accepted. Rule
 * comments carry the display names so decisions read like Windows terms. When
 * Group Policy turns off local rule merging, only policy rules count.
 */
export function compileFirewall(host: Host): Ruleset {
  const w = host.win!;
  const profile = activeProfile(host);
  const p = effectiveProfile(host, profile);
  let handle = 1;
  const mk = (text: string, comment: string): Rule => ({ ...parseRuleExpr(text, handle++), comment });
  const chain = (dir: 'Inbound' | 'Outbound') => {
    const rules: Rule[] = [];
    if (p.enabled) {
      rules.push(mk('ct state established,related accept', 'Stateful: replies to allowed connections'));
      rules.push(mk('iif "lo" accept', 'Loopback'));
      // Local rules and the rules Group Policy delivered (both are in the active store).
      const local = p.allowLocalRules === false ? [] : w.firewall.rules;
      const applicable = [...local, ...(w.gp?.rules ?? [])].filter((r) => r.direction === dir && ruleApplies(r, profile));
      for (const r of [...applicable.filter((x) => x.action === 'Block'), ...applicable.filter((x) => x.action === 'Allow')]) {
        const m = ruleMatchText(host, r);
        if (m === null) continue;
        rules.push(mk(`${m} ${r.action === 'Allow' ? 'accept' : 'drop'}`.trim(), r.displayName));
      }
    }
    const dflt = dir === 'Inbound' ? p.defaultInbound : p.defaultOutbound;
    return { name: `${profile}-${dir}`, base: { type: 'filter', hook: dir === 'Inbound' ? ('input' as const) : ('output' as const), priority: 0, policy: !p.enabled || dflt === 'Allow' ? ('accept' as const) : ('drop' as const) }, rules, handle: handle++ };
  };
  return { tables: [{ family: 'inet', name: WF_TABLE, chains: [chain('Inbound'), chain('Outbound')], handle: handle++ }], nextHandle: handle };
}

export function applyFirewall(host: Host): void {
  host.nft = compileFirewall(host);
}

// ---------------------------------------------------------------------------
// Services and network configuration
// ---------------------------------------------------------------------------

function allocPid(host: Host): number {
  host.nextPid += 4 + (host.nextPid % 7);
  return host.nextPid;
}

export type ServiceResult = { ok: true } | { ok: false; error: string };

export function startWinService(world: World, host: Host, name: string, chain: string[] = []): ServiceResult {
  const w = host.win!;
  const s = w.services[name];
  if (!s) return { ok: false, error: 'not found' };
  if (s.status === 'Running') return { ok: true };
  if (s.startType === 'Disabled') {
    winEvent(world, host, 'System', 7000, 'Service Control Manager', `The ${s.displayName} service failed to start due to the following error: \r\nThe service cannot be started, either because it is disabled or because it has no enabled devices associated with it.`, 'Error');
    return { ok: false, error: 'disabled' };
  }
  for (const d of s.dependsOn) {
    if (chain.includes(d)) continue;
    const r = startWinService(world, host, d, [...chain, name]);
    if (!r.ok) {
      winEvent(world, host, 'System', 7001, 'Service Control Manager', `The ${s.displayName} service depends on the ${w.services[d]?.displayName ?? d} service which failed to start because of the following error: \r\nThe service cannot be started, either because it is disabled or because it has no enabled devices associated with it.`, 'Error');
      return { ok: false, error: 'dependency' };
    }
  }
  world.clock += 200;
  s.status = 'Running';
  s.pid = allocPid(host);
  if (name === 'TermService') w.rdpPort = Number(w.registry[RDP_TCP_KEY]?.PortNumber ?? 3389);
  if (name === 'MpsSvc') applyFirewall(host);
  if (name === 'W32Time') timeSync(world, host);
  winEvent(world, host, 'System', 7036, 'Service Control Manager', `The ${s.displayName} service entered the running state.`);
  // Program rules match the owner of a listening socket: recompile when listeners change.
  if (name !== 'MpsSvc') applyFirewall(host);
  return { ok: true };
}

export function stopWinService(world: World, host: Host, name: string): ServiceResult {
  const s = host.win!.services[name];
  if (!s) return { ok: false, error: 'not found' };
  if (s.protected) return { ok: false, error: 'protected' };
  if (s.status === 'Stopped') return { ok: true };
  world.clock += 200;
  s.status = 'Stopped';
  s.pid = null;
  winEvent(world, host, 'System', 7036, 'Service Control Manager', `The ${s.displayName} service entered the stopped state.`);
  applyFirewall(host);
  return { ok: true };
}

/** Apply the adapters' IP settings to the simulator interfaces and routes. */
export function applyAdapters(world: World, host: Host): void {
  host.routes = [];
  host.routes6 = [];
  for (const a of host.win!.adapters) {
    const i = host.ifaces.find((x) => x.name === a.alias);
    if (!i) continue;
    i.up = true;
    i.address = a.address;
    i.prefix = a.prefix;
    i.addrs6 = [{ address: linkLocalFromMac(i.mac), prefix: 64, scope: 'link', origin: 'kernel' }];
    if (a.address && a.prefix !== null) {
      host.routes.push({ dest: networkOf(a.address, a.prefix), dev: a.alias, proto: 'kernel', src: a.address });
      if (a.gateway) host.routes.push({ dest: 'default', via: a.gateway, dev: a.alias, proto: 'static' });
    }
  }
  recomputeL2(world);
}

/** Boot: runtime state rebuilt from the persistent configuration. */
export function bootWindows(world: World, host: Host): void {
  const w = host.win!;
  host.conntrack = [];
  host.nat = [];
  host.neighbors = [];
  host.pmtu = {};
  host.ipForward = false;
  host.ip6Forward = false;
  world.clock += 1000;
  host.bootTime = world.clock;
  host.nextPid = 600;
  w.domainNetwork = false;
  for (const s of Object.values(w.services)) {
    s.status = 'Stopped';
    s.pid = null;
  }
  for (const i of host.ifaces) if (i.name === 'lo') { i.up = true; i.address = '127.0.0.1'; i.prefix = 8; }
  winEvent(world, host, 'System', 6009, 'EventLog', `Microsoft (R) Windows (R) 10.00. ${w.build} Multiprocessor Free.`);
  winEvent(world, host, 'System', 6005, 'EventLog', 'The Event log service was started.');
  applyAdapters(world, host);
  for (const s of Object.values(w.services)) if (s.startType === 'Automatic' || s.startType === 'AutomaticDelayedStart') startWinService(world, host, s.name);
  // TermService is "Manual" but trigger-started when Remote Desktop is enabled.
  // With it come its helpers: Remote Desktop Configuration and the UserMode Port Redirector.
  if (rdpEnabled(host)) for (const n of ['TermService', 'SessionEnv', 'UmRdpService']) if (w.services[n]?.startType === 'Manual') startWinService(world, host, n);
  if (w.services.MpsSvc?.status !== 'Running') applyFirewall(host);
  // Domain membership: a pending join or unjoin takes effect now; then locate a DC
  // (network profile, DNS registration, Netlogon events).
  domainBoot(world, host);
}

/** Resolver configuration of a Windows host (DNS servers and suffix of its adapters). */
export function winResolver(host: Host): { nameservers: string[]; search: string[] } {
  const w = host.win!;
  const ads = w.adapters;
  // The primary DNS suffix (the domain, once joined) comes first in the search list.
  const primary = w.domain ? [w.domain.domain] : [];
  return { nameservers: ads.flatMap((a) => a.dns), search: [...new Set([...primary, ...ads.map((a) => a.dnsSuffix).filter(Boolean)])] };
}

export const WIN_HOSTS_PATH = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
