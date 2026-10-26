import type { World } from '../types';

export type ConceptId =
  | 'dns.resolution' | 'dns.zone' | 'net.arp' | 'net.routing' | 'net.icmp' | 'tcp.handshake'
  | 'fw.stateful' | 'fw.persistence' | 'svc.systemd' | 'svc.listening' | 'ssh.kex' | 'ssh.hostkeys'
  | 'ssh.userauth' | 'ssh.authorized-keys' | 'linux.permissions' | 'ssh.config' | 'ssh.authz' | 'logs.journal'
  | 'net.cidr' | 'fw.path' | 'net.dhcp' | 'net.nat' | 'net.vlan' | 'net.ipv6' | 'net.ndp'
  | 'linux.fs' | 'net.ops' | 'ops.recovery' | 'win.services' | 'win.rdp' | 'ad.dns' | 'ad.kerberos' | 'ad.gpo'
  | 'docker.lifecycle' | 'docker.networking' | 'pfsense.rules' | 'pfsense.nat' | 'tls.pki' | 'net.mtu' | 'net.interfaces' | 'web.proxy' | 'ntp.sync' | 'logs.central' | 'files.nfs' | 'files.smb';

export type CauseCategory = 'Name resolution' | 'Network path' | 'Firewall' | 'Service' | 'Configuration' | 'Authentication' | 'Authorization' | 'Permissions' | 'Client' | 'Cryptography' | 'Persistence';

export interface Cause {
  id: string;
  title: string;
  category: CauseCategory;
  /** What the evidence looks like when this IS the cause. */
  signature: string;
  /** How to confirm or rule it out. */
  check: string;
  concept: ConceptId;
}

/** An SSH login from ws01 (the default goal kind). */
export interface SshGoal {
  kind?: 'ssh';
  description: string;
  localUser: string;
  user: string;
  target: string;
  method: 'publickey' | 'password' | 'any';
}

/** An HTTP request (curl -I) from a host must return 200. */
export interface HttpGoal {
  kind: 'http';
  description: string;
  fromHost: string;
  fromUser: string;
  url: string;
  /** Extra curl options, e.g. "-6" to require IPv6. */
  curlFlags?: string;
  /** Download the whole body (GET) instead of only the headers (HEAD). */
  download?: boolean;
}

/** Name resolution (getent hosts) on a host must return the expected address. */
export interface ResolveGoal {
  kind: 'resolve';
  description: string;
  fromHost: string;
  name: string;
  expect: string;
}

/** Kerberos: kinit with the user's password on a host; optionally an SSH login that may use only the ticket. */
export interface KerberosGoal {
  kind: 'kerberos';
  description: string;
  fromHost: string;
  localUser: string;
  password: string;
  /** ssh with gssapi-with-mic only (no keys, no password) to this host must log in. */
  sshTarget?: string;
}

/** Remote Desktop: xfreerdp from a Linux host must log the user on to a Windows host. */
export interface RdpGoal {
  kind: 'rdp';
  description: string;
  fromHost: string;
  localUser: string;
  target: string;
  user: string;
  password: string;
}

/**
 * A competition scoring engine's SSH check: a Go client logs in once with a
 * password (no keys, host key ignored) and runs a command. Results use Go's
 * error text ("ssh: handshake failed: ssh: unable to authenticate, ...").
 */
export interface ScoredSshGoal {
  kind: 'scored-ssh';
  description: string;
  /** Where the scoring engine's checks come from in the lab. */
  fromHost: string;
  fromUser: string;
  target: string;
  user: string;
  password: string;
  port?: number;
  command?: string;
}

/**
 * The scoring engine's web check: one GET with Go's net/http client (redirects
 * not followed, certificates not verified), then the status code and a
 * pattern in the page are compared with what the white team expects.
 */
export interface ScoredWebGoal {
  kind: 'scored-web';
  description: string;
  fromHost: string;
  url: string;
  /** Default 200. */
  status?: number;
  /** A regular expression the page must contain. */
  content?: string;
}

/** The scoring engine's DNS check: one UDP query to the team's DNS server; the answer must contain the expected address. */
export interface ScoredDnsGoal {
  kind: 'scored-dns';
  description: string;
  fromHost: string;
  server: string;
  name: string;
  expect: string;
}

/** A host's clock must be synchronized by NTP (timedatectl) and within a second of the correct time. */
export interface TimeGoal {
  kind: 'time';
  description: string;
  host: string;
}

/** A message logged on a host (logger, as root) must arrive in the central log server's files. */
export interface SyslogGoal {
  kind: 'syslog';
  description: string;
  fromHost: string;
  /** logger -p FACILITY.LEVEL (default user.notice). */
  priority?: string;
  /** Where the message must appear on log01 (a file path; the tag is used as the program name). */
  server: string;
  path: string;
}

/** Commands run in order (each as its user, in a fresh shell); the last one must succeed and its output match. */
export interface CommandGoal {
  kind: 'command';
  description: string;
  steps: { host: string; user: string; command: string }[];
  /** A regular expression the last command's output must match. */
  expect?: string;
}

export type Goal = SshGoal | HttpGoal | ResolveGoal | KerberosGoal | RdpGoal | ScoredSshGoal | ScoredWebGoal | ScoredDnsGoal | TimeGoal | SyslogGoal | CommandGoal;

export interface ConstraintResult {
  id: string;
  ok: boolean;
  required: boolean;
  message: string;
}

export interface Constraint {
  id: string;
  required: boolean;
  description: string;
  check(world: World): ConstraintResult;
}

export interface Scenario {
  id: string;
  title: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  /** The ticket as a user/colleague would report it. */
  ticket: string;
  /** Environment facts given to the student up front. */
  briefing: string[];
  goals: Goal[];
  setup(world: World): void;
  rootCauses: string[];
  /** Causes that are not wrong to include (symptom-level or contributing), with an explanation. */
  acceptable?: Record<string, string>;
  /** Causes offered in the diagnosis form. */
  candidates: string[];
  /** Scenario-specific feedback when a candidate is selected wrongly (overrides the generic signature text). */
  feedback?: Record<string, string>;
  /** Local user of the ws01 terminal (defaults to alice). */
  clientUser?: string;
  /** Terminals offered in the workspace (default: ws01 + consoles on srv01, ns1, rtr01). */
  terminals?: { hostId: string; user: string; label: string; banner?: string; kind?: 'terminal' | 'pfweb'; fromHost?: string }[];
  hints: string[];
  /** Reference repair, shown after the scenario is resolved or revealed, and used by automated tests. */
  solution: { host: string; user?: string; commands: string[]; note?: string }[];
  explanation: { rootCause: string; manifestation: string; evidence: string; prevention: string };
  constraints: Constraint[];
  concepts: ConceptId[];
}
