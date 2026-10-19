import type { World } from '../types';

export type ConceptId =
  | 'dns.resolution' | 'dns.zone' | 'net.arp' | 'net.routing' | 'net.icmp' | 'tcp.handshake'
  | 'fw.stateful' | 'fw.persistence' | 'svc.systemd' | 'svc.listening' | 'ssh.kex' | 'ssh.hostkeys'
  | 'ssh.userauth' | 'ssh.authorized-keys' | 'linux.permissions' | 'ssh.config' | 'ssh.authz' | 'logs.journal'
  | 'net.cidr' | 'fw.path' | 'net.dhcp' | 'net.nat' | 'net.vlan' | 'net.ipv6' | 'net.ndp';

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
}

/** Name resolution (getent hosts) on a host must return the expected address. */
export interface ResolveGoal {
  kind: 'resolve';
  description: string;
  fromHost: string;
  name: string;
  expect: string;
}

export type Goal = SshGoal | HttpGoal | ResolveGoal;

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
  terminals?: { hostId: string; user: string; label: string; banner?: string }[];
  hints: string[];
  /** Reference repair, shown after the scenario is resolved or revealed, and used by automated tests. */
  solution: { host: string; user?: string; commands: string[]; note?: string }[];
  explanation: { rootCause: string; manifestation: string; evidence: string; prevention: string };
  constraints: Constraint[];
  concepts: ConceptId[];
}
