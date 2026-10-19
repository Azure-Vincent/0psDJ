// Helpers for constructing simulated Debian hosts with a realistic base filesystem.

import { emptyRuleset } from '../config/nft';
import { mkdir, writeFile } from '../fs';
import type { Host, ServiceRuntime, UserAccount, World } from '../types';

export const DEBIAN_MOTD = `
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
`;

export const DEBIAN_DEFAULT_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter;
	}
	chain forward {
		type filter hook forward priority filter;
	}
	chain output {
		type filter hook output priority filter;
	}
}
`;

export interface HostSpec {
  id: string;
  hostname: string;
  domain: string;
  role: string;
  kind?: 'linux' | 'router' | 'switch';
  osName?: string;
  /** segment: fixed broadcast domain; null for NICs cabled to the switch (derived from its VLAN config). */
  ifaces: { name: string; mac: string; segment: string | null }[];
  services: string[];
}

export function newWorld(name: string, startIso: string): World {
  return { name, hosts: {}, segments: {}, clock: Date.parse(startIso), counter: 1000 };
}

function svc(enabled = true): ServiceRuntime {
  return { state: 'inactive', enabled, since: 0, pid: null, loaded: null, result: 'success' };
}

export function createHost(world: World, spec: HostSpec): Host {
  const t = world.clock;
  const host: Host = {
    id: spec.id,
    hostname: spec.hostname,
    domain: spec.domain,
    osName: spec.osName ?? 'Debian GNU/Linux 12 (bookworm)',
    kind: spec.kind ?? 'linux',
    role: spec.role,
    users: {},
    fs: {},
    ifaces: [
      { name: 'lo', mac: '00:00:00:00:00:00', segment: null, address: '127.0.0.1', prefix: 8, up: true, addrs6: [{ address: '::1', prefix: 128, scope: 'host', origin: 'kernel' }] },
      ...spec.ifaces.map((i) => ({ ...i, address: null, prefix: null, up: false, staticSegment: i.segment, addrs6: [] })),
    ],
    routes: [],
    routes6: [],
    neighbors: [],
    nft: emptyRuleset(),
    conntrack: [],
    nat: [],
    ipForward: false,
    ip6Forward: false,
    bridge: spec.kind === 'switch' ? null : undefined,
    services: {},
    journal: [],
    capture: [],
    nextPid: 400,
    bootTime: t,
  };
  for (const s of ['networking', ...spec.services]) host.services[s] = svc(true);
  for (const d of ['/', '/bin', '/etc', '/etc/ssh', '/etc/ssh/sshd_config.d', '/etc/network', '/etc/sysctl.d', '/etc/nginx', '/etc/dhcp', '/etc/default', '/var/lib', '/var/lib/dhcp', '/home', '/root', '/usr', '/usr/bin', '/usr/sbin', '/var', '/var/log', '/tmp']) {
    mkdir(host, d, t, d === '/root' ? { mode: 0o700 } : d === '/tmp' ? { mode: 0o1777 } : undefined);
  }
  for (const b of ['/bin/bash', '/bin/sh', '/usr/sbin/nologin', '/bin/false', '/usr/bin/ssh', '/usr/sbin/sshd']) {
    writeFile(host, b, '', t, { mode: 0o755 });
  }
  writeFile(host, '/etc/hostname', `${spec.hostname}\n`, t);
  writeFile(host, '/etc/hosts', `127.0.0.1\tlocalhost\n127.0.1.1\t${spec.hostname}.${spec.domain}\t${spec.hostname}\n\n# The following lines are desirable for IPv6 capable hosts\n::1     localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n`, t);
  writeFile(host, '/etc/motd', DEBIAN_MOTD, t);
  writeFile(host, '/etc/nftables.conf', DEBIAN_DEFAULT_NFT, t, { mode: 0o755 });
  writeFile(host, '/etc/nsswitch.conf', 'passwd:         files systemd\ngroup:          files systemd\nshadow:         files\nhosts:          files dns\nnetworks:       files\n', t);
  addUser(host, { name: 'root', uid: 0, gid: 0, primaryGroup: 'root', groups: [], home: '/root', shell: '/bin/bash', gecos: 'root', password: 'r00t-console' }, t, false);
  world.hosts[host.id] = host;
  return host;
}

export function addUser(host: Host, u: UserAccount, time: number, createHome = true): void {
  host.users[u.name] = u;
  if (createHome && !host.fs[u.home]) {
    mkdir(host, u.home, time, { mode: 0o700, owner: u.name, group: u.primaryGroup });
    writeFile(host, `${u.home}/.bashrc`, '# ~/.bashrc: executed by bash(1) for non-login shells.\n', time, { owner: u.name, group: u.primaryGroup });
    writeFile(host, `${u.home}/.profile`, '# ~/.profile: executed by the command interpreter for login shells.\n', time, { owner: u.name, group: u.primaryGroup });
  }
}

export function staticInterfaces(ifaces: { name: string; address: string; gateway?: string }[]): string {
  const lines = [
    '# This file describes the network interfaces available on your system',
    '# and how to activate them. For more information, see interfaces(5).',
    '',
    'source /etc/network/interfaces.d/*',
    '',
    '# The loopback network interface',
    'auto lo',
    'iface lo inet loopback',
  ];
  for (const i of ifaces) {
    lines.push('', `# ${i.name}`, `auto ${i.name}`, `iface ${i.name} inet static`, `    address ${i.address}`);
    if (i.gateway) lines.push(`    gateway ${i.gateway}`);
  }
  return lines.join('\n') + '\n';
}

/** Verify every file's parent directory exists (catches lab definitions that would break shell writes). */
export function missingParents(host: Host): string[] {
  return Object.keys(host.fs).filter((p) => p !== '/' && !host.fs[p.slice(0, p.lastIndexOf('/')) || '/']);
}
