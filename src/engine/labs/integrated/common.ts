// Building blocks shared by the integrated labs: request-path hops and checks
// that run real commands on a copy of the lab.

import { mkdir, writeFile } from '../../fs';
import { addUser, createHost, staticInterfaces } from '../../lab/builder';
import { TIMESYNCD_CONF } from '../../lab/krbLab';
import { installRsyslog } from '../../lab/logLab';
import { trustCorpRoot } from '../../lab/pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys, SW01_INTERFACES } from '../../lab/sshLab';
import { recomputeL2 } from '../../sim/l2';
import { bootHost } from '../../sim/services';
import { script } from '../../scenarios/engine';
import type { Host, World } from '../../types';
import { NO, OK, probe } from '../engine';
import type { LabCheck, PathNode } from '../types';

/** The evidence a probe shows: the prompt, the command and (the end of) its output. */
export function evidence(host: string, user: string, command: string, output: string, code: number): string {
  const lines = output.split('\n').filter((l) => l.trim() !== '');
  const shown = lines.length > 12 ? [...lines.slice(0, 4), `… (${lines.length - 8} more lines)`, ...lines.slice(-4)] : lines;
  return [`${user}@${host}${user === 'root' || user === 'Administrator' ? '#' : '$'} ${command}`, ...shown, ...(code !== 0 ? [`(exit status ${code})`] : [])].join('\n');
}

/** A hop on a request path: OK when the command's output passes the test. */
export function hop(id: string, label: string, role: string, host: string, user: string, command: string, test: (out: string, code: number) => boolean): PathNode {
  return {
    id, label, role, host,
    probe(world: World) {
      const r = probe(world, host, user, command);
      return { ok: test(r.output, r.code), evidence: evidence(host, user, command, r.output, r.code) };
    },
  };
}

/** The host's default gateway (from its routing table) answers a ping: the hop users depend on, whatever the files say. */
export function gatewayHop(host: string, user: string): PathNode {
  return {
    id: 'gateway', label: 'Default gateway answers', role: 'The router named by the default route in the routing table (from DHCP or the configuration).', host,
    probe(world: World) {
      const r = probe(world, host, user, 'ip route');
      const gw = /^default via (\S+)/m.exec(r.output)?.[1];
      const ev = evidence(host, user, 'ip route', r.output, r.code);
      if (!gw) return { ok: false, evidence: `${ev}\n(no default route)` };
      const p = probe(world, host, user, `ping -c 1 -W 2 ${gw}`);
      return { ok: p.code === 0, evidence: `${ev}\n${evidence(host, user, `ping -c 1 -W 2 ${gw}`, p.output, p.code)}` };
    },
  };
}

/**
 * A check that runs one command: fail(out, code) returns the failure detail,
 * or null when the requirement holds; pass is the detail shown on success.
 */
export function cmdCheck(id: string, description: string, host: string, user: string, command: string, fail: (out: string, code: number) => string | null, pass: string): LabCheck {
  return {
    id, description,
    check(world: World) {
      const r = probe(world, host, user, command);
      const f = fail(r.output, r.code);
      return f ? NO(`${f}\n${evidence(host, user, command, r.output, r.code)}`) : OK(pass);
    },
  };
}

/** The last line of a command's output (for short failure messages). */
export const lastLine = (s: string) => s.trim().split('\n').pop() ?? '';

// ---------------------------------------------------------------------------
// A new Debian server cabled to sw01 (VLAN 20), as Lab 9 adds web02.
// ---------------------------------------------------------------------------


export interface NewServer { id: string; ip: string; port: string; mac: string; portMac: string; alias: string; role: string; services: string[]; nft: string; alicePassword: string }

/** Create, cable and boot a server on VLAN 20 (no DNS record: adding it is the learner's job). */
export function addServer(world: World, s: NewServer, prepare?: (h: Host, t: number) => void): Host {
  const t = world.clock;
  const sw = world.hosts.sw01;
  sw.ifaces.push({ name: s.port, mac: s.portMac, segment: null, address: null, prefix: null, up: false, staticSegment: null, addrs6: [] });
  const swConf = world.hosts.sw01.fs['/etc/network/interfaces']?.content ?? SW01_INTERFACES;
  writeFile(sw, '/etc/network/interfaces', swConf
    .replace('auto br0\n', `auto ${s.port}\niface ${s.port}\n    alias ${s.alias}\n    bridge-access 20\n\nauto br0\n`)
    .replace(/(bridge-ports .*)\n/, `$1 ${s.port}\n`), t);
  world.links = [...(world.links ?? []), { a: { host: s.id, iface: 'eth0' }, b: { host: 'sw01', iface: s.port } }];
  const h = createHost(world, { id: s.id, hostname: s.id, domain: 'corp.lab', role: s.role, ifaces: [{ name: 'eth0', mac: s.mac, segment: null }], services: s.services });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${s.ip}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', s.nft, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: s.alicePassword }, t);
  prepare?.(h, t);
  recomputeL2(world);
  script(world, 'sw01', ['ifreload -a']);
  bootHost(world, h);
  return h;
}
