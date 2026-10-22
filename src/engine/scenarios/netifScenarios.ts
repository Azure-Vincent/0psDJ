// Interface and virtual-switch tickets: a NIC renamed by a VM migration, and a
// switch port left out of the bridge on sw01.

import { readFile, writeFile } from '../fs';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const WEB: Goal = { kind: 'http', description: 'From ws01, "curl -I http://srv01.corp.lab/" returns HTTP 200.', fromHost: 'ws01', fromUser: 'alice', url: 'http://srv01.corp.lab/' };
const SSH: Goal = { description: 'alice@ws01 can "ssh srv01.corp.lab" with her key.', localUser: 'alice', user: 'alice', target: 'srv01.corp.lab', method: 'publickey' };

const TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'ws01 in the office. sudo password: ws01-alice.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Out-of-band console on srv01 (root): works without the network.' },
  { hostId: 'rtr01', user: 'root', label: 'rtr01 console', banner: 'Console on rtr01 (root), the gateway of every VLAN.' },
  { hostId: 'sw01', user: 'root', label: 'sw01 console', banner: 'Serial console on the switch sw01 (Linux bridge br0 with VLAN filtering, ifupdown2).' },
];

const BRIEFING = [
  'srv01 (10.0.20.10, VLAN 20) is the intranet web and SSH server. It is cabled to port swp6 of sw01, a Linux bridge (br0) with VLAN filtering.',
  'Debian names network interfaces at boot (eth0, or "predictable" names such as ens18 and enp1s0 that depend on the virtual hardware). /etc/network/interfaces must use the names that exist.',
  'Fixes must survive a reboot of every machine. Keep srv01 on its static address and keep VLANs separated.',
];

const CANDIDATES = ['nic-renamed', 'bridge-port-missing', 'vlan-access-wrong', 'routing-server-gateway', 'firewall-drop', 'server-down', 'dns-wrong-record', 'web-not-running'];

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

function srvStaticAddress(): Constraint {
  return {
    id: 'srv01-static', required: true,
    description: 'srv01 must keep its static address 10.0.20.10/24 (DNS, firewall rules and monitoring depend on it).',
    check(world) {
      const ok = /address 10\.0\.20\.10\/24/.test(readFile(world.hosts.srv01, '/etc/network/interfaces') ?? '') && !/inet dhcp/.test(readFile(world.hosts.srv01, '/etc/network/interfaces') ?? '');
      return { id: this.id, ok, required: true, message: ok ? 'srv01 is statically configured with 10.0.20.10/24.' : 'srv01 no longer has its static 10.0.20.10/24 configuration.' };
    },
  };
}

function swp6Vlan20(): Constraint {
  return {
    id: 'swp6-vlan20', required: true,
    description: 'swp6 (srv01) must be an access port in VLAN 20 only, not a trunk carrying other VLANs.',
    check(world) {
      const p = world.hosts.sw01.bridge?.ports.swp6;
      const ok = !!p && p.pvid === 20 && p.vids.length === 1 && p.vids[0] === 20;
      return { id: this.id, ok, required: true, message: ok ? 'swp6 is an access port in VLAN 20.' : 'swp6 is not a VLAN 20 access port (missing from the bridge, or carrying other VLANs).' };
    },
  };
}

export const NETIF_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'netif-renamed-nic',
    title: 'Migrated, and now unreachable',
    difficulty: 'beginner',
    ticket: 'Platform team: "We migrated srv01 from the old VMware cluster to Proxmox last night (CHG-1320). The VM boots fine and the console works, but nobody can reach the intranet or SSH since then. We did not touch the network."',
    briefing: BRIEFING,
    goals: [WEB, SSH],
    terminals: TERMINALS,
    setup(world) {
      world.clock += 3600_000;
      // The new virtual NIC (virtio on Proxmox) gets a predictable name instead of eth0.
      const srv = world.hosts.srv01;
      const nic = srv.ifaces.find((i) => i.name === 'eth0')!;
      nic.name = 'ens18';
      for (const l of world.links ?? []) if (l.a.host === 'srv01' && l.a.iface === 'eth0') l.a.iface = 'ens18';
      bootHost(world, srv);
      world.clock += 8 * 3600_000;
    },
    rootCauses: ['nic-renamed'],
    candidates: CANDIDATES,
    feedback: {
      'bridge-port-missing': 'sw01 still has swp6 in br0 (bridge link show), and the link is up on both ends. srv01 simply has no address on its NIC.',
      'vlan-access-wrong': 'swp6 is still an access port in VLAN 20. The switch is fine; srv01 never configured its interface.',
      'routing-server-gateway': 'srv01 has no route at all because it has no address at all. "ip -br addr" shows the NIC without IPv4.',
      'firewall-drop': 'A firewall drop would leave srv01 with its address; here ARP for 10.0.20.10 fails because nobody owns that address.',
      'server-down': 'The VM is running (console works). It is unreachable because its network interface is unconfigured.',
      'dns-wrong-record': 'srv01.corp.lab still resolves to 10.0.20.10; that address just is not configured anywhere.',
      'web-not-running': 'nginx may well be running on srv01; without an address nobody can reach it.',
    },
    hints: [
      'Use the console: does srv01 have an address and a link? "ip -br link" and "ip -br addr".',
      'The NIC is called ens18 now, not eth0. What does networking.service say? "systemctl status networking" and "journalctl -u networking -b".',
      'Change every "eth0" in /etc/network/interfaces to "ens18" (sed -i \'s/eth0/ens18/g\'), then "systemctl restart networking" and test from ws01.',
    ],
    explanation: {
      rootCause: 'The migration replaced the virtual NIC. On the new hypervisor it is a virtio device that Debian names ens18, but /etc/network/interfaces still configures eth0, which no longer exists.',
      manifestation: 'At boot ifupdown fails with "Cannot find device \\"eth0\\"", networking.service is failed, and ens18 stays DOWN without an address. From the network srv01 looks switched off: rtr01 cannot resolve 10.0.20.10 by ARP, so clients get "Destination Host Unreachable" / "No route to host".',
      evidence: 'srv01 console: "ip -br link" lists lo and ens18 (DOWN), no eth0; "systemctl status networking" failed with "Cannot find device \\"eth0\\""; rtr01: "ip neigh" shows 10.0.20.10 FAILED; sw01: swp6 up and in VLAN 20.',
      prevention: 'Check interface names after hardware, driver or hypervisor changes (part of the migration checklist); configure by MAC address with systemd .link files or match rules (netplan "match: macaddress", NetworkManager) when names may change; keep console access for exactly this case.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's/eth0/ens18/g' /etc/network/interfaces", 'systemctl restart networking', 'ip -br addr'] }],
    constraints: [srvStaticAddress(), firewallStillRestrictive('srv01')],
    concepts: ['net.interfaces', 'svc.systemd'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'netif-bridge-port',
    title: 'Cable fine, link up, server isolated',
    difficulty: 'intermediate',
    ticket: 'Monitoring: "srv01 DOWN (ping, HTTP, SSH) since 06:12." The server team: "srv01 is up, its config has not changed for months, and the link LED is green." The network team upgraded sw01 overnight and restored its configuration from the change template (NET-74).',
    briefing: BRIEFING,
    goals: [WEB, SSH],
    terminals: TERMINALS,
    setup(world) {
      edit(world, 'sw01', '/etc/network/interfaces', (s) => s.replace('bridge-ports swp1 swp2 swp3 swp4 swp5 swp6 swp7 swp8 swp9', 'bridge-ports swp1 swp2 swp3 swp4 swp5 swp7 swp8 swp9'));
      script(world, 'sw01', ['ifreload -a']);
      world.clock += 6 * 3600_000;
    },
    rootCauses: ['bridge-port-missing'],
    candidates: CANDIDATES,
    feedback: {
      'nic-renamed': 'srv01 has eth0 with 10.0.20.10/24 and networking.service is fine. The host side is healthy.',
      'vlan-access-wrong': 'swp6 is not in the wrong VLAN: it is in no VLAN at all, because it is not a bridge member (bridge vlan show does not list it).',
      'routing-server-gateway': 'srv01 has its default route via 10.0.20.1, but cannot even resolve the gateway by ARP: the problem is below routing.',
      'firewall-drop': 'Nothing reaches srv01 at all, not even ARP. Firewalls do not filter ARP.',
      'server-down': 'srv01 is up (console) with a correct address and carrier.',
      'dns-wrong-record': 'The name resolves to the right address; the address is unreachable at layer 2.',
      'web-not-running': 'nginx runs; frames never get from the switch to srv01.',
    },
    hints: [
      'Work up from layer 1. On srv01: link (ip -br link), address, and can it reach its gateway (ping 10.0.20.1, ip neigh)? On rtr01: ip neigh for 10.0.20.10.',
      'Both ends have carrier, but ARP fails in both directions. Look at the switch: "bridge link show" and "bridge vlan show" on sw01. Which port is srv01\'s, and is it there?',
      'swp6 is missing from "bridge-ports" in sw01\'s /etc/network/interfaces, so it is not part of br0. Add it back to the bridge-ports line and run "ifreload -a".',
    ],
    explanation: {
      rootCause: 'The restored switch template lists the bridge members without swp6. The port is up (link LED, carrier) but not attached to br0, so frames from srv01 are not switched anywhere.',
      manifestation: 'srv01 and the router both show their links up and correct addresses, yet ARP between them fails (rtr01: 10.0.20.10 FAILED; srv01: 10.0.20.1 FAILED). Every service on srv01 is unreachable while everything else on VLAN 20 would still work. The usual suspects (cable, server config, firewall) all look fine.',
      evidence: 'sw01: "bridge link show" lists swp1–5 and swp7–9 only; "ip -d link show swp6" has no "master br0" / "bridge_slave"; "bridge vlan show" has no swp6 line. /etc/network/interfaces: bridge-ports without swp6.',
      prevention: 'Diff switch configuration against the last known good version after upgrades and restores; monitor per-port bridge membership and MAC learning (an access port that never learns a MAC is suspicious); generate port lists from an inventory.',
    },
    solution: [{ host: 'sw01', commands: ["sed -i 's/bridge-ports swp1 swp2 swp3 swp4 swp5 swp7 swp8 swp9/bridge-ports swp1 swp2 swp3 swp4 swp5 swp6 swp7 swp8 swp9/' /etc/network/interfaces", 'ifreload -a', 'bridge link show'] }],
    constraints: [swp6Vlan20(), srvStaticAddress()],
    concepts: ['net.interfaces', 'net.vlan', 'net.arp'],
  },
];
