// Module A (networking fundamentals) tickets: client addressing, gateways,
// router forwarding, resolver configuration, /etc/hosts and socket binding.

import { readFile, writeFile } from '../fs';
import type { World } from '../types';
import { firewallStillRestrictive, script, sessionStillWorks } from './engine';
import type { Goal, Scenario } from './types';

const SSH_GOAL: Goal = { description: 'alice on ws01 can ssh to srv01.corp.lab.', localUser: 'alice', user: 'alice', target: 'srv01.corp.lab', method: 'publickey' };
const WEB_GOAL: Goal = { kind: 'http', description: 'From ws01, "curl -I http://srv01.corp.lab/" returns HTTP 200.', fromHost: 'ws01', fromUser: 'alice', url: 'http://srv01.corp.lab/' };

const BRIEFING = [
  'Office LAN 10.0.10.0/24: ws01 (10.0.10.25), DNS server ns1 (10.0.10.53), router rtr01 (10.0.10.1).',
  'Server network 10.0.20.0/24: srv01.corp.lab (10.0.20.10) behind rtr01 (10.0.20.1). srv01 runs sshd and nginx.',
  'You have a terminal on ws01 as alice (sudo password: ws01-alice) and root consoles on srv01, ns1 and rtr01.',
  'Fixes must survive a reboot (persistent configuration files).',
];

const CANDIDATES = [
  'client-netmask', 'routing-client', 'router-forwarding-disabled', 'routing-server-gateway', 'dns-client-config', 'hosts-file-override',
  'dns-wrong-record', 'listen-loopback', 'web-not-running', 'firewall-drop', 'server-down',
];

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

export const NETWORK_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'net-wrong-mask',
    title: 'Everything outside the office is unreachable',
    difficulty: 'beginner',
    ticket: 'alice: "After I reconfigured my workstation\'s network (we are moving to a bigger address plan), I can still reach the DNS server and printers, but srv01 and everything on the server network says No route to host."',
    briefing: BRIEFING,
    goals: [SSH_GOAL, WEB_GOAL],
    setup(world) {
      edit(world, 'ws01', '/etc/network/interfaces', (s) => s.replace('address 10.0.10.25/24', 'address 10.0.10.25/16'));
      script(world, 'ws01', ['systemctl restart networking']);
      world.clock += 30 * 60_000;
    },
    rootCauses: ['client-netmask'],
    candidates: CANDIDATES,
    feedback: {
      'routing-client': 'The default gateway is still 10.0.10.1 and reachable. Ask instead: does ws01 even USE the gateway for 10.0.20.10? (ip route get 10.0.20.10)',
      'server-down': 'Other machines (e.g. ns1, from its console) can reach srv01. The problem is specific to ws01.',
      'router-forwarding-disabled': 'tcpdump on rtr01 shows nothing from ws01 for 10.0.20.10: ws01 never sends those packets to the router.',
    },
    hints: [
      '"No route to host" can be produced by the client itself. Who sends the "Destination Host Unreachable" in ping\'s output?',
      'Ask the kernel how it would send a packet to 10.0.20.10: ip route get 10.0.20.10. Is there a "via"? Then check the prefix length in ip -4 addr.',
      '/16 makes 10.0.0.0–10.0.255.255 "on-link", so ws01 ARPs for 10.0.20.10 on the office LAN instead of using the router. Set /24 in /etc/network/interfaces (sudo) and restart networking.',
    ],
    explanation: {
      rootCause: 'ws01 was configured with 10.0.10.25/16 instead of /24. Its connected route became 10.0.0.0/16, which includes the server network 10.0.20.0/24.',
      manifestation: 'For 10.0.20.10 the longest matching route is the connected /16, not the default route, so ws01 sends an ARP request for 10.0.20.10 on the office LAN. Nobody there owns that address; after ~3 s the kernel gives up and reports EHOSTUNREACH ("No route to host"). Hosts really on 10.0.10.0/24 keep working, which hides the problem.',
      evidence: 'ip -4 addr shows 10.0.10.25/16; ip route shows "10.0.0.0/16 dev eth0 proto kernel"; ip route get 10.0.20.10 has no "via"; ip neigh shows "10.0.20.10 dev eth0 FAILED"; ping prints "From 10.0.10.25 ... Destination Host Unreachable" (from itself, not from the router).',
      prevention: 'Change address plans for all hosts and routers together, and validate with ip route get to a remote address. A prefix that is too short makes a host skip its gateway; one that is too long makes it send local traffic to the router.',
    },
    solution: [{ host: 'ws01', user: 'root', commands: ["sed -i 's|address 10.0.10.25/16|address 10.0.10.25/24|' /etc/network/interfaces", 'systemctl restart networking', 'ip route get 10.0.20.10'], note: 'As alice: prefix these with sudo.' }],
    constraints: [firewallStillRestrictive()],
    concepts: ['net.cidr', 'net.routing', 'net.arp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'net-wrong-gateway',
    title: 'The gateway that is not there',
    difficulty: 'beginner',
    ticket: 'alice: "My workstation can resolve names and reach ns1, but nothing on other networks. I copied the network settings from the old office template."',
    briefing: [...BRIEFING, 'The old office used 10.0.10.254 as its router address.'],
    goals: [SSH_GOAL],
    setup(world) {
      edit(world, 'ws01', '/etc/network/interfaces', (s) => s.replace('gateway 10.0.10.1', 'gateway 10.0.10.254'));
      script(world, 'ws01', ['systemctl restart networking']);
      world.clock += 20 * 60_000;
    },
    rootCauses: ['routing-client'],
    candidates: CANDIDATES,
    feedback: {
      'client-netmask': 'ip -4 addr shows /24, and ip route get 10.0.20.10 does use a "via": the prefix is fine. Look at which router it uses.',
      'router-forwarding-disabled': 'rtr01 never receives anything from ws01 (tcpdump on rtr01). The question is whether ws01 sends to rtr01 at all.',
    },
    hints: [
      'Off-subnet traffic goes to the default gateway. Which one does ws01 use (ip route), and does that address exist?',
      'Ping the gateway, and look at ip neigh for its address.',
      'The gateway is 10.0.10.254, which does not exist; the router is 10.0.10.1. Fix /etc/network/interfaces (sudo) and restart networking.',
    ],
    explanation: {
      rootCause: 'The default gateway in /etc/network/interfaces was set to 10.0.10.254 (the old office\'s router address). No device on this LAN uses that address.',
      manifestation: 'Every off-subnet packet must first be handed to 10.0.10.254, so ws01 ARPs for it, gets no reply and reports "No route to host" (EHOSTUNREACH) after about 3 s. Local traffic (ns1) does not need the gateway and works, so name resolution succeeds.',
      evidence: 'ip route shows "default via 10.0.10.254"; ip neigh shows "10.0.10.254 dev eth0 FAILED"; ping 10.0.10.254 fails; ping 10.0.10.1 works; tcpdump on ws01 shows unanswered "ARP, Request who-has 10.0.10.254".',
      prevention: 'Use DHCP (or configuration management) for client network settings; when static, verify the gateway with ping and ip neigh after every change.',
    },
    solution: [{ host: 'ws01', user: 'root', commands: ["sed -i 's/gateway 10.0.10.254/gateway 10.0.10.1/' /etc/network/interfaces", 'systemctl restart networking', 'ip route'] }],
    constraints: [firewallStillRestrictive()],
    concepts: ['net.routing', 'net.arp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'net-ip-forward',
    title: 'The router answers, but routes nothing',
    difficulty: 'intermediate',
    ticket: 'Monday: "Since the weekend patching, nobody in the office can reach any server. Pinging the router (10.0.10.1) works fine, and the servers can ping their side of the router (10.0.20.1)."',
    briefing: [...BRIEFING, 'During patching, a hardening script based on a CIS benchmark ran on all Linux machines, including rtr01, and they were rebooted.'],
    goals: [SSH_GOAL, WEB_GOAL],
    setup(world) {
      edit(world, 'rtr01', '/etc/sysctl.d/99-router.conf', (s) => s.replace('net.ipv4.ip_forward=1', '# CIS 3.1.1: IP forwarding disabled\n#net.ipv4.ip_forward=1'));
      script(world, 'rtr01', ['reboot']);
      world.clock += 36 * 3600_000;
    },
    rootCauses: ['router-forwarding-disabled'],
    candidates: CANDIDATES,
    feedback: {
      'routing-client': 'ws01\'s route points at 10.0.10.1, and 10.0.10.1 answers (ping, ARP). The question is what rtr01 does with packets that are not for itself.',
      'firewall-drop': 'A drop would produce a timeout. Here an ICMP "host unreachable" comes back immediately from 10.0.10.1. And rtr01\'s forward chain policy is accept.',
      'routing-server-gateway': 'tcpdump on srv01 shows nothing at all from the office: packets never get that far.',
    },
    hints: [
      'Read ping\'s output carefully: WHO reports "Destination Host Unreachable"? Then capture on rtr01: do packets arrive on eth0? Do they leave on eth1?',
      'A Linux box is only a router if the kernel is allowed to forward. Check sysctl net.ipv4.ip_forward on rtr01, and where it is configured persistently.',
      'The hardening script commented out net.ipv4.ip_forward=1 in /etc/sysctl.d/99-router.conf. Restore it and apply it (sysctl -w net.ipv4.ip_forward=1) so it works now and after reboot.',
    ],
    explanation: {
      rootCause: 'A CIS hardening script commented out "net.ipv4.ip_forward=1" on rtr01 (correct for servers, wrong for a router). After the reboot the kernel no longer forwards.',
      manifestation: 'rtr01 still owns its own addresses, so pings to 10.0.10.1 and ARP work. Packets addressed to other networks fail the kernel\'s input route lookup, and rtr01 answers each with ICMP host unreachable, so clients print "No route to host" immediately.',
      evidence: 'ping srv01 from ws01: "From 10.0.10.1 icmp_seq=1 Destination Host Unreachable"; on rtr01: sysctl net.ipv4.ip_forward = 0, tcpdump on eth0 shows the packets and the ICMP replies, nothing on eth1; /etc/sysctl.d/99-router.conf has the setting commented out.',
      prevention: 'Apply hardening profiles per role (a router is not a server), review automated changes, and test cross-network reachability after maintenance.',
    },
    solution: [{ host: 'rtr01', commands: ["sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.d/99-router.conf", 'sysctl -w net.ipv4.ip_forward=1', 'sysctl net.ipv4.ip_forward'] }],
    constraints: [firewallStillRestrictive()],
    concepts: ['net.routing', 'net.icmp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'net-dns-resolvconf',
    title: 'Names do not work, addresses do',
    difficulty: 'beginner',
    ticket: 'alice: "ssh srv01.corp.lab says Temporary failure in name resolution. But ssh 10.0.20.10 works! Other people in the office have no problem."',
    briefing: [...BRIEFING, 'alice edited her resolver configuration by hand yesterday while testing a VPN client.'],
    goals: [SSH_GOAL],
    setup(world) {
      edit(world, 'ws01', '/etc/resolv.conf', (s) => s.replace('nameserver 10.0.10.53', 'nameserver 10.0.10.35'));
      world.clock += 18 * 3600_000;
    },
    rootCauses: ['dns-client-config'],
    candidates: CANDIDATES,
    feedback: {
      'dns-wrong-record': 'A wrong record would resolve to a wrong address. Here nothing resolves at all, and dig @10.0.10.53 srv01.corp.lab returns the right answer.',
      'hosts-file-override': 'getent hosts fails completely; nothing in /etc/hosts matches.',
    },
    hints: [
      'Only alice is affected, and only names. Which file tells her machine which DNS server to ask?',
      'Compare cat /etc/resolv.conf with the known DNS server, and compare "dig srv01.corp.lab" with "dig @10.0.10.53 srv01.corp.lab".',
      'resolv.conf points at 10.0.10.35 (digits swapped). Fix it with sudo (sudo nano /etc/resolv.conf or sed).',
    ],
    explanation: {
      rootCause: '/etc/resolv.conf on ws01 lists 10.0.10.35 as nameserver: a typo for 10.0.10.53.',
      manifestation: 'Every lookup is sent to 10.0.10.35. That address is on the local subnet but unused, so ARP fails and each query fails; glibc gives up with EAI_AGAIN, "Temporary failure in name resolution". Connecting by IP does not use DNS and works.',
      evidence: 'cat /etc/resolv.conf shows nameserver 10.0.10.35; dig srv01.corp.lab reports communication errors to 10.0.10.35; dig @10.0.10.53 srv01.corp.lab answers 10.0.20.10; ip neigh shows 10.0.10.35 FAILED.',
      prevention: 'Manage resolver settings through DHCP/NetworkManager/systemd-resolved instead of editing resolv.conf by hand; when debugging, always note WHICH server answered (dig\'s SERVER line).',
    },
    solution: [{ host: 'ws01', user: 'root', commands: ["sed -i 's/nameserver 10.0.10.35/nameserver 10.0.10.53/' /etc/resolv.conf", 'getent hosts srv01.corp.lab'] }],
    constraints: [firewallStillRestrictive()],
    concepts: ['dns.resolution', 'net.arp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'net-hosts-override',
    title: 'DNS is right, the connection still goes elsewhere',
    difficulty: 'intermediate',
    ticket: 'alice: "ssh srv01.corp.lab fails with No route to host after a few seconds. I checked DNS with dig and it returns 10.0.20.10, which is correct!"',
    briefing: [...BRIEFING, 'Last month ws01 was used to test a server migration.'],
    goals: [SSH_GOAL, WEB_GOAL],
    setup(world) {
      edit(world, 'ws01', '/etc/hosts', (s) => s + '\n# migration test MIG-12\n10.0.20.99\tsrv01.corp.lab srv01\n', 30 * 24 * 3600_000);
      world.clock += 3600_000;
    },
    rootCauses: ['hosts-file-override'],
    candidates: CANDIDATES,
    feedback: {
      'dns-wrong-record': 'dig (which only asks DNS) returns the correct 10.0.20.10. Something ELSE answers for ssh.',
      'server-down': 'srv01 answers at 10.0.20.10 (ping 10.0.20.10 works). Which address does ssh actually try? (ssh -v)',
      'dns-client-config': 'DNS queries succeed and return the right answer.',
    },
    hints: [
      'dig talks to DNS directly. ssh asks the system resolver (NSS). Do they agree? Compare dig with getent hosts.',
      'ssh -v shows the address it connects to. Where could that address come from if not DNS? Look at /etc/nsswitch.conf ("hosts: files dns").',
      'An old /etc/hosts entry maps srv01.corp.lab to 10.0.20.99. Remove it (sudo).',
    ],
    explanation: {
      rootCause: 'A leftover /etc/hosts line from a migration test (MIG-12) maps srv01.corp.lab to 10.0.20.99.',
      manifestation: 'NSS consults /etc/hosts before DNS ("hosts: files dns"), so ssh connects to 10.0.20.99. The router cannot ARP that address and returns ICMP host unreachable after ~3 s: "No route to host". dig bypasses NSS, so it shows the correct DNS record and misleads the investigation.',
      evidence: 'getent hosts srv01.corp.lab → 10.0.20.99 while dig +short → 10.0.20.10; ssh -v "Connecting to srv01.corp.lab [10.0.20.99]"; grep srv01 /etc/hosts.',
      prevention: 'Avoid static host entries for managed names; if needed for tests, mark them with a ticket and remove them afterwards. Use getent (not dig) to see what applications resolve.',
    },
    solution: [{ host: 'ws01', user: 'root', commands: ["sed -i '/10.0.20.99/d' /etc/hosts", 'getent hosts srv01.corp.lab'] }],
    constraints: [firewallStillRestrictive()],
    concepts: ['dns.resolution', 'net.arp'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'net-nginx-loopback',
    title: 'Works on the server, refused everywhere else',
    difficulty: 'intermediate',
    ticket: 'Web team: "After preparing srv01 for a reverse proxy, the intranet is refused from every client. On srv01 itself, curl http://localhost works perfectly, and the firewall was not touched."',
    briefing: [...BRIEFING, 'The plan (not yet implemented) is to put a reverse proxy in front of nginx later.'],
    goals: [WEB_GOAL],
    setup(world) {
      edit(world, 'srv01', '/etc/nginx/nginx.conf', (s) => s.replace('listen 80 default_server;', 'listen 127.0.0.1:80 default_server;  # behind proxy (WEB-31)').replace('        listen [::]:80 default_server;\n', ''));
      script(world, 'srv01', ['systemctl reload nginx']);
      world.clock += 4 * 3600_000;
    },
    rootCauses: ['listen-loopback'],
    candidates: CANDIDATES,
    feedback: {
      'web-not-running': 'nginx is active and curl http://localhost on srv01 works. The question is WHICH addresses it accepts connections on.',
      'firewall-drop': 'The client gets an immediate refusal (RST), not a timeout; srv01\'s firewall accepts tcp/80.',
    },
    hints: [
      'Local works, remote refused, no firewall change. A socket listens on an address AND a port. Which address does nginx listen on?',
      'ss -tlnp on srv01: compare the Local Address of nginx with sshd\'s 0.0.0.0:22.',
      'nginx listens on 127.0.0.1:80 only. Change the listen directive back to "listen 80 default_server;", test with nginx -t, and reload.',
    ],
    explanation: {
      rootCause: 'nginx.conf was changed to "listen 127.0.0.1:80" in preparation for a reverse proxy that does not exist yet.',
      manifestation: 'nginx accepts connections only on the loopback address. A SYN to 10.0.20.10:80 finds no matching socket, so srv01\'s kernel answers RST and clients report "Couldn\'t connect to server". curl http://localhost on the server matches the loopback socket and works.',
      evidence: 'ss -tlnp shows "127.0.0.1:80 ... nginx" (no 0.0.0.0:80); nginx.conf contains "listen 127.0.0.1:80"; the nft counter for tcp dport 80 increases (the firewall accepts the SYN).',
      prevention: 'Change bind addresses only when the component that should connect is in place; test from a client network, not only from the server.',
    },
    solution: [{ host: 'srv01', commands: ["sed -i 's|listen 127.0.0.1:80 default_server;  # behind proxy (WEB-31)|listen 80 default_server;|' /etc/nginx/nginx.conf", 'nginx -t', 'systemctl reload nginx', 'ss -tlnp'] }],
    constraints: [firewallStillRestrictive(), sessionStillWorks(SSH_GOAL, 'ssh-still-works', 'SSH to srv01 must keep working.')],
    concepts: ['svc.listening', 'tcp.handshake'],
  },
];
