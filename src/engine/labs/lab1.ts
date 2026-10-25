// Lab 1: Basic Linux Server. Build a freshly installed Debian server (srv02)
// into a production intranet server: switch port, static address, DNS,
// SSH keys and hardening, a default-deny firewall, a web page, and a reboot test.

import { parseInterfaces } from '../config/netconf';
import { evaluate } from '../config/nft';
import { readFile } from '../fs';
import { aliceKey } from '../lab/sshLab';
import { checkGoal } from '../scenarios/engine';
import { runSsh } from '../sim/ssh';
import type { NamedLoaded, SshdLoaded } from '../sim/services';
import type { World } from '../types';
import { probe } from './engine';
import { buildLab1World, SRV02_PASSWORD } from './lab1World';
import type { GuidedLab, LabCheck } from './types';

const OK = (detail: string) => ({ ok: true, detail });
const NO = (detail: string) => ({ ok: false, detail });

function swConfig(world: World) {
  return parseInterfaces(readFile(world.hosts.sw01, '/etc/network/interfaces') ?? '').ifaces;
}

function srv02Config(world: World) {
  return parseInterfaces(readFile(world.hosts.srv02, '/etc/network/interfaces') ?? '');
}

function fwVerdict(world: World, src: string, dport: number): string {
  const h = world.hosts.srv02;
  return evaluate(h.nft, 'input', { src, dst: '10.0.20.20', proto: 'tcp', dport, sport: 50000, iif: 'eth0', ctState: 'new', len: 60, tcpFlags: ['syn'] }).verdict;
}

const ALICE_KEY_LOGIN = { description: 'alice@ws01 logs in to srv02.corp.lab with her key', localUser: 'alice', user: 'alice', target: 'srv02.corp.lab', method: 'publickey' as const };

// ---------------------------------------------------------------- checks

const switchFile: LabCheck = {
  id: 'sw-config', description: 'sw01: swp10 is in bridge-ports and configured as an access port in VLAN 20 in /etc/network/interfaces',
  check(w) {
    const ifs = swConfig(w);
    const br = ifs.find((i) => i.options['bridge-ports']);
    const port = ifs.find((i) => i.name === 'swp10');
    if (!br?.options['bridge-ports'].split(/\s+/).includes('swp10')) return NO('swp10 is not listed in "bridge-ports" of br0.');
    if (!port) return NO('No "iface swp10" stanza.');
    if (port.options['bridge-access'] !== '20') return NO(`swp10 has ${port.options['bridge-access'] ? `bridge-access ${port.options['bridge-access']}` : 'no bridge-access line'}; VLAN 20 is the server VLAN.`);
    if (!port.auto) return NO('swp10 has no "auto swp10" line, so ifupdown2 will not bring it up.');
    return OK('auto swp10 / bridge-access 20, and swp10 in bridge-ports.');
  },
};

const switchRunning: LabCheck = {
  id: 'sw-running', description: 'sw01: swp10 is a bridge member with PVID 20, untagged, carrying only VLAN 20 (running state)',
  check(w) {
    const p = w.hosts.sw01.bridge?.ports.swp10;
    if (!p) return NO('swp10 is not a member of br0 (bridge link). Apply the configuration with "ifreload -a".');
    const ok = p.pvid === 20 && p.vids.length === 1 && p.vids[0] === 20 && p.untagged.includes(20);
    return ok ? OK('bridge vlan show: swp10 20 PVID Egress Untagged.') : NO(`swp10 carries VLAN(s) ${p.vids.join(', ')} with PVID ${p.pvid ?? 'none'}.`);
  },
};

const srvCarrier: LabCheck = {
  id: 'srv-carrier', description: 'srv02: eth0 has a link (carrier)',
  check(w) {
    const out = probe(w, 'srv02', 'root', 'cat /sys/class/net/eth0/carrier').output.trim();
    return out === '1' ? OK('/sys/class/net/eth0/carrier = 1 (LOWER_UP).') : NO(`/sys/class/net/eth0/carrier: ${out || 'no value'}.`);
  },
};

const staticFile: LabCheck = {
  id: 'ip-config', description: 'srv02: /etc/network/interfaces configures eth0 statically with 10.0.20.20/24 and gateway 10.0.20.1, brought up at boot',
  check(w) {
    const { ifaces, errors } = srv02Config(w);
    if (errors.length) return NO(`Syntax problems: ${errors.join('; ')}`);
    const v4 = ifaces.filter((i) => i.name === 'eth0' && i.family === 'inet');
    if (v4.some((i) => i.method === 'dhcp')) return NO('eth0 is still "inet dhcp": there is no DHCP server on the server VLAN, and servers need fixed addresses.');
    const s = v4.find((i) => i.method === 'static');
    if (!s) return NO('No "iface eth0 inet static" stanza.');
    if (s.address !== '10.0.20.20' || s.prefix !== 24) return NO(`address is ${s.address ?? 'missing'}/${s.prefix ?? '?'}; expected 10.0.20.20/24.`);
    if (s.gateway !== '10.0.20.1') return NO(`gateway is ${s.gateway ?? 'missing'}; expected 10.0.20.1 (rtr01 on VLAN 20).`);
    if (!s.auto && !/^\s*allow-hotplug\s+.*\beth0\b/m.test(readFile(w.hosts.srv02, '/etc/network/interfaces') ?? '')) return NO('eth0 has no "auto eth0" (or allow-hotplug) line: it would stay down after a reboot.');
    return OK('iface eth0 inet static, address 10.0.20.20/24, gateway 10.0.20.1.');
  },
};

const staticRunning: LabCheck = {
  id: 'ip-running', description: 'srv02: eth0 has 10.0.20.20/24 and the default route via 10.0.20.1 (running state)',
  check(w) {
    const addr = probe(w, 'srv02', 'root', 'ip -br -4 addr show eth0').output;
    const route = probe(w, 'srv02', 'root', 'ip route').output;
    if (!/10\.0\.20\.20\/24/.test(addr)) return NO(`ip -br addr: ${addr.trim() || 'no IPv4 address'}. Apply the configuration (systemctl restart networking).`);
    if (!/^default via 10\.0\.20\.1 dev eth0/m.test(route)) return NO(`No default route via 10.0.20.1 (ip route: ${route.split('\n')[0] || 'empty'}).`);
    return OK('10.0.20.20/24 on eth0; default via 10.0.20.1.');
  },
};

const gatewayPing: LabCheck = {
  id: 'ip-gateway', description: 'srv02 reaches its gateway (ping 10.0.20.1)',
  check(w) {
    const r = probe(w, 'srv02', 'root', 'ping -c 1 -W 2 10.0.20.1');
    return /1 received/.test(r.output) ? OK('64 bytes from 10.0.20.1.') : NO(r.output.split('\n').find((l) => /From|unreachable|100% packet loss/.test(l)) ?? 'no reply');
  },
};

const officePing: LabCheck = {
  id: 'ip-from-office', description: 'ws01 (office) reaches srv02 (ping 10.0.20.20), so monitoring works across the router',
  check(w) {
    const r = probe(w, 'ws01', 'alice', 'ping -c 1 -W 2 10.0.20.20');
    return /1 received/.test(r.output) ? OK('64 bytes from 10.0.20.20.') : NO(r.output.split('\n').find((l) => /From|unreachable|100% packet loss/.test(l)) ?? 'no reply');
  },
};

const resolvFile: LabCheck = {
  id: 'dns-client', description: 'srv02: /etc/resolv.conf uses ns1 (10.0.10.53) with search domain corp.lab',
  check(w) {
    const rc = readFile(w.hosts.srv02, '/etc/resolv.conf') ?? '';
    if (!/^\s*nameserver\s+10\.0\.10\.53\s*$/m.test(rc)) return NO('No "nameserver 10.0.10.53" line.');
    if (!/^\s*(search|domain)\s+.*\bcorp\.lab\b/m.test(rc)) return NO('No "search corp.lab" line: short names such as "srv01" will not resolve.');
    return OK('nameserver 10.0.10.53, search corp.lab.');
  },
};

const resolvWorks: LabCheck = {
  id: 'dns-client-works', description: 'srv02 resolves the short name "srv01" to 10.0.20.10',
  check(w) {
    const r = probe(w, 'srv02', 'root', 'getent hosts srv01');
    return /^10\.0\.20\.10\s/.test(r.output) ? OK(r.output.trim()) : NO(`getent hosts srv01: ${r.output.trim() || `no answer (exit ${r.code})`}`);
  },
};

const zoneFile: LabCheck = {
  id: 'dns-record', description: 'ns1: the corp.lab zone file has "srv02 A 10.0.20.20" and a higher serial than 2026101901',
  check(w) {
    const z = readFile(w.hosts.ns1, '/etc/bind/db.corp.lab') ?? '';
    if (!/^srv02(\.corp\.lab\.)?\s+(\d+\s+)?(IN\s+)?A\s+10\.0\.20\.20\s*$/m.test(z)) return NO('No A record "srv02 IN A 10.0.20.20" in /etc/bind/db.corp.lab.');
    const serial = Number(/(\d+)\s*;\s*serial/i.exec(z)?.[1] ?? 0);
    if (serial <= 2026101901) return NO(`The serial is still ${serial}: increase it (e.g. 2026101902) so secondaries and caches notice the change.`);
    return OK(`A record present, serial ${serial}.`);
  },
};

const zoneLoaded: LabCheck = {
  id: 'dns-record-loaded', description: 'named on ns1 has loaded the new zone, and ws01 resolves srv02.corp.lab to 10.0.20.20',
  check(w) {
    const loaded = w.hosts.ns1.services.named?.loaded as NamedLoaded | null;
    const zone = loaded?.zones.find((z) => z.origin.replace(/\.$/, '') === 'corp.lab');
    if (!zone || zone.serial <= 2026101901) return NO(`named still serves serial ${zone?.serial ?? '(zone not loaded)'}: check the file with named-checkzone, then "rndc reload".`);
    const r = probe(w, 'ws01', 'alice', 'getent hosts srv02.corp.lab');
    return /^10\.0\.20\.20\s/.test(r.output) ? OK(`named serves serial ${zone.serial}; ${r.output.trim()}.`) : NO(`getent hosts srv02.corp.lab on ws01: ${r.output.trim() || 'no answer'}`);
  },
};

const keyInstalled: LabCheck = {
  id: 'ssh-key-installed', description: 'srv02: alice\'s public key from ws01 is in /home/alice/.ssh/authorized_keys',
  check(w) {
    const ak = readFile(w.hosts.srv02, '/home/alice/.ssh/authorized_keys') ?? '';
    const key = aliceKey().publicLine.split(' ').slice(0, 2).join(' ');
    return ak.includes(key) ? OK('authorized_keys contains alice@ws01 (ssh-ed25519).') : NO(ak ? 'authorized_keys exists but does not contain alice\'s ws01 key.' : 'No /home/alice/.ssh/authorized_keys on srv02.');
  },
};

const keyLogin: LabCheck = {
  id: 'ssh-key-login', description: 'alice@ws01 can "ssh srv02.corp.lab" with her key (no password)',
  check(w) {
    const r = checkGoal(w, ALICE_KEY_LOGIN);
    return r.ok ? OK('Logged in with publickey.') : NO(r.lines.filter(Boolean).slice(-2).join(' ') || 'login failed');
  },
};

function sshdRunning(w: World) {
  return w.hosts.srv02.services.ssh?.loaded as SshdLoaded | null;
}

const sshdHardened: LabCheck = {
  id: 'ssh-hardened', description: 'srv02: the running sshd refuses passwords (PasswordAuthentication no) and root logins (PermitRootLogin no)',
  check(w) {
    const e = sshdRunning(w)?.effective;
    if (!e) return NO('sshd is not running.');
    const problems = [e.passwordAuthentication ? 'PasswordAuthentication is yes' : '', e.permitRootLogin !== 'no' ? `PermitRootLogin is ${e.permitRootLogin}` : ''].filter(Boolean);
    return problems.length ? NO(`${problems.join('; ')} in the running configuration (sshd -T). Did you reload ssh after editing?`) : OK('sshd -T: passwordauthentication no, permitrootlogin no.');
  },
};

const sshdPasswordRejected: LabCheck = {
  id: 'ssh-password-rejected', description: 'A password login to srv02 is refused, even with the right password',
  check(w) {
    // ssh -o PubkeyAuthentication=no alice@srv02.corp.lab, answering with alice's real password.
    const r = runSsh(structuredClone(w), { clientHostId: 'ws01', localUser: 'alice', target: 'srv02.corp.lab', pubkeyAuthentication: false, strictHostKeyChecking: 'accept-new', answers: [SRV02_PASSWORD], connectTimeoutS: 10, remoteCommand: 'true' });
    if (r.outcome === 'session') return NO('A password login with alice\'s password still succeeds.');
    const last = r.lines.filter(Boolean).at(-1) ?? '';
    return /Permission denied/.test(last) ? OK(last) : NO(`The login failed for another reason: ${last || r.failure}`);
  },
};

const fwEnabled: LabCheck = {
  id: 'fw-enabled', description: 'srv02: nftables.service is enabled (the ruleset loads at boot) and active',
  check(w) {
    const rt = w.hosts.srv02.services.nftables;
    if (!rt.enabled) return NO('nftables is disabled: after a reboot the server would have no firewall ("systemctl enable nftables").');
    if (rt.state !== 'active') return NO(`nftables is ${rt.state}.`);
    return OK('enabled and active.');
  },
};

const fwPolicy: LabCheck = {
  id: 'fw-policy', description: 'srv02: the input chain has policy drop, with no rule that accepts everything',
  check(w) {
    const input = w.hosts.srv02.nft.tables.flatMap((t) => t.chains).find((c) => c.base?.hook === 'input');
    if (!input) return NO('No input base chain is loaded (nft list ruleset).');
    if (input.base!.policy !== 'drop') return NO('The input chain policy is accept.');
    const blanket = input.rules.find((r) => r.verdict?.kind === 'accept' && (r.matches.length === 0 || r.matches.every((m) => m.kind === 'nfproto')));
    return blanket ? NO(`Rule handle ${blanket.handle} accepts all traffic.`) : OK('policy drop with specific allow rules.');
  },
};

const fwRules: LabCheck = {
  id: 'fw-rules', description: 'srv02: SSH only from the office network 10.0.10.0/24, HTTP from everywhere, other ports closed',
  check(w) {
    const v = {
      sshOffice: fwVerdict(w, '10.0.10.25', 22),
      sshDev: fwVerdict(w, '10.0.30.25', 22),
      http: fwVerdict(w, '10.0.30.25', 80),
      other: fwVerdict(w, '10.0.10.25', 3306),
    };
    const problems = [
      v.sshOffice !== 'accept' ? 'SSH from 10.0.10.25 (ws01) is not accepted' : '',
      v.sshDev === 'accept' ? 'SSH from 10.0.30.25 (dev VLAN) is accepted' : '',
      v.http !== 'accept' ? 'HTTP (80) from 10.0.30.25 is not accepted' : '',
      v.other === 'accept' ? 'TCP 3306 is accepted (default deny expected)' : '',
    ].filter(Boolean);
    return problems.length ? NO(problems.join('; ') + '.') : OK('22 from 10.0.10.0/24, 80 from anywhere, everything else dropped.');
  },
};

const fwPersistent: LabCheck = {
  id: 'fw-persistent', description: 'srv02: /etc/nftables.conf contains the default-drop input chain (survives a reboot)',
  check(w) {
    const conf = readFile(w.hosts.srv02, '/etc/nftables.conf') ?? '';
    return /hook input[^;]*;\s*policy drop/.test(conf) ? OK('/etc/nftables.conf: input chain with policy drop.') : NO('/etc/nftables.conf has no input chain with "policy drop": rules added with "nft add" are lost at reboot.');
  },
};

const webPage: LabCheck = {
  id: 'web-page', description: 'srv02: /var/www/html/index.html exists and names the server ("srv02")',
  check(w) {
    const page = readFile(w.hosts.srv02, '/var/www/html/index.html');
    if (page === undefined) return NO('No /var/www/html/index.html (nginx serves the Debian welcome page).');
    return /srv02/i.test(page) ? OK(`index.html: ${page.trim().slice(0, 60)}`) : NO('index.html does not mention srv02.');
  },
};

const webService: LabCheck = {
  id: 'web-service', description: 'srv02: nginx is enabled and running',
  check(w) {
    const rt = w.hosts.srv02.services.nginx;
    return rt.enabled && rt.state === 'active' ? OK('nginx enabled and active.') : NO(`nginx is ${rt.enabled ? 'enabled' : 'disabled'} and ${rt.state}.`);
  },
};

const webFromOffice: LabCheck = {
  id: 'web-office', description: 'ws01: "curl http://srv02.corp.lab/" returns the status page',
  check(w) {
    const r = probe(w, 'ws01', 'alice', 'curl -s -m 10 http://srv02.corp.lab/');
    return r.code === 0 && /srv02/i.test(r.output) ? OK(r.output.trim().slice(0, 80)) : NO(r.output.trim().split('\n')[0] || `curl exit ${r.code}`);
  },
};

const webFromDev: LabCheck = {
  id: 'web-dev', description: 'dev01 (VLAN 30): the status page is reachable from the other client network too',
  check(w) {
    const r = probe(w, 'dev01', 'erin', 'curl -s -4 -m 10 http://srv02.corp.lab/');
    return r.code === 0 && /srv02/i.test(r.output) ? OK('Status page received.') : NO(r.output.trim().split('\n')[0] || `curl exit ${r.code}`);
  },
};

// ---------------------------------------------------------------- the lab

const SW01_SOLUTION = [
  "sed -i 's/^\\(    bridge-ports .*\\)$/\\1 swp10/' /etc/network/interfaces",
  "sed -i 's/^auto br0$/auto swp10\\niface swp10\\n    alias srv02\\n    bridge-access 20\\n\\nauto br0/' /etc/network/interfaces",
  'ifreload -a',
  'bridge vlan show dev swp10',
];

const SRV02_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto { icmp, ipv6-icmp } accept
		ip saddr 10.0.10.0/24 tcp dport 22 accept
		tcp dport 80 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const LAB1: GuidedLab = {
  id: 'lab1',
  title: 'Lab 1: Basic Linux Server',
  level: 'beginner',
  duration: '60–90 min',
  summary: 'Take a freshly installed Debian server from "plugged in, no network" to a hardened intranet web server: switch port, static addressing, DNS (client and zone), SSH keys and hardening, a default-deny firewall, a web page, and a reboot test.',
  brief: 'The status page of the operations team needs its own server. The virtualization team has installed Debian 12 on **srv02** and cabled it to port **swp10** of the access switch sw01; the installer was left at its defaults (DHCP, password logins, no firewall). Your change ticket (CHG-1500): put srv02 on the **server VLAN 20** as **10.0.20.20**, publish it in DNS as **srv02.corp.lab**, allow administration only with SSH keys from the office network, and serve the status page to everyone on the intranet. The change is only done when everything still works after a reboot.',
  objectives: [
    'Configure an access port on a Linux bridge (ifupdown2) and verify layer 2 from both ends.',
    'Replace installer DHCP with a persistent static configuration (ifupdown).',
    'Configure the resolver and publish a host in a BIND zone (serial, checkzone, rndc reload).',
    'Move administration to SSH keys, then disable passwords and root logins safely.',
    'Write, test and persist a default-deny nftables ruleset that keeps your own access.',
    'Publish content with nginx and verify it from two client networks.',
    'Prove the whole change survives a reboot of every machine.',
  ],
  prerequisites: [
    { label: 'IP networking', link: 'lesson/ipnet/what' },
    { label: 'VLANs, trunks and inter-VLAN routing', link: 'lesson/vlan/what' },
    { label: 'SSH', link: 'lesson/ssh/what' },
    { label: 'Firewalls (nftables)', link: 'lesson/nftables/what' },
  ],
  setupNote: 'This lab adds **srv02** (eth0, MAC 52:54:00:c3:00:14), cabled to sw01 port **swp10**. Target: VLAN 20, 10.0.20.20.',
  terminals: [
    { hostId: 'srv02', user: 'root', label: 'srv02 console (root)', banner: 'Console of the new server srv02 (root, from the hypervisor). Fresh Debian 12 install; alice\'s password on srv02 is "srv02-alice".' },
    { hostId: 'sw01', user: 'root', label: 'sw01 console (root)', banner: 'Serial console of the access switch sw01 (Linux bridge br0 with VLAN filtering, ifupdown2).' },
    { hostId: 'ns1', user: 'root', label: 'ns1 console (root)', banner: 'Console of ns1: BIND 9, authoritative for corp.lab (/etc/bind/db.corp.lab).' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: 'alice\'s admin workstation in the office (10.0.10.25). Her SSH key: ~/.ssh/id_ed25519.' },
  ],
  build: buildLab1World,
  steps: [
    {
      id: 'switch-port', title: 'Patch the switch port into VLAN 20',
      objective: 'srv02 has **no link**: its port **swp10** on sw01 is not configured, and ifupdown2 leaves unconfigured ports down. Make swp10 an **access port in VLAN 20** (the server VLAN), persistently.',
      background: 'sw01 is a VLAN-aware Linux bridge (br0). A port only switches frames when it is a **member** of the bridge (`bridge-ports`), and the VLAN of untagged frames is its **PVID** (`bridge-access 20` = PVID 20, egress untagged, nothing else). Configuration lives in /etc/network/interfaces and `ifreload -a` applies the difference without touching the other ports. Check from both ends: the switch shows the port in `bridge link` / `bridge vlan show`, and the server sees carrier (`LOWER_UP`).',
      tasks: [
        'On srv02: `ip -br link` shows eth0 with **NO-CARRIER**. On sw01: `ip -br link show swp10` (DOWN) and `bridge link` (swp10 missing).',
        'On sw01, edit /etc/network/interfaces (`nano /etc/network/interfaces`): add **swp10** to the `bridge-ports` line of br0, and add a stanza\n```\nauto swp10\niface swp10\n    alias srv02\n    bridge-access 20\n```',
        'Apply with `ifreload -a`, then verify: `bridge vlan show dev swp10` (20 PVID Egress Untagged) and, on srv02, `ip -br link` (UP, LOWER_UP).',
      ],
      hints: [
        'Copy the swp6 stanza (srv01, also VLAN 20) and change the name.',
        'Forgetting bridge-ports is the classic mistake: the port then comes up but is not switched (see the "Cable fine, link up, server isolated" ticket).',
      ],
      checks: [switchFile, switchRunning, srvCarrier],
      solution: [{ host: 'sw01', user: 'root', commands: SW01_SOLUTION }],
      learn: [{ label: 'Linux bridges (interfaces lesson)', link: 'lesson/netif/internals' }, { label: 'Access and trunk ports (VLAN lesson)', link: 'lesson/vlan/config' }, { label: 'bridge command', link: 'reference?id=bridge' }],
      concepts: ['net.vlan', 'net.interfaces'],
    },
    {
      id: 'static-ip', title: 'Configure the static address',
      objective: 'Configure eth0 with **10.0.20.20/24**, default gateway **10.0.20.1**, brought up at boot. Remove the installer\'s DHCP stanza.',
      background: 'The installer configured `allow-hotplug eth0` / `iface eth0 inet dhcp`, but there is no DHCP server on the server VLAN (and servers need addresses that DNS, firewall rules and monitoring can rely on). ifupdown reads /etc/network/interfaces at boot (networking.service). You are on the console, so restarting networking cannot cut your own session; over SSH you would use `ifreload`/`ifup` carefully or schedule a rollback.',
      tasks: [
        'On srv02: `journalctl -u networking -b` shows the failing DHCP attempts ("No DHCPOFFERS received").',
        'Edit /etc/network/interfaces:\n```\nauto eth0\niface eth0 inet static\n    address 10.0.20.20/24\n    gateway 10.0.20.1\n```',
        'Apply: `systemctl restart networking`. Verify: `ip -br addr`, `ip route`, `ping -c 2 10.0.20.1`, and from ws01 `ping -c 2 10.0.20.20`.',
      ],
      hints: [
        '"auto eth0" brings the interface up at boot unconditionally; "allow-hotplug" waits for the kernel to report the device. Either works here, but servers usually use auto.',
        'If ping from ws01 fails but the gateway answers, compare with srv01 (10.0.20.10): same VLAN, same gateway.',
      ],
      checks: [staticFile, staticRunning, gatewayPing, officePing],
      solution: [{ host: 'srv02', user: 'root', commands: ["sed -i 's/^allow-hotplug eth0$/auto eth0/; s/^iface eth0 inet dhcp$/iface eth0 inet static\\n    address 10.0.20.20\\/24\\n    gateway 10.0.20.1/' /etc/network/interfaces", 'systemctl restart networking', 'ip -br addr'] }],
      learn: [{ label: '/etc/network/interfaces', link: 'reference?id=file:etc-network-interfaces' }, { label: 'Network configuration and recovery', link: 'lesson/netops/deploy' }, { label: 'ip command', link: 'reference?id=ip' }],
      concepts: ['net.routing', 'net.cidr'],
    },
    {
      id: 'resolver', title: 'Configure name resolution',
      objective: 'srv02 must resolve corp.lab names through **ns1 (10.0.10.53)**, including short names via the search domain **corp.lab**.',
      background: 'Without resolvconf/systemd-resolved, /etc/resolv.conf is a plain file that ifupdown leaves alone, so it persists as written. `nameserver` lines are tried in order; `search corp.lab` appends the domain to names without dots. `getent hosts` uses the same path as applications (nsswitch: files, then dns); `dig` asks DNS directly and ignores /etc/hosts and the search list unless told otherwise.',
      tasks: [
        'Write /etc/resolv.conf on srv02:\n```\nsearch corp.lab\nnameserver 10.0.10.53\n```',
        'Test: `getent hosts srv01` and `dig srv01.corp.lab +short`.',
      ],
      hints: ['`echo "search corp.lab" > /etc/resolv.conf` then `echo "nameserver 10.0.10.53" >> /etc/resolv.conf` works too.'],
      checks: [resolvFile, resolvWorks],
      solution: [{ host: 'srv02', user: 'root', commands: ["printf 'search corp.lab\\nnameserver 10.0.10.53\\n' > /etc/resolv.conf", 'getent hosts srv01'] }],
      learn: [{ label: 'DNS resolution (TCP, UDP and DNS lesson)', link: 'lesson/transport/internals' }, { label: '/etc/resolv.conf', link: 'reference?id=file:resolv.conf' }],
      concepts: ['dns.resolution'],
    },
    {
      id: 'dns-record', title: 'Publish srv02 in DNS',
      objective: 'Add **srv02.corp.lab → 10.0.20.20** to the corp.lab zone on ns1 and make named serve it.',
      background: 'BIND loads a zone file at start and on `rndc reload`. Every change needs a **higher SOA serial** (secondaries and caches compare it), and `named-checkzone` catches syntax errors before they take the zone down. A record line is `name [TTL] IN A address`; names without a trailing dot are relative to the zone ($ORIGIN corp.lab.).',
      tasks: [
        'On ns1: back up first: `cp -a /etc/bind/db.corp.lab /root/db.corp.lab.bak`.',
        'Edit /etc/bind/db.corp.lab: increase the serial (2026101901 → 2026101902) and add `srv02   IN A    10.0.20.20` next to srv01.',
        'Check and load: `named-checkzone corp.lab /etc/bind/db.corp.lab`, then `rndc reload`. Verify from ws01: `getent hosts srv02.corp.lab`.',
      ],
      hints: ['If named-checkzone reports an error, fix it before reloading: a zone that fails to load is not served at all (SERVFAIL for every corp.lab name).'],
      checks: [zoneFile, zoneLoaded],
      solution: [{ host: 'ns1', user: 'root', commands: ['cp -a /etc/bind/db.corp.lab /root/db.corp.lab.bak', "sed -i 's/2026101901 ; serial/2026101902 ; serial/' /etc/bind/db.corp.lab", "echo 'srv02   IN A    10.0.20.20' >> /etc/bind/db.corp.lab", 'named-checkzone corp.lab /etc/bind/db.corp.lab', 'rndc reload'] }],
      learn: [{ label: 'Safe zone change procedure', link: 'reference?id=proc:bind-zone-change' }, { label: 'named-checkzone', link: 'reference?id=named-checkzone' }],
      concepts: ['dns.zone'],
    },
    {
      id: 'ssh-keys', title: 'Set up key-based login for alice',
      objective: 'alice must log in from ws01 to **srv02.corp.lab** with her **SSH key**, without a password.',
      background: 'The installer created alice with a password and sshd allows password logins by default, which is what lets you install the key. `ssh-copy-id` logs in once with the password and appends the public key to ~/.ssh/authorized_keys with the right permissions. The first connection also records srv02\'s host key in ws01\'s known_hosts: confirm the fingerprint against the console (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on srv02).',
      tasks: [
        'On srv02: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` (the fingerprint you should see on first connect).',
        'On ws01: `ssh-copy-id srv02.corp.lab` (answer "yes", then alice\'s srv02 password "srv02-alice").',
        'Test: `ssh srv02.corp.lab hostname` must not ask for a password.',
      ],
      hints: ['If ssh-copy-id cannot connect, check the previous steps: DNS name, routing, and that sshd runs on srv02 (`systemctl status ssh`).'],
      checks: [keyInstalled, keyLogin],
      solution: [{ host: 'ws01', user: 'alice', commands: ['ssh-copy-id srv02.corp.lab'], answers: ['yes', SRV02_PASSWORD] }],
      learn: [{ label: 'SSH lesson: key authentication', link: 'lesson/ssh/internals' }, { label: 'ssh-keygen', link: 'reference?id=ssh-keygen' }],
      concepts: ['ssh.authorized-keys', 'ssh.hostkeys'],
    },
    {
      id: 'ssh-hardening', title: 'Harden SSH',
      objective: 'Disable **password authentication** and **root logins** on srv02 without locking yourself out.',
      background: 'Put local settings in a drop-in (/etc/ssh/sshd_config.d/*.conf): Debian\'s sshd_config includes that directory first, and the first value for a keyword wins. `sshd -t` validates the files; `systemctl reload ssh` applies them to new connections while existing sessions stay open; `sshd -T` prints the effective configuration. Test a new key login before you close the console or your old session.',
      tasks: [
        'On srv02, create /etc/ssh/sshd_config.d/10-hardening.conf:\n```\nPermitRootLogin no\nPasswordAuthentication no\n```',
        'Validate and apply: `sshd -t && systemctl reload ssh`; check `sshd -T | grep -i -e passwordauthentication -e permitrootlogin`.',
        'From ws01: `ssh srv02.corp.lab hostname` (key login still works).',
      ],
      hints: ['Never restart sshd with a configuration you have not tested with sshd -t. A reload keeps the running daemon if the new configuration is invalid.'],
      checks: [sshdHardened, sshdPasswordRejected, keyLogin],
      solution: [{ host: 'srv02', user: 'root', commands: ["printf 'PermitRootLogin no\\nPasswordAuthentication no\\n' > /etc/ssh/sshd_config.d/10-hardening.conf", 'sshd -t', 'systemctl reload ssh'] }],
      learn: [{ label: 'sshd_config.d drop-ins', link: 'reference?id=file:sshd_config.d' }, { label: 'Safe sshd restart', link: 'reference?id=proc:sshd-safe-restart' }],
      concepts: ['ssh.config', 'ssh.userauth'],
    },
    {
      id: 'firewall', title: 'Default-deny host firewall',
      objective: 'Allow **SSH only from the office network 10.0.10.0/24**, **HTTP from everywhere**, ping, and drop everything else; load it at every boot.',
      background: 'Debian installs nftables with an empty, accepting ruleset and the service **disabled**. A host firewall starts from `policy drop` in the input chain, then accepts replies (`ct state established,related`), loopback, ICMP (monitoring, PMTUD, IPv6 neighbour discovery) and the services you offer. `nft -c -f` checks a file without loading it; `systemctl enable --now nftables` loads /etc/nftables.conf now and at boot. Keep a session open while you load it: a mistake in the SSH rule would lock out new logins.',
      tasks: [
        'Write /etc/nftables.conf on srv02 (start from srv01\'s ruleset, or):\n```\ntable inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t\tct state invalid drop\n\t\tiif "lo" accept\n\t\tmeta l4proto { icmp, ipv6-icmp } accept\n\t\tip saddr 10.0.10.0/24 tcp dport 22 accept\n\t\ttcp dport 80 accept\n\t}\n}\n```\n(with `flush ruleset` at the top, and forward/output chains as in srv01\'s file).',
        'Check, load and enable: `nft -c -f /etc/nftables.conf && systemctl enable --now nftables`; then `nft list ruleset`.',
        'Test from ws01: `ssh srv02.corp.lab hostname` (allowed) and from dev01 `nc -zv -w 2 10.0.20.20 22` (refused by the firewall: timeout).',
      ],
      hints: ['`systemctl is-enabled nftables` must say "enabled": a ruleset loaded with "nft -f" alone is gone after a reboot.', 'Write the file with the editor: `nano /etc/nftables.conf`.'],
      checks: [fwPolicy, fwRules, fwEnabled, fwPersistent],
      // The ruleset has no quotes, backslashes or percent signs, so one printf writes it.
      solution: [{ host: 'srv02', user: 'root', commands: [`printf '${SRV02_NFT.replace(/\n/g, '\\n')}' > /etc/nftables.conf`, 'nft -c -f /etc/nftables.conf', 'systemctl enable --now nftables'] }],
      learn: [{ label: 'nftables lesson', link: 'lesson/nftables/what' }, { label: 'Safe ruleset reload', link: 'reference?id=proc:nft-safe-reload' }, { label: '/etc/nftables.conf', link: 'reference?id=file:nftables.conf' }],
      concepts: ['fw.stateful', 'fw.persistence'],
    },
    {
      id: 'web', title: 'Publish the status page',
      objective: 'Serve a page that names the server (**srv02**) at **http://srv02.corp.lab/**, reachable from the office and the development VLAN.',
      background: 'Debian\'s nginx package is enabled and serves /var/www/html; with no index.html it shows the Debian welcome page (index.nginx-debian.html). Content changes need no reload; configuration changes do (`nginx -t && systemctl reload nginx`). Test from clients on different networks: it proves DNS, routing and the firewall rule for port 80 together.',
      tasks: [
        'On srv02: `echo \'<h1>srv02 status: OK</h1>\' > /var/www/html/index.html`.',
        'Check the service: `systemctl is-enabled nginx`, `ss -tlnp | grep :80`.',
        'From ws01: `curl http://srv02.corp.lab/`; from dev01: `curl -4 http://srv02.corp.lab/`.',
      ],
      hints: ['If curl times out from dev01 but works from ws01, compare the firewall rule for port 80: is it limited to the office network?'],
      checks: [webPage, webService, webFromOffice, webFromDev],
      solution: [{ host: 'srv02', user: 'root', commands: ["echo '<h1>srv02 status: OK</h1>' > /var/www/html/index.html", 'systemctl enable --now nginx'] }],
      learn: [{ label: 'curl', link: 'reference?id=curl' }, { label: 'TCP, UDP and DNS lesson', link: 'lesson/transport/what' }],
      concepts: ['svc.listening', 'tcp.handshake'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Prove the change is complete: every check of the previous steps must still pass **after every machine reboots** and rebuilds its state from the configuration files.',
      background: 'Runtime changes (`ip addr add`, `nft add rule`, `bridge vlan add`, a started-but-disabled service) work until the next reboot and then silently disappear, often months later during a power cut or a kernel update. The simulator reboots all hosts on a copy of the lab (your lab is not changed) and re-runs every check. You can also reboot a machine yourself in its terminal (`reboot`).',
      tasks: ['Press **Check step**: the lab is rebooted on a copy and all checks run again.', 'Fix anything that only worked at runtime, then check again.'],
      hints: ['A check that passed before but fails now points at a runtime-only change: compare the configuration file with the running state.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Safe configuration change', link: 'reference?id=proc:safe-config-change' }],
      concepts: ['fw.persistence', 'ops.recovery'],
      afterReboot: true,
    },
  ],
};
