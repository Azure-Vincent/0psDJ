// Kerberos tickets: the realm CORP.LAB with the MIT KDC on ns1, clients that
// find it through DNS SRV records, and Kerberos single sign-on (GSSAPI) for
// SSH to srv01. Each fault is a classic: the clock, DNS, the firewall, the keytab.

import { readFile, writeFile } from '../fs';
import { ALICE_KRB_PASSWORD } from '../lab/krbLab';
import type { World } from '../types';
import { firewallStillRestrictive, script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const SSO: Goal = { kind: 'kerberos', description: 'On ws01, alice gets a ticket with "kinit" and then logs in to srv01.corp.lab with Kerberos alone ("ssh -o PubkeyAuthentication=no -o PasswordAuthentication=no srv01.corp.lab").', fromHost: 'ws01', localUser: 'alice', password: ALICE_KRB_PASSWORD, sshTarget: 'srv01.corp.lab' };

const TERMINALS = [
  { hostId: 'ws01', user: 'alice', label: 'ws01 (alice)', banner: `ws01, Alice's workstation. Her Kerberos password (alice@CORP.LAB) is ${ALICE_KRB_PASSWORD}; her sudo password on ws01 is ws01-alice.` },
  { hostId: 'ns1', user: 'root', label: 'ns1 console', banner: 'Console on ns1 (root): DNS (BIND, zone corp.lab) and the Kerberos KDC for CORP.LAB (krb5-kdc, krb5-admin-server). kadmin.local works here.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 console', banner: 'Console on srv01 (root). sshd accepts Kerberos logins (GSSAPIAuthentication yes in /etc/ssh/sshd_config.d/20-kerberos.conf). The Kerberos admin principal is alice/admin (password Corp-Admin-2026).' },
];

const BRIEFING = [
  'corp.lab is a Kerberos realm, CORP.LAB. The KDC (krb5-kdc) and the admin server (kadmind, krb5-admin-server) run on ns1; their configuration is in /etc/krb5kdc/ (kdc.conf, kadm5.acl). Clients have no KDC in /etc/krb5.conf: they find it through DNS SRV records in corp.lab (_kerberos._udp, _kerberos._tcp, _kerberos-adm._tcp).',
  'srv01 accepts Kerberos SSH logins (CHG-1500): its host principal host/srv01.corp.lab@CORP.LAB has a key in /etc/krb5.keytab. With a ticket from kinit, "ssh srv01.corp.lab" logs in without keys or passwords.',
  'Kerberos requires clocks within 5 minutes of the KDC; corp.lab machines synchronise with systemd-timesyncd. Fixes must survive a reboot of every machine; firewalls keep their default-deny input policy.',
];

const CANDIDATES = ['krb-clock-skew', 'krb-missing-srv', 'krb-kdc-firewall', 'krb-kdc-down', 'krb-stale-keytab', 'krb-wrong-password', 'dns-zone-error'];

/** Kerberos SSO for SSH on srv01 (the state these tickets start from). */
function enableSso(world: World) {
  world.clock += 60_000;
  const srv = world.hosts.srv01;
  writeFile(srv, '/etc/ssh/sshd_config.d/20-kerberos.conf', '# CHG-1500: Kerberos single sign-on for corp.lab accounts\nGSSAPIAuthentication yes\n', world.clock);
  script(world, 'srv01', ['systemctl reload ssh']);
}

function edit(world: World, host: string, path: string, fn: (s: string) => string, gapMs = 60_000) {
  world.clock += gapMs;
  const h = world.hosts[host];
  writeFile(h, path, fn(readFile(h, path) ?? ''), world.clock);
}

function ntpEnabled(hostId: string): Constraint {
  return {
    id: `ntp-${hostId}`, required: true,
    description: `${hostId} must keep its clock synchronised automatically (systemd-timesyncd enabled), not just set by hand.`,
    check(world) {
      const s = world.hosts[hostId].services['systemd-timesyncd'];
      const ok = !!s?.enabled;
      return { id: this.id, ok, required: true, message: ok ? `${hostId}: systemd-timesyncd is enabled.` : `${hostId}: systemd-timesyncd is disabled, so the clock will drift again (timedatectl set-ntp true).` };
    },
  };
}

function kdcFromDns(): Constraint {
  return {
    id: 'kdc-from-dns', required: true,
    description: 'Clients keep finding the KDC through DNS: do not hard-code a kdc line in /etc/krb5.conf on ws01.',
    check(world) {
      const conf = readFile(world.hosts.ws01, '/etc/krb5.conf') ?? '';
      const ok = !/^\s*kdc\s*=/m.test(conf);
      return { id: this.id, ok, required: true, message: ok ? 'ws01 still locates the KDC with DNS SRV records.' : 'ws01\'s krb5.conf names the KDC directly: every other machine is still broken, and the next KDC move breaks ws01 too.' };
    },
  };
}

function keytabProtected(): Constraint {
  return {
    id: 'keytab-mode', required: true,
    description: 'srv01:/etc/krb5.keytab holds the server\'s secret key: it must stay readable by root only (mode 600).',
    check(world) {
      const f = world.hosts.srv01.fs['/etc/krb5.keytab'];
      const ok = !!f && (f.mode & 0o077) === 0 && f.owner === 'root';
      return { id: this.id, ok, required: true, message: ok ? 'srv01: /etc/krb5.keytab is root-only.' : 'srv01: /etc/krb5.keytab is missing or readable by other users: anyone who reads it can impersonate srv01.' };
    },
  };
}

const NS1_BASELINE_NFT = `#!/usr/sbin/nft -f
# SEC-14 infrastructure server baseline (applied by configuration management)
flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif "lo" accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		# DNS for all clients
		udp dport 53 accept
		tcp dport 53 accept
		# administration from the office network
		ip saddr 10.0.10.0/24 tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const KRB_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'krb-clock-skew',
    title: 'The clock was set by hand',
    difficulty: 'beginner',
    ticket: 'Alice (ws01): "Since desktop support updated my workstation\'s BIOS yesterday, kinit says \'Clock skew too great\'. I changed my password last week, could that be it? Kerberos SSO to srv01 does not work either."',
    briefing: BRIEFING,
    goals: [SSO],
    terminals: TERMINALS,
    setup(world) {
      enableSso(world);
      // The technician turned NTP off to set the time manually, and set it 9 minutes fast.
      script(world, 'ws01', ['timedatectl set-ntp false']);
      world.hosts.ws01.clockOffset = 9 * 60_000 + 17_000;
      world.clock += 20 * 60_000;
    },
    rootCauses: ['krb-clock-skew'],
    candidates: CANDIDATES,
    feedback: {
      'krb-missing-srv': '"host -t SRV _kerberos._udp.corp.lab" answers, and the KDC logs alice\'s requests: the client finds and reaches the KDC.',
      'krb-kdc-firewall': 'The KDC receives the requests and answers them (journalctl -u krb5-kdc shows AS_REQ from 10.0.10.25).',
      'krb-kdc-down': 'krb5-kdc is active on ns1 and answering.',
      'krb-stale-keytab': 'The failure happens at kinit, before any service ticket or keytab is involved.',
      'krb-wrong-password': 'The KDC log says "Clock skew too great", not "Preauthentication failed": the password decrypted the timestamp fine, the timestamp itself is the problem.',
      'dns-zone-error': 'The zone loads and answers (the SRV records resolve).',
    },
    hints: [
      'Read the error literally, then compare "date" on ws01 with "date" on ns1.',
      '"timedatectl" on ws01: is the clock synchronised? Is the NTP service running?',
      'Turn automatic synchronisation back on: "sudo timedatectl set-ntp true" (enables and starts systemd-timesyncd, which corrects the clock). Setting the time by hand would drift again and not survive the next BIOS mishap.',
    ],
    explanation: {
      rootCause: 'ws01\'s clock is 9 minutes fast, and NTP (systemd-timesyncd) was disabled when the time was set by hand. Kerberos rejects any request whose timestamp differs from the KDC\'s clock by more than clockskew (300 s): the encrypted timestamp in the AS-REQ is the proof of the password, and an old or future one could be a replay.',
      manifestation: 'kinit fails with "Clock skew too great while getting initial credentials". The KDC logs "preauth (encrypted_timestamp) verify failure: Clock skew too great". Even with an existing ticket, srv01 would reject the authenticator for the same reason.',
      evidence: '"date" on ws01 vs ns1: about 9 minutes apart. "timedatectl" on ws01: "System clock synchronized: no", "NTP service: inactive". journalctl -u krb5-kdc on ns1: PREAUTH_FAILED ... Clock skew too great.',
      prevention: 'Keep NTP enabled everywhere (monitor "System clock synchronized"), and make the KDC/domain controllers the reference time source. Never "fix" skew errors by raising clockskew.',
    },
    solution: [{ host: 'ws01', commands: ['timedatectl set-ntp true'] }],
    constraints: [ntpEnabled('ws01')],
    concepts: ['ad.kerberos'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'krb-missing-srv',
    title: 'The IPAM export',
    difficulty: 'intermediate',
    ticket: 'Service desk: "Nobody in the office can get a Kerberos ticket since this morning: \'kinit: Cannot find KDC for realm "CORP.LAB"\'. The network team regenerated the corp.lab zone from the IPAM export last night (NET-95). The KDC team says the KDC is up."',
    briefing: BRIEFING,
    goals: [SSO],
    terminals: TERMINALS,
    setup(world) {
      enableSso(world);
      edit(world, 'ns1', '/etc/bind/db.corp.lab', (s) => s.replace(/; Kerberos realm CORP\.LAB[\s\S]*$/, '').replace('2026101901 ; serial', '2026102201 ; serial'));
      script(world, 'ns1', ['rndc reload']);
    },
    rootCauses: ['krb-missing-srv'],
    candidates: CANDIDATES,
    feedback: {
      'krb-clock-skew': 'The clocks agree, and no request ever reaches the KDC: its log has nothing for ws01.',
      'krb-kdc-firewall': 'kinit fails instantly without sending anything to port 88; there is nothing for a firewall to drop.',
      'krb-kdc-down': 'krb5-kdc is active on ns1 and listening on port 88.',
      'krb-stale-keytab': 'kinit itself fails, before any server key is involved.',
      'krb-wrong-password': 'kinit does not even ask for the password: it cannot find a KDC to ask.',
      'dns-zone-error': 'The zone loads without errors and answers ("host srv01.corp.lab" works); some records are simply missing from it.',
    },
    hints: [
      '"Cannot find KDC" means the library has no address for the KDC at all. Where does ws01 get it from? Look at [realms] in /etc/krb5.conf.',
      'There is no kdc line, so the library asks DNS: "host -t SRV _kerberos._udp.corp.lab". Compare with the zone file on ns1.',
      'Restore the SRV records in /etc/bind/db.corp.lab (_kerberos._udp and _kerberos._tcp to ns1 port 88, _kerberos-adm._tcp to port 749), increase the serial and run "rndc reload".',
    ],
    explanation: {
      rootCause: 'The regenerated corp.lab zone contains only the host records from the IPAM export; the Kerberos SRV records (_kerberos._udp, _kerberos._tcp, _kerberos-adm._tcp, _kerberos TXT) were not part of the export and disappeared.',
      manifestation: 'Clients have dns_lookup_kdc enabled and no kdc line for CORP.LAB, so the library looks up _kerberos._udp.corp.lab and _kerberos._tcp.corp.lab, gets NXDOMAIN and gives up immediately with "Cannot find KDC for realm". The KDC is never contacted.',
      evidence: '"host -t SRV _kerberos._udp.corp.lab" → NXDOMAIN on any client; "grep _kerberos /etc/bind/db.corp.lab" on ns1 finds nothing; the KDC log has no requests from clients.',
      prevention: 'Service records must be part of the source of truth that generates the zone (or live in a separate included file). Monitor them: a check for "host -t SRV _kerberos._udp.corp.lab". Active Directory has the same dependency: domain join and logon find domain controllers through _ldap._tcp and _kerberos._tcp SRV records.',
    },
    solution: [{ host: 'ns1', commands: [
      "sed -i 's/2026102201 ; serial/2026102202 ; serial/' /etc/bind/db.corp.lab",
      "printf '%s\\n' '_kerberos._udp IN SRV 0 0 88 ns1' '_kerberos._tcp IN SRV 0 0 88 ns1' '_kerberos-adm._tcp IN SRV 0 0 749 ns1' >> /etc/bind/db.corp.lab",
      'rndc reload',
    ] }],
    constraints: [kdcFromDns()],
    concepts: ['ad.dns', 'ad.kerberos', 'dns.zone'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'krb-kdc-firewall',
    title: 'The new baseline',
    difficulty: 'intermediate',
    ticket: 'Monitoring: "Kerberos login check FAILED" since the SEC-14 server baseline was applied to ns1 at 06:00. DNS checks are green. Users say kinit "hangs for a while" and then fails.',
    briefing: BRIEFING,
    goals: [SSO],
    terminals: TERMINALS,
    setup(world) {
      enableSso(world);
      edit(world, 'ns1', '/etc/nftables.conf', () => NS1_BASELINE_NFT);
      script(world, 'ns1', ['systemctl reload nftables']);
    },
    rootCauses: ['krb-kdc-firewall'],
    candidates: CANDIDATES,
    feedback: {
      'krb-clock-skew': 'The requests never reach the KDC process, so no time is compared.',
      'krb-missing-srv': 'The SRV records resolve (host -t SRV _kerberos._udp.corp.lab), so kinit knows where to send its requests.',
      'krb-kdc-down': 'krb5-kdc is active and "ss -ulnp" shows it listening on port 88. A stopped KDC would also fail faster (ICMP port unreachable instead of silence).',
      'krb-stale-keytab': 'kinit fails before any server key is involved.',
      'krb-wrong-password': 'kinit never gets to the password: no answer from any KDC.',
      'dns-zone-error': 'DNS works through the new baseline (udp/tcp 53 are allowed).',
    },
    hints: [
      '"Hangs, then fails" means silence, not a refusal. Does the KDC see the requests? "journalctl -u krb5-kdc" on ns1.',
      'Is krb5kdc listening? "ss -ulnp" on ns1. Do the packets arrive? "tcpdump -n -i eth0 port 88" while you run kinit on ws01.',
      'The SEC-14 ruleset allows DNS and SSH only. Add "udp dport { 88, 464, 750 } accept" and "tcp dport { 88, 464, 749 } accept" to the input chain in /etc/nftables.conf and reload nftables.',
    ],
    explanation: {
      rootCause: 'The SEC-14 baseline replaced ns1\'s ruleset with a default-drop input chain that allows DNS and SSH but not Kerberos (UDP/TCP 88; 464 for password changes, 749 for kadmin).',
      manifestation: 'The client sends AS-REQs over UDP to port 88, gets no answer, retries (1 s each), tries TCP (SYNs dropped as well) and then reports "Cannot contact any KDC for realm \'CORP.LAB\'". Silence (drop) makes it slow; a missing service would fail at once with ICMP port unreachable.',
      evidence: 'ns1: krb5-kdc active and listening on :88 (ss -ulnp), but no AS_REQ in its log since 06:00; tcpdump shows the requests arriving; nft list ruleset has no rule for port 88.',
      prevention: 'Build server baselines from the services each role runs (a KDC needs 88/464/749), and test the role\'s health checks after applying a baseline.',
    },
    solution: [{ host: 'ns1', commands: [
      "sed -i 's/^\\t\\ttcp dport 53 accept$/\\t\\ttcp dport 53 accept\\n\\t\\t# Kerberos KDC, kpasswd and kadmin\\n\\t\\tudp dport { 88, 464, 750 } accept\\n\\t\\ttcp dport { 88, 464, 749 } accept/' /etc/nftables.conf",
      'systemctl reload nftables',
    ] }],
    constraints: [firewallStillRestrictive('ns1')],
    concepts: ['ad.kerberos', 'fw.stateful'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'krb-stale-keytab',
    title: 'The key rotation',
    difficulty: 'advanced',
    ticket: 'Alice: "Since the security team rotated the Kerberos host keys this morning (SEC-15), SSO to srv01 is gone: ssh asks for my key again, and colleagues without a key cannot log in at all. kinit works fine."',
    briefing: BRIEFING,
    goals: [SSO],
    terminals: TERMINALS,
    setup(world) {
      enableSso(world);
      // SEC-15: the key was randomised on the KDC; nobody exported it to srv01's keytab.
      script(world, 'ns1', ['kadmin.local -q "cpw -randkey host/srv01.corp.lab"']);
    },
    rootCauses: ['krb-stale-keytab'],
    candidates: CANDIDATES,
    feedback: {
      'krb-clock-skew': 'kinit works and the clocks agree.',
      'krb-missing-srv': 'kinit and kvno find the KDC.',
      'krb-kdc-firewall': 'The KDC answers kinit and kvno.',
      'krb-kdc-down': 'The KDC issues tickets: kinit and "kvno host/srv01.corp.lab" succeed.',
      'krb-wrong-password': 'kinit succeeds with alice\'s password.',
      'dns-zone-error': 'Names resolve.',
    },
    hints: [
      'kinit works, so the KDC side is healthy. What does srv01 need to accept a ticket? Its own key, in /etc/krb5.keytab.',
      'Compare key versions: "kvno host/srv01.corp.lab" on ws01 (what the KDC encrypts tickets with) and "klist -k" on srv01 (what srv01 can decrypt). "getprinc host/srv01.corp.lab" on ns1 shows the KDC\'s side too.',
      'Export the current key into srv01\'s keytab, on srv01: "kadmin -p alice/admin -q \\"ktadd host/srv01.corp.lab\\"" (password Corp-Admin-2026). ktadd creates a new random key (kvno + 1) and writes it, so the KDC and the keytab agree again; clients need a fresh ticket (kdestroy; kinit).',
    ],
    explanation: {
      rootCause: 'The host principal\'s key was randomised on the KDC (kvno 2 → 3) without updating srv01\'s keytab, which still has only kvno 2. Service tickets are encrypted with the KDC\'s current key, which srv01 does not have.',
      manifestation: 'kinit and "kvno host/srv01.corp.lab" work, but sshd cannot decrypt the ticket ("Key version number for principal in key table is incorrect", visible only at LogLevel DEBUG1), so gssapi-with-mic fails silently and ssh moves on to publickey or password. Users with keys hardly notice; users without keys are locked out.',
      evidence: 'ws01: "kvno host/srv01.corp.lab" → kvno = 3. srv01: "klist -k" → only kvno 2. ns1: getprinc host/srv01.corp.lab → "Key: vno 3". ssh -v shows gssapi-with-mic tried and then "Next authentication method: publickey".',
      prevention: 'Rotate a service key on the server itself ("kadmin ktadd" writes the new key into the keytab in the same step), or distribute the keytab in the same change. Monitor that kvno on the KDC matches the keytab. Note that clients may hold cached tickets with the old kvno until they expire.',
    },
    solution: [{ host: 'srv01', commands: ['kadmin -p alice/admin -w Corp-Admin-2026 -q "ktadd host/srv01.corp.lab"'] }],
    constraints: [keytabProtected()],
    concepts: ['ad.kerberos', 'ssh.userauth'],
  },
];
