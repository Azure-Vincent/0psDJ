// The Tier 2 tickets: chained incidents, each built from Tier 1 tickets of one
// area. Every chain was checked to really chain: after fixing the first fault
// alone, the goals still fail (with a different symptom), and the parts'
// solutions together pass verification, including after a reboot.

import { chain, type ChainSpec } from './tier2';
import type { Scenario } from './types';

const SPECS: { id: string; title: string; specs: ChainSpec[] }[] = [
  {
    id: 'network', title: 'Networking fundamentals',
    specs: [
      {
        id: 't2-net-new-workstation', title: 'The new address plan', difficulty: 'intermediate',
        parts: ['net-dns-resolvconf', 'net-wrong-mask'],
        ticket: 'alice: "Since I reconfigured my workstation for the new address plan, nothing resolves: ssh srv01.corp.lab says Temporary failure in name resolution. I followed the migration guide step by step, addresses and resolv.conf included."',
      },
      {
        id: 't2-net-template', title: 'Copied from the old template',
        parts: ['net-wrong-gateway', 'net-nginx-loopback'],
        ticket: 'alice: "I copied my network settings from the old office template and now nothing on other networks answers. Also, the web team says they prepared srv01 for a reverse proxy this morning; the intranet is what I need most."',
      },
      {
        id: 't2-net-patch-weekend', title: 'After the patch weekend',
        parts: ['net-ip-forward', 'net-hosts-override'],
        ticket: 'Monday: "Since the weekend patching nobody in the office reaches any server; pinging the router works." alice adds: "I also had a hosts-file workaround on my machine from the migration test, but that should not matter."',
      },
    ],
  },
  {
    id: 'dhcp-nat', title: 'DHCP and NAT',
    specs: [
      {
        id: 't2-dhcp-migration', title: 'The DHCP migration', difficulty: 'intermediate',
        parts: ['dhcp-interface', 'dhcp-wrong-router'],
        ticket: 'Dana: "My laptop has no IPv4 address since this morning." The sysadmin migrated ns1\'s DHCP configuration from the old VM template yesterday "and cleaned up the options while at it".',
      },
      {
        id: 't2-dhcp-nat-office', title: 'Laptops and the Internet',
        parts: ['dhcp-pool-exhausted', 'nat-no-masquerade'],
        ticket: 'Office: "New laptops get no address, and the people whose laptops do have one say no website on the Internet loads since the firewall migration."',
      },
      {
        id: 't2-nat-both-ways', title: 'In and out',
        parts: ['nat-no-masquerade', 'nat-dnat-typo'],
        ticket: 'Office: "No website on the Internet loads since the firewall migration." Customer support, an hour later: "And customers cannot reach our website either."',
      },
    ],
  },
  {
    id: 'vlan-ipv6', title: 'VLANs and IPv6',
    specs: [
      {
        id: 't2-vlan-desk-move', title: 'Desk move and switch maintenance', difficulty: 'intermediate',
        parts: ['vlan-access-port', 'vlan-trunk-pruned'],
        ticket: 'Erin: "Since the desk move dev01 reaches nothing, not even the gateway." Change log: NET-51 "sw01: standardised desk ports", NET-52 "sw01: pruned unused VLANs from trunk ports".',
      },
      {
        id: 't2-ipv6-hardening-nic', title: 'IPv6 after the hardening and the NIC swap',
        parts: ['ipv6-icmp-hardening', 'ipv6-server-gateway'],
        ticket: 'Erin: "Our deployment script\'s curl -6 against srv01 fails with No route to host." Security SEC-88 restricted ICMPv6 on srv01 yesterday; ops replaced srv01\'s NIC the same week.',
      },
    ],
  },
  {
    id: 'ssh', title: 'SSH',
    specs: [
      {
        id: 't2-ssh-bot-noise', title: 'Less bot noise', difficulty: 'intermediate',
        parts: ['ssh-firewall-drop', 'ssh-port-moved'],
        ticket: 'alice: "ssh to srv01 just hangs and times out." In chat, a colleague: "I tightened srv01\'s firewall and moved SSH off port 22 to reduce the bot noise, should be transparent."',
      },
      {
        id: 't2-ssh-renumbering', title: 'The renumbering',
        parts: ['ssh-dns-stale', 'ssh-missing-gateway'],
        ticket: 'alice: "ssh srv01.corp.lab fails with No route to host." The network team renumbered and re-cabled part of the server network last week.',
      },
    ],
  },
  {
    id: 'scoring', title: 'Scored services (competition scoring engine)',
    specs: [
      {
        id: 't2-score-red-team', title: 'Red team round',
        parts: ['score-password-changed', 'score-faillock'],
        ticket: 'Scoring engine, SSH (srv01): "unable to authenticate, attempted methods [none password]" since round 412. Teammate: "The red team was on srv01 this morning."',
      },
      {
        id: 't2-score-audit', title: 'Audit fixes',
        parts: ['score-sshd-masked', 'score-allowgroups'],
        ticket: 'Scoring engine, SSH (srv01): "dial tcp 10.0.20.10:22: connect: connection refused" since the audit fixes ("make sure nobody can start a rogue sshd", "restrict SSH to the admin group").',
      },
    ],
  },
  {
    id: 'kerberos', title: 'Kerberos and DNS service records',
    specs: [
      {
        id: 't2-krb-dr-test', title: 'After the DR test',
        parts: ['krb-missing-srv', 'krb-clock-skew'],
        ticket: 'alice: "kinit says Cannot find KDC for realm CORP.LAB since the disaster-recovery test restored ns1 and the KDC last night." The DR log: "DNS zone and time sources restored from backup".',
      },
      {
        id: 't2-krb-zone-firewall', title: 'Zone clean-up and firewall',
        parts: ['krb-missing-srv', 'krb-kdc-firewall'],
        ticket: 'alice: "kinit cannot find the KDC since the DNS zone clean-up." The security team also reviewed the KDC\'s firewall the same afternoon.',
      },
    ],
  },
  {
    id: 'windows-firewall', title: 'Windows Defender Firewall',
    specs: [
      {
        id: 't2-wfw-app-rules', title: 'Application rules',
        parts: ['wfw-program-mismatch', 'wfw-block-precedence'],
        ticket: 'The reporting service on win01 is unreachable since its upgrade, and the security team added "a few deny rules" the same week.',
      },
    ],
  },
  {
    id: 'nftables', title: 'Firewalls (nftables)',
    specs: [
      { id: 't2-fw-maintenance', title: 'Maintenance night', difficulty: 'intermediate', parts: ['fw-nginx-stopped', 'fw-tcp-reset'], ticket: 'Users: "The intranet is down since last night\'s maintenance on srv01." The change log lists a web server update and "firewall hardening".' },
      { id: 't2-fw-ruleset-rewrite', title: 'The ruleset rewrite', parts: ['fw-cidr-guest', 'fw-no-established'], ticket: 'Users on the office network cannot reach the intranet since the firewall ruleset on srv01 was rewritten "to be cleaner".' },
    ],
  },
  {
    id: 'tls', title: 'TLS and certificates',
    specs: [
      { id: 't2-tls-renewal', title: 'The certificate renewal', difficulty: 'intermediate', parts: ['tls-key-mismatch', 'tls-missing-intermediate'], ticket: 'Monitoring: "https://www.corp.lab certificate check failed" right after the yearly certificate renewal on srv01.' },
      { id: 't2-tls-new-ca', title: 'The new CA', parts: ['tls-wrong-cert', 'tls-untrusted-root'], ticket: 'Users get certificate warnings on https://www.corp.lab since the move to the new internal CA.' },
    ],
  },
  {
    id: 'containers', title: 'Containers (Docker)',
    specs: [
      { id: 't2-docker-redeploy', title: 'The tidy redeploy', difficulty: 'intermediate', parts: ['docker-renamed-service', 'docker-forward-drop'], ticket: 'The inventory site is down since this morning. The developer: "I only renamed the database service to postgres in compose.yaml and redeployed." Security, the same night: "we applied the standard server firewall template to dock01; port 8000 is allowed in the input chain."' },
      { id: 't2-docker-patch-reboot', title: 'Patch reboot on dock01', parts: ['docker-forward-drop', 'docker-no-restart'], ticket: 'The inventory site is down since dock01\'s patch reboot. Security hardened dock01\'s firewall the same week.' },
    ],
  },
  {
    id: 'proxy', title: 'Web servers and reverse proxies',
    specs: [
      { id: 't2-proxy-migration', title: 'The app migration', difficulty: 'intermediate', parts: ['proxy-host-not-found', 'proxy-gateway-timeout'], ticket: 'Users of https://apps.corp.lab get errors since the application moved to its new server.' },
      { id: 't2-proxy-new-path', title: 'Hardened, then tidied', parts: ['proxy-gateway-timeout', 'proxy-prefix-404'], ticket: 'Since security applied firewall standard SEC-120 to dock01, http://apps.corp.lab/inventory/ spins and then shows "504 Gateway Time-out". The same day a colleague "cleaned up" the proxy configuration on srv01; nginx -t is happy.' },
    ],
  },
  {
    id: 'ntp', title: 'Time synchronisation (NTP)',
    specs: [
      { id: 't2-ntp-drift', title: 'Clocks drifting', difficulty: 'intermediate', parts: ['ntp-blocked', 'ntp-upstream-lost'], ticket: 'Kerberos and log timestamps disagree across servers: clocks are drifting. The firewall team and the network team both made changes last week.' },
    ],
  },
  {
    id: 'files', title: 'File sharing (NFS and SMB)',
    specs: [
      { id: 't2-nfs-restore', title: 'After the file server restore', difficulty: 'intermediate', parts: ['nfs-exportfs', 'nfs-uid-mismatch'], ticket: 'The shared project directory is unavailable on srv01 since fs01 was restored from backup; "and once it mounts, check that people can still write".' },
      { id: 't2-smb-new-colleague', title: 'A new colleague', parts: ['smb-new-user', 'smb-valid-users'], ticket: 'The new finance colleague cannot open the finance share, and the share was "tidied up" last week.' },
    ],
  },
  {
    id: 'email', title: 'Email (Postfix and Dovecot)',
    specs: [
      { id: 't2-mail-rebuild', title: 'The mail server rebuild', difficulty: 'intermediate', parts: ['mail-loopback-only', 'mail-mbox-maildir'], ticket: 'Nobody receives mail since mail01 was rebuilt from the new template.' },
      { id: 't2-mail-alerts', title: 'Lost alerts', parts: ['mail-alias-newaliases', 'mail-sasl-socket'], ticket: 'Ops: "We get no alert mails any more", and users cannot send through the submission port since the mail server hardening.' },
    ],
  },
  {
    id: 'database', title: 'Databases (PostgreSQL)',
    specs: [
      { id: 't2-db-new-app', title: 'The new application', difficulty: 'intermediate', parts: ['db-listen-default', 'db-hba-office'], ticket: 'The new office application cannot connect to its database on db01.' },
      { id: 't2-db-hardening', title: 'Database hardening', parts: ['db-hba-office', 'db-md5-scram'], ticket: 'The office application fails to log in to the database since the security hardening of db01.' },
    ],
  },
  {
    id: 'monitoring', title: 'Monitoring (Prometheus, Alertmanager, SNMP)',
    specs: [
      { id: 't2-mon-blind-spots', title: 'Blind spots', difficulty: 'intermediate', parts: ['mon-fs01-firewall', 'mon-silence-log01'], ticket: 'Monitoring shows fs01 down, and the on-call engineer says log01 has not paged in weeks although it had problems.' },
      { id: 't2-mon-config-change', title: 'The monitoring config change', parts: ['mon-prom-timeout', 'mon-am-submission'], ticket: 'Since last week\'s monitoring configuration change nothing pages any more.' },
    ],
  },
  {
    id: 'identity', title: 'Directory services (LDAP/LDAPS) and RADIUS',
    specs: [
      { id: 't2-id-security-day', title: 'Security day', difficulty: 'intermediate', parts: ['id-ldap-signing', 'id-svc-locked'], ticket: 'The intranet phone book on srv01 fails since the security team\'s "LDAP hardening day".' },
      { id: 't2-id-radius-move', title: 'Moving RADIUS', parts: ['id-radius-ca', 'id-radius-secret'], ticket: 'Network admins cannot log in to rtr01 with their AD accounts since RADIUS got its new CA and a secret rotation.' },
    ],
  },
  {
    id: 'windows', title: 'Windows Server and Remote Desktop',
    specs: [
      { id: 't2-win-rdp-baseline', title: 'The security baseline', difficulty: 'intermediate', parts: ['win-rdp-firewall', 'win-rdp-rights'], ticket: 'Remote Desktop to win01 fails since the new security baseline was applied.' },
      { id: 't2-win-rdp-rebuild', title: 'After the rebuild', parts: ['win-termservice-disabled', 'win-rdp-port'], ticket: 'Nobody can open a Remote Desktop session to win01 since it was rebuilt from the hardened image.' },
    ],
  },
  {
    id: 'domain', title: 'Active Directory domain',
    specs: [
      { id: 't2-dom-member', title: 'The member server', difficulty: 'intermediate', parts: ['dom-member-dns', 'dom-group-membership'], ticket: 'alice cannot log in to win01 with her domain account since win01\'s network settings were changed.' },
    ],
  },
  {
    id: 'win-kerberos', title: 'Kerberos for Windows logons',
    specs: [
      { id: 't2-winkrb-time-kdc', title: 'Time and the KDC', parts: ['krb-w32time-disabled', 'krb-dc-kdc-blocked'], ticket: 'Domain logons to win01 fail since the Windows hardening script ran on the servers.' },
    ],
  },
  {
    id: 'gpo', title: 'Group Policy',
    specs: [
      { id: 't2-gpo-filter-hardening', title: 'Filtered and hardened', parts: ['gpo-filter-token', 'gpo-sysvol-blocked'], ticket: 'Windows team: "Since CHG-2402 Server Baseline only applies to the group Baseline Servers. We added WIN01 to the group yesterday, but monitoring still cannot ping it." Last week dc01 was also hardened (SEC-152: domain controllers host no file shares).' },
    ],
  },
  {
    id: 'pfsense', title: 'Perimeter firewall (pfSense)',
    specs: [
      { id: 't2-pf-publish', title: 'Publishing the portal', parts: ['pf-forward-no-rule', 'pf-rule-source'], ticket: 'The customer portal is unreachable from the Internet since it was published through fw01.' },
    ],
  },
  {
    id: 'kubernetes', title: 'Kubernetes (k3s)',
    specs: [
      { id: 't2-k8s-service-standards', title: 'Service standards', difficulty: 'intermediate', parts: ['k8s-selector-mismatch', 'k8s-target-port'], ticket: 'Users: "http://kube01.corp.lab:30800 refuses the connection." The platform team applied two standards to every Service manifest this week: the new label naming and "all web services on port 80".' },
      { id: 't2-k8s-resource-campaign', title: 'The resource campaign', parts: ['k8s-oomkilled', 'k8s-readiness-path'], ticket: 'The inventory API is down, and the release pipeline is blocked too. This week: memory limits "right-sized" from usage graphs, and the new probe standard rolled out.' },
    ],
  },
];

/** Build the Tier 2 sets from the Tier 1 tickets. */
export function buildTier2Sets(find: (id: string) => Scenario | undefined): { id: string; title: string; scenarios: Scenario[] }[] {
  return SPECS.map((set) => ({ id: `t2-${set.id}`, title: set.title, scenarios: set.specs.map((s) => chain(s, find)) }));
}
