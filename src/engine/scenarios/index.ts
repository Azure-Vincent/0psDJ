import { FIREWALL_SCENARIOS } from './firewallScenarios';
import { NETWORK_SCENARIOS } from './networkScenarios';
import { DHCP_NAT_SCENARIOS } from './dhcpNatScenarios';
import { SSH_SCENARIOS } from './sshScenarios';
import { VLAN_IPV6_SCENARIOS } from './vlanIpv6Scenarios';
import { CASE_SCENARIOS } from './caseScenarios';
import { DHCP_RELAY_SCENARIOS } from './dhcpRelayScenarios';
import { NETIF_SCENARIOS } from './netifScenarios';
import { DHCPV6_SCENARIOS } from './dhcpv6Scenarios';
import { MTU_SCENARIOS, TLS_SCENARIOS } from './tlsMtuScenarios';
import { KRB_SCENARIOS } from './krbScenarios';
import { WIN_SCENARIOS } from './winScenarios';
import { DOMAIN_SCENARIOS } from './domainScenarios';
import { PF_SCENARIOS } from './pfScenarios';
import { SCORING_REACH_SCENARIOS } from './scoringReachScenarios';
import { SCORING_WEB_DNS_SCENARIOS } from './scoringWebDnsScenarios';
import { SCORING_SCENARIOS } from './scoringScenarios';
import { CONTAINER_SCENARIOS } from './containerScenarios';
import { PROXY_SCENARIOS } from './proxyScenarios';
import { NTP_SCENARIOS } from './ntpScenarios';
import { LOG_SCENARIOS } from './logScenarios';
import { NFS_SCENARIOS } from './nfsScenarios';
import { SMB_SCENARIOS } from './smbScenarios';
import { GPO_SCENARIOS } from './gpoScenarios';
import { WIN_KRB_SCENARIOS } from './winKrbScenarios';
import { WFW_SCENARIOS } from './wfwScenarios';
import { MAIL_SCENARIOS } from './mailScenarios';
import { DB_SCENARIOS } from './dbScenarios';
import { BACKUP_SCENARIOS } from './backupScenarios';
import type { Scenario } from './types';

/** Every troubleshooting scenario, grouped by the lesson that introduces it. */
export const SCENARIO_SETS: { id: string; title: string; scenarios: Scenario[] }[] = [
  { id: 'network', title: 'Networking fundamentals', scenarios: NETWORK_SCENARIOS },
  { id: 'dhcp-nat', title: 'DHCP and NAT', scenarios: [...DHCP_NAT_SCENARIOS, ...DHCP_RELAY_SCENARIOS] },
  { id: 'vlan-ipv6', title: 'VLANs and IPv6', scenarios: [...VLAN_IPV6_SCENARIOS, ...DHCPV6_SCENARIOS] },
  { id: 'netif', title: 'Interfaces and virtual switches', scenarios: NETIF_SCENARIOS },
  { id: 'mtu', title: 'MTU and path MTU discovery', scenarios: MTU_SCENARIOS },
  { id: 'ssh', title: 'SSH', scenarios: SSH_SCENARIOS },
  { id: 'scoring', title: 'Scored services (competition scoring engine)', scenarios: [...SCORING_SCENARIOS, ...SCORING_REACH_SCENARIOS, ...SCORING_WEB_DNS_SCENARIOS] },
  { id: 'tls', title: 'TLS and certificates', scenarios: TLS_SCENARIOS },
  { id: 'kerberos', title: 'Kerberos and DNS service records', scenarios: KRB_SCENARIOS },
  { id: 'windows', title: 'Windows Server and Remote Desktop', scenarios: WIN_SCENARIOS },
  { id: 'windows-firewall', title: 'Windows Defender Firewall', scenarios: WFW_SCENARIOS },
  { id: 'domain', title: 'Active Directory domain', scenarios: DOMAIN_SCENARIOS },
  { id: 'gpo', title: 'Group Policy', scenarios: GPO_SCENARIOS },
  { id: 'win-kerberos', title: 'Kerberos for Windows logons', scenarios: WIN_KRB_SCENARIOS },
  { id: 'nftables', title: 'Firewalls (nftables)', scenarios: FIREWALL_SCENARIOS },
  { id: 'pfsense', title: 'Perimeter firewall (pfSense)', scenarios: PF_SCENARIOS },
  { id: 'containers', title: 'Containers (Docker)', scenarios: CONTAINER_SCENARIOS },
  { id: 'proxy', title: 'Web servers and reverse proxies', scenarios: PROXY_SCENARIOS },
  { id: 'ntp', title: 'Time synchronisation (NTP)', scenarios: NTP_SCENARIOS },
  { id: 'logging', title: 'Central logging (rsyslog)', scenarios: LOG_SCENARIOS },
  { id: 'files', title: 'File sharing (NFS and SMB)', scenarios: [...NFS_SCENARIOS, ...SMB_SCENARIOS] },
  { id: 'email', title: 'Email (Postfix and Dovecot)', scenarios: MAIL_SCENARIOS },
  { id: 'database', title: 'Databases (PostgreSQL)', scenarios: DB_SCENARIOS },
  { id: 'backup', title: 'Backups (restic, systemd timers)', scenarios: BACKUP_SCENARIOS },
  { id: 'cases', title: 'End-to-end case studies', scenarios: CASE_SCENARIOS },
];

export const ALL_SCENARIOS: Scenario[] = SCENARIO_SETS.flatMap((s) => s.scenarios);

export function findScenario(id: string): Scenario | undefined {
  return ALL_SCENARIOS.find((s) => s.id === id);
}
