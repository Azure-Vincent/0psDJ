import { DHCP_ASSESSMENT, IP_ASSESSMENT, IPV6_ASSESSMENT, MTU_ASSESSMENT, NAT_ASSESSMENT, NETIF_ASSESSMENT, TLS_ASSESSMENT, TRANSPORT_ASSESSMENT, VLAN_ASSESSMENT } from './network/assessments';
import { TLS_LESSON } from './network/tlsLesson';
import { MTU_LESSON } from './network/mtuLesson';
import { TLS_GUIDE } from './guides/tls';
import { MTU_GUIDE } from './guides/mtu';
import { NETIF_LESSON } from './network/netifLesson';
import { NETIF_GUIDE } from './guides/netif';
import { IPV6_LESSON } from './network/ipv6Lesson';
import { VLAN_LESSON } from './network/vlanLesson';
import { DHCP_LESSON } from './network/dhcpLesson';
import { NAT_LESSON } from './network/natLesson';
import { IP_LESSON } from './network/ipLesson';
import { TRANSPORT_LESSON } from './network/transportLesson';
import { NFTABLES_ASSESSMENT } from './nftables/assessment';
import { NFTABLES_LESSON } from './nftables/lesson';
import { SSH_ASSESSMENT } from './ssh/assessment';
import { SSH_LESSON } from './ssh/lesson';
import { SSH_GUIDE } from './guides/ssh';
import { VLAN_GUIDE } from './guides/vlan';
import { IPNET_GUIDE } from './guides/ipnet';
import { TRANSPORT_GUIDE } from './guides/transport';
import { DHCP_GUIDE } from './guides/dhcp';
import { SYSTEMD_ASSESSMENT, SYSTEMD_LESSON } from './ops/systemd';
import { NETOPS_ASSESSMENT, NETOPS_LESSON } from './ops/netops';
import { AD_KERBEROS_ASSESSMENT, AD_KERBEROS_LESSON } from './ops/adKerberos';
import { KERBEROS_LESSON } from './kerberos/lesson';
import { KERBEROS_ASSESSMENT } from './kerberos/assessment';
import { DOCKER_ASSESSMENT, DOCKER_LESSON } from './ops/docker';
import { RECOVERY_ASSESSMENT, RECOVERY_LESSON } from './ops/recovery';
import { WINDOWS_RDP_ASSESSMENT, WINDOWS_RDP_LESSON } from './ops/windowsRdp';
import { NAT_GUIDE } from './guides/nat';
import { IPV6_GUIDE } from './guides/ipv6';
import { NFTABLES_GUIDE } from './guides/nftables';
import { PFSENSE_ASSESSMENT, PFSENSE_LESSON } from './ops/pfsense';
import { WEBPROXY_ASSESSMENT, WEBPROXY_LESSON } from './ops/webproxy';
import { NTP_ASSESSMENT, NTP_LESSON } from './ops/ntp';
import { LOGGING_ASSESSMENT, LOGGING_LESSON } from './ops/logging';
import { NFS_ASSESSMENT, NFS_LESSON } from './ops/nfs';
import { SMB_ASSESSMENT, SMB_LESSON } from './ops/smb';
import { EMAIL_ASSESSMENT, EMAIL_LESSON } from './ops/email';
import { DATABASE_ASSESSMENT, DATABASE_LESSON } from './ops/database';
import { BACKUP_ASSESSMENT, BACKUP_LESSON } from './ops/backup';
import { MONITORING_ASSESSMENT, MONITORING_LESSON } from './ops/monitoring';
import { IDENTITY_ASSESSMENT, IDENTITY_LESSON } from './ops/identity';
import { GPO_ASSESSMENT, GPO_LESSON } from './ops/gpo';
import { WINDOWS_FIREWALL_ASSESSMENT, WINDOWS_FIREWALL_LESSON } from './ops/windowsFirewall';
import { PRIMERS } from './primers';
import type { Assessment, Lesson } from './types';

/** Registry of complete lessons. Adding a lesson = adding an entry here (plus optional UI widgets). */
export const LESSONS: Lesson[] = [
  { ...IP_LESSON, guide: IPNET_GUIDE, caseStudyIds: ['linux-no-internet'] },
  { ...TRANSPORT_LESSON, guide: TRANSPORT_GUIDE, caseStudyIds: ['shared-dependency'] },
  { ...DHCP_LESSON, guide: DHCP_GUIDE },
  { ...NAT_LESSON, guide: NAT_GUIDE, caseStudyIds: ['linux-no-internet'] }, { ...VLAN_LESSON, guide: VLAN_GUIDE },
  { ...IPV6_LESSON, guide: IPV6_GUIDE },
  { ...NETIF_LESSON, guide: NETIF_GUIDE },
  { ...MTU_LESSON, guide: MTU_GUIDE },
  { ...TLS_LESSON, guide: TLS_GUIDE },
  { ...SSH_LESSON, guide: SSH_GUIDE, caseStudyIds: ['ssh-refused'] },
  { ...NFTABLES_LESSON, guide: NFTABLES_GUIDE, caseStudyIds: ['shared-dependency', 'ssh-refused'] },
  PFSENSE_LESSON, WINDOWS_FIREWALL_LESSON, WINDOWS_RDP_LESSON, AD_KERBEROS_LESSON, KERBEROS_LESSON, DOCKER_LESSON,
  SYSTEMD_LESSON, NETOPS_LESSON, RECOVERY_LESSON, WEBPROXY_LESSON, NTP_LESSON, LOGGING_LESSON, NFS_LESSON, SMB_LESSON, EMAIL_LESSON, DATABASE_LESSON, BACKUP_LESSON, MONITORING_LESSON, IDENTITY_LESSON, GPO_LESSON];

export const ASSESSMENTS: Record<string, Assessment> = {
  [SSH_ASSESSMENT.id]: SSH_ASSESSMENT,
  [NFTABLES_ASSESSMENT.id]: NFTABLES_ASSESSMENT,
  [IP_ASSESSMENT.id]: IP_ASSESSMENT,
  [TRANSPORT_ASSESSMENT.id]: TRANSPORT_ASSESSMENT,
  [DHCP_ASSESSMENT.id]: DHCP_ASSESSMENT,
  [NAT_ASSESSMENT.id]: NAT_ASSESSMENT,
  [VLAN_ASSESSMENT.id]: VLAN_ASSESSMENT,
  [IPV6_ASSESSMENT.id]: IPV6_ASSESSMENT,
  [TLS_ASSESSMENT.id]: TLS_ASSESSMENT,
  [MTU_ASSESSMENT.id]: MTU_ASSESSMENT,
  [NETIF_ASSESSMENT.id]: NETIF_ASSESSMENT,
  [PFSENSE_ASSESSMENT.id]: PFSENSE_ASSESSMENT,
  [SYSTEMD_ASSESSMENT.id]: SYSTEMD_ASSESSMENT,
  [NETOPS_ASSESSMENT.id]: NETOPS_ASSESSMENT,
  [AD_KERBEROS_ASSESSMENT.id]: AD_KERBEROS_ASSESSMENT,
  [KERBEROS_ASSESSMENT.id]: KERBEROS_ASSESSMENT,
  [DOCKER_ASSESSMENT.id]: DOCKER_ASSESSMENT,
  [RECOVERY_ASSESSMENT.id]: RECOVERY_ASSESSMENT,
  [WINDOWS_RDP_ASSESSMENT.id]: WINDOWS_RDP_ASSESSMENT,
  [WEBPROXY_ASSESSMENT.id]: WEBPROXY_ASSESSMENT,
  [NTP_ASSESSMENT.id]: NTP_ASSESSMENT,
  [LOGGING_ASSESSMENT.id]: LOGGING_ASSESSMENT,
  [NFS_ASSESSMENT.id]: NFS_ASSESSMENT,
  [SMB_ASSESSMENT.id]: SMB_ASSESSMENT,
  [EMAIL_ASSESSMENT.id]: EMAIL_ASSESSMENT,
  [DATABASE_ASSESSMENT.id]: DATABASE_ASSESSMENT,
  [BACKUP_ASSESSMENT.id]: BACKUP_ASSESSMENT,
  [MONITORING_ASSESSMENT.id]: MONITORING_ASSESSMENT,
  [IDENTITY_ASSESSMENT.id]: IDENTITY_ASSESSMENT,
  [GPO_ASSESSMENT.id]: GPO_ASSESSMENT,
  [WINDOWS_FIREWALL_ASSESSMENT.id]: WINDOWS_FIREWALL_ASSESSMENT,
};

// Attach the beginner primers (plain language and worked examples) to their lessons.
for (const l of LESSONS) l.primer ??= PRIMERS[l.id];

export function getLesson(id: string): Lesson | undefined {
  return LESSONS.find((l) => l.id === id);
}
