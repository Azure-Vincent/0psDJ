import { DHCP_ASSESSMENT, IP_ASSESSMENT, IPV6_ASSESSMENT, NAT_ASSESSMENT, TRANSPORT_ASSESSMENT, VLAN_ASSESSMENT } from './network/assessments';
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
import { DOCKER_ASSESSMENT, DOCKER_LESSON } from './ops/docker';
import { RECOVERY_ASSESSMENT, RECOVERY_LESSON } from './ops/recovery';
import { WINDOWS_RDP_ASSESSMENT, WINDOWS_RDP_LESSON } from './ops/windowsRdp';
import { NAT_GUIDE } from './guides/nat';
import { IPV6_GUIDE } from './guides/ipv6';
import { NFTABLES_GUIDE } from './guides/nftables';
import { PFSENSE_ASSESSMENT, PFSENSE_LESSON } from './ops/pfsense';
import type { Assessment, Lesson } from './types';

/** Registry of complete lessons. Adding a lesson = adding an entry here (plus optional UI widgets). */
export const LESSONS: Lesson[] = [
  { ...IP_LESSON, guide: IPNET_GUIDE, caseStudyIds: ['linux-no-internet'], objectives: ['N10-009:1.1', 'N10-009:1.7', 'N10-009:2.1', 'N10-009:5.3', '200-301:1.6', '200-301:3.1', '200-301:3.2', '200-301:3.3'] },
  { ...TRANSPORT_LESSON, guide: TRANSPORT_GUIDE, caseStudyIds: ['shared-dependency'], objectives: ['N10-009:1.4', 'N10-009:3.4', 'N10-009:5.3', '200-301:1.5', '200-301:4.3'] },
  { ...DHCP_LESSON, guide: DHCP_GUIDE, objectives: ['N10-009:3.4', 'N10-009:5.3', '200-301:4.3', '200-301:4.6'] },
  { ...NAT_LESSON, guide: NAT_GUIDE, caseStudyIds: ['linux-no-internet'], objectives: ['N10-009:1.7', '200-301:1.7', '200-301:4.1'] }, { ...VLAN_LESSON, guide: VLAN_GUIDE, objectives: ['N10-009:2.2', '200-301:1.13', '200-301:2.1', '200-301:2.2'] },
  { ...IPV6_LESSON, guide: IPV6_GUIDE, objectives: ['N10-009:3.4', '200-301:1.8', '200-301:1.9', '200-301:3.3'] },
  { ...SSH_LESSON, guide: SSH_GUIDE, caseStudyIds: ['ssh-refused'], objectives: ['N10-009:3.5', 'N10-009:5.3', '200-301:4.8', '200-301:2.8'] },
  { ...NFTABLES_LESSON, guide: NFTABLES_GUIDE, caseStudyIds: ['shared-dependency', 'ssh-refused'], objectives: ['N10-009:4.3', 'N10-009:5.3', '200-301:5.6'] },
  PFSENSE_LESSON, WINDOWS_RDP_LESSON, AD_KERBEROS_LESSON, DOCKER_LESSON,
  SYSTEMD_LESSON, NETOPS_LESSON, RECOVERY_LESSON];

export const ASSESSMENTS: Record<string, Assessment> = {
  [SSH_ASSESSMENT.id]: SSH_ASSESSMENT,
  [NFTABLES_ASSESSMENT.id]: NFTABLES_ASSESSMENT,
  [IP_ASSESSMENT.id]: IP_ASSESSMENT,
  [TRANSPORT_ASSESSMENT.id]: TRANSPORT_ASSESSMENT,
  [DHCP_ASSESSMENT.id]: DHCP_ASSESSMENT,
  [NAT_ASSESSMENT.id]: NAT_ASSESSMENT,
  [VLAN_ASSESSMENT.id]: VLAN_ASSESSMENT,
  [IPV6_ASSESSMENT.id]: IPV6_ASSESSMENT,
  [PFSENSE_ASSESSMENT.id]: PFSENSE_ASSESSMENT,
  [SYSTEMD_ASSESSMENT.id]: SYSTEMD_ASSESSMENT,
  [NETOPS_ASSESSMENT.id]: NETOPS_ASSESSMENT,
  [AD_KERBEROS_ASSESSMENT.id]: AD_KERBEROS_ASSESSMENT,
  [DOCKER_ASSESSMENT.id]: DOCKER_ASSESSMENT,
  [RECOVERY_ASSESSMENT.id]: RECOVERY_ASSESSMENT,
  [WINDOWS_RDP_ASSESSMENT.id]: WINDOWS_RDP_ASSESSMENT,
};

export function getLesson(id: string): Lesson | undefined {
  return LESSONS.find((l) => l.id === id);
}
