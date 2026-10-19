import { DHCP_ASSESSMENT, IP_ASSESSMENT, NAT_ASSESSMENT, TRANSPORT_ASSESSMENT } from './network/assessments';
import { DHCP_LESSON } from './network/dhcpLesson';
import { NAT_LESSON } from './network/natLesson';
import { IP_LESSON } from './network/ipLesson';
import { TRANSPORT_LESSON } from './network/transportLesson';
import { NFTABLES_ASSESSMENT } from './nftables/assessment';
import { NFTABLES_LESSON } from './nftables/lesson';
import { SSH_ASSESSMENT } from './ssh/assessment';
import { SSH_LESSON } from './ssh/lesson';
import type { Assessment, Lesson } from './types';

/** Registry of complete lessons. Adding a lesson = adding an entry here (plus optional UI widgets). */
export const LESSONS: Lesson[] = [IP_LESSON, TRANSPORT_LESSON, DHCP_LESSON, NAT_LESSON, SSH_LESSON, NFTABLES_LESSON];

export const ASSESSMENTS: Record<string, Assessment> = {
  [SSH_ASSESSMENT.id]: SSH_ASSESSMENT,
  [NFTABLES_ASSESSMENT.id]: NFTABLES_ASSESSMENT,
  [IP_ASSESSMENT.id]: IP_ASSESSMENT,
  [TRANSPORT_ASSESSMENT.id]: TRANSPORT_ASSESSMENT,
  [DHCP_ASSESSMENT.id]: DHCP_ASSESSMENT,
  [NAT_ASSESSMENT.id]: NAT_ASSESSMENT,
};

export function getLesson(id: string): Lesson | undefined {
  return LESSONS.find((l) => l.id === id);
}
