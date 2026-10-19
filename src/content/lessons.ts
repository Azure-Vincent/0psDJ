import { NFTABLES_ASSESSMENT } from './nftables/assessment';
import { NFTABLES_LESSON } from './nftables/lesson';
import { SSH_ASSESSMENT } from './ssh/assessment';
import { SSH_LESSON } from './ssh/lesson';
import type { Assessment, Lesson } from './types';

/** Registry of complete lessons. Adding a lesson = adding an entry here (plus optional UI widgets). */
export const LESSONS: Lesson[] = [SSH_LESSON, NFTABLES_LESSON];

export const ASSESSMENTS: Record<string, Assessment> = {
  [SSH_ASSESSMENT.id]: SSH_ASSESSMENT,
  [NFTABLES_ASSESSMENT.id]: NFTABLES_ASSESSMENT,
};

export function getLesson(id: string): Lesson | undefined {
  return LESSONS.find((l) => l.id === id);
}
