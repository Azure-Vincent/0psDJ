// End-to-end troubleshooting case studies (A–G). Each walks from symptom to
// verified repair; those with a scenarioId can be reproduced as an
// interactive ticket in the troubleshooting lab.

import { CASES_LINUX } from './casestudies/linux';
import { CASES_PLATFORMS } from './casestudies/platforms';
import type { CaseStudy } from './types';

export const CASE_STUDIES: CaseStudy[] = [...CASES_LINUX, ...CASES_PLATFORMS].sort((a, b) => a.letter.localeCompare(b.letter));

export function getCase(id: string): CaseStudy | undefined {
  return CASE_STUDIES.find((c) => c.id === id);
}
