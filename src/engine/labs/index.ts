import { LAB1 } from './lab1';
import type { GuidedLab } from './types';

/** Guided multi-step labs (the "Progressive enterprise labs" of the curriculum that are simulated). */
export const GUIDED_LABS: GuidedLab[] = [LAB1];

export function findLab(id: string): GuidedLab | undefined {
  return GUIDED_LABS.find((l) => l.id === id);
}
