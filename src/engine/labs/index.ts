import { LAB1 } from './lab1';
import { LAB2 } from './lab2';
import { LAB3 } from './lab3';
import { LAB4 } from './lab4';
import type { GuidedLab } from './types';

/** Guided multi-step labs (the "Progressive enterprise labs" of the curriculum that are simulated). */
export const GUIDED_LABS: GuidedLab[] = [LAB1, LAB2, LAB3, LAB4];

export function findLab(id: string): GuidedLab | undefined {
  return GUIDED_LABS.find((l) => l.id === id);
}
