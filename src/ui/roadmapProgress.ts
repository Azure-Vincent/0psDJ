// Where the learner is on the study roadmap, from their saved progress.

import { getLesson } from '../content/lessons';
import { ROADMAP_STEPS, type RoadmapStep } from '../content/roadmap';
import { findLab } from '../engine/labs';
import type { Progress } from '../learning/progress';
import { SECTIONS } from './sections';

export type StepStatus = 'done' | 'started' | 'todo';

export interface StepView {
  title: string;
  /** Short kind label: lesson, guided lab, integrated lab, practice. */
  kindLabel: string;
  /** Where "open" goes (resuming where the learner stopped). */
  link: string;
  status: StepStatus;
  /** e.g. "3 of 8 sections", "2 of 6 steps". */
  detail: string;
  /** Fraction done (0..1); practice steps have none. */
  fraction?: number;
}

export function viewStep(p: Progress, s: RoadmapStep): StepView {
  if (s.kind === 'lesson') {
    const L = getLesson(s.id);
    const visited = p.lessons[s.id]?.visited ?? [];
    const next = SECTIONS.find((x) => !visited.includes(x.id));
    const status: StepStatus = !next ? 'done' : visited.length ? 'started' : 'todo';
    return {
      title: L?.title ?? s.id,
      kindLabel: 'Lesson',
      link: `lesson/${s.id}/${next?.id ?? p.lessons[s.id]?.lastSection ?? 'what'}`,
      status,
      detail: `${visited.length} of ${SECTIONS.length} sections`,
      fraction: visited.length / SECTIONS.length,
    };
  }
  if (s.kind === 'lab') {
    const lab = findLab(s.id);
    const lp = p.labs?.[s.id];
    const done = lp?.completed.length ?? 0;
    const total = lab?.steps.length ?? 1;
    const status: StepStatus = lp?.finishedAt ? 'done' : done || lp?.fault ? 'started' : 'todo';
    return {
      title: lab?.title ?? s.id,
      kindLabel: lab?.integrated ? 'Integrated lab' : 'Guided lab',
      link: `labs/${s.id}`,
      status,
      detail: lp?.finishedAt ? 'finished' : `${done} of ${total} steps${lp?.fault ? ', incident started' : ''}`,
      fraction: lp?.finishedAt ? 1 : done / total,
    };
  }
  return { title: s.title, kindLabel: 'Practice', link: s.link, status: 'todo', detail: 'open-ended' };
}

/** The roadmap step to work on now: the first unfinished lesson or lab, in order (practice never blocks). */
export function currentStepIndex(p: Progress): number {
  const i = ROADMAP_STEPS.findIndex(({ step }) => step.kind !== 'practice' && viewStep(p, step).status !== 'done');
  return i === -1 ? ROADMAP_STEPS.length - 1 : i;
}

/** The roadmap position of a lesson or lab, if it is on the roadmap. */
export function roadmapIndexOf(kind: 'lesson' | 'lab', id: string): number {
  return ROADMAP_STEPS.findIndex(({ step }) => step.kind === kind && step.id === id);
}

export function roadmapCounts(p: Progress): { done: number; total: number } {
  const tracked = ROADMAP_STEPS.filter(({ step }) => step.kind !== 'practice');
  return { done: tracked.filter(({ step }) => viewStep(p, step).status === 'done').length, total: tracked.length };
}
