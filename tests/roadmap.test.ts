// The study roadmap: every lesson and lab is on it exactly once, and every lab
// comes after the lessons it relies on.

import { describe, expect, it } from 'vitest';
import { LESSONS, getLesson } from '../src/content/lessons';
import { ROADMAP, ROADMAP_STEPS } from '../src/content/roadmap';
import { GUIDED_LABS, findLab } from '../src/engine/labs';
import { emptyProgress } from '../src/learning/progress';
import { currentStepIndex, roadmapCounts, viewStep } from '../src/ui/roadmapProgress';
import { SECTIONS } from '../src/ui/sections';

const pos = (kind: 'lesson' | 'lab', id: string) => ROADMAP_STEPS.findIndex(({ step }) => step.kind === kind && step.id === id);

describe('roadmap', () => {
  it('lists every lesson and every guided lab exactly once, and nothing else', () => {
    const lessons = ROADMAP_STEPS.flatMap(({ step }) => (step.kind === 'lesson' ? [step.id] : []));
    const labs = ROADMAP_STEPS.flatMap(({ step }) => (step.kind === 'lab' ? [step.id] : []));
    expect([...lessons].sort()).toEqual(LESSONS.map((l) => l.id).sort());
    expect([...labs].sort()).toEqual(GUIDED_LABS.map((l) => l.id).sort());
    for (const id of lessons) expect(getLesson(id), id).toBeDefined();
    for (const id of labs) expect(findLab(id), id).toBeDefined();
  });

  it('places every lab after the lessons it builds on', () => {
    for (const lab of GUIDED_LABS) {
      const at = pos('lab', lab.id);
      const needs = [
        ...lab.prerequisites.map((p) => /^lesson\/([^/]+)/.exec(p.link)?.[1]).filter((x): x is string => !!x),
        ...(lab.integrated?.after ?? []),
      ];
      for (const l of needs) expect(pos('lesson', l), `${lab.id} needs ${l} first`).toBeLessThan(at);
    }
  });

  it('ends with the complete-deployment integrated lab as the last lab', () => {
    const last = ROADMAP_STEPS.filter(({ step }) => step.kind === 'lab').pop()!;
    expect(last.step.kind === 'lab' && last.step.id).toBe('ilab10');
  });

  it('every phase has a goal, a reason and steps with reasons', () => {
    for (const ph of ROADMAP) {
      expect(ph.goal.length && ph.why.length && ph.steps.length, ph.id).toBeTruthy();
      for (const s of ph.steps) expect(s.why.length, `${ph.id}`).toBeGreaterThan(10);
    }
  });

  it('starts a new learner at the first lesson and moves on as steps are completed', () => {
    const p = emptyProgress();
    expect(currentStepIndex(p)).toBe(0);
    expect(viewStep(p, ROADMAP_STEPS[0].step)).toMatchObject({ status: 'todo', link: 'lesson/ipnet/what' });
    p.lessons.ipnet = { visited: ['what', 'internals'], lastSection: 'internals' };
    expect(viewStep(p, ROADMAP_STEPS[0].step)).toMatchObject({ status: 'started', link: 'lesson/ipnet/visualize' });
    expect(currentStepIndex(p)).toBe(0);
    p.lessons.ipnet = { visited: SECTIONS.map((s) => s.id), lastSection: 'assess' };
    expect(currentStepIndex(p)).toBe(1);
    expect(roadmapCounts(p).done).toBe(1);
    // A finished lab counts; an unfinished one is "started".
    p.labs.lab1 = { completed: ['a'], assisted: [], startedAt: 1 };
    expect(viewStep(p, ROADMAP_STEPS[pos('lab', 'lab1')].step).status).toBe('started');
    p.labs.lab1 = { ...p.labs.lab1, finishedAt: 2 };
    expect(viewStep(p, ROADMAP_STEPS[pos('lab', 'lab1')].step).status).toBe('done');
  });
});
