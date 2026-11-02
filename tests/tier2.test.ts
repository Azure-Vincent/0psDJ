import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { checkGoal, gradeDiagnosis } from '../src/engine/scenarios/engine';
import { ALL_SCENARIOS, SCENARIO_SETS, TIER2_SETS, findScenario } from '../src/engine/scenarios';
import { Lab } from './helpers';

const TIER2 = TIER2_SETS.flatMap((s) => s.scenarios);

describe('Tier 2 tickets', () => {
  it('are built from Tier 1 tickets of the same area, and are listed apart from Tier 1', () => {
    expect(TIER2.length).toBeGreaterThanOrEqual(15);
    const tier1 = SCENARIO_SETS.flatMap((s) => s.scenarios);
    expect(tier1.every((s) => s.tier !== 2)).toBe(true);
    for (const s of TIER2) {
      expect(s.tier).toBe(2);
      expect(s.parts!.length).toBeGreaterThanOrEqual(2);
      const areas = s.parts!.map((p) => SCENARIO_SETS.find((set) => set.scenarios.some((x) => x.id === p))?.id);
      expect(new Set(areas).size, `${s.id} mixes areas ${areas.join(', ')}`).toBe(1);
      expect(findScenario(s.id)).toBe(s);
      expect(s.rootCauses).toEqual([...new Set(s.parts!.flatMap((p) => findScenario(p)!.rootCauses))]);
    }
    expect(new Set(ALL_SCENARIOS.map((s) => s.id)).size).toBe(ALL_SCENARIOS.length);
  });

  it('naming only one of the root causes is not a correct diagnosis', () => {
    for (const s of TIER2) {
      const first = findScenario(s.parts![0])!.rootCauses;
      if (first.length === s.rootCauses.length) continue;
      const g = gradeDiagnosis(s, first);
      expect(g.correct, s.id).toBe(false);
      expect(g.missing.length).toBeGreaterThan(0);
    }
  });
});

describe.each(TIER2.map((s) => [s.id, s] as const))('Tier 2 %s', (_id, s) => {
  it('chains: after fixing only the first fault the goals still fail, with a different symptom', () => {
    const world = buildSshLab();
    s.setup(world);
    const before = s.goals.map((g) => checkGoal(world, g));
    expect(before.some((g) => !g.ok)).toBe(true);
    const lab = new Lab(world);
    for (const step of findScenario(s.parts![0])!.solution) for (const c of step.commands) lab.run(step.host, step.user ?? 'root', c);
    const mid = s.goals.map((g) => checkGoal(lab.world, g));
    expect(mid.some((g) => !g.ok), 'the first fix alone must not be enough').toBe(true);
  });

  it('every fault survives the setup: leaving out any one part\'s fix leaves the goals failing', () => {
    for (const skip of s.parts!) {
      const world = buildSshLab();
      s.setup(world);
      const lab = new Lab(world);
      for (const p of s.parts!) if (p !== skip) for (const step of findScenario(p)!.solution) for (const c of step.commands) lab.run(step.host, step.user ?? 'root', c);
      const res = s.goals.map((g) => checkGoal(lab.world, g));
      expect(res.some((g) => !g.ok), `${s.id}: without the fix for ${skip} the goals must still fail`).toBe(true);
    }
  });
});
