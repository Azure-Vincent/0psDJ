// Guided multi-step labs: the learner builds something in the simulated network
// one step at a time; each step has checks the engine evaluates against the
// current world, and the last step re-runs every check after rebooting all hosts.

import type { ConceptId } from '../scenarios/types';
import type { World } from '../types';

export interface LabCheckResult {
  ok: boolean;
  /** What was found (shown under the check). */
  detail: string;
}

export interface LabCheck {
  id: string;
  /** What must be true, phrased as a requirement. */
  description: string;
  check(world: World): LabCheckResult;
}

export interface LabStep {
  id: string;
  title: string;
  /** The outcome this step must achieve (markdown). */
  objective: string;
  /** Background: why this is done and how it works (markdown). */
  background: string;
  /** Concrete actions, in order (markdown each). */
  tasks: string[];
  hints: string[];
  checks: LabCheck[];
  /** Reference solution (used for "show solution" and to fast-forward to a step). */
  solution: { host: string; user: string; commands: string[]; answers?: string[] }[];
  /** Links into lessons and the reference library ("lesson/netif/internals", "reference?id=ip"). */
  learn: { label: string; link: string }[];
  concepts: ConceptId[];
  /** Run the checks of every previous step after rebooting all hosts (the final step). */
  afterReboot?: boolean;
}

export interface LabTerminal {
  hostId: string;
  user: string;
  label: string;
  banner: string;
}

export interface GuidedLab {
  id: string;
  title: string;
  level: 'beginner' | 'intermediate' | 'advanced';
  /** Rough time for a learner, e.g. "60–90 min". */
  duration: string;
  summary: string;
  /** The story: what you are asked to do and why. */
  brief: string;
  objectives: string[];
  /** Lessons worth doing first. */
  prerequisites: { label: string; link: string }[];
  terminals: LabTerminal[];
  steps: LabStep[];
  build(): World;
}
