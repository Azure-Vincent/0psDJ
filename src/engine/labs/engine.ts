// Running guided-lab checks: commands run on a copy of the world, so checking
// never changes the learner's lab.

import { rebootAll } from '../scenarios/engine';
import { Shell } from '../shell/shell';
import type { World } from '../types';
import type { GuidedLab, LabCheck, LabCheckResult, LabStep } from './types';

export const OK = (detail: string): LabCheckResult => ({ ok: true, detail });
export const NO = (detail: string): LabCheckResult => ({ ok: false, detail });

/** The last two non-empty lines of a goal check (the part worth showing under a failed check). */
export const lastLines = (r: { lines: string[] }): string => r.lines.filter(Boolean).slice(-2).join(' ');

/**
 * A file's contents as a printf command line (reference solutions): escapes
 * backslashes, % (printf directives), single quotes (the shell) and newlines.
 */
export function printfTo(text: string, path: string, append = false): string {
  const body = text.replace(/\\/g, '\\\\').replace(/%/g, '%%').replace(/'/g, "'\\''").replace(/\n/g, '\\n');
  return `printf '${body}' ${append ? '>>' : '>'} ${path}`;
}

/** Run a command line on a copy of the world and return its output and exit code. */
export function probe(world: World, host: string, user: string, line: string): { output: string; code: number } {
  let w = structuredClone(world);
  const home = w.hosts[host].users[user]?.home ?? '/';
  const sh = new Shell(() => w, (n) => (w = n), { hostId: host, user, cwd: home });
  const r = sh.execute(line);
  return { output: r.output, code: r.code };
}

export interface CheckOutcome extends LabCheckResult {
  id: string;
  description: string;
  /** For the reboot step: the step the check belongs to. */
  step?: string;
}

function run(c: LabCheck, world: World, step?: string): CheckOutcome {
  try {
    return { id: c.id, description: c.description, step, ...c.check(world) };
  } catch (e) {
    return { id: c.id, description: c.description, step, ok: false, detail: `check failed to run: ${(e as Error).message}` };
  }
}

/**
 * Evaluate one step. The final step (afterReboot) reboots every host on a copy
 * of the world and re-runs the checks of all earlier steps.
 */
export function checkStep(world: World, lab: GuidedLab, step: LabStep): { passed: boolean; results: CheckOutcome[] } {
  if (step.afterReboot) {
    const rebooted = rebootAll(world);
    const results = lab.steps.filter((s) => !s.afterReboot).flatMap((s) => s.checks.map((c) => run(c, rebooted, s.title)));
    return { passed: results.every((r) => r.ok), results };
  }
  const results = step.checks.map((c) => run(c, world));
  return { passed: results.every((r) => r.ok), results };
}

/** Apply a step's reference solution to the world (fast-forward, or "do it for me"). */
export function applySolution(world: World, step: LabStep): World {
  let w = world;
  for (const s of step.solution) {
    const home = w.hosts[s.host].users[s.user]?.home ?? '/';
    const sh = new Shell(() => w, (n) => (w = n), { hostId: s.host, user: s.user, cwd: home });
    for (const c of s.commands) sh.execute(c, s.answers ?? []);
  }
  return step.gui ? step.gui.apply(w) : w;
}
