// Reusing the troubleshooting tickets inside integrated labs: a ticket's
// setup is a realistic fault, its goals and constraints are the checks that
// prove a repair (and reject the tempting wrong fixes), and its root causes,
// hints and explanation feed the diagnosis. Existing service-lab steps are
// reused the same way, so every lab runs on the same simulation.

import { ALL_SCENARIOS } from '../../scenarios';
import { checkGoal } from '../../scenarios/engine';
import type { ConceptId, Scenario } from '../../scenarios/types';
import { lastLines, NO, OK } from '../engine';
import type { GuidedLab, LabCheck, LabFault, LabStep } from '../types';

const WINDOWS = /^(win01|dc01)$/;

function ticket(id: string): Scenario {
  const s = ALL_SCENARIOS.find((x) => x.id === id);
  if (!s) throw new Error(`unknown ticket ${id}`);
  return s;
}

/** A ticket's goals (all, or the ones listed) as lab checks. */
export function ticketGoalChecks(id: string, which?: number[]): LabCheck[] {
  const s = ticket(id);
  return s.goals.filter((_g, i) => !which || which.includes(i)).map((g, i) => ({
    id: `${id}-goal-${i}`,
    description: g.description,
    check(world) {
      const r = checkGoal(world, g);
      return r.ok ? OK('Works.') : NO(lastLines(r) || 'Does not work yet.');
    },
  }));
}

/** A ticket's required constraints (the tempting wrong fixes it rejects) as lab checks. */
export function ticketConstraintChecks(id: string): LabCheck[] {
  return ticket(id).constraints.filter((c) => c.required).map((c) => ({
    id: `${id}-${c.id}`,
    description: c.description,
    check(world) {
      const r = c.check(world);
      return r.ok ? OK(r.message) : NO(r.message);
    },
  }));
}

export function ticketSolution(id: string): LabStep['solution'] {
  return ticket(id).solution.map((x) => ({ host: x.host, user: x.user ?? (WINDOWS.test(x.host) ? 'Administrator' : 'root'), commands: x.commands }));
}

/** Break a world the way the ticket does. */
export function applyTicket(world: Parameters<Scenario['setup']>[0], id: string): void {
  ticket(id).setup(world);
}

/** A ticket as the incident of an integrated lab (title and report can be adapted to the lab's story). */
export function ticketFault(id: string, opts: { title?: string; report?: string } = {}): LabFault {
  const s = ticket(id);
  return {
    title: opts.title ?? s.title,
    report: opts.report ?? s.ticket,
    inject: (w) => s.setup(w),
    rootCauses: s.rootCauses,
    candidates: [...new Set([...s.rootCauses, ...s.candidates])],
    hints: s.hints,
    checks: [...ticketGoalChecks(id), ...ticketConstraintChecks(id)],
    solution: ticketSolution(id),
    explanation: { rootCause: s.explanation.rootCause, evidence: s.explanation.evidence, lesson: s.explanation.prevention },
    concepts: s.concepts,
  };
}

/** Several faults at once (a change window, a bad day): every root cause must be found. */
export function combinedFault(title: string, report: string, faults: LabFault[]): LabFault {
  return {
    title,
    report,
    inject: (w) => { for (const f of faults) f.inject(w); },
    rootCauses: [...new Set(faults.flatMap((f) => f.rootCauses))],
    candidates: [...new Set(faults.flatMap((f) => f.candidates))],
    hints: faults.flatMap((f) => f.hints.slice(0, 2)),
    checks: faults.flatMap((f) => f.checks),
    solution: faults.flatMap((f) => f.solution),
    explanation: {
      rootCause: faults.map((f) => f.explanation.rootCause).join(' '),
      evidence: faults.map((f) => f.explanation.evidence).join(' '),
      lesson: faults.map((f) => f.explanation.lesson).join(' '),
    },
    concepts: [...new Set(faults.flatMap((f) => f.concepts))] as ConceptId[],
  };
}

/**
 * A "restore this service" step from a ticket: the checks are the ticket's
 * goals (optionally a subset) and constraints; the reference solution is the
 * ticket's. The objective and background are the lab's own words, so they
 * teach the dependency without giving the cause away.
 */
export function ticketStep(id: string, s: Omit<LabStep, 'checks' | 'solution' | 'hints'> & { goals?: number[]; hints?: string[] }): LabStep {
  const t = ticket(id);
  const { goals, ...rest } = s;
  return {
    ...rest,
    hints: s.hints ?? t.hints,
    checks: [...ticketGoalChecks(id, goals), ...ticketConstraintChecks(id)],
    solution: ticketSolution(id),
  };
}

/** Reuse a step of a service lab (same checks and reference solution), optionally with explained commands or other changes. */
export function reuseStep(lab: GuidedLab, id: string, extra: Partial<LabStep> = {}): LabStep {
  const s = lab.steps.find((x) => x.id === id);
  if (!s) throw new Error(`${lab.id} has no step ${id}`);
  return { ...s, ...extra };
}
