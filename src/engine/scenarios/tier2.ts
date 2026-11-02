// Tier 2 tickets: chained incidents built from Tier 1 tickets of the same
// area. Every part's fault is applied to the same lab, in order, so the first
// symptom hides the next: fixing one fault changes the symptom instead of
// ending the outage. The goals are those of all parts, the diagnosis must name
// every root cause, the constraints of all parts apply, and the reference
// solution is the parts' solutions in order.

import type { ConceptId, Constraint, Goal, Scenario } from './types';

export interface ChainSpec {
  id: string;
  title: string;
  /** The ticket as the user reports it (the first symptom only). */
  ticket: string;
  /** Tier 1 ticket ids, in the order their faults were introduced. */
  parts: string[];
  difficulty?: Scenario['difficulty'];
  /** Extra briefing line (for instance, what changed recently). */
  context?: string;
}

const uniqBy = <T>(xs: T[], key: (x: T) => string) => [...new Map(xs.map((x) => [key(x), x])).values()];

export function chain(spec: ChainSpec, find: (id: string) => Scenario | undefined): Scenario {
  const parts = spec.parts.map((id) => {
    const s = find(id);
    if (!s) throw new Error(`tier 2 ${spec.id}: unknown part ${id}`);
    return s;
  });
  const first = parts[0];
  const goals = uniqBy<Goal>(parts.flatMap((p) => p.goals), (g) => JSON.stringify(g));
  const constraints = uniqBy<Constraint>(parts.flatMap((p) => p.constraints), (c) => c.id);
  const rootCauses = [...new Set(parts.flatMap((p) => p.rootCauses))];
  const candidates = [...new Set([...parts.flatMap((p) => p.candidates), ...rootCauses])];
  const acceptable = Object.assign({}, ...parts.map((p) => p.acceptable ?? {}));
  for (const c of rootCauses) delete acceptable[c];
  // Feedback for a wrong pick: the first part's explanation of why it does not fit, unless another part has that cause as a root cause.
  const feedback: Record<string, string> = {};
  for (const p of parts) for (const [k, v] of Object.entries(p.feedback ?? {})) if (!rootCauses.includes(k) && !feedback[k]) feedback[k] = v;
  const terminals = uniqBy(parts.flatMap((p) => p.terminals ?? []), (t) => `${t.hostId}:${t.user}:${t.kind ?? ''}`);
  return {
    id: spec.id,
    title: spec.title,
    difficulty: spec.difficulty ?? 'advanced',
    ticket: spec.ticket,
    briefing: [...new Set([...first.briefing, ...parts.slice(1).flatMap((p) => p.briefing.filter((b) => !first.briefing.includes(b)))])].concat(
      spec.context ? [spec.context] : [],
      [`This is a chained incident: ${parts.length === 2 ? 'two faults were' : `${parts.length} faults were`} introduced one after the other. Fixing one changes the symptom; keep going until every goal passes, and name every root cause in the diagnosis.`],
    ),
    goals,
    setup(world) {
      for (const p of parts) p.setup(world);
    },
    rootCauses,
    acceptable: Object.keys(acceptable).length ? acceptable : undefined,
    candidates,
    feedback,
    clientUser: first.clientUser,
    terminals: terminals.length ? terminals : undefined,
    hints: [
      'Start from the symptom you can see now and find its cause, exactly as for a single fault. Write down the evidence: after the first fix the symptom will change.',
      ...parts.map((p, i) => `${i === 0 ? 'First fault' : 'Next'}: ${p.hints[0]}`),
      'After each fix, test again from the user\'s side and compare the new symptom with the old one: a different error means progress, not a failed fix.',
      ...parts.map((p) => p.hints.at(-1)!),
    ],
    solution: parts.flatMap((p) => p.solution),
    explanation: {
      rootCause: parts.map((p, i) => `(${i + 1}) ${p.explanation.rootCause}`).join(' '),
      manifestation: `${parts[0].explanation.manifestation} Once that was fixed, the next fault showed: ${parts.slice(1).map((p) => p.explanation.manifestation).join(' Then: ')}`,
      evidence: parts.map((p, i) => `(${i + 1}) ${p.explanation.evidence}`).join(' '),
      prevention: [...new Set(parts.map((p) => p.explanation.prevention))].join(' '),
    },
    constraints,
    concepts: [...new Set(parts.flatMap((p) => p.concepts))] as ConceptId[],
    tier: 2,
    parts: spec.parts,
  };
}
