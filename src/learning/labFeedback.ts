// Feedback at the end of an integrated lab: which subjects the learner showed
// they understand (steps done without help, a first-time diagnosis, review
// answers) and which to review (with links to the lessons), plus remarks on
// the troubleshooting process itself.

import { CONCEPTS } from '../content/concepts';
import type { GuidedLab } from '../engine/labs/types';
import type { ConceptId } from '../engine/scenarios/types';
import type { LabProgress } from './progress';

export interface ConceptFeedback { id: ConceptId; title: string; status: 'shown' | 'review'; evidence: string[]; link: string }

export interface LabFeedback {
  concepts: ConceptFeedback[];
  process: { ok: boolean; text: string }[];
  score: { steps: number; stepsTotal: number; review: number; reviewTotal: number; diagnosis: boolean | null; repaired: boolean };
}

export function labFeedback(lab: GuidedLab, p: LabProgress | undefined): LabFeedback {
  const info = lab.integrated;
  const completed = new Set(p?.completed ?? []);
  const assisted = new Set(p?.assisted ?? []);
  const good = new Map<ConceptId, string[]>();
  const bad = new Map<ConceptId, string[]>();
  const add = (m: Map<ConceptId, string[]>, c: ConceptId, why: string) => m.set(c, [...(m.get(c) ?? []), why]);

  for (const s of lab.steps) {
    for (const c of s.concepts) {
      if (completed.has(s.id) && !assisted.has(s.id)) add(good, c, `"${s.title}" done without the reference solution`);
      else if (assisted.has(s.id)) add(bad, c, `"${s.title}" done with "do it for me"`);
    }
  }
  const diag = p?.fault?.diagnosis;
  if (info && diag) {
    for (const c of info.fault.concepts) {
      if (diag.correct && diag.attempts === 1) add(good, c, 'root cause of the incident found at the first attempt');
      else add(bad, c, diag.correct ? `root cause of the incident found after ${diag.attempts} attempts` : 'root cause of the incident not found yet');
    }
  }
  for (const q of info?.review ?? []) {
    const a = p?.review?.[q.id];
    if (a === undefined) continue;
    for (const c of q.concepts) {
      if (a === q.answer) add(good, c, `review question answered correctly: "${q.question.slice(0, 60)}${q.question.length > 60 ? '…' : ''}"`);
      else add(bad, c, `review question missed: "${q.question.slice(0, 60)}${q.question.length > 60 ? '…' : ''}"`);
    }
  }
  const all = [...new Set([...good.keys(), ...bad.keys()])];
  const concepts: ConceptFeedback[] = all.map((id): ConceptFeedback => {
    const g = good.get(id) ?? [];
    const b = bad.get(id) ?? [];
    return { id, title: CONCEPTS[id]?.title ?? id, status: b.length > 0 && b.length >= g.length ? 'review' : 'shown', evidence: [...g, ...b], link: CONCEPTS[id]?.review ?? '' };
  }).sort((a, b) => (a.status === b.status ? a.title.localeCompare(b.title) : a.status === 'review' ? -1 : 1));

  const process: LabFeedback['process'] = [];
  const f = p?.fault;
  if (f) {
    const before = f.commandsBefore ?? 0;
    if (f.diagnosis) {
      process.push(before >= 3
        ? { ok: true, text: `You gathered evidence before deciding: ${before} diagnostic command${before === 1 ? '' : 's'} before your diagnosis.` }
        : { ok: false, text: `Only ${before} diagnostic command${before === 1 ? '' : 's'} before your diagnosis. Look first (status, logs, connectivity tests, configuration), then decide.` });
    }
    const r = f.restartsBefore ?? 0;
    if (r > 1) process.push({ ok: false, text: `${r} restarts or reboots before the diagnosis. A restart hides evidence and rarely fixes a configuration or dependency problem; find out why it failed first.` });
    else if (f.diagnosis) process.push({ ok: true, text: r === 0 ? 'No restarts before the diagnosis: the evidence stayed intact.' : 'One restart before the diagnosis: fine if it was to test a hypothesis.' });
    if (f.diagnosis && !f.diagnosis.correct) process.push({ ok: false, text: 'The diagnosis is not right yet: compare the evidence with each cause\'s signature.' });
    if (f.diagnosis?.correct) process.push({ ok: f.diagnosis.attempts === 1, text: f.diagnosis.attempts === 1 ? 'Root cause identified at the first attempt.' : `Root cause identified after ${f.diagnosis.attempts} attempts: note which evidence would have told the causes apart.` });
    if (f.repairedAt) process.push({ ok: true, text: 'The repair was verified, including after a reboot of every machine.' });
    if (f.solutionShown && !f.repairedAt) process.push({ ok: false, text: 'The reference repair was opened before the repair was verified: next time, try to repair from your own diagnosis first.' });
    if ((f.hints ?? 0) > 0) process.push({ ok: (f.hints ?? 0) <= 1, text: `${f.hints} hint${f.hints === 1 ? '' : 's'} used during troubleshooting.` });
  }
  const tools = p?.tools ?? [];
  if (tools.length) process.push({ ok: tools.length >= 4, text: `Tools you used: ${tools.slice(0, 14).join(', ')}${tools.length > 14 ? ' …' : ''}.` });

  const review = info?.review ?? [];
  return {
    concepts,
    process,
    score: {
      steps: lab.steps.filter((s) => completed.has(s.id) && !assisted.has(s.id)).length,
      stepsTotal: lab.steps.length,
      review: review.filter((q) => p?.review?.[q.id] === q.answer).length,
      reviewTotal: review.length,
      diagnosis: diag ? diag.correct && diag.attempts === 1 : null,
      repaired: !!f?.repairedAt,
    },
  };
}
