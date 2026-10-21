// Cross-reference integrity for the content: every id a lesson, guide, case
// study or certification objective links to must exist, and every command
// marked as runnable in the simulator must be a simulator command.

import { describe, expect, it } from 'vitest';
import { CASE_STUDIES } from '../src/content/cases';
import { CERT_EXAMS } from '../src/content/certification';
import { COMMAND_REFS } from '../src/content/commands';
import { CURRICULUM } from '../src/content/curriculum';
import { ASSESSMENTS, LESSONS, getLesson } from '../src/content/lessons';
import { FILE_REFS, PROCEDURES, REF_ENTRIES, getRef } from '../src/content/reference';
import { ALL_SCENARIOS } from '../src/engine/scenarios';
import { COMMANDS } from '../src/engine/shell/shell';

const SHELL_BUILTINS = new Set(['sudo', 'exit', 'logout', 'clear', 'true', 'false', 'help', 'which', 'type', 'for', 'echo']);
const SECTIONS = new Set(['what', 'internals', 'visualize', 'deploy', 'config', 'operate', 'troubleshoot', 'assess']);
const OBJECTIVES = new Set(CERT_EXAMS.flatMap((e) => e.domains.flatMap((d) => d.objectives.map((o) => o.id))));

/** Is an in-app route valid? */
function routeOk(link: string): string | null {
  const [path, query] = link.split('?');
  const [head, a, b] = path.split('/');
  switch (head) {
    case 'lesson': {
      const L = getLesson(a);
      if (!L) return `unknown lesson ${a}`;
      if (b && !SECTIONS.has(b)) return `unknown section ${b}`;
      if (b === 'operate' && !L.guide) return `lesson ${a} has no guide`;
      return null;
    }
    case 'troubleshoot': return !a || ALL_SCENARIOS.some((s) => s.id === a) ? null : `unknown ticket ${a}`;
    case 'cases': return !a || CASE_STUDIES.some((c) => c.id === a) ? null : `unknown case ${a}`;
    case 'reference': {
      const id = new URLSearchParams(query ?? '').get('id');
      return !id || getRef(id) ? null : `unknown reference ${id}`;
    }
    case 'packets': case 'glossary': case 'commands': case 'certification': case 'curriculum': return null;
    default: return `unknown route ${link}`;
  }
}

/** First word of every command line in a (possibly multi-line) command string. */
function commandWords(cmd: string): string[] {
  return cmd.split('\n').flatMap((line) => line.replace(/"[^"]*"|'[^']*'/g, 'Q').split(/\s*(?:&&|\|\||;|\|)\s*/)).map((part) => {
    const words = part.trim().replace(/^sudo\s+(-\S+\s+)*/, '').split(/\s+/);
    return words[0];
  }).filter((w) => w && !w.startsWith('#'));
}

describe('reference library', () => {
  it('has unique ids', () => {
    const ids = REF_ENTRIES.map((e) => e.id);
    expect(ids.filter((id, i) => ids.indexOf(id) !== i)).toEqual([]);
  });
  it('names real simulator commands', () => {
    for (const c of COMMAND_REFS) if (c.simulator) expect(COMMANDS[c.simulator.split(' ')[0]], `${c.id}: ${c.simulator}`).toBeDefined();
  });
  it('file entries link to existing commands', () => {
    for (const f of FILE_REFS) for (const r of f.relatedCommands ?? []) expect(getRef(r), `${f.id} → ${r}`).toBeDefined();
  });
  it('procedures have steps', () => {
    for (const p of PROCEDURES) expect(p.steps.length, p.id).toBeGreaterThan(1);
  });
});

describe.each(LESSONS.map((L) => [L.id, L] as const))('lesson %s', (_id, L) => {
  it('links resolve', () => {
    expect(ASSESSMENTS[L.assessmentId], 'assessment').toBeDefined();
    expect(L.deployment.length, 'deployment guides').toBeGreaterThan(0);
    for (const s of L.scenarioIds) expect(ALL_SCENARIOS.some((x) => x.id === s), `ticket ${s}`).toBe(true);
    for (const c of L.caseStudyIds ?? []) expect(CASE_STUDIES.some((x) => x.id === c), `case ${c}`).toBe(true);
    for (const o of L.objectives ?? []) expect(OBJECTIVES.has(o), `objective ${o}`).toBe(true);
    for (const r of L.guide?.refIds ?? []) expect(getRef(r), `ref ${r}`).toBeDefined();
  });
  it('marks only real simulator commands as runnable', () => {
    const sim: string[] = [];
    if (L.mode === 'reference') {
      expect(L.guide?.management.some((m) => m.tasks.some((t) => t.sim)) ?? false, 'reference lesson with sim tasks').toBe(false);
      expect(L.guide?.workflow.some((w) => w.sim) ?? false, 'reference lesson with sim workflow').toBe(false);
      expect(L.deployment.some((d) => d.steps.some((s) => s.simulated)), 'reference lesson with simulated steps').toBe(false);
    }
    for (const m of L.guide?.management ?? []) for (const t of m.tasks) if (t.sim) sim.push(t.command);
    for (const w of L.guide?.workflow ?? []) if (w.sim) sim.push(w.command);
    for (const cmd of sim) {
      for (const word of commandWords(cmd)) expect(COMMANDS[word] || SHELL_BUILTINS.has(word), `"${word}" in: ${cmd}`).toBeTruthy();
    }
  });
  it('has diagrams that fit', () => {
    const g = L.guide;
    if (!g) return;
    const ids = new Set(g.dependencies.rows.flatMap((r) => r.nodes.map((n) => n.id)));
    for (const [a, b] of g.dependencies.edges) expect(ids.has(a) && ids.has(b), `edge ${a}→${b}`).toBe(true);
    for (const r of g.dependencies.rows) expect(r.nodes.length).toBeLessThanOrEqual(6);
    if (g.sequence) {
      const lanes = new Set(g.sequence.lanes.map((l) => l.id));
      for (const s of g.sequence.steps) expect(lanes.has(s.from) && lanes.has(s.to), `step ${s.label}`).toBe(true);
    }
  });
});

describe.each(CASE_STUDIES.map((c) => [c.letter, c] as const))('case study %s', (_l, c) => {
  it('is complete and its links resolve', () => {
    if (c.scenarioId) expect(ALL_SCENARIOS.some((s) => s.id === c.scenarioId), c.scenarioId).toBe(true);
    for (const l of c.lessonIds) expect(getLesson(l), `lesson ${l}`).toBeDefined();
    for (const r of c.refIds ?? []) expect(getRef(r), `ref ${r}`).toBeDefined();
    expect(c.investigation.length).toBeGreaterThanOrEqual(5);
    expect(c.repair.length).toBeGreaterThan(0);
    expect(c.verify.length).toBeGreaterThan(0);
    expect(c.prevention.length).toBeGreaterThan(0);
    const ids = new Set(c.environment.rows.flatMap((r) => r.nodes.map((n) => n.id)));
    for (const [a, b] of c.environment.edges) expect(ids.has(a) && ids.has(b), `edge ${a}→${b}`).toBe(true);
  });
});

describe('case studies', () => {
  it('cover scenarios A to G', () => {
    expect(CASE_STUDIES.map((c) => c.letter).join('')).toBe('ABCDEFG');
  });
});

describe('certification map', () => {
  it('has objective ids prefixed with the exam code and valid links', () => {
    for (const e of CERT_EXAMS) {
      for (const d of e.domains) {
        for (const o of d.objectives) {
          expect(o.id.startsWith(e.code + ':'), o.id).toBe(true);
          for (const l of o.links) expect(routeOk(l), `${o.id} → ${l}`).toBeNull();
        }
      }
    }
  });
});

describe('curriculum', () => {
  it('links resolve', () => {
    for (const m of CURRICULUM) for (const t of m.topics) if (t.link) expect(routeOk(t.link), `${m.id}: ${t.title}`).toBeNull();
  });
});
