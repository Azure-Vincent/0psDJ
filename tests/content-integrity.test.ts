// Cross-reference integrity for the content: every id a lesson, guide, case
// study or curriculum topic links to must exist, and every command
// marked as runnable in the simulator must be a simulator command.

import { describe, expect, it } from 'vitest';
import { CASE_STUDIES } from '../src/content/cases';
import { COMMAND_REFS } from '../src/content/commands';
import { CURRICULUM, LABS } from '../src/content/curriculum';
import { ASSESSMENTS, LESSONS, getLesson } from '../src/content/lessons';
import { practiceBlocks, stripPractice } from '../src/content/practice';
import { readFileSync, readdirSync } from 'node:fs';
import { FILE_REFS, PROCEDURES, REF_ENTRIES, getRef } from '../src/content/reference';
import { ALL_SCENARIOS } from '../src/engine/scenarios';
import { GUIDED_LABS } from '../src/engine/labs';
import { PF_COMMANDS } from '../src/engine/shell/cmdPf';
import { COMMANDS } from '../src/engine/shell/shell';
import { resolveCommand } from '../src/engine/win/ps/runtime';

const SHELL_BUILTINS = new Set(['sudo', 'exit', 'logout', 'clear', 'true', 'false', 'help', 'which', 'type', 'for', 'echo', 'set', '.']);
const SECTIONS = new Set(['what', 'internals', 'visualize', 'deploy', 'config', 'operate', 'troubleshoot', 'assess']);

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
    case 'packets': case 'glossary': case 'commands': case 'curriculum': return null;
    default: return `unknown route ${link}`;
  }
}

/** First word of every command line in a (possibly multi-line) command string. */
function commandWords(cmd: string): string[] {
  // Quoted strings and brace blocks (PowerShell hashtables and script blocks) are arguments, not command separators.
  return cmd.split('\n').flatMap((line) => line.replace(/"[^"]*"|'[^']*'/g, 'Q').replace(/@?\{[^{}]*\}/g, 'Q').split(/\s*(?:&&|\|\||;|\|)\s*/)).map((part) => {
    const words = part.trim().replace(/^sudo\s+(-[ug]\s+\S+\s+|-\S+\s+)*/, '').split(/\s+/);
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

describe('assessments', () => {
  it('question ids are unique (answers are saved by id)', () => {
    const ids = Object.values(ASSESSMENTS).flatMap((a) => a.questions.map((q) => q.id));
    expect(ids.filter((id, i) => ids.indexOf(id) !== i)).toEqual([]);
  });
});

describe.each(LESSONS.map((L) => [L.id, L] as const))('lesson %s', (_id, L) => {
  it('links resolve', () => {
    expect(ASSESSMENTS[L.assessmentId], 'assessment').toBeDefined();
    expect(L.deployment.length, 'deployment guides').toBeGreaterThan(0);
    for (const s of L.scenarioIds) expect(ALL_SCENARIOS.some((x) => x.id === s), `ticket ${s}`).toBe(true);
    for (const c of L.caseStudyIds ?? []) expect(CASE_STUDIES.some((x) => x.id === c), `case ${c}`).toBe(true);
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
      // Linux commands, pfSense console tools (fw01), or PowerShell cmdlets and Windows programs (win01's console).
      for (const word of commandWords(cmd)) expect(COMMANDS[word] || PF_COMMANDS[word] || SHELL_BUILTINS.has(word) || resolveCommand(word), `"${word}" in: ${cmd}`).toBeTruthy();
    }
  });
  it('has a complete beginner primer', () => {
    const p = L.primer;
    expect(p, 'primer').toBeDefined();
    expect(p!.oneLiner.length).toBeGreaterThan(40);
    expect(p!.ideas.length).toBeGreaterThanOrEqual(4);
    for (const i of p!.ideas) expect(i.example.trim().length, `example for "${i.title}"`).toBeGreaterThan(30);
    expect(p!.walkthrough.steps.length).toBeGreaterThanOrEqual(4);
    expect(p!.misconceptions.length).toBeGreaterThanOrEqual(3);
    expect(p!.checks.length).toBeGreaterThanOrEqual(4);
    // Code fences must be balanced or the markdown renderer swallows the rest of the text.
    const texts = [p!.analogy, ...p!.ideas.flatMap((i) => [i.explain, i.example]), ...p!.walkthrough.steps.map((s) => s.detail), ...p!.misconceptions.map((m) => m.truth), ...p!.checks.map((c) => c.a)];
    for (const t of texts) expect((t.match(/```/g) ?? []).length % 2, t.slice(0, 60)).toBe(0);
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

describe('curriculum', () => {
  it('links resolve', () => {
    for (const m of CURRICULUM) for (const t of m.topics) if (t.link) expect(routeOk(t.link), `${m.id}: ${t.title}`).toBeNull();
  });
  it('lists only what the application covers (no roadmap items)', () => {
    for (const m of CURRICULUM) for (const t of m.topics) {
      expect(['available', 'partial'], `${m.id}: ${t.title}`).toContain(t.status);
      expect(t.link, `${m.id}: ${t.title}`).toBeTruthy();
      expect(t.note ?? '', `${m.id}: ${t.title}`).not.toMatch(/\bplanned\b/);
    }
    for (const l of LABS) expect(l.status, l.title).not.toBe('planned');
  });
});

describe('practice blocks', () => {
  // Orientation sections and reference lists teach no concept of their own, so they need no practice.
  const ORIENTATION = new Set(['In the lab', 'In the simulator', 'The example network', 'Where you meet it', 'Problems it solves', 'The problems it solves', 'Why it matters', 'What you will be able to answer']);
  const NO_PRACTICE = new Set(['ad-kerberos: Services involved, by machine', 'systemd: Unit file directives']);
  const TABS = ['what', 'internals', 'configIntro', 'operateIntro', 'troubleshootingIntro'] as const;
  const sections = (text: string) => text.split(/^(?=### )/m).filter((x) => x.startsWith('### '));
  it('every concept section of every tab ends with a practice block', () => {
    for (const L of LESSONS) for (const tab of TABS) for (const sec of sections(L[tab] ?? '')) {
      const title = sec.split('\n')[0].slice(4);
      if ((tab === 'what' && ORIENTATION.has(title)) || NO_PRACTICE.has(`${L.id}: ${title}`)) continue;
      const blocks = practiceBlocks(sec);
      expect(blocks.length, `${L.id}: ${title} has no practice block`).toBeGreaterThan(0);
      expect(blocks[blocks.length - 1].after.trim(), `${L.id}: ${title}: text after the practice block`).toBe('');
    }
  });
  it('every practice block is closed and every question has an answer that is not a graded question', () => {
    const prompts = new Set(Object.values(ASSESSMENTS).flatMap((A) => A.questions.map((q) => q.prompt.trim())));
    for (const L of LESSONS) for (const tab of TABS) for (const b of practiceBlocks(L[tab] ?? '')) {
      const where = `${L.id}: ${b.pairs[0]?.q ?? '(empty block)'}`;
      expect(b.closed, `${where}: missing ":::"`).toBe(true);
      expect(b.stray, `${where}: lines outside Q/A`).toEqual([]);
      expect(b.pairs.length, where).toBeGreaterThan(0);
      for (const { q, a } of b.pairs) {
        expect(a.trim(), `${L.id}: no answer for: ${q}`).not.toBe('');
        expect(prompts.has(q.trim()), `${L.id}: copies a graded question: ${q}`).toBe(false);
      }
    }
  });
  it('practice source lines keep their backslashes (template literals swallow single ones)', () => {
    for (const f of readdirSync('src/content', { recursive: true }) as string[]) {
      if (!f.endsWith('.ts')) continue;
      readFileSync(`src/content/${f}`, 'utf8').split('\n').forEach((l, i) => {
        if (!/^[QA]: /.test(l)) return;
        expect(l.replace(/\\\\/g, '').replace(/\\`/g, ''), `${f}:${i + 1}`).not.toContain('\\');
      });
    }
  });
  it('search snippets leave out practice answers', () => {
    expect(stripPractice('a\n:::practice\nQ: q\nA: secret\n:::\nb')).toBe('a\nb');
  });
  it('the parser reports broken blocks', () => {
    expect(practiceBlocks(':::practice\nQ: x\nA: y\n### Next')[0].closed).toBe(false);
    expect(practiceBlocks(':::practice\nQ: x\nA: y\n:::\ntrailing')[0].after).toBe('trailing');
    expect(practiceBlocks(':::practice\nA: orphan\n:::')[0].stray).toEqual(['A: orphan']);
  });
});

describe('assessment questions', () => {
  it('every question links to the lesson sections that teach it', () => {
    for (const A of Object.values(ASSESSMENTS)) for (const q of A.questions) {
      expect(q.learn?.length ?? 0, `${q.id} has no learn links`).toBeGreaterThan(0);
      for (const r of q.learn ?? []) {
        const [head, , sec] = r.split('/');
        expect(head === 'lesson' && SECTIONS.has(sec) && sec !== 'assess', `${q.id} → ${r}`).toBe(true);
        expect(routeOk(r), `${q.id} → ${r}`).toBeNull();
      }
    }
  });
});

describe('in-text links', () => {
  it('every [label](#/route) in lessons, tickets, labs and case studies points to an existing page', () => {
    const text = JSON.stringify([LESSONS, ALL_SCENARIOS, GUIDED_LABS.map(({ build: _b, ...l }) => ({ ...l, steps: l.steps.map((s) => ({ ...s, check: undefined, solution: undefined })) })), CASE_STUDIES]);
    const links = [...text.matchAll(/\]\(#\/([^)\s]+)\)/g)].map((m) => m[1]);
    for (const l of links) {
      const route = l.replace(/^(labs)\/.*/, '$1');
      if (route === 'labs') expect(GUIDED_LABS.some((g) => l === `labs/${g.id}` || l === 'labs'), l).toBe(true);
      else expect(routeOk(l), l).toBeNull();
    }
  });
});
