// Grading for assessment questions and command exercises. Pure functions so
// they can be unit-tested. Practical questions (nft rules, sshd config) are
// graded by running the learner's answer through the simulator's own parsers.

import { evaluate, NftError, parseRuleExpr, parseRulesetFile } from '../engine/config/nft';
import { effectiveConfig, formatErrors, parseSshdConfig } from '../engine/config/sshdConfig';
import type { CommandExercise, Question } from '../content/types';
import { tokenizeLine } from '../engine/shell/tokenize';

export interface GradeResult {
  correct: boolean;
  /** Per-part feedback (test cases, option misconceptions...). */
  feedback: { ok: boolean; text: string }[];
}

const norm = (s: string) => s.trim().replace(/\s+/g, ' ').toLowerCase();

export function gradeQuestion(q: Question, answer: unknown): GradeResult {
  switch (q.kind) {
    case 'single': {
      const idx = answer as number;
      const opt = q.options[idx];
      if (!opt) return { correct: false, feedback: [{ ok: false, text: 'Choose an answer.' }] };
      return {
        correct: !!opt.correct,
        feedback: [{ ok: !!opt.correct, text: opt.correct ? 'Correct.' : opt.misconception ?? 'Not quite.' }],
      };
    }
    case 'multi': {
      const chosen = new Set(answer as number[]);
      const feedback: GradeResult['feedback'] = [];
      let correct = true;
      q.options.forEach((o, i) => {
        const picked = chosen.has(i);
        if (picked && !o.correct) {
          correct = false;
          feedback.push({ ok: false, text: `"${o.text}": ${o.misconception ?? 'this does not apply.'}` });
        }
        if (!picked && o.correct) {
          correct = false;
          feedback.push({ ok: false, text: `Missed: "${o.text}".` });
        }
      });
      if (correct) feedback.push({ ok: true, text: 'All correct options selected, and no incorrect ones.' });
      return { correct, feedback };
    }
    case 'order': {
      const order = answer as string[];
      const correct = order.length === q.items.length && order.every((v, i) => v === q.items[i]);
      const feedback = order.map((v, i) => ({ ok: v === q.items[i], text: `${i + 1}. ${v}${v === q.items[i] ? '' : `  (expected: ${q.items[i]})`}` }));
      return { correct, feedback };
    }
    case 'text': {
      const a = norm(String(answer ?? ''));
      const ok = q.accept.some((acc) => (acc instanceof RegExp ? acc.test(a) || acc.test(String(answer ?? '').trim()) : norm(acc) === a));
      return { correct: ok, feedback: [{ ok, text: ok ? 'Correct.' : 'Not accepted. Check the command name and options.' }] };
    }
    case 'nft-rule': {
      // One rule per line; each may be typed with or without the "nft add rule inet filter input" prefix.
      const rules = String(answer ?? '')
        .split('\n')
        .map((l) => l.trim().replace(/^nft\s+(add|insert)\s+rule\s+(inet|ip)\s+filter\s+input\s+/, ''))
        .filter(Boolean);
      if (rules.length === 0) return { correct: false, feedback: [{ ok: false, text: 'Write at least one rule.' }] };
      for (const r of rules) {
        try {
          parseRuleExpr(r, 1);
        } catch (e) {
          return { correct: false, feedback: [{ ok: false, text: `nft: Error: ${(e as Error).message} (in "${r}")` }] };
        }
      }
      let rs;
      try {
        rs = parseRulesetFile(`table inet filter {\n chain input {\n type filter hook input priority filter; policy drop;\n${[...q.context, ...rules].map((c) => ' ' + c).join('\n')}\n }\n}\n`);
      } catch (e) {
        return { correct: false, feedback: [{ ok: false, text: e instanceof NftError ? e.message : String(e) }] };
      }
      const feedback = q.tests.map((t) => {
        const r = evaluate(rs, 'input', { src: t.packet.src, dst: '10.0.20.10', proto: t.packet.proto, sport: 50000, dport: t.packet.dport, ctState: 'new', len: 60, iif: 'eth0' });
        const verdict = r.verdict === 'accept' ? 'accept' : 'drop';
        return { ok: verdict === t.expect, text: `${t.description}: ${verdict}${verdict === t.expect ? '' : ` (expected ${t.expect})`}` };
      });
      return { correct: feedback.every((f) => f.ok), feedback };
    }
    case 'sshd-config': {
      const text = String(answer ?? '');
      const parsed = parseSshdConfig('/etc/ssh/sshd_config', (p) => (p === '/etc/ssh/sshd_config' ? text : undefined), () => ['/etc/ssh/sshd_config']);
      if (parsed.errors.length) return { correct: false, feedback: formatErrors(parsed.errors).map((e) => ({ ok: false, text: e })) };
      const feedback = q.checks.map((c) => {
        const eff = effectiveConfig(parsed, c.context ? { user: c.context.user, groups: [], address: c.context.address } : undefined) as unknown as Record<string, unknown>;
        const actual = eff[c.key];
        const ok = JSON.stringify(actual) === JSON.stringify(c.expect);
        return { ok, text: `${c.description}: effective ${c.key} = ${JSON.stringify(actual)}${ok ? '' : ` (expected ${JSON.stringify(c.expect)})`}` };
      });
      return { correct: feedback.every((f) => f.ok), feedback };
    }
  }
}

export function gradeCommandExercise(ex: CommandExercise, answer: unknown): GradeResult {
  if (ex.kind === 'choose-command') {
    const line = String(answer ?? '').trim();
    let argv: string[] = [];
    try {
      argv = tokenizeLine(line).filter((t) => !t.startsWith('\u0000'));
    } catch {
      return { correct: false, feedback: [{ ok: false, text: 'Could not parse the command line.' }] };
    }
    while (argv[0] === 'sudo') argv.shift();
    const name = (argv[0] ?? '').toLowerCase();
    const nameOk = (ex.acceptCommands ?? []).includes(name);
    const rest = argv.slice(1).join(' ');
    const flagsOk = (ex.mustMatch ?? []).every((re) => re.test(rest) || re.test(line));
    const feedback = [{ ok: nameOk, text: nameOk ? `${name} is a good tool for this.` : `"${name || '(nothing)'}" is not the most direct tool here.` }];
    if (nameOk) feedback.push({ ok: flagsOk, text: flagsOk ? 'Arguments target the right thing.' : 'Right tool, but the options/arguments would not show what you need.' });
    return { correct: nameOk && flagsOk, feedback };
  }
  const chosen = (answer as number[]).slice().sort();
  const expected = (ex.abnormal ?? []).slice().sort();
  const ok = JSON.stringify(chosen) === JSON.stringify(expected);
  return { correct: ok, feedback: [{ ok, text: ok ? 'Correct.' : 'Not quite.' }] };
}

/** Deterministic shuffle for ordering questions (same order every time for a question id). */
export function stableShuffle<T>(items: T[], seed: string): T[] {
  const out = items.slice();
  let x = 2166136261;
  for (const c of seed) x = Math.imul(x ^ c.charCodeAt(0), 16777619) >>> 0;
  for (let i = out.length - 1; i > 0; i--) {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    const j = x % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  if (out.every((v, i) => v === items[i]) && out.length > 1) [out[0], out[1]] = [out[1], out[0]];
  return out;
}
