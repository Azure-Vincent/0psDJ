import { describe, expect, it } from 'vitest';
import { SCORING_SCENARIOS } from '../src/engine/scenarios/scoringScenarios';
import { SSH_ASSESSMENT } from '../src/content/ssh/assessment';
import { COMMAND_EXERCISES, COMMAND_REFS } from '../src/content/commands';
import { SSH_LESSON } from '../src/content/ssh/lesson';
import { CONCEPTS } from '../src/content/concepts';
import { gradeCommandExercise, gradeQuestion, stableShuffle } from '../src/learning/grading';
import { emptyProgress, loadProgress, mastery, recordConcepts, saveProgress } from '../src/learning/progress';
import { SSH_SCENARIOS } from '../src/engine/scenarios/sshScenarios';
import { COMMANDS } from '../src/engine/shell/shell';
import type { Question } from '../src/content/types';

const q = (id: string) => SSH_ASSESSMENT.questions.find((x) => x.id === id)! as Question;

describe('assessment grading', () => {
  it('every question has a gradable correct answer', () => {
    for (const question of SSH_ASSESSMENT.questions) {
      if (question.kind === 'single') expect(question.options.filter((o) => o.correct)).toHaveLength(1);
      if (question.kind === 'multi') expect(question.options.some((o) => o.correct)).toBe(true);
      for (const c of question.concepts) expect(CONCEPTS[c]).toBeDefined();
    }
  });
  it('grades ordering, short text and multi-select', () => {
    const order = q('ssh-q-order');
    if (order.kind !== 'order') throw new Error();
    expect(gradeQuestion(order, order.items).correct).toBe(true);
    expect(gradeQuestion(order, stableShuffle(order.items, order.id)).correct).toBe(false);
    expect(gradeQuestion(q('ssh-q-journal-unit'), 'journalctl -u ssh -n 50').correct).toBe(true);
    expect(gradeQuestion(q('ssh-q-journal-unit'), 'sudo journalctl -n 50 -u ssh').correct).toBe(true);
    expect(gradeQuestion(q('ssh-q-journal-unit'), 'tail /var/log/auth.log').correct).toBe(false);
    expect(gradeQuestion(q('ssh-q-effective'), 'sshd -T').correct).toBe(true);
    expect(gradeQuestion(q('ssh-q-noroute'), [0, 1, 2]).correct).toBe(true);
    const wrong = gradeQuestion(q('ssh-q-noroute'), [0, 3]);
    expect(wrong.correct).toBe(false);
    expect(wrong.feedback.map((f) => f.text).join(' ')).toMatch(/DROP sends nothing back/);
  });
  it('evaluates nftables answers against test packets', () => {
    const nq = q('ssh-q-nft');
    expect(gradeQuestion(nq, 'ip saddr { 10.0.10.0/24, 10.0.99.5 } tcp dport 22 accept').correct).toBe(true);
    const tooBroad = gradeQuestion(nq, 'tcp dport 22 accept');
    expect(tooBroad.correct).toBe(false);
    expect(tooBroad.feedback.filter((f) => !f.ok).length).toBe(2);
    expect(gradeQuestion(nq, 'ip saddr 10.0.10.0/24 tcp dport 22 accept').correct).toBe(false);
    expect(gradeQuestion(nq, 'tcp dprt 22 accept').feedback[0].text).toMatch(/syntax error/);
  });
  it('evaluates sshd_config answers on the effective configuration, including Match', () => {
    const sq = q('ssh-q-sshd-config');
    const good = 'PasswordAuthentication no\nPermitRootLogin no\nPubkeyAuthentication yes\nMatch Address 10.0.30.0/24\n    PasswordAuthentication yes\n';
    expect(gradeQuestion(sq, good).correct).toBe(true);
    const matchFirst = 'Match Address 10.0.30.0/24\n    PasswordAuthentication yes\nPasswordAuthentication no\nPermitRootLogin no\n';
    expect(gradeQuestion(sq, matchFirst).correct).toBe(false);
    expect(gradeQuestion(sq, 'PermitRootLogn no').feedback[0].text).toMatch(/Bad configuration option/);
  });
});

describe('command exercises and reference', () => {
  it('accepts reasonable commands and rejects wrong tools', () => {
    const ex = (id: string) => COMMAND_EXERCISES.find((e) => e.id === id)!;
    expect(gradeCommandExercise(ex('cx-listening'), 'sudo ss -tlnp').correct).toBe(true);
    expect(gradeCommandExercise(ex('cx-listening'), 'ping srv01').correct).toBe(false);
    expect(gradeCommandExercise(ex('cx-route-get'), 'ip route get 10.0.20.10').correct).toBe(true);
    expect(gradeCommandExercise(ex('cx-route-get'), 'ip route').correct).toBe(false);
    expect(gradeCommandExercise(ex('cx-effective'), 'sshd -T -C user=carol,addr=10.0.10.25').correct).toBe(true);
    expect(gradeCommandExercise(ex('sx-route'), []).correct).toBe(true);
    expect(gradeCommandExercise(ex('sx-journal'), [1]).correct).toBe(true);
  });
  it('every reference marked as simulated exists in the simulator shell', () => {
    for (const c of COMMAND_REFS) if (c.simulator) expect(COMMANDS[c.simulator], c.id).toBeDefined();
  });
  it('lesson links to existing scenarios', () => {
    // The SSH lesson covers its own tickets and the scored-service (competition) SSH tickets.
    const linked = [...SSH_SCENARIOS, ...SCORING_SCENARIOS];
    for (const id of SSH_LESSON.scenarioIds) expect(linked.some((s) => s.id === id), id).toBe(true);
    expect(SSH_LESSON.scenarioIds).toHaveLength(linked.length);
  });
});

describe('progress and mastery', () => {
  it('round-trips through storage and tolerates garbage', () => {
    const mem = new Map<string, string>();
    const storage = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v) };
    let p = emptyProgress();
    p = recordConcepts(p, ['tcp.handshake'], true, 1);
    saveProgress(storage, p);
    expect(loadProgress(storage).concepts['tcp.handshake']?.correct).toBe(1);
    mem.set('infralab.progress.v1', '{not json');
    expect(loadProgress(storage)).toEqual(emptyProgress());
  });
  it('classifies mastery levels', () => {
    let p = emptyProgress();
    expect(mastery(p.concepts['fw.stateful']).level).toBe('not started');
    p = recordConcepts(p, ['fw.stateful'], false, 1, 'firewall-drop');
    p = recordConcepts(p, ['fw.stateful'], false, 2, 'firewall-reject');
    expect(mastery(p.concepts['fw.stateful']).level).toBe('struggling');
    expect(p.concepts['fw.stateful']?.misconceptions).toEqual(['firewall-drop', 'firewall-reject']);
    for (let i = 0; i < 8; i++) p = recordConcepts(p, ['fw.stateful'], true, 3 + i);
    expect(mastery(p.concepts['fw.stateful']).level).toBe('proficient');
  });
});
