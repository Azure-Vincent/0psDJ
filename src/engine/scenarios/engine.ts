// Scenario mechanics: applying faults through the real shell, verifying the
// repair (now AND after a simulated reboot of every host), checking security
// constraints, and grading the learner's diagnosis.

import { type SshdLoaded, bootHost } from '../sim/services';
import { runSsh } from '../sim/ssh';
import { Shell } from '../shell/shell';
import type { World } from '../types';
import { CAUSES } from './catalog';
import type { Constraint, ConstraintResult, Goal, Scenario } from './types';

/** Run shell commands as root on a host, mutating `world` in place (used to inject faults). */
export function script(world: World, hostId: string, lines: string[], gapMs = 45_000): string[] {
  let w = world;
  const sh = new Shell(() => w, (n) => (w = n), { hostId, user: 'root', cwd: '/root' });
  const outputs: string[] = [];
  for (const l of lines) {
    w.clock += gapMs;
    const r = sh.execute(l);
    if (r.needInput) throw new Error(`setup command needs input: ${l}`);
    outputs.push(r.output);
  }
  Object.assign(world, w);
  return outputs;
}

export interface GoalResult {
  goal: Goal;
  ok: boolean;
  lines: string[];
  authMethod?: string;
}

export function checkGoal(world: World, goal: Goal): GoalResult {
  const w = structuredClone(world);
  const res = runSsh(w, {
    clientHostId: 'ws01',
    localUser: goal.localUser,
    target: goal.target,
    user: goal.user,
    strictHostKeyChecking: 'accept-new',
    batchMode: true,
    connectTimeoutS: 10,
  });
  const ok = res.outcome === 'session' && (goal.method === 'any' || res.authMethod === goal.method);
  return { goal, ok, lines: res.lines, authMethod: res.authMethod };
}

export function rebootAll(world: World): World {
  const w = structuredClone(world);
  w.sessions = [];
  for (const id of ['rtr01', 'ns1', 'srv01', 'ws01']) if (w.hosts[id]) bootHost(w, w.hosts[id]);
  w.clock += 30_000;
  return w;
}

export interface Verification {
  now: GoalResult[];
  afterReboot: GoalResult[];
  constraints: ConstraintResult[];
  constraintsAfterReboot: ConstraintResult[];
  passed: boolean;
}

export function verifyScenario(world: World, scenario: Scenario): Verification {
  const now = scenario.goals.map((g) => checkGoal(world, g));
  const rebooted = rebootAll(world);
  const afterReboot = scenario.goals.map((g) => checkGoal(rebooted, g));
  const constraints = scenario.constraints.map((c) => c.check(world));
  const constraintsAfterReboot = scenario.constraints.map((c) => c.check(rebooted));
  const passed =
    now.every((g) => g.ok) &&
    afterReboot.every((g) => g.ok) &&
    [...constraints, ...constraintsAfterReboot].every((c) => c.ok || !c.required);
  return { now, afterReboot, constraints, constraintsAfterReboot, passed };
}

export interface DiagnosisGrade {
  correct: boolean;
  matched: string[];
  missing: string[];
  wrong: { id: string; title: string; explanation: string }[];
  acceptable: { id: string; title: string; note: string }[];
}

export function gradeDiagnosis(scenario: Scenario, selected: string[]): DiagnosisGrade {
  const matched = selected.filter((s) => scenario.rootCauses.includes(s));
  const missing = scenario.rootCauses.filter((r) => !selected.includes(r));
  const acceptable = selected
    .filter((s) => !scenario.rootCauses.includes(s) && scenario.acceptable?.[s])
    .map((id) => ({ id, title: CAUSES[id].title, note: scenario.acceptable![id] }));
  const wrong = selected
    .filter((s) => !scenario.rootCauses.includes(s) && !scenario.acceptable?.[s])
    .map((id) => ({
      id,
      title: CAUSES[id].title,
      explanation: scenario.feedback?.[id] ?? `If this were the cause you would expect: ${CAUSES[id].signature} How to check: ${CAUSES[id].check}`,
    }));
  return { correct: missing.length === 0 && wrong.length === 0, matched, missing, wrong, acceptable };
}

// ---------------------------------------------------------------------------
// Reusable constraints
// ---------------------------------------------------------------------------

export function firewallStillRestrictive(hostId = 'srv01'): Constraint {
  return {
    id: `fw-restrictive-${hostId}`,
    required: true,
    description: `${hostId}'s firewall must keep a default-deny input policy (do not "fix" SSH by opening everything).`,
    check(world) {
      const h = world.hosts[hostId];
      const input = h.nft.tables.flatMap((t) => t.chains).find((c) => c.base?.hook === 'input');
      if (!input || input.base!.policy !== 'drop') {
        return { id: this.id, ok: false, required: true, message: `${hostId}: the input chain policy is not "drop" (or the ruleset was flushed). Every port is now reachable.` };
      }
      const blanket = input.rules.find((r) => r.verdict?.kind === 'accept' && (r.matches.length === 0 || r.matches.every((m) => m.kind === 'addr' && m.values.includes('0.0.0.0/0'))));
      if (blanket) return { id: this.id, ok: false, required: true, message: `${hostId}: rule handle ${blanket.handle} accepts all traffic.` };
      return { id: this.id, ok: true, required: true, message: `${hostId}: input policy is still drop with specific allow rules.` };
    },
  };
}

function sshdLoaded(world: World, hostId: string): SshdLoaded | null {
  return (world.hosts[hostId].services.ssh?.loaded as SshdLoaded | null) ?? null;
}

export function sshdPolicy(hostId = 'srv01'): Constraint {
  return {
    id: 'sshd-policy',
    required: true,
    description: 'The SSH security policy (CHG-1042) must stay in force: PasswordAuthentication no, PermitRootLogin no, StrictModes yes.',
    check(world) {
      const l = sshdLoaded(world, hostId);
      if (!l) return { id: this.id, ok: true, required: true, message: 'sshd is not running, so its policy cannot be evaluated (the goal check covers this).' };
      const e = l.effective;
      const problems: string[] = [];
      if (e.passwordAuthentication) problems.push('PasswordAuthentication is yes');
      if (e.permitRootLogin !== 'no') problems.push(`PermitRootLogin is ${e.permitRootLogin}`);
      if (!e.strictModes) problems.push('StrictModes is no');
      return problems.length
        ? { id: this.id, ok: false, required: true, message: `Running sshd violates the policy: ${problems.join(', ')}.` }
        : { id: this.id, ok: true, required: true, message: 'Running sshd still enforces key-only logins, no root login and StrictModes.' };
    },
  };
}

export function modernKex(hostId = 'srv01'): Constraint {
  return {
    id: 'modern-kex',
    required: true,
    description: 'sshd must offer at least one modern key exchange (curve25519 or sntrup761x25519) and must not offer diffie-hellman-group1-sha1.',
    check(world) {
      const l = sshdLoaded(world, hostId);
      if (!l) return { id: this.id, ok: true, required: true, message: 'sshd not running.' };
      const k = l.effective.kexAlgorithms;
      const modern = k.some((a) => a.startsWith('curve25519') || a.startsWith('sntrup'));
      const weak = k.includes('diffie-hellman-group1-sha1');
      return modern && !weak
        ? { id: this.id, ok: true, required: true, message: `Server KEX list: ${k.slice(0, 3).join(', ')}${k.length > 3 ? ', ...' : ''}` }
        : { id: this.id, ok: false, required: true, message: modern ? 'diffie-hellman-group1-sha1 (1024-bit, SHA-1) is enabled.' : 'No modern key exchange algorithm is enabled; the server relies on legacy algorithms only.' };
    },
  };
}

export function zoneSerialBumped(original: number): Constraint {
  return {
    id: 'zone-serial',
    required: false,
    description: 'Best practice: increment the SOA serial whenever a zone changes, so secondary servers pick up the change.',
    check(world) {
      const loaded = world.hosts.ns1.services.named?.loaded as { zones: { origin: string; serial: number }[] } | null;
      const z = loaded?.zones.find((x) => x.origin === 'corp.lab.');
      if (!z) return { id: this.id, ok: false, required: false, message: 'corp.lab is not loaded on ns1.' };
      return z.serial > original
        ? { id: this.id, ok: true, required: false, message: `Serial increased to ${z.serial}.` }
        : { id: this.id, ok: false, required: false, message: `Serial is still ${z.serial}. Secondaries would not transfer the corrected zone.` };
    },
  };
}

export function sessionStillWorks(goal: Goal, id: string, description: string): Constraint {
  return {
    id,
    required: true,
    description,
    check(world) {
      const r = checkGoal(world, goal);
      return { id, ok: r.ok, required: true, message: r.ok ? `${goal.user} can still log in.` : `${goal.user} can no longer log in: ${r.lines[r.lines.length - 1] ?? ''}` };
    },
  };
}
