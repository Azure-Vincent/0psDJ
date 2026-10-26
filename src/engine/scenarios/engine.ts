// Scenario mechanics: applying faults through the real shell, verifying the
// repair (now AND after a simulated reboot of every host), checking security
// constraints, and grading the learner's diagnosis.

import { type SshdLoaded, bootHost } from '../sim/services';
import { runSsh } from '../sim/ssh';
import { Shell } from '../shell/shell';
import type { World } from '../types';
import { CAUSES } from './catalog';
import { isWindows } from '../win/model';
import { scoredDnsCheck, scoredSshCheck, scoredWebCheck } from './scoring';
import { dockerTick } from '../sim/docker';
import { clockSynchronized, ntpSettle } from '../sim/ntp';
import { syslogFlush } from '../sim/syslog';
import type { Constraint, ConstraintResult, Goal, Scenario } from './types';

/** Run shell commands as root on a host, mutating `world` in place (used to inject faults). */
export function script(world: World, hostId: string, lines: string[], gapMs = 45_000): string[] {
  let w = world;
  // Windows hosts are configured from an administrator's PowerShell console.
  const win = isWindows(w.hosts[hostId]);
  const sh = new Shell(() => w, (n) => (w = n), win ? { hostId, user: 'Administrator', cwd: w.hosts[hostId].users.Administrator.home } : { hostId, user: 'root', cwd: '/root' });
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

export function goalLabel(goal: Goal): string {
  if (goal.kind === 'http') return `${goal.fromHost}: curl ${goal.curlFlags ? goal.curlFlags + ' ' : ''}${goal.url}`;
  if (goal.kind === 'resolve') return `${goal.fromHost}: resolve ${goal.name}`;
  if (goal.kind === 'rdp') return `${goal.fromHost}: xfreerdp /v:${goal.target} /u:${goal.user}`;
  if (goal.kind === 'scored-ssh') return `scoring engine: SSH ${goal.user}@${goal.target} (password)`;
  if (goal.kind === 'scored-web') return `scoring engine: web ${goal.url}`;
  if (goal.kind === 'scored-dns') return `scoring engine: DNS ${goal.name} A @${goal.server}`;
  if (goal.kind === 'time') return `${goal.host}: timedatectl (clock synchronized and correct)`;
  if (goal.kind === 'syslog') return `${goal.fromHost}: logger${goal.priority ? ` -p ${goal.priority}` : ''} → ${goal.server}:${goal.path}`;
  if (goal.kind === 'command') return goal.steps.map((s) => `${s.host}: ${s.command}`).join(' → ');
  if (goal.kind === 'kerberos') return `${goal.fromHost}: kinit ${goal.localUser}${goal.sshTarget ? ` + ssh ${goal.sshTarget} (Kerberos)` : ''}`;
  return `${goal.user}@${goal.target}`;
}

export function checkGoal(world: World, goal: Goal): GoalResult {
  // Daemons keep working in the background while the user is away: NTP clients poll
  // again, and Docker retries containers in "restarting". Let them catch up before the check.
  world = structuredClone(world);
  ntpSettle(world);
  syslogFlush(world);
  for (const h of Object.values(world.hosts)) if (h.services.docker?.state === 'active') dockerTick(world, h);
  if (goal.kind === 'scored-ssh') return { goal, ...scoredSshCheck(world, goal) };
  if (goal.kind === 'scored-web') return { goal, ...scoredWebCheck(world, goal) };
  if (goal.kind === 'scored-dns') return { goal, ...scoredDnsCheck(world, goal) };
  const w = structuredClone(world);
  if (goal.kind === 'syslog') {
    let cur = w;
    const token = `probe-${(w.counter * 2654435761 >>> 0).toString(16)}`;
    const line = `logger${goal.priority ? ` -p ${goal.priority}` : ''} -t labcheck "central logging test ${token}"`;
    const sh = new Shell(() => cur, (n) => (cur = n), { hostId: goal.fromHost, user: 'root', cwd: '/root' });
    sh.execute(line);
    // rsyslog forwards in the background: let a moment pass, then look on the server.
    syslogFlush(cur);
    const path = goal.path.replace('%PROGRAMNAME%', 'labcheck');
    const content = cur.hosts[goal.server].fs[path]?.content ?? '';
    const got = content.split('\n').find((l) => l.includes(token));
    return { goal, ok: !!got, lines: [`${goal.fromHost}# ${line}`, `${goal.server}# grep ${token} ${path}`, got ?? (cur.hosts[goal.server].fs[path] ? '(no such line)' : `grep: ${path}: No such file or directory`)] };
  }
  if (goal.kind === 'command') {
    let cur = w;
    const lines: string[] = [];
    let last = { code: 0, output: '' };
    for (const s of goal.steps) {
      const u = cur.hosts[s.host].users[s.user];
      const sh = new Shell(() => cur, (n) => (cur = n), { hostId: s.host, user: s.user, cwd: u?.home ?? '/' });
      cur.clock += 5_000;
      const r = sh.execute(s.command);
      last = { code: r.code, output: r.output };
      lines.push(`${s.user}@${s.host}${s.user === 'root' ? '#' : '$'} ${s.command}`, ...(r.output ? r.output.split('\n') : []));
    }
    const ok = last.code === 0 && (!goal.expect || new RegExp(goal.expect, 'm').test(last.output));
    return { goal, ok, lines };
  }
  if (goal.kind === 'time') {
    let cur = w;
    const sh = new Shell(() => cur, (n) => (cur = n), { hostId: goal.host, user: 'root', cwd: '/root' });
    const r = sh.execute('timedatectl');
    const h = cur.hosts[goal.host];
    const offMs = h.clockOffset ?? 0;
    const synced = clockSynchronized(h);
    const lines = [`$ timedatectl`, ...r.output.split('\n')];
    if (Math.abs(offMs) >= 1000) lines.push(`(the correct time is ${new Date(Math.floor(cur.clock)).toISOString().slice(11, 19)} UTC: this clock is ${Math.round(Math.abs(offMs) / 1000)} s ${offMs > 0 ? 'fast' : 'slow'})`);
    return { goal, ok: synced && Math.abs(offMs) < 1000, lines };
  }
  if (goal.kind === 'kerberos') {
    let cur = w;
    const home = cur.hosts[goal.fromHost].users[goal.localUser].home;
    const sh = new Shell(() => cur, (n) => (cur = n), { hostId: goal.fromHost, user: goal.localUser, cwd: home });
    sh.execute('kdestroy');
    const k = sh.execute('kinit', [goal.password]);
    const lines = ['$ kinit', ...(k.output ? k.output.split('\n') : [])];
    if (k.code !== 0) return { goal, ok: false, lines };
    if (!goal.sshTarget) return { goal, ok: true, lines: [...lines, '(ticket obtained)'] };
    const line = `ssh -o PubkeyAuthentication=no -o PasswordAuthentication=no -o BatchMode=yes -o StrictHostKeyChecking=accept-new ${goal.sshTarget} hostname`;
    const r = sh.execute(line);
    return { goal, ok: r.code === 0, lines: [...lines, `$ ${line}`, ...(r.output ? r.output.split('\n') : ['(no output)'])], authMethod: r.code === 0 ? 'gssapi-with-mic' : undefined };
  }
  if (goal.kind === 'rdp') {
    let cur = w;
    const home = cur.hosts[goal.fromHost].users[goal.localUser].home;
    const sh = new Shell(() => cur, (n) => (cur = n), { hostId: goal.fromHost, user: goal.localUser, cwd: home });
    const line = `xfreerdp /v:${goal.target} /u:'${goal.user}' /p:'${goal.password}' /cert:ignore`;
    const r = sh.execute(line);
    // Timestamps vary between runs; show the messages only.
    const lines = [`$ ${line.replace(goal.password, '********')}`, ...(r.output ? r.output.split('\n').map((l) => l.replace(/^\[[\d:]+\] \[\d+:\d+\] /, '')) : ['(no output)'])];
    return { goal, ok: r.code === 0, lines };
  }
  if (goal.kind === 'http' || goal.kind === 'resolve') {
    let cur = w;
    const user = goal.kind === 'http' ? goal.fromUser : 'root';
    const home = cur.hosts[goal.fromHost].users[user].home;
    const sh = new Shell(() => cur, (n) => (cur = n), { hostId: goal.fromHost, user, cwd: home });
    const line = goal.kind === 'http'
      ? goal.download ? `curl ${goal.curlFlags ? goal.curlFlags + ' ' : ''}-sS -o /dev/null -w '%{http_code}\\n' -m 30 ${goal.url}` : `curl ${goal.curlFlags ? goal.curlFlags + ' ' : ''}-I -m 10 ${goal.url}`
      : `getent hosts ${goal.name}`;
    const r = sh.execute(line);
    const lines = [`$ ${line}`, ...(r.output ? r.output.split('\n') : ['(no output)'])];
    const ok = goal.kind === 'http' ? (goal.download ? /^200$/m.test(r.output) && r.code === 0 : /^HTTP\/1\.1 200/.test(r.output)) : r.code === 0 && r.output.startsWith(goal.expect + ' ');
    return { goal, ok, lines };
  }
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
  // Infrastructure first (switch, router, DNS/DHCP), then servers and clients; hosts added by a lab boot last.
  // Domain controllers before members (members look for a DC while they boot).
  const order = ['sw01', 'rtr01', 'fw01', 'ns1', 'dc01', 'fs01', 'srv01', 'ws01', 'ws02', 'ext01', 'dev01', 'dev02'];
  for (const id of [...order, ...Object.keys(w.hosts).filter((h) => !order.includes(h))]) if (w.hosts[id]) bootHost(w, w.hosts[id]);
  ntpSettle(w);
  syslogFlush(w);
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
      const blanket = input.rules.find((r) => r.verdict?.kind === 'accept' && (r.matches.length === 0 || r.matches.every((m) => m.kind === 'nfproto' || (m.kind === 'addr' && (m.values.includes('0.0.0.0/0') || m.values.includes('::/0'))))));
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
      return { id, ok: r.ok, required: true, message: r.ok ? `${goalLabel(goal)} still works.` : `${goalLabel(goal)} no longer works: ${r.lines[r.lines.length - 1] ?? ''}` };
    },
  };
}
