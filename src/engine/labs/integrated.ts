// Integrated labs: what the six stages need from the engine. Everything runs
// against the simulated world: request paths are probed with real commands on
// a copy of the lab, a fault is injected into the learner's own (working)
// lab, its repair is verified by checks (now and after a reboot), and the
// learner's commands are classified to give feedback on the process.

import { CAUSES } from '../scenarios/catalog';
import { rebootAll } from '../scenarios/engine';
import type { World } from '../types';
import { applySolution } from './engine';
import type { GuidedLab, LabCheck, LabFault, RequestPath } from './types';

export interface HopResult {
  id: string;
  label: string;
  role: string;
  host?: string;
  status: 'ok' | 'fail' | 'not-reached';
  evidence: string;
}

/**
 * Probe a request path hop by hop, on a copy of the world. The first failing
 * hop is where communication stops; later hops are not reached (their
 * evidence would be meaningless). The cause is left to the learner.
 */
export function probePath(world: World, path: RequestPath): HopResult[] {
  const out: HopResult[] = [];
  let stopped = false;
  for (const n of path.nodes) {
    if (stopped) { out.push({ id: n.id, label: n.label, role: n.role, host: n.host, status: 'not-reached', evidence: '' }); continue; }
    let r: { ok: boolean; evidence: string };
    try {
      r = n.probe(structuredClone(world));
    } catch (e) {
      r = { ok: false, evidence: `probe failed to run: ${(e as Error).message}` };
    }
    out.push({ id: n.id, label: n.label, role: n.role, host: n.host, status: r.ok ? 'ok' : 'fail', evidence: r.evidence });
    if (!r.ok) stopped = true;
  }
  return out;
}

export interface FaultCheck { id: string; description: string; ok: boolean; detail: string; afterReboot?: boolean }

function runChecks(checks: LabCheck[], world: World, afterReboot = false): FaultCheck[] {
  return checks.map((c) => {
    try {
      return { id: c.id, description: c.description, afterReboot, ...c.check(world) };
    } catch (e) {
      return { id: c.id, description: c.description, afterReboot, ok: false, detail: `check failed to run: ${(e as Error).message}` };
    }
  });
}

/** Is the fault repaired? Checks on the lab as it is, then on a rebooted copy. */
export function checkRepair(world: World, fault: LabFault): { passed: boolean; results: FaultCheck[] } {
  const now = runChecks(fault.checks, world);
  const after = now.every((r) => r.ok) ? runChecks(fault.checks, rebootAll(world), true) : [];
  const results = [...now, ...after];
  return { passed: now.every((r) => r.ok) && after.length > 0 && after.every((r) => r.ok), results };
}

/** Inject the lab's fault into a copy of the learner's world. */
export function injectFault(world: World, fault: LabFault): World {
  const w = structuredClone(world);
  fault.inject(w);
  return w;
}

export interface LabDiagnosisGrade {
  correct: boolean;
  missing: string[];
  wrong: { id: string; title: string; signature: string }[];
}

export function gradeLabDiagnosis(fault: LabFault, selected: string[]): LabDiagnosisGrade {
  const missing = fault.rootCauses.filter((c) => !selected.includes(c));
  const wrong = selected.filter((s) => !fault.rootCauses.includes(s)).map((id) => ({ id, title: CAUSES[id]?.title ?? id, signature: CAUSES[id]?.signature ?? '' }));
  return { correct: missing.length === 0 && wrong.length === 0, missing, wrong };
}

/** Tools that gather evidence without changing anything. */
const DIAGNOSTIC = new Set([
  'ping', 'ip', 'ss', 'netstat', 'dig', 'host', 'nslookup', 'getent', 'resolvectl', 'traceroute', 'tracepath', 'mtr', 'curl', 'wget', 'nc', 'tcpdump',
  'journalctl', 'cat', 'less', 'tail', 'head', 'grep', 'ls', 'stat', 'id', 'nft', 'iptables', 'named-checkzone', 'named-checkconf', 'nginx', 'sshd', 'testparm',
  'timedatectl', 'chronyc', 'klist', 'ldapsearch', 'ldapwhoami', 'radtest', 'docker', 'exportfs', 'showmount', 'df', 'ps', 'openssl', 'arp', 'route', 'cat',
  'Test-NetConnection', 'Resolve-DnsName', 'Get-NetIPConfiguration', 'Get-NetIPAddress', 'Get-NetRoute', 'Get-Service', 'Get-NetFirewallRule', 'Get-WinEvent',
  'Get-ADUser', 'Get-ADComputer', 'Get-ADGroupMember', 'Test-ComputerSecureChannel', 'nltest', 'w32tm', 'gpresult', 'ipconfig', 'Get-DnsClientServerAddress', 'pfctl', 'clog',
]);

export type CommandKind = 'diagnostic' | 'restart' | 'change';

/**
 * Classify one command line. Restarts (systemctl restart, reboot, Restart-Service …) are counted
 * separately: restarting is sometimes the fix, but never a substitute for finding out why.
 */
export function classifyCommand(line: string): { kind: CommandKind; tool: string } {
  const words = line.trim().replace(/^sudo\s+/, '').split(/\s+/);
  const tool = words[0] ?? '';
  if (/^(reboot|shutdown|Restart-Computer|Restart-Service)$/i.test(tool) || (tool === 'systemctl' && /^(restart|reload|try-restart|reload-or-restart)$/.test(words[1] ?? '')) || (tool === 'service' && words[2] === 'restart')) return { kind: 'restart', tool };
  if (tool === 'systemctl' && /^(status|is-active|is-enabled|is-failed|list-units|list-timers|cat|show)$/.test(words[1] ?? '')) return { kind: 'diagnostic', tool: 'systemctl' };
  if (tool === 'nft' && /^list$/.test(words[1] ?? '')) return { kind: 'diagnostic', tool };
  if (tool === 'nft') return { kind: 'change', tool };
  if (tool === 'docker' && /^(ps|logs|inspect|network|exec)$/.test(words[1] ?? '')) return { kind: 'diagnostic', tool };
  if (DIAGNOSTIC.has(tool) || /^Get-/.test(tool) || /^Test-/.test(tool)) return { kind: 'diagnostic', tool };
  return { kind: 'change', tool };
}

/**
 * Rebuild a lab from saved progress: the machines themselves are not saved,
 * so the completed steps' reference solutions are replayed, then the fault is
 * injected (and repaired) if the learner had got that far.
 */
export function rebuildLab(lab: GuidedLab, completed: string[], fault?: { injected: boolean; repaired: boolean }): World {
  let w = lab.build();
  for (const s of lab.steps) if (completed.includes(s.id) && !s.afterReboot) w = applySolution(w, s);
  const f = lab.integrated?.fault;
  if (f && fault?.injected) {
    w = injectFault(w, f);
    if (fault.repaired) w = applySolution(w, { solution: f.solution } as never);
  }
  return w;
}

/** The configuration and verification steps of an integrated lab are done. */
export function readyForFault(lab: GuidedLab, completed: string[]): boolean {
  return lab.steps.every((s) => completed.includes(s.id));
}
