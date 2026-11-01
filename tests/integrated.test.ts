import { describe, expect, it } from 'vitest';
import { getLesson } from '../src/content/lessons';
import { getRef } from '../src/content/reference';
import { applySolution, checkStep } from '../src/engine/labs/engine';
import { INTEGRATED_LABS } from '../src/engine/labs';
import { checkRepair, classifyCommand, gradeLabDiagnosis, injectFault, probePath, readyForFault, rebuildLab } from '../src/engine/labs/integrated';
import { ILAB1 } from '../src/engine/labs/integrated/ilab1';
import type { GuidedLab } from '../src/engine/labs/types';
import { CAUSES } from '../src/engine/scenarios/catalog';
import { findScenario } from '../src/engine/scenarios';
import type { World } from '../src/engine/types';
import { labFeedback } from '../src/learning/labFeedback';
import { emptyProgress, loadProgress, saveProgress } from '../src/learning/progress';
import { choiceOrder } from '../src/ui/components/IntegratedLabPanels';
import { Lab } from './helpers';

const SECTIONS = ['what', 'internals', 'visualize', 'deploy', 'config', 'operate', 'troubleshoot', 'assess'];
function linkOk(link: string): boolean {
  const ref = /^reference\?id=(.+)$/.exec(link);
  if (ref) return !!getRef(ref[1]);
  const lesson = /^lesson\/([^/]+)\/([^/]+)$/.exec(link);
  if (lesson) return !!getLesson(lesson[1]) && SECTIONS.includes(lesson[2]);
  const t = /^troubleshoot\/(.+)$/.exec(link);
  if (t) return !!findScenario(t[1]);
  return false;
}

/** Build, then apply every step's reference solution. */
function finished(lab: GuidedLab): World {
  let w = lab.build();
  for (const s of lab.steps) w = applySolution(w, s);
  return w;
}

describe('integrated labs: definitions are complete and consistent', () => {
  it('ten labs, numbered 1–10, each with every stage filled in', () => {
    expect(INTEGRATED_LABS.map((l) => l.integrated?.number)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(new Set(INTEGRATED_LABS.map((l) => l.id)).size).toBe(10);
  });

  it.each(INTEGRATED_LABS.map((l) => [l.id, l] as const))('%s: scenario, dependencies, tools, fault and review are well-formed', (_id, lab) => {
    const i = lab.integrated!;
    expect(i.scenario.goal.length).toBeGreaterThan(20);
    expect(i.technologies.length).toBeGreaterThanOrEqual(3);
    expect(i.startingState.length).toBeGreaterThan(0);
    expect(i.mistakes.length).toBeGreaterThanOrEqual(3);
    expect(i.dependencies.paths.length).toBeGreaterThan(0);
    for (const t of i.tools) if (t.refId) expect(getRef(t.refId), `tool ref ${t.refId}`).toBeTruthy();
    for (const l of i.after) expect(getLesson(l), `lesson ${l}`).toBeTruthy();
    for (const p of lab.prerequisites) expect(linkOk(p.link), p.link).toBe(true);
    for (const s of lab.steps) for (const l of s.learn) expect(linkOk(l.link), `${s.id}: ${l.link}`).toBe(true);
    // The systems named in the story exist, and every terminal opens on a real account.
    const w = lab.build();
    for (const s of i.systems) expect(w.hosts[s.host], s.host).toBeDefined();
    for (const t of lab.terminals) { const h = t.kind === 'pfweb' ? t.fromHost! : t.hostId; expect(w.hosts[h]?.users[t.user], `${h}/${t.user}`).toBeDefined(); expect(w.hosts[t.hostId], t.hostId).toBeDefined(); }
    // Configure steps first, then at least one verify step; the last one reboots.
    expect(lab.steps.some((s) => s.stage === 'verify')).toBe(true);
    expect(lab.steps.at(-1)!.afterReboot).toBe(true);
    // Diagnosis: root causes are among the candidates and exist in the catalog.
    for (const c of [...i.fault.rootCauses, ...i.fault.candidates]) expect(CAUSES[c], c).toBeDefined();
    for (const c of i.fault.rootCauses) expect(i.fault.candidates).toContain(c);
    expect(i.fault.candidates.length).toBeGreaterThanOrEqual(5);
    expect(i.fault.hints.length).toBeGreaterThanOrEqual(2);
    expect(i.review.length).toBeGreaterThanOrEqual(4);
    for (const q of i.review) expect(q.answer).toBeLessThan(q.choices.length);
  });
});

describe.each(INTEGRATED_LABS.map((l) => [l.id, l] as const))('integrated lab %s: the simulation behaves', (_id, lab) => {
  it('starts broken, each step fails before its solution and passes after it, and the build survives a reboot', () => {
    let world = lab.build();
    for (const step of lab.steps.filter((s) => !s.afterReboot)) {
      const before = checkStep(world, lab, step);
      expect(before.passed, `${step.id} should not pass before its solution`).toBe(false);
      world = applySolution(world, step);
      const after = checkStep(world, lab, step);
      expect(after.results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.detail}`), step.id).toEqual([]);
    }
    const final = checkStep(world, lab, lab.steps.at(-1)!);
    expect(final.results.filter((r) => !r.ok).map((r) => `${r.step} / ${r.id}: ${r.detail}`)).toEqual([]);
  });

  it('the incident breaks a path, the diagnosis is graded, and the reference repair passes (also after a reboot)', () => {
    const f = lab.integrated!.fault;
    const good = finished(lab);
    // Every path works on the finished build.
    for (const p of lab.integrated!.dependencies.paths) expect(probePath(good, p).map((h) => `${h.id}:${h.status}`), p.id).toEqual(p.nodes.map((n) => `${n.id}:ok`));
    const broken = injectFault(good, f);
    expect(checkRepair(broken, f).passed).toBe(false);
    // The evidence shows where communication stops somewhere, without naming the cause.
    expect(lab.integrated!.dependencies.paths.some((p) => probePath(broken, p).some((h) => h.status === 'fail'))).toBe(true);
    expect(gradeLabDiagnosis(f, f.rootCauses).correct).toBe(true);
    const wrong = f.candidates.find((c) => !f.rootCauses.includes(c))!;
    expect(gradeLabDiagnosis(f, [wrong]).correct).toBe(false);
    const repaired = applySolution(broken, { solution: f.solution } as never);
    const r = checkRepair(repaired, f);
    expect(r.results.filter((x) => !x.ok).map((x) => `${x.id}: ${x.detail}`)).toEqual([]);
    expect(r.passed).toBe(true);
  });

  it('continuing from saved progress rebuilds the same state (steps replayed, incident re-injected)', () => {
    const all = lab.steps.map((s) => s.id);
    expect(readyForFault(lab, all)).toBe(true);
    const w = rebuildLab(lab, all, { injected: true, repaired: false });
    expect(checkRepair(w, lab.integrated!.fault).passed).toBe(false);
    const fixed = rebuildLab(lab, all, { injected: true, repaired: true });
    expect(checkRepair(fixed, lab.integrated!.fault).passed).toBe(true);
  });
});

describe('Integrated Lab 1: state is consistent with what the learner types', () => {
  it('starting state: no gateway on dev01, no lease on dev02, no record for dev01', () => {
    const l = new Lab(ILAB1.build());
    expect(l.run('dev01', 'root', 'ip route').output).not.toMatch(/^default/m);
    expect(l.run('dev01', 'root', 'ping -c 1 -W 2 10.0.20.10').output).toMatch(/Network is unreachable/);
    expect(l.run('dev02', 'root', 'ip -4 -br addr show eth0').output).not.toMatch(/10\.0\.30\./);
    expect(l.run('ws01', 'alice', 'getent hosts dev01.corp.lab').code).not.toBe(0);
  });

  it('a runtime-only gateway works now but is rejected (and gone after a reboot)', () => {
    const l = new Lab(ILAB1.build());
    l.run('dev01', 'root', 'ip route add default via 10.0.30.1');
    expect(l.run('dev01', 'root', 'ping -c 1 -W 2 10.0.20.10').code).toBe(0);
    const step = ILAB1.steps.find((s) => s.id === 'gateway')!;
    expect(checkStep(l.world, ILAB1, step).results[0].detail).toMatch(/gone after the next reboot/);
    l.run('dev01', 'root', 'reboot');
    expect(l.run('dev01', 'root', 'ip route').output).not.toMatch(/^default/m);
  });

  it('a DHCP scope without the router option gives a lease that only works locally', () => {
    let w = ILAB1.build();
    const l = new Lab(w);
    l.run('ns1', 'root', "printf 'subnet 10.0.30.0 netmask 255.255.255.0 {\\n    range 10.0.30.100 10.0.30.150;\\n}\\n' >> /etc/dhcp/dhcpd.conf");
    l.run('ns1', 'root', 'systemctl restart isc-dhcp-server');
    l.run('dev02', 'root', 'dhclient eth0');
    w = l.world;
    expect(l.run('dev02', 'root', 'ip -4 -br addr show eth0').output).toMatch(/10\.0\.30\.1\d\d\//);
    const step = ILAB1.steps.find((s) => s.id === 'dhcp')!;
    expect(checkStep(w, ILAB1, step).results[0].detail).toMatch(/option routers 10\.0\.30\.1/);
  });

  it('a drop rule without the DNS exception cuts name resolution, and the check says so', () => {
    let w = ILAB1.build();
    for (const s of ILAB1.steps.filter((x) => ['gateway', 'dhcp', 'dns'].includes(x.id))) w = applySolution(w, s);
    const l = new Lab(w);
    l.run('rtr01', 'root', "sed -i 's/^\\t\\ttype filter hook forward priority filter; policy drop;$/\\t\\ttype filter hook forward priority filter; policy accept;\\n\\t\\tct state established,related accept\\n\\t\\tiifname \"eth3.30\" oifname \"eth0\" drop/' /etc/nftables.conf");
    l.run('rtr01', 'root', "sed -i '/^\\tchain forward {$/,/^\\t}$/d' /etc/nftables.conf");
    l.run('rtr01', 'root', "sed -i 's/^\\tchain output {$/\\tchain forward {\\n\\t\\ttype filter hook forward priority filter; policy accept;\\n\\t\\tct state established,related accept\\n\\t\\tiifname \"eth3.30\" oifname \"eth0\" drop\\n\\t}\\n\\tchain output {/' /etc/nftables.conf");
    l.run('rtr01', 'root', 'nft -f /etc/nftables.conf');
    expect(l.run('dev02', 'root', 'getent hosts srv01.corp.lab').code).not.toBe(0);
    const step = ILAB1.steps.find((s) => s.id === 'segment')!;
    expect(checkStep(l.world, ILAB1, step).results[0].detail).toMatch(/also blocks DNS/);
  });

  it('restarting services does not repair the incident; renewing after the server fix does', () => {
    const f = ILAB1.integrated!.fault;
    const l = new Lab(injectFault(finished(ILAB1), f));
    expect(l.run('dev02', 'root', 'ip route').output).toMatch(/^default via 10\.0\.30\.254/m);
    for (const c of ['systemctl restart isc-dhcp-server', 'systemctl restart networking']) l.run(c.includes('isc') ? 'ns1' : 'dev02', 'root', c);
    l.run('rtr01', 'root', 'systemctl restart isc-dhcp-relay');
    expect(checkRepair(l.world, f).passed).toBe(false);
    // Fixing the server alone is not enough until the client renews.
    l.run('ns1', 'root', "sed -i 's/option routers 10.0.30.254;/option routers 10.0.30.1;/' /etc/dhcp/dhcpd.conf");
    l.run('ns1', 'root', 'systemctl restart isc-dhcp-server');
    expect(l.run('dev02', 'root', 'ip route').output).toMatch(/^default via 10\.0\.30\.254/m);
    l.run('dev02', 'root', 'dhclient -r eth0');
    l.run('dev02', 'root', 'dhclient eth0');
    expect(checkRepair(l.world, f).passed).toBe(true);
  });

  it('the dependency map shows where the laptop path stops during the incident', () => {
    const broken = injectFault(finished(ILAB1), ILAB1.integrated!.fault);
    const hops = probePath(broken, ILAB1.integrated!.dependencies.paths[0]);
    expect(hops.map((h) => h.status)).toEqual(['ok', 'fail', 'not-reached', 'not-reached', 'not-reached']);
    expect(hops[1].evidence).toMatch(/default via 10\.0\.30\.254[\s\S]*ping -c 1 -W 2 10\.0\.30\.254/);
  });

  it('resetting gives back exactly the starting configuration', () => {
    const a = ILAB1.build();
    const b = ILAB1.build();
    for (const [h, p] of [['dev01', '/etc/network/interfaces'], ['ns1', '/etc/dhcp/dhcpd.conf'], ['ns1', '/etc/bind/db.corp.lab'], ['rtr01', '/etc/nftables.conf']]) {
      expect(b.hosts[h].fs[p]?.content).toBe(a.hosts[h].fs[p]?.content);
    }
    expect(checkStep(b, ILAB1, ILAB1.steps[0]).passed).toBe(false);
  });
});

describe('process tracking and feedback', () => {
  it('classifies commands: evidence, restarts, changes', () => {
    expect(classifyCommand('ip route')).toEqual({ kind: 'diagnostic', tool: 'ip' });
    expect(classifyCommand('journalctl -u isc-dhcp-server')).toEqual({ kind: 'diagnostic', tool: 'journalctl' });
    expect(classifyCommand('systemctl status ssh').kind).toBe('diagnostic');
    expect(classifyCommand('systemctl restart nginx').kind).toBe('restart');
    expect(classifyCommand('Restart-Service DNS').kind).toBe('restart');
    expect(classifyCommand('reboot').kind).toBe('restart');
    // Tools that both look and change: only the read-only forms are evidence.
    expect(classifyCommand('docker restart app').kind).toBe('restart');
    expect(classifyCommand('docker compose up -d').kind).toBe('restart');
    expect(classifyCommand('docker compose logs db').kind).toBe('diagnostic');
    expect(classifyCommand('docker rm -f app').kind).toBe('change');
    expect(classifyCommand('nginx -s reload').kind).toBe('restart');
    expect(classifyCommand('nginx -t').kind).toBe('diagnostic');
    expect(classifyCommand('ip route add default via 10.0.30.1').kind).toBe('change');
    expect(classifyCommand('ip link set eth0 down').kind).toBe('change');
    expect(classifyCommand('ip -br addr').kind).toBe('diagnostic');
    expect(classifyCommand('pfctl -d').kind).toBe('change');
    expect(classifyCommand('pfctl -sr').kind).toBe('diagnostic');
    expect(classifyCommand('cat > /etc/resolv.conf').kind).toBe('change');
    expect(classifyCommand('rndc reload').kind).toBe('restart');
    expect(classifyCommand('nft list ruleset').kind).toBe('diagnostic');
    expect(classifyCommand('nft add rule inet filter input tcp dport 22 accept').kind).toBe('change');
    expect(classifyCommand("sed -i 's/a/b/' /etc/x").kind).toBe('change');
  });

  it('feedback names the subjects shown and to review, with lesson links, and comments on restarts', () => {
    const p = {
      completed: ILAB1.steps.map((s) => s.id), assisted: ['dhcp'], startedAt: 0, mode: 'guided' as const,
      tools: ['ip', 'ping', 'journalctl'],
      fault: { injectedAt: 1, commandsBefore: 1, restartsBefore: 4, diagnosis: { selected: ['dhcp-bad-option'], correct: true, attempts: 2 }, repairedAt: 2, hints: 1 },
      review: { q1: 0, q2: 1 },
    };
    const fb = labFeedback(ILAB1, p);
    const dhcp = fb.concepts.find((c) => c.id === 'net.dhcp')!;
    expect(dhcp.status).toBe('review');
    expect(dhcp.link).toMatch(/^lesson\//);
    expect(fb.concepts.find((c) => c.id === 'dns.zone')?.status).toBe('shown');
    expect(fb.process.map((x) => x.text).join(' ')).toMatch(/4 restarts or reboots before the diagnosis/);
    expect(fb.process.map((x) => x.text).join(' ')).toMatch(/Only 1 diagnostic command/);
    expect(fb.score.review).toBe(1);
  });

  it('integrated-lab progress survives saving and loading (an application restart)', () => {
    const store = new Map<string, string>();
    const storage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) };
    const p = emptyProgress();
    p.labs.ilab1 = { completed: ['gateway'], assisted: [], startedAt: 1, mode: 'independent', notes: 'gw missing', hints: 2, fault: { injectedAt: 5 }, review: { q1: 0 }, modesCompleted: ['guided'] };
    saveProgress(storage, p);
    expect(loadProgress(storage).labs.ilab1).toEqual(p.labs.ilab1);
  });

  it('review choices are shown in a fixed order that differs between questions', () => {
    const orders = ILAB1.integrated!.review.map((q) => choiceOrder(`ilab1:${q.id}`, q.choices.length));
    for (const o of orders) expect([...o].sort()).toEqual([0, 1, 2, 3]);
    expect(new Set(orders.map((o) => o.indexOf(0))).size).toBeGreaterThan(1);
    expect(choiceOrder('ilab1:q1', 4)).toEqual(choiceOrder('ilab1:q1', 4));
  });
});
