import { describe, expect, it } from 'vitest';
import { getLesson } from '../src/content/lessons';
import { getRef } from '../src/content/reference';
import { applySolution, checkStep, printfTo } from '../src/engine/labs/engine';
import { GUIDED_LABS } from '../src/engine/labs';
import { LAB1 } from '../src/engine/labs/lab1';
import { LAB2 } from '../src/engine/labs/lab2';
import { LAB3 } from '../src/engine/labs/lab3';
import { LAB4 } from '../src/engine/labs/lab4';
import { LAB5 } from '../src/engine/labs/lab5';
import { LAB6 } from '../src/engine/labs/lab6';
import { findScenario } from '../src/engine/scenarios';
import { rebootAll } from '../src/engine/scenarios/engine';
import type { World } from '../src/engine/types';
import { Lab } from './helpers';

const LESSON_SECTIONS = ['what', 'internals', 'visualize', 'deploy', 'config', 'operate', 'troubleshoot', 'assess'];

function linkResolves(link: string): boolean {
  const ref = /^reference\?id=(.+)$/.exec(link);
  if (ref) return !!getRef(ref[1]);
  const lesson = /^lesson\/([^/]+)\/([^/]+)$/.exec(link);
  if (lesson) return !!getLesson(lesson[1]) && LESSON_SECTIONS.includes(lesson[2]);
  const ticket = /^troubleshoot\/(.+)$/.exec(link);
  if (ticket) return !!findScenario(ticket[1]);
  return false;
}

describe('guided labs: Labs 5 and 6 reject the tempting wrong fixes', () => {
  const upTo = (lab: typeof LAB5, id: string): World => {
    let w = lab.build();
    for (const s of lab.steps) { if (s.id === id) break; w = applySolution(w, s); }
    return w;
  };
  const runAll = (w: World, host: string, user: string, lines: string[]): World => {
    const l = new Lab(w);
    for (const line of lines) l.run(host, user, line);
    return l.world;
  };
  const failing = (w: World, lab: typeof LAB5, id: string) => checkStep(w, lab, lab.steps.find((s) => s.id === id)!).results.filter((r) => !r.ok).map((r) => r.detail).join(' | ');

  it('Lab 6: runtime-only fixes and the old backup are caught', () => {
    let w = upTo(LAB6, 'routing');
    w = runAll(w, 'rtr01', 'root', ['sysctl -w net.ipv4.ip_forward=1']);
    expect(failing(w, LAB6, 'routing')).toMatch(/next boot sets net\.ipv4\.ip_forward=0 \(not set\)/);
    w = upTo(LAB6, 'dns');
    w = runAll(w, 'ns1', 'root', ['cp /var/backups/bind/db.corp.lab.2026-10-12 /etc/bind/db.corp.lab', 'rndc reload']);
    expect(failing(w, LAB6, 'dns')).toMatch(/fs01\.corp\.lab/);
    w = upTo(LAB6, 'time');
    w = runAll(w, 'rtr01', 'root', ['systemctl start chrony']);
    expect(failing(w, LAB6, 'time')).toMatch(/not enabled/);
    w = upTo(LAB6, 'apps');
    w = runAll(w, 'dock01', 'root', ['docker start inventory-db-1 inventory-app-1']);
    w = runAll(w, 'srv01', 'root', ['systemctl start nginx']);
    expect(failing(w, LAB6, 'apps')).toMatch(/will not be started by dockerd after the next reboot/);
  });

  it('review fixes: rtr01\'s other address counts for NTP; a non-.conf sysctl file does not; printfTo survives % and quotes', () => {
    let w = upTo(LAB5, 'time');
    w = runAll(w, 'app01', 'root', ["printf '[Time]\\nNTP=10.0.20.1\\n' > /etc/systemd/timesyncd.conf", 'systemctl restart systemd-timesyncd']);
    expect(failing(w, LAB5, 'time')).toBe('');
    let v = upTo(LAB6, 'routing');
    v = runAll(v, 'rtr01', 'root', ["printf 'net.ipv4.ip_forward=1\\n' > /etc/sysctl.d/99-router", 'sysctl -w net.ipv4.ip_forward=1']);
    expect(failing(v, LAB6, 'routing')).toMatch(/files without \.conf are ignored/);
    let z = upTo(LAB6, 'routing');
    z = runAll(z, 'rtr01', 'root', ["printf 'net.ipv4.ip_forward=1\\n' > /etc/sysctl.d/10-router.conf", "printf 'net.ipv4.ip_forward=0\\n' > /etc/sysctl.d/99-cis.conf", 'sysctl -w net.ipv4.ip_forward=1']);
    expect(failing(z, LAB6, 'routing')).toMatch(/next boot sets net\.ipv4\.ip_forward=0/);
    expect(rebootAll(z).hosts.rtr01.ipForward).toBe(false);
    const text = "log_format main '%h %t \\\\n';\nit's 100%\n";
    const t = runAll(LAB5.build(), 'app01', 'root', [printfTo(text, '/tmp/t.txt')]);
    expect(t.hosts.app01.fs['/tmp/t.txt'].content).toBe(text);
  });

  it('Lab 5: a wide export, usermod -G without -a, and an open port 80 are caught', () => {
    let w = upTo(LAB5, 'nfs');
    w = applySolution(w, { ...LAB5.steps.find((s) => s.id === 'nfs')!, solution: LAB5.steps.find((s) => s.id === 'nfs')!.solution.map((x) => ({ ...x, commands: x.commands.map((c) => c.replace('10.0.20.70(rw', '10.0.20.0/24(rw')) })) });
    expect(failing(w, LAB5, 'nfs')).toMatch(/also exported to 10\.0\.20\.0\/24/);
    w = upTo(LAB5, 'smb');
    w = applySolution(w, { ...LAB5.steps.find((s) => s.id === 'smb')!, solution: LAB5.steps.find((s) => s.id === 'smb')!.solution.map((x) => ({ ...x, commands: x.commands.map((c) => c.replace('usermod -aG finance', 'usermod -G finance')) })) });
    expect(failing(w, LAB5, 'smb')).toMatch(/dana lost \[office\]/);
    w = upTo(LAB5, 'firewall');
    w = applySolution(w, { ...LAB5.steps.find((s) => s.id === 'firewall')!, solution: LAB5.steps.find((s) => s.id === 'firewall')!.solution.map((x) => ({ ...x, commands: x.commands.map((c) => c.replace('ip saddr 10.0.20.10 tcp dport 80', 'tcp dport 80')) })) });
    expect(failing(w, LAB5, 'firewall')).toMatch(/ws01 connects to app01:80 directly/);
  });
});

describe('guided labs', () => {
  it('Lab 6: each step fails before its solution and passes after it; the reboot test passes at the end', () => {
    let world: World = LAB6.build();
    for (const step of LAB6.steps.filter((s) => !s.afterReboot)) {
      const before = checkStep(world, LAB6, step);
      expect(before.passed, `${step.id} should not pass before its solution`).toBe(false);
      world = applySolution(world, step);
      const after = checkStep(world, LAB6, step);
      expect(after.results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.detail}`), step.id).toEqual([]);
    }
    const final = checkStep(world, LAB6, LAB6.steps.at(-1)!);
    expect(final.results.filter((r) => !r.ok).map((r) => `${r.step} / ${r.id}: ${r.detail}`)).toEqual([]);
  });

  it('Lab 5: each step fails before its solution and passes after it; the reboot test passes at the end', () => {
    let world: World = LAB5.build();
    for (const step of LAB5.steps.filter((s) => !s.afterReboot)) {
      const before = checkStep(world, LAB5, step);
      expect(before.passed, `${step.id} should not pass before its solution`).toBe(false);
      world = applySolution(world, step);
      const after = checkStep(world, LAB5, step);
      expect(after.results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.detail}`), step.id).toEqual([]);
    }
    const final = checkStep(world, LAB5, LAB5.steps.at(-1)!);
    expect(final.results.filter((r) => !r.ok).map((r) => `${r.step} / ${r.id}: ${r.detail}`)).toEqual([]);
  });

  it('Lab 2: each step fails before its solution and passes after it; the reboot test passes at the end', () => {
    let world: World = LAB2.build();
    for (const step of LAB2.steps.filter((s) => !s.afterReboot)) {
      const before = checkStep(world, LAB2, step);
      expect(before.passed, `${step.id} should not pass before its solution`).toBe(false);
      world = applySolution(world, step);
      const after = checkStep(world, LAB2, step);
      expect(after.results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.detail}`), step.id).toEqual([]);
    }
    const final = checkStep(world, LAB2, LAB2.steps.at(-1)!);
    expect(final.results.filter((r) => !r.ok).map((r) => `${r.step} / ${r.id}: ${r.detail}`)).toEqual([]);
  });

  it('Lab 3: each step fails before its solution and passes after it; the reboot test passes at the end', () => {
    let world: World = LAB3.build();
    for (const step of LAB3.steps.filter((s) => !s.afterReboot)) {
      const before = checkStep(world, LAB3, step);
      expect(before.passed, `${step.id} should not pass before its solution`).toBe(false);
      world = applySolution(world, step);
      const after = checkStep(world, LAB3, step);
      expect(after.results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.detail}`), step.id).toEqual([]);
    }
    const final = checkStep(world, LAB3, LAB3.steps.at(-1)!);
    expect(final.results.filter((r) => !r.ok).map((r) => `${r.step} / ${r.id}: ${r.detail}`)).toEqual([]);
  });

  it('Lab 4: each step fails before its solution and passes after it; the reboot test passes at the end', () => {
    let world: World = LAB4.build();
    for (const step of LAB4.steps.filter((s) => !s.afterReboot)) {
      const before = checkStep(world, LAB4, step);
      expect(before.passed, `${step.id} should not pass before its solution`).toBe(false);
      world = applySolution(world, step);
      const after = checkStep(world, LAB4, step);
      expect(after.results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.detail}`), step.id).toEqual([]);
    }
    const final = checkStep(world, LAB4, LAB4.steps.at(-1)!);
    expect(final.results.filter((r) => !r.ok).map((r) => `${r.step} / ${r.id}: ${r.detail}`)).toEqual([]);
  });

  it('Lab 4: reloading nftables removes Docker\'s tables until dockerd is restarted', () => {
    let world: World = LAB4.build();
    for (const step of LAB4.steps.slice(0, 4)) world = applySolution(world, step);
    const fw = LAB4.steps.find((s) => s.id === 'firewall')!;
    const l = new Lab(world);
    l.run('dock01', 'root', fw.solution[0].commands[0]);
    l.run('dock01', 'root', 'systemctl restart nftables');
    expect(l.run('ws01', 'alice', 'curl -sS -m 5 http://inventory.corp.lab:8000/health').output).toMatch(/curl: \(28\)/);
    l.run('dock01', 'root', 'systemctl restart docker');
    expect(l.run('ws01', 'alice', 'curl -sS -m 5 http://inventory.corp.lab:8000/health').output).toBe('{"status":"ok","database":"ok"}');
  });

  it.each(GUIDED_LABS.map((l) => l.id))('%s: links, terminals and solutions are well-formed', (id) => {
    const lab = GUIDED_LABS.find((l) => l.id === id)!;
    const world = lab.build();
    for (const p of lab.prerequisites) expect(linkResolves(p.link), p.link).toBe(true);
    for (const s of lab.steps) for (const l of s.learn) expect(linkResolves(l.link), `${s.id}: ${l.link}`).toBe(true);
    for (const t of lab.terminals) {
      const h = t.kind === 'pfweb' ? t.fromHost! : t.hostId;
      expect(world.hosts[h]?.users[t.user], `${h}/${t.user}`).toBeDefined();
      expect(world.hosts[t.hostId], t.hostId).toBeDefined();
    }
    expect(lab.steps.at(-1)!.afterReboot).toBe(true);
  });

  it('Lab 1: each step fails before its solution and passes after it; the reboot test passes at the end', () => {
    let world: World = LAB1.build();
    for (const step of LAB1.steps.filter((s) => !s.afterReboot)) {
      const before = checkStep(world, LAB1, step);
      expect(before.passed, `${step.id} should not pass before its solution`).toBe(false);
      world = applySolution(world, step);
      const after = checkStep(world, LAB1, step);
      expect(after.results.filter((r) => !r.ok).map((r) => `${r.id}: ${r.detail}`), step.id).toEqual([]);
    }
    const final = checkStep(world, LAB1, LAB1.steps.at(-1)!);
    expect(final.results.filter((r) => !r.ok).map((r) => `${r.step} / ${r.id}: ${r.detail}`)).toEqual([]);
    expect(final.results.length).toBe(LAB1.steps.flatMap((s) => s.checks).length);
  });

  it('Lab 1: runtime-only changes pass their step but fail the reboot test', () => {
    let world: World = LAB1.build();
    for (const step of LAB1.steps.filter((s) => !s.afterReboot && s.id !== 'firewall')) world = applySolution(world, step);
    // Load the firewall by hand without enabling the service.
    const lab = new Lab(world);
    const fw = LAB1.steps.find((s) => s.id === 'firewall')!;
    lab.run('srv02', 'root', fw.solution[0].commands[0]);
    lab.run('srv02', 'root', 'nft -f /etc/nftables.conf');
    const step = checkStep(lab.world, LAB1, fw);
    expect(step.results.find((r) => r.id === 'fw-enabled')!.ok).toBe(false);
    expect(step.results.find((r) => r.id === 'fw-policy')!.ok).toBe(true);
    const reboot = checkStep(lab.world, LAB1, LAB1.steps.at(-1)!);
    expect(reboot.passed).toBe(false);
    expect(reboot.results.find((r) => r.id === 'fw-policy')!.detail).toMatch(/policy is accept|No input base chain/);
  });

  it('Lab 1: the password check really tries a password login', () => {
    let world: World = LAB1.build();
    for (const step of LAB1.steps.filter((s) => ['switch-port', 'static-ip', 'resolver', 'dns-record', 'ssh-keys'].includes(s.id))) world = applySolution(world, step);
    const hardening = LAB1.steps.find((s) => s.id === 'ssh-hardening')!;
    const pw = (w: World) => checkStep(w, LAB1, hardening).results.find((r) => r.id === 'ssh-password-rejected')!;
    expect(pw(world).ok).toBe(false);
    world = applySolution(world, hardening);
    expect(pw(world)).toMatchObject({ ok: true, detail: expect.stringMatching(/Permission denied \(publickey\)/) });
  });

  it('Lab 1: the starting state shows the symptoms the first step describes', () => {
    const lab = new Lab(LAB1.build());
    expect(lab.run('srv02', 'root', 'ip -br link show eth0').output).toMatch(/NO-CARRIER/);
    expect(lab.run('sw01', 'root', 'ip -br link show swp10').output).toMatch(/DOWN/);
    expect(lab.run('srv02', 'root', 'journalctl -u networking -b').output).toMatch(/No DHCPOFFERS received/);
    expect(lab.run('srv02', 'root', 'systemctl is-enabled nftables').output).toBe('disabled');
  });
});
