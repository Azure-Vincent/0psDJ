import { describe, expect, it } from 'vitest';
import { getLesson } from '../src/content/lessons';
import { getRef } from '../src/content/reference';
import { applySolution, checkStep } from '../src/engine/labs/engine';
import { GUIDED_LABS } from '../src/engine/labs';
import { LAB1 } from '../src/engine/labs/lab1';
import { LAB2 } from '../src/engine/labs/lab2';
import type { World } from '../src/engine/types';
import { Lab } from './helpers';

const LESSON_SECTIONS = ['what', 'internals', 'visualize', 'deploy', 'config', 'operate', 'troubleshoot', 'assess'];

function linkResolves(link: string): boolean {
  const ref = /^reference\?id=(.+)$/.exec(link);
  if (ref) return !!getRef(ref[1]);
  const lesson = /^lesson\/([^/]+)\/([^/]+)$/.exec(link);
  if (lesson) return !!getLesson(lesson[1]) && LESSON_SECTIONS.includes(lesson[2]);
  return false;
}

describe('guided labs', () => {
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

  it.each(GUIDED_LABS.map((l) => l.id))('%s: links, terminals and solutions are well-formed', (id) => {
    const lab = GUIDED_LABS.find((l) => l.id === id)!;
    const world = lab.build();
    for (const p of lab.prerequisites) expect(linkResolves(p.link), p.link).toBe(true);
    for (const s of lab.steps) for (const l of s.learn) expect(linkResolves(l.link), `${s.id}: ${l.link}`).toBe(true);
    for (const t of lab.terminals) expect(world.hosts[t.hostId]?.users[t.user], `${t.hostId}/${t.user}`).toBeDefined();
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
