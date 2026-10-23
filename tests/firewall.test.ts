import { describe, expect, it } from 'vitest';
import { NFTABLES_ASSESSMENT } from '../src/content/nftables/assessment';
import { NFTABLES_LESSON } from '../src/content/nftables/lesson';
import { LESSONS, ASSESSMENTS } from '../src/content/lessons';
import { CONCEPTS } from '../src/content/concepts';
import { explainPacket, parseRulesetFile } from '../src/engine/config/nft';
import { FIREWALL_RUNS, runVisual } from '../src/engine/lab/visualRuns';
import { SRV01_NFT, buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario, ALL_SCENARIOS } from '../src/engine/scenarios';
import { verifyScenario } from '../src/engine/scenarios/engine';
import { gradeQuestion } from '../src/learning/grading';
import { Lab } from './helpers';

const q = (id: string) => NFTABLES_ASSESSMENT.questions.find((x) => x.id === id)!;

describe('lesson registry', () => {
  it('every lesson references existing scenarios, assessments and concepts', () => {
    for (const L of LESSONS) {
      expect(ASSESSMENTS[L.assessmentId]).toBeDefined();
      for (const id of L.scenarioIds) expect(findScenario(id), id).toBeDefined();
      for (const c of L.concepts) expect(CONCEPTS[c]).toBeDefined();
      for (const qq of ASSESSMENTS[L.assessmentId].questions) for (const c of qq.concepts) expect(CONCEPTS[c], qq.id).toBeDefined();
    }
    const ids = ALL_SCENARIOS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(NFTABLES_LESSON.deployment.length).toBe(4);
  });
});

describe('nftables assessment', () => {
  it('grades the DNS rule question with th dport, sets and multiple rules', () => {
    expect(gradeQuestion(q('nft-q-dns-rule'), 'ip saddr 10.0.0.0/16 meta l4proto { tcp, udp } th dport 53 accept').correct).toBe(true);
    expect(gradeQuestion(q('nft-q-dns-rule'), 'ip saddr 10.0.0.0/16 udp dport 53 accept\nip saddr 10.0.0.0/16 tcp dport 53 accept').correct).toBe(true);
    expect(gradeQuestion(q('nft-q-dns-rule'), 'ip saddr 10.0.0.0/16 udp dport 53 accept').correct).toBe(false);
    expect(gradeQuestion(q('nft-q-dns-rule'), 'th dport 53 accept').correct).toBe(false);
  });
  it('grades CIDR and handle questions', () => {
    expect(gradeQuestion(q('nft-q-cidr'), '10.0.11.255').correct).toBe(true);
    expect(gradeQuestion(q('nft-q-cidr'), '10.0.10.255').correct).toBe(false);
    expect(gradeQuestion(q('nft-q-handles'), 'sudo nft -a list ruleset').correct).toBe(true);
  });
});

describe('rule explanation', () => {
  it('lists each rule considered and stops at the first verdict without touching counters', () => {
    const rs = parseRulesetFile(SRV01_NFT.replace('tcp dport 22 accept', 'tcp dport 22 counter accept'));
    const r = explainPacket(rs, 'input', { src: '10.0.10.25', dst: '10.0.20.10', proto: 'tcp', sport: 5, dport: 22, ctState: 'new', len: 60, iif: 'eth0' });
    expect(r.result.verdict).toBe('accept');
    expect(r.steps.map((s) => s.matched)).toEqual([false, false, false, false, false, true]);
    expect(r.steps.at(-1)!.text).toContain('tcp dport 22');
    expect(rs.tables[0].chains[0].rules[5].counter!.packets).toBe(0);
    const d = explainPacket(rs, 'input', { src: '10.0.10.25', dst: '10.0.20.10', proto: 'tcp', sport: 5, dport: 3306, ctState: 'new', len: 60, iif: 'eth0' });
    expect(d.steps.at(-1)!.outcome).toBe('end of chain → policy drop');
  });
});

describe('nftables.service semantics', () => {
  it('reload is atomic (bad file keeps old rules); restart flushes and leaves the host open', () => {
    const lab = new Lab();
    lab.run('srv01', 'root', "sed -i 's/tcp dport 22 accept/tcp dprt 22 accept/' /etc/nftables.conf");
    const reload = lab.run('srv01', 'root', 'systemctl reload nftables');
    expect(reload.code).toBe(1);
    expect(lab.world.hosts.srv01.nft.tables.length).toBe(1);
    lab.run('srv01', 'root', 'systemctl restart nftables');
    expect(lab.world.hosts.srv01.nft.tables.length).toBe(0);
    expect(lab.run('srv01', 'root', 'systemctl is-active nftables').output).toBe('failed');
    // With no ruleset, a previously dropped port is now reachable (the kernel answers RST: nothing listens on 3306).
    expect(lab.run('ws01', 'alice', 'nc -zv -w 3 srv01.corp.lab 3306').output).toMatch(/Connection refused/);
  });
});

describe('firewall visual runs', () => {
  const expectOut: Record<string, RegExp> = {
    'web-ok': /HTTP\/1.1 200 OK/, 'ssh-drop': /Connection timed out/, 'web-reset': /Couldn't connect/, 'admin-prohibited': /No route to host/,
    'forward-drop': /curl: \(28\)/, 'no-established': /no servers could be reached/, traceroute: /^ 1 {2}10\.0\.10\.1 /m,
  };
  it.each(FIREWALL_RUNS.map((r) => r.id))('%s produces a trace and the expected output', (id) => {
    const r = runVisual(FIREWALL_RUNS.find((x) => x.id === id)!);
    expect(r.trace.length).toBeGreaterThan(1);
    expect(r.output).toMatch(expectOut[id]);
  });
  it('hop notes name the deciding rule', () => {
    const r = runVisual(FIREWALL_RUNS.find((x) => x.id === 'web-ok')!);
    const notes = r.trace.flatMap((e) => e.hops ?? []).map((h) => h.note).join('\n');
    expect(notes).toMatch(/rule handle \d+ "tcp dport \{ 80, 443 \} accept" → accept/);
    expect(notes).toMatch(/"ct state established,related accept" → accept/);
    const d = runVisual(FIREWALL_RUNS.find((x) => x.id === 'no-established')!);
    expect(d.trace.some((e) => e.packet?.app?.protocol === 'DNS' && e.delivered === false && /policy drop/.test(e.outcome ?? ''))).toBe(true);
  });
});

describe('firewall scenarios reject unsafe fixes', () => {
  const setup = (id: string) => {
    const world = buildSshLab();
    findScenario(id)!.setup(world);
    return new Lab(world);
  };
  it('udp sport 53 accept restores DNS but fails the constraint', () => {
    const lab = setup('fw-no-established');
    lab.run('srv01', 'root', 'nft insert rule inet filter input udp sport 53 accept');
    lab.run('srv01', 'root', 'echo "#!/usr/sbin/nft -f" > /etc/nftables.conf');
    lab.run('srv01', 'root', 'echo "flush ruleset" >> /etc/nftables.conf');
    lab.run('srv01', 'root', 'nft list ruleset >> /etc/nftables.conf');
    const v = verifyScenario(lab.world, findScenario('fw-no-established')!);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.afterReboot.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'no-sport-53-hole')?.ok).toBe(false);
    expect(v.passed).toBe(false);
  });
  it('deleting the guest rule fixes the office but violates SEC-88', () => {
    const lab = setup('fw-cidr-guest');
    lab.run('srv01', 'root', "sed -i '/SEC-88/d' /etc/nftables.conf");
    lab.run('srv01', 'root', 'systemctl reload nftables');
    const v = verifyScenario(lab.world, findScenario('fw-cidr-guest')!);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'guest-blocked')?.ok).toBe(false);
  });
  it('setting the router forward policy to accept is rejected', () => {
    const lab = setup('fw-router-forward');
    lab.run('rtr01', 'root', "sed -i 's/hook forward priority filter; policy drop;/hook forward priority filter; policy accept;/' /etc/nftables.conf");
    lab.run('rtr01', 'root', 'systemctl reload nftables');
    const v = verifyScenario(lab.world, findScenario('fw-router-forward')!);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'rtr-forward-restrictive')?.ok).toBe(false);
  });
});

describe('nft add/delete table and chain', () => {
  it('builds a ruleset from the command line like nft does', async () => {
    const { Lab } = await import('./helpers');
    const lab = new Lab();
    const run = (c: string) => lab.run('ns1', 'root', c);
    expect(run('nft add table inet f').code).toBe(0);
    expect(run("nft add chain inet f in '{ type filter hook input priority 0; policy accept; }'").code).toBe(0);
    expect(run('nft add rule inet f in udp dport 88 drop').code).toBe(0);
    expect(run('nft list table inet f').output).toMatch(/table inet f \{\n\tchain in \{\n\t\ttype filter hook input priority filter; policy accept;\n\t\tudp dport 88 drop/);
    // UDP 88 dropped: the client falls back to TCP after three 1-second UDP timeouts.
    expect(lab.run('ws01', 'alice', 'kinit', ['Corp-Lab-2026']).code).toBe(0);
    expect(run('nft add rule inet f in tcp dport 88 drop').code).toBe(0);
    expect(lab.run('ws01', 'alice', 'kinit', ['Corp-Lab-2026']).output).toMatch(/Cannot contact any KDC/);
    expect(run('nft delete chain inet f in').output).toMatch(/Device or resource busy/);
    expect(run('nft create table inet f').output).toMatch(/File exists/);
    expect(run('nft delete table inet f').code).toBe(0);
    expect(lab.run('ws01', 'alice', 'kinit', ['Corp-Lab-2026']).code).toBe(0);
  });
});
