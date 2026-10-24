import { describe, expect, it } from 'vitest';
import { parseSshdConfig, effectiveConfig } from '../src/engine/config/sshdConfig';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { rebootAll, script, verifyScenario } from '../src/engine/scenarios/engine';
import { scoredSshCheck } from '../src/engine/scenarios/scoring';
import { SCORE_PASSWORD, SCORE_USER, SCORING_SCENARIOS, scoringBaseline } from '../src/engine/scenarios/scoringScenarios';
import type { ScoredSshGoal } from '../src/engine/scenarios/types';
import type { World } from '../src/engine/types';
import { Lab } from './helpers';

const CHECK: ScoredSshGoal = { kind: 'scored-ssh', description: '', fromHost: 'ws01', fromUser: 'alice', target: 'srv01.corp.lab', user: SCORE_USER, password: SCORE_PASSWORD };

function baseline(): World {
  const w = buildSshLab();
  scoringBaseline(w);
  return w;
}
const scenario = (id: string) => SCORING_SCENARIOS.find((s) => s.id === id)!;
const errorOf = (w: World, g: ScoredSshGoal = CHECK) => scoredSshCheck(w, g).lines.at(-1)!;

describe('scoring engine SSH check (Go client messages)', () => {
  it('passes on the competition baseline, and alice keeps key-only logins', () => {
    const w = baseline();
    expect(scoredSshCheck(w, CHECK).lines.at(-1)).toBe('Status: Success!');
    expect(scoredSshCheck(w, { ...CHECK, user: 'root', password: 'Root-Score-2026' }).ok).toBe(true);
    expect(new Lab(w).run('ws01', 'alice', 'ssh srv01.corp.lab hostname').output).toBe('srv01');
  });

  it('reports each failure layer with Go\'s wording', () => {
    let w = baseline();
    expect(errorOf(w, { ...CHECK, password: 'wrong' })).toBe('Error: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain');
    // Password logins not offered to this account: Go never tries the password.
    expect(errorOf(w, { ...CHECK, user: 'alice', password: 'x' })).toBe('Error: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain');
    expect(errorOf(w, { ...CHECK, target: 'nosuch.corp.lab' })).toBe('Error: dial tcp: lookup nosuch.corp.lab on 10.0.10.53:53: no such host');
    // srv01's firewall drops ports it does not allow: no answer at all.
    expect(errorOf(w, { ...CHECK, port: 2222 })).toBe('Error: dial tcp 10.0.20.10:2222: i/o timeout');
    const stopped = structuredClone(w);
    script(stopped, 'srv01', ['systemctl stop ssh']);
    expect(errorOf(stopped)).toBe('Error: dial tcp 10.0.20.10:22: connect: connection refused');
    script(w, 'srv01', ['nft add rule inet filter input tcp dport 22 drop', 'nft insert rule inet filter input tcp dport 22 drop']);
    expect(errorOf(w)).toBe('Error: dial tcp 10.0.20.10:22: i/o timeout');
    w = baseline();
    script(w, 'srv01', [`usermod -s /usr/sbin/nologin ${SCORE_USER}`]);
    expect(scoredSshCheck(w, CHECK).lines).toContain('Error: Process exited with status 1');
    w = baseline();
    script(w, 'srv01', [`chage -E 2026-10-01 ${SCORE_USER}`]);
    expect(errorOf(w)).toBe('Error: ssh: handshake failed: EOF');
  });

  it('tries the password once, so a single check never locks the account by itself', () => {
    const w = scenario('score-faillock');
    const world = buildSshLab();
    w.setup(world);
    const lab = new Lab(world);
    lab.run('srv01', 'root', `faillock --user ${SCORE_USER} --reset`);
    scoredSshCheck(lab.world, { ...CHECK, password: 'wrong' });
    expect(lab.run('srv01', 'root', `faillock --user ${SCORE_USER}`).output.split('\n').length).toBe(2);
  });
});

describe('account tools', () => {
  it('passwd -S/-l/-u, chage -l/-E, usermod -e and /etc/shadow agree', () => {
    const lab = new Lab(baseline());
    expect(lab.run('srv01', 'root', `passwd -S ${SCORE_USER}`).output).toMatch(new RegExp(`^${SCORE_USER} P `));
    lab.run('srv01', 'root', `passwd -l ${SCORE_USER}`);
    expect(lab.run('srv01', 'root', `passwd -S ${SCORE_USER}`).output).toMatch(new RegExp(`^${SCORE_USER} L `));
    expect(lab.run('srv01', 'root', `grep ${SCORE_USER} /etc/shadow`).output).toMatch(new RegExp(`^${SCORE_USER}:!`));
    expect(errorOf(lab.world)).toMatch(/attempted methods \[none password\]/);
    lab.run('srv01', 'root', `passwd -u ${SCORE_USER}`);
    expect(errorOf(lab.world)).toBe('Status: Success!');
    lab.run('srv01', 'root', `usermod -e 2026-01-01 ${SCORE_USER}`);
    expect(lab.run('srv01', 'root', `chage -l ${SCORE_USER}`).output).toMatch(/Account expires\s+: Jan 01, 2026/);
    lab.run('srv01', 'root', `chage -E -1 ${SCORE_USER}`);
    expect(lab.run('srv01', 'root', `chage -l ${SCORE_USER}`).output).toMatch(/Account expires\s+: never/);
    expect(lab.run('srv01', 'alice', `chage -E 0 ${SCORE_USER}`).code).not.toBe(0);
  });

  it('chpasswd sets passwords from standard input and logs the change', () => {
    const lab = new Lab(baseline());
    lab.run('srv01', 'root', `echo '${SCORE_USER}:Other-Pass-1' | chpasswd`);
    expect(lab.run('srv01', 'root', 'journalctl -t chpasswd -n 1').output).toMatch(`password changed for ${SCORE_USER}`);
    expect(scoredSshCheck(lab.world, { ...CHECK, password: 'Other-Pass-1' }).ok).toBe(true);
  });

  it('pam_faillock tallies live in /var/run and are cleared by a reboot', () => {
    const world = buildSshLab();
    scenario('score-faillock').setup(world);
    const lab = new Lab(world);
    expect(lab.run('srv01', 'root', `faillock --user ${SCORE_USER}`).output).toMatch(/RHOST 10\.0\.30\.25\s+V/);
    expect(lab.run('srv01', 'root', 'journalctl -u ssh').output).toMatch(`pam_faillock(sshd:auth): Consecutive login failures for user ${SCORE_USER} account temporarily locked`);
    expect(scoredSshCheck(world, CHECK).ok).toBe(false);
    expect(scoredSshCheck(rebootAll(world), CHECK).ok).toBe(true);
  });
});

describe('scored tickets reject bad fixes', () => {
  const run = (id: string, cmds: string[]) => {
    const world = buildSshLab();
    scenario(id).setup(world);
    const lab = new Lab(world);
    for (const c of cmds) lab.run('srv01', 'root', c);
    return verifyScenario(lab.world, scenario(id));
  };

  it('faillock: removing pam_faillock or only resetting the tally is not enough', () => {
    const removed = run('score-faillock', ['printf "auth\\t[success=1 default=ignore]\\tpam_unix.so nullok\\nauth\\trequisite\\tpam_deny.so\\nauth\\trequired\\tpam_permit.so\\n" > /etc/pam.d/common-auth']);
    expect(removed.now.every((g) => g.ok)).toBe(true);
    expect(removed.passed).toBe(false);
    const resetOnly = run('score-faillock', [`faillock --user ${SCORE_USER} --reset`]);
    expect(resetOnly.now.every((g) => g.ok)).toBe(true);
    expect(resetOnly.constraints.find((c) => c.id === 'attacker-blocked')!.ok).toBe(false);
    expect(resetOnly.passed).toBe(false);
  });

  it('root: allowing root password logins globally is rejected', () => {
    const v = run('score-root-prohibit', ["sed -i 's/^PermitRootLogin no$/PermitRootLogin yes/' /etc/ssh/sshd_config.d/10-hardening.conf", "sed -i 's/prohibit-password/yes/' /etc/ssh/sshd_config.d/50-scoring.conf", 'systemctl reload ssh']);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });

  it('AllowGroups: deleting the restriction is rejected', () => {
    const v = run('score-allowgroups', ["sed -i '/^AllowGroups/d' /etc/ssh/sshd_config.d/10-hardening.conf", 'systemctl reload ssh']);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.constraints.find((c) => c.id === 'allowgroups-kept')!.ok).toBe(false);
  });

  it('password changed: opening password logins for everyone is rejected', () => {
    const v = run('score-password-changed', [`echo '${SCORE_USER}:${SCORE_PASSWORD}' | chpasswd`, "sed -i 's/^PasswordAuthentication no$/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/10-hardening.conf", 'systemctl reload ssh']);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(v.passed).toBe(false);
  });
});

describe('sshd_config: Match blocks and Include', () => {
  it('a Match block in an included file ends with that file', () => {
    const files: Record<string, string> = {
      // Debian's layout: the Include comes first, the main settings after it.
      '/etc/ssh/sshd_config': 'Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nUsePAM yes\nX11Forwarding yes\n',
      '/etc/ssh/sshd_config.d/50-x.conf': 'Match Group scored\n    PasswordAuthentication yes\nMatch User root Address 10.0.10.25\n    PermitRootLogin yes\n',
    };
    const parsed = parseSshdConfig('/etc/ssh/sshd_config', (p) => files[p], () => Object.keys(files));
    expect(parsed.global.map((d) => d.key)).toContain('usepam');
    const e = effectiveConfig(parsed, { user: 'joe', groups: ['scored'], address: '10.0.10.25' });
    expect(e.usePAM).toBe(true);
    expect(e.passwordAuthentication).toBe(true);
    expect(effectiveConfig(parsed, { user: 'joe', groups: ['joe'], address: '10.0.10.25' }).passwordAuthentication).toBe(false);
  });
});
