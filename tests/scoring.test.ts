import { describe, expect, it } from 'vitest';
import { parseSshdConfig, effectiveConfig } from '../src/engine/config/sshdConfig';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { rebootAll, script, verifyScenario } from '../src/engine/scenarios/engine';
import { scoredDnsCheck, scoredSshCheck, scoredWebCheck } from '../src/engine/scenarios/scoring';
import { DNS_CHECK, SCORING_WEB_DNS_SCENARIOS, WEB_CHECK, webBaseline } from '../src/engine/scenarios/scoringWebDnsScenarios';
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
    // srv01's firewall drops ports it does not allow: no answer at all, so the engine's check deadline fires first.
    expect(scoredSshCheck(w, { ...CHECK, port: 2222 }).lines.slice(1)).toEqual(['Status: Encountered an unexpected error during the check.', 'Error: check timed out. this is most likely due to services timing out']);
    const stopped = structuredClone(w);
    script(stopped, 'srv01', ['systemctl stop ssh']);
    expect(errorOf(stopped)).toBe('Error: dial tcp 10.0.20.10:22: connect: connection refused');
    script(w, 'srv01', ['nft add rule inet filter input tcp dport 22 drop', 'nft insert rule inet filter input tcp dport 22 drop']);
    expect(errorOf(w)).toBe('Error: check timed out. this is most likely due to services timing out');
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

describe('systemctl mask', () => {
  it('refuses start and enable, shows masked, and keeps the unit down across a reboot until unmasked', () => {
    const lab = new Lab(baseline());
    expect(lab.run('srv01', 'root', 'systemctl mask ssh').output).toMatch(/Created symlink .* → \/dev\/null\./);
    expect(lab.run('srv01', 'root', 'systemctl is-enabled ssh').output).toBe('masked');
    expect(lab.run('srv01', 'root', 'systemctl start ssh').output).toMatch(/Unit ssh\.service is masked\./);
    expect(lab.run('srv01', 'root', 'systemctl enable ssh').code).not.toBe(0);
    expect(lab.run('srv01', 'root', 'systemctl status ssh').output).toMatch(/Loaded: masked/);
    lab.run('srv01', 'root', 'systemctl stop ssh');
    expect(errorOf(rebootAll(lab.world))).toBe('Error: dial tcp 10.0.20.10:22: connect: connection refused');
    expect(lab.run('srv01', 'alice', 'systemctl unmask ssh').code).not.toBe(0);
    lab.run('srv01', 'root', 'systemctl unmask ssh');
    lab.run('srv01', 'root', 'systemctl start ssh');
    expect(errorOf(lab.world)).toBe('Status: Success!');
  });
});

describe('scoring engine web and DNS checks', () => {
  const lab = () => { const w = buildSshLab(); webBaseline(w); return w; };
  const web = (w: World, g = WEB_CHECK) => scoredWebCheck(w, g).lines.slice(1);
  const dns = (w: World, g = DNS_CHECK) => scoredDnsCheck(w, g).lines.slice(1);

  it('pass on the baseline and report each layer with Go\'s wording', () => {
    let w = lab();
    expect(web(w)).toEqual(['Status: Success!']);
    expect(dns(w)).toEqual(['Status: Success!']);
    expect(web(w, { ...WEB_CHECK, url: 'https://www.corp.lab/' })).toEqual(['Status: Success!']);
    expect(web(w, { ...WEB_CHECK, url: 'http://srv01.corp.lab:22/' }).at(-1)).toMatch(/malformed HTTP response "SSH-2\.0-OpenSSH/);
    expect(web(w, { ...WEB_CHECK, url: 'https://www.corp.lab:80/' }).at(-1)).toBe('Error: Get "https://www.corp.lab:80/": http: server gave HTTP response to HTTPS client');
    expect(web(w, { ...WEB_CHECK, url: 'http://nosuch.corp.lab/' }).at(-1)).toBe('Error: Get "http://nosuch.corp.lab/": dial tcp: lookup nosuch.corp.lab on 10.0.10.53:53: no such host');
    expect(web(w, { ...WEB_CHECK, url: 'http://www.corp.lab/missing.html' }).at(-1)).toBe('Error: expected status code 200, got 404 (404 Not Found)');
    expect(dns(w, { ...DNS_CHECK, name: 'nosuch.corp.lab' }).at(-1)).toBe('Error: nosuch.corp.lab. A: server answered NXDOMAIN (no such name)');
    script(w, 'ns1', ['systemctl stop named']);
    expect(dns(w).at(-1)).toMatch(/^Error: read udp 10\.0\.10\.25:\d+->10\.0\.10\.53:53: read: connection refused$/);
    w = lab();
    script(w, 'ns1', ["sed -i 's/^srv01   IN A    10.0.20.10$/srv01   IN A    10.0.20.300/' /etc/bind/db.corp.lab", 'systemctl restart named']);
    expect(dns(w).at(-1)).toBe('Error: www.corp.lab. A: server answered SERVFAIL');
    // SERVFAIL while resolving the web check's host name: Go says "server misbehaving".
    expect(web(w).at(-1)).toBe('Error: Get "http://www.corp.lab/": dial tcp: lookup www.corp.lab on 10.0.10.53:53: server misbehaving');
  });

  it('nginx logs the engine\'s requests and explains a 403', () => {
    const world = buildSshLab();
    SCORING_WEB_DNS_SCENARIOS.find((s) => s.id === 'score-web-forbidden')!.setup(world);
    const l = new Lab(world);
    expect(l.run('srv01', 'root', 'tail -n 1 /var/log/nginx/access.log').output).toMatch(/^10\.0\.10\.25 - - \[.*\] "GET \/ HTTP\/1\.1" 403 \d+ "-" "Go-http-client\/1\.1"$/);
    expect(l.run('srv01', 'root', 'tail -n 1 /var/log/nginx/error.log').output).toMatch(/"\/var\/www\/html\/index\.html" is forbidden \(13: Permission denied\), client: 10\.0\.10\.25/);
    expect(l.run('srv01', 'root', 'namei -l /var/www/html/index.html').output.split('\n')).toEqual(['f: /var/www/html/index.html', 'drwxr-xr-x root root /', 'drwxr-xr-x root root var', 'drwxr-x--- root root www', 'drwxr-x--- root root html', '-rw-r----- root root index.html']);
    // curl -i: the status line and headers, then the body (as the engine sees it).
    expect(l.run('ws01', 'alice', 'curl -sS -i http://www.corp.lab/').output).toMatch(/^HTTP\/1\.1 403 Forbidden\nServer: nginx\/1\.22\.1\n[\s\S]*\n\n<html>\n<head><title>403 Forbidden<\/title>/);
    // chmod X: execute for directories only.
    l.run('srv01', 'root', 'chmod -R o+rX /var/www');
    expect(l.run('srv01', 'root', 'stat /var/www/html/index.html').output).toMatch(/Access: \(0644\/-rw-r--r--\)/);
    expect(l.run('srv01', 'root', 'stat /var/www/html').output).toMatch(/Access: \(0755\/drwxr-xr-x\)/);
  });

  it('BIND rejects a bad address and a CNAME with other data', () => {
    const l = new Lab(buildSshLab());
    l.run('ns1', 'root', "sed -i 's/^www     IN CNAME srv01$/&\\nwww     IN A    10.0.20.10/' /etc/bind/db.corp.lab");
    expect(l.run('ns1', 'root', 'named-checkzone corp.lab /etc/bind/db.corp.lab').output).toMatch(/www\.corp\.lab: CNAME and other data/);
  });
});

describe('scored web and DNS tickets reject bad fixes', () => {
  const run = (id: string, host: string, cmds: string[]) => {
    const s = SCORING_WEB_DNS_SCENARIOS.find((x) => x.id === id)!;
    const world = buildSshLab();
    s.setup(world);
    const l = new Lab(world);
    for (const c of cmds) l.run(host, 'root', c);
    return verifyScenario(l.world, s);
  };
  const failed = (v: ReturnType<typeof verifyScenario>) => v.constraints.filter((c) => !c.ok).map((c) => c.id);

  it('403: chmod 777 serves the page but makes it writable', () => {
    const v = run('score-web-forbidden', 'srv01', ['chmod -R 777 /var/www']);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(failed(v)).toContain('web-files-protected');
  });
  it('defaced: restoring the page without fixing its mode is not enough', () => {
    const v = run('score-web-defaced', 'srv01', ['cp /var/backups/www/index.html /var/www/html/index.html']);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(failed(v)).toEqual(['web-files-protected']);
  });
  it('certificate renamed: renaming the files back is a valid fix too', () => {
    const v = run('score-web-cert-renamed', 'srv01', ['mv /etc/ssl/certs/www.corp.lab-2026.crt /etc/ssl/certs/www.corp.lab.crt', 'mv /etc/ssl/private/www.corp.lab-2026.key /etc/ssl/private/www.corp.lab.key', 'systemctl restart nginx']);
    expect(v.passed).toBe(true);
  });
  it('HTTPS only: a redirect to HTTPS does not satisfy an engine that does not follow redirects', () => {
    const s = SCORING_WEB_DNS_SCENARIOS.find((x) => x.id === 'score-web-https-only')!;
    const world = buildSshLab();
    s.setup(world);
    script(world, 'srv01', ["sed -i 's/^\\(\\s*\\)tcp dport 443 accept$/\\1tcp dport { 80, 443 } accept/' /etc/nftables.conf", 'systemctl reload nftables']);
    script(world, 'srv01', ["sed -i 's|^        root /var/www/html;$|        return 301 https://$host$request_uri;|' /etc/nginx/nginx.conf", 'systemctl reload nginx']);
    expect(scoredWebCheck(world, WEB_CHECK).lines.at(-1)).toBe('Error: expected status code 200, got 301 (301 Moved Permanently)');
  });
  it('SERVFAIL: deleting the teammate\'s record is rejected', () => {
    const v = run('score-dns-servfail', 'ns1', ["sed -i '/^mail/d' /etc/bind/db.corp.lab", 'rndc reload']);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(failed(v)).toEqual(['mail-record-kept']);
  });
  it('DNS firewall: flushing the ruleset is rejected', () => {
    const v = run('score-dns-firewall', 'ns1', ['nft flush ruleset']);
    expect(v.now.every((g) => g.ok)).toBe(true);
    expect(failed(v)).toContain('fw-restrictive-ns1');
  });
});
