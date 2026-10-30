import { describe, expect, it } from 'vitest';
import { BACKUP_LESSON } from '../src/content/ops/backup';
import { readFile, writeFile } from '../src/engine/fs';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { verifyScenario } from '../src/engine/scenarios/engine';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());
const ENV = 'set -a; . /etc/restic/env; set +a';

describe('Shell environment', () => {
  it('export, set -a and VAR=x prefixes reach child processes; plain assignments do not', () => {
    const l = lab();
    expect(l.run('srv01', 'root', 'X=1; printenv X; echo "[$?]"').output).toBe('[1]');
    expect(l.run('srv01', 'root', 'export X=1; printenv X').output).toBe('1');
    expect(l.run('srv01', 'root', 'set -a; . /etc/restic/env; set +a; printenv RESTIC_PASSWORD_FILE').output).toBe('/etc/restic/password');
    expect(l.run('srv01', 'root', 'Y=2 printenv Y; printenv Y; echo "[$?]"').output).toBe('2\n[1]');
    expect(l.run('srv01', 'root', '. /etc/restic/env; restic snapshots').output).toMatch(/Please specify repository location/);
  });
});

describe('systemd timers', () => {
  it('list-timers shows the nightly job; systemd-analyze calendar rejects two times in one expression', () => {
    const l = lab();
    expect(l.run('srv01', 'root', 'systemctl list-timers').output).toMatch(/Tue 2026-10-20 02:30:00 UTC .* restic-backup\.timer +restic-backup\.service/);
    const bad = l.run('srv01', 'root', 'systemd-analyze calendar "*-*-* 02:30 14:30"');
    expect(bad.code).toBe(1);
    expect(bad.output).toMatch(/Failed to parse calendar specification/);
    expect(l.run('srv01', 'root', 'systemd-analyze calendar "*-*-* 02,14:30:00"').output).toMatch(/Next elapse: Mon 2026-10-19 14:30:00 UTC/);
  });

  it('a week of nightly runs is in the journal and in the repository', () => {
    const l = lab();
    expect(l.run('srv01', 'root', 'journalctl -u restic-backup.service -n 2').output).toMatch(/Finished restic-backup\.service - Nightly restic backup to bak01\./);
    expect(l.run('srv01', 'root', `${ENV}; restic snapshots`).output).toMatch(/^7 snapshots$/m);
  });
});

describe('restic', () => {
  it('a second backup only adds changes; ls and restore find the file', () => {
    const l = lab();
    const r = l.run('srv01', 'root', `${ENV}; restic backup --tag nightly /etc /var/www /root`);
    expect(r.output).toMatch(/using parent snapshot [0-9a-f]{8}\n/);
    expect(r.output).toMatch(/0 new, +0 changed/);
    expect(l.run('srv01', 'root', `${ENV}; restic ls latest /etc/hosts`).output).toMatch(/^\/etc\/hosts$/m);
    l.run('srv01', 'root', `${ENV}; restic restore latest --target /tmp/r --include /etc/hosts`);
    expect(l.run('srv01', 'root', 'diff /etc/hosts /tmp/r/etc/hosts && echo same').output).toBe('same');
  });

  it('a wrong password is refused', () => {
    const l = lab();
    l.run('srv01', 'root', "printf 'nope\\n' > /tmp/pw");
    expect(l.run('srv01', 'root', `${ENV}; restic -p /tmp/pw snapshots`).output).toMatch(/Fatal: wrong password or no key found/);
  });

  it('bak01 refuses a client key from another address', () => {
    const l = lab();
    const srv = l.world.hosts.srv01;
    // srv01's key copied to db01: authorized_keys accepts it only from 10.0.20.10.
    writeFile(l.world.hosts.db01, '/root/.ssh/id_ed25519', readFile(srv, '/root/.ssh/id_ed25519')!, l.world.clock, { mode: 0o600 });
    const r = l.run('db01', 'root', 'ssh -i /root/.ssh/id_ed25519 -o BatchMode=yes restic@bak01.corp.lab true');
    expect(r.output).toMatch(/Permission denied \(publickey,password\)/);
  });
});

describe('Review fixes: shell, timers, restic and file tools', () => {
  it('set -o forms and set -ae in a script export the environment', () => {
    const l = lab();
    expect(l.run('srv01', 'root', 'set -euo pipefail; set -o allexport; X=5; printenv X').output).toBe('5');
    expect(l.run('srv01', 'root', "printf 'set -ae\\n. /etc/restic/env\\nrestic snapshots --latest 1\\n' > /tmp/s.sh; chmod 755 /tmp/s.sh; /tmp/s.sh").output).toMatch(/^1 snapshots$/m);
  });

  it('rsync --delete skips deletion when the source cannot be read', () => {
    const l = lab();
    l.run('srv01', 'root', 'mkdir -p /tmp/d/a; rsync -a /tmp/d/ /tmp/m/');
    expect(l.run('srv01', 'root', 'rsync -a --delete /nonexist/ /tmp/m/').output).toMatch(/IO error encountered -- skipping file deletion/);
    expect(l.run('srv01', 'root', 'ls /tmp/m').output).toBe('a');
  });

  it('forget --tag leaves snapshots with other tags alone', () => {
    const l = lab();
    l.run('srv01', 'root', `${ENV}; restic backup --tag pre-upgrade /etc /var/www /root`);
    expect(l.run('srv01', 'root', `${ENV}; restic forget --tag nightly --keep-last 1 --dry-run`).output).not.toMatch(/pre-upgrade/);
  });

  it('systemd-analyze verify does not change the loaded timer', () => {
    const l = lab();
    l.run('srv01', 'root', "cp /etc/systemd/system/restic-backup.timer /tmp/d.timer; sed -i 's/02:30/05:00/' /tmp/d.timer; systemd-analyze verify /tmp/d.timer");
    expect(l.run('srv01', 'root', 'systemctl list-timers').output).toMatch(/02:30:00/);
  });
});

describe('Backup lesson: commands marked as runnable in the sandbox', () => {
  it('Deploy steps make mail01 a client of bak01 (the authorized_keys line is pasted on bak01)', () => {
    const l = lab();
    for (const g of BACKUP_LESSON.deployment) for (const s of g.steps) {
      if (/^On bak01/.test(s.title)) {
        // The step shows a placeholder key: paste mail01's real one, as a reader would.
        const pub = readFile(l.world.hosts.mail01, '/root/.ssh/id_ed25519.pub')!.trim();
        const r = l.run('bak01', 'root', `echo 'restrict,from="10.0.20.25" ${pub}' >> /home/restic/.ssh/authorized_keys`);
        expect(r.code).toBe(0);
        continue;
      }
      if (!s.simulated || !s.command) continue;
      for (const c of s.command.split('\n').filter((x) => !x.startsWith('#'))) {
        const r = l.run('mail01', 'root', c);
        expect(r.code, `${s.title}: ${c}\n${r.output}`).toBe(0);
      }
    }
    expect(l.run('mail01', 'root', 'systemctl is-enabled restic-backup.timer').output).toBe('enabled');
    // Two runs today, but --keep-daily keeps one snapshot per day.
    expect(l.run('mail01', 'root', `${ENV}; restic snapshots`).output).toMatch(/^1 snapshots$/m);
    expect(l.run('bak01', 'root', 'ls /srv/backup/restic').output).toMatch(/mail01/);
  });

  it('Operate and workflow commands run without errors (each task on a fresh lab)', () => {
    const g = BACKUP_LESSON.guide!;
    const tasks = [
      ...g.management.flatMap((m) => m.tasks.filter((t) => t.sim).map((t) => ({ name: t.task, host: /bak01/.test(m.platform) ? 'bak01' : 'srv01', command: t.command, diagnostic: false }))),
      // Workflow commands are diagnostics: an inactive unit (exit 3) can be the answer they look for.
      ...g.workflow.filter((w) => w.sim).map((w) => ({ name: w.question, host: 'srv01', command: w.command, diagnostic: true })),
    ];
    for (const t of tasks) {
      const l = lab();
      // One terminal per task, as in the sandbox: a line that loads the environment applies to the next ones.
      const sh = l.shell(t.host, 'root');
      for (const c of t.command.split('\n').filter((x) => !x.startsWith('#'))) {
        const r = sh.execute(c);
        if (t.diagnostic) expect(r.output, `${t.name}: ${t.host}# ${c}`).not.toMatch(/command not found|invalid option|unrecognized option|unknown command|syntax error|Usage:|Please specify repository/);
        else expect(r.code, `${t.name}: ${t.host}# ${c}\n${r.output}`).toBe(0);
      }
    }
  });
});

describe('Backup tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('switching host key checking off is rejected', () => {
    const { s, l } = broken('bk-hostkey-changed');
    for (const h of ['srv01', 'db01', 'fs01']) l.run(h, 'root', "printf 'Host bak01.corp.lab\\n  StrictHostKeyChecking no\\n  UserKnownHostsFile /dev/null\\n' > /root/.ssh/config; systemctl start restic-backup.service");
    const v = verifyScenario(l.world, s);
    expect(v.constraints.find((c) => c.id === 'bk-known-host')?.ok).toBe(false);
    expect(v.passed).toBe(false);
  });

  it('starting a new repository instead of unlocking loses the history', () => {
    const { s, l } = broken('bk-stale-lock');
    l.run('srv01', 'root', `sed -i 's|restic/srv01|restic/srv01-new|' /etc/restic/env; ${ENV}; restic init; systemctl start restic-backup.service`);
    expect(verifyScenario(l.world, s).passed).toBe(false);
  });

  it('removing the exclude file from the job backs up the 32 GB scratch dumps', () => {
    const { s, l } = broken('bk-db-exclude');
    l.run('db01', 'root', "printf '# Not worth backing up\\n' > /etc/restic/excludes; systemctl start restic-backup.service");
    const v = verifyScenario(l.world, s);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'bk-scratch-excluded')?.ok).toBe(false);
  });

  it('restoring all of /srv/office over the share loses today\'s minutes', () => {
    const { s, l } = broken('bk-restore-file');
    l.run('fs01', 'root', `${ENV}; rm -r /srv/office; restic restore latest --target / --include /srv/office`);
    const v = verifyScenario(l.world, s);
    expect(v.constraints.find((c) => c.id === 'bk-today-kept')?.ok).toBe(false);
  });
});
