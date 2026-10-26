import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { checkGoal, rebootAll, verifyScenario } from '../src/engine/scenarios/engine';
import { findScenario } from '../src/engine/scenarios';
import { parseExports, specMatches } from '../src/engine/sim/nfs';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());

describe('NFS: exports', () => {
  it('parses client lists and options like exportfs', () => {
    const r = parseExports('/srv/a  10.0.10.0/24(rw,no_root_squash) host1(ro)\n/srv/b *(rw,all_squash,anonuid=34,anongid=34)\n/srv/c 10.0.0.1(rw,bogus)\n');
    expect(r.exports.map((e) => e.path)).toEqual(['/srv/a', '/srv/b']);
    expect(r.exports[0].clients[0].options).toMatchObject({ rw: true, squash: 'none' });
    expect(r.exports[0].clients[1].options).toMatchObject({ rw: false, squash: 'root' });
    expect(r.exports[1].clients[0].options).toMatchObject({ squash: 'all', anonuid: 34 });
    expect(r.errors).toEqual(['exportfs: /etc/exports:3: unknown keyword "bogus"']);
    expect(specMatches('10.0.20.0/24', '10.0.20.10', [])).toBe(true);
    expect(specMatches('srv01.corp.lab', '10.0.20.10', ['srv01', 'srv01.corp.lab'])).toBe(true);
    expect(specMatches('*.corp.lab', '10.0.20.10', ['srv01', 'srv01.corp.lab'])).toBe(true);
    expect(specMatches('10.0.10.0/24', '10.0.20.10', [])).toBe(false);
  });

  it('exportfs -v shows the table in use; showmount -e asks the server', () => {
    const l = lab();
    expect(l.run('fs01', 'root', 'exportfs -v').output).toMatch(/^\/srv\/projects \s*\t10\.0\.10\.0\/24\(sync,wdelay,hide,no_subtree_check,sec=sys,rw,secure,root_squash,no_all_squash\)$/m);
    expect(l.run('ws01', 'alice', 'showmount -e fs01').output).toMatch(/^Export list for fs01:\n\/srv\/projects\s+10\.0\.10\.0\/24,10\.0\.20\.0\/24\n\/srv\/software\s+10\.0\.0\.0\/16$/);
  });
});

describe('NFS: mounts', () => {
  it('fstab mounts at boot; users share files by number', () => {
    const l = lab();
    expect(l.run('ws01', 'alice', 'mount -t nfs4').output).toMatch(/^fs01\.corp\.lab:\/srv\/projects on \/mnt\/projects type nfs4 \(rw,.*addr=10\.0\.20\.60\)$/);
    expect(l.run('ws01', 'root', 'journalctl -u mnt-projects.mount').output).toMatch(/Mounted mnt-projects\.mount - \/mnt\/projects\./);
    l.run('ws01', 'alice', 'echo draft > /mnt/projects/notes.txt');
    expect(l.run('fs01', 'root', 'ls -l /srv/projects/notes.txt').output).toMatch(/ alice +alice /);
    expect(l.run('fs01', 'root', 'cat /srv/projects/notes.txt').output).toBe('draft');
    expect(l.run('ws01', 'root', 'df -h').output).toMatch(/fs01\.corp\.lab:\/srv\/projects\s+98G .* \/mnt\/projects$/m);
  });

  it('root is squashed to nobody; chown and chmod from the client are refused', () => {
    const l = lab();
    expect(l.run('ws01', 'root', 'touch /mnt/projects/x').output).toBe("touch: cannot touch '/mnt/projects/x': Permission denied");
    expect(l.run('ws01', 'root', 'chmod 777 /mnt/projects').output).toBe("chmod: changing permissions of '/mnt/projects': Operation not permitted");
    expect(l.run('fs01', 'root', 'stat /srv/projects').output).toMatch(/drwxrwxr-x/);
  });

  it('read-only exports and refused clients', () => {
    const l = lab();
    expect(l.run('srv01', 'root', 'touch /opt/software/x').output).toBe("touch: cannot touch '/opt/software/x': Read-only file system");
    l.run('dev01', 'root', 'mkdir -p /mnt/p');
    expect(l.run('dev01', 'root', 'mount -t nfs4 fs01.corp.lab:/srv/projects /mnt/p').output).toBe('mount.nfs4: access denied by server while mounting fs01.corp.lab:/srv/projects');
    expect(l.run('dev01', 'root', 'mount -t nfs4 fs01.corp.lab:/srv/nothing /mnt/p').output).toBe('mount.nfs4: mounting fs01.corp.lab:/srv/nothing failed, reason given by server: No such file or directory');
  });

  it('removing a client from the export table makes its mount stale', () => {
    const l = lab();
    l.run('fs01', 'root', "sed -i 's#^/srv/projects .*#/srv/projects  10.0.10.0/24(rw,sync,no_subtree_check)#' /etc/exports");
    l.run('fs01', 'root', 'exportfs -ra');
    expect(l.run('ws01', 'alice', 'ls /mnt/projects').code).toBe(0);
    l.run('fs01', 'root', "sed -i 's#^/srv/projects .*#/srv/projects  10.0.20.0/24(rw,sync,no_subtree_check)#' /etc/exports");
    l.run('fs01', 'root', 'exportfs -ra');
    expect(l.run('ws01', 'root', 'df').output).toMatch(/df: \/mnt\/projects: Stale file handle/);
  });

  it('mounts come back after a reboot', () => {
    const w = rebootAll(buildSshLab());
    expect(w.hosts.ws01.mounts?.map((m) => m.target)).toEqual(['/mnt/projects']);
    expect(w.hosts.srv01.mounts?.map((m) => m.target)).toEqual(['/opt/software']);
  });
});

describe('NFS tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('no_root_squash or a world-writable directory breaks the backup constraint', () => {
    for (const fix of [
      ["sed -i 's#srv01.corp.lab(rw,#srv01.corp.lab(rw,no_root_squash,#' /etc/exports", 'exportfs -ra'],
      ['chmod 1777 /srv/backup'],
    ]) {
      const { s, l } = broken('nfs-root-squash');
      for (const c of fix) l.run('fs01', 'root', c);
      const v = verifyScenario(l.world, s);
      expect(v.now.every((g) => g.ok), fix.join(';')).toBe(true);
      expect(v.passed, fix.join(';')).toBe(false);
    }
  });

  it('changing alice\'s UID on fs01 instead of srv01 breaks ws01', () => {
    const { s, l } = broken('nfs-uid-mismatch');
    l.run('fs01', 'root', 'usermod -u 1001 alice');
    const v = verifyScenario(l.world, s);
    expect(v.now.map((g) => g.ok)).toEqual([true, false]);
  });

  it('exporting the share to everyone is rejected', () => {
    const { s, l } = broken('nfs-exportfs');
    l.run('fs01', 'root', "sed -i 's#^/srv/projects .*#/srv/projects  *(rw,sync,no_subtree_check)#' /etc/exports");
    l.run('fs01', 'root', 'exportfs -ra');
    expect(checkGoal(l.world, s.goals[0]).ok).toBe(true);
    expect(verifyScenario(l.world, s).passed).toBe(false);
  });
});
