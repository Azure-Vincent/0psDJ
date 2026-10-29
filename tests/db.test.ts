import { describe, expect, it } from 'vitest';
import { buildSshLab } from '../src/engine/lab/sshLab';
import { findScenario } from '../src/engine/scenarios';
import { verifyScenario } from '../src/engine/scenarios/engine';
import { parseHba } from '../src/engine/sim/postgres';
import { Lab } from './helpers';

const lab = () => new Lab(buildSshLab());
const LOG = '/var/log/postgresql/postgresql-15-main.log';

describe('PostgreSQL server', () => {
  it('pg_hba.conf: the first matching line decides', () => {
    const p = parseHba('local all postgres peer\nhost inventory webapp 10.0.20.10/32 scram-sha-256\nhost all all 10.0.20.0/24 reject\n');
    expect(p.rules.map((r) => r.method)).toEqual(['peer', 'scram-sha-256', 'reject']);
  });

  it('cluster tools and the superuser session through peer authentication', () => {
    const l = lab();
    expect(l.run('db01', 'root', 'pg_lsclusters').output).toMatch(/^15\s+main\s+5432 online postgres \/var\/lib\/postgresql\/15\/main/m);
    expect(l.run('db01', 'root', 'psql -c "SELECT 1"').output).toMatch(/role "root" does not exist|Peer authentication failed/);
    expect(l.run('db01', 'root', 'sudo -u postgres psql -A -t -c "SELECT count(*) FROM orders" -d inventory').output).toBe('6');
  });

  it('the application connects; other clients are refused by pg_hba.conf and logged', () => {
    const l = lab();
    expect(l.run('srv01', 'root', 'inventory-check').output).toMatch(/^\d+$/);
    const r = l.run('ws01', 'alice', 'psql -h db01.corp.lab -U webapp -d inventory -c "SELECT 1"');
    expect(r.code).not.toBe(0);
    expect(r.output).toMatch(/FATAL: {2}no pg_hba\.conf entry for host "10\.0\.10\.25", user "webapp", database "inventory"/);
    expect(l.run('db01', 'root', `tail -n 3 ${LOG}`).output).toMatch(/FATAL: {2}no pg_hba\.conf entry for host "10\.0\.10\.25"/);
  });

  it('listen_addresses needs a restart; a reload only logs that it was not applied', () => {
    const l = lab();
    l.run('db01', 'root', "printf \"listen_addresses = 'localhost'\\n\" > /etc/postgresql/15/main/conf.d/zz-local.conf");
    l.run('db01', 'root', 'systemctl reload postgresql');
    expect(l.run('db01', 'root', `tail -n 5 ${LOG}`).output).toMatch(/cannot be changed without restarting the server/);
    expect(l.run('srv01', 'root', 'pg_isready -h db01.corp.lab').output).toMatch(/accepting connections/);
    l.run('db01', 'root', 'systemctl restart postgresql');
    expect(l.run('srv01', 'root', 'pg_isready -h db01.corp.lab').output).toMatch(/no response/);
  });

  it('privileges: a role without a grant is refused per table', () => {
    const l = lab();
    l.run('db01', 'root', `sudo -u postgres psql -d inventory -c "CREATE ROLE viewer LOGIN PASSWORD 'x'" -c "GRANT SELECT ON items TO viewer"`);
    expect(l.run('db01', 'root', 'sudo -u postgres psql -d inventory -c "\\dp items"').output).toMatch(/viewer=r\/invowner/);
  });

  it('backups: pg_restore lists the nightly archive', () => {
    const l = lab();
    const out = l.run('db01', 'root', 'pg_restore -l /var/backups/postgresql/inventory.dump').output;
    expect(out).toMatch(/TABLE DATA public orders invowner/);
    expect(out).toMatch(/Format: CUSTOM/);
  });
});

describe('Database tickets: wrong fixes are rejected', () => {
  const broken = (id: string) => {
    const s = findScenario(id)!;
    const world = buildSshLab();
    s.setup(world);
    return { s, l: new Lab(world) };
  };

  it('a reload does not apply listen_addresses', () => {
    const { s, l } = broken('db-listen-default');
    l.run('db01', 'root', "printf \"listen_addresses = '*'\\n\" > /etc/postgresql/15/main/conf.d/listen.conf; systemctl reload postgresql");
    expect(verifyScenario(l.world, s).now[0].ok).toBe(false);
  });

  it('opening pg_hba.conf to every address with trust is rejected', () => {
    const { s, l } = broken('db-hba-office');
    l.run('db01', 'root', "printf 'host all all 0.0.0.0/0 trust\\n' >> /etc/postgresql/15/main/pg_hba.conf; systemctl reload postgresql");
    const v = verifyScenario(l.world, s);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'db-hba-policy')?.ok).toBe(false);
  });

  it('making webapp a superuser is rejected', () => {
    const { s, l } = broken('db-missing-grant');
    l.run('db01', 'root', 'sudo -u postgres psql -c "ALTER ROLE webapp SUPERUSER"');
    const v = verifyScenario(l.world, s);
    expect(v.now[0].ok).toBe(true);
    expect(v.constraints.find((c) => c.id === 'db-roles-limited')?.ok).toBe(false);
  });

  it('chmod 777 on the data directory does not start the server', () => {
    const { s, l } = broken('db-datadir-owner');
    l.run('db01', 'root', 'chmod -R 777 /var/lib/postgresql/15/main; systemctl start postgresql');
    expect(verifyScenario(l.world, s).passed).toBe(false);
  });

  it('restoring orders with --clean loses the newer order', () => {
    const { s, l } = broken('db-restore-orders');
    l.run('db01', 'root', 'sudo -u postgres pg_restore -d inventory --clean -t orders /var/backups/postgresql/inventory.dump');
    const v = verifyScenario(l.world, s);
    expect(v.now.map((g) => g.ok)).toEqual([true, false]);
  });
});
