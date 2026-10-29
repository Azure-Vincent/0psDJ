// Lab 7: Database Server. A new VM, db02, was installed from the standard
// template with "apt install postgresql": the package created the cluster
// 15/main with Debian's defaults (listening on localhost, peer and
// scram-sha-256 in pg_hba.conf, only the postgres role). The learner sets it up
// for the new helpdesk application on srv01 the way a DBA does: an owner role
// and the database, the schema, a least-privilege application role, network
// access (listen_addresses, firewall, pg_hba.conf), a backup with a restore
// test, and a reboot test.

import { mkdir, readFile, writeFile } from '../fs';
import { addUser, createHost, staticInterfaces } from '../lab/builder';
import { DB01_PG_HBA, DB01_POSTGRESQL_CONF, installPostgresPackage } from '../lab/dbLab';
import { TIMESYNCD_CONF } from '../lab/krbLab';
import { installRsyslog } from '../lab/logLab';
import { trustCorpRoot } from '../lab/pkiLab';
import { buildSshLab, CORP_ZONE, DEBIAN_SSHD_CONFIG, installHostKeys, SW01_INTERFACES } from '../lab/sshLab';
import { script } from '../scenarios/engine';
import { recomputeL2 } from '../sim/l2';
import { parseCustom } from '../sim/pgsql';
import { cluster, initCluster, parseHba, PG_HBA, tablePriv } from '../sim/postgres';
import { bootHost } from '../sim/services';
import type { World } from '../types';
import { NO, OK, printfTo, probe } from './engine';
import type { GuidedLab, LabCheck } from './types';

export const DB02_IP = '10.0.20.36';
export const DB02_ALICE = 'db02-alice';
export const HELPDESK_APP_PASSWORD = 'Helpdesk-db-26';
export const HELPDESK_BACKUP_PASSWORD = 'HdBackup-db-26';

/** The package's postgresql.conf: listen_addresses left at its default (localhost), Debian's snakeoil certificate. */
const DEFAULT_CONF = DB01_POSTGRESQL_CONF
  .replace(/# The web application on srv01 connects over the network \(CHG-2501\)\nlisten_addresses = '\*'(\t+)/, "#listen_addresses = 'localhost'$1")
  .replace(/# Who connected from where, for the audit \(SEC-221\)\nlog_connections = on\n/, '#log_connections = off\n')
  .replace("ssl_cert_file = '/etc/ssl/certs/db01.corp.lab.crt'", "ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'")
  .replace("ssl_key_file = '/etc/ssl/private/db01.corp.lab.key'", "ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'");
const DEFAULT_HBA = DB01_PG_HBA.replace(/\n# Inventory web application on srv01 \(CHG-2501\)\n.*\n$/, '\n');

/** The application team's schema script (delivered with the release, CHG-2540). */
export const HELPDESK_SCHEMA = `-- helpdesk 1.0 schema (CHG-2540)
CREATE TABLE tickets (
    id serial PRIMARY KEY,
    title text NOT NULL,
    requester text NOT NULL,
    status text NOT NULL,
    opened date
);

CREATE TABLE comments (
    id serial PRIMARY KEY,
    ticket_id integer NOT NULL,
    author text,
    body text
);

INSERT INTO tickets (title, requester, status, opened) VALUES
    ('Printer on floor 2 jams', 'dana', 'open', '2026-10-15'),
    ('VPN asks for password twice', 'erin', 'open', '2026-10-16'),
    ('New laptop for Carol', 'alice', 'closed', '2026-10-12');

INSERT INTO comments (ticket_id, author, body) VALUES
    (1, 'alice', 'Ordered a new fuser unit.'),
    (3, 'alice', 'Delivered.');
`;

const DB02_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const DB02_NFT_SOLVED = DB02_NFT.replace('\t\ttcp dport 22 accept\n', '\t\ttcp dport 22 accept\n\t\t# helpdesk application server only (CHG-2540)\n\t\tip saddr 10.0.20.10 tcp dport 5432 accept\n');

const LAB7_ZONE = CORP_ZONE.replace('2026101901 ; serial', '2026101902 ; serial').replace('db01    IN A    10.0.20.35\n', `db01    IN A    10.0.20.35\ndb02    IN A    ${DB02_IP}\n`);

export function buildLab7World(): World {
  const world = buildSshLab();
  const t = world.clock;
  // The network team patched swp17 into VLAN 20; DNS has the name already.
  const sw = world.hosts.sw01;
  sw.ifaces.push({ name: 'swp17', mac: '52:54:00:5e:00:11', segment: null, address: null, prefix: null, up: false, staticSegment: null, addrs6: [] });
  writeFile(sw, '/etc/network/interfaces', SW01_INTERFACES
    .replace('auto br0\n', 'auto swp17\niface swp17\n    alias db02 (helpdesk database)\n    bridge-access 20\n\nauto br0\n')
    .replace(/(bridge-ports .*)\n/, '$1 swp17\n'), t);
  world.links = [...(world.links ?? []), { a: { host: 'db02', iface: 'eth0' }, b: { host: 'sw01', iface: 'swp17' } }];
  writeFile(world.hosts.ns1, '/etc/bind/db.corp.lab', LAB7_ZONE, t, { group: 'bind' });

  const h = createHost(world, {
    id: 'db02', hostname: 'db02', domain: 'corp.lab', role: 'Helpdesk database server (new, PostgreSQL 15 just installed)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:db:00:24', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'postgresql'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${DB02_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', DB02_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: DB02_ALICE }, t);
  if (!h.fs['/etc/ssl/private']) mkdir(h, '/etc/ssl/private', t, { mode: 0o710, group: 'ssl-cert' });
  writeFile(h, '/etc/ssl/certs/ssl-cert-snakeoil.pem', '-----BEGIN CERTIFICATE-----\n(ssl-cert package: self-signed certificate for db02)\n-----END CERTIFICATE-----\n', t);
  writeFile(h, '/etc/ssl/private/ssl-cert-snakeoil.key', '-----BEGIN PRIVATE KEY-----\n(ssl-cert package)\n-----END PRIVATE KEY-----\n', t, { mode: 0o640, group: 'ssl-cert' });
  installPostgresPackage(h, t, DEFAULT_CONF, DEFAULT_HBA);
  h.pg = initCluster();
  writeFile(h, '/tmp/helpdesk-schema.sql', HELPDESK_SCHEMA, t, { mode: 0o644, owner: 'alice', group: 'alice' });
  if (!h.fs['/var/backups/postgresql']) mkdir(h, '/var/backups/postgresql', t, { mode: 0o750, group: 'postgres' });

  recomputeL2(world);
  script(world, 'sw01', ['ifreload -a']);
  script(world, 'ns1', ['rndc reload']);
  bootHost(world, world.hosts.db02);
  world.clock += 5 * 60_000;
  return world;
}

// ---------------------------------------------------------------- checks

const db = (w: World) => cluster(w.hosts.db02);

const ownerAndDb: LabCheck = {
  id: 'db-created', description: 'The database helpdesk exists and is owned by helpdesk_owner, a role that cannot log in; PUBLIC no longer has CONNECT on it',
  check(w) {
    const c = db(w);
    const o = c.roles.helpdesk_owner;
    if (!o) return NO('There is no role helpdesk_owner (CREATE ROLE helpdesk_owner NOLOGIN;).');
    if (o.login) return NO('helpdesk_owner can log in: an owner role should be NOLOGIN, so nobody connects with all the rights of the owner.');
    if (o.superuser) return NO('helpdesk_owner is a superuser: it only needs to own the database.');
    const d = c.databases.helpdesk;
    if (!d) return NO('There is no database helpdesk (createdb -O helpdesk_owner helpdesk, or CREATE DATABASE … OWNER …).');
    if (d.owner !== 'helpdesk_owner') return NO(`helpdesk is owned by ${d.owner}, not helpdesk_owner (ALTER DATABASE helpdesk OWNER TO helpdesk_owner;).`);
    if (d.connect.includes('PUBLIC')) return NO('Every role may still connect to helpdesk: REVOKE CONNECT ON DATABASE helpdesk FROM PUBLIC;');
    return OK('helpdesk owned by helpdesk_owner (NOLOGIN); CONNECT revoked from PUBLIC.');
  },
};

const schemaLoaded: LabCheck = {
  id: 'schema', description: 'The tables tickets and comments exist in helpdesk with the application\'s data, owned by helpdesk_owner',
  check(w) {
    const d = db(w).databases.helpdesk;
    if (!d) return NO('There is no database helpdesk yet.');
    for (const n of ['tickets', 'comments']) {
      const t = d.tables[n];
      if (!t) return NO(`Table ${n} is missing: run the schema script into helpdesk (psql -d helpdesk -f /tmp/helpdesk-schema.sql).`);
      if (t.owner !== 'helpdesk_owner') return NO(`Table ${n} is owned by ${t.owner}: ALTER TABLE ${n} OWNER TO helpdesk_owner;`);
    }
    if (d.tables.tickets.rows.length < 3) return NO(`tickets has ${d.tables.tickets.rows.length} rows; the script inserts 3.`);
    return OK('tickets and comments loaded, owner helpdesk_owner.');
  },
};

const appRole: LabCheck = {
  id: 'app-role', description: 'helpdesk_app logs in with a SCRAM password, may CONNECT to helpdesk, SELECT/INSERT/UPDATE (but not DELETE) both tables, and future tables get the same grants',
  check(w) {
    const c = db(w);
    const r = c.roles.helpdesk_app;
    if (!r) return NO('There is no role helpdesk_app.');
    if (!r.login) return NO('helpdesk_app cannot log in (LOGIN).');
    if (r.superuser || r.createrole || r.createdb) return NO('helpdesk_app has administrative attributes (SUPERUSER/CREATEROLE/CREATEDB): the application needs none of them.');
    if (r.hash !== 'scram' || !r.password) return NO('helpdesk_app has no SCRAM password (ALTER ROLE helpdesk_app PASSWORD …; with password_encryption = scram-sha-256).');
    const d = c.databases.helpdesk;
    if (!d) return NO('There is no database helpdesk yet.');
    if (!d.connect.includes('helpdesk_app')) return NO('helpdesk_app has no CONNECT on helpdesk (GRANT CONNECT ON DATABASE helpdesk TO helpdesk_app;).');
    for (const n of ['tickets', 'comments']) {
      const t = d.tables[n];
      if (!t) return NO(`Table ${n} is missing.`);
      for (const [p, name] of [['r', 'SELECT'], ['a', 'INSERT'], ['w', 'UPDATE']]) if (!tablePriv(c, t, 'helpdesk_app', p)) return NO(`helpdesk_app lacks ${name} on ${n}.`);
      if (tablePriv(c, t, 'helpdesk_app', 'd') || tablePriv(c, t, 'helpdesk_app', 'D')) return NO(`helpdesk_app may DELETE or TRUNCATE ${n}: the application never deletes tickets, so it should not be able to.`);
    }
    const def = d.defaultAcl.find((x) => x.owner === 'helpdesk_owner' && x.grantee === 'helpdesk_app');
    if (!def || !/r/.test(def.privs) || !/a/.test(def.privs)) return NO('No default privileges: the next table helpdesk_owner creates will not be readable by the application (ALTER DEFAULT PRIVILEGES FOR ROLE helpdesk_owner GRANT SELECT, INSERT, UPDATE ON TABLES TO helpdesk_app;).');
    return OK('LOGIN with SCRAM; CONNECT; SELECT/INSERT/UPDATE on both tables, no DELETE; default privileges for future tables.');
  },
};

const listening: LabCheck = {
  id: 'network', description: 'PostgreSQL on db02 accepts connections on the network from srv01 (port 5432), but not from the office (ws01)',
  check(w) {
    const ss = probe(w, 'db02', 'root', 'ss -tlnp').output;
    if (!/(0\.0\.0\.0|10\.0\.20\.36):5432 /.test(ss)) return NO('PostgreSQL only listens on localhost: set listen_addresses (e.g. in conf.d) and restart.');
    const fromSrv = probe(w, 'srv01', 'root', 'pg_isready -h db02.corp.lab');
    if (fromSrv.code !== 0) return NO(`From srv01: ${fromSrv.output.trim()} (is TCP 5432 allowed from 10.0.20.10 in db02's firewall?).`);
    const fromWs = probe(w, 'ws01', 'alice', 'pg_isready -h db02.corp.lab');
    if (fromWs.code === 0) return NO('ws01 (office) reaches PostgreSQL on db02: allow 5432 only from srv01.');
    if (!w.hosts.db02.services.nftables?.enabled || !/dport 5432/.test(readFile(w.hosts.db02, '/etc/nftables.conf') ?? '')) return NO('The firewall rule is not in /etc/nftables.conf (or nftables is not enabled): it would be gone after a reboot.');
    return OK('Listening on the network; srv01 reaches 5432, ws01 does not; the rule is in /etc/nftables.conf.');
  },
};

const appLogin: LabCheck = {
  id: 'app-login', description: 'From srv01, helpdesk_app logs in to helpdesk (password from /root/.pgpass) and reads and adds tickets; pg_hba.conf allows only that, with scram-sha-256',
  check(w) {
    const p = parseHba(readFile(w.hosts.db02, PG_HBA) ?? '');
    const weak = p.rules.find((r) => ['trust', 'md5', 'password'].includes(r.method));
    if (weak) return NO(`pg_hba.conf line ${weak.line} uses ${weak.method}: use scram-sha-256.`);
    const wide = p.rules.find((r) => r.type !== 'local' && (['0.0.0.0/0', '::/0', 'all'].includes(r.address ?? '') || (r.databases.includes('all') && r.users.includes('all') && !/^(127\.|::1)/.test(r.address ?? ''))));
    if (wide) return NO(`pg_hba.conf line ${wide.line} ("${wide.raw}") is too wide: name the database (helpdesk), the user (helpdesk_app) and the client (10.0.20.10/32).`);
    const pass = probe(w, 'srv01', 'root', 'ls -l /root/.pgpass');
    if (!/^-rw-------/.test(pass.output)) return NO('/root/.pgpass on srv01 is missing or not mode 0600 (libpq ignores it otherwise).');
    const read = probe(w, 'srv01', 'root', 'psql -h db02.corp.lab -U helpdesk_app -d helpdesk -w -A -t -c "SELECT count(*) FROM tickets"');
    if (read.code !== 0 || !/^\d+$/.test(read.output.trim())) return NO(`psql from srv01: ${read.output.trim().split('\n').slice(-2).join(' ')}`);
    const write = probe(w, 'srv01', 'root', "psql -h db02.corp.lab -U helpdesk_app -d helpdesk -w -c \"INSERT INTO tickets (title, requester, status) VALUES ('lab check', 'srv01', 'open')\"");
    if (!/INSERT 0 1/.test(write.output)) return NO(`INSERT as helpdesk_app: ${write.output.trim()}`);
    return OK(`helpdesk_app@helpdesk from srv01: ${read.output.trim()} tickets; INSERT works.`);
  },
};

const backupDone: LabCheck = {
  id: 'backup', description: '/var/backups/postgresql/helpdesk.dump is a custom-format dump of helpdesk with the data of both tables, made by helpdesk_backup (a read-only role, not a superuser)',
  check(w) {
    const c = db(w);
    const b = c.roles.helpdesk_backup;
    if (!b) return NO('There is no role helpdesk_backup.');
    if (b.superuser) return NO('helpdesk_backup is a superuser: a backup only needs to read (pg_read_all_data).');
    if (b.memberOf.includes('pg_write_all_data')) return NO('helpdesk_backup can write data: it only needs pg_read_all_data.');
    const text = readFile(w.hosts.db02, '/var/backups/postgresql/helpdesk.dump');
    if (text === undefined) return NO('/var/backups/postgresql/helpdesk.dump does not exist.');
    const a = parseCustom(text);
    if (!a) return NO('helpdesk.dump is not a custom-format archive (pg_dump -Fc).');
    if (a.db !== 'helpdesk') return NO(`The dump is of ${a.db}, not helpdesk.`);
    for (const n of ['tickets', 'comments']) if (!a.entries.some((e) => e.kind === 'TABLE DATA' && e.table === n)) return NO(`The dump has no data for ${n}.`);
    return OK('Custom-format dump of helpdesk with tickets and comments (pg_restore -l lists them).');
  },
};

// ---------------------------------------------------------------- the lab

const PSQL = (sql: string, dbname = 'postgres') => `sudo -u postgres psql -d ${dbname} -c "${sql}"`;

export const LAB7: GuidedLab = {
  id: 'lab7',
  title: 'Lab 7: Database Server',
  level: 'intermediate',
  duration: '60–90 min',
  summary: 'Set up PostgreSQL for a new application the way a DBA does: an owner role and the database, the schema, a least-privilege application role with default privileges, network access (listen_addresses, firewall, pg_hba.conf), a backup with a restore test, and a reboot test.',
  brief: `The new **helpdesk** application goes live on srv01 next week (change CHG-2540). Its database server **db02** (${DB02_IP}, Debian 12) was installed from the standard template, and \`apt install postgresql\` has been run: the package created the cluster **15/main** with Debian's defaults. Nothing else has been done.

The application team's requirements:

- **A database** called **helpdesk**, owned by a role **helpdesk_owner** that cannot log in. Other roles must not be able to connect to it unless allowed.
- **The schema** from their script **/tmp/helpdesk-schema.sql**, loaded into helpdesk and owned by helpdesk_owner.
- **An application account** **helpdesk_app** (password **${HELPDESK_APP_PASSWORD}**) that can read, add and update tickets and comments, but never delete them, including in tables added by future releases.
- **Network access** from the application server **srv01** (10.0.20.10) only, with a password check (scram-sha-256). The application reads its password from **/root/.pgpass** on srv01.
- **A backup**: a nightly-style logical dump to **/var/backups/postgresql/helpdesk.dump** made by a read-only role **helpdesk_backup** (password **${HELPDESK_BACKUP_PASSWORD}**), and a restore test that proves it can be restored.

Everything must work again after every machine restarts. Each step explains what you are building and why; hints and a reference solution are there if you get stuck.`,
  objectives: [
    'Find your way around a Debian PostgreSQL installation: clusters, configuration files, data directory, log, and the postgres account.',
    'Create a database with a dedicated owner role and close it to other roles.',
    'Load a schema and set object ownership.',
    'Create a least-privilege application role: LOGIN, CONNECT, table privileges, default privileges for future tables.',
    'Open a server to one client: listen_addresses (restart), firewall, and a narrow pg_hba.conf line (reload).',
    'Store a client password safely in ~/.pgpass.',
    'Make a logical backup with a read-only role and prove it restores.',
  ],
  prerequisites: [
    { label: 'TCP, UDP and DNS', link: 'lesson/transport/what' },
    { label: 'Linux service administration', link: 'lesson/systemd/what' },
    { label: 'Firewalls (nftables)', link: 'lesson/nftables/what' },
    { label: 'Databases (PostgreSQL)', link: 'lesson/database/what' },
  ],
  setupNote: `This lab adds **db02** (${DB02_IP}) on sw01 port swp17 (VLAN 20, configured; db02.corp.lab is in DNS). PostgreSQL 15 runs with the package defaults. The application side is **srv01**; **ws01** stands for the office network, which must not reach the database.`,
  terminals: [
    { hostId: 'db02', user: 'root', label: 'db02 console (root)', banner: 'db02 console (hypervisor), logged in as root. PostgreSQL 15 was just installed. Try: pg_lsclusters, ls /etc/postgresql/15/main, sudo -u postgres psql, ss -tlnp.' },
    { hostId: 'srv01', user: 'root', label: 'srv01 (application server)', banner: 'srv01: the helpdesk application will run here. Test with psql -h db02.corp.lab -U helpdesk_app -d helpdesk.' },
    { hostId: 'ws01', user: 'alice', label: 'ws01 (office)', banner: 'ws01: the office network. The database must NOT be reachable from here: pg_isready -h db02.corp.lab.' },
  ],
  build: buildLab7World,
  steps: [
    {
      id: 'database', title: 'Create the owner role and the database',
      objective: 'Create the role **helpdesk_owner** (cannot log in) and the database **helpdesk** owned by it, and take CONNECT away from PUBLIC.',
      background: 'On Debian the database superuser **postgres** is reached through the operating-system account of the same name: `sudo -u postgres psql` connects over the Unix socket, and pg_hba.conf\'s first line (`local all postgres peer`) lets it in because the OS user and the database user match. That is how all administration starts.\n\nEvery database object has an **owner**, who holds every privilege on it and is the only one (with superusers) who may change or drop it or grant access. Good practice is a dedicated owner role that **cannot log in** (NOLOGIN): nobody works with the owner\'s full rights day to day, and applications use separate, smaller roles.\n\nA new database lets every role (PUBLIC) **CONNECT** by default; pg_hba.conf limits who reaches the server, but revoking CONNECT from PUBLIC also limits which database each role can open.',
      tasks: [
        'Look around: `pg_lsclusters`, `ls /etc/postgresql/15/main`, `sudo -u postgres psql -c "\\l"` and `-c "\\du"`.',
        'Create the owner: `sudo -u postgres psql -c "CREATE ROLE helpdesk_owner NOLOGIN"`.',
        'Create the database: `sudo -u postgres createdb -O helpdesk_owner helpdesk` (or `CREATE DATABASE helpdesk OWNER helpdesk_owner;`).',
        'Close it: `REVOKE CONNECT ON DATABASE helpdesk FROM PUBLIC;` and check `\\l`: the access privileges now list only the owner.',
      ],
      hints: ['createdb and createuser are small wrappers that connect to the database postgres and run CREATE DATABASE / CREATE ROLE; run them as postgres too.', 'In \\l, "=Tc/owner" is PUBLIC\'s entry (temp + connect); after REVOKE it disappears.'],
      checks: [ownerAndDb],
      solution: [{ host: 'db02', user: 'root', commands: [PSQL('CREATE ROLE helpdesk_owner NOLOGIN'), 'sudo -u postgres createdb -O helpdesk_owner helpdesk', PSQL('REVOKE CONNECT ON DATABASE helpdesk FROM PUBLIC')] }],
      learn: [{ label: 'Roles and ownership', link: 'lesson/database/internals' }, { label: 'psql', link: 'reference?id=psql' }],
      concepts: ['db.admin'],
    },
    {
      id: 'schema', title: 'Load the application schema',
      objective: 'Run **/tmp/helpdesk-schema.sql** into helpdesk and make **helpdesk_owner** the owner of its tables.',
      background: 'Tables belong to the role that created them. Running a script as postgres makes postgres the owner, which is not what you want: the owner should be the application\'s owner role, so that later grants and migrations work without superuser rights. `ALTER TABLE … OWNER TO` hands a table over.\n\n`psql -f FILE` runs a script statement by statement and prints each result (CREATE TABLE, INSERT 0 3 …); errors are printed with the file name and line and the script continues, unless you add `-v ON_ERROR_STOP=1`.',
      tasks: [
        'Read the script first: `cat /tmp/helpdesk-schema.sql`.',
        'Run it into the right database: `sudo -u postgres psql -d helpdesk -v ON_ERROR_STOP=1 -f /tmp/helpdesk-schema.sql`.',
        'Hand the tables over: `ALTER TABLE tickets OWNER TO helpdesk_owner;` and the same for comments (in helpdesk).',
        'Check: `\\dt` in helpdesk lists both tables with owner helpdesk_owner.',
      ],
      hints: ['Forgot -d helpdesk? Then the tables were created in the database postgres: drop them there and run the script again in the right database.', '\\c helpdesk inside psql switches database.'],
      checks: [schemaLoaded],
      solution: [{ host: 'db02', user: 'root', commands: ['sudo -u postgres psql -d helpdesk -v ON_ERROR_STOP=1 -f /tmp/helpdesk-schema.sql', PSQL('ALTER TABLE tickets OWNER TO helpdesk_owner', 'helpdesk'), PSQL('ALTER TABLE comments OWNER TO helpdesk_owner', 'helpdesk')] }],
      learn: [{ label: 'Running SQL scripts', link: 'lesson/database/deploy' }],
      concepts: ['db.admin'],
    },
    {
      id: 'app-role', title: 'A least-privilege account for the application',
      objective: `Create **helpdesk_app** (LOGIN, password ${HELPDESK_APP_PASSWORD}) with CONNECT on helpdesk and SELECT, INSERT, UPDATE (no DELETE) on both tables, also for future tables.`,
      background: 'Privileges in PostgreSQL are granted **per object**: CONNECT on the database, then SELECT/INSERT/UPDATE/DELETE on each table. A role gets nothing it was not granted (except through PUBLIC). The application should get exactly what it uses, so a bug or an attacker using its account cannot do more.\n\nGrants on existing tables do not cover tables created later. **ALTER DEFAULT PRIVILEGES FOR ROLE helpdesk_owner** records grants that PostgreSQL adds automatically to every table helpdesk_owner creates from now on, so the next release does not end with "permission denied".\n\nPasswords are stored as a SCRAM-SHA-256 verifier (password_encryption = scram-sha-256 on PostgreSQL 14+), never in clear text.',
      tasks: [
        `\`CREATE ROLE helpdesk_app LOGIN PASSWORD '${HELPDESK_APP_PASSWORD}';\` (as postgres).`,
        '`GRANT CONNECT ON DATABASE helpdesk TO helpdesk_app;`',
        'In helpdesk: `GRANT SELECT, INSERT, UPDATE ON tickets, comments TO helpdesk_app;`',
        'In helpdesk: `ALTER DEFAULT PRIVILEGES FOR ROLE helpdesk_owner GRANT SELECT, INSERT, UPDATE ON TABLES TO helpdesk_app;`',
        'Check with `\\dp` (helpdesk_app=arw/helpdesk_owner) and `\\ddp`… or the lab check.',
      ],
      hints: ['GRANT … ON tickets runs in the database where the table is: connect with -d helpdesk.', 'Privilege letters in \\dp: r SELECT, a INSERT, w UPDATE, d DELETE, D TRUNCATE.'],
      checks: [appRole],
      solution: [{ host: 'db02', user: 'root', commands: [PSQL(`CREATE ROLE helpdesk_app LOGIN PASSWORD '${HELPDESK_APP_PASSWORD}'`), PSQL('GRANT CONNECT ON DATABASE helpdesk TO helpdesk_app'), PSQL('GRANT SELECT, INSERT, UPDATE ON tickets, comments TO helpdesk_app', 'helpdesk'), PSQL('ALTER DEFAULT PRIVILEGES FOR ROLE helpdesk_owner GRANT SELECT, INSERT, UPDATE ON TABLES TO helpdesk_app', 'helpdesk')] }],
      learn: [{ label: 'Privileges', link: 'lesson/database/internals' }],
      concepts: ['db.admin'],
    },
    {
      id: 'network', title: 'Listen on the network, for srv01 only',
      objective: 'Make PostgreSQL listen on db02\'s network address and allow TCP 5432 in db02\'s firewall from srv01 (10.0.20.10) only, persistently.',
      background: 'Debian\'s PostgreSQL listens on **localhost only** (listen_addresses defaults to localhost): a fresh server is not reachable from the network at all. listen_addresses is read when the server **starts**: after changing it you must restart; a reload only logs that the change needs a restart.\n\nPut local settings in **/etc/postgresql/15/main/conf.d/** (postgresql.conf includes that directory): a later package update can replace postgresql.conf, not your files there.\n\nThe host firewall is the first filter: only the application server needs the database port. pg_hba.conf (next step) is the second.',
      tasks: [
        "`printf \"listen_addresses = '*'\\n\" > /etc/postgresql/15/main/conf.d/listen.conf` (or 'localhost,10.0.20.36'), then `systemctl restart postgresql` and `ss -tlnp | grep 5432`.",
        'Add `ip saddr 10.0.20.10 tcp dport 5432 accept` to the input chain in /etc/nftables.conf, check with `nft -c -f /etc/nftables.conf`, apply with `systemctl restart nftables`.',
        'From srv01: `pg_isready -h db02.corp.lab` → accepting connections; from ws01 → no response.',
      ],
      hints: ['After `systemctl reload postgresql` the log says: parameter "listen_addresses" cannot be changed without restarting the server.', 'SHOW listen_addresses; in psql shows the value in effect; pg_settings.pending_restart shows changes still waiting for a restart.'],
      checks: [listening],
      solution: [{ host: 'db02', user: 'root', commands: ["printf \"listen_addresses = '*'\\n\" > /etc/postgresql/15/main/conf.d/listen.conf", 'systemctl restart postgresql', printfTo(DB02_NFT_SOLVED, '/etc/nftables.conf'), 'systemctl restart nftables'] }],
      learn: [{ label: 'Reload or restart', link: 'lesson/database/config' }, { label: 'nftables', link: 'lesson/nftables/what' }],
      concepts: ['db.access', 'svc.listening'],
    },
    {
      id: 'hba', title: 'Let the application in',
      objective: 'Add a pg_hba.conf line for **helpdesk_app** from **10.0.20.10** to **helpdesk** with scram-sha-256, reload, and store the password in **/root/.pgpass** on srv01 (mode 0600).',
      background: 'Every connection is matched against **pg_hba.conf from top to bottom**; the **first** line whose type (local/host/hostssl), database, user and client address match decides the method, and if no line matches the connection is refused ("no pg_hba.conf entry"). A narrow line names the database, the role and the client address (/32).\n\npg_hba.conf only needs a **reload** (`systemctl reload postgresql` or `SELECT pg_reload_conf();`). If the new file has an error, PostgreSQL logs it and keeps the old rules.\n\nClients read passwords from **~/.pgpass** (host:port:database:user:password), which libpq ignores unless its mode is 0600.',
      tasks: [
        'On db02, append to /etc/postgresql/15/main/pg_hba.conf: `host    helpdesk    helpdesk_app    10.0.20.10/32    scram-sha-256`, then `systemctl reload postgresql`.',
        `On srv01: \`printf 'db02.corp.lab:5432:helpdesk:helpdesk_app:${HELPDESK_APP_PASSWORD}\\n' > /root/.pgpass\` and \`chmod 600 /root/.pgpass\`.`,
        'From srv01: `psql -h db02.corp.lab -U helpdesk_app -d helpdesk -c "SELECT * FROM tickets"`.',
      ],
      hints: ['Still "no pg_hba.conf entry"? Did you reload? Check SELECT * FROM pg_hba_file_rules; as postgres, and the server log.', 'Never use trust, and do not open all databases to all users from 0.0.0.0/0.'],
      checks: [appLogin],
      solution: [
        { host: 'db02', user: 'root', commands: ["printf '# helpdesk application on srv01 (CHG-2540)\\nhost    helpdesk        helpdesk_app    10.0.20.10/32           scram-sha-256\\n' >> /etc/postgresql/15/main/pg_hba.conf", 'systemctl reload postgresql'] },
        { host: 'srv01', user: 'root', commands: [`printf 'db02.corp.lab:5432:helpdesk:helpdesk_app:${HELPDESK_APP_PASSWORD}\\n' > /root/.pgpass`, 'chmod 600 /root/.pgpass'] },
      ],
      learn: [{ label: 'pg_hba.conf', link: 'lesson/database/internals' }, { label: 'pg_hba.conf reference', link: 'reference?id=file:pg-hba-conf' }],
      concepts: ['db.access'],
    },
    {
      id: 'backup', title: 'Back it up, and prove the restore',
      objective: `Create **helpdesk_backup** (LOGIN, password ${HELPDESK_BACKUP_PASSWORD}, member of pg_read_all_data), dump helpdesk with it to **/var/backups/postgresql/helpdesk.dump** (custom format), and restore the dump into a scratch database to prove it works.`,
      background: '**pg_dump** makes a consistent logical backup of one database while it is in use; it needs to read every table, so the backup role gets **pg_read_all_data** (PostgreSQL 14+): read access to every table, also future ones, and nothing else. The custom format (-Fc) is compressed and lets **pg_restore** list the contents (-l) and restore selectively (-t TABLE, --data-only).\n\nA backup that has never been restored is a hope, not a backup: restore it into a scratch database, look at it, drop it. Roles are cluster-wide and not in pg_dump\'s output: save them with `pg_dumpall --globals-only`.',
      tasks: [
        `As postgres: \`CREATE ROLE helpdesk_backup LOGIN PASSWORD '${HELPDESK_BACKUP_PASSWORD}';\` and \`GRANT pg_read_all_data TO helpdesk_backup;\` and \`GRANT CONNECT ON DATABASE helpdesk TO helpdesk_backup;\`.`,
        `As root on db02: \`printf 'localhost:5432:helpdesk:helpdesk_backup:${HELPDESK_BACKUP_PASSWORD}\\n' > /root/.pgpass\`, \`chmod 600 /root/.pgpass\`.`,
        '`pg_dump -h localhost -U helpdesk_backup -Fc -f /var/backups/postgresql/helpdesk.dump helpdesk`, then `pg_restore -l /var/backups/postgresql/helpdesk.dump`.',
        'Restore test: `sudo -u postgres createdb restoretest`, `sudo -u postgres pg_restore -d restoretest /var/backups/postgresql/helpdesk.dump`, check the rows, `sudo -u postgres dropdb restoretest`.',
      ],
      hints: ['pg_dump: error: … permission denied for table …: the backup role needs read access to every table (pg_read_all_data).', 'The localhost line host all all 127.0.0.1/32 scram-sha-256 in the default pg_hba.conf already lets the backup role in over TCP from db02 itself.'],
      checks: [backupDone],
      solution: [{ host: 'db02', user: 'root', commands: [
        PSQL(`CREATE ROLE helpdesk_backup LOGIN PASSWORD '${HELPDESK_BACKUP_PASSWORD}'`), PSQL('GRANT pg_read_all_data TO helpdesk_backup'), PSQL('GRANT CONNECT ON DATABASE helpdesk TO helpdesk_backup'),
        `printf 'localhost:5432:helpdesk:helpdesk_backup:${HELPDESK_BACKUP_PASSWORD}\\n' > /root/.pgpass`, 'chmod 600 /root/.pgpass',
        'pg_dump -h localhost -U helpdesk_backup -w -Fc -f /var/backups/postgresql/helpdesk.dump helpdesk',
        'sudo -u postgres createdb restoretest', 'sudo -u postgres pg_restore -d restoretest /var/backups/postgresql/helpdesk.dump', 'sudo -u postgres dropdb restoretest',
      ] }],
      learn: [{ label: 'Backups and restores', link: 'lesson/database/operate' }, { label: 'pg_dump', link: 'reference?id=pg_dump' }],
      concepts: ['db.admin'],
    },
    {
      id: 'reboot', title: 'Reboot test',
      objective: 'Every check of the earlier steps still passes after all machines restart.',
      background: 'Runtime-only fixes disappear at the next boot: a firewall rule added with `nft add rule` but not saved, a setting changed with `SET` instead of in a file. The cluster\'s contents (roles, databases, grants) are on disk and survive; the configuration files must say what you want too.',
      tasks: ['Run the check: it reboots every host on a copy of the lab and runs all checks again.'],
      hints: ['A failing network check after the reboot usually means the nftables rule was added with nft add rule but not written to /etc/nftables.conf. Read the detail under the check.'],
      checks: [],
      solution: [],
      learn: [{ label: 'Reload or restart', link: 'lesson/database/config' }],
      concepts: ['db.admin', 'db.access'],
      afterReboot: true,
    },
  ],
};
