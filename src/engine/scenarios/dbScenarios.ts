// Database tickets on db01 (PostgreSQL 15). Each one breaks a step a DBA sets
// up or maintains: the listening address, pg_hba.conf, table privileges after
// a release, a password hash migrated from an old server, the backup role's
// privileges, the data directory's ownership, and a restore after a DELETE
// without WHERE.

import { readFile } from '../fs';
import { cluster, DATA_DIR, matchHba, parseHba, PG_HBA } from '../sim/postgres';
import type { World } from '../types';
import { script } from './engine';
import type { Constraint, Goal, Scenario } from './types';

const PSQL = (sql: string, db = 'inventory') => `sudo -u postgres psql -d ${db} -c "${sql}"`;

const BRIEFING = [
  'db01 (10.0.20.35) runs PostgreSQL 15 (Debian cluster 15/main, unit postgresql@15-main). The inventory database is owned by the role invowner (no login); the web application on srv01 logs in as webapp over TCP 5432 with scram-sha-256, and the nightly backup (/usr/local/sbin/pg-backup, as root with /root/.pgpass) logs in as backup.',
  'Administer the server on db01 as the postgres operating-system user: sudo -u postgres psql (peer authentication), then \\l, \\du, \\dp, SELECT … Configuration: /etc/postgresql/15/main/postgresql.conf and pg_hba.conf; log: /var/log/postgresql/postgresql-15-main.log. Some settings need a restart (systemctl restart postgresql), pg_hba.conf only a reload (systemctl reload postgresql).',
  'On srv01, inventory-check runs the application\'s health query (its password is in /root/.pgpass).',
  'Policy: passwords only with scram-sha-256 (no trust, md5 or password methods), no pg_hba.conf line open to every address, and application roles are never superusers. Fixes must survive a reboot.',
];

const TERMINALS = [
  { hostId: 'db01', user: 'root', label: 'db01 console (root)', banner: 'db01: PostgreSQL 15. Try: pg_lsclusters, systemctl status postgresql, sudo -u postgres psql, tail /var/log/postgresql/postgresql-15-main.log, ss -tlnp.' },
  { hostId: 'srv01', user: 'root', label: 'srv01 (application server)', banner: 'srv01: the inventory application. Try: inventory-check, psql -h db01.corp.lab -U webapp -d inventory (password in /root/.pgpass).' },
];

const CANDIDATES = [
  'db-listen-localhost', 'db-hba-no-entry', 'db-missing-grant', 'db-md5-secret', 'db-wrong-password', 'db-connect-privilege',
  'db-service-down', 'db-datadir-perms', 'db-data-deleted', 'firewall-drop', 'dns-wrong-record',
];

const appCheck: Goal = {
  kind: 'command',
  description: 'On srv01, inventory-check gets an answer from the inventory database (as webapp).',
  steps: [{ host: 'srv01', user: 'root', command: 'inventory-check' }],
  expect: '^\\d+$',
};

/** pg_hba.conf: scram-sha-256 only (peer for local logins is fine), and no line open to every address. */
function hbaPolicy(): Constraint {
  return {
    id: 'db-hba-policy', required: true,
    description: 'pg_hba.conf uses no trust, md5 or password method and has no line for every address (0.0.0.0/0, ::/0, all).',
    check(world) {
      const p = parseHba(readFile(world.hosts.db01, PG_HBA) ?? '');
      const weak = p.rules.find((r) => ['trust', 'md5', 'password'].includes(r.method));
      const wide = p.rules.find((r) => r.type !== 'local' && ['0.0.0.0/0', '::/0', '::0/0', 'all'].includes(r.address ?? ''));
      const bad = weak ?? wide;
      return { id: this.id, ok: !bad, required: true, message: bad ? `pg_hba.conf line ${bad.line} ("${bad.raw}") breaks the policy: ${weak ? `method ${bad.method} is not allowed (scram-sha-256 only)` : 'it accepts every address'}.` : 'pg_hba.conf follows the policy (scram-sha-256, limited networks).' };
    },
  };
}

/** Application and service roles stay ordinary roles. */
function rolesLimited(...names: string[]): Constraint {
  return {
    id: 'db-roles-limited', required: true,
    description: `${names.join(', ')} ${names.length > 1 ? 'are' : 'is'} not superuser, cannot create roles and ${names.length > 1 ? 'do' : 'does'} not own the application's tables.`,
    check(world) {
      const c = cluster(world.hosts.db01);
      const bad = names.find((n) => c.roles[n]?.superuser || c.roles[n]?.createrole || Object.values(c.databases.inventory?.tables ?? {}).some((t) => t.owner === n) || c.roles[n]?.memberOf.includes('invowner'));
      return { id: this.id, ok: !bad, required: true, message: bad ? `${bad} has more power than it needs (superuser, CREATEROLE, table ownership or membership in invowner): grant exactly the privileges required instead.` : 'Application roles have only the privileges they need.' };
    },
  };
}

/** No privileges for every role (PUBLIC) on the inventory tables. */
function noPublicGrants(): Constraint {
  return {
    id: 'db-no-public-grants', required: true,
    description: 'No inventory table grants privileges to PUBLIC.',
    check(world) {
      const t = Object.values(cluster(world.hosts.db01).databases.inventory?.tables ?? {}).find((x) => x.acl.PUBLIC);
      return { id: this.id, ok: !t, required: true, message: t ? `Table ${t.name} grants ${t.acl.PUBLIC} to PUBLIC: every role (and every future role) would get it.` : 'No table privileges for PUBLIC.' };
    },
  };
}

/** A morning of normal use: the health check runs from cron. */
function activity(world: World, minutes = 20): void {
  world.clock += minutes * 60_000;
  script(world, 'srv01', ['inventory-check']);
}

export const DB_SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------------
  {
    id: 'db-listen-default',
    title: 'After the minor upgrade',
    difficulty: 'intermediate',
    ticket: 'Application team: "Since last night\'s patch window the inventory site shows \'database unavailable\'. The database server is up, and the DBA can use psql on db01 without problems." Patch notes (CHG-2520): postgresql 15.8 installed; at the dpkg prompt about /etc/postgresql/15/main/postgresql.conf the operator chose "install the package maintainer\'s version".',
    briefing: BRIEFING,
    goals: [appCheck],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'db01', [`sed -i "/CHG-2501/d; s/^listen_addresses = .*/#listen_addresses = 'localhost'		# what IP address(es) to listen on;/" /etc/postgresql/15/main/postgresql.conf`, 'systemctl restart postgresql']);
      activity(world);
    },
    rootCauses: ['db-listen-localhost'],
    candidates: CANDIDATES,
    feedback: {
      'db-service-down': 'The server runs: pg_lsclusters says online, and psql on db01 works.',
      'firewall-drop': 'The connection is refused at once (RST), not timed out: db01 answers, but nothing listens on that address. The firewall still allows 5432.',
      'db-hba-no-entry': 'The connection never reaches pg_hba.conf: a missing entry would give "FATAL: no pg_hba.conf entry", not "Connection refused".',
      'db-wrong-password': 'Authentication is never reached: TCP itself is refused.',
    },
    hints: [
      '"Connection refused" from srv01 but psql works on db01: compare where PostgreSQL listens. On db01: ss -tlnp | grep 5432.',
      'It listens on 127.0.0.1 and ::1 only. Which setting decides that? SHOW listen_addresses; in psql, and grep listen_addresses /etc/postgresql/15/main/postgresql.conf (the package default is commented out: localhost).',
      'Set listen_addresses = \'*\' (or \'localhost,10.0.20.35\') again, then restart: a reload only logs "parameter "listen_addresses" cannot be changed without restarting the server". Check with ss -tlnp and inventory-check.',
    ],
    explanation: {
      rootCause: 'Accepting the package maintainer\'s postgresql.conf removed the local change listen_addresses = \'*\'. The default (commented out) is localhost, so after the restart PostgreSQL only listens on 127.0.0.1 and ::1.',
      manifestation: 'Local connections (Unix socket, localhost) keep working, so the DBA sees nothing wrong; every client on the network gets "Connection refused".',
      evidence: 'ss -tlnp on db01: 127.0.0.1:5432 and [::1]:5432 only; SHOW listen_addresses → localhost; the server log lists "listening on IPv4 address "127.0.0.1"" at the last start; psql on srv01: "connection to server at "db01.corp.lab" (10.0.20.35), port 5432 failed: Connection refused".',
      prevention: 'Keep local settings in /etc/postgresql/15/main/conf.d/*.conf (or ALTER SYSTEM), not in the packaged file, so a package update cannot overwrite them; review dpkg conffile prompts (show the differences before choosing); test from a client after every patch window.',
    },
    solution: [{ host: 'db01', commands: ["sed -i \"s/^#listen_addresses = 'localhost'.*/listen_addresses = '*'/\" /etc/postgresql/15/main/postgresql.conf", 'systemctl restart postgresql'] }],
    constraints: [hbaPolicy()],
    concepts: ['db.access', 'svc.listening'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'db-hba-office',
    title: 'Reporting from the office',
    difficulty: 'beginner',
    ticket: 'Finance: "IT created a read-only database account for our reports yesterday (CHG-2523: role report, password Report-db-26, CONNECT on inventory, SELECT on items and orders). From my PC (ws01) psql says: no pg_hba.conf entry for host "10.0.10.25"." The password is saved in her ~/.pgpass.',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'From ws01, alice runs a report query as report on the inventory database.',
      steps: [{ host: 'ws01', user: 'alice', command: 'psql -h db01.corp.lab -U report -d inventory -w -c "SELECT customer, count(*) FROM orders GROUP BY customer"' }],
      expect: '\\(\\d+ rows?\\)',
    }],
    terminals: [...TERMINALS, { hostId: 'ws01', user: 'alice', label: 'ws01 (alice, finance PC)', banner: 'ws01: Try psql -h db01.corp.lab -U report -d inventory (the password is in ~/.pgpass).' }],
    setup(world) {
      script(world, 'db01', [
        PSQL("CREATE ROLE report LOGIN PASSWORD 'Report-db-26'", 'postgres'),
        PSQL('GRANT CONNECT ON DATABASE inventory TO report', 'postgres'),
        PSQL('GRANT SELECT ON items, orders TO report'),
      ]);
      script(world, 'ws01', [`printf 'db01.corp.lab:5432:inventory:report:Report-db-26\\n' > /home/alice/.pgpass`, 'chown alice:alice /home/alice/.pgpass', 'chmod 600 /home/alice/.pgpass']);
      activity(world);
      world.clock += 60_000;
      script(world, 'ws01', ['psql -h db01.corp.lab -U report -d inventory -w -c "SELECT count(*) FROM orders"']);
    },
    rootCauses: ['db-hba-no-entry'],
    candidates: CANDIDATES,
    feedback: {
      'db-listen-localhost': 'The connection reaches the server: the error comes from PostgreSQL itself (FATAL), so it listens on the network.',
      'db-wrong-password': 'No password was checked: the server refused the connection before authentication, because no pg_hba.conf line matches.',
      'db-connect-privilege': 'CONNECT is checked after pg_hba.conf and authentication; the message would be "permission denied for database".',
      'firewall-drop': 'A firewall drop would time out; here the server answers with a FATAL message.',
    },
    hints: [
      'The message names host, user and database: PostgreSQL looked through pg_hba.conf from top to bottom and found no line for that combination.',
      'On db01: grep -v "^#" /etc/postgresql/15/main/pg_hba.conf | grep -v "^$". The only network line for inventory is for webapp from 10.0.20.10. (Superuser view: SELECT * FROM pg_hba_file_rules;)',
      'Add a line for exactly this access, e.g. host inventory report 10.0.10.0/24 scram-sha-256, then reload: systemctl reload postgresql (or SELECT pg_reload_conf();). No restart is needed.',
    ],
    explanation: {
      rootCause: 'The role and its privileges were created, but pg_hba.conf has no line that lets report connect to inventory from the office network (10.0.10.0/24). Without a matching line PostgreSQL refuses the connection before checking the password.',
      manifestation: 'psql shows the FATAL twice (once with SSL, once without, because sslmode=prefer retries) for host 10.0.10.25, user report, database inventory.',
      evidence: 'Server log: "FATAL:  no pg_hba.conf entry for host "10.0.10.25", user "report", database "inventory", SSL encryption"; pg_hba_file_rules lists no line matching it.',
      prevention: 'Make "add the pg_hba.conf line and reload" part of the account request procedure, scoped to the database, the role and the client network; test from the user\'s machine before closing the change.',
    },
    solution: [{ host: 'db01', commands: ["printf '# Finance reports from the office (CHG-2523)\\nhost    inventory       report          10.0.10.0/24            scram-sha-256\\n' >> /etc/postgresql/15/main/pg_hba.conf", 'systemctl reload postgresql'] }],
    constraints: [hbaPolicy(), rolesLimited('report', 'webapp'), {
      id: 'db-office-scope', required: true,
      description: 'From the office network, only report may connect, and only to inventory.',
      check(world) {
        const h = world.hosts.db01;
        const c = cluster(h);
        const rules = parseHba(readFile(h, PG_HBA) ?? '').rules;
        const opens = (user: string, db: string) => { const r = matchHba(c, rules, { local: false, ssl: true, ip: '10.0.10.40', user, db, serverHost: h }); return !!r && r.method !== 'reject'; };
        const bad = opens('webapp', 'inventory') ? 'webapp may now log in from the office' : opens('report', 'postgres') ? 'report may now connect to other databases' : opens('postgres', 'inventory') ? 'postgres may now log in from the office' : null;
        return { id: this.id, ok: !bad, required: true, message: bad ? `Too wide: ${bad}. Scope the line to database inventory and user report.` : 'The office line is limited to report on inventory.' };
      },
    }],
    concepts: ['db.access'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'db-missing-grant',
    title: 'Release 2.4',
    difficulty: 'intermediate',
    ticket: 'Application team: "Release 2.4 went live this morning: invoices are now stored in the database. The release script created the table, but every invoice page fails: ERROR: permission denied for table invoices. It works in our test environment, where the app connects as the owner."',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'The application (webapp, from srv01) can store and read invoices.',
      steps: [
        { host: 'srv01', user: 'root', command: "psql -h db01.corp.lab -U webapp -d inventory -w -c \"INSERT INTO invoices (order_id, amount, issued) VALUES (1006, 120, '2026-10-19')\"" },
        { host: 'srv01', user: 'root', command: 'psql -h db01.corp.lab -U webapp -d inventory -w -A -t -c "SELECT count(*) FROM invoices"' },
      ],
      expect: '^\\d+$',
    }],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'db01', [
        PSQL('CREATE TABLE invoices (id serial PRIMARY KEY, order_id integer NOT NULL, amount numeric(10,2), issued date)'),
        PSQL('ALTER TABLE invoices OWNER TO invowner'),
        PSQL("INSERT INTO invoices (order_id, amount, issued) VALUES (1001, 250, '2026-10-14'), (1004, 1800, '2026-10-16')"),
      ]);
      activity(world);
      script(world, 'srv01', ['psql -h db01.corp.lab -U webapp -d inventory -w -c "SELECT * FROM invoices"']);
    },
    rootCauses: ['db-missing-grant'],
    acceptable: { 'db-connect-privilege': 'Close: privileges are the topic, but CONNECT works (webapp reads items fine); it is the table privilege that is missing.' },
    candidates: CANDIDATES,
    feedback: {
      'db-hba-no-entry': 'webapp connects and reads items: pg_hba.conf and authentication are fine.',
      'db-wrong-password': 'The login works; the error comes later, on one table.',
      'db-data-deleted': 'The table exists and has rows (as postgres: SELECT count(*) FROM invoices).',
    },
    hints: [
      'webapp can log in and read items, but not invoices: compare the privileges of the tables. In psql on db01 (sudo -u postgres psql -d inventory): \\dp.',
      'invoices has only its owner\'s privileges (invowner=arwdDxt/invowner). In PostgreSQL a new table belongs to its owner; nobody else gets anything until it is granted.',
      'GRANT SELECT, INSERT ON invoices TO webapp; (as postgres in inventory). For the next releases, ALTER DEFAULT PRIVILEGES FOR ROLE invowner GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO webapp; makes future tables come with the grants.',
    ],
    explanation: {
      rootCause: 'The release script created invoices (owned by invowner) but granted nothing to webapp. Privileges in PostgreSQL are per object: the existing GRANTs on items and orders do not apply to a new table, and no default privileges were defined.',
      manifestation: 'Every statement on invoices fails with "permission denied for table invoices"; the rest of the application works. In test the app logs in as the owner, which hides the problem.',
      evidence: '\\dp invoices shows only invowner=arwdDxt/invowner; the server log has "webapp@inventory ERROR:  permission denied for table invoices" with the statement.',
      prevention: 'Let migrations include their GRANTs, or set ALTER DEFAULT PRIVILEGES for the owner role once; test with the application\'s real role, never as the owner or a superuser.',
    },
    solution: [{ host: 'db01', commands: [PSQL('GRANT SELECT, INSERT ON invoices TO webapp')] }],
    constraints: [rolesLimited('webapp'), noPublicGrants(), hbaPolicy()],
    concepts: ['db.admin'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'db-md5-scram',
    title: 'Migrated account',
    difficulty: 'advanced',
    ticket: 'Billing team: "Our nightly export (billing-export on srv01) fails since the database moved to db01: password authentication failed for user "billing". The password in our .pgpass is the same as on the old server, and we checked it twice." The account was copied from the old PostgreSQL 11 server with pg_dumpall --globals-only (CHG-2510).',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'On srv01, billing-export logs in as billing and reads the orders.',
      steps: [{ host: 'srv01', user: 'root', command: 'billing-export' }],
      expect: '^\\d+$',
    }],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'db01', [
        `sudo -u postgres psql -c "SET password_encryption = 'md5'; CREATE ROLE billing LOGIN PASSWORD 'Billing-db-26';"`,
        PSQL('GRANT CONNECT ON DATABASE inventory TO billing', 'postgres'),
        PSQL('GRANT SELECT ON orders TO billing'),
        "printf '# Billing export on srv01 (CHG-2510)\\nhost    inventory       billing         10.0.20.10/32           scram-sha-256\\n' >> /etc/postgresql/15/main/pg_hba.conf",
        'systemctl reload postgresql',
      ]);
      script(world, 'srv01', [
        "printf 'db01.corp.lab:5432:inventory:billing:Billing-db-26\\n' >> /root/.pgpass",
        `printf '#!/bin/sh\\n# Nightly billing export (cron)\\nset -e\\npsql -h db01.corp.lab -U billing -d inventory -w -A -t -c "SELECT count(*) FROM orders"\\n' > /usr/local/bin/billing-export`,
        'chmod 755 /usr/local/bin/billing-export',
      ]);
      activity(world);
      script(world, 'srv01', ['billing-export']);
    },
    rootCauses: ['db-md5-secret'],
    acceptable: { 'db-wrong-password': 'The message is the same, but the password is right: the server log says why it still fails.' },
    candidates: CANDIDATES,
    feedback: {
      'db-hba-no-entry': 'A line matches (the log names it: "Connection matched pg_hba.conf line …"): the failure is the password check.',
      'db-connect-privilege': 'The connection fails at authentication, before CONNECT is checked.',
      'db-listen-localhost': 'The server answers with a FATAL message: it listens.',
    },
    hints: [
      'The client only says "password authentication failed". The server log says more: tail /var/log/postgresql/postgresql-15-main.log on db01. Read the DETAIL line.',
      '"User "billing" does not have a valid SCRAM secret": the role\'s password is stored as an MD5 hash (as superuser: SELECT rolname, rolpassword FROM pg_authid WHERE rolname = \'billing\';), and the matching pg_hba.conf line requires scram-sha-256, which cannot use an MD5 hash.',
      'Store the password again so it is hashed with SCRAM (password_encryption is scram-sha-256): sudo -u postgres psql -c "ALTER ROLE billing PASSWORD \'Billing-db-26\'" (or \\password billing). Do not switch the line to md5: the policy is scram only.',
    ],
    explanation: {
      rootCause: 'The old server stored passwords as MD5 hashes; pg_dumpall copied the hash, not the password. db01\'s pg_hba.conf requires scram-sha-256 for billing, and a SCRAM exchange cannot be done with an MD5 hash, so every login fails even with the right password.',
      manifestation: '"FATAL:  password authentication failed for user "billing"" exactly like a wrong password, which sends people retyping it.',
      evidence: 'Server log DETAIL: "User "billing" does not have a valid SCRAM secret." followed by the matched pg_hba.conf line; pg_authid.rolpassword starts with md5 instead of SCRAM-SHA-256$.',
      prevention: 'When migrating to SCRAM, reset each role\'s password after setting password_encryption = scram-sha-256 (query pg_authid for md5 hashes first); keep a list of service accounts to update; never fall back to md5 in pg_hba.conf.',
    },
    solution: [{ host: 'db01', commands: [`sudo -u postgres psql -c "ALTER ROLE billing PASSWORD 'Billing-db-26'"`] }],
    constraints: [hbaPolicy(), rolesLimited('billing', 'webapp')],
    concepts: ['db.access'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'db-backup-grant',
    title: 'The nightly backup',
    difficulty: 'intermediate',
    ticket: 'Monitoring: "Backup check CRITICAL on db01: /var/backups/postgresql/inventory.dump is 2 days old." Nobody changed the backup job; the only database change this week was the new supplier_contracts table (CHG-2526, Tuesday).',
    briefing: BRIEFING,
    goals: [{
      kind: 'command',
      description: 'pg-backup on db01 completes and the dump contains every table, including supplier_contracts.',
      steps: [{ host: 'db01', user: 'root', command: 'pg-backup' }, { host: 'db01', user: 'root', command: 'pg_restore -l /var/backups/postgresql/inventory.dump' }],
      expect: 'TABLE DATA public supplier_contracts',
    }],
    terminals: TERMINALS,
    setup(world) {
      const h = world.hosts.db01;
      // The last good dump is from Sunday night.
      const dump = h.fs['/var/backups/postgresql/inventory.dump'];
      if (dump) dump.mtime = Date.parse('2026-10-17T02:15:01Z');
      script(world, 'db01', [
        PSQL('CREATE TABLE supplier_contracts (id serial PRIMARY KEY, supplier_id integer NOT NULL, starts date, ends date, value numeric(12,2))'),
        PSQL('ALTER TABLE supplier_contracts OWNER TO invowner'),
        PSQL("INSERT INTO supplier_contracts (supplier_id, starts, ends, value) VALUES (1, '2026-01-01', '2026-12-31', 48000), (2, '2026-07-01', '2027-06-30', 15500)"),
        PSQL('GRANT SELECT ON supplier_contracts TO webapp'),
        'pg-backup',
      ]);
      activity(world);
    },
    rootCauses: ['db-missing-grant'],
    candidates: CANDIDATES,
    feedback: {
      'db-wrong-password': 'The backup logs in (the log shows "connection authorized: user=backup"): the failure comes after.',
      'db-hba-no-entry': 'backup connects from localhost through the default line host all all 127.0.0.1/32.',
      'db-service-down': 'PostgreSQL runs; only the dump fails.',
      'db-datadir-perms': 'The server runs normally: run pg-backup by hand and read its error.',
    },
    hints: [
      'Run the job by hand as cron does: pg-backup on db01 (as root). What does pg_dump say?',
      '"permission denied for table supplier_contracts" while running LOCK TABLE: pg_dump must read every table it dumps, and the backup role was granted SELECT table by table (\\dp in inventory).',
      'Give the backup role read access that also covers future tables: GRANT pg_read_all_data TO backup; (PostgreSQL 14+). A plain GRANT SELECT ON supplier_contracts TO backup works too, until the next new table. Then run pg-backup again and check with pg_restore -l.',
    ],
    explanation: {
      rootCause: 'The backup role had SELECT granted on each existing table. The new table supplier_contracts was not granted to it, and pg_dump stops at the first table it cannot read, so every night since Tuesday the job failed and left the old dump in place.',
      manifestation: 'No new dump; the old file stays, so a quick "is there a backup file" check passes while the backup ages. The error only appears in the job\'s output (cron mail) and the server log.',
      evidence: 'pg-backup: "pg_dump: error: query failed: ERROR:  permission denied for table supplier_contracts" / "Query was: LOCK TABLE public.supplier_contracts IN ACCESS SHARE MODE"; server log: "backup@inventory ERROR:  permission denied for table supplier_contracts"; ls -l shows the dump\'s date.',
      prevention: 'Give backup roles pg_read_all_data instead of per-table grants; monitor the age of the newest dump and the job\'s exit status; test restores regularly (pg_restore -l, or a restore into a scratch database).',
    },
    solution: [{ host: 'db01', commands: [PSQL('GRANT pg_read_all_data TO backup', 'postgres')] }],
    constraints: [rolesLimited('backup', 'webapp'), noPublicGrants(), {
      id: 'db-backup-read-only', required: true,
      description: 'The backup role stays read-only (no pg_write_all_data, no write privileges on tables).',
      check(world) {
        const c = cluster(world.hosts.db01);
        const b = c.roles.backup;
        const writes = !b || b.memberOf.includes('pg_write_all_data') || Object.values(c.databases.inventory.tables).some((t) => /[awdD]/.test(t.acl.backup ?? ''));
        return { id: this.id, ok: !writes, required: true, message: writes ? 'The backup role can now change data: give it read access only (pg_read_all_data or SELECT).' : 'The backup role can only read.' };
      },
    }],
    concepts: ['db.admin'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'db-datadir-owner',
    title: 'After the disk move',
    difficulty: 'advanced',
    ticket: 'Storage team: "We moved db01\'s database files to the new disk tonight (CHG-2531): stopped PostgreSQL, copied /var/lib/postgresql/15/main away and back with cp -r as root, started it again. It says it failed but we could not see why." The inventory site is down.',
    briefing: BRIEFING,
    goals: [appCheck],
    terminals: TERMINALS,
    setup(world) {
      script(world, 'db01', ['systemctl stop postgresql', `chown -R root:root ${DATA_DIR}`, 'systemctl start postgresql']);
      activity(world, 30);
    },
    rootCauses: ['db-datadir-perms'],
    acceptable: { 'db-service-down': 'True, PostgreSQL is not running: the question is why it does not start.' },
    candidates: CANDIDATES,
    feedback: {
      'db-listen-localhost': 'Nothing listens at all, not even on localhost: the server is not running (pg_lsclusters: down).',
      'firewall-drop': 'The refusal is immediate, and pg_lsclusters on db01 says down.',
    },
    hints: [
      'On db01: pg_lsclusters and systemctl status postgresql. Then the reason: journalctl -u postgresql@15-main -n 20 or tail /var/log/postgresql/postgresql-15-main.log.',
      '"FATAL:  data directory "/var/lib/postgresql/15/main" has wrong ownership": PostgreSQL refuses to run unless its data directory belongs to the user it runs as (postgres) and is closed to others (0700 or 0750). cp -r as root made root the owner of every file.',
      'chown -R postgres:postgres /var/lib/postgresql/15/main (keep the mode 0700), then systemctl start postgresql and check with pg_lsclusters and inventory-check.',
    ],
    explanation: {
      rootCause: 'The copy with cp -r as root (without -a or --preserve) made root the owner of the data directory and every file in it. The postmaster checks the data directory before anything else and refuses to start when it does not own it.',
      manifestation: 'systemctl start fails; nothing listens on 5432 or the socket, so every client gets "Connection refused" (or "No such file or directory" for the socket).',
      evidence: 'Server log and journal: "FATAL:  data directory "/var/lib/postgresql/15/main" has wrong ownership" with "HINT:  The server must be started by the user that owns the data directory."; ls -ld shows root root.',
      prevention: 'Copy data directories with cp -a or rsync -a (preserving owner and mode) while the server is stopped; better, use pg_basebackup or the platform\'s volume tools; check ownership before starting.',
    },
    solution: [{ host: 'db01', commands: [`chown -R postgres:postgres ${DATA_DIR}`, 'systemctl start postgresql'] }],
    constraints: [hbaPolicy(), {
      id: 'db-datadir-mode', required: true,
      description: 'The data directory stays owned by postgres and closed to other users (0700 or 0750).',
      check(world) {
        const n = world.hosts.db01.fs[DATA_DIR];
        const ok = !!n && n.owner === 'postgres' && ((n.mode & 0o777) === 0o700 || (n.mode & 0o777) === 0o750);
        return { id: this.id, ok, required: true, message: ok ? 'The data directory is postgres-owned with mode 0700/0750.' : 'The data directory must be owned by postgres with mode 0700 (or 0750).' };
      },
    }],
    concepts: ['db.admin', 'linux.permissions'],
  },
  // -------------------------------------------------------------------------
  {
    id: 'db-restore-orders',
    title: 'DELETE without WHERE',
    difficulty: 'intermediate',
    ticket: 'Developer: "Sorry! I wanted to delete one test order from the application console and typed DELETE FROM orders; without the WHERE. All orders are gone. One customer order has come in since (1007), please don\'t lose it." Last night\'s backup is /var/backups/postgresql/inventory.dump.',
    briefing: [...BRIEFING, 'Backups are custom-format archives (pg_dump -Fc): list them with pg_restore -l, restore selectively with pg_restore -d DB -t TABLE (--data-only for rows only).'],
    goals: [
      { kind: 'command', description: 'The orders from before the incident are back (order 1004 for Northwind).', steps: [{ host: 'srv01', user: 'root', command: 'psql -h db01.corp.lab -U webapp -d inventory -w -A -t -c "SELECT customer FROM orders WHERE id = 1004"' }], expect: '^Northwind$' },
      { kind: 'command', description: 'Order 1007, placed after the incident, is still there.', steps: [{ host: 'srv01', user: 'root', command: 'psql -h db01.corp.lab -U webapp -d inventory -w -A -t -c "SELECT customer FROM orders WHERE id = 1007"' }], expect: '^Litware$' },
    ],
    terminals: TERMINALS,
    setup(world) {
      activity(world, 90);
      script(world, 'srv01', [
        'psql -h db01.corp.lab -U webapp -d inventory -w -c "DELETE FROM orders"',
        "psql -h db01.corp.lab -U webapp -d inventory -w -c \"INSERT INTO orders (item_id, qty, customer, created) VALUES (5, 4, 'Litware', '2026-10-19')\"",
      ]);
    },
    rootCauses: ['db-data-deleted'],
    candidates: CANDIDATES,
    feedback: {
      'db-missing-grant': 'The application can read and write orders; the rows are simply gone.',
      'db-service-down': 'The database answers; it returns an almost empty table.',
    },
    hints: [
      'First look before you touch anything: what is in orders now (SELECT * FROM orders;), and what is in the backup (pg_restore -l /var/backups/postgresql/inventory.dump)?',
      'Restoring the whole database (or the table with --clean) would bring back the old orders but delete order 1007. Restore only the rows of that one table: pg_restore --data-only -t orders.',
      'As postgres (the file is readable by the postgres group): sudo -u postgres pg_restore -d inventory --data-only -t orders /var/backups/postgresql/inventory.dump. Then check both orders 1004 and 1007.',
    ],
    explanation: {
      rootCause: 'A DELETE without a WHERE clause removed every row of orders. The table and its privileges are intact; only data is missing, and it exists in last night\'s logical backup.',
      manifestation: 'The application shows no order history; new orders still work. Nothing is wrong with the server, so no monitoring alarm fires.',
      evidence: 'SELECT count(*) FROM orders → 1 (only 1007); with log_statement = mod the server log would show the DELETE; pg_restore -l lists "TABLE DATA public orders" in the dump from 02:15.',
      prevention: 'Do not give application roles DELETE where it is not needed; run manual changes inside BEGIN … COMMIT and check the row count before COMMIT; keep tested backups, and consider point-in-time recovery (WAL archiving) for data changed between backups.',
    },
    solution: [{ host: 'db01', commands: ['sudo -u postgres pg_restore -d inventory --data-only -t orders /var/backups/postgresql/inventory.dump'] }],
    constraints: [rolesLimited('webapp'), {
      id: 'db-items-intact', required: true,
      description: 'The other tables are untouched (items still has its 6 rows, suppliers its 3).',
      check(world) {
        const t = cluster(world.hosts.db01).databases.inventory.tables;
        const ok = t.items?.rows.length === 6 && t.suppliers?.rows.length === 3 && !!t.orders;
        return { id: this.id, ok, required: true, message: ok ? 'items and suppliers are unchanged.' : 'items or suppliers changed: restore only what was lost (the orders rows).' };
      },
    }],
    concepts: ['db.admin'],
  },
];

