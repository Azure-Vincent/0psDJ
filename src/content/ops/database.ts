// Database servers with PostgreSQL. Examples follow the lab: db01 (10.0.20.35)
// runs PostgreSQL 15 (Debian cluster 15/main) with the inventory database used
// by the application on srv01; Lab 7 sets up db02 from a fresh install. The
// sandbox and the tickets run there. MySQL/MariaDB, RHEL and SQL Server are
// covered as deployment notes.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const DATABASE_GUIDE: ServiceGuide = {
  purpose:
    'A **database server** stores an organisation\'s structured data (orders, accounts, tickets) and lets many applications read and change it at the same time, safely. Applications connect over the network, log in as a **role**, and send **SQL**. The server enforces who may see and change what, keeps data consistent when many changes happen at once, and survives crashes because every change is first written to a log (the WAL). An administrator installs it, creates databases and roles, opens it to exactly the clients that need it, backs it up and proves the backups restore.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Shared, consistent, durable data: many clients at once, transactions that either happen completely or not at all, privileges per role and object, and recovery after a crash or a mistake (from backups).' },
    { q: 'How does it work internally?', a: 'The **postmaster** (the main postgres process) listens for connections and starts one **backend process per connection**. Changes go to shared memory and are written first to the **write-ahead log** (WAL, pg_wal/) and later to the table files in the **data directory**; after a crash the server replays the WAL. Background processes write and checkpoint data, and **autovacuum** cleans up old row versions.' },
    { q: 'Which protocols does it use?', a: 'PostgreSQL\'s own frontend/backend protocol over TCP (or a Unix socket on the server itself), optionally inside TLS. The client sends a startup message (user, database), authenticates as pg_hba.conf requires, then sends SQL and receives rows.' },
    { q: 'Which ports and transport?', a: 'TCP **5432** (PostgreSQL), 3306 (MySQL/MariaDB), 1433 (SQL Server). Local clients use the Unix socket /var/run/postgresql/.s.PGSQL.5432. The port should be reachable only from the application servers, never from the Internet.' },
    { q: 'Which processes and OS components implement it?', a: '`postgres` processes (postmaster, one backend per client, checkpointer, background writer, WAL writer, autovacuum launcher) running as the **postgres** OS user; on Debian the unit postgresql@15-main.service and the tools pg_lsclusters / pg_ctlcluster from postgresql-common.' },
    { q: 'Which other services does it depend on?', a: 'Disk (the data directory and WAL; a full disk stops writes), the network and firewall (5432 from the applications), DNS for clients that use the server\'s name, accurate time (logs, TLS, password expiry), and a backup target.' },
    { q: 'How do requests travel?', a: 'The application on srv01 opens TCP to db01:5432 → asks for TLS → sends user webapp and database inventory → PostgreSQL finds the first matching pg_hba.conf line (host inventory webapp 10.0.20.10/32 scram-sha-256) → SCRAM password exchange → checks LOGIN and CONNECT → a backend process serves the session → each SQL statement is checked against the table privileges → rows come back.' },
    { q: 'How do authentication and authorisation work?', a: '**Authentication**: pg_hba.conf decides *how* a connection must prove who it is (peer: same OS user, for local admin access; scram-sha-256: password; trust: nothing, never use it) and *whether* it may connect at all. **Authorisation**: roles have attributes (LOGIN, SUPERUSER, CREATEDB …), and privileges are granted per object: CONNECT on a database, SELECT/INSERT/UPDATE/DELETE on each table. The owner of an object has all privileges on it.' },
    { q: 'How does it start at boot?', a: 'postgresql@15-main.service starts the cluster if start.conf says auto. At start it checks the data directory (owner postgres, mode 0700), reads postgresql.conf (and conf.d, postgresql.auto.conf) and pg_hba.conf, binds listen_addresses:port and the socket, and replays the WAL if it was not shut down cleanly.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'Every client loses its connection and its open transactions are rolled back. Committed data is safe: at the next start the server replays the WAL ("database system was interrupted; last known up at …", then "redo done"). Applications must reconnect.' },
  ],
  ports: [
    { port: '5432', proto: 'TCP', purpose: 'PostgreSQL (frontend/backend protocol, optionally TLS)' },
    { port: 'Unix socket', proto: '/var/run/postgresql/.s.PGSQL.5432', purpose: 'Local connections on the server (peer authentication)' },
    { port: '3306', proto: 'TCP', purpose: 'MySQL / MariaDB' },
    { port: '1433', proto: 'TCP', purpose: 'Microsoft SQL Server' },
  ],
  processes: [
    { name: 'postgres (postmaster)', platform: 'Linux (postgresql@15-main.service)', role: 'Listens, authenticates and starts one backend per connection' },
    { name: 'postgres: 15/main: USER DB CLIENT', platform: 'Linux', role: 'A backend serving one client session (visible in ps and pg_stat_activity)' },
    { name: 'checkpointer, background writer, walwriter, autovacuum', platform: 'Linux', role: 'Write data and WAL to disk, clean up old row versions' },
    { name: 'mysqld / mariadbd', platform: 'Linux (MySQL, MariaDB)', role: 'One process, one thread per connection' },
    { name: 'sqlservr.exe (MSSQLSERVER)', platform: 'Windows (SQL Server)', role: 'The SQL Server engine' },
  ],
  dependencies: {
    title: 'What "the application on srv01 reads the inventory" depends on (top needs everything below it)',
    caption: 'Each layer refuses in its own words: refused, no pg_hba.conf entry, password authentication failed, permission denied.',
    rows: [
      { label: 'Client', nodes: [{ id: 'app', label: 'Application', sub: 'webapp, ~/.pgpass', kind: 'service' }] },
      { label: 'Path', nodes: [{ id: 'dns', label: 'DNS', sub: 'db01.corp.lab', kind: 'network' }, { id: 'fw', label: 'db01 firewall', sub: 'tcp dport 5432', kind: 'network' }] },
      { label: 'Server', nodes: [{ id: 'pm', label: 'postmaster', sub: 'listen_addresses:5432', kind: 'service' }, { id: 'hba', label: 'pg_hba.conf', sub: 'first matching line', kind: 'data' }] },
      { label: 'Database', nodes: [{ id: 'role', label: 'Role webapp', sub: 'LOGIN, SCRAM password', kind: 'data' }, { id: 'priv', label: 'Privileges', sub: 'CONNECT, SELECT …', kind: 'data' }] },
      { label: 'Storage', nodes: [{ id: 'data', label: 'Data directory', sub: 'postgres 0700', kind: 'os' }, { id: 'bak', label: 'Backups', sub: 'pg_dump', kind: 'data' }] },
    ],
    edges: [['app', 'dns'], ['app', 'fw'], ['fw', 'pm'], ['pm', 'hba'], ['hba', 'role'], ['role', 'priv'], ['pm', 'data'], ['data', 'bak']],
  },
  sequence: {
    title: 'srv01 runs SELECT count(*) FROM items as webapp',
    caption: 'PostgreSQL 15 on db01, libpq with sslmode=prefer. Where each ticket breaks the exchange is noted.',
    lanes: [{ id: 'c', label: 'srv01', sub: 'psql (webapp)' }, { id: 's', label: 'db01', sub: 'postmaster / backend' }],
    steps: [
      { from: 'c', to: 's', label: 'TCP SYN to 10.0.20.35:5432', note: 'listen_addresses = localhost → Connection refused. Server not started (data directory owned by root) → refused too.' },
      { from: 'c', to: 's', label: 'SSLRequest → S, TLS handshake' },
      { from: 'c', to: 's', label: 'StartupMessage (user webapp, database inventory)', note: 'pg_hba.conf: first matching line decides; none → FATAL: no pg_hba.conf entry.' },
      { from: 's', to: 'c', label: 'AuthenticationSASL (SCRAM-SHA-256)', note: 'Wrong password → password authentication failed; MD5-stored password → "does not have a valid SCRAM secret".' },
      { from: 'c', to: 's', label: 'SCRAM client-first / client-final' },
      { from: 's', to: 'c', label: 'AuthenticationOk, ReadyForQuery', note: 'Role without LOGIN, or no CONNECT on the database → FATAL here.' },
      { from: 'c', to: 's', label: 'Query: SELECT count(*) FROM items', note: 'No SELECT on the table → ERROR: permission denied for table items.' },
      { from: 's', to: 'c', label: 'RowDescription, DataRow (6), CommandComplete' },
    ],
  },
  files: [
    { path: '/etc/postgresql/15/main/postgresql.conf', platform: 'Debian / Ubuntu', kind: 'config', perms: 'postgres:postgres 0644', contains: 'Server settings: listen_addresses, port, max_connections, memory, logging, ssl, include_dir = \'conf.d\'.', accessed: 'At start; most settings also on reload, some (listen_addresses, port, max_connections, shared_buffers) only at restart.', problems: 'A package update may offer to replace it: keep local settings in conf.d/*.conf.' },
    { path: '/etc/postgresql/15/main/pg_hba.conf', platform: 'Debian / Ubuntu', kind: 'auth', perms: 'postgres:postgres 0640', contains: 'Who may connect: TYPE DATABASE USER ADDRESS METHOD, matched top to bottom; first match decides.', accessed: 'At start and reload (systemctl reload postgresql, SELECT pg_reload_conf()).', problems: 'A line in the wrong place never matches (an earlier line wins); an invalid line keeps the old rules loaded.' },
    { path: '/var/lib/postgresql/15/main', platform: 'Debian (data directory)', kind: 'data', perms: 'postgres:postgres 0700', contains: 'Table files (base/), WAL (pg_wal/), PG_VERSION, postgresql.auto.conf (ALTER SYSTEM).', accessed: 'Constantly by the server.', problems: 'Wrong owner or mode → the server refuses to start. Never copy it while the server runs; never edit files in it.' },
    { path: '/var/log/postgresql/postgresql-15-main.log', platform: 'Debian', kind: 'log', perms: 'postgres:adm 0640', contains: 'Start/stop, connection and authentication failures (with the pg_hba.conf line), errors with the statement.', accessed: 'Written by the server.', problems: 'The client only sees "password authentication failed": the reason (DETAIL) is here.' },
    { path: '~/.pgpass', platform: 'Clients (libpq)', kind: 'auth', perms: 'USER 0600', contains: 'host:port:database:user:password lines used by psql, pg_dump and applications.', accessed: 'When the server asks for a password.', problems: 'Ignored (with a warning) unless mode 0600.' },
    { path: '/var/lib/pgsql/data (RHEL), /etc/mysql/mariadb.conf.d (MariaDB)', platform: 'Other platforms', kind: 'config-dir', contains: 'RHEL keeps postgresql.conf and pg_hba.conf inside the data directory; MariaDB uses /etc/mysql with bind-address and user@host accounts.', accessed: 'At start.', problems: 'Same ideas, different places.' },
  ],
  management: [
    {
      platform: 'Database server (db01): service and cluster',
      tasks: [
        { task: 'Which clusters exist, and are they running?', command: 'pg_lsclusters\nsystemctl status postgresql@15-main', explain: 'Version, cluster name, port, status, data directory and log file.', sim: true },
        { task: 'Start, stop, reload, restart', command: 'pg_ctlcluster 15 main reload\nsystemctl restart postgresql', explain: 'Reload for pg_hba.conf and most settings; restart for listen_addresses, port, memory.', sim: true },
        { task: 'Read the log', command: 'tail -n 20 /var/log/postgresql/postgresql-15-main.log', explain: 'Connection failures with their DETAIL and the matched pg_hba.conf line.', sim: true },
        { task: 'Where does it listen?', command: 'ss -tlnp | grep 5432', explain: '127.0.0.1 only means listen_addresses = localhost.', sim: true },
      ],
    },
    {
      platform: 'Database server (db01): inside PostgreSQL',
      tasks: [
        { task: 'Open psql as the database superuser', command: 'sudo -u postgres psql', explain: 'Peer authentication over the Unix socket; \\l, \\du, \\c inventory, \\dt, \\dp, \\q.', sim: true },
        { task: 'Create an application database and role', command: 'sudo -u postgres createuser --no-login appowner\nsudo -u postgres createdb -O appowner appdb\nsudo -u postgres createuser -P appuser', explain: 'Wrappers around CREATE ROLE / CREATE DATABASE: an owner nobody logs in as, its database, and a login role (-P asks for its password).', sim: true },
        { task: 'Grant and check privileges', command: 'sudo -u postgres psql -c "CREATE ROLE report LOGIN PASSWORD \'Report-db-26\'"\nsudo -u postgres psql -d inventory -c "GRANT CONNECT ON DATABASE inventory TO report" -c "GRANT SELECT ON items, orders TO report"\nsudo -u postgres psql -d inventory -c "\\dp"', explain: 'CONNECT on the database and privileges per table are separate grants; \\dp shows them (report=r/invowner).', sim: true },
        { task: 'Who is connected?', command: 'sudo -u postgres psql -c "SELECT pid, usename, datname, client_addr, state FROM pg_stat_activity"', explain: 'One row per backend; pg_terminate_backend(pid) ends one.', sim: true },
        { task: 'Settings in effect and pending', command: 'sudo -u postgres psql -c "SELECT name, setting, pending_restart FROM pg_settings WHERE name = \'listen_addresses\'"', explain: 'pending_restart t: the file changed but needs a restart.', sim: true },
      ],
    },
    {
      platform: 'Backups',
      tasks: [
        { task: 'Logical backup of one database', command: 'pg_dump -h localhost -U backup -Fc -f /var/backups/postgresql/inventory.dump inventory', explain: 'Consistent, compressed custom format.', sim: true },
        { task: 'Inspect and restore', command: 'pg_restore -l /var/backups/postgresql/inventory.dump\nsudo -u postgres pg_restore -d inventory --data-only -t orders /var/backups/postgresql/inventory.dump', explain: 'List the contents; put back the rows of one table whose rows were lost (rows still present cause a duplicate key error: restore into a scratch database instead).', sim: true },
        { task: 'Roles (cluster-wide)', command: 'sudo -u postgres pg_dumpall --globals-only -f /var/backups/postgresql/globals.sql', explain: 'pg_dump does not include roles.', sim: true },
      ],
    },
    {
      platform: 'Client (srv01, ws01)',
      tasks: [
        { task: 'Connect and run a query', command: 'psql -h db01.corp.lab -U webapp -d inventory -c "SELECT count(*) FROM items"', explain: 'The error tells which layer refused.', sim: true },
        { task: 'Is the server up (no login needed)?', command: 'pg_isready -h db01.corp.lab', explain: 'accepting connections / no response.', sim: true },
      ],
    },
  ],
  actions: [
    { action: 'Reload (systemctl reload postgresql, SELECT pg_reload_conf())', when: 'After editing pg_hba.conf or reloadable settings.', effect: 'New connections use the new rules; sessions stay connected.', risk: 'An error in pg_hba.conf keeps the old rules (check the log).' },
    { action: 'Restart (systemctl restart postgresql)', when: 'After changing listen_addresses, port, max_connections, shared_buffers, or for a minor version update.', effect: 'Every session is disconnected; open transactions are rolled back.', risk: 'A configuration error now stops the server: check the log, keep a console open.' },
    { action: 'GRANT / REVOKE / ALTER DEFAULT PRIVILEGES', when: 'Giving or taking access.', effect: 'Immediate for every session.', risk: 'GRANT … TO PUBLIC gives every role (and future roles) the access.' },
    { action: 'pg_terminate_backend(pid)', when: 'A stuck or abusive session.', effect: 'Ends that backend; its transaction is rolled back.', risk: 'The application sees an error and must reconnect.' },
    { action: 'pg_restore --clean', when: 'Restoring a whole database to a backup.', effect: 'Drops and recreates the objects from the dump.', risk: 'Everything changed since the backup is lost: prefer selective restores (-t, --data-only) or a scratch database.' },
  ],
  workflow: [
    { question: 'Does the server run and listen where the client connects?', why: 'Nothing else matters if TCP does not connect; refused and timed out point to different causes.', command: 'pg_lsclusters\nss -tlnp | grep 5432\npg_isready -h db01.corp.lab', healthy: 'online; 0.0.0.0:5432; accepting connections', broken: 'down (read the log: data directory, configuration); 127.0.0.1:5432 only (listen_addresses); no response from the client (firewall).', next: 'Then who may connect.', sim: true },
    { question: 'Does pg_hba.conf let this client in?', why: 'PostgreSQL refuses connections that match no line, before any password.', command: 'psql -h db01.corp.lab -U report -d inventory -c "SELECT 1"\nsudo -u postgres psql -c "SELECT line_number, type, database, user_name, address, auth_method FROM pg_hba_file_rules"', healthy: 'A password prompt, or a result', broken: 'FATAL: no pg_hba.conf entry for host "IP", user "U", database "D"', next: 'Then authentication.', sim: true },
    { question: 'Does authentication succeed?', why: 'Same client message for wrong password, unknown role and MD5 hash: the server log says which.', command: 'tail -n 5 /var/log/postgresql/postgresql-15-main.log', healthy: 'connection authorized: user=U database=D', broken: 'DETAIL: Password does not match / Role does not exist / does not have a valid SCRAM secret', next: 'Then the database and privileges.', sim: true },
    { question: 'May the role open the database and use the tables?', why: 'LOGIN, CONNECT and table privileges are separate checks.', command: 'sudo -u postgres psql -c "\\du"\nsudo -u postgres psql -c "\\l"\nsudo -u postgres psql -d inventory -c "\\dp"', healthy: 'The role has LOGIN, CONNECT on the database, and the privileges it needs', broken: 'role is not permitted to log in; permission denied for database; permission denied for table', next: 'Grant exactly what is missing.', sim: true },
    { question: 'Is the data itself right?', why: 'A server that answers can still hold wrong data (a DELETE without WHERE).', command: 'sudo -u postgres psql -d inventory -c "SELECT count(*) FROM orders"\npg_restore -l /var/backups/postgresql/inventory.dump', healthy: 'The expected rows', broken: 'Missing rows: restore selectively from the last backup', next: 'Restore only what was lost.', sim: true },
  ],
  failures: [
    { symptom: 'Connection refused from other machines; psql on the server works', causes: ['listen_addresses = localhost (the default)'], diagnose: ['ss -tlnp | grep 5432', 'SHOW listen_addresses'], fix: 'listen_addresses = \'*\' (or the server\'s address) in conf.d, then restart.', verify: 'ss shows 0.0.0.0:5432; pg_isready from the client.' },
    { symptom: 'FATAL: no pg_hba.conf entry for host …', causes: ['No line for that database/user/address', 'The line is there but was not reloaded'], diagnose: ['pg_hba_file_rules', 'The server log'], fix: 'A narrow host line with scram-sha-256, then reload.', verify: 'The client gets a password prompt or a result.' },
    { symptom: 'password authentication failed (password is right)', causes: ['Password stored as MD5, line requires scram-sha-256', 'Outdated ~/.pgpass'], diagnose: ['DETAIL line in the server log', 'pg_authid.rolpassword'], fix: 'ALTER ROLE … PASSWORD (re-hashed with SCRAM).', verify: 'The log shows connection authorized.' },
    { symptom: 'permission denied for table T', causes: ['No GRANT on a new table', 'Backup role granted table by table'], diagnose: ['\\dp T'], fix: 'GRANT the needed privileges; ALTER DEFAULT PRIVILEGES; pg_read_all_data for backups.', verify: 'The statement works as the real role.' },
    { symptom: 'Server does not start', causes: ['Data directory with wrong owner or mode', 'Error in postgresql.conf or pg_hba.conf', 'Port in use / address not on the host'], diagnose: ['journalctl -u postgresql@15-main', 'The cluster log'], fix: 'Fix what the FATAL line names; chown -R postgres:postgres the data directory.', verify: 'pg_lsclusters online.' },
  ],
  verification: [
    { check: 'Running and listening', command: 'pg_lsclusters && ss -tlnp | grep 5432', expect: 'online; postgres on the intended addresses' },
    { check: 'Application access', command: 'psql -h db01.corp.lab -U webapp -d inventory -c "SELECT count(*) FROM items"', expect: 'A count (as the real application role)' },
    { check: 'No unintended access', command: 'psql -h db01.corp.lab -U webapp -d inventory (from ws01)', expect: 'FATAL: no pg_hba.conf entry (or a firewall timeout)' },
    { check: 'Backup is fresh and restorable', command: 'ls -l /var/backups/postgresql && pg_restore -l /var/backups/postgresql/inventory.dump', expect: "Today's dump listing every table" },
  ],
  refIds: ['psql', 'pg_dump', 'pg_ctlcluster', 'file:pg-hba-conf', 'file:postgresql-conf', 'proc:db-new-application', 'proc:db-restore', 'ss'],
};

// --- Lesson -------------------------------------------------------------------------

export const DATABASE_LESSON: Lesson = {
  id: 'database',
  moduleId: 'F',
  title: 'Databases (PostgreSQL)',
  level: 'intermediate',
  summary: 'Set up and run a database server: the cluster and its files, roles, databases and privileges, the path from connection to query (listen_addresses, pg_hba.conf, authentication, CONNECT, GRANT), reload versus restart, logical backups and restore drills, and the errors each layer produces.',
  concepts: ['db.access', 'db.admin', 'linux.permissions', 'fw.path'],
  what: `
A **database server** keeps an organisation's structured data, such as orders, accounts or tickets, and lets many programs use it at the same time. Programs connect over the network, **log in** as a role, and ask for data in **SQL**: \`SELECT customer FROM orders WHERE id = 1004\`. The server makes sure that two changes at the same moment do not corrupt each other, that a change is either complete or not there at all, and that nothing committed is lost if the machine crashes.

**PostgreSQL** is the open-source database server used here; MySQL/MariaDB and Microsoft SQL Server work on the same ideas (see the Deploy tab). The same network rules as for any service apply ([ports and firewalls](#/lesson/transport/what)), and the files and service are managed like any other ([systemd](#/lesson/systemd/what)).

### Problems it solves
- **Shared data.** Many applications and users read and change the same data safely.
- **Integrity.** Transactions, constraints (a primary key cannot repeat) and types (a quantity is a number).
- **Access control.** Each role sees and changes only what it was granted.
- **Recovery.** A write-ahead log survives crashes; backups survive mistakes.

### The pieces
- **Cluster**: one running PostgreSQL server with its data directory and configuration (Debian names it by version and name: **15/main**).
- **Databases** inside the cluster (inventory, postgres …), each with **tables** of rows and columns.
- **Roles**: the accounts. A role with LOGIN is a user; roles can be members of other roles (groups). **postgres** is the superuser.
- **Privileges**: what a role may do on which object (CONNECT to a database, SELECT/INSERT/UPDATE/DELETE on a table). The **owner** of an object may do everything with it.
- **pg_hba.conf**: who may connect from where, and how they must prove who they are.
- **Clients**: \`psql\` (the command-line client), applications (through a driver), \`pg_dump\` for backups.

> In the lab, **db01** (10.0.20.35) runs PostgreSQL 15 with the **inventory** database. The application on **srv01** logs in as **webapp**; a nightly job dumps the database as **backup**. As root on db01, \`sudo -u postgres psql\` opens the superuser's session. **Lab 7** builds a second server, db02, from a fresh install. Simulated: the Debian cluster layout (postgresql.conf with include_dir and postgresql.auto.conf, pg_hba.conf, the data directory and its ownership check, the log in Debian's format), settings that need a restart or only a reload, listen_addresses, pg_hba.conf matched top to bottom with peer, scram-sha-256, md5, trust and reject, stored SCRAM and MD5 hashes, ~/.pgpass, LOGIN/CONNECT/connection limits, roles and memberships (including pg_read_all_data), databases, tables and rows, GRANT/REVOKE and default privileges, ALTER SYSTEM, pg_stat_activity, pg_settings, pg_hba_file_rules, pg_authid, psql (interactive with \\l \\du \\dt \\d \\dp \\c \\conninfo \\password \\x, -c, -f), pg_dump (plain and custom format), pg_restore (-l, -t, --data-only, --clean), pg_dumpall --globals-only, pg_lsclusters, pg_ctlcluster, pg_isready, createuser/createdb/dropuser/dropdb. Simplified: one schema (public), a subset of SQL (no joins, views, indexes, sequences as objects or transactions that can be rolled back), no replication, WAL archiving or point-in-time recovery, no pg_upgradecluster.

:::practice
Q: What is a role in PostgreSQL?
A: An account: with **LOGIN** it can connect (a user); without it, it can still own objects or act as a **group** that other roles are members of.
Q: Which file decides which clients may connect to a PostgreSQL server, and how they authenticate?
A: **pg_hba.conf** (host-based authentication).
:::

`,

  internals: `
### 1. The cluster and its files
On Debian, \`apt install postgresql\` creates a **cluster**, here 15/main:
- configuration in **/etc/postgresql/15/main/** (postgresql.conf, pg_hba.conf, pg_ident.conf, conf.d/);
- data in the **data directory** /var/lib/postgresql/15/main: table files (base/), the **write-ahead log** (pg_wal/), PG_VERSION, postgresql.auto.conf;
- the log /var/log/postgresql/postgresql-15-main.log;
- the service postgresql@15-main, running as the operating-system user **postgres**.

\`pg_lsclusters\` lists clusters with their port, status, data directory and log. The data directory must belong to postgres with mode 0700 (or 0750): the server checks this first and refuses to start otherwise ("has wrong ownership"). RHEL keeps everything, configuration included, in /var/lib/pgsql/data.

:::practice
Q: A colleague copied /var/lib/postgresql/15/main to another disk and back with cp -r as root. Why will PostgreSQL not start?
A: The copy made **root** the owner of the data directory; the server must be started by the user that owns it (postgres) and refuses: "data directory … has wrong ownership".
Q: Which command shows Debian's clusters with their status, port and log file?
A: \`pg_lsclusters\`.
:::

### 2. Processes and sessions
The **postmaster** listens on the socket and the TCP port; for each connection it starts a **backend** process that serves that client until it disconnects. \`max_connections\` (100 by default) caps the number of backends. \`pg_stat_activity\` shows one row per backend: who, from where, which database, idle or active; \`pg_terminate_backend(pid)\` ends one.

Changes are written first to the **WAL** and then, lazily, to the table files; after a crash the server replays the WAL, so committed transactions survive.

:::practice
Q: An application opens 120 connections to a server with max_connections = 100. What happens to the extra ones?
A: They are refused with "FATAL: sorry, too many clients already" (a few slots are reserved for superusers).
Q: Which view shows who is connected right now, from which address, to which database?
A: \`pg_stat_activity\`.
:::

### 3. From connect to query
Every connection passes these checks, in this order, and each one fails with its own message:
| Step | What decides | Typical failure |
|---|---|---|
| TCP connect | listen_addresses, port, firewall, server running | Connection refused / timed out |
| pg_hba.conf | first line matching type, database, user, client address | no pg_hba.conf entry for host … |
| Authentication | the line's method (peer, scram-sha-256 …) and the role's password | password authentication failed |
| Role | LOGIN, password expiry, connection limit | role "x" is not permitted to log in |
| Database | exists, CONNECT privilege | permission denied for database "d" |
| Each statement | privileges on the objects | permission denied for table t |

The client only sees the FATAL line; the server log adds a **DETAIL** with the real reason and the matched pg_hba.conf line.

:::practice
Q: psql says "FATAL: no pg_hba.conf entry for host …". Was the password wrong?
A: **No.** No pg_hba.conf line matched, so the server refused the connection before asking for a password.
Q: A role logs in fine but gets "permission denied for table invoices". Which step failed?
A: The **statement's privilege check**: the role lacks a privilege (here probably SELECT) on that table.
:::

### 4. pg_hba.conf
\`\`\`
# TYPE  DATABASE   USER     ADDRESS          METHOD
local   all        postgres                  peer
host    all        all      127.0.0.1/32     scram-sha-256
host    inventory  webapp   10.0.20.10/32    scram-sha-256
\`\`\`
- **TYPE**: local (Unix socket), host (TCP, with or without SSL), hostssl (TCP with SSL only).
- **DATABASE / USER**: names, \`all\`, or \`+group\` for members of a role.
- **ADDRESS**: the client's network in CIDR form.
- **METHOD**: **peer** (the operating-system user must have the same name; local only), **scram-sha-256** (password), **md5** (older password method), **reject**, **trust** (no check at all: never on a network).

Lines are read **from top to bottom and the first match decides**; there is no fall-through to a later line. Changes need a **reload**. Keep lines narrow: one database, one role, one client network.

:::practice
Q: pg_hba.conf has "host all all 10.0.20.0/24 reject" above "host inventory webapp 10.0.20.10/32 scram-sha-256". Can webapp connect from 10.0.20.10?
A: **No.** The reject line matches first (10.0.20.10 is in 10.0.20.0/24), and the first match decides.
Q: After adding a line to pg_hba.conf, what must you run so that new connections use it?
A: A **reload**: \`systemctl reload postgresql\` (or \`SELECT pg_reload_conf();\`). No restart is needed.
:::

### 5. Passwords and peer authentication
The superuser **postgres** usually has no password at all: administrators become the postgres operating-system user (\`sudo -u postgres psql\`), and the first pg_hba.conf line, \`local all postgres peer\`, lets them in because the names match.

Applications use passwords. PostgreSQL stores a **SCRAM-SHA-256 verifier** (password_encryption = scram-sha-256, the default since version 14), never the password. Roles migrated from old servers may still have **MD5 hashes**; a scram-sha-256 line cannot use them ("does not have a valid SCRAM secret"), so reset those passwords. Clients keep passwords in **~/.pgpass** (\`host:port:database:user:password\`, mode 0600) instead of typing them or putting them on the command line.

:::practice
Q: Why does \`sudo -u postgres psql\` work without a password on Debian?
A: It connects over the Unix socket as the OS user postgres, and the line \`local all postgres peer\` accepts it because the OS user name equals the database role name.
Q: A role migrated from PostgreSQL 11 cannot log in through a scram-sha-256 line although its password is right. What do you do?
A: Set its password again (\`ALTER ROLE … PASSWORD …\` or \`\\password\`), so it is stored as a SCRAM verifier. Do not switch the line to md5.
:::

### 6. Roles, owners and privileges
- Every object has an **owner** with all privileges on it; only the owner (or a superuser) can alter it, drop it or grant access to it.
- A role gets nothing it was not granted: \`GRANT CONNECT ON DATABASE inventory TO webapp\`, \`GRANT SELECT, INSERT ON items TO webapp\`. **PUBLIC** means every role.
- Grants are **per object**: a new table has only its owner's privileges. **ALTER DEFAULT PRIVILEGES FOR ROLE owner GRANT … ON TABLES TO app** adds grants automatically to tables that owner creates later.
- **Group roles**: grant to a NOLOGIN role and make users members (\`GRANT reporting TO report\`).
- **Predefined roles** (PostgreSQL 14+): **pg_read_all_data** (read every table, ideal for backups), pg_write_all_data, pg_monitor, pg_signal_backend.
- Since PostgreSQL 15, ordinary roles can no longer create tables in the **public** schema of a database they do not own.

Good practice: a **NOLOGIN owner role** per application, a separate **application role** with only the privileges it uses, and a **read-only backup role**. Never let the application log in as the owner or as a superuser.

:::practice
Q: The release script (run as the owner) created a new table, and the application now gets "permission denied" on it although it can read the other tables. Why?
A: Privileges are **per table**: the new table has only its owner's privileges. Grant them, and set ALTER DEFAULT PRIVILEGES for the future.
Q: Which predefined role gives a backup account read access to every table, also tables created later?
A: **pg_read_all_data**.
:::

### 7. Configuration: reload or restart
postgresql.conf settings have a **context**: some are only read when the server **starts** (listen_addresses, port, max_connections, shared_buffers), most are re-read on **reload** (logging, ssl, authentication timeouts), and some can even be set per session (\`SET work_mem = …\`). PostgreSQL reads postgresql.conf, then the files in **conf.d/** (include_dir), then **postgresql.auto.conf** (written by \`ALTER SYSTEM SET\`); the last value wins.

After a reload, a restart-only change is not applied: the log says "parameter "listen_addresses" cannot be changed without restarting the server", and \`pg_settings.pending_restart\` shows t. \`SHOW name\` shows the value in effect.

:::practice
Q: You changed listen_addresses and ran systemctl reload postgresql. Does the server now listen on the new address?
A: **No.** listen_addresses is read only at start: restart the server. The log and pg_settings.pending_restart tell you.
Q: Where should local settings go on Debian so that a package update cannot overwrite them?
A: In a file under **/etc/postgresql/15/main/conf.d/** (or with ALTER SYSTEM, which writes postgresql.auto.conf).
:::

### 8. Backups
- **Logical**: \`pg_dump\` writes one database as SQL (-Fp) or a compressed archive (-Fc) while it is in use, consistent at one moment. \`pg_restore\` lists (-l) and restores an archive, also selectively (-t TABLE, --data-only). Roles are cluster-wide and need \`pg_dumpall --globals-only\`. Simple and portable (also to a newer version), but a restore only brings back the state at the time of the dump.
- **Physical**: \`pg_basebackup\` copies the whole cluster; together with archived **WAL** it allows **point-in-time recovery** (restore to 10:04, one minute before a mistake). Used for large databases and replicas.

A backup counts only when a **restore** was tested: restore into a scratch database, check the rows, drop it. Watch the age of the newest backup, not only whether a file exists.

:::practice
Q: Which backup method lets you recover the database to 10:04, one minute before a DELETE without WHERE at 10:05?
A: A **physical** backup (pg_basebackup) with **archived WAL** (point-in-time recovery). A nightly pg_dump only restores the state of the night.
Q: pg_dump of one database: does it include the roles and their passwords?
A: **No.** Roles belong to the cluster: save them with \`pg_dumpall --globals-only\`.
:::

### 9. Keeping it healthy
- **VACUUM**: an UPDATE or DELETE leaves old row versions; autovacuum removes them in the background. Disabling it slowly bloats tables and, eventually, risks transaction-ID wraparound.
- **Logs**: log_connections, failed logins, slow statements (log_min_duration_statement) belong in central logging.
- **Updates**: minor versions (15.7 → 15.8) are package updates plus a restart; a major version (15 → 16) needs pg_upgradecluster (or dump and restore).
- **Monitoring**: is it up (pg_isready), connections near max_connections, disk space of the data directory and WAL, age of the last backup, replication lag.

:::practice
Q: What is the difference between updating 15.7 to 15.8 and moving from 15 to 16?
A: A **minor** update (15.7 → 15.8) only needs the new packages and a restart; a **major** upgrade (15 → 16) changes the data format and needs pg_upgradecluster/pg_upgrade or a dump and restore.
Q: What does autovacuum clean up?
A: Old **row versions** left behind by UPDATE and DELETE, so tables do not grow without end.
:::

`,

  deployment: [
    {
      id: 'debian',
      platform: 'Debian 12 / Ubuntu (PostgreSQL 15)',
      summary: 'From apt install to an application database that one application server can use, with a backup. Steps marked simulated can be tried in the sandbox (db01) or step by step in Lab 7.',
      prerequisites: ['A server with a fixed address and a DNS name.', 'The application\'s requirements: database name, which tables it reads and writes, from which host.'],
      steps: [
        { title: 'Install', command: 'sudo apt install -y postgresql', what: 'The package creates the cluster 15/main and starts it.', why: 'Debian sets up a working cluster with safe defaults (localhost only, peer for local logins).', expected: '' },
        { title: 'Look around', command: 'pg_lsclusters\nls /etc/postgresql/15/main', what: 'The cluster, its port, data directory and log; the configuration files.', why: 'Know where configuration, data and log live before changing anything.', expected: '15  main    5432 online postgres /var/lib/postgresql/15/main /var/log/postgresql/postgresql-15-main.log', simulated: true },
        { title: 'Owner role and database', command: 'sudo -u postgres psql -c "CREATE ROLE appowner NOLOGIN"\nsudo -u postgres createdb -O appowner appdb\nsudo -u postgres psql -c "REVOKE CONNECT ON DATABASE appdb FROM PUBLIC"', what: 'A database owned by a role nobody logs in as.', why: 'Owner rights stay out of daily use; other roles cannot open the database by default.', expected: 'CREATE ROLE\nREVOKE', simulated: true },
        { title: 'Application role', command: "sudo -u postgres psql -c \"CREATE ROLE appuser LOGIN PASSWORD 'secret'\"\nsudo -u postgres psql -c \"GRANT CONNECT ON DATABASE appdb TO appuser\"\nsudo -u postgres psql -d appdb -c \"ALTER DEFAULT PRIVILEGES FOR ROLE appowner GRANT SELECT, INSERT, UPDATE ON TABLES TO appuser\"", what: 'A login with only the privileges the application uses.', why: 'Limits what a bug or a stolen password can do.', expected: 'CREATE ROLE\nGRANT\nALTER DEFAULT PRIVILEGES', simulated: true },
        { title: 'Listen on the network', command: "echo \"listen_addresses = '*'\" | sudo tee /etc/postgresql/15/main/conf.d/listen.conf\nsudo systemctl restart postgresql\nss -tlnp | grep 5432", what: 'The default is localhost only.', why: 'A restart is needed; conf.d survives package updates.', expected: 'LISTEN 0 … 0.0.0.0:5432', simulated: true },
        { title: 'pg_hba.conf and firewall', command: 'echo "host    appdb    appuser    10.0.20.10/32    scram-sha-256" | sudo tee -a /etc/postgresql/15/main/pg_hba.conf\nsudo systemctl reload postgresql\n# nftables: ip saddr 10.0.20.10 tcp dport 5432 accept', what: 'One line for one application, one client; the firewall allows only that host.', why: 'Two independent filters; pg_hba.conf only needs a reload.', expected: 'host    appdb    appuser    10.0.20.10/32    scram-sha-256', simulated: true },
        { title: 'Backup and restore test', command: 'sudo -u postgres psql -c "GRANT pg_read_all_data TO backup" -c "GRANT CONNECT ON DATABASE appdb TO backup"\npg_dump -h localhost -U backup -w -Fc -f /var/backups/postgresql/appdb.dump appdb\nsudo -u postgres createdb restoretest\nsudo -u postgres pg_restore -d restoretest /var/backups/postgresql/appdb.dump\nsudo -u postgres pg_restore -l /var/backups/postgresql/appdb.dump\nsudo -u postgres dropdb restoretest', what: 'A read-only backup role (pg_read_all_data) dumps the database; its password comes from root\'s ~/.pgpass (localhost:5432:*:backup:PASSWORD, mode 0600), so cron needs no prompt (-w). The dump is restored once into a scratch database to prove it works.', why: 'An untested backup is not a backup.', expected: 'GRANT ROLE\nGRANT\n;     dbname: appdb\n;     Format: CUSTOM', simulated: true },
      ],
    },
    {
      id: 'rhel',
      platform: 'RHEL 9 (PostgreSQL 15 from AppStream)',
      summary: 'The cluster is not created by the package: initialise it first. Configuration lives in the data directory, and the default pg_hba.conf uses ident for TCP from localhost.',
      prerequisites: ['dnf module enable postgresql:15 && dnf install postgresql-server'],
      steps: [
        { title: 'Initialise and start', command: 'sudo postgresql-setup --initdb\nsudo systemctl enable --now postgresql\nsudo firewall-cmd --permanent --add-service=postgresql && sudo firewall-cmd --reload', what: 'Creates /var/lib/pgsql/data (with postgresql.conf and pg_hba.conf inside).', why: 'RHEL does not start a cluster on its own.', expected: '' },
        { title: 'Same administration', command: 'sudo -u postgres psql', what: 'Roles, databases, GRANTs and pg_dump work the same way.', why: '', expected: 'postgres=#' },
      ],
    },
    {
      id: 'mariadb',
      platform: 'MySQL / MariaDB (Debian: mariadb-server)',
      summary: 'Same ideas, different names: accounts are user@host (the host part replaces pg_hba.conf), bind-address replaces listen_addresses, mysqldump replaces pg_dump.',
      prerequisites: ['sudo apt install mariadb-server; sudo mysql_secure_installation'],
      steps: [
        { title: 'Database, account, privileges', command: "sudo mysql -e \"CREATE DATABASE appdb\"\nsudo mysql -e \"CREATE USER 'appuser'@'10.0.20.10' IDENTIFIED BY 'secret'\"\nsudo mysql -e \"GRANT SELECT, INSERT, UPDATE ON appdb.* TO 'appuser'@'10.0.20.10'\"", what: 'The account includes the client host it may connect from.', why: 'MariaDB checks user and host together.', expected: '' },
        { title: 'Network and backup', command: '# /etc/mysql/mariadb.conf.d/50-server.cnf: bind-address = 0.0.0.0\nsudo systemctl restart mariadb\nmysqldump --single-transaction appdb > appdb.sql', what: 'Listen on the network; consistent logical dump.', why: 'Debian binds to 127.0.0.1 by default.', expected: '' },
      ],
    },
    {
      id: 'windows',
      platform: 'Microsoft SQL Server (Windows Server)',
      summary: 'Logins (server level) map to users (database level); Windows authentication or SQL logins; TCP 1433 enabled in SQL Server Configuration Manager; backups with BACKUP DATABASE.',
      prerequisites: ['SQL Server installed with a named or default instance.'],
      steps: [
        { title: 'Login, user, role and backup', command: "CREATE LOGIN appuser WITH PASSWORD = 'secret';\nUSE appdb; CREATE USER appuser FOR LOGIN appuser;\nALTER ROLE db_datareader ADD MEMBER appuser;\nBACKUP DATABASE appdb TO DISK = 'D:\\Backup\\appdb.bak';", what: 'Run in SQL Server Management Studio or sqlcmd.', why: 'Same layers: who may connect, what they may do, a tested backup.', expected: '' },
      ],
    },
  ],

  configIntro: `
Configuration is in three places:
- **/etc/postgresql/15/main/postgresql.conf** (and **conf.d/*.conf**, and **postgresql.auto.conf** in the data directory, written by ALTER SYSTEM): how the server runs.
- **/etc/postgresql/15/main/pg_hba.conf**: who may connect and how they authenticate.
- **Inside the database**: roles, databases, ownership and GRANTs, changed with SQL and stored in the data directory.

### Where a setting comes from
\`SHOW listen_addresses\` gives the value in effect; \`SELECT name, setting, source, sourcefile, sourceline, pending_restart FROM pg_settings\` tells where it was set and whether a changed file still waits for a restart. The order is postgresql.conf, then conf.d (alphabetical), then postgresql.auto.conf: the last one wins, so an ALTER SYSTEM value overrides a file edit.

:::practice
Q: You set listen_addresses in postgresql.conf, but SHOW listen_addresses after a restart still shows the old value. Where else could it be set?
A: In a file in **conf.d/** or in **postgresql.auto.conf** (ALTER SYSTEM), which are read later and win. pg_settings.sourcefile tells which one.
Q: Which SQL command writes a setting into postgresql.auto.conf?
A: \`ALTER SYSTEM SET name = value;\` (then reload or restart, depending on the setting).
:::

`,

  configFiles: [
    { platform: 'PostgreSQL on Debian / Ubuntu', items: [
      { path: '/etc/postgresql/15/main/postgresql.conf', purpose: 'Server settings (listen_addresses, port, logging, memory, ssl).' },
      { path: '/etc/postgresql/15/main/conf.d/*.conf', purpose: 'Local settings that survive package updates.' },
      { path: '/etc/postgresql/15/main/pg_hba.conf', purpose: 'Client authentication rules (reload to apply).' },
      { path: '/var/lib/postgresql/15/main/postgresql.auto.conf', purpose: 'ALTER SYSTEM settings (do not edit by hand).' },
      { path: '/var/log/postgresql/postgresql-15-main.log', purpose: 'Server log.' },
      { path: '~/.pgpass (clients)', purpose: 'Saved passwords for libpq clients, mode 0600.' },
    ] },
    { platform: 'RHEL / MariaDB / SQL Server', items: [
      { path: '/var/lib/pgsql/data/{postgresql.conf,pg_hba.conf}', purpose: 'RHEL: configuration inside the data directory.' },
      { path: '/etc/mysql/mariadb.conf.d/50-server.cnf', purpose: 'MariaDB: bind-address, port, datadir.' },
      { path: 'SQL Server Configuration Manager', purpose: 'SQL Server: network protocols (TCP 1433), service account.' },
    ] },
  ],

  directives: [
    { name: 'listen_addresses', compiledDefault: 'localhost', recommended: "'*' or the server's address, plus a firewall", explanation: 'Addresses the server listens on. Restart required.', security: 'Do not expose 5432 beyond the networks that need it.' },
    { name: 'port', compiledDefault: '5432', recommended: '5432', explanation: 'TCP port and socket name. Restart required.', security: 'A different port is not a security measure.' },
    { name: 'max_connections', compiledDefault: '100', recommended: 'Sized to the applications (use a pooler for many clients)', explanation: 'Maximum concurrent sessions. Restart required.', security: 'superuser_reserved_connections keeps slots for administrators.' },
    { name: 'password_encryption', compiledDefault: 'scram-sha-256', recommended: 'scram-sha-256', explanation: 'How new passwords are stored.', security: 'md5 hashes are weaker and cannot be used by scram-sha-256 lines.' },
    { name: 'ssl', compiledDefault: 'off (Debian: on with the snakeoil certificate)', recommended: 'on, with a certificate from your CA', explanation: 'TLS for client connections.', security: 'Use hostssl lines to require it.' },
    { name: 'log_connections / log_disconnections', compiledDefault: 'off', recommended: 'on (audit)', explanation: 'Log every connection and its authentication.', security: 'Needed to investigate who connected when.' },
    { name: 'log_line_prefix', compiledDefault: "'%m [%p] '", recommended: "Debian: '%m [%p] %q%u@%d '", explanation: 'What each log line starts with (time, pid, user@database).', security: '' },
    { name: 'pg_hba.conf METHOD', compiledDefault: 'peer (local), scram-sha-256 (host) on Debian', recommended: 'peer for local admin, scram-sha-256 for clients', explanation: 'How a matching connection authenticates.', security: 'Never trust on host lines; avoid md5.' },
  ],

  operateIntro: `
### Setting up a database for a new application
The same recipe every time (Lab 7 walks through it):
1. An **owner role** without LOGIN and the **database** owned by it; \`REVOKE CONNECT … FROM PUBLIC\`.
2. The **schema**, created by (or handed over to) the owner.
3. An **application role** with LOGIN and a SCRAM password, CONNECT, the table privileges it needs, and **default privileges** for future tables.
4. **Network**: listen_addresses (restart), the firewall for the application servers only, a narrow **pg_hba.conf** line (reload).
5. A **backup role** (pg_read_all_data), a scheduled pg_dump, and a **restore test**.

:::practice
Q: Why should the application not log in as the role that owns its tables?
A: The owner can do everything with the tables (drop, alter, grant): a bug or a stolen password would have all of that power. The application role gets only the privileges it uses.
Q: Which statement makes tables created later by the owner readable by the application?
A: \`ALTER DEFAULT PRIVILEGES FOR ROLE owner GRANT SELECT … ON TABLES TO app;\`
:::

### Backups and restore drills
- Schedule \`pg_dump -Fc\` with a read-only role; keep \`pg_dumpall --globals-only\` for the roles.
- Monitor the **age** of the newest dump and the job's exit status (a failed job leaves yesterday's file in place).
- Practise restores: list (\`pg_restore -l\`), restore into a scratch database, restore one table's rows (\`--data-only -t\`) when only some data was lost.

:::practice
Q: Only the rows of one table were deleted by mistake; other tables changed normally since the backup. How do you restore without losing the other changes?
A: Restore **only that table's data** from the archive: \`pg_restore -d DB --data-only -t TABLE dumpfile\`, not the whole database.
Q: The backup file exists every morning. Why is that not enough to know the backup works?
A: A failed job can leave an **old** file in place; check its age and the job's result, and test restores.
:::

### Watching the server
Check regularly: \`pg_lsclusters\` / \`pg_isready\`, sessions in \`pg_stat_activity\` against max_connections, the log for FATAL lines (failed logins, refused hosts), disk space of the data directory, and the last backup.

:::practice
Q: Which query lists the current sessions with their user, database and client address?
A: \`SELECT pid, usename, datname, client_addr, state FROM pg_stat_activity;\`
Q: Where do you find why a client's login failed, beyond the client's one-line message?
A: In the **server log** (/var/log/postgresql/postgresql-15-main.log): the FATAL line and its DETAIL with the matched pg_hba.conf line.
:::

`,
  troubleshootingIntro: `
### Follow the connection, then the statement
1. **Is it running and listening?** \`pg_lsclusters\`, \`ss -tlnp | grep 5432\`, from the client \`pg_isready -h SERVER\`. Down: read the log (data directory, configuration). Listening on 127.0.0.1 only: listen_addresses (restart).
2. **Does pg_hba.conf match?** "no pg_hba.conf entry for host …": add a narrow line and reload.
3. **Does authentication succeed?** "password authentication failed": the server log's DETAIL tells wrong password, unknown role or an MD5 hash.
4. **Role and database?** "not permitted to log in", "permission denied for database": LOGIN and CONNECT.
5. **The statement?** "permission denied for table": \\dp and GRANT. Wrong or missing rows: the data, not the server; restore selectively.

Read the **server log** at every step: it says which pg_hba.conf line matched and why authentication failed.

:::practice
Q: A client gets "Connection refused" while psql on the server works. What do you check first?
A: Where the server listens: \`ss -tlnp | grep 5432\` and \`SHOW listen_addresses\` (localhost only by default).
Q: A client gets "password authentication failed" with the right password. Where is the reason?
A: In the **server log**: the DETAIL line (for example "does not have a valid SCRAM secret").
:::

`,

  errorMap: [
    { message: 'connection to server at "db01.corp.lab" (10.0.20.35), port 5432 failed: Connection refused', layer: 'Network / listening', meaning: 'Nothing listens on that address and port.', firstCheck: 'pg_lsclusters; ss -tlnp | grep 5432; SHOW listen_addresses' },
    { message: '… port 5432 failed: Connection timed out', layer: 'Firewall / path', meaning: 'No answer at all.', firstCheck: 'nft list ruleset on the server; routing' },
    { message: 'connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: No such file or directory', layer: 'Service (local)', meaning: 'The server is not running (or uses another port/socket directory).', firstCheck: 'pg_lsclusters; systemctl status postgresql' },
    { message: 'FATAL:  no pg_hba.conf entry for host "IP", user "U", database "D", SSL encryption', layer: 'pg_hba.conf', meaning: 'No line matches this client, user and database.', firstCheck: 'pg_hba.conf / pg_hba_file_rules; reload after editing' },
    { message: 'FATAL:  password authentication failed for user "U"', layer: 'Authentication', meaning: 'Wrong password, unknown role, MD5 hash or expired password.', firstCheck: 'The DETAIL line in the server log; ~/.pgpass' },
    { message: 'FATAL:  Peer authentication failed for user "postgres"', layer: 'Authentication (local)', meaning: 'The OS user is not the database role.', firstCheck: 'sudo -u postgres psql' },
    { message: 'FATAL:  role "U" is not permitted to log in', layer: 'Role', meaning: 'The role lacks LOGIN.', firstCheck: '\\du; ALTER ROLE U LOGIN' },
    { message: 'FATAL:  permission denied for database "D" / DETAIL: User does not have CONNECT privilege.', layer: 'Database privilege', meaning: 'CONNECT was not granted (or revoked from PUBLIC).', firstCheck: '\\l; GRANT CONNECT ON DATABASE' },
    { message: 'FATAL:  database "D" does not exist', layer: 'Client parameters', meaning: 'Wrong database name (the default is the user name).', firstCheck: '\\l; psql -d' },
    { message: 'ERROR:  permission denied for table T', layer: 'Table privilege', meaning: 'The role lacks the privilege for this statement.', firstCheck: '\\dp T; GRANT' },
    { message: 'FATAL:  data directory "…" has wrong ownership', layer: 'Server start', meaning: 'The data directory is not owned by postgres.', firstCheck: 'ls -ld; chown -R postgres:postgres' },
    { message: 'LOG:  parameter "listen_addresses" cannot be changed without restarting the server', layer: 'Configuration', meaning: 'A reload cannot apply this setting.', firstCheck: 'systemctl restart postgresql' },
  ],

  scenarioIds: ['db-listen-default', 'db-hba-office', 'db-missing-grant', 'db-md5-scram', 'db-backup-grant', 'db-datadir-owner', 'db-restore-orders'],
  assessmentId: 'database',
  references: [
    { title: 'PostgreSQL 15 documentation: Server Setup and Operation', url: 'https://www.postgresql.org/docs/15/runtime.html' },
    { title: 'PostgreSQL 15: The pg_hba.conf File', url: 'https://www.postgresql.org/docs/15/auth-pg-hba-conf.html' },
    { title: 'PostgreSQL 15: Database Roles and Privileges', url: 'https://www.postgresql.org/docs/15/user-manag.html' },
    { title: 'PostgreSQL 15: Backup and Restore', url: 'https://www.postgresql.org/docs/15/backup.html' },
    { title: 'Debian Wiki: PostgreSQL', url: 'https://wiki.debian.org/PostgreSql' },
    { title: 'MariaDB Knowledge Base: Configuring MariaDB for Remote Client Access', url: 'https://mariadb.com/kb/en/configuring-mariadb-for-remote-client-access/' },
    { title: 'Microsoft Learn: Create a login (SQL Server)', url: 'https://learn.microsoft.com/sql/relational-databases/security/authentication-access/create-a-login' },
  ],
  guide: DATABASE_GUIDE,
  objectives: ['N10-009:1.4', 'N10-009:5.3'],
};

// --- Primer -------------------------------------------------------------------------

export const DATABASE_PRIMER: Primer = {
  oneLiner: 'A **database server** keeps shared data in tables and lets applications read and change it over the network, after they **connect**, **log in** as a role and are **allowed** by the privileges an administrator granted.',
  analogy: `
A company archive with a security desk. The building has one entrance (**listen_addresses** and port 5432); a guest list at the desk says who may come in from where and how they prove who they are (**pg_hba.conf**: the first line that fits your name and where you come from decides). Inside, each filing cabinet (**table**) has an owner, who decides who else may open which drawer (**GRANT**: read, add, change, remove).

The night shift photocopies the archive (**pg_dump**); a copy you never tried to read back may be blank. And the archive itself is in a locked room that must belong to the archive staff (the **data directory** owned by postgres), or the doors do not open in the morning.`,
  ideas: [
    {
      title: 'Cluster, databases, tables, roles',
      explain: 'One server (cluster) holds several databases; each has tables; roles are the accounts, some can log in.',
      example: 'On db01, `pg_lsclusters` shows 15/main; `sudo -u postgres psql -c "\\l"` lists inventory; in it, `\\dt` lists items, orders, suppliers; `\\du` lists webapp, backup, invowner.',
    },
    {
      title: 'Connecting: listen, pg_hba.conf, password',
      explain: 'The server must listen on the network address, a pg_hba.conf line must match the client, and the role must authenticate.',
      example: 'srv01 → db01:5432 matches `host inventory webapp 10.0.20.10/32 scram-sha-256`; the password comes from srv01\'s /root/.pgpass.',
    },
    {
      title: 'Owners and GRANTs',
      explain: 'Every table has an owner; everybody else needs privileges granted per table (or by default privileges for future tables).',
      example: '`\\dp` shows `webapp=arwd/invowner` on items: webapp may SELECT (r), INSERT (a), UPDATE (w), DELETE (d).',
    },
    {
      title: 'Reload or restart',
      explain: 'pg_hba.conf and most settings need a reload; listen_addresses, port and max_connections need a restart.',
      example: '`systemctl reload postgresql` after editing pg_hba.conf; `systemctl restart postgresql` after changing listen_addresses.',
    },
    {
      title: 'Backups you have restored',
      explain: 'pg_dump makes a consistent copy of one database; pg_restore lists it and restores all or part of it.',
      example: '`pg_restore -l /var/backups/postgresql/inventory.dump` lists the tables; `pg_restore -d inventory --data-only -t orders …` brings back one table\'s rows.',
    },
  ],
  walkthrough: {
    title: 'The application on srv01 counts the items',
    steps: [
      { label: 'Connect', detail: 'psql on srv01 opens TCP to db01.corp.lab:5432: PostgreSQL listens on all addresses (listen_addresses = \'*\') and the firewall allows 5432.' },
      { label: 'Match pg_hba.conf', detail: 'Client 10.0.20.10, user webapp, database inventory: the line `host inventory webapp 10.0.20.10/32 scram-sha-256` matches first.' },
      { label: 'Authenticate', detail: 'SCRAM exchange with the password from /root/.pgpass; the log says "connection authorized: user=webapp database=inventory".' },
      { label: 'Check LOGIN and CONNECT', detail: 'webapp has LOGIN and CONNECT on inventory, so a backend process starts for this session.' },
      { label: 'Run the query', detail: 'SELECT count(*) FROM items: webapp has SELECT on items, so the answer is 6.' },
    ],
  },
  misconceptions: [
    { myth: 'If the database runs, clients on the network can reach it.', truth: 'By default PostgreSQL listens on localhost only: set listen_addresses and restart.' },
    { myth: '"password authentication failed" always means a wrong password.', truth: 'It can also be an unknown role or an MD5-stored password: the server log\'s DETAIL says which.' },
    { myth: 'Granting SELECT on the tables covers future tables too.', truth: 'Grants are per table; use ALTER DEFAULT PRIVILEGES (or pg_read_all_data for backups).' },
    { myth: 'A backup file that exists is a working backup.', truth: 'It may be old or unreadable: check its age and test a restore.' },
  ],
  checks: [
    { q: 'Which file decides whether a client may connect, and how it authenticates?', a: 'pg_hba.conf (first matching line).' },
    { q: 'Which setting makes PostgreSQL listen on the network, and what does changing it require?', a: 'listen_addresses; a restart.' },
    { q: 'How do you open psql as the superuser on Debian?', a: 'sudo -u postgres psql (peer authentication over the Unix socket).' },
    { q: 'Which tool lists what is inside a custom-format backup?', a: 'pg_restore -l FILE.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const DATABASE_ASSESSMENT: Assessment = {
  id: 'database',
  title: 'Database knowledge check',
  questions: [
    {
      id: 'db-q-order',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/database/internals'],
      prompt: 'Order the checks a new PostgreSQL connection passes before its first query runs.',
      items: ['TCP connection to listen_addresses:5432', 'First matching pg_hba.conf line', 'Authentication (password or peer)', 'The role has LOGIN', 'CONNECT privilege on the database'],
      concepts: ['db.access'],
      explanation: 'Each step fails with its own message; the server log adds the reason.',
    },
    {
      id: 'db-q-listen',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/database/internals', 'lesson/database/config'],
      prompt: 'After a fresh install, psql works on the server but every other host gets "Connection refused". What is the most likely cause?',
      options: [
        { text: 'listen_addresses is still the default (localhost)', correct: true },
        { text: 'pg_hba.conf has no line for the clients', misconception: 'That gives a FATAL "no pg_hba.conf entry", not a refused TCP connection.' },
        { text: 'The clients use the wrong password', misconception: 'Authentication is never reached when TCP is refused.' },
        { text: 'max_connections is too low', misconception: 'That gives "too many clients", after connecting.' },
      ],
      concepts: ['db.access'],
      explanation: 'PostgreSQL listens on localhost only until listen_addresses is changed (and the server restarted).',
    },
    {
      id: 'db-q-hba-order',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/database/internals'],
      prompt: 'pg_hba.conf contains, in this order: "host all all 10.0.0.0/16 reject" and "host inventory report 10.0.10.0/24 scram-sha-256". report connects from 10.0.10.25. What happens?',
      options: [
        { text: 'The connection is rejected: the first matching line decides', correct: true },
        { text: 'report gets a password prompt: the more specific line wins', misconception: 'PostgreSQL does not pick the most specific line; it stops at the first match.' },
        { text: 'Both lines are combined', misconception: 'Only one line is used.' },
      ],
      concepts: ['db.access'],
      explanation: 'Put specific allow lines above broad reject lines.',
    },
    {
      id: 'db-q-reload',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/database/internals', 'lesson/database/config'],
      prompt: 'Which changes take effect with a reload (no restart)? (choose all that apply)',
      options: [
        { text: 'A new line in pg_hba.conf', correct: true },
        { text: 'log_connections = on', correct: true },
        { text: 'listen_addresses = \'*\'', misconception: 'Only read at start: needs a restart.' },
        { text: 'max_connections = 200', misconception: 'Only read at start: needs a restart.' },
      ],
      concepts: ['db.admin'],
      explanation: 'pg_settings.context tells: postmaster settings need a restart, sighup settings a reload.',
    },
    {
      id: 'db-q-grant',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/database/internals', 'lesson/database/operate'],
      prompt: 'An application role can read items and orders, but gets "permission denied for table invoices" on a table added in today\'s release. Which fix also prevents the next release from hitting the same error?',
      options: [
        { text: 'GRANT the privileges on invoices and ALTER DEFAULT PRIVILEGES FOR ROLE owner … TO app', correct: true },
        { text: 'Make the application role a superuser', misconception: 'Far too much power for an application.' },
        { text: 'Let the application log in as the owner', misconception: 'Gives it the right to drop and alter every table.' },
        { text: 'GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC', misconception: 'Every role, now and in the future, would get every privilege.' },
      ],
      concepts: ['db.admin'],
      explanation: 'Privileges are per object; default privileges cover objects the owner creates later.',
    },
    {
      id: 'db-q-scram',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/database/internals'],
      prompt: 'A role imported from an old server cannot log in through a scram-sha-256 line; the log says "User \\"billing\\" does not have a valid SCRAM secret." What is the right fix?',
      options: [
        { text: 'Set the role\'s password again so it is stored as a SCRAM verifier', correct: true },
        { text: 'Change the pg_hba.conf line to md5', misconception: 'Works, but weakens authentication for that role.' },
        { text: 'Change the line to trust', misconception: 'Removes authentication completely.' },
      ],
      concepts: ['db.access'],
      explanation: 'The MD5 hash cannot be used for SCRAM; re-hash the password with password_encryption = scram-sha-256.',
    },
    {
      id: 'db-q-backup',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/database/internals', 'lesson/database/operate'],
      prompt: 'Which statements about pg_dump are true? (choose all that apply)',
      options: [
        { text: 'It makes a consistent copy of one database while it is in use', correct: true },
        { text: 'It needs read access to every table it dumps', correct: true },
        { text: 'It includes the cluster\'s roles and their passwords', misconception: 'Roles are cluster-wide: pg_dumpall --globals-only.' },
        { text: 'It allows recovery to any point in time', misconception: 'Point-in-time recovery needs a base backup plus archived WAL.' },
      ],
      concepts: ['db.admin'],
      explanation: 'Logical dumps restore the state at dump time; roles and PITR need other tools.',
    },
    {
      id: 'db-q-datadir',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/database/internals'],
      prompt: 'Which operating-system user must own the PostgreSQL data directory on Debian?',
      accept: ['postgres'],
      placeholder: 'user name',
      concepts: ['db.admin'],
      explanation: 'The server runs as postgres and refuses a data directory owned by anyone else.',
    },
    {
      id: 'db-q-port',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/database/what', 'lesson/database/internals'],
      prompt: 'Which TCP port does PostgreSQL use by default?',
      accept: ['5432'],
      placeholder: 'port',
      concepts: ['db.access'],
      explanation: 'PostgreSQL 5432, MySQL/MariaDB 3306, SQL Server 1433.',
    },
  ],
};
