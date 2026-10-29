// Reference entries for databases: psql, pg_dump/pg_restore, the Debian
// cluster tools, PostgreSQL's configuration files, and the procedures for
// giving an application access and restoring lost data.

import type { CommandRef, FileRef, Procedure } from '../types';

export const DB_COMMAND_REFS: CommandRef[] = [
  {
    id: 'psql', name: 'psql', platform: 'Linux', category: 'Database', simulator: 'psql',
    purpose: 'PostgreSQL\'s command-line client: connect to a server as a role, run SQL, and inspect roles, databases and privileges with backslash meta-commands.',
    syntax: 'psql [-h HOST] [-p PORT] [-U ROLE] [-d DB] [-c "SQL" | -f FILE] [-l] [-x] [-A -t] [-v ON_ERROR_STOP=1]',
    args: [
      { arg: '-h HOST', meaning: 'Connect over TCP to HOST; without -h psql uses the local Unix socket (pg_hba.conf "local" lines, peer authentication)' },
      { arg: '-U ROLE / -d DB', meaning: 'Role to log in as and database to open (both default to the operating-system user name)' },
      { arg: '-c "SQL" / -f FILE', meaning: 'Run one command or a script, then exit' },
      { arg: '-l', meaning: 'List databases with owner and access privileges' },
      { arg: '-x / -A -t', meaning: 'Expanded output (one column per line) / unaligned, tuples only (for scripts)' },
      { arg: '-v ON_ERROR_STOP=1', meaning: 'Stop a script at the first error (exit code 3)' },
      { arg: '\\l \\du \\dt \\d T \\dp \\c DB \\conninfo \\password', meaning: 'Interactive meta-commands: databases, roles, tables, table columns, privileges, switch database, current connection, change a password' },
    ],
    example: { command: 'psql -h db01.corp.lab -U webapp -d inventory -c "SELECT count(*) FROM items"', output: 'Password for user webapp: \n count \n-------\n     6\n(1 row)\n' },
    interpretation: 'The first error tells which layer refused: "Connection refused" (nothing listens: listen_addresses, service down), "no pg_hba.conf entry" (no matching line), "password authentication failed" (the server log\'s DETAIL says why), "permission denied for database" (CONNECT), "permission denied for table" (GRANT).',
    limitations: 'The simulator supports the options and meta-commands above and a subset of SQL (SELECT/INSERT/UPDATE/DELETE without joins, CREATE/ALTER/DROP ROLE, DATABASE and TABLE, GRANT/REVOKE, ALTER DEFAULT PRIVILEGES, ALTER SYSTEM, SHOW, catalog views). No transactions that can be rolled back.',
    errors: [
      { message: 'psql: error: connection to server at "db01.corp.lab" (10.0.20.35), port 5432 failed: Connection refused', meaning: 'Nothing listens on that address: listen_addresses = localhost, or the server is down.' },
      { message: 'FATAL:  no pg_hba.conf entry for host "10.0.20.10", user "webapp", database "inventory", no encryption', meaning: 'No pg_hba.conf line matches this connection (with sslmode=prefer psql prints it twice: SSL and no encryption).' },
      { message: 'FATAL:  password authentication failed for user "webapp"', meaning: 'Wrong password, unknown role or an MD5 hash where the line requires scram-sha-256: the DETAIL line in the server log tells which.' },
      { message: 'FATAL:  Peer authentication failed for user "postgres"', meaning: 'A "local … peer" line: the operating-system user must have the role\'s name (use sudo -u postgres psql).' },
      { message: 'FATAL:  permission denied for database "inventory"', meaning: 'The role lacks CONNECT on that database.' },
      { message: 'ERROR:  permission denied for table orders', meaning: 'The role lacks the privilege (SELECT, INSERT …) on that table.' },
    ],
    permissions: 'Any user; what they may do depends on the PostgreSQL role. sudo -u postgres psql gives the superuser through peer authentication.',
    risks: 'SQL runs immediately: a DELETE or UPDATE without WHERE changes every row. A password in a connection string ends up in the shell history; use the prompt or ~/.pgpass (mode 0600).',
    compat: 'PostgreSQL client 9.x to 17 (package postgresql-client). MySQL: mysql; SQL Server: sqlcmd.',
    services: ['Database', 'PostgreSQL'], protocols: ['PGSQL', 'TCP'], symptoms: ['Cannot connect to database', 'Permission denied', 'Password authentication failed'],
  },
  {
    id: 'pg_dump', name: 'pg_dump / pg_restore / pg_dumpall', platform: 'Linux', category: 'Database', simulator: 'pg_dump',
    purpose: 'Logical backups: pg_dump writes one database as SQL or as a custom-format archive; pg_restore lists, restores all or selected objects from that archive; pg_dumpall -g saves roles and other cluster-wide objects.',
    syntax: 'pg_dump [-h HOST] [-U ROLE] [-Fc] [-t TABLE] [-f FILE] DB | pg_restore -l FILE | pg_restore -d DB [-t TABLE] [--data-only] [--clean] FILE | pg_dumpall -g [-f FILE]',
    args: [
      { arg: '-Fc', meaning: 'Custom format: compressed archive for pg_restore (selective restore); default is a plain SQL script for psql -f' },
      { arg: '-f FILE', meaning: 'Write to FILE instead of standard output' },
      { arg: '-t TABLE', meaning: 'Only this table (pg_dump and pg_restore)' },
      { arg: 'pg_restore -l', meaning: 'List the archive\'s contents (table of contents) without restoring' },
      { arg: 'pg_restore -d DB --data-only', meaning: 'Load only rows into existing tables' },
      { arg: 'pg_restore --clean', meaning: 'Drop each object before recreating it' },
      { arg: 'pg_dumpall -g', meaning: 'Roles (with password hashes) and tablespaces: pg_dump does not include them' },
    ],
    example: { command: 'pg_restore -l /var/backups/postgresql/inventory.dump', output: ';\n; Archive created at 2026-10-19 02:15:01 UTC\n;     dbname: inventory\n;     TOC Entries: 9\n;     Format: CUSTOM\n;     Dumped from database version: 15.8 (Debian 15.8-0+deb12u1)\n;\n215; 1259 16390 TABLE public items invowner\n216; 1259 16396 TABLE public orders invowner\n217; 1259 16402 TABLE public suppliers invowner\n3329; 0 16390 TABLE DATA public items invowner\n3330; 0 16396 TABLE DATA public orders invowner\n3331; 0 16402 TABLE DATA public suppliers invowner' },
    interpretation: 'A dump is consistent: it shows the database as it was at the moment pg_dump started, even while the application writes. Restore into a scratch database first, compare, then copy back only what was lost.',
    limitations: 'Simulated: plain and custom format, -t, -f, -l, -d, --data-only, --clean, pg_dumpall -g. No directory format, -j parallel jobs or --create.',
    errors: [
      { message: 'pg_dump: error: query failed: ERROR:  permission denied for table suppliers', meaning: 'The backup role cannot read every table (grant pg_read_all_data).' },
      { message: 'pg_restore: error: input file does not appear to be a valid archive', meaning: 'A plain SQL dump: restore it with psql -f.' },
      { message: 'pg_restore: error: could not execute query: ERROR:  duplicate key value violates unique constraint', meaning: '--data-only into a table that still has those rows: restore only the missing rows, or into a scratch database.' },
    ],
    permissions: 'pg_dump: a role that can read every object (owner, superuser or pg_read_all_data). pg_restore: a role that may create or write those objects.',
    risks: 'pg_restore --clean overwrites everything changed since the backup. Dump files contain all the data: protect them (0640, group postgres).',
    compat: 'Dump with the newer version\'s pg_dump when upgrading; pg_restore cannot read archives from a newer pg_dump. MySQL: mysqldump; SQL Server: BACKUP DATABASE.',
    services: ['Database', 'PostgreSQL', 'Backup'], protocols: ['PGSQL'], symptoms: ['Data deleted', 'Backup failed'],
  },
  {
    id: 'pg_ctlcluster', name: 'pg_lsclusters / pg_ctlcluster / pg_isready', platform: 'Linux', category: 'Database', simulator: 'pg_ctlcluster',
    purpose: 'Debian\'s cluster tools: list clusters with status, port, data directory and log; start, stop, reload or restart one; pg_isready checks from anywhere whether a server accepts connections.',
    syntax: 'pg_lsclusters | pg_ctlcluster VERSION NAME start|stop|reload|restart|status | pg_isready [-h HOST] [-p PORT]',
    args: [
      { arg: 'pg_lsclusters', meaning: 'Ver Cluster Port Status Owner Data directory Log file' },
      { arg: 'pg_ctlcluster 15 main reload', meaning: 'Re-read configuration (same as systemctl reload postgresql@15-main)' },
      { arg: 'pg_ctlcluster 15 main restart', meaning: 'Needed for listen_addresses, port, max_connections, shared_buffers' },
      { arg: 'pg_isready -h HOST', meaning: 'Exit 0 "accepting connections", 1 "rejecting", 2 "no response"; needs no login' },
    ],
    example: { command: 'pg_lsclusters', output: 'Ver Cluster Port Status Owner    Data directory              Log file\n15  main    5432 online postgres /var/lib/postgresql/15/main /var/log/postgresql/postgresql-15-main.log' },
    interpretation: '"down" means the server is not running: the log file in the last column says why. "online" plus a failing client points at listen_addresses, the firewall or pg_hba.conf.',
    limitations: 'Simulated: pg_lsclusters, pg_ctlcluster start/stop/reload/restart/status, pg_isready -h/-p. No pg_createcluster, pg_dropcluster or pg_upgradecluster.',
    errors: [
      { message: 'Error: /usr/lib/postgresql/15/bin/pg_ctl … exited with status 1: … FATAL:  data directory "/var/lib/postgresql/15/main" has wrong ownership', meaning: 'The data directory must belong to postgres (chown -R postgres:postgres).' },
      { message: 'db01.corp.lab:5432 - no response', meaning: 'pg_isready got no TCP answer: server down, listen_addresses, firewall.' },
    ],
    permissions: 'pg_lsclusters, pg_isready: any user. pg_ctlcluster: root or postgres.',
    risks: 'stop and restart disconnect every session and roll back open transactions.',
    compat: 'Debian/Ubuntu (postgresql-common). RHEL: systemctl … postgresql and pg_ctl -D /var/lib/pgsql/data.',
    services: ['Database', 'PostgreSQL'], protocols: ['PGSQL'], symptoms: ['Database down', 'Cannot connect to database'],
  },
];

export const DB_FILE_REFS: FileRef[] = [
  {
    id: 'file:pg-hba-conf', path: '/etc/postgresql/15/main/pg_hba.conf', platform: 'PostgreSQL 15 (Debian / Ubuntu; RHEL: /var/lib/pgsql/data)', kind: 'config',
    services: ['Database', 'PostgreSQL'],
    purpose: 'Host-based authentication: which connections are allowed (type, database, role, client address) and how they must authenticate.',
    contents: 'One rule per line: TYPE DATABASE USER [ADDRESS] METHOD. TYPE is local (Unix socket), host (TCP, with or without SSL), hostssl or hostnossl. DATABASE and USER may be all, a name, a list or +group. ADDRESS is a CIDR (10.0.20.10/32). METHOD: peer (OS user = role, local only), scram-sha-256 (password, the current standard), md5 (also accepts SCRAM hashes), trust (no password: never on a network line), reject. Lines are checked top to bottom; the first line that matches type, database, user and address decides, even if it rejects.',
    accessed: 'At start and on reload (systemctl reload postgresql, SELECT pg_reload_conf()). A line with a syntax error makes the reload keep the old rules (logged).',
    permissions: 'postgres:postgres 640.',
    problems: 'Forgetting to reload; a broad line above a narrow one wins; md5-hashed passwords failing on scram-sha-256 lines ("does not have a valid SCRAM secret"). Check the loaded rules with SELECT * FROM pg_hba_file_rules.',
    example: '# TYPE  DATABASE   USER     ADDRESS          METHOD\nlocal   all        postgres                  peer\nlocal   all        all                       peer\nhost    all        all      127.0.0.1/32     scram-sha-256\nhost    inventory  webapp   10.0.20.10/32    scram-sha-256',
    relatedCommands: ['psql', 'pg_ctlcluster'],
  },
  {
    id: 'file:postgresql-conf', path: '/etc/postgresql/15/main/postgresql.conf, conf.d/*.conf, postgresql.auto.conf', platform: 'PostgreSQL 15 (Debian / Ubuntu; RHEL: /var/lib/pgsql/data)', kind: 'config',
    services: ['Database', 'PostgreSQL'],
    purpose: 'Server settings: where the data is, which addresses and port it listens on, how many connections, memory, logging and SSL.',
    contents: 'data_directory, hba_file, listen_addresses (default localhost), port (5432), max_connections (100), shared_buffers, ssl/ssl_cert_file/ssl_key_file, password_encryption (scram-sha-256), log_connections, log_line_prefix, include_dir = \'conf.d\'. Later lines win: conf.d files are read after postgresql.conf, and postgresql.auto.conf (written by ALTER SYSTEM) is read last.',
    accessed: 'At start; reloadable settings (sighup context) on reload. Settings with context postmaster (listen_addresses, port, max_connections, shared_buffers) need a restart; SELECT name, setting, pending_restart FROM pg_settings shows which are waiting.',
    permissions: 'postgres:postgres 644. postgresql.auto.conf lives in the data directory and must not be edited by hand.',
    problems: 'A setting changed but not applied (reload instead of restart); a value overridden by a later file or by ALTER SYSTEM; a typo stops the server at the next start (check the log).',
    example: "# /etc/postgresql/15/main/conf.d/listen.conf\nlisten_addresses = '*'\nlog_connections = on",
    relatedCommands: ['psql', 'pg_ctlcluster', 'ss'],
  },
];

export const DB_PROCEDURES: Procedure[] = [
  {
    id: 'proc:db-new-application', title: 'Give an application its own database and role', platform: 'PostgreSQL 15 (Debian)',
    services: ['Database', 'PostgreSQL'],
    symptoms: ['New application', 'Cannot connect to database'],
    purpose: 'Create a database owned by a NOLOGIN role, a login role with only the privileges the application needs, and a narrow network path to it.',
    steps: [
      { title: 'Owner role and database', command: "sudo -u postgres psql -c \"CREATE ROLE helpdesk_owner NOLOGIN\"\nsudo -u postgres psql -c \"CREATE DATABASE helpdesk OWNER helpdesk_owner\"", why: 'Objects belong to a role nobody logs in as; the application cannot drop or alter its own tables.' },
      { title: 'Load the schema, then hand the tables to the owner', command: 'sudo -u postgres psql -d helpdesk -v ON_ERROR_STOP=1 -f /tmp/helpdesk-schema.sql\nsudo -u postgres psql -d helpdesk -c "ALTER TABLE tickets OWNER TO helpdesk_owner"', why: 'Tables created by postgres belong to postgres; the owner role should own them.' },
      { title: 'Login role with only what it needs', command: "sudo -u postgres psql -c \"CREATE ROLE helpdesk_app LOGIN PASSWORD 'Helpdesk-db-26'\"\nsudo -u postgres psql -d helpdesk -c \"GRANT CONNECT ON DATABASE helpdesk TO helpdesk_app\" -c \"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO helpdesk_app\"", why: 'CONNECT and table privileges are separate; no DELETE, no ownership. ALTER DEFAULT PRIVILEGES covers tables added later.' },
      { title: 'Listen on the network (restart)', command: "echo \"listen_addresses = '*'\" > /etc/postgresql/15/main/conf.d/listen.conf\nsystemctl restart postgresql", why: 'listen_addresses is a postmaster setting: reload is not enough.' },
      { title: 'One pg_hba.conf line, then reload', command: 'echo "host helpdesk helpdesk_app 10.0.20.10/32 scram-sha-256" >> /etc/postgresql/15/main/pg_hba.conf\nsystemctl reload postgresql', why: 'Only that role, only that database, only from the application server, with a password.' },
      { title: 'Test from the client as the real role', command: 'psql -h db02.corp.lab -U helpdesk_app -d helpdesk -c "SELECT count(*) FROM tickets"', why: 'A test as postgres proves nothing about the application\'s access.' },
    ],
    risks: 'Restarting disconnects every session. A broad pg_hba.conf line (all all 0.0.0.0/0) or a trust method exposes every database.',
    verify: 'The query works from the application server as helpdesk_app, fails from other machines (no pg_hba.conf entry), and DELETE is refused.',
  },
  {
    id: 'proc:db-restore', title: 'Restore lost rows from a backup', platform: 'PostgreSQL 15 (Debian)',
    services: ['Database', 'PostgreSQL', 'Backup'],
    symptoms: ['Data deleted'],
    purpose: 'Bring back rows deleted by mistake without losing what was written since the backup.',
    steps: [
      { title: 'Find the backup and check what it contains', command: 'ls -l /var/backups/postgresql\npg_restore -l /var/backups/postgresql/inventory.dump', why: 'The archive time tells which changes it holds; the list shows the table is in it.' },
      { title: 'Restore into a scratch database', command: 'sudo -u postgres createdb inventory_restore\nsudo -u postgres pg_restore -d inventory_restore -t orders /var/backups/postgresql/inventory.dump', why: 'Never --clean over the live database: newer rows would be lost.' },
      { title: 'Compare', command: 'sudo -u postgres psql -d inventory_restore -c "SELECT * FROM orders WHERE id = 1004"\nsudo -u postgres psql -d inventory -c "SELECT * FROM orders WHERE id = 1004"', why: 'Confirm exactly which rows are missing.' },
      { title: 'Copy back only the missing rows', command: "sudo -u postgres psql -d inventory -c \"INSERT INTO orders VALUES (1004, 4, 30, 'Northwind', '2026-10-16')\"", why: 'The rest of the table keeps today\'s changes.' },
      { title: 'Clean up', command: 'sudo -u postgres dropdb inventory_restore', why: 'The scratch copy holds production data.' },
    ],
    risks: 'pg_restore --clean on the live database overwrites everything since the backup. A dump restored as postgres may change object ownership.',
    verify: 'The rows are back, the row count matches the backup plus newer rows, and the application role can read them.',
  },
];
