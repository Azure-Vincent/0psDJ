// Database server: db01 (10.0.20.35, Debian 12, switch port swp16) runs
// PostgreSQL 15 (cluster 15/main) with the inventory database used by the web
// application on srv01. Roles: invowner owns the schema (no login), webapp is
// the application's login, backup is used by the nightly pg_dump. srv01 reaches
// the database over TCP 5432 with scram-sha-256; administrators work on db01
// as the postgres operating-system user (peer authentication).

import { mkdir, writeFile } from '../fs';
import { CORP_ISSUING, issueServerCert, keyPem } from '../sim/pki';
import { archiveToCustom, dumpDatabase } from '../sim/pgsql';
import { DATA_DIR, initCluster, newRole, type PgCluster, type PgTable, storedHash } from '../sim/postgres';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { TIMESYNCD_CONF } from './krbLab';
import { installRsyslog } from './logLab';
import { fullchain, trustCorpRoot } from './pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const DB01_IP = '10.0.20.35';
export const DB_PASSWORDS: Record<string, string> = { webapp: 'Webapp-db-26', backup: 'Backup-db-26', alice: 'db01-alice' };

/** Debian's postgresql.conf for 15/main (comments shortened), with the lab's changes marked. */
export const DB01_POSTGRESQL_CONF = `# -----------------------------
# PostgreSQL configuration file
# -----------------------------
#
# This file consists of lines of the form:
#
#   name = value
#
# (The "=" is optional.)  Whitespace may be used.  Comments are introduced with
# "#" anywhere on a line.  Some parameters need a restart ("change requires
# restart"); the others are applied by a reload (systemctl reload, pg_ctlcluster
# 15 main reload, or SELECT pg_reload_conf()).

#------------------------------------------------------------------------------
# FILE LOCATIONS
#------------------------------------------------------------------------------

data_directory = '/var/lib/postgresql/15/main'		# use data in another directory
					# (change requires restart)
hba_file = '/etc/postgresql/15/main/pg_hba.conf'	# host-based authentication file
					# (change requires restart)
ident_file = '/etc/postgresql/15/main/pg_ident.conf'	# ident configuration file
					# (change requires restart)

# If external_pid_file is not explicitly set, no extra PID file is written.
external_pid_file = '/var/run/postgresql/15-main.pid'			# write an extra PID file
					# (change requires restart)

#------------------------------------------------------------------------------
# CONNECTIONS AND AUTHENTICATION
#------------------------------------------------------------------------------

# - Connection Settings -

# The web application on srv01 connects over the network (CHG-2501)
listen_addresses = '*'			# what IP address(es) to listen on;
					# comma-separated list of addresses;
					# defaults to 'localhost'; use '*' for all
					# (change requires restart)
port = 5432				# (change requires restart)
max_connections = 100			# (change requires restart)
#superuser_reserved_connections = 3	# (change requires restart)
unix_socket_directories = '/var/run/postgresql'	# comma-separated list of directories
					# (change requires restart)

# - Authentication -

#authentication_timeout = 1min		# 1s-600s
#password_encryption = scram-sha-256	# scram-sha-256 or md5

# - SSL -

ssl = on
#ssl_ca_file = ''
ssl_cert_file = '/etc/ssl/certs/db01.corp.lab.crt'
ssl_key_file = '/etc/ssl/private/db01.corp.lab.key'

#------------------------------------------------------------------------------
# RESOURCE USAGE (except WAL)
#------------------------------------------------------------------------------

shared_buffers = 128MB			# min 128kB
					# (change requires restart)
#work_mem = 4MB				# min 64kB
#maintenance_work_mem = 64MB		# min 1MB
dynamic_shared_memory_type = posix	# the default is usually the first option

#------------------------------------------------------------------------------
# WRITE-AHEAD LOG
#------------------------------------------------------------------------------

#wal_level = replica			# minimal, replica, or logical
					# (change requires restart)
max_wal_size = 1GB
min_wal_size = 80MB

#------------------------------------------------------------------------------
# REPORTING AND LOGGING
#------------------------------------------------------------------------------

#log_min_duration_statement = -1	# -1 is disabled, 0 logs all statements
# Who connected from where, for the audit (SEC-221)
log_connections = on
#log_disconnections = off
log_line_prefix = '%m [%p] %q%u@%d '		# special values:
					#   %m = timestamp with milliseconds
					#   %p = process ID, %u = user name
					#   %d = database name, %q = stop here in
					#        non-session processes
#log_statement = 'none'			# none, ddl, mod, all
log_timezone = 'Etc/UTC'

#------------------------------------------------------------------------------
# PROCESS TITLE
#------------------------------------------------------------------------------

cluster_name = '15/main'			# added to process titles if nonempty
					# (change requires restart)

#------------------------------------------------------------------------------
# AUTOVACUUM
#------------------------------------------------------------------------------

#autovacuum = on			# Enable autovacuum subprocess?  'on'
					# requires track_counts to also be on.

#------------------------------------------------------------------------------
# CLIENT CONNECTION DEFAULTS
#------------------------------------------------------------------------------

datestyle = 'iso, mdy'
timezone = 'Etc/UTC'
lc_messages = 'C.UTF-8'			# locale for system error message
					# strings
lc_monetary = 'C.UTF-8'			# locale for monetary formatting
lc_numeric = 'C.UTF-8'			# locale for number formatting
lc_time = 'C.UTF-8'				# locale for time formatting
default_text_search_config = 'pg_catalog.english'

#------------------------------------------------------------------------------
# CONFIG FILE INCLUDES
#------------------------------------------------------------------------------

# These options allow settings to be loaded from files other than the
# default postgresql.conf.  Note that these are directives, not variable
# assignments, so they can usefully be given more than once.

include_dir = 'conf.d'			# include files ending in '.conf' from
					# a directory, e.g., 'conf.d'
`;

/** Debian's pg_hba.conf for a new cluster, plus the application's line. */
export const DB01_PG_HBA = `# PostgreSQL Client Authentication Configuration File
# ===================================================
#
# Refer to the "Client Authentication" section in the PostgreSQL
# documentation for a complete description of this file.
#
# Records are read top to bottom; the FIRST record that matches the
# connection type, database, user and client address is used, and its
# method decides. If no record matches, access is denied.
#
# local         DATABASE  USER  METHOD  [OPTIONS]
# host          DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
# hostssl       DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
# hostnossl     DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
#
# METHOD can be "trust", "reject", "md5", "password", "scram-sha-256",
# "gss", "sspi", "ident", "peer", "pam", "ldap", "radius" or "cert".
#
# This file is read on server start and when the server is reloaded
# (systemctl reload postgresql, or SELECT pg_reload_conf()).

# DO NOT DISABLE!
# If you change this first entry you will need to make sure that the
# database superuser can access the database using some other method.
# Noninteractive access to all databases is required during automatic
# maintenance (custom daily cronjobs, replication, and similar tasks).
#
# Database administrative login by Unix domain socket
local   all             postgres                                peer

# TYPE  DATABASE        USER            ADDRESS                 METHOD

# "local" is for Unix domain socket connections only
local   all             all                                     peer
# IPv4 local connections:
host    all             all             127.0.0.1/32            scram-sha-256
# IPv6 local connections:
host    all             all             ::1/128                 scram-sha-256
# Allow replication connections from localhost, by a user with the
# replication privilege.
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            scram-sha-256
host    replication     all             ::1/128                 scram-sha-256

# Inventory web application on srv01 (CHG-2501)
host    inventory       webapp          10.0.20.10/32           scram-sha-256
`;

export const DB01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
		# PostgreSQL for the corp.lab networks; pg_hba.conf decides who may log in (CHG-2501)
		ip saddr 10.0.0.0/16 tcp dport 5432 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const PG_BACKUP_SCRIPT = `#!/bin/sh
# Nightly logical backup of the inventory database (CHG-2502).
# Runs from /etc/cron.d/pg-backup as root; the password of the backup role is
# in /root/.pgpass. Restore test: pg_restore -l /var/backups/postgresql/inventory.dump
set -e
pg_dump -h localhost -U backup -w -Fc -f /var/backups/postgresql/inventory.dump inventory
logger -t pg-backup "inventory backup written to /var/backups/postgresql/inventory.dump"
`;

export const INVENTORY_CHECK = `#!/bin/sh
# Health check of the inventory application's database access (cron, every minute).
# The application connects as webapp; its password is in /root/.pgpass.
set -e
psql -h db01.corp.lab -U webapp -d inventory -w -A -t -c "SELECT count(*) FROM items"
`;

export const DB_CERT = issueServerCert(CORP_ISSUING, ['db01.corp.lab'], 'db01-2026', '2026-07-01T09:00:00Z', 397);

const col = (name: string, type: string, extra: Partial<PgTable['columns'][number]> = {}) => ({ name, type, ...extra });

/** The inventory database as the application team delivered it. */
export function inventoryCluster(): PgCluster {
  const c = initCluster();
  let oid = 16384;
  const role = (name: string, opts: Parameters<typeof newRole>[2]) => {
    const r = newRole(name, oid++, opts);
    c.roles[name] = r;
    const h = storedHash(r);
    if (h && r.password) (c.hashes ??= {})[h] = r.password;
    return r;
  };
  role('invowner', {});
  role('webapp', { login: true, password: DB_PASSWORDS.webapp, hash: 'scram' });
  role('backup', { login: true, password: DB_PASSWORDS.backup, hash: 'scram' });
  const table = (name: string, columns: PgTable['columns'], rows: PgTable['rows'], acl: Record<string, string>): PgTable => ({ name, owner: 'invowner', columns, rows, acl, nextSerial: Math.max(0, ...rows.map((r) => Number(r[0]))) + 1 });
  c.databases.inventory = {
    name: 'inventory', oid: oid++, owner: 'invowner', connect: ['webapp', 'backup'], schemaCreate: [], defaultAcl: [],
    tables: {
      items: table('items', [col('id', 'integer', { serial: true, primaryKey: true, notNull: true }), col('sku', 'text', { notNull: true }), col('name', 'text'), col('qty', 'integer')], [
        [1, 'W-100', 'Widget', 40], [2, 'W-200', 'Widget XL', 12], [3, 'G-310', 'Gadget', 7], [4, 'S-020', 'Spare cable', 120], [5, 'B-001', 'Bracket', 64], [6, 'P-777', 'Power supply', 9],
      ], { webapp: 'arwd', backup: 'r' }),
      orders: table('orders', [col('id', 'integer', { serial: true, primaryKey: true, notNull: true }), col('item_id', 'integer'), col('qty', 'integer'), col('customer', 'text'), col('created', 'date')], [
        [1001, 1, 5, 'Contoso', '2026-10-14'], [1002, 3, 1, 'Fabrikam', '2026-10-15'], [1003, 2, 2, 'Contoso', '2026-10-16'], [1004, 4, 30, 'Northwind', '2026-10-16'], [1005, 6, 1, 'Adatum', '2026-10-17'], [1006, 1, 10, 'Northwind', '2026-10-18'],
      ], { webapp: 'arwd', backup: 'r' }),
      suppliers: table('suppliers', [col('id', 'integer', { serial: true, primaryKey: true, notNull: true }), col('name', 'text', { notNull: true }), col('email', 'text')], [
        [1, 'Acme Parts', 'orders@acme.example'], [2, 'Globex', 'sales@globex.example'], [3, 'Initech', 'supply@initech.example'],
      ], { webapp: 'r', backup: 'r' }),
    },
  };
  c.nextOid = oid;
  return c;
}

/** Debian's postgresql-15 package layout for cluster 15/main (pg_createcluster). */
export function installPostgresPackage(h: Host, t: number, conf: string, hba: string): void {
  addUser(h, { name: 'postgres', uid: 108, gid: 114, primaryGroup: 'postgres', groups: ['ssl-cert'], home: '/var/lib/postgresql', shell: '/bin/bash', gecos: 'PostgreSQL administrator,,,', password: null }, t, false);
  for (const d of ['/etc/postgresql', '/etc/postgresql/15', '/etc/postgresql/15/main', '/etc/postgresql/15/main/conf.d', '/etc/postgresql-common', '/usr', '/usr/lib', '/usr/lib/postgresql', '/var', '/var/lib', '/var/log', '/var/backups', '/usr/local', '/usr/local/sbin']) if (!h.fs[d]) mkdir(h, d, t);
  for (const d of ['/etc/postgresql/15', '/etc/postgresql/15/main', '/etc/postgresql/15/main/conf.d']) { h.fs[d].owner = 'postgres'; h.fs[d].group = 'postgres'; }
  const conf0 = { owner: 'postgres', group: 'postgres' };
  writeFile(h, '/etc/postgresql/15/main/postgresql.conf', conf, t, { mode: 0o644, ...conf0 });
  writeFile(h, '/etc/postgresql/15/main/pg_hba.conf', hba, t, { mode: 0o640, ...conf0 });
  writeFile(h, '/etc/postgresql/15/main/pg_ident.conf', '# PostgreSQL User Name Maps\n# ==========================\n# MAPNAME       SYSTEM-USERNAME         PG-USERNAME\n', t, { mode: 0o640, ...conf0 });
  writeFile(h, '/etc/postgresql/15/main/start.conf', '# Automatic startup configuration\n#   auto: automatically start the cluster\n#   manual: manual startup with pg_ctlcluster/postgresql@.service only\n#   disabled: refuse to start cluster\nauto\n', t, { mode: 0o644, ...conf0 });
  writeFile(h, '/etc/postgresql/15/main/pg_ctl.conf', "# Automatic pg_ctl configuration\npg_ctl_options = ''\n", t, { mode: 0o644, ...conf0 });
  writeFile(h, '/etc/postgresql/15/main/environment', '# environment variables for postgres processes\n', t, { mode: 0o644, ...conf0 });
  mkdir(h, '/var/lib/postgresql', t, { mode: 0o755, ...conf0 });
  mkdir(h, '/var/lib/postgresql/15', t, { mode: 0o755, ...conf0 });
  mkdir(h, DATA_DIR, t, { mode: 0o700, ...conf0 });
  writeFile(h, `${DATA_DIR}/PG_VERSION`, '15\n', t, { mode: 0o600, ...conf0 });
  for (const d of ['base', 'global', 'pg_wal', 'pg_xact', 'pg_stat', 'pg_tblspc']) mkdir(h, `${DATA_DIR}/${d}`, t, { mode: 0o700, ...conf0 });
  writeFile(h, `${DATA_DIR}/postgresql.auto.conf`, '# Do not edit this file manually!\n# It will be overwritten by the ALTER SYSTEM command.\n', t, { mode: 0o600, ...conf0 });
  writeFile(h, `${DATA_DIR}/postmaster.opts`, '/usr/lib/postgresql/15/bin/postgres "-D" "/var/lib/postgresql/15/main" "-c" "config_file=/etc/postgresql/15/main/postgresql.conf"\n', t, { mode: 0o600, ...conf0 });
  mkdir(h, '/var/log/postgresql', t, { mode: 0o1775, owner: 'root', group: 'postgres' });
  if (!h.fs['/var/run']) mkdir(h, '/var/run', t);
  mkdir(h, '/var/run/postgresql', t, { mode: 0o2775, ...conf0 });
  writeFile(h, '/etc/postgresql-common/createcluster.conf', "# Default values for pg_createcluster\ncreate_main_cluster = true\nssl = on\n", t);
}

/** Create db01 (cabled to sw01 swp16), the application's client side on srv01, and the backup job. */
export function installDb01(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'db01', hostname: 'db01', domain: 'corp.lab', role: 'Database server (PostgreSQL 15)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:db:00:23', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh', 'postgresql'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${DB01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', DB01_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, true);
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: DB_PASSWORDS.alice }, t);
  if (!h.fs['/etc/ssl/private']) mkdir(h, '/etc/ssl/private', t, { mode: 0o710, group: 'ssl-cert' });
  writeFile(h, '/etc/ssl/certs/db01.corp.lab.crt', fullchain(DB_CERT.cert, CORP_ISSUING.cert), t);
  writeFile(h, '/etc/ssl/private/db01.corp.lab.key', keyPem(DB_CERT.key), t, { mode: 0o640, group: 'ssl-cert' });
  installPostgresPackage(h, t, DB01_POSTGRESQL_CONF, DB01_PG_HBA);
  h.pg = inventoryCluster();

  // Nightly backup: script, cron entry, credentials for the backup role.
  mkdir(h, '/var/backups/postgresql', t, { mode: 0o750, group: 'postgres' });
  writeFile(h, '/usr/local/sbin/pg-backup', PG_BACKUP_SCRIPT, t, { mode: 0o755 });
  if (!h.fs['/etc/cron.d']) mkdir(h, '/etc/cron.d', t);
  writeFile(h, '/etc/cron.d/pg-backup', '# Nightly PostgreSQL backup (CHG-2502)\n15 2 * * * root /usr/local/sbin/pg-backup\n', t);
  writeFile(h, '/root/.pgpass', `localhost:5432:*:backup:${DB_PASSWORDS.backup}\n`, t, { mode: 0o600 });

  // srv01: the application's credentials and its health check.
  const srv = world.hosts.srv01;
  writeFile(srv, '/root/.pgpass', `db01.corp.lab:5432:inventory:webapp:${DB_PASSWORDS.webapp}\n`, t, { mode: 0o600 });
  if (!srv.fs['/usr/local/bin']) mkdir(srv, '/usr/local/bin', t);
  writeFile(srv, '/usr/local/bin/inventory-check', INVENTORY_CHECK, t, { mode: 0o755 });
  return h;
}

/** Last night's backup, as the cron job wrote it (the lab starts the next morning). */
export function seedBackup(world: World): void {
  const h = world.hosts.db01;
  const at = Date.parse('2026-10-19T02:15:01Z');
  const d = dumpDatabase({ world, server: h, user: 'backup', db: 'inventory', pid: 0, settings: {} });
  if (d.ok) writeFile(h, '/var/backups/postgresql/inventory.dump', archiveToCustom({ ...d.archive, createdAt: at }), at, { mode: 0o644 });
}
