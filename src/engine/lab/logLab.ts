// Central logging: log01 (10.0.20.50, Debian 12, switch port swp12) receives
// syslog from the corp.lab servers over TCP 514 and files it per host and
// program under /var/log/remote/. rtr01, ns1, srv01 and dock01 run rsyslog with
// Debian's default rules plus a forwarding rule to log01.

import { mkdir, writeFile } from '../fs';
import type { Host, World } from '../types';
import { addUser, createHost, staticInterfaces } from './builder';
import { TIMESYNCD_CONF } from './krbLab';
import { trustCorpRoot } from './pkiLab';
import { DEBIAN_SSHD_CONFIG, installHostKeys } from './sshLab';

export const LOG01_IP = '10.0.20.50';
export const LOG01_ALICE_PASSWORD = 'log01-alice';

/** /etc/rsyslog.conf as shipped by Debian 12 (rsyslog 8.2302). */
export const DEBIAN_RSYSLOG_CONF = `# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html


#################
#### MODULES ####
#################

module(load="imuxsock") # provides support for local system logging
module(load="imklog")   # provides kernel logging support
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
#module(load="imudp")
#input(type="imudp" port="514")

# provides TCP syslog reception
#module(load="imtcp")
#input(type="imtcp" port="514")


###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Set the default permissions for all log files.
#
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
$IncludeConfig /etc/rsyslog.d/*.conf


###############
#### RULES ####
###############

#
# Log anything besides private authentication messages to a single log file
#
*.*;auth,authpriv.none		-/var/log/syslog

#
# Log commonly used facilities to their own log file
#
auth,authpriv.*			/var/log/auth.log
cron.*				-/var/log/cron.log
kern.*				-/var/log/kern.log
mail.*				-/var/log/mail.log
user.*				-/var/log/user.log

#
# Emergencies are sent to everybody logged in.
#
*.emerg				:omusrmsg:*
`;

/** /etc/rsyslog.d/50-central.conf on the senders. */
export const FORWARD_CONF = `# Forward everything to the central log server log01 (CHG-2270) over TCP.
# The in-memory queue keeps messages while log01 is unreachable.
*.* action(type="omfwd" target="log01.corp.lab" port="514" protocol="tcp"
           queue.type="LinkedList" action.resumeRetryCount="-1")
`;

/** /etc/rsyslog.d/10-remote.conf on log01. */
export const LOG01_REMOTE_CONF = `# Central log server (CHG-2270): receive syslog from the corp.lab servers.
module(load="imtcp")
input(type="imtcp" port="514")
module(load="imudp")
input(type="imudp" port="514")

# One directory per sending host, one file per program; remote messages do
# not go into log01's own files.
template(name="RemoteLogs" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
:fromhost-ip, !isequal, "127.0.0.1" ?RemoteLogs
& stop
`;

export const LOG01_NFT = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto icmp accept
		tcp dport 22 accept
		# syslog from the corp.lab networks (CHG-2270)
		ip saddr 10.0.0.0/16 tcp dport 514 accept
		ip saddr 10.0.0.0/16 udp dport 514 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

export const LOG_SENDERS = ['rtr01', 'ns1', 'srv01', 'dock01'];

/** rsyslog with Debian's configuration and, on the senders, forwarding to log01. */
export function installRsyslog(host: Host, t: number, forward: boolean): void {
  mkdir(host, '/etc/rsyslog.d', t);
  if (!host.fs['/var/spool']) mkdir(host, '/var/spool', t);
  mkdir(host, '/var/spool/rsyslog', t, { mode: 0o700 });
  writeFile(host, '/etc/rsyslog.conf', DEBIAN_RSYSLOG_CONF, t);
  if (forward) writeFile(host, '/etc/rsyslog.d/50-central.conf', FORWARD_CONF, t);
}

/** Create log01 (cabled to sw01 swp12); buildSshLab boots it with the rest of the lab. */
export function installLog01(world: World): Host {
  const t = world.clock;
  const h = createHost(world, {
    id: 'log01', hostname: 'log01', domain: 'corp.lab', role: 'Central log server (rsyslog)',
    ifaces: [{ name: 'eth0', mac: '52:54:00:10:00:32', segment: null }],
    services: ['rsyslog', 'systemd-timesyncd', 'nftables', 'ssh'],
  });
  writeFile(h, '/etc/network/interfaces', staticInterfaces([{ name: 'eth0', address: `${LOG01_IP}/24`, gateway: '10.0.20.1' }]), t);
  writeFile(h, '/etc/resolv.conf', 'search corp.lab\nnameserver 10.0.10.53\n', t);
  writeFile(h, '/etc/ssh/sshd_config', DEBIAN_SSHD_CONFIG, t);
  writeFile(h, '/etc/nftables.conf', LOG01_NFT, t, { mode: 0o755 });
  mkdir(h, '/etc/systemd', t);
  writeFile(h, '/etc/systemd/timesyncd.conf', TIMESYNCD_CONF, t);
  installHostKeys(h, t);
  trustCorpRoot(h, t);
  installRsyslog(h, t, false);
  writeFile(h, '/etc/rsyslog.d/10-remote.conf', LOG01_REMOTE_CONF, t);
  mkdir(h, '/var/log/remote', t, { mode: 0o755 });
  addUser(h, { name: 'alice', uid: 1000, gid: 1000, primaryGroup: 'alice', groups: ['sudo', 'adm'], home: '/home/alice', shell: '/bin/bash', gecos: 'Alice Admin', password: LOG01_ALICE_PASSWORD }, t);
  return h;
}
