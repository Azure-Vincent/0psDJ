// SNMP with net-snmp 5.9.3 as Debian 12 packages it: snmpd reads
// /etc/snmp/snmpd.conf (plus snmpd.conf.d and /var/lib/snmp/snmpd.conf),
// listens where agentaddress says (Debian's default: localhost only), and
// answers v1/v2c communities (rocommunity with a source and a view) and v3
// users (createUser + rouser with a security level). The MIB values come from
// the host: system group, IF-MIB interface tables, HOST-RESOURCES uptime and
// storage. The client tools print OIDs numerically unless MIB loading is
// enabled in /etc/snmp/snmp.conf (Debian disables it: "mibs :").

import { readFile } from '../fs';
import type { Host, Packet, ServiceRuntime, World } from '../types';
import { diskUsedKB } from './disk';
import { log } from './journal';
import { activeRecorder } from './trace';
import { icmpMeaning, nextId, sendIcmpError, sourceAddress, transmit } from './network';
import { findListener, type Listener } from './services';
import { inCidr, parseCidr } from '../net/ip';

export const SNMPD_CONF = '/etc/snmp/snmpd.conf';
export const SNMP_CONF = '/etc/snmp/snmp.conf';

/** /etc/snmp/snmpd.conf as Debian 12 ships it. */
export const DEBIAN_SNMPD_CONF = `###########################################################################
#
# snmpd.conf
# An example configuration file for configuring the Net-SNMP agent ('snmpd')
# See snmpd.conf(5) man page for details
#
###########################################################################
# SECTION: System Information Setup
#

# syslocation: The [typically physical] location of the system.
#   Note that setting this value here means that when trying to
#   perform an snmp SET operation to the sysLocation.0 variable will make
#   the agent return the "notWritable" error code.  IE, including
#   this token in the snmpd.conf file will disable write access to
#   the variable.
#   arguments:  location_string
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>

# sysservices: The proper value for the sysServices object.
#   arguments:  sysservices_number
sysServices    72

###########################################################################
# SECTION: Agent Operating Mode
#
#   This section defines how the agent will operate when it
#   is running.

# master: Should the agent operate as a master agent or not.
#   Currently, the only supported master agent type for this token
#   is "agentx".
#
#   arguments: (on|yes|agentx|all|off|no)

master  agentx

# agentaddress: The IP address and port number that the agent will listen on.
#   By default the agent listens to any and all traffic from any
#   interface on the default SNMP port (161).  This allows you to
#   specify which address, interface, transport type and port(s) that you
#   want the agent to listen on.  Multiple definitions of this token
#   are concatenated together (using ':'s).
#   arguments: [transport:]port[@interface/address],...

agentaddress  127.0.0.1,[::1]

###########################################################################
# SECTION: Access Control Setup
#
#   This section defines who is allowed to talk to your running
#   snmp agent.

# Views
#   arguments viewname included [oid]

#  system + hrSystem groups only
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1


# rocommunity: a SNMPv1/SNMPv2c read-only access community name
#   arguments:  community [default|hostname|network/bits] [oid | -V view]

# Read-only access to everyone to the systemonly view
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly

# SNMPv3 doesn't use communities, but users with (optionally) an
# authentication and encryption string. This user needs to be created
# with what they can view with rouser/rwuser lines in this file.
#
# createUser username (MD5|SHA|SHA-512|SHA-384|SHA-256|SHA-224) authpassphrase [DES|AES] [privpassphrase]
# e.g.
# createuser authPrivUser SHA-512 myauthphrase AES myprivphrase
#
# This should be put into /var/lib/snmp/snmpd.conf
#
# rouser: a SNMPv3 read-only access username
#    arguments: username [noauth|auth|priv [OID | -V VIEW [CONTEXT]]]
rouser authPrivUser authpriv -V systemonly

# include a all *.conf files in a directory
includeDir /etc/snmp/snmpd.conf.d
`;

/** /etc/snmp/snmp.conf as Debian ships it: no MIBs are loaded. */
export const DEBIAN_SNMP_CONF = `# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
mibs :

# If you want to globally change where snmp libraries, commands and daemons
# look for MIBS, change the line below. Note you can set this for individual
# tools with the -M option or MIBDIRS environment variable.
#
# mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
`;

// ---------------------------------------------------------------------------
// OIDs and MIB names
// ---------------------------------------------------------------------------

export type Oid = number[];
export const parseOid = (s: string): Oid | null => (/^\.?\d+(\.\d+)*$/.test(s) ? s.replace(/^\./, '').split('.').map(Number) : null);
export const oidStr = (o: Oid) => o.join('.');
export function cmpOid(a: Oid, b: Oid): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
const startsWith = (o: Oid, p: Oid) => p.length <= o.length && p.every((x, i) => o[i] === x);

/** The objects the tools can name when MIBs are loaded: module, name, OID, enumerations. */
const MIB: { module: string; name: string; oid: Oid; enums?: Record<number, string>; scalar?: boolean }[] = [
  { module: 'SNMPv2-MIB', name: 'system', oid: [1, 3, 6, 1, 2, 1, 1] },
  { module: 'SNMPv2-MIB', name: 'sysDescr', oid: [1, 3, 6, 1, 2, 1, 1, 1], scalar: true },
  { module: 'SNMPv2-MIB', name: 'sysObjectID', oid: [1, 3, 6, 1, 2, 1, 1, 2], scalar: true },
  { module: 'DISMAN-EVENT-MIB', name: 'sysUpTimeInstance', oid: [1, 3, 6, 1, 2, 1, 1, 3, 0] },
  { module: 'SNMPv2-MIB', name: 'sysUpTime', oid: [1, 3, 6, 1, 2, 1, 1, 3], scalar: true },
  { module: 'SNMPv2-MIB', name: 'sysContact', oid: [1, 3, 6, 1, 2, 1, 1, 4], scalar: true },
  { module: 'SNMPv2-MIB', name: 'sysName', oid: [1, 3, 6, 1, 2, 1, 1, 5], scalar: true },
  { module: 'SNMPv2-MIB', name: 'sysLocation', oid: [1, 3, 6, 1, 2, 1, 1, 6], scalar: true },
  { module: 'SNMPv2-MIB', name: 'sysServices', oid: [1, 3, 6, 1, 2, 1, 1, 7], scalar: true },
  { module: 'IF-MIB', name: 'interfaces', oid: [1, 3, 6, 1, 2, 1, 2] },
  { module: 'IF-MIB', name: 'ifNumber', oid: [1, 3, 6, 1, 2, 1, 2, 1], scalar: true },
  { module: 'IF-MIB', name: 'ifTable', oid: [1, 3, 6, 1, 2, 1, 2, 2] },
  { module: 'IF-MIB', name: 'ifEntry', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1] },
  { module: 'IF-MIB', name: 'ifIndex', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 1] },
  { module: 'IF-MIB', name: 'ifDescr', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 2] },
  { module: 'IF-MIB', name: 'ifType', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 3], enums: { 6: 'ethernetCsmacd', 24: 'softwareLoopback', 135: 'l2vlan' } },
  { module: 'IF-MIB', name: 'ifMtu', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 4] },
  { module: 'IF-MIB', name: 'ifSpeed', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 5] },
  { module: 'IF-MIB', name: 'ifPhysAddress', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 6] },
  { module: 'IF-MIB', name: 'ifAdminStatus', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 7], enums: { 1: 'up', 2: 'down', 3: 'testing' } },
  { module: 'IF-MIB', name: 'ifOperStatus', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 8], enums: { 1: 'up', 2: 'down', 3: 'testing', 5: 'dormant', 7: 'lowerLayerDown' } },
  { module: 'IF-MIB', name: 'ifLastChange', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 9] },
  { module: 'IF-MIB', name: 'ifInOctets', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 10] },
  { module: 'IF-MIB', name: 'ifInErrors', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 14] },
  { module: 'IF-MIB', name: 'ifOutOctets', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 16] },
  { module: 'IF-MIB', name: 'ifOutErrors', oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 20] },
  { module: 'IF-MIB', name: 'ifXTable', oid: [1, 3, 6, 1, 2, 1, 31, 1, 1] },
  { module: 'IF-MIB', name: 'ifName', oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1] },
  { module: 'IF-MIB', name: 'ifHCInOctets', oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6] },
  { module: 'IF-MIB', name: 'ifHCOutOctets', oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10] },
  { module: 'IF-MIB', name: 'ifHighSpeed', oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15] },
  { module: 'IF-MIB', name: 'ifAlias', oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18] },
  { module: 'HOST-RESOURCES-MIB', name: 'host', oid: [1, 3, 6, 1, 2, 1, 25] },
  { module: 'HOST-RESOURCES-MIB', name: 'hrSystem', oid: [1, 3, 6, 1, 2, 1, 25, 1] },
  { module: 'HOST-RESOURCES-MIB', name: 'hrSystemUptime', oid: [1, 3, 6, 1, 2, 1, 25, 1, 1], scalar: true },
  { module: 'HOST-RESOURCES-MIB', name: 'hrSystemDate', oid: [1, 3, 6, 1, 2, 1, 25, 1, 2], scalar: true },
  { module: 'HOST-RESOURCES-MIB', name: 'hrSystemNumUsers', oid: [1, 3, 6, 1, 2, 1, 25, 1, 5], scalar: true },
  { module: 'HOST-RESOURCES-MIB', name: 'hrSystemProcesses', oid: [1, 3, 6, 1, 2, 1, 25, 1, 6], scalar: true },
  { module: 'HOST-RESOURCES-MIB', name: 'hrSystemMaxProcesses', oid: [1, 3, 6, 1, 2, 1, 25, 1, 7], scalar: true },
  { module: 'HOST-RESOURCES-MIB', name: 'hrStorageTable', oid: [1, 3, 6, 1, 2, 1, 25, 2, 3] },
  { module: 'HOST-RESOURCES-MIB', name: 'hrStorageDescr', oid: [1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 3] },
  { module: 'HOST-RESOURCES-MIB', name: 'hrStorageAllocationUnits', oid: [1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 4] },
  { module: 'HOST-RESOURCES-MIB', name: 'hrStorageSize', oid: [1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 5] },
  { module: 'HOST-RESOURCES-MIB', name: 'hrStorageUsed', oid: [1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6] },
  { module: 'NET-SNMP-MIB', name: 'netSnmpAgentOIDs', oid: [1, 3, 6, 1, 4, 1, 8072, 3, 2] },
];

/** "SNMPv2-MIB::sysName.0", "sysName.0", "IF-MIB::ifTable", ".1.3.6.1.2.1.1.5.0" → OID (null: unknown). */
export function resolveName(text: string, mibs: boolean): Oid | null | 'unknown' {
  const numeric = parseOid(text.replace(/^iso\./, '1.'));
  if (numeric) return numeric;
  if (!mibs) return 'unknown';
  const m = /^(?:([\w-]+)::)?([a-zA-Z][\w]*)((?:\.\d+)*)$/.exec(text);
  if (!m) return 'unknown';
  const e = MIB.find((x) => x.name === m[2] && (!m[1] || x.module === m[1]));
  if (!e) return 'unknown';
  return [...e.oid, ...(m[3] ? m[3].slice(1).split('.').map(Number) : [])];
}

/** How the tools print an OID: iso.3.6… without MIBs, MODULE::name.index with them, .1.3.6… with -On. */
export function oidName(o: Oid, mibs: boolean, numeric: boolean): string {
  if (numeric) return '.' + oidStr(o);
  if (!mibs) return 'iso.' + oidStr(o.slice(1));
  const e = [...MIB].filter((x) => startsWith(o, x.oid)).sort((a, b) => b.oid.length - a.oid.length)[0];
  if (!e) return 'iso.' + oidStr(o.slice(1));
  const rest = o.slice(e.oid.length);
  return `${e.module}::${e.name}${rest.length ? '.' + oidStr(rest) : ''}`;
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

export type VarType = 'STRING' | 'OID' | 'Timeticks' | 'INTEGER' | 'Counter32' | 'Counter64' | 'Gauge32' | 'Hex-STRING';
export interface VarBind { oid: Oid; type: VarType; value: string | number | Oid }

function ticks(cs: number): string {
  const t = Math.floor(cs);
  const d = Math.floor(t / 8_640_000);
  const h = Math.floor((t % 8_640_000) / 360_000);
  const m = Math.floor((t % 360_000) / 6000);
  const s = Math.floor((t % 6000) / 100);
  const c = t % 100;
  return `(${t}) ${d ? `${d} day${d > 1 ? 's' : ''}, ` : ''}${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}.${String(c).padStart(2, '0')}`;
}

/** "STRING: rtr01", "INTEGER: up(1)", "Timeticks: (123) 0:00:01.23" … */
export function formatVar(v: VarBind, mibs: boolean): string {
  const e = mibs ? [...MIB].filter((x) => startsWith(v.oid, x.oid)).sort((a, b) => b.oid.length - a.oid.length)[0] : undefined;
  switch (v.type) {
    case 'STRING': return mibs ? `STRING: ${v.value}` : `STRING: "${v.value}"`;
    case 'Hex-STRING': return mibs ? `STRING: ${String(v.value).split(' ').map((x) => parseInt(x, 16).toString(16)).join(':')}` : `Hex-STRING: ${v.value}`;
    case 'OID': return `OID: ${oidName(v.value as Oid, mibs, false)}`;
    case 'Timeticks': return `Timeticks: ${ticks(Number(v.value))}`;
    case 'INTEGER': return e?.enums?.[Number(v.value)] ? `INTEGER: ${e.enums[Number(v.value)]}(${v.value})` : `INTEGER: ${v.value}`;
    default: return `${v.type}: ${v.value}`;
  }
}

// ---------------------------------------------------------------------------
// snmpd configuration
// ---------------------------------------------------------------------------

export interface SnmpView { name: string; included: boolean; oid: Oid }
export interface SnmpCommunity { community: string; source: string; v6: boolean; oid?: Oid; view?: string }
export interface SnmpUser { name: string; authProto?: string; authPass?: string; privProto?: string; privPass?: string }
export interface SnmpRouser { name: string; level: 'noauth' | 'auth' | 'priv'; oid?: Oid; view?: string }
export interface SnmpdLoaded {
  pid: number; listen: { addr: string; port: number }[]; views: SnmpView[]; communities: SnmpCommunity[]; users: SnmpUser[]; rousers: SnmpRouser[];
  sysLocation: string; sysContact: string; sysServices: number; sysName?: string; started: number;
}

const KNOWN = new Set(['syslocation', 'syscontact', 'sysservices', 'sysname', 'sysdescr', 'master', 'agentaddress', 'agentuser', 'agentgroup', 'view', 'rocommunity', 'rocommunity6', 'rwcommunity', 'rwcommunity6', 'createuser', 'rouser', 'rwuser', 'includedir', 'includefile', 'com2sec', 'group', 'access', 'trapsink', 'trap2sink', 'informsink', 'authtrapenable', 'disk', 'load', 'proc', 'extend', 'defaultmonitors', 'linkupdownnotifications', 'iquerysecname', 'dontlogtcpwrappersconnects', 'agentsecname']);

function configFiles(host: Host): string[] {
  const files = [SNMPD_CONF];
  const main = readFile(host, SNMPD_CONF) ?? '';
  for (const m of main.matchAll(/^\s*includeDir\s+(\S+)/gim)) {
    const dir = m[1].replace(/\/$/, '');
    files.push(...Object.keys(host.fs).filter((p) => p.startsWith(dir + '/') && p.endsWith('.conf') && host.fs[p].type === 'file').sort());
  }
  files.push('/var/lib/snmp/snmpd.conf');
  return files.filter((f) => host.fs[f]);
}

export function snmpdLoad(world: World, host: Host, rt: ServiceRuntime): SnmpdLoaded | null {
  const pid = rt.pid ?? 0;
  const loaded: SnmpdLoaded = { pid, listen: [], views: [], communities: [], users: [], rousers: [], sysLocation: '', sysContact: '', sysServices: 72, started: world.clock };
  const warn = (file: string, line: number, msg: string) => log(world, host, 'snmpd', `${file}: line ${line}: ${msg}`, { pid, unit: 'snmpd.service', priority: 'warning' });
  let addrs: string[] = [];
  for (const file of configFiles(host)) {
    (readFile(host, file) ?? '').split('\n').forEach((raw, i) => {
      const line = raw.replace(/#.*$/, '').trim();
      if (!line) return;
      const [tokRaw, ...rest] = line.split(/\s+/);
      const tok = tokRaw.toLowerCase();
      const args = rest;
      if (!KNOWN.has(tok)) { warn(file, i + 1, `Warning: Unknown token: ${tokRaw}.`); return; }
      switch (tok) {
        case 'syslocation': loaded.sysLocation = rest.join(' '); break;
        case 'syscontact': loaded.sysContact = rest.join(' '); break;
        case 'sysservices': loaded.sysServices = Number(rest[0]) || 72; break;
        case 'sysname': loaded.sysName = rest.join(' '); break;
        case 'agentaddress': addrs = addrs.concat(rest.join('').split(',')); break;
        case 'view': {
          const oid = parseOid(args[2] ?? '');
          if (!oid) { warn(file, i + 1, `Error: bad view OID: ${args[2] ?? ''}`); return; }
          loaded.views.push({ name: args[0], included: args[1] !== 'excluded', oid });
          break;
        }
        case 'rocommunity': case 'rocommunity6': case 'rwcommunity': case 'rwcommunity6': {
          const [community, source = 'default', ...more] = args;
          const vi = more.indexOf('-V');
          loaded.communities.push({ community, source, v6: tok.endsWith('6'), view: vi >= 0 ? more[vi + 1] : undefined, oid: vi < 0 && more[0] ? parseOid(more[0]) ?? undefined : undefined });
          break;
        }
        case 'createuser': {
          const [name, authProto, authPass, privProto, privPass] = args.map((a) => a.replace(/^"|"$/g, ''));
          if (authPass !== undefined && authPass.length < 8) { warn(file, i + 1, 'Error: Error: passphrase chosen is below the length requirements of the USM (min=8).'); return; }
          loaded.users.push({ name, authProto, authPass, privProto, privPass });
          break;
        }
        case 'rouser': case 'rwuser': {
          const [name, levelRaw = 'auth', ...more] = args;
          const lv = levelRaw.toLowerCase().replace(/^authpriv$/, 'priv').replace(/^authnopriv$/, 'auth').replace(/^noauthnopriv$/, 'noauth');
          const vi = more.indexOf('-V');
          loaded.rousers.push({ name, level: (['noauth', 'auth', 'priv'].includes(lv) ? lv : 'auth') as SnmpRouser['level'], view: vi >= 0 ? more[vi + 1] : undefined, oid: vi < 0 && more[0] ? parseOid(more[0]) ?? undefined : undefined });
          break;
        }
      }
    });
  }
  if (!addrs.length) addrs = ['udp:161'];
  for (const a of addrs) {
    const s = a.trim().replace(/^udp6?:/, '').replace(/^tcp6?:.*$/, '');
    if (!s) continue;
    if (/^\d+$/.test(s)) { loaded.listen.push({ addr: '0.0.0.0', port: Number(s) }); continue; }
    const v6 = /^\[(.*)\](?::(\d+))?$/.exec(s);
    if (v6) { loaded.listen.push({ addr: v6[1] === '' ? '::' : v6[1], port: Number(v6[2] ?? 161) }); continue; }
    const [ip, port] = s.split(':');
    loaded.listen.push({ addr: ip, port: Number(port ?? 161) });
  }
  for (const v of loaded.communities) if (v.view && !loaded.views.some((x) => x.name === v.view)) warn(SNMPD_CONF, 0, `Error: unknown view name: ${v.view}`);
  log(world, host, 'snmpd', 'NET-SNMP version 5.9.3', { pid, unit: 'snmpd.service' });
  return loaded;
}

export function snmpdListeners(rt: ServiceRuntime): Listener[] {
  const l = rt.loaded as SnmpdLoaded | null;
  if (!l) return [];
  return l.listen.map((x) => ({ proto: 'udp' as const, addr: x.addr, port: x.port, process: 'snmpd', pid: l.pid, service: 'snmpd' }));
}

/** Is OID visible in the named view (longest matching subtree decides)? */
function inView(l: SnmpdLoaded, view: string | undefined, root: Oid | undefined, o: Oid): boolean {
  if (root) return startsWith(o, root);
  if (!view) return true;
  const entries = l.views.filter((v) => v.name === view && startsWith(o, v.oid)).sort((a, b) => b.oid.length - a.oid.length);
  return !!entries[0]?.included;
}

// ---------------------------------------------------------------------------
// The MIB tree of a host
// ---------------------------------------------------------------------------

const u32 = (x: number) => Math.floor(x) % 4_294_967_296;

export function mibTree(world: World, host: Host, l: SnmpdLoaded): VarBind[] {
  const now = world.clock;
  const agentUp = (now - l.started) / 10;
  const hostUp = (now - host.bootTime) / 10;
  const vb: VarBind[] = [];
  const add = (oid: Oid, type: VarType, value: VarBind['value']) => vb.push({ oid, type, value });
  const sys = [1, 3, 6, 1, 2, 1, 1];
  add([...sys, 1, 0], 'STRING', `Linux ${host.hostname} 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64`);
  add([...sys, 2, 0], 'OID', [1, 3, 6, 1, 4, 1, 8072, 3, 2, 10]);
  add([...sys, 3, 0], 'Timeticks', agentUp);
  add([...sys, 4, 0], 'STRING', l.sysContact);
  add([...sys, 5, 0], 'STRING', l.sysName ?? host.hostname);
  add([...sys, 6, 0], 'STRING', l.sysLocation);
  add([...sys, 7, 0], 'INTEGER', l.sysServices);
  const ifs = host.ifaces.filter((i) => !i.kind);
  const ifTable = [1, 3, 6, 1, 2, 1, 2, 2, 1];
  add([1, 3, 6, 1, 2, 1, 2, 1, 0], 'INTEGER', ifs.length);
  const aliases = new Map<string, string>();
  for (const m of (readFile(host, '/etc/network/interfaces') ?? '').matchAll(/^iface\s+(\S+)[^\n]*\n((?:[ \t]+\S[^\n]*\n?)*)/gm)) {
    const a = /^\s+alias\s+(.+)$/m.exec(m[2]);
    if (a) aliases.set(m[1], a[1].trim());
  }
  const rate = (i: number) => 1200 + ((host.id.charCodeAt(0) * 31 + i * 977) % 5000);
  const cols: [number, (i: typeof ifs[number], idx: number) => [VarType, VarBind['value']]][] = [
    [1, (_i, idx) => ['INTEGER', idx]],
    [2, (i) => ['STRING', i.name]],
    [3, (i) => ['INTEGER', i.name === 'lo' ? 24 : i.name.includes('.') ? 135 : 6]],
    [4, (i) => ['INTEGER', i.name === 'lo' ? 65536 : i.mtu ?? 1500]],
    [5, (i) => ['Gauge32', i.name === 'lo' ? 10_000_000 : 1_000_000_000]],
    [6, (i) => ['Hex-STRING', i.name === 'lo' ? '' : i.mac.split(':').map((x) => x.toUpperCase().padStart(2, '0')).join(' ')]],
    [7, (i) => ['INTEGER', i.up ? 1 : 2]],
    [8, (i) => ['INTEGER', i.up ? 1 : 2]],
    [9, () => ['Timeticks', 0]],
    [10, (i, idx) => ['Counter32', i.up ? u32(hostUp / 100 * rate(idx)) : 0]],
    [14, () => ['Counter32', 0]],
    [16, (i, idx) => ['Counter32', i.up ? u32(hostUp / 100 * rate(idx) * 0.7) : 0]],
    [20, () => ['Counter32', 0]],
  ];
  for (const [col, f] of cols) ifs.forEach((i, k) => { const [t, v] = f(i, k + 1); add([...ifTable, col, k + 1], t, v); });
  const ifX = [1, 3, 6, 1, 2, 1, 31, 1, 1, 1];
  const xcols: [number, (i: typeof ifs[number], idx: number) => [VarType, VarBind['value']]][] = [
    [1, (i) => ['STRING', i.name]],
    [6, (i, idx) => ['Counter64', i.up ? Math.floor(hostUp / 100 * rate(idx)) : 0]],
    [10, (i, idx) => ['Counter64', i.up ? Math.floor(hostUp / 100 * rate(idx) * 0.7) : 0]],
    [15, (i) => ['Gauge32', i.name === 'lo' ? 10 : 1000]],
    [18, (i) => ['STRING', aliases.get(i.name) ?? '']],
  ];
  for (const [col, f] of xcols) ifs.forEach((i, k) => { const [t, v] = f(i, k + 1); add([...ifX, col, k + 1], t, v); });
  const hr = [1, 3, 6, 1, 2, 1, 25, 1];
  add([...hr, 1, 0], 'Timeticks', hostUp);
  const d = new Date(Math.floor(now));
  add([...hr, 2, 0], 'Hex-STRING', [d.getUTCFullYear() >> 8, d.getUTCFullYear() & 255, d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), 0, 0x2b, 0, 0].map((x) => x.toString(16).toUpperCase().padStart(2, '0')).join(' '));
  add([...hr, 5, 0], 'Gauge32', 1);
  add([...hr, 6, 0], 'Gauge32', 87 + Object.values(host.services).filter((s) => s.state === 'active').length);
  add([...hr, 7, 0], 'INTEGER', 0);
  const st = [1, 3, 6, 1, 2, 1, 25, 2, 3, 1];
  const storage: [number, string, number, number][] = [[1, 'Physical memory', 2_018_972, 1_201_444], [3, 'Virtual memory', 3_017_368, 1_201_444], [31, '/', 5_116_564, 800_391]];
  (host.disks ?? []).forEach((dk, k) => storage.push([32 + k, dk.mount, Math.floor(dk.sizeKB / 4), Math.floor(Math.min(dk.sizeKB, diskUsedKB(host, dk)) / 4)]));
  for (const [idx, descr] of storage) add([...st, 3, idx], 'STRING', descr);
  for (const [idx, descr] of storage) add([...st, 4, idx], 'INTEGER', descr.startsWith('/') ? 4096 : 1024);
  for (const [idx, , size] of storage) add([...st, 5, idx], 'INTEGER', size);
  for (const [idx, , , used] of storage) add([...st, 6, idx], 'INTEGER', used);
  return vb.sort((a, b) => cmpOid(a.oid, b.oid));
}

// ---------------------------------------------------------------------------
// The protocol exchange
// ---------------------------------------------------------------------------

export interface SnmpRequest {
  version: '1' | '2c' | '3';
  community?: string;
  user?: string; level?: 'noauth' | 'auth' | 'priv'; authPass?: string; authProto?: string; privPass?: string; privProto?: string;
  op: 'get' | 'getnext' | 'getbulk';
  oids: Oid[];
}

export type SnmpResult =
  | { kind: 'timeout' }
  | { kind: 'error'; message: string }
  | { kind: 'response'; binds: (VarBind | { oid: Oid; missing: 'noSuchObject' | 'noSuchInstance' | 'endOfMibView' })[] };

/** One request/response from `host` to agent ip:port (the world clock is restored: tools wait, the network does not move). */
export function snmpExchange(world: World, host: Host, ip: string, port: number, req: SnmpRequest): SnmpResult {
  const start = world.clock;
  const rec = activeRecorder();
  const prev = rec?.phase;
  if (rec) rec.phase = 'SNMP';
  const pduName = req.op === 'get' ? 'get-request' : req.op === 'getnext' ? 'get-next-request' : 'getBulkRequest';
  try {
    const sport = 40000 + ((world.counter * 7919) % 20000);
    const q: Packet = {
      id: nextId(world), src: sourceAddress(host, ip), dst: ip, ttl: 64, proto: 'udp',
      udp: { sport, dport: port, len: 40 + req.oids.length * 14 },
      app: {
        protocol: 'SNMP', info: `${pduName} ${req.oids.map((o) => oidStr(o)).join(' ')}`,
        fields: [{ name: 'version', value: req.version === '1' ? 'version-1 (0)' : req.version === '2c' ? 'v2c (1)' : 'v3 (3)' }, ...(req.version === '3' ? [{ name: 'msgUserName', value: req.user ?? '' }, { name: 'msgFlags', value: req.level === 'priv' ? 'auth, priv, reportable' : req.level === 'auth' ? 'auth, reportable' : 'reportable' }] : [{ name: 'community', value: req.community ?? '' }])],
      },
    };
    const d = transmit(world, host.id, q);
    rec?.describe(q.id, `SNMP ${pduName}`, req.version === '3'
      ? `An SNMPv3 request from user ${req.user}: with authPriv the PDU is authenticated (HMAC) and encrypted, so only the user name travels in clear text.`
      : `An SNMP${req.version === '1' ? 'v1' : 'v2c'} request: one UDP datagram to port ${port}. The community string "${req.community}" travels in clear text and is the only "password".`);
    if (d.status !== 'delivered') {
      if (d.status !== 'local-error' && d.error?.delivered && icmpMeaning(d.error.packet) !== 'port') return { kind: 'timeout' };
      return { kind: 'timeout' };
    }
    const srv = world.hosts[d.host];
    const fq = d.final;
    const listener = findListener(srv, 'udp', fq.dst, port);
    if (!listener || listener.process !== 'snmpd') {
      if (!listener) sendIcmpError(world, srv, fq, 'port-unreachable');
      return { kind: 'timeout' };
    }
    const l = srv.services.snmpd?.loaded as SnmpdLoaded | null;
    if (!l) return { kind: 'timeout' };
    // Access control: v1/v2c by community and source, v3 by user, keys and level.
    let view: string | undefined;
    let root: Oid | undefined;
    if (req.version !== '3') {
      const c = l.communities.find((x) => x.community === req.community && !x.v6 && (x.source === 'default' || x.source === fq.src || (x.source.includes('/') && !!parseCidr(x.source) && inCidr(fq.src, parseCidr(x.source)!)) || (x.source === 'localhost' && fq.src.startsWith('127.'))));
      if (!c) {
        log(world, srv, 'snmpd', `Connection from UDP: [${fq.src}]:${sport}->[${fq.dst}]:${port}`, { pid: l.pid, unit: 'snmpd.service' });
        return { kind: 'timeout' };
      }
      view = c.view;
      root = c.oid;
    } else {
      const u = l.users.find((x) => x.name === req.user);
      if (!u) return { kind: 'error', message: 'Unknown user name' };
      if (req.level !== 'noauth' && (u.authPass !== req.authPass || (req.authProto && u.authProto && !u.authProto.toUpperCase().startsWith(req.authProto.toUpperCase())))) return { kind: 'error', message: 'Authentication failure (incorrect password, community or key)' };
      if (req.level === 'priv' && (u.privPass ?? u.authPass) !== req.privPass) return { kind: 'error', message: 'Decryption error' };
      if (req.level === 'priv' && !u.privProto) return { kind: 'error', message: 'Unsupported security level' };
      if (req.level === 'auth' && !u.authProto) return { kind: 'error', message: 'Unsupported security level' };
      const r = l.rousers.find((x) => x.name === req.user);
      const rank = { noauth: 0, auth: 1, priv: 2 };
      if (!r || rank[req.level ?? 'noauth'] < rank[r.level]) return { kind: 'error', message: 'Error in packet\nReason: authorizationError (access denied to that object)' };
      view = r.view;
      root = r.oid;
    }
    const tree = mibTree(world, srv, l).filter((v) => inView(l, view, root, v.oid));
    const binds: Extract<SnmpResult, { kind: 'response' }>['binds'] = [];
    for (const o of req.oids) {
      if (req.op === 'get') {
        const v = tree.find((x) => cmpOid(x.oid, o) === 0);
        if (v) binds.push(v);
        else binds.push({ oid: o, missing: tree.some((x) => startsWith(x.oid, o.slice(0, -1)) && x.oid.length === o.length) ? 'noSuchInstance' : 'noSuchObject' });
      } else {
        const next = tree.find((x) => cmpOid(x.oid, o) > 0);
        binds.push(next ?? { oid: o, missing: 'endOfMibView' });
      }
    }
    world.clock += 0.4;
    const r: Packet = {
      id: nextId(world), src: fq.dst, dst: fq.src, ttl: 64, proto: 'udp', udp: { sport: port, dport: sport, len: 60 + binds.length * 30 },
      app: { protocol: 'SNMP', info: `get-response ${binds.map((b) => oidStr(b.oid)).join(' ')}`, fields: [{ name: 'error-status', value: 'noError (0)' }] },
    };
    const back = transmit(world, srv.id, r);
    if (back.status !== 'delivered') return { kind: 'timeout' };
    return { kind: 'response', binds };
  } finally {
    world.clock = start;
    if (rec && prev) rec.phase = prev;
  }
}

/** The tools load MIBs unless /etc/snmp/snmp.conf has an active "mibs :" line. */
export function mibsLoaded(host: Host): boolean {
  const conf = readFile(host, SNMP_CONF);
  if (conf === undefined) return false;
  return !/^\s*mibs\s*:\s*$/m.test(conf);
}

/** What the tools print when nothing answers (wrong community, ACL, firewall, agent on localhost only). */
export const timeoutHint = (agent: string) => `Timeout: No Response from ${agent}`;
