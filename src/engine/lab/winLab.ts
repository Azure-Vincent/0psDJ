// win01: a Windows Server 2022 member of the server network (VLAN 20), a VM on
// the virtualisation host whose virtual switch carries VLAN 20. It runs IIS,
// Remote Desktop, SMB and WinRM; administrators use PowerShell on its console.

import { mkdir, writeFile } from '../fs';
import type { Host, UserAccount, World } from '../types';
import { AD_DOMAIN, AD_NETBIOS, promoteForest } from '../win/ad';
import { FW_PROFILES, RDP_TCP_KEY, TS_KEY, type StartType, type WinFwRule, type WinService, type WinState } from '../win/model';

export const WIN01_IP = '10.0.20.30';
export const WIN01_ADMIN_PASSWORD = 'W1n-Adm1n-2026';
export const WIN01_ALICE_PASSWORD = 'Corp-Lab-2026';
export const DC01_IP = '10.0.20.5';
export const DC01_ADMIN_PASSWORD = 'Dc-Adm1n-2026';
/** alice's domain account (CORP\\alice), separate from her local account on win01. */
export const AD_ALICE_PASSWORD = 'Office-Corp-2026';

type Svc = [name: string, display: string, start: StartType, process: string, deps?: string[], prot?: boolean];

/** The services that matter in the lab (a real server has ~250). */
const SERVICES: Svc[] = [
  ['RpcSs', 'Remote Procedure Call (RPC)', 'Automatic', 'svchost', [], true],
  ['EventLog', 'Windows Event Log', 'Automatic', 'svchost', [], true],
  ['BFE', 'Base Filtering Engine', 'Automatic', 'svchost', ['RpcSs'], true],
  ['MpsSvc', 'Windows Defender Firewall', 'Automatic', 'svchost', ['BFE'], true],
  ['Dnscache', 'DNS Client', 'Automatic', 'svchost', [], true],
  ['W32Time', 'Windows Time', 'Automatic', 'svchost'],
  ['LanmanServer', 'Server', 'Automatic', 'System'],
  ['LanmanWorkstation', 'Workstation', 'Automatic', 'svchost'],
  ['TermService', 'Remote Desktop Services', 'Manual', 'svchost', ['RpcSs']],
  ['SessionEnv', 'Remote Desktop Configuration', 'Manual', 'svchost', ['RpcSs']],
  ['UmRdpService', 'Remote Desktop Services UserMode Port Redirector', 'Manual', 'svchost', ['TermService']],
  ['WinRM', 'Windows Remote Management (WS-Management)', 'Automatic', 'svchost', ['RpcSs']],
  ['W3SVC', 'World Wide Web Publishing Service', 'Automatic', 'svchost', ['WAS']],
  ['WAS', 'Windows Process Activation Service', 'Manual', 'svchost', ['RpcSs']],
  ['Spooler', 'Print Spooler', 'Automatic', 'spoolsv', ['RpcSs']],
  ['WinDefend', 'Microsoft Defender Antivirus Service', 'Automatic', 'MsMpEng', [], true],
  ['Netlogon', 'Netlogon', 'Manual', 'lsass', ['LanmanWorkstation']],
  ['RemoteRegistry', 'Remote Registry', 'Disabled', 'svchost', ['RpcSs']],
  ['wuauserv', 'Windows Update', 'Manual', 'svchost', ['RpcSs']],
  ['sshd', 'OpenSSH SSH Server', 'Disabled', 'sshd'],
];

function rule(name: string, displayName: string, group: string, protocol: WinFwRule['protocol'], localPort: WinFwRule['localPort'], enabled: boolean, extra: Partial<WinFwRule> = {}): WinFwRule {
  return { name, displayName, group, direction: 'Inbound', action: 'Allow', enabled, profiles: 'Any', protocol, localPort, remoteAddress: 'Any', builtIn: true, ...extra };
}

/** Built-in inbound rules of Windows Server 2022 that matter here (enabled as on a server with these roles). */
export function defaultFirewallRules(): WinFwRule[] {
  return [
    rule('RemoteDesktop-UserMode-In-TCP', 'Remote Desktop - User Mode (TCP-In)', 'Remote Desktop', 'TCP', ['3389'], true, { description: 'Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]', program: '%SystemRoot%\\system32\\svchost.exe' }),
    rule('RemoteDesktop-UserMode-In-UDP', 'Remote Desktop - User Mode (UDP-In)', 'Remote Desktop', 'UDP', ['3389'], true, { description: 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3389]' }),
    rule('FPS-SMB-In-TCP', 'File and Printer Sharing (SMB-In)', 'File and Printer Sharing', 'TCP', ['445'], true, { description: 'Inbound rule for File and Printer Sharing to allow Server Message Block transmission and reception via Named Pipes. [TCP 445]' }),
    rule('FPS-ICMP4-ERQ-In', 'File and Printer Sharing (Echo Request - ICMPv4-In)', 'File and Printer Sharing', 'ICMPv4', 'Any', false, { icmpType: '8', description: 'Echo Request messages are sent as ping requests to other nodes.' }),
    rule('FPS-ICMP6-ERQ-In', 'File and Printer Sharing (Echo Request - ICMPv6-In)', 'File and Printer Sharing', 'ICMPv6', 'Any', false, { icmpType: '128', description: 'Echo Request messages are sent as ping requests to other nodes.' }),
    rule('WINRM-HTTP-In-TCP', 'Windows Remote Management (HTTP-In)', 'Windows Remote Management', 'TCP', ['5985'], true, { profiles: ['Domain', 'Private'], description: 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]' }),
    rule('WINRM-HTTP-In-TCP-PUBLIC', 'Windows Remote Management (HTTP-In)', 'Windows Remote Management', 'TCP', ['5985'], true, { profiles: ['Public'], remoteAddress: ['LocalSubnet'], description: 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]' }),
    rule('IIS-WebServerRole-HTTP-In-TCP', 'World Wide Web Services (HTTP Traffic-In)', 'World Wide Web Services (HTTP)', 'TCP', ['80'], true, { description: 'An inbound rule to allow HTTP traffic for Internet Information Services (IIS) [TCP 80]' }),
    rule('CoreNet-ICMP4-DUFRAG-In', 'Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)', 'Core Networking', 'ICMPv4', 'Any', true, { icmpType: '3:4' }),
    rule('RemoteEventLogSvc-In-TCP', 'Remote Event Log Management (RPC)', 'Remote Event Log Management', 'TCP', ['RPC'], false),
    rule('OpenSSH-Server-In-TCP', 'OpenSSH SSH Server (sshd)', 'OpenSSH Server', 'TCP', ['22'], false),
  ];
}

export const IIS_START = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a>
</div>
</body>
</html>
`;

const WIN_HOSTS = `# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
`;

function winUser(name: string, uid: number, password: string, groups: string[], gecos: string): UserAccount {
  return { name, uid, gid: 513, primaryGroup: 'Users', groups, home: `C:\\Users\\${name}`, shell: 'powershell.exe', gecos, password };
}

export interface WinHostOptions {
  /** Web Server (IIS) role and the local account alice (win01). */
  iis?: boolean;
  adminPassword?: string;
  role?: string;
  readme?: string;
}

export function createWindowsHost(world: World, id: string, hostname: string, mac: string, segment: string, address: string, gateway: string, dns: string[], opts: WinHostOptions = { iis: true }): Host {
  const t = world.clock;
  const services: Record<string, WinService> = {};
  for (const [name, displayName, startType, process, deps, prot] of SERVICES) {
    if (!opts.iis && (name === 'W3SVC' || name === 'WAS')) continue;
    services[name] = { name, displayName, startType, status: 'Stopped', process, pid: null, dependsOn: deps ?? [], protected: prot };
  }
  const win: WinState = {
    productName: 'Windows Server 2022 Standard',
    build: '20348',
    workgroup: 'WORKGROUP',
    firewall: {
      profiles: Object.fromEntries(FW_PROFILES.map((p) => [p, { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow', logBlocked: false }])) as WinState['firewall']['profiles'],
      rules: defaultFirewallRules().filter((r) => opts.iis || !r.name.startsWith('IIS-')),
    },
    services,
    adapters: [{ alias: 'Ethernet0', ifIndex: 4, description: 'Microsoft Hyper-V Network Adapter', dhcp: false, address, prefix: 24, gateway, dns, dnsSuffix: 'corp.lab', category: 'Private' }],
    registry: {
      [TS_KEY]: { fDenyTSConnections: 0 },
      [RDP_TCP_KEY]: { PortNumber: 3389, UserAuthentication: 1, SecurityLayer: 2 },
      'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters': { Hostname: hostname.toUpperCase(), Domain: '', 'NV Domain': 'corp.lab' },
    },
    events: [],
    nextRecord: 1,
    features: ['FileAndStorage-Services', 'Storage-Services', 'NET-Framework-45-Core', 'PowerShell', 'Windows-Defender', ...(opts.iis ? ['Web-Server', 'Web-WebServer'] : [])],
  };
  const host: Host = {
    id, hostname: hostname.toUpperCase(), domain: 'corp.lab', osName: 'Microsoft Windows Server 2022 Standard', kind: 'windows',
    role: opts.role ?? 'Windows Server 2022 (IIS, Remote Desktop, SMB, WinRM)',
    users: {}, fs: {},
    ifaces: [
      { name: 'lo', mac: '00:00:00:00:00:00', segment: null, address: '127.0.0.1', prefix: 8, up: true, addrs6: [{ address: '::1', prefix: 128, scope: 'host', origin: 'kernel' }] },
      { name: 'Ethernet0', mac, segment, address: null, prefix: null, up: false, staticSegment: segment, addrs6: [] },
    ],
    routes: [], routes6: [], neighbors: [], nft: { tables: [], nextHandle: 1 }, conntrack: [], nat: [], ipForward: false, ip6Forward: false,
    services: {}, journal: [], capture: [], nextPid: 600, bootTime: t, win,
  };
  host.users.Administrator = winUser('Administrator', 500, opts.adminPassword ?? WIN01_ADMIN_PASSWORD, ['Administrators'], 'Built-in account for administering the computer/domain');
  host.users.Guest = { ...winUser('Guest', 501, '', ['Guests'], 'Built-in account for guest access to the computer/domain'), password: null };
  if (opts.iis) host.users.alice = winUser('alice', 1001, WIN01_ALICE_PASSWORD, ['Remote Desktop Users', 'Users'], 'Alice Admin');
  const dirs = ['C:\\', 'C:\\Windows', 'C:\\Windows\\System32', 'C:\\Windows\\System32\\drivers', 'C:\\Windows\\System32\\drivers\\etc', 'C:\\Windows\\System32\\LogFiles', 'C:\\Windows\\System32\\LogFiles\\Firewall', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData', 'C:\\Users', 'C:\\Users\\Public', 'C:\\Temp', 'C:\\Backup', ...(opts.iis ? ['C:\\inetpub', 'C:\\inetpub\\wwwroot', 'C:\\inetpub\\logs'] : [])];
  for (const d of dirs) mkdir(host, d, t, { owner: 'SYSTEM', group: 'SYSTEM' });
  for (const u of Object.keys(host.users).filter((x) => x !== 'Guest')) for (const d of ['', '\\Desktop', '\\Documents', '\\Downloads']) mkdir(host, `C:\\Users\\${u}${d}`, t, { owner: u, group: u });
  writeFile(host, 'C:\\Windows\\System32\\drivers\\etc\\hosts', WIN_HOSTS, t, { owner: 'SYSTEM', group: 'SYSTEM' });
  if (opts.iis) writeFile(host, 'C:\\inetpub\\wwwroot\\iisstart.htm', IIS_START, t, { owner: 'SYSTEM', group: 'SYSTEM' });
  writeFile(host, 'C:\\Users\\Administrator\\Desktop\\README.txt', opts.readme ?? 'win01 - Windows Server 2022\r\nRoles: Web Server (IIS), Remote Desktop, File Server (SMB), WinRM\r\nChanges: open a change ticket first (CHG-xxxx).\r\n', t, { owner: 'Administrator', group: 'Administrator' });
  world.hosts[id] = host;
  return host;
}

export function installWin01(world: World): Host {
  return createWindowsHost(world, 'win01', 'win01', '52:54:00:c3:00:1e', 'srv20', WIN01_IP, '10.0.20.1', ['10.0.10.53']);
}

/** dc01: a Windows Server 2022 that becomes (or, with promote, already is) the DC of ad.corp.lab. */
export function installDc01(world: World, promote: boolean): Host {
  const host = createWindowsHost(world, 'dc01', 'dc01', '52:54:00:c3:00:05', 'srv20', DC01_IP, '10.0.20.1', ['10.0.10.53'], {
    iis: false, adminPassword: DC01_ADMIN_PASSWORD, role: promote ? 'Windows Server 2022 domain controller (AD DS, DNS) for ad.corp.lab' : 'Windows Server 2022 (to become the domain controller)',
    readme: promote ? 'dc01 - domain controller for ad.corp.lab (NetBIOS CORP)\r\nRoles: AD DS, DNS Server (forwarder: ns1 10.0.10.53)\r\n' : 'dc01 - Windows Server 2022, freshly installed.\r\nPlanned: first domain controller of ad.corp.lab (NetBIOS CORP), with DNS.\r\n',
  });
  if (promote) {
    promoteForest(world, host, AD_DOMAIN, AD_NETBIOS);
    const ad = host.win!.ad!;
    ad.users.alice = { sam: 'alice', name: 'Alice Martin', enabled: true, password: AD_ALICE_PASSWORD, lockedOut: false, badCount: 0, description: 'Office, systems team', rid: ad.nextRid++ };
    ad.users.bob = { sam: 'bob', name: 'Bob Keller', enabled: true, password: 'Finance-Corp-2026', lockedOut: false, badCount: 0, description: 'Office, finance', rid: ad.nextRid++ };
    ad.groups['rdp-users'] = { name: 'RDP-Users', scope: 'Global', category: 'Security', description: 'May log on to member servers with Remote Desktop', members: ['alice'], rid: ad.nextRid++ };
  }
  return host;
}
