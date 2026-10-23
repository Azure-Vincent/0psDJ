// win01: a Windows Server 2022 member of the server network (VLAN 20), a VM on
// the virtualisation host whose virtual switch carries VLAN 20. It runs IIS,
// Remote Desktop, SMB and WinRM; administrators use PowerShell on its console.

import { mkdir, writeFile } from '../fs';
import type { Host, UserAccount, World } from '../types';
import { FW_PROFILES, RDP_TCP_KEY, TS_KEY, type StartType, type WinFwRule, type WinService, type WinState } from '../win/model';

export const WIN01_IP = '10.0.20.30';
export const WIN01_ADMIN_PASSWORD = 'W1n-Adm1n-2026';
export const WIN01_ALICE_PASSWORD = 'Corp-Lab-2026';

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

export function createWindowsHost(world: World, id: string, hostname: string, mac: string, segment: string, address: string, gateway: string, dns: string[]): Host {
  const t = world.clock;
  const services: Record<string, WinService> = {};
  for (const [name, displayName, startType, process, deps, prot] of SERVICES) services[name] = { name, displayName, startType, status: 'Stopped', process, pid: null, dependsOn: deps ?? [], protected: prot };
  const win: WinState = {
    productName: 'Windows Server 2022 Standard',
    build: '20348',
    workgroup: 'WORKGROUP',
    firewall: {
      profiles: Object.fromEntries(FW_PROFILES.map((p) => [p, { enabled: true, defaultInbound: 'Block', defaultOutbound: 'Allow', logBlocked: false }])) as WinState['firewall']['profiles'],
      rules: defaultFirewallRules(),
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
  };
  const host: Host = {
    id, hostname: hostname.toUpperCase(), domain: 'corp.lab', osName: 'Microsoft Windows Server 2022 Standard', kind: 'windows',
    role: 'Windows Server 2022 (IIS, Remote Desktop, SMB, WinRM)',
    users: {}, fs: {},
    ifaces: [
      { name: 'lo', mac: '00:00:00:00:00:00', segment: null, address: '127.0.0.1', prefix: 8, up: true, addrs6: [{ address: '::1', prefix: 128, scope: 'host', origin: 'kernel' }] },
      { name: 'Ethernet0', mac, segment, address: null, prefix: null, up: false, staticSegment: segment, addrs6: [] },
    ],
    routes: [], routes6: [], neighbors: [], nft: { tables: [], nextHandle: 1 }, conntrack: [], nat: [], ipForward: false, ip6Forward: false,
    services: {}, journal: [], capture: [], nextPid: 600, bootTime: t, win,
  };
  host.users.Administrator = winUser('Administrator', 500, WIN01_ADMIN_PASSWORD, ['Administrators'], 'Built-in account for administering the computer/domain');
  host.users.Guest = { ...winUser('Guest', 501, '', ['Guests'], 'Built-in account for guest access to the computer/domain'), password: null };
  host.users.alice = winUser('alice', 1001, WIN01_ALICE_PASSWORD, ['Remote Desktop Users', 'Users'], 'Alice Admin');
  const dirs = ['C:\\', 'C:\\Windows', 'C:\\Windows\\System32', 'C:\\Windows\\System32\\drivers', 'C:\\Windows\\System32\\drivers\\etc', 'C:\\Windows\\System32\\LogFiles', 'C:\\Windows\\System32\\LogFiles\\Firewall', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData', 'C:\\Users', 'C:\\Users\\Public', 'C:\\inetpub', 'C:\\inetpub\\wwwroot', 'C:\\inetpub\\logs', 'C:\\Temp', 'C:\\Backup'];
  for (const d of dirs) mkdir(host, d, t, { owner: 'SYSTEM', group: 'SYSTEM' });
  for (const u of ['Administrator', 'alice']) for (const d of ['', '\\Desktop', '\\Documents', '\\Downloads']) mkdir(host, `C:\\Users\\${u}${d}`, t, { owner: u, group: u });
  writeFile(host, 'C:\\Windows\\System32\\drivers\\etc\\hosts', WIN_HOSTS, t, { owner: 'SYSTEM', group: 'SYSTEM' });
  writeFile(host, 'C:\\inetpub\\wwwroot\\iisstart.htm', IIS_START, t, { owner: 'SYSTEM', group: 'SYSTEM' });
  writeFile(host, 'C:\\Users\\Administrator\\Desktop\\README.txt', 'win01 - Windows Server 2022\r\nRoles: Web Server (IIS), Remote Desktop, File Server (SMB), WinRM\r\nChanges: open a change ticket first (CHG-xxxx).\r\n', t, { owner: 'Administrator', group: 'Administrator' });
  world.hosts[id] = host;
  return host;
}

export function installWin01(world: World): Host {
  return createWindowsHost(world, 'win01', 'win01', '52:54:00:c3:00:1e', 'srv20', WIN01_IP, '10.0.20.1', ['10.0.10.53']);
}
