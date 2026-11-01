// Lesson: Windows Server administration and RDP. The examples follow a domain
// (corp.lab, member server app01 10.0.20.21, DC dc01 10.0.20.5, client WS01
// 10.0.10.25) and are representative of Windows Server 2022 and Windows 11
// 23H2. The sandbox and the tickets use the simulated standalone server win01
// (10.0.20.30) with Windows PowerShell 5.1; tasks marked sim run there.

import type { Assessment, Lesson, ServiceGuide } from '../types';

export const WINDOWS_RDP_GUIDE: ServiceGuide = {
  purpose:
    'Remote Desktop Services (service name **TermService**) lets an administrator or user run an interactive Windows desktop on a remote machine over the Remote Desktop Protocol (RDP). A listener (**RDP-Tcp**) accepts connections on TCP and UDP 3389, the connection is protected by TLS, the user is authenticated **before** a session is created when Network Level Authentication (NLA, implemented with CredSSP) is required, the Local Security Authority checks the **user right** "Allow log on through Remote Desktop Services", and Winlogon builds a desktop session. Each of those steps depends on something else (the service, the listener, the firewall, DNS, a domain controller, synchronised time, Group Policy) and each fails with its own message. All example output in this lesson is representative of **Windows Server 2022** and **Windows 11 23H2** in a domain. Tasks marked "in simulator" also run on the lab\'s simulated Windows server **win01** (Windows PowerShell 5.1); domain logons run in the simulated domain ad.corp.lab (dc01; see Lab 2), while Group Policy objects and Kerberos for Windows logons are not simulated.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Graphical remote administration and remote work: a full desktop session (or single RemoteApp programs on an RD Session Host farm) with redirected clipboard, drives, printers, audio and smart cards. On Windows Server, up to **two concurrent administrative sessions** are allowed without RDS licensing ("Remote Desktop for Administration"); more sessions for users need the RD Session Host role and RDS CALs. Windows 10/11 Pro/Enterprise allow one session at a time.' },
    { q: 'How does it work internally?', a: '**TermService** (display name "Remote Desktop Services", a svchost-hosted service running as NETWORK SERVICE) owns the **listener** (a "WinStation" named RDP-Tcp, configured under `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp`). For each connection it negotiates the security protocol, runs TLS and (with NLA) CredSSP, then asks the Local Session Manager (part of the OS session infrastructure) to create a session: a new `csrss.exe` and `winlogon.exe`, then the user\'s shell. **UmRdpService** ("Remote Desktop Services UserMode Port Redirector") handles redirection of drives, printers and ports and depends on TermService. **SessionEnv** ("Remote Desktop Configuration") manages configuration and certificate tasks.' },
    { q: 'Which protocols does it use?', a: 'RDP (Microsoft MS-RDPBCGR) over TCP, optionally with a UDP transport (RDP 8.0+) for better performance on lossy links; X.224 connection request with an RDP Negotiation Request listing the security protocols the client supports (standard RDP security, TLS, CredSSP/"HYBRID"); **TLS** for encryption and server authentication; **CredSSP** (MS-CSSP) for NLA, which carries SPNEGO, that is **Kerberos** (preferred, needs a DC, DNS and time within 5 minutes) or **NTLM** (fallback, for IP addresses, workgroups, or when Kerberos fails).' },
    { q: 'Which ports and transport?', a: 'TCP **3389** and UDP **3389** on the server (the port is `PortNumber` in the RDP-Tcp key; changing it needs a TermService restart and a new firewall rule). The client uses ephemeral ports. Authentication against Active Directory uses the DC: DNS 53, Kerberos TCP/UDP 88, LDAP 389, and for Group Policy SMB 445 to SYSVOL. Remote PowerShell (WinRM) uses TCP 5985 (HTTP) / 5986 (HTTPS) and is the best way to repair RDP without RDP.' },
    { q: 'Which processes and OS components implement it?', a: '`svchost.exe` hosting **TermService**; **UmRdpService** and **SessionEnv**; `lsass.exe` (LSA: authentication, CredSSP, user rights checks); per session `csrss.exe`, `winlogon.exe`, `LogonUI.exe` and `rdpclip.exe` (clipboard); **Windows Defender Firewall** (rules in the "Remote Desktop" group); **Group Policy** client (applies RDS settings and user rights); the client `mstsc.exe` (Remote Desktop Connection) on Windows.' },
    { q: 'Which other services does it depend on?', a: 'TermService requires **RPCSS** (Remote Procedure Call). For a useful connection: an IP route between client and server; **DNS** for the name (and for finding a DC); the **firewall** rules for 3389; for domain accounts a **reachable domain controller**, a working **secure channel** between the server and the domain, and **time** within 5 minutes (Kerberos); **Group Policy** for the RDS policy settings and the user rights; a server **certificate** for TLS (a self-signed one is generated automatically in the "Remote Desktop" certificate store).' },
    { q: 'How do requests travel?', a: 'Client resolves `app01.corp.lab` → TCP handshake to 3389 → X.224 Connection Request with the requested protocols → Connection Confirm with the selected protocol (CredSSP if NLA is required) → TLS handshake, the server presents its certificate → CredSSP: the client obtains a Kerberos service ticket for `TERMSRV/app01.corp.lab` (or uses NTLM) and authenticates; the client then delegates the user\'s credentials to the server → the server logs the user on: LSA checks the right "Allow log on through Remote Desktop Services" and the absence of "Deny log on through ..." → a session is created and the desktop is sent as graphics updates. See the sequence below.' },
    { q: 'How do authentication and authorisation work?', a: '**Authentication** happens in CredSSP before the session exists (with NLA): the credentials are checked by the server\'s LSA, which for a domain account asks a DC (Kerberos or NTLM pass-through). A wrong password fails here. Without NLA, the server first creates a session and shows the Windows sign-in screen inside it (more resource use and attack surface). **Authorisation** is the user right **SeRemoteInteractiveLogonRight** ("Allow log on through Remote Desktop Services"), granted by default on member servers to **Administrators** and **Remote Desktop Users**, and on domain controllers to Administrators only, minus **SeDenyRemoteInteractiveLogonRight** ("Deny log on through Remote Desktop Services"), which always wins. Both are normally set by Group Policy (Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment).' },
    { q: 'How does it start at boot?', a: 'The Service Control Manager starts services according to their startup type and dependencies. RDP is accepted when TermService runs, the listener is enabled (`fDenyTSConnections` = 0, or the policy value under `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services`, which overrides it), and the firewall allows 3389 in the **current network profile** (Domain, Private or Public). A server that boots without reaching a DC may select the **Public** profile, where rules enabled only for Domain do not apply. Group Policy is re-applied at boot and every 90 minutes (± 30) afterwards, so a manual change that contradicts a GPO is reverted.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'All RDP sessions are disconnected (users\' processes keep running in disconnected sessions as long as the session infrastructure survives; reconnecting later resumes them). The SCM logs **7031** ("terminated unexpectedly ... The following corrective action will be taken ...") or **7034** (no recovery action configured) in the System log and applies the service\'s recovery actions. While it is down, clients get "Remote Desktop can\'t connect to the remote computer". **Stopping or restarting it deliberately has the same effect, including on your own RDP session**: restart it from the console, the hypervisor or iLO/iDRAC, or remotely over WinRM.' },
  ],
  ports: [
    { port: '3389', proto: 'TCP', purpose: 'RDP listener RDP-Tcp (PortNumber in the registry)' },
    { port: '3389', proto: 'UDP', purpose: 'RDP UDP transport (optional, RDP 8.0+); TCP alone still works' },
    { port: '5985 / 5986', proto: 'TCP', purpose: 'WinRM HTTP / HTTPS: PowerShell remoting, used to repair RDP remotely' },
    { port: '88', proto: 'TCP/UDP', purpose: 'Kerberos to the domain controller (NLA with domain accounts)' },
    { port: '53', proto: 'UDP/TCP', purpose: 'DNS: the server name and the DC SRV records (_kerberos._tcp, _ldap._tcp)' },
    { port: '389 / 445', proto: 'TCP/UDP / TCP', purpose: 'LDAP and SMB (SYSVOL) to the DC for Group Policy' },
  ],
  processes: [
    { name: 'svchost.exe (TermService)', platform: 'Windows Server 2019/2022, Windows 10/11 Pro', role: 'Remote Desktop Services: listener, protocol, TLS, session brokering. Runs as NT AUTHORITY\\NetworkService. Find its PID with `sc.exe queryex TermService`.' },
    { name: 'UmRdpService', platform: 'Windows', role: 'Remote Desktop Services UserMode Port Redirector: device redirection; depends on TermService, so it stops when TermService stops.' },
    { name: 'SessionEnv', platform: 'Windows', role: 'Remote Desktop Configuration: configuration and certificate housekeeping for RDS.' },
    { name: 'lsass.exe', platform: 'Windows', role: 'Local Security Authority: CredSSP/NLA, Kerberos/NTLM, user rights (SeRemoteInteractiveLogonRight) checks, Security log events 4624/4625.' },
    { name: 'winlogon.exe, LogonUI.exe, csrss.exe, rdpclip.exe', platform: 'Windows (per session)', role: 'Created for each RDP session: logon, the session subsystem and clipboard redirection.' },
    { name: 'mstsc.exe', platform: 'Windows 10/11, Windows Server', role: 'Remote Desktop Connection client; settings in .rdp files (e.g. `%USERPROFILE%\\Documents\\Default.rdp`, hidden).' },
    { name: 'xrdp, xrdp-sesman', platform: 'Linux (Debian/Ubuntu, RHEL via EPEL)', role: 'Open-source RDP server for Linux desktops; not part of Windows RDS.' },
  ],
  dependencies: {
    title: 'What an RDP logon to app01 depends on (top needs everything below it)',
    caption: 'Work bottom-up from the client (name → route → TCP 3389), then the server stages (service → listener → NLA → user rights → session). The client\'s error text tells you which row failed.',
    rows: [
      { label: 'Session', nodes: [{ id: 'session', label: 'Desktop session', sub: 'winlogon, LSM 21/22', kind: 'os' }] },
      { label: 'Authorise', nodes: [{ id: 'rights', label: 'User rights', sub: 'Allow log on via RDS', kind: 'service' }, { id: 'gpo', label: 'Group Policy', sub: 'gpresult /r', kind: 'data' }, { id: 'group', label: 'RD Users group', sub: 'Remote Desktop Users', kind: 'data' }] },
      { label: 'Authenticate', nodes: [{ id: 'nla', label: 'NLA / CredSSP', sub: 'TLS + Kerberos/NTLM', kind: 'service' }, { id: 'dc', label: 'Domain controller', sub: 'Kerberos 88, time', kind: 'external' }, { id: 'cert', label: 'TLS certificate', sub: 'Remote Desktop store', kind: 'data' }] },
      { label: 'Service', nodes: [{ id: 'term', label: 'TermService', sub: 'Remote Desktop Svcs', kind: 'service' }, { id: 'listener', label: 'RDP-Tcp listener', sub: 'fDeny=0, port 3389', kind: 'data' }, { id: 'fw', label: 'Windows Firewall', sub: 'Remote Desktop group', kind: 'network' }] },
      { label: 'Network', nodes: [{ id: 'dns', label: 'Name resolution', sub: 'DNS app01.corp.lab', kind: 'network' }, { id: 'route', label: 'Route + ARP', sub: 'default gateway', kind: 'network' }, { id: 'tcp', label: 'TCP connect', sub: 'port 3389', kind: 'network' }] },
    ],
    edges: [
      ['session', 'rights'], ['rights', 'gpo'], ['rights', 'group'], ['rights', 'nla'],
      ['nla', 'dc'], ['nla', 'cert'], ['nla', 'listener'], ['dc', 'dns'],
      ['listener', 'term'], ['tcp', 'fw'], ['fw', 'listener'], ['tcp', 'route'], ['route', 'dns'],
    ],
  },
  sequence: {
    title: 'mstsc /v:app01.corp.lab with NLA: messages and where each failure appears',
    caption: 'Representative of a Windows 11 23H2 client, a Windows Server 2022 member server and a Server 2022 DC.',
    lanes: [{ id: 'c', label: 'WS01', sub: 'mstsc, CORP\\h.lee' }, { id: 'd', label: 'dc01', sub: 'DNS + KDC' }, { id: 's', label: 'app01', sub: 'TermService + LSA' }],
    steps: [
      { from: 'c', to: 'd', label: 'DNS A? app01.corp.lab', note: 'No answer → "Remote Desktop can\'t find the computer app01.corp.lab".' },
      { from: 'd', to: 'c', label: 'A 10.0.20.21' },
      { from: 'c', to: 's', label: 'TCP SYN :3389', note: 'Dropped by a firewall, no route, RDP disabled, TermService stopped or listener on another port → "Remote Desktop can\'t connect to the remote computer for one of these reasons".', fail: true },
      { from: 'c', to: 's', label: 'X.224 request: TLS, CredSSP', note: 'Server requires NLA, client cannot do CredSSP → "The remote computer requires Network Level Authentication, which your computer does not support".' },
      { from: 's', to: 'c', label: 'TLS: server certificate', note: 'Self-signed or wrong name → "The identity of the remote computer cannot be verified" prompt.' },
      { from: 'c', to: 'd', label: 'Kerberos TGS TERMSRV/app01', note: 'DC unreachable, clock skew > 5 min → NTLM fallback or "There is a time and/or date difference between the client and server".' },
      { from: 'c', to: 's', label: 'CredSSP: authenticate', note: 'Wrong password → "The logon attempt failed" (RdpCoreTS 140, Security 4625). Patch mismatch → "This could be due to CredSSP encryption oracle remediation".' },
      { from: 's', to: 's', label: 'LSA: SeRemoteInteractiveLogon', note: 'No right or a Deny entry → "To sign in remotely, you need the right to sign in through Remote Desktop Services" (4625 status 0xC000015B).' },
      { from: 's', to: 'c', label: 'Session created, desktop', note: 'Success: RCM 1149, Security 4624 logon type 10, LSM 21 and 22.' },
    ],
  },
  files: [
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', platform: 'Windows Server 2019/2022, Windows 10/11', kind: 'registry', perms: 'Administrators and SYSTEM: Full Control', contains: '`fDenyTSConnections` (DWORD): **1 = RDP connections refused** (the default on a fresh Windows Server install), 0 = allowed. Set by System Properties > Remote, Settings > System > Remote Desktop, `sconfig`, or directly.', accessed: 'Watched by TermService: the listener is enabled or disabled when the value changes.', problems: 'A value of 1 means no listener on 3389: clients get "can\'t connect". A Group Policy value under `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\fDenyTSConnections` overrides this one, and the GUI then shows the setting greyed out.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', platform: 'Windows', kind: 'registry', perms: 'Administrators and SYSTEM', contains: '`PortNumber` (DWORD, 3389), `UserAuthentication` (1 = NLA required), `SecurityLayer` (0 = RDP security, 1 = negotiate, 2 = TLS), `SSLCertificateSHA1Hash` (certificate to use), `MinEncryptionLevel`.', accessed: 'When TermService starts and when the listener is (re)created.', problems: 'Changing PortNumber needs a TermService restart and a firewall rule for the new port (the built-in rules allow only 3389). A deleted or corrupted key removes the listener: `qwinsta` no longer shows rdp-tcp. Export the key before editing.' },
    { path: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', platform: 'Windows (written by Group Policy)', kind: 'registry', contains: 'Policy versions of RDS settings: `fDenyTSConnections`, `UserAuthentication`, `SecurityLayer`, session limits.', accessed: 'Rewritten at every Group Policy refresh (boot and every ~90 minutes).', problems: 'Wins over the non-policy values. Manual changes to the non-policy key appear to work and are ignored, or are reverted at the next refresh. Use `gpresult /h` to find the GPO.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService', platform: 'Windows', kind: 'registry', contains: '`Start` (2 automatic, 3 manual, 4 disabled), `DependOnService` (RPCSS), `ObjectName` (NT Authority\\NetworkService), recovery `FailureActions`.', accessed: 'By the SCM at boot and on start.', problems: '`Start` = 4 (disabled) prevents the service from starting at all (error 1058, "The service cannot be started, either because it is disabled ..."). Event 7040 in the System log records start-type changes.' },
    { path: '%SystemRoot%\\System32\\winevt\\Logs\\', platform: 'Windows', kind: 'eventlog', perms: 'Read via Event Log service; Security log needs Administrators or Event Log Readers + audit privilege', contains: '`System.evtx` (Service Control Manager 7000/7001/7009/7031/7034/7036/7040), `Security.evtx` (4624/4625/4634/4647/4778/4779), `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` (1149), `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` (21, 22, 23, 24, 25), `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx` (131, 140).', accessed: 'Written continuously; read with Event Viewer (`eventvwr.msc`) or `Get-WinEvent`.', problems: 'Logs are size-limited and wrap; export with `wevtutil epl Security C:\\Temp\\sec.evtx` before they roll over during an investigation.' },
    { path: 'Cert:\\LocalMachine\\Remote Desktop', platform: 'Windows', kind: 'cert', contains: 'The self-signed certificate RDS creates (CN = the computer\'s FQDN), or one deployed by Group Policy / an enterprise CA template.', accessed: 'At every TLS handshake.', problems: 'An expired or deleted certificate is regenerated automatically; a wrong `SSLCertificateSHA1Hash` or a certificate whose private key NETWORK SERVICE cannot read breaks TLS. Clients that do not trust a self-signed certificate show "The identity of the remote computer cannot be verified".' },
    { path: '\\\\corp.lab\\SYSVOL\\corp.lab\\Policies\\{GUID}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', platform: 'Active Directory', kind: 'config', contains: 'User Rights Assignment from a GPO, e.g. `SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555` (Administrators, Remote Desktop Users) and `SeDenyRemoteInteractiveLogonRight`.', accessed: 'Downloaded at Group Policy refresh.', problems: 'A GPO that sets this right **replaces** the whole list on every server it applies to: a baseline that lists only Administrators silently removes Remote Desktop Users (case study F).' },
    { path: '%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log', platform: 'Windows', kind: 'log', contains: 'Allowed/dropped connections, if logging is enabled per profile (it is off by default).', accessed: 'Written while logging is enabled.', problems: 'Enable it temporarily: `Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True`. Without it, a firewall drop leaves no trace except the client timeout.' },
    { path: 'WSMan:\\localhost\\Client\\TrustedHosts', platform: 'Windows (WinRM client)', kind: 'config', contains: 'Hosts the WinRM client may authenticate to without Kerberos (by IP, in a workgroup).', accessed: 'When opening a remoting session that cannot use Kerberos.', problems: 'Needed only outside the domain or by IP. Setting it to `*` disables a protection against connecting to an impostor; use specific names, or HTTPS (5986).' },
  ],
  management: [
    {
      platform: 'Windows Server 2019/2022',
      tasks: [
        { task: 'Is it running?', sim: true, command: 'Get-Service TermService, UmRdpService, SessionEnv\nsc.exe queryex TermService', explain: '`Get-Service` shows Status and DisplayName; `sc.exe queryex` adds the PID (to match with `Get-NetTCPConnection`). In PowerShell always type `sc.exe`: plain `sc` is an alias of Set-Content.' },
        { task: 'Start / stop', sim: true, command: 'Start-Service TermService\nStop-Service TermService -Force', explain: 'Starting re-creates the listener. Stopping requires `-Force` because UmRdpService depends on it.', risk: 'Stopping TermService disconnects **every** RDP session, including yours. Do it from the console, the hypervisor, iLO/iDRAC, or over WinRM.' },
        { task: 'Restart', sim: true, command: 'Restart-Service TermService -Force\nGet-Service TermService, UmRdpService', explain: 'Stops TermService and its dependent UmRdpService, then starts them again. Needed after changing PortNumber or the certificate, or when the listener is stuck. Without `-Force`: "Cannot stop service ... because it has dependent services".', risk: 'Disconnects all sessions. Users\' disconnected sessions normally survive and can be reconnected, but warn them first.' },
        { task: 'Restart it without RDP', command: 'Invoke-Command -ComputerName app01 -ScriptBlock { Restart-Service TermService -Force; Get-Service TermService, UmRdpService }', explain: 'Runs over WinRM (TCP 5985), which is a different service: it keeps working while RDS restarts. Check first with `Test-WSMan app01`.' },
        { task: '"Reload" configuration', command: 'gpupdate /force\nSet-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 0', explain: 'There is no reload for TermService. Policy changes are applied with `gpupdate /force`; `fDenyTSConnections` is picked up without a restart; port and certificate changes need a TermService restart.' },
        { task: 'Enable / disable at boot', sim: true, command: 'Set-Service TermService -StartupType Manual\nGet-Service TermService | Select-Object Name, Status, StartType', explain: 'Status is "now", StartType is "at boot". Do not set TermService to Disabled to "turn RDP off": use fDenyTSConnections or the GPO, which is what the GUI does.' },
        { task: 'Failed services and why', sim: true, command: 'Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName="Service Control Manager"; Id=7000,7001,7009,7031,7034,7040} -MaxEvents 20 | Format-List TimeCreated, Id, Message', explain: '7000 failed to start (with the Win32 error), 7001 a dependency failed, 7009 start timeout, 7031/7034 crashed, 7040 start type changed (who disabled it?).' },
        { task: 'Dependencies', sim: true, command: 'Get-Service TermService -RequiredServices\nGet-Service TermService -DependentServices\nsc.exe qc TermService', explain: 'Required: RPCSS. Dependent: UmRdpService. `sc.exe qc` shows START_TYPE, DEPENDENCIES and the service account.' },
        { task: 'Recent RDP logs', sim: true, command: 'Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 20\nGet-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -MaxEvents 20\nGet-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 10 | Format-List', explain: 'LSM: logons 21, logoffs 23, disconnects 24, reconnects 25. RCM 1149: a user authenticated at the network level. Security 4625: why a logon failed (Status/Sub Status, Logon Type).' },
        { task: 'Is it listening?', sim: true, command: 'qwinsta\nGet-NetTCPConnection -LocalPort 3389 -State Listen\nnetstat -ano | findstr :3389', explain: '`qwinsta` (query session) must show **rdp-tcp ... Listen**. The TCP listener PID should be TermService\'s PID.' },
        { task: 'Firewall', sim: true, command: 'Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table DisplayName, Enabled, Profile, Action\nGet-NetConnectionProfile\nEnable-NetFirewallRule -DisplayGroup "Remote Desktop"', explain: 'The three rules are "Remote Desktop - User Mode (TCP-In)", "(UDP-In)" and "Remote Desktop - Shadow (TCP-In)". `Get-NetConnectionProfile` shows which profile (DomainAuthenticated, Private, Public) is active.' },
        { task: 'Restore after a config error', command: 'reg import C:\\Backup\\rdp-tcp.reg\nRestart-Service TermService -Force', explain: 'Re-imports the exported RDP-Tcp key (port, NLA, security layer) and recreates the listener. Run it from the console or WinRM.', risk: 'Restart disconnects sessions.' },
      ],
    },
    {
      platform: 'Windows 10/11',
      tasks: [
        { task: 'Can this edition host RDP?', command: 'Get-ComputerInfo -Property WindowsProductName, WindowsEditionId', explain: 'Only **Pro, Enterprise and Education** can accept RDP connections. **Home** has the client (mstsc) but no RDP host: there is no Remote Desktop toggle in Settings.' },
        { task: 'Enable / disable', command: 'Settings > System > Remote Desktop > Remote Desktop: On', explain: 'Sets fDenyTSConnections = 0, enables the firewall rules, and (by default) requires NLA. Only one session at a time: a remote logon locks out the local user.' },
        { task: 'Client-side checks', command: 'Resolve-DnsName app01.corp.lab\nTest-NetConnection app01.corp.lab -Port 3389\nmstsc /v:app01.corp.lab', explain: 'Name, TCP reachability, then the connection. `mstsc /admin` connects to the console/administrative session.' },
        { task: 'Clear saved credentials', command: 'cmdkey /list\ncmdkey /delete:TERMSRV/app01.corp.lab', explain: 'A stale saved password produces repeated "The logon attempt failed" (and can lock the account).' },
      ],
    },
    {
      platform: 'Linux (xrdp)',
      tasks: [
        { task: 'Status and logs', command: 'systemctl status xrdp xrdp-sesman\njournalctl -u xrdp -n 50\ntail /var/log/xrdp.log /var/log/xrdp-sesman.log', explain: 'xrdp listens on 3389 and hands sessions to xrdp-sesman, which starts an X session. On Debian/Ubuntu the xrdp user must be in group `ssl-cert` to read the TLS key (`adduser xrdp ssl-cert`).' },
        { task: 'Restart', command: 'sudo systemctl restart xrdp', explain: 'Unlike Windows RDS, existing X sessions normally survive (they belong to sesman), but connected clients are dropped.' },
      ],
    },
  ],
  actions: [
    { action: 'Disconnect / log off one session (tsdiscon, logoff <id>, Task Manager > Users)', when: 'A user\'s session is hung, or the two administrative sessions are in use ("The number of connections to this computer is limited").', effect: 'Only that session; `logoff` ends its programs, disconnect keeps them running.', risk: 'Lowest. Unsaved work in a logged-off session is lost.' },
    { action: 'Apply policy (gpupdate /force) or change fDenyTSConnections', when: 'After changing RDS policy, user rights or enabling RDP.', effect: 'Settings are re-read; existing sessions continue.', risk: 'A GPO can still override local changes; verify with gpresult.' },
    { action: 'Restart-Service TermService -Force', when: 'Listener missing or stuck, PortNumber/certificate changed, TermService hung.', effect: 'Stops TermService and UmRdpService, starts them again; all RDP connections drop, disconnected sessions usually remain.', risk: 'Disconnects **your** RDP session too. Use console, hypervisor, iLO/iDRAC, or `Invoke-Command` over WinRM.' },
    { action: 'Restart-NetAdapter / disable-enable the NIC', when: 'Only when the adapter itself is wedged or its IP configuration changed.', effect: 'All network connections on that adapter drop; DHCP and DNS registration repeat; the firewall profile may be re-detected.', risk: 'You lose remote access if the adapter does not come back as expected; never from an RDP session over that adapter without a console.' },
    { action: 'Reboot (Restart-Computer)', when: 'Updates, or when services cannot be recovered individually, in a maintenance window.', effect: 'Everything restarts; Group Policy and the firewall profile are re-evaluated.', risk: 'Longest outage for every user of the server; if RDP was broken by policy or a disabled service, it stays broken after the reboot. Not a diagnostic step.' },
  ],
  workflow: [
    { question: 'What exactly does the client say?', why: 'Each stage of RDP fails with its own message. Reading it exactly saves you from checking the wrong stage.', command: 'mstsc /v:app01.corp.lab', healthy: 'The desktop of app01 appears.', broken: '"can\'t find the computer" → DNS. "can\'t connect to the remote computer for one of these reasons" → network, firewall, RDP disabled, service or listener. "requires Network Level Authentication" / "CredSSP" → NLA. "The logon attempt failed" → credentials. "you need the right to sign in through Remote Desktop Services" / "not authorized for remote login" → user rights.', next: 'Jump to the step for that layer; for "can\'t connect", go through steps 2–8 in order.' },
    { question: 'Does the name resolve to the right address?', why: 'The client must find the right server first. A stale DNS record sends you to another machine.', command: 'Resolve-DnsName app01.corp.lab', healthy: 'Name           Type TTL  Section IPAddress\n----           ---- ---  ------- ---------\napp01.corp.lab A    1200 Answer  10.0.20.21', broken: '"DNS name does not exist" → missing record or wrong suffix. A different IP → stale record (DHCP-registered server, re-IPed host); RDP goes to the wrong machine or nowhere.', next: 'Correct → step 3. Test also `mstsc /v:10.0.20.21` to bypass DNS (NLA then uses NTLM).' },
    { question: 'Is there a route to the server?', why: 'Packets need a path to the server and back before any port can be tested.', command: 'Test-NetConnection app01.corp.lab -TraceRoute', healthy: 'PingSucceeded : True\nTraceRoute    : 10.0.10.1\n                10.0.20.21', broken: 'Stops at the gateway or earlier → routing problem (client gateway, router, server\'s own gateway for the return path). Note: ICMP may be blocked while 3389 works.', next: 'Then test the port itself (step 4).' },
    { question: 'Can a TCP connection to 3389 be established?', why: 'This tests exactly the TCP connection RDP uses. Refused and timed out point to different causes.', command: 'Test-NetConnection app01.corp.lab -Port 3389', healthy: 'ComputerName     : app01.corp.lab\nRemoteAddress    : 10.0.20.21\nRemotePort       : 3389\nSourceAddress    : 10.0.10.25\nTcpTestSucceeded : True', broken: 'WARNING: TCP connect to (10.0.20.21 : 3389) failed\nPingSucceeded : True\nTcpTestSucceeded : False\n→ host up but nothing accepts 3389: firewall, RDP disabled, TermService stopped, or the listener is on another port. Continue on the server via console or WinRM.', next: 'Succeeded → skip to step 8 (NLA). Failed → steps 5–7 on the server.' },
    { question: 'Is Remote Desktop enabled (and not overridden by policy)?', why: 'RDP can be switched off in the registry, and a Group Policy setting overrides the local one.', sim: true, command: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections\nreg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v fDenyTSConnections', healthy: 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\n    fDenyTSConnections    REG_DWORD    0x0\nERROR: The system was unable to find the specified registry key or value.', broken: '`0x1` in the first key → RDP disabled. A policy value of `0x1` → a GPO disables RDP (fix the GPO, not the local key).', next: 'Enable with `Set-ItemProperty ... fDenyTSConnections 0` (or sconfig option 7), then step 6.' },
    { question: 'Is Remote Desktop Services running?', why: 'TermService is the program that answers RDP connections. The System log records why it failed to start or stopped.', sim: true, command: 'Get-Service TermService, UmRdpService, SessionEnv | Format-Table Name, Status, StartType', healthy: 'Name         Status StartType\n----         ------ ---------\nTermService  Running    Manual\nUmRdpService Running    Manual\nSessionEnv   Running    Manual', broken: 'TermService Stopped (StartType Disabled → someone disabled it: event 7040). Look at System events 7000/7031/7034 for why it stopped.', next: '`Set-Service TermService -StartupType Manual; Start-Service TermService`, then step 7.' },
    { question: 'Is the listener present, and on which port?', why: 'The listener must exist and listen on the port clients use. A changed PortNumber moves it away from 3389.', sim: true, command: 'qwinsta\nGet-NetTCPConnection -LocalPort 3389 -State Listen\nreg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v PortNumber', healthy: ' SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n services                                    0  Disc\n>console           Administrator             1  Active\n rdp-tcp                                 65536  Listen\n\n    PortNumber    REG_DWORD    0xd3d', broken: 'No `rdp-tcp ... Listen` line → listener missing (RDP disabled, corrupted RDP-Tcp key, TermService not running). PortNumber not 0xd3d (3389) → port changed: clients must use `app01:<port>` and the firewall must allow it.', next: 'Fix the key or port (restore the exported .reg), `Restart-Service TermService -Force`, then step 8.' },
    { question: 'Does the firewall allow 3389 in the active profile?', why: 'Windows applies firewall rules per profile. A rule enabled only for the Domain profile does nothing while the network counts as Public.', sim: true, command: 'Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table DisplayName, Enabled, Profile, Action\nGet-NetConnectionProfile | Format-Table InterfaceAlias, NetworkCategory', healthy: 'DisplayName                          Enabled Profile Action\nRemote Desktop - User Mode (TCP-In)     True     Any  Allow\nRemote Desktop - User Mode (UDP-In)     True     Any  Allow\n\nInterfaceAlias NetworkCategory\nEthernet       DomainAuthenticated', broken: 'Enabled False → `Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`. Profile Domain only while the category is Public (server did not detect the domain) → the rule does not apply. A GPO-delivered block rule wins over local allows.', next: 'If TCP 3389 now connects, continue with authentication (step 9).' },
    { question: 'Does NLA/authentication succeed?', why: 'With NLA, the password is checked before any desktop exists. For domain accounts, this needs the domain controller, DNS and correct time.', command: 'Get-WinEvent -LogName "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" -MaxEvents 10\nnltest /sc_query:corp.lab\nw32tm /query /status', healthy: '131 The server accepted a new TCP connection from client 10.0.10.25:52144.\nTrusted DC Connection Status Status = 0 0x0 NERR_Success\nSource: dc01.corp.lab', broken: '140 "failed because the user name or password is not correct" → credentials. Secure channel broken ("The trust relationship ... failed", nltest error) or DC unreachable → domain accounts fail NLA ("The Local Security Authority cannot be contacted"). Clock off by more than 5 minutes → Kerberos fails. CredSSP message on the client → patch levels differ (update the unpatched side; do not weaken the Encryption Oracle Remediation policy).', next: 'Authentication OK but logon refused → step 10.' },
    { question: 'Is the user allowed to log on through RDS?', why: 'Even with a correct password, the user needs the right to log on through Remote Desktop, usually through Remote Desktop Users or a GPO.', command: 'Get-LocalGroupMember -Group "Remote Desktop Users"\ngpresult /r /scope computer\nGet-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 5 | Format-List', healthy: 'ObjectClass Name                  PrincipalSource\nGroup       CORP\\Helpdesk         ActiveDirectory\n\nApplied Group Policy Objects: ... Default Domain Policy', broken: '4625 with "Logon Type: 10", "Failure Reason: The user has not been granted the requested logon type at this machine", "Status: 0xC000015B" → user right missing or a Deny entry. The GPO list from `gpresult` shows which baseline set it; `gpresult /h C:\\Temp\\gp.html` shows the winning GPO per setting.', next: 'Fix in the GPO (User Rights Assignment), `gpupdate /force`, retest. Then verify the session (LSM 21/22).' },
  ],
  failures: [
    { symptom: 'Remote Desktop can\'t connect to the remote computer for one of these reasons (RDP disabled)', causes: ['fDenyTSConnections = 1 (fresh server, or turned off)', 'Group Policy "Allow users to connect remotely by using Remote Desktop Services" = Disabled'], diagnose: ['reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v fDenyTSConnections', 'qwinsta (no rdp-tcp Listen line)'], fix: 'Enable locally (sconfig 7, SystemPropertiesRemote, or `Set-ItemProperty ... fDenyTSConnections 0` + `Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`) or fix the GPO that disables it.', verify: 'qwinsta shows rdp-tcp Listen; Test-NetConnection app01 -Port 3389 → TcpTestSucceeded True' },
    { symptom: 'Same "can\'t connect" error; TermService stopped', causes: ['service stopped by an admin or a script', 'StartType Disabled (event 7040)', 'crashed (7031/7034) or failed to start (7000/7001: dependency RPCSS)'], diagnose: ['Get-Service TermService, UmRdpService', 'Get-WinEvent System, Service Control Manager 7000/7031/7034/7036/7040', 'sc.exe qc TermService'], fix: 'Restore the startup type (Manual is the default), `Start-Service TermService` from the console or `Invoke-Command`; investigate why it stopped from the events.', verify: 'Get-Service TermService → Running; qwinsta → rdp-tcp Listen' },
    { symptom: 'Ping works, TCP 3389 times out', causes: ['Remote Desktop firewall rules disabled', 'rules enabled for Domain only while the network profile is Public', 'a network firewall (router ACL, pfSense) between client and server', 'GPO-deployed block rule'], diagnose: ['Get-NetFirewallRule -DisplayGroup "Remote Desktop" | ft DisplayName, Enabled, Profile', 'Get-NetConnectionProfile', 'Test-NetConnection from a host on the same subnet', 'pfirewall.log with LogBlocked enabled'], fix: 'Enable the rules for the right profile; fix the profile detection (NLA service, DNS to the DC); open 3389 on the network firewall for the admin networks only.', verify: 'Test-NetConnection app01 -Port 3389 → True' },
    { symptom: 'Port 3389 refused/time out after "hardening": listener on another port', causes: ['PortNumber changed in RDP-Tcp (e.g. 3390)', 'new port not allowed by the firewall (built-in rules are for 3389 only)', 'clients still using 3389'], diagnose: ['reg query "...\\WinStations\\RDP-Tcp" /v PortNumber', 'Get-NetTCPConnection -State Listen | ? OwningProcess -eq (Get-CimInstance Win32_Service -Filter "Name=\'TermService\'").ProcessId'], fix: 'Return to 3389 (policy) or create a firewall rule for the new port and tell clients (`mstsc /v:app01:3390`); restart TermService either way.', verify: 'Get-NetTCPConnection -LocalPort 3389 -State Listen' },
    { symptom: 'The remote computer requires Network Level Authentication, which your computer does not support', causes: ['very old client or third-party client without CredSSP', 'CredSSP disabled on the client', 'client cannot reach a DC for the account (in some versions reported this way)'], diagnose: ['Client OS/version; mstsc About', 'reg query "...\\WinStations\\RDP-Tcp" /v UserAuthentication', 'nltest /sc_query:corp.lab on the server'], fix: 'Update the client. Disable NLA (`UserAuthentication` = 0) only temporarily from the console to recover access, and turn it back on.', verify: 'Connect with NLA enabled; RCM 1149 logged' },
    { symptom: 'An authentication error has occurred. The function requested is not supported ... This could be due to CredSSP encryption oracle remediation.', causes: ['client and server at different CredSSP patch levels (May 2018 updates, CVE-2018-0886) with "Force Updated Clients" on one side'], diagnose: ['patch level of both machines (Get-HotFix)', 'gpresult: Computer Configuration > Administrative Templates > System > Credentials Delegation > Encryption Oracle Remediation'], fix: 'Install current updates on the unpatched machine. Setting the policy to "Vulnerable" is an insecure workaround: if ever used, document it and remove it.', verify: 'mstsc connects without the CredSSP error' },
    { symptom: 'An authentication error has occurred. The Local Security Authority cannot be contacted. / The trust relationship between this workstation and the primary domain failed.', causes: ['server cannot reach a DC (DNS points to a non-AD resolver, firewall, DC down)', 'broken secure channel (machine account password mismatch, e.g. after a VM snapshot revert)', 'user must change password at next logon (NLA cannot do that)'], diagnose: ['nltest /sc_query:corp.lab', 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab', 'Test-ComputerSecureChannel -Verbose'], fix: 'Fix DNS on the server to point to the DCs; repair the channel from the console (`Test-ComputerSecureChannel -Repair -Credential CORP\\admin`); have the user change the password elsewhere first.', verify: 'nltest /sc_query → NERR_Success; RDP logon works' },
    { symptom: 'There is a time and/or date difference between the client and server.', causes: ['clock skew > 5 minutes between client, server or DC (Kerberos)', 'Windows Time service stopped or syncing from the wrong source'], diagnose: ['w32tm /query /status', 'w32tm /stripchart /computer:dc01.corp.lab /samples:3 /dataonly'], fix: 'Fix the time hierarchy: domain members sync from the domain (`w32tm /config /syncfromflags:domhier /update`, `w32tm /resync`); the PDC emulator syncs from a reliable external source.', verify: 'w32tm /query /status shows Source: a DC and a small offset' },
    { symptom: 'To sign in remotely, you need the right to sign in through Remote Desktop Services. / The connection was denied because the user account is not authorized for remote login.', causes: ['user not in Remote Desktop Users (or another group granted the right)', 'a GPO defines "Allow log on through Remote Desktop Services" without Remote Desktop Users', 'user or group in "Deny log on through Remote Desktop Services"'], diagnose: ['Get-LocalGroupMember "Remote Desktop Users"', 'gpresult /h C:\\Temp\\gp.html (User Rights Assignment, winning GPO)', 'Security 4625, Logon Type 10, Status 0xC000015B'], fix: 'Grant the right in the GPO that owns it (or add a group to Remote Desktop Users), `gpupdate /force` on the server. Do not "fix" it by adding helpdesk users to Administrators.', verify: 'Security 4624 Logon Type 10 for the user; LSM 21' },
    { symptom: 'The logon attempt failed', causes: ['wrong password or user name format (use CORP\\user or user@corp.lab)', 'saved stale credentials in the client', 'account locked or disabled'], diagnose: ['RdpCoreTS 140 on the server', 'Security 4625 Status (0xC000006A wrong password, 0xC0000234 locked, 0xC0000072 disabled)', 'cmdkey /list on the client'], fix: 'Correct the credentials, delete saved ones, unlock/enable the account in AD.', verify: 'Successful logon; 4624 type 10' },
    { symptom: 'Remote Desktop can\'t find the computer "app01.corp.lab"', causes: ['missing or stale DNS record', 'client uses a non-AD DNS server', 'wrong DNS suffix for a short name'], diagnose: ['Resolve-DnsName app01.corp.lab', 'Get-DnsClientServerAddress', 'ipconfig /all'], fix: 'Fix the record (or dynamic registration: `ipconfig /registerdns` on the server) or the client\'s DNS servers.', verify: 'Resolve-DnsName returns 10.0.20.21; mstsc by name works' },
  ],
  verification: [
    { check: 'RDP enabled and not overridden', command: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', expect: 'fDenyTSConnections    REG_DWORD    0x0 (and no policy value of 1)' },
    { check: 'Service running', command: 'Get-Service TermService, UmRdpService', expect: 'Running  TermService   Remote Desktop Services\nRunning  UmRdpService  Remote Desktop Services UserMode Port Redirector' },
    { check: 'Listener present on the expected port', command: 'qwinsta; Get-NetTCPConnection -LocalPort 3389 -State Listen', expect: 'rdp-tcp  65536  Listen; 0.0.0.0:3389 Listen' },
    { check: 'Firewall rules enabled for the active profile', command: 'Get-NetFirewallRule -DisplayGroup "Remote Desktop" | ft DisplayName, Enabled, Profile', expect: 'User Mode (TCP-In) True Any' },
    { check: 'NLA required', command: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication', expect: 'UserAuthentication    REG_DWORD    0x1' },
    { check: 'Reachable from the client network', command: 'Test-NetConnection app01.corp.lab -Port 3389 (from WS01)', expect: 'TcpTestSucceeded : True' },
    { check: 'The intended user can log on (and only them)', command: 'mstsc /v:app01.corp.lab as CORP\\h.lee; then Get-WinEvent Security 4624', expect: 'Desktop appears; 4624 Logon Type 10 for CORP\\h.lee' },
    { check: 'Survives a policy refresh and a reboot', command: 'gpupdate /force; (in the window) Restart-Computer; repeat the tests', expect: 'Same results: the fix is in the GPO / persistent settings, not a local override.' },
  ],
  refIds: ['get-service', 'restart-service', 'sc', 'qwinsta', 'get-netfirewallrule', 'get-nettcpconnection', 'get-winevent', 'reg-query', 'gpresult', 'gpupdate', 'tnc', 'resolve-dnsname', 'nltest', 'w32tm', 'test-wsman', 'klist', 'file:winevt-logs', 'file:reg-terminal-server', 'file:reg-rdp-tcp', 'file:reg-services', 'file:windows-firewall-log', 'file:hosts-win', 'file:sysvol', 'proc:rdp-restore', 'proc:restart-rds-safely', 'proc:gpo-troubleshoot', 'proc:secure-channel-repair', 'proc:time-sync-fix', 'proc:windows-network-reset'],
};

export const WINDOWS_RDP_LESSON: Lesson = {
  id: 'windows-rdp',
  moduleId: 'B',
  title: 'Windows Server administration and RDP',
  level: 'intermediate',
  summary: 'Services, the event log, the firewall, the registry, Group Policy and WinRM on Windows Server, applied to the most common remote-access problem: an RDP connection that does not work, investigated layer by layer.',
  concepts: ['win.services', 'win.rdp', 'ad.gpo', 'ad.kerberos', 'ad.dns', 'dns.resolution', 'net.routing', 'tcp.handshake'],
  mode: 'simulated',
  guide: WINDOWS_RDP_GUIDE,
  caseStudyIds: ['rdp-after-change', 'domain-login'],

  what: `
Windows Server is administered through a small number of building blocks. Many of them have a direct Linux equivalent you have already met: services instead of [systemd units](#/lesson/systemd/what), the Event Viewer instead of the journal, Windows Defender Firewall instead of [nftables](#/lesson/nftables/what), the registry instead of files in /etc. Once you know where each one lives, the same diagnostic questions you use on Linux work on Windows: **is it running, is it configured, is it reachable, is it allowed, and what does the log say?**

### The building blocks
- **Services and the Service Control Manager (SCM).** Long-running programs (DNS, DHCP, Remote Desktop Services, WinRM) run as services. Manage them with \`services.msc\`, \`Get-Service\` / \`Start-Service\` / \`Restart-Service\`, or \`sc.exe\`.
- **Event Viewer** (\`eventvwr.msc\`, \`Get-WinEvent\`). The equivalent of the journal: System, Application and Security logs plus per-component "Applications and Services Logs".
- **Windows Defender Firewall** (\`wf.msc\`, \`Get-NetFirewallRule\`). A stateful host firewall with three **profiles** (Domain, Private, Public) chosen per network.
- **The registry** (\`regedit\`, \`reg query\`, \`Get-ItemProperty\`). Where services and most components keep their configuration; the equivalent of \`/etc\`.
- **Group Policy** (\`gpedit.msc\` locally, the Group Policy Management Console in a domain, \`gpresult\` to see what applied). Central configuration that overrides local settings.
- **PowerShell and WinRM.** Every task above can be done from PowerShell, locally or remotely over WinRM (\`Invoke-Command\`, \`Enter-PSSession\`), which is how you repair a server whose RDP is broken.
- **Active Directory.** Domain logons need a domain controller, DNS that can find it, and synchronised clocks.

:::practice
Q: Name the Windows equivalent of each Linux tool: systemctl, journalctl, nftables, files in /etc.
A: **Services / Get-Service** (Service Control Manager), **Event Viewer / Get-WinEvent**, **Windows Defender Firewall**, the **registry** (plus Group Policy, which overrides local settings).
Q: A setting changed in the local registry keeps reverting after about 90 minutes. Which building block is the likely cause?
A: **Group Policy**: it reapplies its settings at every refresh and overrides the local value. Change it in the GPO.
:::

### Remote Desktop Protocol (RDP)
RDP gives you a graphical desktop on a remote Windows machine, the Windows counterpart of [SSH](#/lesson/ssh/what) (which gives you a text terminal). The server side is the **Remote Desktop Services** service (\`TermService\`), listening on **TCP and UDP port 3389**. It is the standard way to administer Windows Server with a graphical interface. Like SSH, it depends on everything underneath it, so it fails in many distinct ways: disabled, service stopped, port blocked, listener changed, NLA/CredSSP problems, missing user rights, domain authentication, DNS, routing, Group Policy. This lesson gives you a complete diagnostic process for all of them.

> The examples follow a domain in the lab naming plan (\`corp.lab\`, member server \`app01\` 10.0.20.21, DC \`dc01\` 10.0.20.5, client \`WS01\` 10.0.10.25) and their output is representative of Windows Server 2022 and Windows 11 23H2. The **sandbox and the tickets** use the simulated server **win01** (10.0.20.30): a standalone Windows Server 2022 with a Windows PowerShell 5.1 console (services, the event log, the registry, Windows Defender Firewall, local accounts, NetTCPIP and DnsClient cmdlets, ipconfig, netstat, netsh, sc.exe, reg). Connect to it from ws01 with \`xfreerdp /v:win01.corp.lab /u:alice\`. Domain logons (CORP\\alice) work once win01 is joined to the simulated domain ad.corp.lab (dc01): see the [Active Directory lesson](#/lesson/ad-kerberos/what) and Lab 2. Group Policy is simulated too (see the [Group Policy lesson](#/lesson/gpo/what)), and domain logons use Kerberos tickets from dc01 after NLA.

:::practice
Q: Which service provides RDP on a Windows server, and on which ports does it listen?
A: **TermService** (Remote Desktop Services), on **TCP and UDP 3389**.
Q: Why can RDP fail in more distinct ways than "the server is down"?
A: It depends on many layers: RDP enabled, the service, the listener and its port, the firewall profile, NLA/CredSSP, domain authentication (DNS, DC, time), user rights and Group Policy. Each has its own error.
:::

`,

  internals: `
### Services and the Service Control Manager
\`services.exe\` (the SCM) starts services at boot in dependency order, stops them at shutdown, and records state changes in the **System** log.
- **Startup types**: *Automatic* (start at boot), *Automatic (Delayed Start)* (about two minutes after the automatic ones, to speed up boot), *Manual* (started on demand, by another service or by a trigger), *Disabled* (cannot be started at all; error 1058). Startup type = "at boot", Status = "now": the same distinction as \`enabled\` vs \`active\` in systemd.
- **Dependencies** are stored in the registry value \`DependOnService\` under \`HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\`. \`Get-Service X -RequiredServices\` shows what X needs; \`-DependentServices\` shows what stops with X. Stopping a service with running dependents needs \`-Force\`.
- **Recovery actions** (services.msc > Recovery, or \`sc.exe failure\`): restart the service, run a program, or reboot after the first, second and subsequent failures. They are the Windows \`Restart=on-failure\`.
- **sc.exe**: \`sc.exe query X\` (state), \`sc.exe queryex X\` (state + PID), \`sc.exe qc X\` (configuration: start type, binary, dependencies, account), \`sc.exe enumdepend X\` (dependents). In PowerShell type \`sc.exe\`, because \`sc\` is an alias for Set-Content.

Key SCM events in the System log:
| ID | Meaning |
|---|---|
| 7036 | The *X* service entered the running/stopped state |
| 7031 | The *X* service terminated unexpectedly ... corrective action will be taken |
| 7034 | The *X* service terminated unexpectedly (no recovery action) |
| 7000 | The *X* service failed to start due to the following error |
| 7001 | The *X* service depends on the *Y* service which failed to start |
| 7009 | A timeout was reached (30000 milliseconds) while waiting for the *X* service to connect |
| 7040 | The start type of the *X* service was changed from ... to ... |

:::practice
Q: A service has startup type Manual and status Stopped after a reboot. Is that a fault?
A: Not necessarily. **Manual** services start only on demand (by another service, a trigger or an admin). It is a fault only if something needs it running and nothing starts it; then the right fix may be Automatic.
Q: The System log shows event **7034** for a service. What happened, and what is the difference from 7031?
A: The service **terminated unexpectedly**. 7031 says the same but adds that a recovery action (such as a restart) will be taken; 7034 means no recovery action is configured.
:::

### Event Viewer
Logs are files in \`%SystemRoot%\\System32\\winevt\\Logs\\*.evtx\`. **Windows Logs** (Application, Security, System) plus **Applications and Services Logs** per component (for RDP: \`Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\`, \`...-RemoteConnectionManager/Operational\`, \`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational\`). Query them efficiently with a filter hashtable, which is evaluated by the event log service rather than in PowerShell:
\`\`\`
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)}
\`\`\`
RDP-related IDs:
| Log | ID | Meaning |
|---|---|---|
| Security | 4624 | Logon succeeded. **Logon Type 10** = RemoteInteractive (RDP); **3** = network (also the NLA pre-authentication); 7 = unlock/reconnect |
| Security | 4625 | Logon failed. Status/Sub Status say why: 0xC000006A wrong password, 0xC0000234 locked, 0xC000015B logon type not granted |
| RemoteConnectionManager | 1149 | "User authentication succeeded" at the network level (with NLA). It does **not** mean the session logon succeeded |
| LocalSessionManager | 21 / 22 | Session logon succeeded / shell start |
| LocalSessionManager | 23 / 24 / 25 | Session logoff / disconnected / reconnection succeeded |
| RdpCoreTS | 131 | The server accepted a new TCP connection from client *ip:port* |
| RdpCoreTS | 140 | Connection from *ip* failed because the user name or password is not correct |

:::practice
Q: Security event 4624 shows Logon Type 3 just before a Logon Type 10 for the same user. What do the two mean for an RDP logon with NLA?
A: Type **3** is the network logon used for the **NLA pre-authentication**; type **10** is the actual RemoteInteractive (RDP) session logon.
Q: RemoteConnectionManager event 1149 shows the user authenticated, but they never got a desktop. Does 1149 prove the logon succeeded?
A: **No.** 1149 only means authentication succeeded at the network level. Look at Security 4625 (with its Status) and the LocalSessionManager events (21/22) for the session logon itself.
:::

### Windows Defender Firewall
Stateful, per-**profile**: *Domain* (the adapter can reach a DC of the joined domain), *Private*, *Public* (the default for unknown networks). Each rule applies to one or more profiles. The built-in group **"Remote Desktop"** contains "Remote Desktop - User Mode (TCP-In)", "Remote Desktop - User Mode (UDP-In)" and "Remote Desktop - Shadow (TCP-In)"; enabling RDP in the GUI enables them. They allow **port 3389** only. Rules can also come from Group Policy, and a block rule wins over an allow rule. The [Windows Defender Firewall lesson](#/lesson/windows-firewall/internals) covers rule conditions, the firewall log and policy rules in depth.

:::practice
Q: The built-in Remote Desktop rules are enabled for the Domain profile only. A server shows its profile as Public. Can clients connect on 3389?
A: **No.** The rules do not apply in the Public profile. Find out why the server does not detect the domain network (usually DNS cannot reach a DC) rather than enabling RDP for Public.
Q: A local allow rule and a Group Policy block rule both match port 3389. Which wins?
A: The **block** rule. In Windows Defender Firewall a block rule wins over an allow rule.
:::

### Registry settings that control RDP
- \`HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections\`: 0 = allow, 1 = deny (the default after installing Windows Server).
- \`...\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber\`: listener port (3389 = 0xd3d).
- \`...\\RDP-Tcp\\UserAuthentication\`: 1 = require NLA.
- \`...\\RDP-Tcp\\SecurityLayer\`: 0 = legacy RDP security, 1 = negotiate, 2 = TLS.
- \`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\`: the same settings from **Group Policy**, which override the values above.

:::practice
Q: \`fDenyTSConnections\` is 0 in \`HKLM\\SYSTEM\\...\\Terminal Server\`, but RDP is still refused as "disabled". Where else do you look?
A: In the **policy** key \`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\`: a Group Policy setting there overrides the local value.
Q: Which value tells you whether the server requires NLA?
A: \`UserAuthentication\` under the RDP-Tcp key: 1 means NLA is required.
:::

### Remote Desktop Services
- **TermService** ("Remote Desktop Services") owns the listener and the protocol. **UmRdpService** ("Remote Desktop Services UserMode Port Redirector") depends on it; **SessionEnv** ("Remote Desktop Configuration") supports it.
- The **listener** RDP-Tcp is visible with \`qwinsta\` (\`query session\`) as \`rdp-tcp ... 65536 Listen\`. No such line, no RDP.
- **NLA** (Network Level Authentication) uses **CredSSP**: TLS first, then Kerberos or NTLM inside it, all **before** a session is created. That protects the server from unauthenticated session creation, but it means a domain account can only authenticate if the server can reach a **domain controller** and the clocks agree.
- **Certificates**: RDS generates a self-signed certificate (store \`Cert:\\LocalMachine\\Remote Desktop\`); in a domain you can deploy CA-issued certificates by Group Policy so clients stop warning.
- **Restarting TermService disconnects every RDP session, including your own.** Restart it from the console, the hypervisor, iLO/iDRAC, or remotely with \`Invoke-Command -ComputerName app01 { Restart-Service TermService -Force }\` over WinRM.

:::practice
Q: \`qwinsta\` lists \`rdp-tcp ... 65536 Listen\`. What does that line prove?
A: The RDP **listener exists and is listening**: TermService is running and RDP is enabled. If clients still cannot connect, look at the firewall, the port and the network.
Q: Why can a domain user fail NLA on a server whose clock is 10 minutes off, while the local Administrator still logs on?
A: NLA authenticates domain accounts with **Kerberos**, which rejects clocks more than 5 minutes apart. Local accounts are checked against the local SAM and need no DC or Kerberos.
:::

### WinRM
The **WinRM** service ("Windows Remote Management (WS-Management)") listens on TCP **5985** (HTTP, messages still encrypted with Kerberos/NTLM) and **5986** (HTTPS). It is enabled by default on Windows Server 2012 and later; \`Enable-PSRemoting -Force\` enables it elsewhere (and creates firewall rules). \`Test-WSMan app01\` checks it. In a domain, Kerberos authenticates both sides; by IP or in a workgroup you must add the target to \`WSMan:\\localhost\\Client\\TrustedHosts\` (or use HTTPS).

:::practice
Q: You want to run commands on app01 by IP address from a workgroup laptop. Why does \`Enter-PSSession 10.0.20.21\` fail where \`Enter-PSSession app01.corp.lab\` from a domain machine works?
A: By IP address (or from a workgroup) Kerberos cannot be used. The laptop must list the target in \`WSMan:\\localhost\\Client\\TrustedHosts\` (or use HTTPS on 5986).
Q: Which command tests whether WinRM answers on a remote server?
A: \`Test-WSMan SERVER\`.
:::

### Active Directory dependencies
A domain RDP logon needs: DNS that resolves the server and the DC SRV records (\`_ldap._tcp.dc._msdcs.corp.lab\`), a reachable DC (Kerberos 88, LDAP 389), a valid **secure channel** between app01 and the domain (\`nltest /sc_query:corp.lab\`), and **time** within 5 minutes (Kerberos). Any one failing breaks NLA for domain accounts while local accounts still work, a useful diagnostic contrast.

:::practice
Q: Name the four things a server needs so that domain accounts can pass NLA.
A: DNS that resolves the DC records, a **reachable DC** (Kerberos 88, LDAP 389), a valid **secure channel** with the domain, and **time** within 5 minutes.
Q: Which command checks the server's secure channel with the domain?
A: \`nltest /sc_query:corp.lab\` (or \`Test-ComputerSecureChannel\` in PowerShell).
:::

### Group Policy
Computer settings apply at boot and every 90 minutes (with a random offset of up to 30); \`gpupdate /force\` applies now; \`gpresult /r /scope computer\` lists applied GPOs; \`gpresult /h report.html\` shows the **winning GPO per setting**. RDP-related settings:
- Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > **Connections** > "Allow users to connect remotely by using Remote Desktop Services".
- ... > Remote Desktop Session Host > **Security** > "Require user authentication for remote connections by using Network Level Authentication", "Require use of specific security layer for remote (RDP) connections".
- Computer Configuration > Windows Settings > Security Settings > Local Policies > **User Rights Assignment** > "Allow log on through Remote Desktop Services" and "Deny log on through Remote Desktop Services". A GPO that defines a user right **replaces** the local list, so a baseline that lists only Administrators removes Remote Desktop Users (case study F).
- Computer Configuration > Administrative Templates > System > Credentials Delegation > "Encryption Oracle Remediation" (CredSSP).

:::practice
Q: A GPO defines "Allow log on through Remote Desktop Services" with only the group Helpdesk-RDP. Can members of the local Remote Desktop Users group still log on through RDP?
A: **No** (unless they are also in Helpdesk-RDP). A GPO that defines a user right **replaces** the local list.
Q: Which command shows which GPO won for each setting on a computer?
A: \`gpresult /h report.html\` (the HTML report lists the winning GPO per setting).
:::

### Windows networking basics for RDP
\`Get-NetIPConfiguration\` (address, gateway, DNS servers per adapter), \`Resolve-DnsName\` (DNS only, unlike ping which also uses hosts and LLMNR), \`Test-NetConnection host -Port 3389\` (TCP test), \`Get-NetTCPConnection -State Listen\` (the \`ss -tlnp\` of Windows), \`Get-NetConnectionProfile\` (which firewall profile is active). A server whose DNS points at a public resolver cannot find its DC and may fall back to the Public profile: two failures from one setting.

:::practice
Q: \`ping app01\` works but \`Resolve-DnsName app01.corp.lab\` fails. How can that be?
A: ping also uses the **hosts file and LLMNR**; Resolve-DnsName asks only DNS. The name is found locally but DNS does not have it (or the client uses the wrong DNS server).
Q: Which cmdlet is the Windows equivalent of \`ss -tlnp\`?
A: \`Get-NetTCPConnection -State Listen\`.
:::

`,

  deployment: [
    {
      id: 'winserver',
      platform: 'Windows Server 2019 / 2022',
      summary: 'Enable RDP securely on a domain-joined member server, restrict who may use it, and verify from a client. Run in an elevated PowerShell on a real Windows Server VM (evaluation editions are free for 180 days). Output is representative of Windows Server 2022.',
      prerequisites: ['Windows Server 2019 or 2022 VM with console access (hypervisor console).', 'Local Administrator rights (and Domain Admin or delegated GPO rights for the domain steps).', 'A Windows 10/11 Pro or Server machine as a client.'],
      steps: [
        { title: 'Check the current state', command: 'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections\nGet-Service TermService', what: 'Shows whether RDP is denied (1) or allowed (0), and whether the service runs.', why: 'RDP is disabled by default on a fresh Windows Server install. Record the original values before changing them.', expected: 'fDenyTSConnections : 1\n...\nStatus   Name               DisplayName\n------   ----               -----------\nRunning  TermService        Remote Desktop Services', simulated: true },
        { title: 'Back up the settings you will change', command: 'reg export "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" C:\\Backup\\terminal-server.reg /y', what: 'Exports the whole Terminal Server key, including WinStations\\RDP-Tcp.', why: '`reg import C:\\Backup\\terminal-server.reg` restores port, NLA and security layer if a later change goes wrong.', expected: 'The operation completed successfully.', simulated: true },
        { title: 'Enable Remote Desktop', command: 'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 0', what: 'Allows RDP connections; TermService creates the RDP-Tcp listener. Equivalents: `sconfig` option 7, or `SystemPropertiesRemote.exe` > "Allow remote connections to this computer".', why: 'This is the switch the GUI flips. A GPO "Allow users to connect remotely..." overrides it in a domain.', expected: '', simulated: true },
        { title: 'Require NLA', command: 'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthentication -Value 1', what: 'Requires Network Level Authentication (CredSSP) before a session is created.', why: 'Without NLA anyone who can reach 3389 gets a sign-in screen and a session, consuming resources and exposing the logon UI to attacks.', expected: '', simulated: true },
        { title: 'Open the firewall', command: 'Enable-NetFirewallRule -DisplayGroup "Remote Desktop"\nGet-NetFirewallRule -DisplayGroup "Remote Desktop" | Format-Table DisplayName, Enabled, Profile, Action', what: 'Enables the built-in Remote Desktop rules (TCP and UDP 3389, shadowing).', why: 'Setting the registry value alone does not open the firewall. Restrict the remote addresses to admin networks: `Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress 10.0.10.0/24`.', expected: 'DisplayName                          Enabled Profile Action\n-----------                          ------- ------- ------\nRemote Desktop - User Mode (TCP-In)     True     Any  Allow\nRemote Desktop - User Mode (UDP-In)     True     Any  Allow\nRemote Desktop - Shadow (TCP-In)        True     Any  Allow', simulated: true },
        { title: 'Allow only the intended users', command: 'Add-LocalGroupMember -Group "Remote Desktop Users" -Member "CORP\\Helpdesk"\nGet-LocalGroupMember -Group "Remote Desktop Users"', what: 'Grants RDP access to a domain group through the local Remote Desktop Users group (which holds the "Allow log on through Remote Desktop Services" right).', why: 'Never add users to Administrators just so they can RDP. In a domain, manage this with Group Policy (Restricted Groups or Group Policy Preferences), and remember that a GPO defining the user right itself replaces the local list.', expected: 'ObjectClass Name          PrincipalSource\n----------- ----          ---------------\nGroup       CORP\\Helpdesk ActiveDirectory' },
        { title: 'Verify the listener', command: 'qwinsta\nGet-NetTCPConnection -LocalPort 3389 -State Listen', what: 'Confirms the rdp-tcp listener and the TCP socket.', why: 'Proves the service side before you test from a client.', expected: ' SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n services                                    0  Disc\n>console           Administrator             1  Active\n rdp-tcp                                 65536  Listen\n\nLocalAddress LocalPort RemoteAddress RemotePort  State AppliedSetting OwningProcess\n------------ --------- ------------- ----------  ----- -------------- -------------\n::           3389      ::            0          Listen                1104\n0.0.0.0      3389      0.0.0.0       0          Listen                1104', simulated: true },
        { title: 'Certificate (optional, recommended in a domain)', command: 'Get-ChildItem "Cert:\\LocalMachine\\Remote Desktop"', what: 'Shows the certificate RDS presents (self-signed by default).', why: 'Clients warn "The identity of the remote computer cannot be verified" for self-signed certificates. Deploy a CA certificate (auto-enrolment + GPO "Server authentication certificate template") so users learn to treat that warning as abnormal.', expected: 'Thumbprint                                Subject\n----------                                -------\n6B1E...D0A2                               CN=app01.corp.lab' },
        { title: 'Test from a client', command: 'Test-NetConnection app01.corp.lab -Port 3389\nmstsc /v:app01.corp.lab', what: 'TCP test, then a real connection as a Remote Desktop Users member.', why: '"Running" and "listening" on the server do not prove the path, firewall, NLA and user rights all work.', expected: 'TcpTestSucceeded : True' },
        { title: 'Read the logon events', command: 'Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 3 | Format-List TimeCreated, Id, Message', what: 'Shows the session logon (21), shell start (22) of your test.', why: 'This is your known-good baseline for later troubleshooting.', expected: 'TimeCreated : 21/10/2026 09:14:02\nId          : 21\nMessage     : Remote Desktop Services: Session logon succeeded:\n\n              User: CORP\\h.lee\n              Session ID: 3\n              Source Network Address: 10.0.10.25', simulated: true },
      ],
    },
    {
      id: 'winclient',
      platform: 'Windows 10 / 11',
      summary: 'Windows clients can host RDP only in **Pro, Enterprise and Education** editions, with one session at a time. Home editions include the client (mstsc) but cannot accept connections. Output is representative of Windows 11 23H2.',
      prerequisites: ['Windows 10/11 Pro, Enterprise or Education.', 'A local administrator account.'],
      steps: [
        { title: 'Check the edition', command: 'Get-ComputerInfo -Property WindowsProductName, WindowsEditionId', what: 'Shows the edition.', why: 'If it says Core (Home), no RDP host is available; use another remote-support tool or upgrade the edition.', expected: 'WindowsProductName WindowsEditionId\n------------------ ----------------\nWindows 10 Pro     Professional' },
        { title: 'Enable Remote Desktop', command: 'Settings > System > Remote Desktop > Remote Desktop: On', what: 'Sets fDenyTSConnections = 0, enables the firewall rules and keeps "Require devices to use Network Level Authentication" on by default.', why: 'Same result as the PowerShell steps on Server. (Windows 11 reports "Windows 10 Pro" in WindowsProductName on many builds; check the build number with `winver`.)', expected: '' },
        { title: 'Who may connect', command: 'Settings > System > Remote Desktop > Remote Desktop users', what: 'Adds accounts to the local Remote Desktop Users group. Administrators can always connect.', why: 'Accounts without a password cannot log on remotely by default (local policy "Limit local account use of blank passwords to console logon only").', expected: '' },
        { title: 'Connect and understand the single-session limit', command: 'mstsc /v:ws07.corp.lab', what: 'Connecting signs out (locks) the local user\'s console session.', why: 'Windows client editions allow one interactive session; a second remote user is asked to disconnect the first.', expected: '' },
      ],
    },
    {
      id: 'winrm',
      platform: 'WinRM (PowerShell remoting)',
      summary: 'WinRM is the second way into a Windows server: use it to repair RDP without RDP, and to restart Remote Desktop Services without being disconnected. Enabled by default on Windows Server 2012 and later; on Windows 10/11 it must be enabled.',
      prerequisites: ['Administrator rights on the target.', 'TCP 5985 (or 5986 for HTTPS) allowed from your management host.'],
      steps: [
        { title: 'Enable on the target (if needed)', command: 'Enable-PSRemoting -Force', what: 'Starts the WinRM service, sets it to Automatic, creates the HTTP listener and firewall rules.', why: 'On client editions WinRM is off by default. On Server it is normally already on; check with `Get-Service WinRM`.', expected: 'WinRM has been updated to receive requests.\nWinRM service type changed successfully.\nWinRM service started.' },
        { title: 'Test from the management host', command: 'Test-WSMan app01.corp.lab', what: 'Sends a WS-Management identify request.', why: 'Proves the listener and firewall before you depend on it in an incident.', expected: 'wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd\nProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\nProductVendor   : Microsoft Corporation\nProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0' },
        { title: 'Run commands remotely', command: 'Invoke-Command -ComputerName app01.corp.lab -ScriptBlock { Get-Service TermService; qwinsta }\nEnter-PSSession app01.corp.lab', what: 'Runs a script block on the target, or opens an interactive remote prompt.', why: 'Unlike RDP, this does not depend on TermService, the RDP listener or RDP user rights (it needs administrator rights or the Remote Management Users group).', expected: '[app01.corp.lab]: PS C:\\Users\\admin\\Documents>' },
        { title: 'Outside the domain or by IP', command: 'Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value "10.0.20.21" -Concatenate\nEnter-PSSession 10.0.20.21 -Credential app01\\Administrator', what: 'Allows the client to use NTLM to a specific host that Kerberos cannot authenticate.', why: 'Kerberos needs a name with an SPN; by IP, WinRM refuses unless the host is trusted or HTTPS is used. Never set TrustedHosts to `*` permanently.', expected: '' },
      ],
    },
    {
      id: 'linux-xrdp',
      platform: 'Linux (xrdp) — note',
      summary: 'Linux has no Remote Desktop Services. The open-source **xrdp** server speaks RDP on TCP 3389 and starts an X session for the user; clients use mstsc as usual. It is not modelled by the simulator, and none of the Windows registry, NLA or Group Policy material applies.',
      prerequisites: ['Debian 12 / Ubuntu 24.04 with a desktop environment, or RHEL 9 with EPEL.'],
      steps: [
        { title: 'Install and start', command: 'sudo apt install xrdp\nsudo adduser xrdp ssl-cert\nsudo systemctl enable --now xrdp', what: 'Installs xrdp and xrdp-sesman; adds xrdp to ssl-cert so it can read the TLS key; enables the service.', why: 'Without the ssl-cert membership, TLS fails on Debian/Ubuntu. On RHEL: `dnf install xrdp` from EPEL and `firewall-cmd --permanent --add-port=3389/tcp && firewall-cmd --reload`.', expected: '' },
        { title: 'Check and troubleshoot', command: 'ss -tlnp | grep 3389\njournalctl -u xrdp -u xrdp-sesman -n 50', what: 'Confirms the listener and shows session start errors.', why: 'The same layered method applies: listening, firewall, authentication (PAM), session start.', expected: 'LISTEN 0 2 *:3389 *:* users:(("xrdp",pid=812,fd=11))' },
      ],
    },
  ],

  configIntro: `
RDP configuration lives in the registry, with **Group Policy values overriding the local ones**. The directives below are the values you check during an incident; for each, the policy equivalent is noted. Always \`reg export\` the key before changing it, and remember that changing the listener (port, certificate) requires restarting TermService, which disconnects every session.
`,

  configFiles: [
    {
      platform: 'Windows Server 2019/2022, Windows 10/11',
      items: [
        { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', purpose: 'fDenyTSConnections (RDP on/off) and global RDS settings.' },
        { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', purpose: 'Listener: PortNumber, UserAuthentication (NLA), SecurityLayer, SSLCertificateSHA1Hash.' },
        { path: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', purpose: 'Policy values from GPO; override the keys above.' },
        { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService', purpose: 'Service definition: Start, DependOnService, account.' },
        { path: 'Cert:\\LocalMachine\\Remote Desktop', purpose: 'Certificate presented in the TLS handshake.' },
        { path: '%SystemRoot%\\System32\\winevt\\Logs\\', purpose: 'System, Security, TerminalServices-* and RdpCoreTS logs (.evtx).' },
        { path: '%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log', purpose: 'Firewall log (when enabled).' },
        { path: 'Local Users and Groups: Remote Desktop Users', purpose: 'Members get the RDP logon right by default.' },
        { path: '\\\\corp.lab\\SYSVOL\\corp.lab\\Policies\\{GUID}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', purpose: 'User rights (SeRemoteInteractiveLogonRight) set by a GPO.' },
      ],
    },
    {
      platform: 'Client (mstsc)',
      items: [
        { path: '%USERPROFILE%\\Documents\\Default.rdp (hidden)', purpose: 'Last-used connection settings.' },
        { path: 'Credential Manager (cmdkey /list): TERMSRV/<host>', purpose: 'Saved RDP credentials.' },
      ],
    },
    {
      platform: 'Linux (xrdp)',
      items: [
        { path: '/etc/xrdp/xrdp.ini, /etc/xrdp/sesman.ini', purpose: 'Listener port, TLS settings, session manager.' },
        { path: '/var/log/xrdp.log, /var/log/xrdp-sesman.log', purpose: 'xrdp logs (also in the journal).' },
      ],
    },
  ],

  directives: [
    { name: 'fDenyTSConnections', compiledDefault: '1 (deny) on a fresh Windows Server install', recommended: '0 on servers administered over RDP; 1 where only WinRM/console is used', explanation: 'RDP on/off switch (DWORD, Terminal Server key). Policy: "Allow users to connect remotely by using Remote Desktop Services".', security: 'Enable RDP only together with NLA, a restricted firewall scope and a restricted user list. Never expose 3389 directly to the Internet; use a VPN or an RD Gateway.' },
    { name: 'PortNumber (RDP-Tcp)', compiledDefault: '3389 (0xd3d)', recommended: '3389', explanation: 'TCP/UDP port of the listener. Needs a TermService restart and a new firewall rule when changed; clients then connect with host:port.', security: 'Moving the port only reduces scanner noise; it breaks monitoring, documentation and firewall rules. Restrict source addresses instead.' },
    { name: 'UserAuthentication (RDP-Tcp)', compiledDefault: '1 when RDP is enabled through the GUI with the default NLA option', recommended: '1 (require NLA)', explanation: 'Require Network Level Authentication (CredSSP) before a session is created. Policy: "Require user authentication for remote connections by using Network Level Authentication".', security: 'Without NLA the server creates a session for every connection and exposes the logon UI. Disable only temporarily, from the console, to recover access.' },
    { name: 'SecurityLayer (RDP-Tcp)', compiledDefault: 'Negotiate/TLS depending on version (check with reg query)', recommended: '2 (TLS)', explanation: '0 = legacy RDP security (no server authentication), 1 = negotiate, 2 = TLS. Policy: "Require use of specific security layer for remote (RDP) connections".', security: 'Value 0 disables TLS and server authentication; NLA requires TLS.' },
    { name: 'Allow log on through Remote Desktop Services (SeRemoteInteractiveLogonRight)', compiledDefault: 'Administrators, Remote Desktop Users (member servers); Administrators only on domain controllers', recommended: 'Administrators + Remote Desktop Users, managed by GPO', explanation: 'User right checked after authentication. A GPO that defines it replaces the local list on every computer it applies to.', security: 'Grant to groups, not users; keep helpdesk out of Administrators.' },
    { name: 'Deny log on through Remote Desktop Services (SeDenyRemoteInteractiveLogonRight)', compiledDefault: '(empty)', recommended: 'Service accounts, local accounts on domain members (e.g. "Local account and member of Administrators group")', explanation: 'Deny always wins over Allow.', security: 'A strong control against lateral movement with local admin passwords; check it first when a specific account is refused.' },
    { name: 'Remote Desktop Users (local group)', compiledDefault: 'empty', recommended: 'A domain group such as CORP\\Helpdesk', explanation: 'Membership gives the RDP logon right through the default user-rights list.', security: 'Use Group Policy to manage membership so it is consistent and auditable.' },
    { name: 'Encryption Oracle Remediation (CredSSP policy)', compiledDefault: 'Mitigated (after the May 2018 updates)', recommended: 'Force Updated Clients (once everything is patched)', explanation: 'Controls whether CredSSP talks to unpatched peers (CVE-2018-0886). Computer Configuration > Administrative Templates > System > Credentials Delegation.', security: '"Vulnerable" makes the CredSSP error go away by re-enabling the vulnerability: patch the old side instead.' },
    { name: 'TermService startup type', compiledDefault: 'Manual on current versions (started when RDP is enabled)', recommended: 'Leave the default', explanation: 'Status and StartType are separate; Disabled prevents the service from ever starting (error 1058).', security: 'Turn RDP off with fDenyTSConnections or policy, not by disabling the service.' },
    { name: 'TrustedHosts (WinRM client)', compiledDefault: '(empty)', recommended: 'Empty in a domain; specific hosts otherwise', explanation: 'Hosts the WinRM client may use NTLM with when Kerberos is not possible (IP addresses, workgroups).', security: '`*` lets your credentials go to any host that answers, including an impostor; prefer HTTPS (5986).' },
  ],

  operateIntro: `
### Management tools
| Tool | Opens / does |
|---|---|
| \`services.msc\` | Services: status, startup type, dependencies, recovery actions |
| \`eventvwr.msc\` | Event Viewer |
| \`regedit\` | Registry editor |
| \`wf.msc\` | Windows Defender Firewall with Advanced Security |
| \`gpedit.msc\` | Local Group Policy editor (not on Home editions) |
| \`gpresult /r\`, \`gpresult /h report.html\` | Which GPOs and settings were applied |
| \`Get-Service\`, \`Get-WinEvent\`, \`Get-NetTCPConnection\` | PowerShell equivalents of systemctl, journalctl, ss |
| \`sconfig\` | Text menu on Server Core and Desktop Experience (option 7: Remote Desktop) |

:::practice
Q: Which tool shows which GPOs were applied to a server and which one won for each setting?
A: \`gpresult /h report.html\` (or \`gpresult /r\` for a summary).
Q: On Server Core, which built-in menu lets you enable Remote Desktop?
A: \`sconfig\` (option 7).
:::

`,
  troubleshootingIntro: `
### A complete RDP diagnostic process
RDP fails at different stages: finding the server, reaching its port, authenticating, and being allowed to log on. Each stage has its own error message and its own place to look. Work through them in order.

1. **Read the exact message on the client.** It tells you which stage failed (see the table below). If a user reports the problem, ask for a screenshot rather than a summary: "it doesn't work" and "an authentication error has occurred" point to very different causes.
2. **Check from the client, bottom-up**, stopping at the first check that fails: \`Resolve-DnsName app01.corp.lab\` (does the name resolve?), \`Test-NetConnection app01 -TraceRoute\` (is there a route?), \`Test-NetConnection app01 -Port 3389\` (does TCP 3389 answer?).
3. **Get onto the server another way**: the console, the hypervisor, iLO/iDRAC, or PowerShell remoting over **WinRM** (\`Enter-PSSession app01\`). Never troubleshoot RDP in a way that depends on RDP working.
4. **On the server, check in this order:**
- Is RDP enabled? (\`fDenyTSConnections\` in the registry, including the Group Policy key, which overrides the local setting.)
- Is TermService running? (\`Get-Service\`, and System events 7000/7031/7034/7040 for start failures, crashes and start-type changes.)
- Is the listener present, on the expected port? (\`qwinsta\`, \`Get-NetTCPConnection\`, and the \`PortNumber\` registry value.)
- Do the firewall rules allow it for the **active profile**? (\`Get-NetFirewallRule -DisplayGroup "Remote Desktop"\` and \`Get-NetConnectionProfile\`: a rule enabled only for Domain does nothing while the network is classed as Public.)
5. **Authentication (NLA, using CredSSP).** Look at RdpCoreTS events 131/140 and Security event 4625. For domain accounts, check the path to the domain controller (\`nltest /sc_query:corp.lab\`), DNS to the DC, and time (\`w32tm /query /status\`). A quick test: try a **local** account. If the local account works and domain accounts do not, the problem is in the domain dependency, not in RDP.
6. **Authorisation.** Security event 4625 with Logon Type 10 and Status 0xC000015B means the user lacks the right "Allow log on through Remote Desktop Services". \`gpresult /h\` shows which Group Policy object sets it.
7. **Fix it in the right place** (the GPO, not a local override that the next policy refresh reverts), restart only what needs it, and **verify** from the client with the affected user.

:::practice
Q: \`Test-NetConnection app01 -Port 3389\` fails, but \`Resolve-DnsName\` and ping work. How do you get onto app01 to continue, and what do you check first there?
A: Through the **console, hypervisor or WinRM** (\`Enter-PSSession app01\`), never via RDP. Then check, in order: RDP enabled (fDenyTSConnections, including the policy key), TermService running, the listener and its port, and the firewall rules for the active profile.
Q: A local account can log on through RDP, domain accounts cannot. Where is the problem?
A: In the **domain dependency** of NLA: DNS to the DC, the secure channel (\`nltest /sc_query\`), or time. RDP itself works.
:::

### Do not "fix" by weakening security
Disabling NLA, setting CredSSP to "Vulnerable", adding users to Administrators or turning off the firewall can make a symptom go away. Each one is a workaround that leaves a security hole. If you ever use one to regain access, record it and undo it afterwards.

:::practice
Q: To restore access quickly during an outage, you temporarily disabled NLA on a server. What must you do afterwards?
A: Record it as a **workaround**, find and fix the real cause, then **re-enable NLA** and verify that logons still work.
Q: Why is adding a helpdesk user to the Administrators group a bad fix for "the user is not allowed to log on through RDP"?
A: It grants far more than the missing right. The fix is the **"Allow log on through Remote Desktop Services"** user right (through Remote Desktop Users or the GPO that defines it).
:::

`,

  errorMap: [
    { message: 'Remote Desktop can\'t find the computer "app01.corp.lab".', layer: 'Name resolution', meaning: 'DNS (or hosts) has no answer for the name.', firstCheck: 'Resolve-DnsName app01.corp.lab; Get-DnsClientServerAddress' },
    { message: 'Remote Desktop can\'t connect to the remote computer for one of these reasons: 1) Remote access to the server is not enabled 2) The remote computer is turned off 3) The remote computer is not available on the network', layer: 'Network / firewall / listener / service', meaning: 'The TCP connection to 3389 failed. The message lists possibilities; it does not know which.', firstCheck: 'Test-NetConnection app01 -Port 3389; then on the server: fDenyTSConnections, Get-Service TermService, qwinsta, firewall rules' },
    { message: 'The remote computer requires Network Level Authentication, which your computer does not support.', layer: 'Security negotiation (NLA)', meaning: 'Server requires CredSSP and the client did not offer it (old or misconfigured client).', firstCheck: 'Client version; RDP-Tcp UserAuthentication' },
    { message: 'An authentication error has occurred. The function requested is not supported. ... This could be due to CredSSP encryption oracle remediation.', layer: 'NLA (CredSSP version)', meaning: 'Client and server have incompatible CredSSP patch levels/policy.', firstCheck: 'Update the unpatched side; gpresult for Encryption Oracle Remediation' },
    { message: 'An authentication error has occurred. The Local Security Authority cannot be contacted.', layer: 'NLA (domain authentication)', meaning: 'The server could not complete authentication with the domain (DC unreachable, broken secure channel), or the user must change the password at next logon.', firstCheck: 'nltest /sc_query:corp.lab on the server; DNS on the server; account flags in AD' },
    { message: 'There is a time and/or date difference between the client and server.', layer: 'NLA (Kerberos time)', meaning: 'Clock skew larger than the Kerberos tolerance (5 minutes by default).', firstCheck: 'w32tm /query /status on client, server and DC' },
    { message: 'The logon attempt failed', layer: 'Authentication', meaning: 'Wrong user name or password (or a stale saved credential).', firstCheck: 'RdpCoreTS 140; Security 4625 Sub Status; cmdkey /list' },
    { message: 'To sign in remotely, you need the right to sign in through Remote Desktop Services.', layer: 'Authorisation (user rights)', meaning: 'Authenticated, but the account lacks SeRemoteInteractiveLogonRight or is in the Deny right.', firstCheck: 'Get-LocalGroupMember "Remote Desktop Users"; gpresult /h; Security 4625 status 0xC000015B' },
    { message: 'The connection was denied because the user account is not authorized for remote login.', layer: 'Authorisation', meaning: 'Same layer as above (wording of some client/server versions): not in Remote Desktop Users or not granted the right.', firstCheck: 'Remote Desktop Users membership; User Rights Assignment GPO' },
    { message: 'The identity of the remote computer cannot be verified. Do you want to connect anyway?', layer: 'TLS (server certificate)', meaning: 'Self-signed or untrusted certificate, or the name used does not match the certificate (e.g. connecting by IP).', firstCheck: 'View certificate in the prompt; Cert:\\LocalMachine\\Remote Desktop on the server' },
    { message: 'The trust relationship between this workstation and the primary domain failed.', layer: 'Domain (secure channel)', meaning: 'The computer account password in AD no longer matches the server\'s (snapshot revert, re-imaged with same name).', firstCheck: 'Test-ComputerSecureChannel -Verbose (from the console, with a local admin account)' },
    { message: 'Restart-Service : Cannot stop service \'Remote Desktop Services (TermService)\' because it has dependent services. It can only be stopped if the Force flag is set.', layer: 'Service dependencies', meaning: 'UmRdpService depends on TermService.', firstCheck: 'Get-Service TermService -DependentServices; use -Force (and accept that sessions disconnect)' },
  ],

  scenarioIds: ['win-rdp-firewall', 'win-rdp-disabled', 'win-termservice-disabled', 'win-rdp-rights', 'win-account-disabled', 'win-rdp-port', 'win-rdp-profile'],
  assessmentId: 'windows-rdp',
  references: [
    { title: 'Microsoft Learn: Remote Desktop Services overview', url: 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/welcome-to-rds' },
    { title: 'Microsoft Learn: Troubleshoot Remote Desktop connections (general)', url: 'https://learn.microsoft.com/troubleshoot/windows-server/remote/troubleshoot-remote-desktop-connections' },
    { title: 'Microsoft Learn: Change the listening port for Remote Desktop', url: 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/change-listening-port' },
    { title: 'Microsoft Learn: CredSSP updates for CVE-2018-0886', url: 'https://support.microsoft.com/help/4093492' },
    { title: 'Microsoft Learn: Allow log on through Remote Desktop Services (user right)', url: 'https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services' },
    { title: 'Microsoft Learn: 4625(F) An account failed to log on', url: 'https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625' },
    { title: 'Microsoft Learn: Get-WinEvent', url: 'https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent' },
    { title: 'Microsoft Learn: Restart-Service', url: 'https://learn.microsoft.com/powershell/module/microsoft.powershell.management/restart-service' },
    { title: 'Microsoft Learn: Installation and configuration for Windows Remote Management', url: 'https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management' },
    { title: 'Microsoft Learn: Windows Defender Firewall with Advanced Security', url: 'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/' },
    { title: '[MS-RDPBCGR]: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting', url: 'https://learn.microsoft.com/openspecs/windows_protocols/ms-rdpbcgr/' },
    { title: '[MS-CSSP]: Credential Security Support Provider (CredSSP) Protocol', url: 'https://learn.microsoft.com/openspecs/windows_protocols/ms-cssp/' },
    { title: 'xrdp project', url: 'https://www.xrdp.org/' },
  ],
};

export const WINDOWS_RDP_ASSESSMENT: Assessment = {
  id: 'windows-rdp',
  title: 'Windows Server administration and RDP knowledge check',
  questions: [
    {
      id: 'windows-rdp-q-order',
      kind: 'order',
      level: 'intermediate',
      learn: ['lesson/windows-rdp/troubleshoot'],
      prompt: 'Helpdesk reports "Remote Desktop can\'t connect to the remote computer" for app01. Put the checks in the order you should do them (stop at the first failure).',
      items: [
        'Resolve-DnsName app01.corp.lab from the client',
        'Test-NetConnection app01 -Port 3389 from the client',
        'Get onto app01 via console or WinRM (not RDP)',
        'Check fDenyTSConnections (local and policy key)',
        'Check that TermService is running',
        'Check the listener with qwinsta and PortNumber',
        'Check the Remote Desktop firewall rules and the active profile',
      ],
      concepts: ['win.rdp', 'dns.resolution', 'tcp.handshake', 'win.services'],
      explanation: 'Client side bottom-up (name, then TCP), then a second way onto the server, then server side from "is RDP enabled at all" through service, listener and firewall. Authentication and user rights come later: this error means TCP never connected.',
    },
    {
      id: 'windows-rdp-q-tnc',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/windows-rdp/troubleshoot'],
      prompt: 'From WS01 you get this. What is the most useful conclusion?',
      exhibit: 'PS C:\\> Test-NetConnection app01.corp.lab -Port 3389\nWARNING: TCP connect to (10.0.20.21 : 3389) failed\n\nComputerName           : app01.corp.lab\nRemoteAddress          : 10.0.20.21\nRemotePort             : 3389\nInterfaceAlias         : Ethernet\nSourceAddress          : 10.0.10.25\nPingSucceeded          : True\nPingReplyDetails (RTT) : 1 ms\nTcpTestSucceeded       : False',
      options: [
        { text: 'DNS is broken.', misconception: 'The name resolved to 10.0.20.21 (RemoteAddress) and the host answered pings.' },
        { text: 'The user lacks the right to log on through Remote Desktop Services.', misconception: 'User rights are checked after TCP, TLS and authentication. Here TCP itself failed.' },
        { text: 'The host is reachable but nothing accepts TCP 3389: check RDP enabled, TermService, the listener port and the firewall on app01.', correct: true },
        { text: 'NLA is misconfigured.', misconception: 'NLA happens inside an established TCP connection.' },
      ],
      concepts: ['tcp.handshake', 'win.rdp'],
      explanation: 'Ping proves IP reachability (if ICMP is allowed); the TCP test failing isolates the problem to the 3389 path: a firewall (host or network), RDP disabled, service stopped, or listener on another port.',
    },
    {
      id: 'windows-rdp-q-restart',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-rdp/internals'],
      prompt: 'You are connected to app01 over RDP and need to restart Remote Desktop Services after changing the RDP certificate. What is the safe way?',
      options: [
        { text: 'Run Restart-Service TermService -Force in your RDP session.', misconception: 'Restarting TermService disconnects every RDP session, including yours; if it fails to start you have no way back in.' },
        { text: 'From another host: Invoke-Command -ComputerName app01 { Restart-Service TermService -Force } (or use the console/iLO), after warning logged-on users.', correct: true },
        { text: 'Reboot app01; it restarts all services.', misconception: 'A reboot is a much larger outage for every user and service on the server, and does not help if RDS fails to start.' },
        { text: 'Run gpupdate /force.', misconception: 'That re-applies policy; it does not restart TermService or load a new certificate.' },
      ],
      concepts: ['win.services', 'win.rdp', 'ops.recovery'],
      explanation: 'WinRM is a different service (TCP 5985) and survives the RDS restart. -Force is needed because UmRdpService depends on TermService; Restart-Service starts it again too. Verify with Get-Service TermService, UmRdpService and qwinsta.',
    },
    {
      id: 'windows-rdp-q-4625',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-rdp/config', 'lesson/windows-rdp/troubleshoot'],
      prompt: 'After a new security baseline GPO, helpdesk users cannot RDP to servers but Domain Admins can. app01\'s Security log shows the event below. Where is the fix?',
      exhibit: 'An account failed to log on.\n\nLogon Type:\t\t\t10\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\th.lee\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tThe user has not been granted the requested logon type at this machine.\n\tStatus:\t\t\t0xC000015B\n\tSub Status:\t\t0x0',
      options: [
        { text: 'In the GPO\'s User Rights Assignment: "Allow log on through Remote Desktop Services" must include Remote Desktop Users (or the helpdesk group), then gpupdate /force.', correct: true },
        { text: 'Restart Remote Desktop Services on app01.', misconception: 'The service works (admins connect). The LSA refused the logon type; a restart changes nothing and disconnects everyone.' },
        { text: 'Reset h.lee\'s password.', misconception: 'Authentication succeeded; the failure is the logon right (0xC000015B), not the password (0xC000006A).' },
        { text: 'Add the helpdesk group to Administrators on all servers.', misconception: 'That grants far more than needed. Fix the user right in the GPO that defines it.' },
      ],
      concepts: ['ad.gpo', 'win.rdp'],
      explanation: 'Logon Type 10 is RemoteInteractive (RDP). A GPO that defines a user right replaces the local list on every computer in scope; the baseline listed only Administrators. `gpresult /h` shows the winning GPO. This is case study F (rdp-after-change).',
    },
    {
      id: 'windows-rdp-q-qwinsta',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-rdp/troubleshoot'],
      prompt: 'On app01 (via the hypervisor console) TermService is Running, the firewall rules are enabled, but clients cannot connect to 3389. You run qwinsta. What is wrong?',
      exhibit: ' SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n services                                    0  Disc\n>console           Administrator             1  Active',
      options: [
        { text: 'Nothing; the listener is not shown by qwinsta.', misconception: 'A working server shows "rdp-tcp ... 65536 Listen".' },
        { text: 'There is no RDP listener: RDP is disabled (fDenyTSConnections = 1 locally or by policy) or the RDP-Tcp configuration is broken.', correct: true },
        { text: 'The administrator is logged on at the console, which blocks RDP.', misconception: 'Console and RDP sessions coexist on Windows Server (up to two administrative RDP sessions).' },
        { text: 'The client\'s NLA settings are wrong.', misconception: 'Clients cannot even open TCP 3389; NLA is not reached.' },
      ],
      concepts: ['win.rdp', 'win.services'],
      explanation: 'Check `reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections` and the policy key; if RDP is enabled, compare the RDP-Tcp key with your exported backup and restart TermService.',
    },
    {
      id: 'windows-rdp-q-nla-domain',
      kind: 'multi',
      level: 'advanced',
      learn: ['lesson/windows-rdp/troubleshoot'],
      prompt: 'Domain users get "An authentication error has occurred. The Local Security Authority cannot be contacted." when connecting to app01, but the local Administrator account can log on through RDP. Which causes fit? (Select all that apply.)',
      options: [
        { text: 'app01 uses a DNS server that cannot resolve the corp.lab DC records', correct: true },
        { text: 'app01\'s secure channel with the domain is broken', correct: true },
        { text: 'A firewall between app01 and dc01 blocks Kerberos/LDAP', correct: true },
        { text: 'TCP 3389 is blocked', misconception: 'The local account connects, so TCP, TLS and the listener work.' },
        { text: 'TermService is stopped', misconception: 'The local account gets a session; the service runs.' },
      ],
      concepts: ['ad.kerberos', 'ad.dns', 'win.rdp'],
      explanation: 'NLA for domain accounts needs the server to reach a DC: DNS to find it, network access to it, and a valid computer account (secure channel). Local accounts are checked against the local SAM, so their success isolates the domain dependency. Check with `nltest /sc_query:corp.lab` and `Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab`.',
    },
    {
      id: 'windows-rdp-q-credssp',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-rdp/troubleshoot'],
      prompt: 'An old, unpatched Windows server cannot be reached from patched clients: "An authentication error has occurred. The function requested is not supported ... This could be due to CredSSP encryption oracle remediation." What is the correct permanent fix?',
      options: [
        { text: 'Set the client policy "Encryption Oracle Remediation" to Vulnerable.', misconception: 'That re-enables the vulnerability (CVE-2018-0886) on every client it applies to. At most an emergency workaround, recorded and removed.' },
        { text: 'Install current security updates on the unpatched server.', correct: true },
        { text: 'Disable NLA on the server.', misconception: 'That removes pre-authentication for everyone and is a security regression, not a fix.' },
        { text: 'Restart Remote Desktop Services on the server.', misconception: 'The CredSSP version does not change with a restart.' },
      ],
      concepts: ['win.rdp'],
      explanation: 'CredSSP patches from 2018 must be on both sides when clients use "Mitigated" or "Force Updated Clients". Update the old side.',
    },
    {
      id: 'windows-rdp-q-port',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/windows-rdp/internals', 'lesson/windows-rdp/config'],
      prompt: 'A colleague changed RDP on app01 to port 3390 by editing PortNumber. Which further steps are required for clients to connect on 3390? (Select all that apply.)',
      options: [
        { text: 'Restart TermService (from console or WinRM)', correct: true },
        { text: 'Create an inbound firewall rule for TCP (and UDP) 3390', correct: true },
        { text: 'Clients connect with mstsc /v:app01:3390', correct: true },
        { text: 'Run gpupdate /force', misconception: 'PortNumber is not a Group Policy setting; policy refresh does not recreate the listener.' },
        { text: 'Nothing: the built-in Remote Desktop rules follow the configured port', misconception: 'The built-in rules allow port 3389 only.' },
      ],
      concepts: ['win.rdp', 'win.services'],
      explanation: 'The listener reads PortNumber when it is created, so TermService must restart (disconnecting sessions). Moving the port reduces scanner noise but is not a security control; restrict source addresses instead.',
    },
    {
      id: 'windows-rdp-q-events',
      kind: 'text',
      level: 'intermediate',
      learn: ['lesson/windows-rdp/operate'],
      prompt: 'Type the event ID in the System log (source Service Control Manager) that records "The start type of the Remote Desktop Services service was changed from demand start to disabled."',
      accept: ['7040'],
      placeholder: 'event ID',
      concepts: ['win.services'],
      explanation: '7040 records start-type changes; 7036 records state changes (running/stopped), 7031/7034 unexpected termination, 7000 failure to start.',
    },
    {
      id: 'windows-rdp-q-getwinevent',
      kind: 'text',
      level: 'advanced',
      learn: ['lesson/windows-rdp/internals'],
      prompt: 'Type a Get-WinEvent command that returns failed logon events (ID 4625) from the Security log using -FilterHashtable.',
      accept: [/^get-winevent\s+-filterhashtable\s+@\{\s*logname\s*=\s*['"]?security['"]?\s*;\s*id\s*=\s*4625\s*\}.*$/i, /^get-winevent\s+-filterhashtable\s+@\{\s*id\s*=\s*4625\s*;\s*logname\s*=\s*['"]?security['"]?\s*\}.*$/i],
      placeholder: 'PowerShell command',
      concepts: ['win.services', 'win.rdp'],
      explanation: '`Get-WinEvent -FilterHashtable @{LogName=\'Security\'; Id=4625}` filters in the event log service, which is much faster than piping every event to Where-Object. Add StartTime to limit the time range and `| Format-List` to read Status, Sub Status and Logon Type.',
    },
    {
      id: 'windows-rdp-q-home',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/windows-rdp/deploy'],
      prompt: 'A user wants to RDP into their Windows 11 **Home** laptop from the office. What do you tell them?',
      options: [
        { text: 'Enable it in Settings > System > Remote Desktop.', misconception: 'That page offers no host toggle on Home: Home editions cannot accept RDP connections.' },
        { text: 'Home editions include the RDP client but cannot host RDP sessions; Pro, Enterprise or Education is required (or another remote-support tool).', correct: true },
        { text: 'Open TCP 3389 in the firewall and start TermService.', misconception: 'The RDP host components are not licensed/enabled on Home; opening the port does not help.' },
      ],
      concepts: ['win.rdp'],
      explanation: 'Remote Desktop host is available on Windows 10/11 Pro, Enterprise and Education, one session at a time. Windows Server allows two administrative sessions without RDS licensing.',
    },
    {
      id: 'windows-rdp-q-winrm',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/windows-rdp/internals'],
      prompt: 'Which port does WinRM (PowerShell remoting) use by default over HTTP, and why is it useful when RDP is broken?',
      options: [
        { text: 'TCP 5985: it is a separate service, so you can run Get-Service, qwinsta or Restart-Service TermService remotely without depending on RDP.', correct: true },
        { text: 'TCP 3389: it shares the RDP listener.', misconception: 'WinRM has its own listener; it does not depend on TermService.' },
        { text: 'TCP 22: it uses SSH.', misconception: 'PowerShell 7 can remote over SSH, but WinRM uses 5985/5986.' },
        { text: 'UDP 5986: it is connectionless.', misconception: '5986 is WinRM over HTTPS, on TCP.' },
      ],
      concepts: ['win.services', 'ops.recovery'],
      explanation: 'WinRM listens on TCP 5985 (HTTP; messages are still encrypted with Kerberos/NTLM) and 5986 (HTTPS). `Test-WSMan app01` checks it; `Invoke-Command`/`Enter-PSSession` use it.',
    },
  ],
};
