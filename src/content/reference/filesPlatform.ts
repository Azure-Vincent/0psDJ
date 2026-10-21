// Reference library: Windows/AD, Docker and pfSense files, registry keys and logs.
// Ids are "file:<short-name>". Example content is representative of the named platform.

import type { FileRef } from '../types';

const raw = String.raw;

export const FILES_PLATFORM: FileRef[] = [
  // --- Windows / Active Directory --------------------------------------------------
  {
    id: 'file:winevt-logs',
    path: '%SystemRoot%\\System32\\winevt\\Logs\\*.evtx',
    platform: 'Windows Server 2019/2022, Windows 10/11',
    kind: 'eventlog',
    services: ['RDP', 'Active Directory', 'Kerberos', 'Group Policy', 'DNS', 'Time sync', 'Windows networking'],
    purpose: 'The Windows event logs: one binary .evtx file per channel. They are where Windows records why a service failed, who logged on (or failed to), and what the domain services are doing. Read them with Event Viewer or `Get-WinEvent`, never by opening the files.',
    contents: '**System** (service control manager, Netlogon, Time-Service, GroupPolicy errors): 7036 service entered running/stopped state, 7031/7034 service terminated unexpectedly, 7000/7023 service failed to start, 5719 Netlogon could not set up a secure session with a DC, 3210 this computer could not authenticate with a DC (broken trust), 1058/1030/1129 Group Policy could not read gpt.ini / query GPOs / reach a DC, Time-Service 36 (not synchronized for 86400 seconds) and 129 (NtpClient could not find a domain peer), Security-Kerberos 4 (KRB_AP_ERR_MODIFIED: duplicate or wrong SPN). **Security** (auditing must be enabled): 4624 logon success (type 3 network, type 10 RemoteInteractive = RDP), 4625 logon failure (Status/Sub Status code gives the reason), 4740 account locked out; on DCs 4768 TGT request (result 0x18 bad password, 0x25 clock skew), 4769 service ticket request, 4771 Kerberos pre-authentication failed. **Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational**: 1149 network-level user authentication succeeded (connection reached the server). **Microsoft-Windows-TerminalServices-LocalSessionManager/Operational**: 21 session logon succeeded, 24 session disconnected, 25 session reconnected. **Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational**: 131 server accepted a TCP connection, 140 connection failed because user name or password was incorrect. **Directory Service** (DCs): 2042 too long since last replication (tombstone lifetime exceeded: do not force replication), 1311 KCC cannot build a replication topology, 1925/2087 replication link or DNS lookup failure. **DNS Server**: 4013 DNS server waiting for AD DS initial synchronization (normal briefly after a DC reboot, a problem if it persists), 4000/4007 zone load failures. **DFS Replication**: 4602 SYSVOL initialised, 4012 replication stopped for too long, 2213 stopped after a dirty shutdown. **Microsoft-Windows-GroupPolicy/Operational**: per-run detail (4000-series start, 5000-series success, 7000-series errors, 5312 list of applicable GPOs). **Microsoft-Windows-Time-Service/Operational** (Server 2016+): time source changes and sync detail.',
    accessed: 'Written continuously by the Event Log service (EventLog, running in svchost). Each channel has a maximum size and a retention mode (default: overwrite oldest), so busy logs such as Security on a DC may only cover hours. File names replace "/" with "%4", e.g. `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`.',
    permissions: 'SYSTEM, Administrators; Event Log Readers (read). Security log: Administrators / Event Log Readers / "Manage auditing and security log" right.',
    problems: 'Missing events usually mean auditing is not enabled (Security 4625/4771 need the Logon and Kerberos audit policies) or the log wrapped. Clearing a log is itself logged (1102 in Security) and destroys evidence: export first (`wevtutil epl Security C:\\temp\\sec.evtx`). Copying the .evtx of a running system needs `wevtutil epl`, as the file is locked. Event IDs are per provider: always read the Source together with the ID (e.g. 129 from Time-Service is not the storage 129 from storahci/stornvme).',
    example: raw`PS> Get-WinEvent -FilterHashtable @{LogName='System'; Id=5719,3210} -MaxEvents 2 | Format-List TimeCreated, Id, Message

TimeCreated : 10/21/2026 8:02:44 AM
Id          : 3210
Message     : This computer could not authenticate with \\dc01.corp.lab, a Windows domain controller for domain CORP,
              and therefore this computer might deny logon requests. This inability to authenticate might be caused
              by another computer on the same network using the same name or the password for this computer account
              is not recognized. If this message appears again, contact your system administrator.`,
    relatedCommands: ['get-winevent', 'nltest', 'w32tm', 'gpupdate', 'qwinsta'],
  },
  {
    id: 'file:reg-terminal-server',
    path: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server',
    platform: 'Windows Server 2019/2022, Windows 10/11 (Pro/Enterprise)',
    kind: 'registry',
    services: ['RDP'],
    purpose: 'Top-level Remote Desktop Services settings. `fDenyTSConnections` is the master switch that "Allow remote connections to this computer" (sysdm.cpl / Settings > Remote Desktop / Server Manager) toggles.',
    contents: '`fDenyTSConnections` (REG_DWORD): 0 = RDP connections allowed, 1 = denied (default on a fresh install). Subkey `WinStations\\RDP-Tcp` holds the listener settings (see file:reg-rdp-tcp). Group Policy writes an overriding value at `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\fDenyTSConnections` ("Allow users to connect remotely by using Remote Desktop Services"); when present, it wins.',
    accessed: 'Read by the Remote Desktop Services service (TermService); a change of fDenyTSConnections is picked up without a restart. The firewall rule group "Remote Desktop" is enabled by the GUI but **not** when you edit the value directly.',
    permissions: 'Administrators and SYSTEM: full control; Users: read.',
    problems: 'Value 1 (or a GPO setting it to deny) makes the server refuse RDP with a connection failure even though the server is healthy. Setting it to 0 by registry or PowerShell without enabling the firewall rules leaves port 3389 blocked. A GPO re-applies its value at every refresh (90 minutes), silently reverting a local fix.',
    example: raw`PS> Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
PS> Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
PS> reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDenyTSConnections
ERROR: The system was unable to find the specified registry key or value.      <- no GPO override: good`,
    relatedCommands: ['reg-query', 'get-netfirewallrule', 'qwinsta'],
  },
  {
    id: 'file:reg-rdp-tcp',
    path: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
    platform: 'Windows Server 2019/2022, Windows 10/11 (Pro/Enterprise)',
    kind: 'registry',
    services: ['RDP'],
    purpose: 'Settings of the RDP listener: the TCP port, whether Network Level Authentication is required, and the security layer and certificate.',
    contents: '`PortNumber` (REG_DWORD, default 3389 = 0xd3d). `UserAuthentication` (REG_DWORD): 1 = NLA required (default), 0 = not required. `SecurityLayer` (REG_DWORD): 0 = RDP security, 1 = negotiate, 2 = TLS (default on current versions). `MinEncryptionLevel`, `SSLCertificateSHA1Hash` (a specific certificate for the listener; otherwise a self-signed "Remote Desktop" certificate is used).',
    accessed: 'Read by TermService when it creates the listener. A change of PortNumber needs a restart of TermService (or a reboot), which disconnects all sessions.',
    permissions: 'Administrators and SYSTEM: full control; Users: read.',
    problems: 'A changed PortNumber without a matching firewall rule makes RDP unreachable after the next restart (clients must also use `host:port`). With NLA, the user is authenticated before a session exists: domain accounts then need a reachable DC, expired passwords cannot be changed at logon, and clients report "An authentication error has occurred" (CredSSP) or the NLA-not-supported message. SSLCertificateSHA1Hash pointing at a deleted/expired certificate breaks the listener (TermService errors in the System log; no Listen line in qwinsta).',
    example: raw`PS> Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |
      Select-Object PortNumber, UserAuthentication, SecurityLayer

PortNumber UserAuthentication SecurityLayer
---------- ------------------ -------------
      3389                  1             2`,
    relatedCommands: ['reg-query', 'qwinsta', 'get-netfirewallrule', 'restart-service'],
  },
  {
    id: 'file:reg-services',
    path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>',
    platform: 'Windows Server 2019/2022, Windows 10/11',
    kind: 'registry',
    services: ['Windows networking', 'RDP', 'Active Directory', 'WinRM'],
    purpose: 'The Service Control Manager database: one subkey per service and driver, holding how and when it starts, which binary runs, as which account, and what it depends on.',
    contents: '`Start` (REG_DWORD): 0 Boot, 1 System (drivers), 2 Automatic, 3 Manual, 4 Disabled; `DelayedAutostart` = 1 for "Automatic (Delayed Start)". `ImagePath`: the executable (or `svchost.exe -k group`). `ObjectName`: account (LocalSystem, NT AUTHORITY\\NetworkService, a domain account). `DependOnService` (REG_MULTI_SZ): services that must start first. `FailureActions`: recovery settings. Service-specific settings often live under `Parameters`.',
    accessed: 'Read by the Service Control Manager at boot to build its in-memory database. **Changes made directly in the registry are generally not seen by the SCM until the next reboot**; changes through `sc.exe config` or Set-Service update both.',
    permissions: 'Administrators and SYSTEM: full control; Users: read. Some keys have tighter ACLs.',
    problems: 'Start = 4 makes the service refuse to start (error 1058). A wrong DependOnService gives error 1075 ("The dependency service does not exist or has been marked for deletion") or 1068 ("The dependency service or group failed to start"). An unquoted ImagePath containing spaces is a privilege-escalation risk. A domain account in ObjectName whose password changed gives error 1069 (logon failure) at the next start. Deleting a subkey removes the service.',
    example: raw`C:\> reg query HKLM\SYSTEM\CurrentControlSet\Services\TermService /v DependOnService

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService
    DependOnService    REG_MULTI_SZ    RPCSS`,
    relatedCommands: ['sc', 'get-service', 'restart-service', 'reg-query'],
  },
  {
    id: 'file:hosts-win',
    path: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
    platform: 'Windows Server 2019/2022, Windows 10/11',
    kind: 'config',
    services: ['DNS', 'Windows networking'],
    purpose: 'Static name-to-address mappings consulted by the Windows resolver before DNS. Useful for temporary tests, dangerous when forgotten.',
    contents: 'Lines of `address  name [aliases]`; `#` starts a comment. The default file contains only comments (localhost is resolved internally).',
    accessed: 'Read by the DNS Client service (Dnscache); entries are loaded into the DNS cache (`ipconfig /displaydns`) and take effect within seconds of saving. Not used by `nslookup`, which always queries a DNS server directly.',
    permissions: 'Administrators and SYSTEM: full control; Users: read. Editing needs an elevated editor.',
    problems: 'A stale entry makes one machine connect to an old IP while everyone else is fine, and nslookup shows the "right" answer, which is confusing: compare `Resolve-DnsName name` with `Resolve-DnsName name -NoHostsFile`. Notepad may save it as `hosts.txt` (ignored). Saving in UTF-16 ("Unicode") encoding is a known cause of entries being ignored: use ANSI/UTF-8. Microsoft Defender flags hosts entries that redirect well-known domains as a threat (SettingsModifier:Win32/HostsFileHijack).',
    example: raw`# Temporary: test the new web server before the DNS change (remove after cut-over, ticket CHG-1042)
10.0.20.12    web01.corp.lab web01`,
    relatedCommands: ['resolve-dnsname', 'nslookup-win', 'ipconfig'],
  },
  {
    id: 'file:windows-firewall-log',
    path: '%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log',
    platform: 'Windows Server 2019/2022, Windows 10/11',
    kind: 'log',
    services: ['Firewall', 'RDP', 'Windows networking'],
    purpose: 'Windows Defender Firewall packet log: which connections were dropped (and optionally allowed). The only direct proof that the host firewall blocked something.',
    contents: 'W3C-style text: a header with `#Fields:` then one line per packet: date, time, action (DROP/ALLOW), protocol, src-ip, dst-ip, src-port, dst-port, size, TCP flags, and path (RECEIVE/SEND). Newer builds may append extra fields such as pid.',
    accessed: '**Logging is off by default** for every profile. When enabled, the firewall service (MpsSvc) appends to the file; it rolls to pfirewall.log.old at the size limit (default 4096 KB).',
    permissions: 'Written by NT SERVICE\\mpssvc; readable by Administrators. If you choose another directory, mpssvc needs write permission there or nothing is logged.',
    problems: 'An empty or missing file usually means logging is off for the active profile (logging is per profile: Domain, Private, Public). Logging allowed connections on a busy server fills the file within minutes. Drops by third-party firewalls or by the network (not the host) never appear here.',
    example: raw`PS> Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogMaxSizeKilobytes 16384
PS> Get-Content $env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log -Tail 3
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

2026-10-21 09:31:07 DROP TCP 10.0.10.25 10.0.20.30 51544 3389 52 S 1874625310 0 64240 - - - RECEIVE`,
    relatedCommands: ['get-netfirewallrule', 'tnc'],
  },
  {
    id: 'file:reg-w32time',
    path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters (and \\Config, \\TimeProviders)',
    platform: 'Windows Server 2019/2022, Windows 10/11',
    kind: 'registry',
    services: ['Time sync', 'Kerberos', 'Active Directory'],
    purpose: 'Configuration of the Windows Time service: where the machine gets its time and how aggressively it corrects it.',
    contents: '`Parameters\\Type`: NT5DS (follow the domain hierarchy: default for domain members and DCs), NTP (use NtpServer list: default for workgroup machines and what the forest-root PDC emulator should use), NoSync. `Parameters\\NtpServer`: e.g. `0.pool.ntp.org,0x8 1.pool.ntp.org,0x8` (0x8 = client mode). `Config\\AnnounceFlags`: 5 marks a reliable time source (PDC emulator), default 10. `Config\\MaxPosPhaseCorrection` / `MaxNegPhaseCorrection`: largest correction in seconds w32time will make (defaults differ between domain members and stand-alone machines). `TimeProviders\\VMICTimeProvider\\Enabled`: hypervisor time sync provider (Hyper-V).',
    accessed: 'Read by the W32Time service at start and when told to reload (`w32tm /config /update`). Prefer `w32tm /config` over editing values: it validates and triggers the reload.',
    permissions: 'Administrators and SYSTEM: full control; Users: read.',
    problems: 'A member or non-PDC DC with Type = NTP ignores the domain hierarchy and can drift from its DC. A PDC emulator with Type = NT5DS has no authoritative source ("Local CMOS Clock"). On virtual DCs, an enabled VMICTimeProvider lets the host clock override domain time. When the offset exceeds MaxPos/NegPhaseCorrection, w32time logs an error and refuses to correct, so Kerberos keeps failing with KRB_AP_ERR_SKEW until the clock is set manually.',
    example: raw`C:\> w32tm /query /configuration | findstr /i "Type NtpServer AnnounceFlags"
AnnounceFlags: 5 (Local)
NtpServer: 0.pool.ntp.org,0x8 1.pool.ntp.org,0x8 (Local)
Type: NTP (Local)`,
    relatedCommands: ['w32tm', 'reg-query'],
  },
  {
    id: 'file:ntds.dit',
    path: 'C:\\Windows\\NTDS\\ntds.dit (with edb.chk, edb*.log, edbres*.jrs)',
    platform: 'Windows Server 2019/2022 (domain controllers)',
    kind: 'data',
    services: ['Active Directory', 'Kerberos'],
    purpose: 'The Active Directory database on a domain controller: every user, group, computer, GPO link and, critically, every password hash in the domain.',
    contents: 'An ESE (Extensible Storage Engine) database plus transaction logs (edb*.log) and a checkpoint file (edb.chk). The location is set at promotion (Dcpromo/Install-ADDSDomainController -DatabasePath) and recorded under `HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters`.',
    accessed: 'Held open and locked by lsass.exe while AD DS (service NTDS) runs. Writes go to the logs first, then the database. Since Server 2008, AD DS is a restartable service, so offline maintenance (ntdsutil "files" / "semantic database analysis") can be done after `Stop-Service NTDS` without DSRM boot.',
    permissions: 'SYSTEM and Administrators only. Anyone who can read a copy of this file (plus the SYSTEM hive for the boot key) can extract every password hash: treat it and its backups as the most sensitive data in the domain.',
    problems: 'Running out of disk space on its volume makes AD DS stop or refuse writes. Never copy, replace or roll back the file by hand, and never restore a DC from a VM snapshot or disk copy: that causes USN rollback (the DC stops replicating, Directory Service event 2095) unless the hypervisor supports VM-GenerationID. Use system-state backups (Windows Server Backup) and authoritative/non-authoritative restore. Anti-virus scanning of the NTDS folder causes corruption and performance issues: exclude it.',
    example: raw`PS> Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters |
      Select-Object 'DSA Database file', 'Database log files path'

DSA Database file           Database log files path
-----------------           -----------------------
C:\Windows\NTDS\ntds.dit    C:\Windows\NTDS`,
    relatedCommands: ['dcdiag', 'repadmin'],
  },
  {
    id: 'file:sysvol',
    path: 'C:\\Windows\\SYSVOL (shared as \\\\corp.lab\\SYSVOL and \\\\corp.lab\\NETLOGON)',
    platform: 'Windows Server 2019/2022 (domain controllers)',
    kind: 'config-dir',
    services: ['Group Policy', 'Active Directory'],
    purpose: 'The replicated folder holding Group Policy templates and logon scripts. Clients read GPO settings from here over SMB after finding the GPO list in AD over LDAP.',
    contents: '`sysvol\\corp.lab\\Policies\\{GUID}\\` per GPO (gpt.ini with the version number, Machine\\ and User\\ settings, Registry.pol); `sysvol\\corp.lab\\scripts\\` shared as NETLOGON. The DFS namespace `\\\\corp.lab\\SYSVOL` resolves to any DC.',
    accessed: 'Read by every domain member at boot, logon and every policy refresh. Replicated between DCs by DFS Replication (DFSR); FRS is deprecated and Server 2019+ cannot join a domain still using FRS for SYSVOL. A DC only shares SYSVOL/NETLOGON once initial replication finished (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SysvolReady` = 1).',
    permissions: 'Authenticated Users: read; Administrators/SYSTEM/Server Operators: modify. Edit GPOs through GPMC, never by hand.',
    problems: 'If a DC is not sharing SYSVOL/NETLOGON (`net share` lacks them), clients using that DC fail Group Policy with event 1058. DFSR stopped by a dirty shutdown (event 2213) or offline too long (4012) leaves GPO versions differing between DCs (the AD part and the SYSVOL part of a GPO out of step), giving inconsistent results depending on which DC the client uses. Large files dropped into SYSVOL slow replication.',
    example: raw`C:\> net share | findstr /i "SYSVOL NETLOGON"
NETLOGON     C:\Windows\SYSVOL\sysvol\corp.lab\SCRIPTS   Logon server share
SYSVOL       C:\Windows\SYSVOL\sysvol                     Logon server share

C:\> dfsrmig /getmigrationstate
All domain controllers have migrated successfully to the Global state ('Eliminated').
Migration has reached a consistent state on all domain controllers.
Succeeded.`,
    relatedCommands: ['gpupdate', 'gpresult', 'dcdiag', 'repadmin'],
  },
  {
    id: 'file:netlogon.log',
    path: '%SystemRoot%\\debug\\netlogon.log (rotates to netlogon.bak)',
    platform: 'Windows Server 2019/2022, Windows 10/11',
    kind: 'log',
    services: ['Active Directory', 'Kerberos'],
    purpose: 'Debug log of the Netlogon service: DC discovery, secure channel setup and NTLM pass-through authentication. Used when "trust relationship" or logon problems are not explained by the event log.',
    contents: 'One line per event with timestamp, category ([SESSION], [LOGON], [CRITICAL], [MISC], [SITE]) and thread ID. Useful lines: `NlSessionSetup: Session setup Failed`, `SamLogon ... Returns 0xC000006A` (wrong password), `NO_CLIENT_SITE: <name> <ip>` (client subnet not mapped to an AD site).',
    accessed: 'Disabled by default (only minimal output). Enable with `nltest /dbflag:0x2080ffff`, reproduce the problem, then disable with `nltest /dbflag:0x0`. Current versions apply the flag without restarting Netlogon. The file rolls to netlogon.bak at the maximum size (MaximumLogFileSize under Netlogon\\Parameters).',
    permissions: 'Administrators (C:\\Windows\\debug is not readable by standard users).',
    problems: 'Left enabled on a busy DC, it rotates quickly and the interesting lines are lost; it adds some I/O. It contains user and computer names and IPs: handle as sensitive. Status codes are NTSTATUS values (0xC000006A wrong password, 0xC0000064 no such user, 0xC0000234 locked, 0xC000018B no trust SAM account).',
    example: raw`10/21 09:41:12 [LOGON] [1234] CORP: SamLogon: Transitive Network logon of CORP\alice from WS01 (via SRV02) Entered
10/21 09:41:12 [LOGON] [1234] CORP: SamLogon: Transitive Network logon of CORP\alice from WS01 (via SRV02) Returns 0xC000006A
10/21 09:42:03 [CRITICAL] [1280] NlDiscoverDc: Cannot find DC.
10/21 09:42:03 [SESSION] [1280] CORP: NlSessionSetup: Session setup Failed
10/21 09:44:10 [MISC] [1180] CORP: NO_CLIENT_SITE: DEV01 10.0.30.20`,
    relatedCommands: ['nltest', 'get-winevent'],
  },
  // --- Docker ------------------------------------------------------------------------
  {
    id: 'file:daemon.json',
    path: '/etc/docker/daemon.json',
    platform: 'Docker Engine 27 (Linux host); Windows: C:\\ProgramData\\docker\\config\\daemon.json',
    kind: 'config',
    services: ['Docker', 'Networking', 'DNS'],
    purpose: 'Configuration file of the Docker daemon (dockerd): logging defaults, address pools, DNS for containers, storage location, live-restore and registry settings.',
    contents: 'A single JSON object. Common keys: `log-driver` and `log-opts` (`{"max-size":"10m","max-file":"3"}`), `live-restore` (keep containers running while dockerd restarts), `default-address-pools` and `bip` (subnets for networks/the default bridge), `dns` (resolvers handed to containers), `data-root` (instead of /var/lib/docker), `iptables`, `registry-mirrors`, `insecure-registries`. The file does not exist by default.',
    accessed: 'Read when dockerd starts. A subset (debug, labels, live-restore, registry-mirrors, insecure-registries, max-concurrent-downloads ...) is reloaded on SIGHUP (`systemctl reload docker`); everything else needs a daemon restart. Log options apply only to containers created afterwards.',
    permissions: 'root:root 0644.',
    problems: 'Invalid JSON (trailing comma, comments) makes dockerd fail to start, which takes every container down: validate with `dockerd --validate --config-file /etc/docker/daemon.json` first. A key set both here and as a command-line flag in the systemd unit (classic: `hosts` with `-H fd://`) also stops the daemon: "the following directives are specified both as a flag and in the configuration file". Default subnets overlapping a real LAN make that LAN unreachable from the host.',
    example: raw`{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "default-address-pools": [ { "base": "172.30.0.0/16", "size": 24 } ]
}

$ sudo dockerd --validate --config-file /etc/docker/daemon.json
configuration OK`,
    relatedCommands: ['docker', 'docker-network', 'systemctl', 'journalctl'],
  },
  {
    id: 'file:var-lib-docker',
    path: '/var/lib/docker/',
    platform: 'Docker Engine 27 (Linux host)',
    kind: 'data',
    services: ['Docker'],
    purpose: 'Docker\'s state directory: image layers, container writable layers and metadata, named volumes, networks and build cache.',
    contents: '`overlay2/` image and container layers; `containers/<id>/` config.v2.json, hostconfig.json, <id>-json.log, resolv.conf, hosts; `volumes/<name>/_data` named volume contents; `image/` image metadata; `network/files/local-kv.db` network database; `buildkit/` build cache.',
    accessed: 'Owned and constantly written by dockerd and containerd. Location can be changed with `data-root` in daemon.json (rootless Docker uses ~/.local/share/docker).',
    permissions: 'root:root, mode 0710 on current releases; contents root-only.',
    problems: 'Never delete or edit files here by hand while Docker runs: it corrupts Docker\'s metadata. Use `docker system df` to see usage and `docker image prune`, `docker builder prune`, `docker volume prune` to reclaim space (volume prune deletes data). A full filesystem gives "no space left on device" in builds and containers and can stop dockerd. Back up volumes from `volumes/<name>/_data` only with the container stopped (or via the application\'s own dump tool).',
    example: raw`$ docker system df
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          14        3         5.2GB     4.1GB (78%)
Containers      3         2         12.4MB    0B (0%)
Local Volumes   4         2         1.8GB     310MB (17%)
Build Cache     52        0         2.3GB     2.3GB`,
    relatedCommands: ['docker', 'docker-inspect'],
  },
  {
    id: 'file:compose-yaml',
    path: '<project>/compose.yaml (also compose.yml, docker-compose.yaml, docker-compose.yml) and <project>/.env',
    platform: 'Docker Engine 27, Compose v2',
    kind: 'config',
    services: ['Docker'],
    purpose: 'Declarative definition of a multi-container application: services, images, ports, volumes, networks, environment and dependencies. `.env` in the project directory supplies variables for `${VAR}` interpolation.',
    contents: 'Top-level `services:`, `volumes:`, `networks:` (optional `name:` for the project). Per service: `image`/`build`, `ports` ("8080:80"), `environment`/`env_file`, `volumes`, `depends_on` (with `condition: service_healthy`), `healthcheck`, `restart`. The `version:` key is obsolete in Compose v2.',
    accessed: 'Read every time you run `docker compose ...` in that directory; nothing watches it. Editing the file changes nothing until `docker compose up -d`, which recreates only services whose configuration changed. Variables in `.env` are used for interpolation only; they reach the container only through `environment:` or `env_file:`.',
    permissions: 'Readable by the user running compose; `.env` holding secrets: 0600, and never committed to git.',
    problems: 'YAML indentation errors and tabs fail parsing; unquoted port mappings can be misparsed (quote them: "22:22"). `docker compose restart` after an edit does nothing visible, a common source of "my change did not work". Renaming a service leaves the old container running as an orphan (`--remove-orphans`). Publishing a database port on 0.0.0.0 exposes it to the network, and Docker\'s iptables rules bypass ufw/firewalld INPUT rules.',
    example: raw`services:
  app:
    image: nginx:1.27
    ports:
      - "8080:80"
    depends_on:
      db:
        condition: service_healthy
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: ${"$"}{DB_PASSWORD}
    volumes:
      - dbdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
volumes:
  dbdata:`,
    relatedCommands: ['docker-compose', 'docker-logs', 'docker-network'],
  },
  {
    id: 'file:docker-sock',
    path: '/var/run/docker.sock (symlink target /run/docker.sock)',
    platform: 'Docker Engine 27 (Linux host)',
    kind: 'runtime',
    services: ['Docker'],
    purpose: 'Unix socket on which dockerd serves its API. The docker CLI, Compose, and tools such as Portainer or Traefik talk to Docker through it.',
    contents: 'A socket, not a file with content. Created by the docker.socket systemd unit (socket activation) or by dockerd.',
    accessed: 'Every `docker` command. Containers that mount it (`-v /var/run/docker.sock:/var/run/docker.sock`) can control the daemon.',
    permissions: 'srw-rw---- root:docker (0660).',
    problems: '**Access to this socket is root on the host**: anyone in the `docker` group, or any container with the socket mounted, can start a privileged container that mounts `/`. Add only administrators to the group; treat socket-mounting containers as root-level. Never expose the API on TCP 2375 without TLS. Errors: "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock" (user not in docker group, or group change not yet effective: log out and in) and "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" (dockerd down: `systemctl status docker`).',
    example: raw`$ ls -l /run/docker.sock
srw-rw---- 1 root docker 0 Oct 21 08:01 /run/docker.sock`,
    relatedCommands: ['docker', 'systemctl'],
  },
  {
    id: 'file:container-logs',
    path: '/var/lib/docker/containers/<id>/<id>-json.log',
    platform: 'Docker Engine 27 (Linux host, json-file log driver)',
    kind: 'log',
    services: ['Docker'],
    purpose: 'Where the default json-file driver stores each container\'s stdout/stderr; `docker logs` reads it.',
    contents: 'One JSON object per line: `{"log":"...\\n","stream":"stdout|stderr","time":"RFC3339Nano"}`.',
    accessed: 'Appended by dockerd while the container runs; kept across restarts; **deleted with the container** (`docker rm`, `docker compose down`, or recreate after a config change).',
    permissions: 'root only.',
    problems: 'With json-file and no `max-size`, the file grows without limit and can fill /var: set `log-opts` in daemon.json (affects new containers) or `logging:` per service. Recreating a container to apply a change throws away the logs that explain the previous failure: save them first (`docker logs web-db-1 > db-before.log 2>&1`). The `local` driver is a compact, rotated alternative.',
    example: raw`{"log":"2026/10/21 09:12:04 [emerg] 1#1: host not found in upstream \"api:3000\" in /etc/nginx/conf.d/default.conf:12\n","stream":"stderr","time":"2026-10-21T09:12:04.102931811Z"}`,
    relatedCommands: ['docker-logs', 'docker-inspect'],
  },
  // --- pfSense -------------------------------------------------------------------------
  {
    id: 'file:config.xml',
    path: '/cf/conf/config.xml (also reachable as /conf/config.xml)',
    platform: 'pfSense CE 2.7.x (FreeBSD 14)',
    kind: 'config',
    services: ['pfSense', 'Firewall', 'NAT', 'DHCP', 'DNS'],
    purpose: 'The entire pfSense configuration in one XML file: interfaces, VLANs, rules, NAT, aliases, DHCP, DNS Resolver, VPNs, users, certificates and package settings. Every other configuration file on the box is generated from it.',
    contents: 'Sections such as `<interfaces>`, `<filter>` (rules, each with a tracker), `<nat>`, `<dhcpd>`, `<unbound>`, `<system>` (users with password hashes), `<cert>` (certificates and private keys), `<revision>` (who changed what, when).',
    accessed: 'Written by the GUI/console on every save (and a copy is saved to /cf/conf/backup/). The PHP code reads a cached parsed copy (/tmp/config.cache) rather than parsing the XML each time. Services and the filter are regenerated from it on apply, boot or reload.',
    permissions: 'root-owned; only root/admin (shell or GUI) should change it.',
    problems: 'Hand edits are risky: a malformed file can prevent services from configuring at boot, the GUI keeps using the cached copy until /tmp/config.cache is removed, and nothing is applied until the relevant subsystem reloads. If you must edit, use `viconfig` from the shell (it handles the cache), keep a copy, and reload/reboot. Prefer the GUI, console menu, or `easyrule`/`pfSsh.php`. The file contains secrets (hashes, VPN and certificate keys): encrypt downloaded backups.',
    example: raw`<rule>
	<id></id>
	<tracker>1770000101</tracker>
	<type>pass</type>
	<interface>lan</interface>
	<ipprotocol>inet</ipprotocol>
	<source><network>lan</network></source>
	<destination><any></any></destination>
	<descr><![CDATA[Default allow LAN to any rule]]></descr>
</rule>`,
    relatedCommands: ['pfsense-console', 'pfctl'],
  },
  {
    id: 'file:pfsense-filter-log',
    path: '/var/log/filter.log (GUI: Status > System Logs > Firewall)',
    platform: 'pfSense CE 2.7.x (FreeBSD 14)',
    kind: 'log',
    services: ['pfSense', 'Firewall'],
    purpose: 'Firewall log: packets matched by rules that have logging enabled, including the default deny rule. Proves whether pfSense blocked a connection and which rule did it.',
    contents: 'Syslog lines from `filterlog` whose message is CSV: rule number, sub-rule, anchor, tracker (the rule\'s ID, matching `ridentifier` in pfctl -sr), real interface, reason, action (pass/block), direction, IP version; then for IPv4: TOS, ECN, TTL, ID, offset, flags, protocol ID, protocol, length, source, destination; then for TCP: source port, destination port, data length, TCP flags, sequence, ack, window, urgent, options.',
    accessed: 'Written by filterlog as pf logs packets; rotated by newsyslog (size set in Status > System Logs > Settings). Read live from console option 10 or `tail -f /var/log/filter.log`. The GUI view parses the CSV and links the action icon to the rule.',
    permissions: 'root (readable via GUI by users with the log page privilege).',
    problems: 'Pass rules do not log by default, so the absence of a pass entry proves nothing; the default deny rule logs by default. A block from a rule without logging enabled is invisible. Heavy logging on a WAN interface rotates the file quickly. Traffic dropped upstream (ISP, cloud security group) never appears.',
    example: raw`Oct 21 09:50:12 fw01 filterlog[61234]: 5,,,1000000103,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.7,203.0.113.2,51544,22,0,S,1874625310,,64240,,mss;sackOK;TS;nop;wscale`,
    relatedCommands: ['pfctl', 'pfsense-console'],
  },
  {
    id: 'file:pfsense-conf-backup',
    path: '/cf/conf/backup/config-<unix-time>.xml (GUI: Diagnostics > Backup & Restore > Config History)',
    platform: 'pfSense CE 2.7.x (FreeBSD 14)',
    kind: 'config-dir',
    services: ['pfSense'],
    purpose: 'Automatic local history of previous configurations: pfSense keeps a copy every time the configuration is saved, so a bad change can be reverted.',
    contents: 'Full config.xml copies named by Unix timestamp, plus a cache of their descriptions (who/what change). The number kept is set under Config History (default 30 on most installs).',
    accessed: 'Written on every configuration save; read by Config History (view, diff, revert) and console option 15 "Restore recent configuration".',
    permissions: 'root-owned.',
    problems: 'Local only: lost with the disk, so also keep off-box backups (Diagnostics > Backup & Restore > Download, or Netgate AutoConfigBackup). With the default count, a burst of changes can rotate out the last known-good config. Restoring a configuration from different hardware brings interface names that do not exist (interface mismatch at boot: reassign with console option 1).',
    example: raw`[2.7.2-RELEASE][admin@fw01.corp.lab]/root: ls -lt /cf/conf/backup | head -3
total 312
-rw-r--r--  1 root  wheel  31544 Oct 21 09:55 config-1792569332.xml
-rw-r--r--  1 root  wheel  31402 Oct 21 09:38 config-1792568310.xml`,
    relatedCommands: ['pfsense-console'],
  },
  {
    id: 'file:pfsense-rules-debug',
    path: '/tmp/rules.debug',
    platform: 'pfSense CE 2.7.x (FreeBSD 14)',
    kind: 'runtime',
    services: ['pfSense', 'Firewall', 'NAT'],
    purpose: 'The pf ruleset (pf.conf syntax) generated from config.xml on each filter reload and loaded with pfctl. A read-only diagnostic: it shows exactly what the GUI rules turned into.',
    contents: 'Macros and interface definitions, tables (aliases, bogons, sshguard/virusprot), options, scrub, NAT/port forwards (`nat`, `rdr`), then filter rules with labels such as "USER_RULE: ..." and "anti-lockout rule" and their ridentifier.',
    accessed: 'Rewritten by every filter reload (rule save, interface change, gateway event, Status > Filter Reload, `/etc/rc.filter_configure`), then loaded with `pfctl -f /tmp/rules.debug`. /tmp does not survive a reboot.',
    permissions: 'root.',
    problems: 'Editing it is pointless: the next reload overwrites it. When loading fails, the previous ruleset stays active and the GUI shows "There were error(s) loading the rules: /tmp/rules.debug:<line>: ..." with the offending line: e.g. a table too large for "Firewall Maximum Table Entries", or an alias URL that returned garbage. Check with `pfctl -nf /tmp/rules.debug`.',
    example: raw`[2.7.2-RELEASE][admin@fw01.corp.lab]/root: grep -n 'USER_RULE' /tmp/rules.debug
212:pass  in  quick  on $LAN inet from $LAN__NETWORK to any ridentifier 1770000101 keep state label "USER_RULE: Default allow LAN to any rule"`,
    relatedCommands: ['pfctl'],
  },
  {
    id: 'file:unbound-conf',
    path: '/var/unbound/unbound.conf',
    platform: 'pfSense CE 2.7.x (FreeBSD 14)',
    kind: 'config',
    services: ['pfSense', 'DNS'],
    purpose: 'Configuration of Unbound, the pfSense DNS Resolver, generated from Services > DNS Resolver. It defines which interfaces Unbound listens on, who may query, forwarding, DNSSEC and local records.',
    contents: 'server: section (interface, access-control include, DNSSEC, cache sizes), plus includes generated alongside it: `host_entries.conf` (Host Overrides and, if enabled, DHCP registrations), `access_lists.conf`, `domainoverrides.conf`, and the "Custom options" text from the GUI pasted verbatim.',
    accessed: 'Regenerated and Unbound restarted whenever DNS Resolver settings are saved and at boot. Unbound runs chrooted in /var/unbound.',
    permissions: 'root-owned; read by the unbound user.',
    problems: 'Manual edits are lost at the next save or reboot: put extra directives in the Custom options box. A syntax error there stops Unbound from starting, so every client using the firewall for DNS fails ("Name resolution fails" while ping by IP works); check with `unbound-checkconf /var/unbound/unbound.conf`. Enabling the DNS Forwarder (dnsmasq) on port 53 at the same time conflicts. DNSSEC validation fails when the firewall clock is wrong.',
    example: raw`[2.7.2-RELEASE][admin@fw01.corp.lab]/root: unbound-checkconf /var/unbound/unbound.conf
unbound-checkconf: no errors in /var/unbound/unbound.conf`,
    relatedCommands: ['pfsense-console', 'dig'],
  },
];
