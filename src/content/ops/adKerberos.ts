// Active Directory, DNS and Kerberos. The sandbox, the domain tickets and Lab 2
// use the simulated domain ad.corp.lab (dc01, member win01).
// Example output is representative of Windows Server 2022 domain controllers
// (dc01 10.0.20.5, dc02 10.0.20.6, domain corp.lab, NetBIOS CORP), Windows 11
// 23H2 clients, Ubuntu 24.04 and RHEL 9 members (sssd 2.9, MIT Kerberos 1.20/1.21).

import type { Assessment, Lesson, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const AD_KERBEROS_GUIDE: ServiceGuide = {
  purpose:
    'Active Directory Domain Services (AD DS) is the directory that stores users, groups, computers and policies for a Windows domain, and the domain controllers (DCs) that host it also provide the **services everything else depends on**: DNS (how clients find a DC), Kerberos (how users and computers prove who they are), LDAP (how applications query the directory), SYSVOL (where Group Policy files live) and the domain time hierarchy. A domain logon is therefore a chain: DNS → DC locator → time within 5 minutes → Kerberos → secure channel → Group Policy. Most "AD is broken" tickets are really one broken link in that chain, and each link has its own tool and its own error.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Central identity (one account for every domain-joined machine and Kerberos-aware application), central authorisation (security groups in access tokens), central configuration (Group Policy) and single sign-on: after one logon, Kerberos tickets let the user reach file shares, intranet sites, SQL Server and RDP without typing the password again.' },
    { q: 'How does it work internally?', a: 'Each DC runs the **NTDS** service (inside `lsass.exe`), which holds a full writable copy of the domain partition in the ESE database `C:\\Windows\\NTDS\\ntds.dit`. Changes are made on any DC and **multi-master replicated** to the others: every change gets an Update Sequence Number (USN), and DCs pull changes they have not seen yet from their replication partners. The **KCC** (Knowledge Consistency Checker) automatically builds the replication topology (connection objects). The KDC (Kerberos Key Distribution Center, service `Kdc`) reads account keys from the directory to issue tickets. Netlogon registers the DC\'s DNS records, answers DC-locator pings and maintains secure channels with member computers. Five FSMO roles (PDC emulator, RID master, infrastructure master, schema master, domain naming master) are single-master exceptions; the PDC emulator is also the root of the domain time hierarchy and the preferred target for password changes.' },
    { q: 'Which protocols does it use?', a: 'DNS (SRV records for locating DCs), Kerberos v5 (RFC 4120) for authentication with NTLM as a fallback, LDAP v3 (and LDAPS) for directory access, CLDAP (LDAP over UDP 389) for DC-locator pings, MS-RPC for replication (DRSUAPI), Netlogon and administration, SMB for SYSVOL and NETLOGON shares, DFSR (over RPC) to replicate SYSVOL, and NTP (MS-SNTP) for time.' },
    { q: 'Which ports and transport?', a: 'DNS 53 TCP/UDP, Kerberos 88 TCP/UDP, kpasswd 464 TCP/UDP, RPC endpoint mapper 135 TCP plus the dynamic range 49152–65535 TCP, LDAP 389 TCP/UDP, LDAPS 636 TCP, Global Catalog 3268 TCP (3269 TLS), SMB 445 TCP, NTP 123 UDP, AD Web Services 9389 TCP (used by the PowerShell AD module). A firewall between clients and DCs that allows only "the obvious" ports (53, 88, 389) breaks Group Policy (445) and secure-channel setup (RPC).' },
    { q: 'Which processes and OS components implement it?', a: 'On a DC: `lsass.exe` hosts NTDS, Kdc and Netlogon; `dns.exe` (service `DNS`); `dfsrs.exe` (service `DFSR`) replicates SYSVOL; `svchost` hosts `W32Time`, `LanmanServer` (shares SYSVOL/NETLOGON) and `IsmServ` (Intersite Messaging). On a member: `lsass.exe` (Kerberos client, Netlogon secure channel), `gpsvc` (Group Policy Client), `LanmanWorkstation` (SMB client to read SYSVOL), `Dnscache` (DNS client), `W32Time`. On Linux members: `sssd`, `realmd`, `adcli`, MIT Kerberos libraries and `chronyd`.' },
    { q: 'Which other services does it depend on?', a: 'Everything starts with **DNS**: clients find DCs only through SRV records under `_msdcs.<domain>`, so clients must use the AD DNS servers and nothing else. Kerberos depends on **time** (default maximum skew 5 minutes) and on correct **SPNs**. Group Policy depends on DNS, Kerberos, SMB to SYSVOL and healthy **DFSR** replication. DCs depend on each other through replication; a DC whose DNS client points only to itself can wait at boot for a directory that is waiting for DNS (DNS Server event 4013).' },
    { q: 'How do requests travel?', a: 'Logon on WS07: the DC locator asks DNS for `_ldap._tcp.<site>._sites.dc._msdcs.corp.lab` (then `_ldap._tcp.dc._msdcs.corp.lab`) → sends a CLDAP ping (UDP 389) to the DCs returned and picks the first one that answers, preferring its own site → Kerberos AS exchange on port 88 for a TGT → TGS exchange for `host/ws07.corp.lab` and later `cifs/dc01.corp.lab` (SYSVOL) or `ldap/dc01.corp.lab` → Group Policy reads `gpt.ini` and policy files from `\\\\corp.lab\\SYSVOL` over SMB. The Visualize tab sequence shows these steps and where each fails.' },
    { q: 'How do authentication and authorisation work?', a: '**Authentication**: Kerberos. The client sends an AS-REQ with a timestamp encrypted with a key derived from the user\'s password (pre-authentication); the KDC checks it and returns a **TGT** (ticket for `krbtgt/CORP.LAB`). For each service the client presents the TGT in a TGS-REQ naming the service\'s **SPN** (e.g. `cifs/fs01.corp.lab`); the KDC finds the account that owns the SPN and returns a **service ticket** encrypted with that account\'s key. The service decrypts it with its own key: no DC contact needed. If Kerberos cannot be used (connection by IP address, missing SPN, no DC reachable for Kerberos), Windows falls back to **NTLM**, which the DC validates through the server\'s Netlogon secure channel. **Authorisation**: the ticket carries a **PAC** (Privilege Attribute Certificate) with the user\'s SID and group SIDs; the server builds an access token from it and checks ACLs, "Allow log on through Remote Desktop Services" and similar user rights.' },
    { q: 'How does it start at boot?', a: 'On a DC, NTDS starts automatically, followed by Kdc, Netlogon, DNS, DFSR and IsmServ. Netlogon registers the DC\'s SRV/A/CNAME records (the list is in `%SystemRoot%\\System32\\config\\netlogon.dns`) and re-registers them every 24 hours. The DC advertises itself (`dcdiag /test:advertising`) only after its first inbound replication since boot, and DFSR must finish SYSVOL initialisation before the SYSVOL share is published. On a member, Netlogon establishes the secure channel to a DC, `gpsvc` applies computer policy before the logon screen, and user policy at logon.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'NTDS runs inside lsass.exe: if lsass crashes, Windows **reboots the DC** (critical process). Stopping NTDS (possible since Server 2008, "restartable AD DS") also stops its dependents (Kdc, DFSR, IsmServ and DNS Server on a DC with AD-integrated zones): that DC stops issuing tickets and serving AD-integrated zones until it is started again. Clients fail over to another DC through the DC locator, **provided** another DC is up and registered in DNS. With a single DC, everything stops: logons only work with cached credentials, Group Policy fails, Kerberos service tickets cannot be renewed.' },
  ],
  ports: [
    { port: '53', proto: 'TCP/UDP', purpose: 'DNS (AD-integrated zones, SRV records for the DC locator)' },
    { port: '88', proto: 'TCP/UDP', purpose: 'Kerberos KDC (AS and TGS exchanges)' },
    { port: '464', proto: 'TCP/UDP', purpose: 'Kerberos password change (kpasswd)' },
    { port: '389', proto: 'TCP/UDP', purpose: 'LDAP (TCP) and CLDAP DC-locator ping (UDP)' },
    { port: '636', proto: 'TCP', purpose: 'LDAPS (LDAP over TLS; needs a DC certificate)' },
    { port: '3268 / 3269', proto: 'TCP', purpose: 'Global Catalog (forest-wide searches, UPN logon) / over TLS' },
    { port: '135 + 49152–65535', proto: 'TCP', purpose: 'RPC endpoint mapper and dynamic RPC (replication, Netlogon, DFSR, management)' },
    { port: '445', proto: 'TCP', purpose: 'SMB: SYSVOL and NETLOGON shares (Group Policy, logon scripts)' },
    { port: '123', proto: 'UDP', purpose: 'NTP / MS-SNTP time synchronisation' },
    { port: '9389', proto: 'TCP', purpose: 'AD Web Services (PowerShell ActiveDirectory module, ADAC)' },
  ],
  processes: [
    { name: 'lsass.exe → NTDS', platform: 'Windows Server (DC)', role: 'Active Directory Domain Services: the directory database (ntds.dit), LDAP/GC server, replication engine' },
    { name: 'lsass.exe → Kdc', platform: 'Windows Server (DC)', role: 'Kerberos Key Distribution Center: issues TGTs and service tickets on port 88' },
    { name: 'lsass.exe → Netlogon', platform: 'Windows Server, Windows 10/11', role: 'DC: registers DC DNS records, answers locator pings, NTLM pass-through. Member: DC locator and machine secure channel' },
    { name: 'dns.exe (DNS)', platform: 'Windows Server (DC)', role: 'DNS Server hosting AD-integrated zones corp.lab and _msdcs.corp.lab, stored in the directory' },
    { name: 'dfsrs.exe (DFSR)', platform: 'Windows Server (DC)', role: 'Replicates the SYSVOL folder (GPO files, logon scripts) between DCs' },
    { name: 'svchost → W32Time', platform: 'All Windows', role: 'Windows Time: domain hierarchy (members ← DCs ← PDC emulator ← external NTP)' },
    { name: 'svchost → gpsvc', platform: 'Windows 10/11, Server', role: 'Group Policy Client: downloads and applies GPOs at boot, logon and every 90 ± 30 minutes' },
    { name: 'LanmanServer / LanmanWorkstation', platform: 'All Windows', role: 'SMB server (shares SYSVOL/NETLOGON on DCs) and SMB client (reads them on members)' },
    { name: 'sssd, realmd, adcli', platform: 'Ubuntu/Debian, RHEL', role: 'Linux AD membership: realmd/adcli join, sssd resolves users and authenticates with Kerberos' },
  ],
  dependencies: {
    title: 'What a domain logon depends on (top needs everything below it)',
    caption: 'Troubleshoot bottom-up: can the client reach a DC, does DNS return the SRV records, is time within 5 minutes, does Kerberos work, is the secure channel intact, and only then Group Policy.',
    rows: [
      { label: 'Logon', nodes: [{ id: 'logon', label: 'Domain logon', sub: 'Winlogon / LSASS', kind: 'client' }, { id: 'gpo', label: 'Group Policy', sub: 'gpsvc reads SYSVOL', kind: 'client' }] },
      { label: 'Auth', nodes: [{ id: 'kdc', label: 'Kerberos KDC', sub: 'Kdc, TCP/UDP 88', kind: 'service' }, { id: 'sc', label: 'Secure channel', sub: 'Netlogon, machine pw', kind: 'service' }, { id: 'time', label: 'Time sync', sub: 'W32Time, max 5 min', kind: 'service' }, { id: 'smb', label: 'SYSVOL share', sub: 'SMB 445', kind: 'service' }] },
      { label: 'Directory', nodes: [{ id: 'ntds', label: 'AD DS (NTDS)', sub: 'ntds.dit, LDAP 389', kind: 'data' }, { id: 'repl', label: 'AD replication', sub: 'RPC, KCC, USNs', kind: 'data' }, { id: 'dfsr', label: 'DFSR', sub: 'SYSVOL replication', kind: 'data' }] },
      { label: 'Locate', nodes: [{ id: 'srv', label: 'SRV records', sub: '_msdcs, by Netlogon', kind: 'network' }, { id: 'cdns', label: 'Client DNS config', sub: 'DC IPs only', kind: 'client' }, { id: 'adns', label: 'AD DNS server', sub: 'AD-integrated zones', kind: 'service' }] },
      { label: 'Network', nodes: [{ id: 'net', label: 'IP path to DC', sub: '53 88 135 389 445', kind: 'network' }] },
    ],
    edges: [
      ['logon', 'kdc'], ['logon', 'sc'], ['gpo', 'smb'], ['gpo', 'kdc'], ['kdc', 'time'], ['kdc', 'ntds'], ['sc', 'ntds'],
      ['smb', 'dfsr'], ['ntds', 'repl'], ['kdc', 'srv'], ['srv', 'cdns'], ['srv', 'adns'], ['adns', 'ntds'], ['cdns', 'net'], ['adns', 'net'], ['dfsr', 'net'], ['repl', 'net'],
    ],
  },
  sequence: {
    title: 'Dana logs on at WS07 and opens \\\\fs01\\data',
    caption: 'Windows 11 client, Windows Server 2022 DC. The pre-authentication round trip (KDC_ERR_PREAUTH_REQUIRED) is normal and appears in every capture.',
    lanes: [{ id: 'c', label: 'WS07', sub: 'Windows 11' }, { id: 'd', label: 'dc01 DNS', sub: 'dns.exe' }, { id: 'k', label: 'dc01 KDC', sub: 'Kdc + Netlogon' }, { id: 'f', label: 'fs01', sub: 'file server' }],
    steps: [
      { from: 'c', to: 'd', label: 'SRV? _ldap._tcp.dc._msdcs', note: 'Wrong DNS server (router, 8.8.8.8) → NXDOMAIN → "domain isn\'t available" / ERROR_NO_SUCH_DOMAIN (1355).' },
      { from: 'd', to: 'c', label: 'dc01, dc02 port 389 + A', note: 'Missing answer while DNS is right → Netlogon on the DC did not register (nltest /dsregdns).' },
      { from: 'c', to: 'k', label: 'CLDAP ping UDP 389', note: 'No reply → DC down or UDP 389 blocked; the locator tries the next DC.' },
      { from: 'c', to: 'k', label: 'AS-REQ dana (pre-auth ts)', note: 'Clock more than 5 min off → KRB_AP_ERR_SKEW; bad password → 4771 0x18.' },
      { from: 'k', to: 'c', label: 'AS-REP: TGT krbtgt/CORP.LAB', note: 'Logged on the DC as Security 4768.' },
      { from: 'c', to: 'k', label: 'TGS-REQ cifs/fs01.corp.lab', note: 'SPN not registered → KDC_ERR_S_PRINCIPAL_UNKNOWN; client falls back to NTLM.' },
      { from: 'k', to: 'c', label: 'TGS-REP: service ticket', note: 'Logged as Security 4769. Ticket encrypted with fs01\'s key; PAC carries group SIDs.' },
      { from: 'c', to: 'f', label: 'SMB session setup: AP-REQ', note: 'SPN on the wrong account (duplicate) → fs01 cannot decrypt → KRB_AP_ERR_MODIFIED.' },
      { from: 'f', to: 'c', label: 'AP-REP, access token built', note: 'Access then depends on share/NTFS ACLs and the groups in the PAC.' },
    ],
  },
  files: [
    { path: 'C:\\Windows\\NTDS\\ntds.dit (+ edb*.log, edb.chk)', platform: 'Windows Server (DC)', kind: 'data', perms: 'SYSTEM only; locked by lsass while NTDS runs', contains: 'The AD database (ESE): all objects, attributes, password hashes, and the transaction logs that make changes durable.', accessed: 'Continuously by NTDS. Backed up only through a **System State** backup (`wbadmin start systemstatebackup`).', problems: 'A full disk stops NTDS (event 1480/2095 class errors, "insufficient disk space"). Never copy or restore ntds.dit from a VM snapshot without the hypervisor\'s VM-GenerationID support: rolling a DC back causes **USN rollback** (event 2095) and the DC silently stops replicating.' },
    { path: 'C:\\Windows\\SYSVOL\\domain (shared as SYSVOL and NETLOGON)', platform: 'Windows Server (DC)', kind: 'config-dir', perms: 'Authenticated Users read; Administrators/SYSTEM full', contains: '`Policies\\{GPO-GUID}\\` folders (gpt.ini, Machine\\Registry.pol, User\\…, GptTmpl.inf) and `scripts\\` (logon scripts), replicated by DFSR.', accessed: 'By every member at boot, logon and every background policy refresh (`\\\\corp.lab\\SYSVOL\\corp.lab\\Policies\\…`).', problems: 'If DFSR replication is broken, DCs hold different versions of a GPO: clients get event 1058 ("Windows attempted to read the file …gpt.ini … and was not successful") or apply old settings depending on which DC they ask.' },
    { path: '%SystemRoot%\\System32\\config\\netlogon.dns', platform: 'Windows Server (DC)', kind: 'data', contains: 'The exact DNS records (SRV, A, CNAME `<DSA-GUID>._msdcs`) the DC\'s Netlogon tries to register.', accessed: 'Written when Netlogon starts or registers (`nltest /dsregdns`, every 24 h).', problems: 'Use it to compare "what should be in DNS" with what is there. If registration fails, System event 5774/5781 and `dcdiag /test:dns` explain why (zone not dynamic, DC DNS client points to a non-AD resolver).' },
    { path: '%windir%\\debug\\netlogon.log', platform: 'Windows Server, Windows 10/11', kind: 'log', contains: 'Netlogon debug log: DC discovery, secure channel setup, NTLM pass-through failures (e.g. `0xC000006A` bad password, `0xC0000064` no such user).', accessed: 'Only after enabling verbose logging: `nltest /dbflag:0x2080ffff` (disable with `nltest /dbflag:0x0`).', problems: 'Grows quickly and is rolled to netlogon.bak at 20 MB by default; switch it off after troubleshooting.' },
    { path: 'Event logs: Directory Service, DNS Server, DFS Replication', platform: 'Windows Server (DC)', kind: 'eventlog', contains: 'Directory Service: replication and KCC (1311 KCC cannot build a topology, 1864 partition not replicated within latency, 2042 "too long since this machine last replicated" beyond tombstone lifetime, 2087/2088 source DC DNS lookup failures, 2095 USN rollback). DNS Server: 4013 waiting for AD initial sync, 4000/4007 zone load errors. DFS Replication: 4602/4604 SYSVOL initialised, 2213 dirty shutdown (replication paused), 4012 offline longer than MaxOfflineTimeInDays (60).', accessed: 'Event Viewer → Applications and Services Logs, or `Get-WinEvent -LogName "Directory Service" -MaxEvents 50`.', problems: 'These logs exist only on DCs. Read them on **every** DC: a replication failure is often only visible on the receiving side.' },
    { path: 'Event logs: System and Security', platform: 'All Windows', kind: 'eventlog', contains: 'System: Netlogon 5719 (cannot set up a secure session with a DC), 5722/5723 (computer account authentication failed, on the DC), 5774/5781 (DNS registration failed); Security-Kerberos 4 (KRB_AP_ERR_MODIFIED); KDC 11 (duplicate SPN); W32Time 36/129/134; GroupPolicy 1030/1058. Security (on DCs): 4768 TGT requested, 4769 service ticket requested, 4771 pre-authentication failed (0x18 bad password, 0x25 clock skew), 4776 NTLM credential validation.', accessed: 'Continuously. Security auditing must be enabled (Default Domain Controllers Policy audits account logon success/failure).', problems: 'The client usually shows a generic message; the DC\'s Security log shows the failure code. The Security log rolls over fast on busy DCs: collect it soon after the incident.' },
    { path: 'Microsoft-Windows-GroupPolicy/Operational', platform: 'Windows 10/11, Server', kind: 'eventlog', contains: 'Step-by-step Group Policy processing: 4000/4001 start, 5308 DC selected, 5312/5313 GPOs applied/filtered, 7016 extension completed with an error, 8000/8001 end with timing.', accessed: 'At every policy refresh.', problems: 'The System log only shows the summary (1058, 1030); the Operational log shows which step and which extension failed.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters (and \\Config)', platform: 'All Windows', kind: 'registry', contains: '`Type` (NT5DS = domain hierarchy, NTP = manual peers), `NtpServer` (peer list with flags such as 0x8), `MaxPosPhaseCorrection`/`MaxNegPhaseCorrection`.', accessed: 'When W32Time starts or `w32tm /config /update` runs.', problems: 'A member with `Type NTP` pointing to an internet server ignores the domain hierarchy; a PDC emulator with `Type NT5DS` has no upstream and free-runs (`Source: Local CMOS Clock`). Change it with `w32tm /config`, not by hand.' },
    { path: '/etc/sssd/sssd.conf', platform: 'Ubuntu/Debian, RHEL', kind: 'config', perms: 'root:root 0600 (sssd refuses to start otherwise)', contains: '`[sssd] domains = corp.lab`, `[domain/corp.lab] id_provider = ad`, `access_provider = ad`, `krb5_realm = CORP.LAB`, `use_fully_qualified_names`, `fallback_homedir`, `cache_credentials`.', accessed: 'When sssd starts.', problems: 'Wrong mode → "File ownership and permissions check failed" and sssd will not start. Edits need `systemctl restart sssd`; stale cache entries can be cleared with `sss_cache -E`.' },
    { path: '/etc/krb5.conf and /etc/krb5.keytab', platform: 'Ubuntu/Debian, RHEL', kind: 'config', perms: 'krb5.conf 0644; krb5.keytab root 0600', contains: 'krb5.conf: `default_realm = CORP.LAB`, `dns_lookup_kdc = true`, `rdns = false`. krb5.keytab: the machine account keys written by `realm join`/adcli.', accessed: 'By kinit, sssd and any Kerberised service.', problems: 'Realm names are **upper case**: `kinit dana@corp.lab` fails with "Cannot find KDC for realm". A keytab whose kvno no longer matches AD (account reset elsewhere) breaks the machine\'s authentication.' },
  ],
  management: [
    {
      platform: 'Windows Server 2019/2022 (domain controller)',
      tasks: [
        { task: 'Status of the DC services', command: 'Get-Service NTDS, Kdc, Netlogon, DNS, DFSR, W32Time, IsmServ, LanmanServer', explain: 'All should be **Running** with StartType Automatic on a DC. A stopped Netlogon means no DNS registration and no locator answers; a stopped Kdc means no tickets from this DC.' },
        { task: 'Dependencies before stopping anything', command: 'Get-Service NTDS -DependentServices\nsc.exe enumdepend NTDS', explain: 'Lists what will stop with NTDS (typically Kdc, DFSR, IsmServ and DNS Server). Know the blast radius before you act.' },
        { task: 'Overall DC health', command: 'dcdiag /q\ndcdiag /v /c /e > C:\\Temp\\dcdiag.txt', explain: '`/q` prints only errors (no output = all tests passed). `/e` tests every DC in the enterprise, `/c` runs comprehensive tests, `/v` verbose.' },
        { task: 'DNS health of the DCs', command: 'dcdiag /test:dns /v', explain: 'Checks the DC\'s DNS client settings, zone delegation, dynamic update, and whether all records from netlogon.dns are registered.' },
        { task: 'Replication health', command: 'repadmin /replsummary\nrepadmin /showrepl\nrepadmin /queue', explain: '`/replsummary` gives fails/total per DC; `/showrepl` the last attempt and error for each partner and partition; `/queue` pending inbound requests.' },
        { task: 'Force replication (after a fix)', command: 'repadmin /syncall /AdeP', explain: 'Asks all partners to push all partitions across sites. Use to verify a fix, not as a routine "fix".', risk: 'Generates replication traffic on WAN links; replicates whatever is current, including mistakes.' },
        { task: 'Re-register DC DNS records', command: 'nltest /dsregdns\nipconfig /registerdns', explain: '`nltest /dsregdns` makes Netlogon register every record in netlogon.dns now; `ipconfig /registerdns` re-registers the host A record. Safer than restarting Netlogon.' },
        { task: 'Restart Netlogon (if registration is stuck)', command: 'Restart-Service Netlogon', explain: 'Netlogon re-reads its configuration and re-registers its DNS records at start.', risk: 'For a few seconds this DC does not answer locator pings or NTLM pass-through; clients pick another DC. Do it on one DC at a time.' },
        { task: 'Time source and status', command: 'w32tm /query /status\nw32tm /query /source\nw32tm /query /configuration\nw32tm /monitor', explain: 'Members should show a DC as source; DCs show the PDC emulator; the PDC emulator shows external NTP peers. `/monitor` compares offsets of all DCs.' },
        { task: 'FSMO role holders', command: 'netdom query fsmo', explain: 'Shows which DC holds the PDC emulator (time root, password changes) and the other roles.' },
        { task: 'Logs', command: 'Get-WinEvent -LogName "Directory Service" -MaxEvents 30\nGet-WinEvent -LogName "DFS Replication" -MaxEvents 30\nGet-WinEvent -LogName "DNS Server" -MaxEvents 30\nGet-WinEvent -FilterHashtable @{LogName="Security"; Id=4771,4769} -MaxEvents 20', explain: 'Each component logs to its own log; the Security log shows Kerberos failures with result codes.' },
        { task: 'Restart AD DS (maintenance only)', command: 'Stop-Service NTDS -Force\nStart-Service NTDS', explain: 'Restartable AD DS lets you do offline defragmentation or apply some updates without rebooting into DSRM. Start dependents again if they do not come back (`Get-Service Kdc, DNS, DFSR`).', risk: 'This DC stops issuing tickets and (with AD-integrated zones) answering DNS until restarted. Only with a second healthy DC, in a window, and never on all DCs at once.' },
      ],
    },
    {
      platform: 'Windows 10/11 and member servers',
      tasks: [
        { task: 'Which DC am I using?', command: 'nltest /dsgetdc:corp.lab\necho %LOGONSERVER%', explain: 'Runs the DC locator (DNS + CLDAP ping) and prints the chosen DC with its flags (KDC, TIMESERV, GC ...). `/force` ignores the cache.' },
        { task: 'Secure channel', command: 'nltest /sc_verify:corp.lab\nTest-ComputerSecureChannel -Verbose', explain: 'Checks that the machine account password shared with the domain is valid. Test-ComputerSecureChannel is in Windows PowerShell 5.1 (not PowerShell 7).' },
        { task: 'Repair the secure channel', command: 'Test-ComputerSecureChannel -Repair -Credential CORP\\adm-alice', explain: 'Resets the machine account password on a DC and locally, without leaving and rejoining the domain (keeps the computer object, group memberships and SID). Needs a local admin logon (cached or local account) and network access to a DC.', risk: 'None for other machines. Rejoining (remove + add) is the heavier fallback and loses nothing only if you rejoin with the same name.' },
        { task: 'Kerberos tickets', command: 'klist\nklist purge\nklist -li 0x3e7 purge', explain: '`klist` shows the TGT and service tickets with their KDC; `purge` forces new tickets (with new group membership) at next access; `-li 0x3e7` targets the computer (SYSTEM) logon session.', risk: 'Purging is harmless: tickets are requested again on demand. It does not refresh group membership in the existing logon token: sign out/in for that.' },
        { task: 'Group Policy', command: 'gpupdate /force\ngpresult /r /scope computer\ngpresult /h C:\\Temp\\gp.html', explain: 'Applies policy now and shows which GPOs were applied or filtered out, from which DC, and when.', risk: '`gpupdate /force` may require a logoff/reboot for some settings (software installation, folder redirection) and will say so.' },
        { task: 'Group Policy service and logs', command: 'Get-Service gpsvc\nGet-WinEvent -LogName Microsoft-Windows-GroupPolicy/Operational -MaxEvents 30', explain: 'gpsvc cannot be stopped by administrators (by design). Use the Operational log to see which step failed.' },
        { task: 'DNS client', command: 'Get-DnsClientServerAddress -AddressFamily IPv4\nResolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab\nipconfig /flushdns', explain: 'Every listed server must be an AD DNS server. A public resolver as "secondary" is used whenever the first is slow and returns NXDOMAIN, which is then cached.' },
        { task: 'Time', command: 'w32tm /query /source\nw32tm /resync', explain: 'Source should be a DC. `/resync` asks for an immediate sync.' },
      ],
    },
    {
      platform: 'Ubuntu/Debian and RHEL members (realmd/SSSD)',
      tasks: [
        { task: 'Status / restart', command: 'systemctl status sssd\nsudo systemctl restart sssd', explain: 'sssd caches identities; a restart re-reads sssd.conf. On RHEL also check `oddjobd` (home directory creation).' },
        { task: 'Membership and identity', command: 'realm list\nid dana@corp.lab\ngetent passwd dana@corp.lab', explain: '`realm list` shows `configured: kerberos-member`. `id` must return the AD groups; nothing → sssd cannot reach AD or the user is filtered.' },
        { task: 'Kerberos', command: 'kinit dana@CORP.LAB\nklist\nsudo klist -k /etc/krb5.keytab', explain: 'The realm is upper case. `klist -k` lists the machine principals (`HOST/…`, `RESTRICTEDKRBHOST/…`, `UBU01$@CORP.LAB`) and their kvno.' },
        { task: 'Logs', command: 'journalctl -u sssd -b\nsudo ls /var/log/sssd/', explain: 'Per-domain logs `sssd_corp.lab.log`; raise `debug_level = 6` in the `[domain/corp.lab]` section temporarily.' },
        { task: 'Time', command: 'chronyc sources -v\ntimedatectl', explain: 'Point chrony at the DCs (`server dc01.corp.lab iburst`): Kerberos needs the same 5-minute window on Linux.' },
      ],
    },
    {
      platform: 'Docker / pfSense',
      tasks: [
        { task: 'Not applicable', command: '(none)', explain: 'AD DS runs only on Windows Server. Containers authenticate against AD through the host or a Kerberos keytab; pfSense can use AD as an LDAP or RADIUS authentication server (System > User Manager > Authentication Servers) and must point its DNS resolver at the DCs for `corp.lab` (Domain Overrides).' },
      ],
    },
  ],
  actions: [
    { action: 'klist purge / gpupdate /force / ipconfig /flushdns (client)', when: 'After fixing the cause on the server side (SPN corrected, group membership changed, DNS record fixed).', effect: 'Discards cached tickets, policy or DNS answers so the client asks again.', risk: 'Harmless, but they are not fixes: if the cause remains, the client gets the same bad answer again.' },
    { action: 'nltest /dsregdns, w32tm /resync, repadmin /syncall', when: 'Targeted actions on one DC component: re-register DNS records, resync time, push replication.', effect: 'Each does one thing on a running service, without interrupting authentication.', risk: 'Lowest-risk DC actions. Prefer them to restarts.' },
    { action: 'Restart-Service Netlogon / W32Time / DFSR on one DC', when: 'A specific component is stuck (registration not happening, time service misconfigured after `w32tm /config`, DFSR after a dirty shutdown once resumed).', effect: 'Restarts that one component; the other DC services continue. Clients use other DCs for the few seconds it takes.', risk: 'Low with two or more healthy DCs. Check replication (`repadmin /replsummary`) first, so you know the other DCs can take over.' },
    { action: 'Restart-Service NTDS -Force (restartable AD DS)', when: 'Maintenance (offline defrag, some updates), not troubleshooting by trial and error.', effect: 'Stops the directory and its dependents (Kdc, DFSR, IsmServ, DNS Server on AD-integrated zones) on that DC.', risk: 'That DC stops authenticating and serving DNS. On a single-DC domain everything stops. Never on more than one DC at a time.' },
    { action: 'Restart-NetAdapter on a DC', when: 'Only if the adapter itself is wedged. It does not fix AD problems.', effect: 'Drops all connections through the adapter; Netlogon may re-register.', risk: 'Disconnects RDP; if the IP or DNS configuration is wrong, the DC comes back unreachable. Use the hypervisor or iDRAC/iLO console.' },
    { action: 'Reboot a DC', when: 'Updates, or after confirming a restart of components did not help, one DC at a time.', effect: 'All DC roles on that server go away for minutes. At boot the DC waits for initial replication before advertising.', risk: 'Never reboot all DCs at once: the first one up may wait for a partner (DNS 4013) and nobody can log on. Reboot one, verify `dcdiag /q` and `repadmin /replsummary`, then the next.' },
    { action: 'Seize FSMO roles (Move-ADDirectoryServerOperationMasterRole -Force)', when: 'Only when the role holder is **permanently** gone (hardware lost, will never return).', effect: 'Another DC takes the role without the old holder\'s agreement.', risk: 'If the old DC ever comes back online with the role, you have two masters (RID or schema conflicts). Last resort; use transfer (without -Force) while both DCs are up.' },
  ],
  workflow: [
    { question: 'Is the client using AD DNS servers, and only those?', why: 'Domain members find domain controllers through special DNS records that only the AD DNS servers hold. A single non-AD DNS server in the list breaks DC location whenever it is asked.', command: 'Get-DnsClientServerAddress -AddressFamily IPv4\nipconfig /all', healthy: 'InterfaceAlias  Interface Address ServerAddresses\n                Index     Family\n--------------  --------- ------- ---------------\nEthernet 2             14 IPv4    {10.0.20.5, 10.0.20.6}', broken: 'A router (`10.0.10.1`), ISP or public resolver (`8.8.8.8`) in the list. Even as a secondary it breaks the locator intermittently: public DNS returns NXDOMAIN for `corp.lab`, and the client caches it.', next: 'Fix the DHCP scope (option 006) or the static NIC setting, `ipconfig /flushdns`, then step 2.' },
    { question: 'Does DNS return the DC SRV records?', why: 'Without the SRV records for the domain, clients cannot find any domain controller at all.', command: 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab\nnslookup -type=SRV _kerberos._tcp.corp.lab', healthy: 'Name                           Type TTL Section NameTarget    Priority Weight Port\n_ldap._tcp.dc._msdcs.corp.lab  SRV  600 Answer  dc01.corp.lab 0        100    389\n_ldap._tcp.dc._msdcs.corp.lab  SRV  600 Answer  dc02.corp.lab 0        100    389', broken: '"DNS name does not exist" through the correct server → the DC did not register its records (Netlogon stopped, zone does not allow secure dynamic updates, DC\'s own DNS client wrong). Only one DC listed → the other failed registration or was removed.', next: 'Missing records → on the DC: `dcdiag /test:dns`, `nltest /dsregdns`, check `netlogon.dns`. Present → step 3.' },
    { question: 'Can the client locate and reach a DC?', why: 'Finding a DC is not enough: the client must also reach its ports (LDAP 389, Kerberos 88, SMB 445).', command: 'nltest /dsgetdc:corp.lab /force\nTest-NetConnection dc01.corp.lab -Port 88\nTest-NetConnection dc01.corp.lab -Port 445', healthy: '           DC: \\\\dc01.corp.lab\n      Address: \\\\10.0.20.5\n        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST\nThe command completed successfully\nTcpTestSucceeded : True', broken: '`Getting DC name failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN` → DNS (steps 1–2) or no DC answering CLDAP. `TcpTestSucceeded : False` on 88/445 → firewall/routing between client and DC, or the DC is down.', next: 'DC found and reachable → step 4. DC down → check the other DCs and the services on it.' },
    { question: 'Is the clock within 5 minutes of the DC?', why: 'Kerberos refuses requests from clocks more than 5 minutes off the DC, so time is part of authentication.', command: 'w32tm /query /source\nw32tm /stripchart /computer:dc01.corp.lab /samples:3 /dataonly', healthy: 'dc01.corp.lab\nTracking dc01.corp.lab [10.0.20.5:123].\nCollecting 3 samples.\n09:14:02, +00.0021840s\n09:14:04, +00.0019912s', broken: 'Source `Local CMOS Clock` or `Free-running System Clock` and an offset of hundreds of seconds (`+412.3381021s`) → Kerberos fails with KRB_AP_ERR_SKEW; DC Security 4771 with failure code 0x25.', next: 'Fix the time hierarchy (proc:time-sync-fix): member → `w32tm /config /syncfromflags:domhier /update` + `w32tm /resync`; check the PDC emulator\'s source.' },
    { question: 'Does Kerberos issue tickets?', why: 'Logons, file access and Group Policy all depend on Kerberos tickets from the KDC on the DC.', command: 'klist purge\nklist get cifs/fs01.corp.lab\nklist', healthy: '#1>     Client: dana @ CORP.LAB\n        Server: cifs/fs01.corp.lab @ CORP.LAB\n        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96\n        Kdc Called: dc01.corp.lab', broken: '`0x7 KDC_ERR_S_PRINCIPAL_UNKNOWN` → no account owns that SPN (`setspn -Q`). Ticket obtained but access fails with KRB_AP_ERR_MODIFIED (System event 4 on the client) → duplicate SPN or the SPN is on the wrong account (`setspn -X`).', next: 'SPN problem → proc:spn-fix. Tickets fine → step 6.' },
    { question: 'Is the computer\'s secure channel intact?', why: 'The computer\'s own trust with the domain rests on its machine password. If the two copies differ, domain logons fail.', command: 'nltest /sc_verify:corp.lab\nTest-ComputerSecureChannel', healthy: 'Flags: b0 HAS_IP  HAS_TIMESERV\nTrusted DC Name \\\\dc01.corp.lab\nTrusted DC Connection Status Status = 0 0x0 NERR_Success\nTrust Verification Status = 0 0x0 NERR_Success\nThe command completed successfully\nTrue', broken: 'Non-zero status (e.g. `1787 0x6fb ERROR_NO_TRUST_SAM_ACCOUNT` when the computer object was deleted or reset) or `False`; at logon "The trust relationship between this workstation and the primary domain failed." System event 5719 on the client, 5722 on the DC.', next: 'Repair: `Test-ComputerSecureChannel -Repair -Credential CORP\\adm-alice` (proc:secure-channel-repair). Then step 7.' },
    { question: 'Does Group Policy apply?', why: 'Group Policy needs DC location, Kerberos and SYSVOL all working, so it is a good end-to-end test of the chain.', command: 'gpupdate /force\ngpresult /r /scope computer', healthy: 'Computer Policy update has completed successfully.\nUser Policy update has completed successfully.\n    Group Policy was applied from:      dc01.corp.lab\n    Applied Group Policy Objects\n        CORP - Workstation Baseline\n        Default Domain Policy', broken: '"Windows attempted to read the file \\\\corp.lab\\SysVol\\corp.lab\\Policies\\{GUID}\\gpt.ini from a domain controller and was not successful" (event 1058) → SMB/DFS to SYSVOL or SYSVOL replication. Event 1030 → policy could not be queried (LDAP/Kerberos). A GPO under "filtered out" → security filtering, WMI filter or link scope, not a failure.', next: 'Check the GroupPolicy Operational log and DFSR on the DCs (step 8).' },
    { question: 'Are the DCs replicating (AD and SYSVOL)?', why: 'With several DCs, each one must have the same data. A DC that stopped replicating hands out stale answers.', command: 'repadmin /replsummary\nrepadmin /showrepl dc02\ndcdiag /test:dfsrevent /test:sysvolcheck', healthy: 'Source DSA          largest delta    fails/total %%   error\n DC01                      04m:12s    0 /   5    0\n DC02                      03m:51s    0 /   5    0', broken: 'Non-zero fails with `(1722) The RPC server is unavailable` (partner down / RPC blocked), `(8524) The DSA operation is unable to proceed because of a DNS lookup failure`, `(1256) The remote system is not available`, or `(8614) … exceeded the tombstone lifetime`. DFSR 2213 or 4012 in the DFS Replication log.', next: 'Fix the named cause (DNS of the partner, firewall, the DC itself). 8614 or USN rollback: do not force; demote/rebuild the stale DC.' },
  ],
  failures: [
    { symptom: 'Logon: "We can\'t sign you in with this credential because your domain isn\'t available" / nltest: ERROR_NO_SUCH_DOMAIN', causes: ['Client DNS points to a router or public resolver (or one of them as secondary)', 'SRV records missing because Netlogon on the DCs could not register them', 'No DC reachable (DC down, firewall/routing between VLANs)'], diagnose: ['Get-DnsClientServerAddress', 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab -Server 10.0.20.5', 'nltest /dsgetdc:corp.lab /force', 'Test-NetConnection dc01 -Port 389'], fix: 'Give clients only the DC DNS servers (DHCP option 006 / NIC), flush the cache. If records are missing, run `dcdiag /test:dns` on the DC and `nltest /dsregdns` there.', verify: 'nltest /dsgetdc:corp.lab /force shows a DC; a new user logs on.' },
    { symptom: 'KRB_AP_ERR_SKEW / "There is a time and/or date difference between the client and server" / 4771 0x25', causes: ['Client clock drifted (VM restored from snapshot, host time sync fighting the domain hierarchy)', 'PDC emulator free-running or syncing to a wrong source, dragging the whole domain', 'Client configured with Type NTP to an unreachable server'], diagnose: ['w32tm /query /source', 'w32tm /query /status', 'w32tm /stripchart /computer:dc01.corp.lab /samples:3 /dataonly', 'w32tm /monitor (on a DC)'], fix: 'Member: `w32tm /config /syncfromflags:domhier /update` then `w32tm /resync /rediscover`. PDC emulator: configure reliable external peers (`w32tm /config /manualpeerlist:"0.pool.ntp.org,0x8 1.pool.ntp.org,0x8" /syncfromflags:manual /reliable:yes /update`). Disable hypervisor time sync for DCs (Hyper-V "Time synchronization" integration service) so it does not override domain time.', verify: 'w32tm /query /source shows a DC; stripchart offset < 1 s; klist purge; access works.' },
    { symptom: 'Access to an intranet site or share fails with KRB_AP_ERR_MODIFIED (System event 4) or repeated password prompts', causes: ['The same SPN registered on two accounts (duplicate)', 'The service runs as a service account but the SPN is on the computer account (or vice versa)', 'Clients reach the service by an alias (CNAME) for which no SPN exists → NTLM fallback, which may be blocked'], diagnose: ['setspn -X', 'setspn -Q HTTP/intranet.corp.lab', 'setspn -L CORP\\svc-web', 'klist get HTTP/intranet.corp.lab'], fix: 'Remove the SPN from the wrong account (`setspn -D HTTP/intranet.corp.lab APP01`) and add it to the account the service actually runs as with `setspn -S` (which refuses to create duplicates). Then `klist purge` on the client.', verify: 'setspn -X reports "found 0 group of duplicate SPNs"; klist shows the HTTP ticket; page opens without a prompt.' },
    { symptom: '"The trust relationship between this workstation and the primary domain failed."', causes: ['Machine restored from an old snapshot/backup (machine password older than the one AD has)', 'Computer account reset or deleted and recreated in AD', 'Two machines with the same name (re-imaged PC joined with the same name while the old one still runs)'], diagnose: ['nltest /sc_verify:corp.lab (log on with a local admin)', 'Test-ComputerSecureChannel -Verbose', 'Get-ADComputer WS07 -Properties PasswordLastSet,whenChanged (on a DC)', 'System log on the DC: Netlogon 5722'], fix: 'Log on locally and run `Test-ComputerSecureChannel -Repair -Credential CORP\\adm-alice` (or `Reset-ComputerMachinePassword -Server dc01 -Credential …`). Rejoin only if the computer object is gone.', verify: 'Test-ComputerSecureChannel returns True; domain logon works after reboot.' },
    { symptom: 'New users or group changes appear on dc01 but not dc02; users get different results depending on the DC', causes: ['Replication failing: partner unreachable (RPC 135/dynamic blocked), DNS cannot resolve the partner\'s `<GUID>._msdcs` CNAME', 'A DC offline longer than the tombstone lifetime (180 days) or rolled back from a snapshot (USN rollback)'], diagnose: ['repadmin /replsummary', 'repadmin /showrepl', 'dcdiag /test:replications', 'Get-WinEvent -LogName "Directory Service" -MaxEvents 50 (2042, 1311, 1864, 2087, 2095)'], fix: 'Fix the cause named by the error code (DNS registration of the partner, firewall, start the partner). Then `repadmin /syncall /AdeP`. A DC past tombstone lifetime or with USN rollback must be demoted (forcibly if needed) and rebuilt, not forced back into replication.', verify: 'repadmin /replsummary: 0 fails on every DC; the new object exists on all DCs.' },
    { symptom: 'gpupdate: "Computer policy could not be updated successfully" / event 1058 or 1030', causes: ['Client cannot reach SYSVOL (SMB 445 blocked, DFS client issue, DC chosen is unhealthy)', 'GPO folder missing on the chosen DC because DFSR SYSVOL replication is broken (2213, 4012)', 'Kerberos/LDAP failure to the DC (time, secure channel) → 1030'], diagnose: ['gpresult /r', 'Get-WinEvent -LogName Microsoft-Windows-GroupPolicy/Operational -MaxEvents 30', 'dir \\\\corp.lab\\SYSVOL\\corp.lab\\Policies', 'Get-WinEvent -LogName "DFS Replication" -MaxEvents 30 (on each DC)'], fix: 'Fix connectivity or the DFSR state on the affected DC (for 2213, follow the event text to resume replication after checking the database). Then `gpupdate /force` on the client.', verify: 'gpupdate completes for computer and user; gpresult lists the expected GPOs applied from a healthy DC.' },
    { symptom: 'DC reboots and nobody can log on for 10+ minutes; DNS Server event 4013', causes: ['DC\'s DNS client points only to itself (or 127.0.0.1 first), so DNS waits for AD and AD waits for DNS to find its replication partners', 'All DCs rebooted together'], diagnose: ['Get-DnsClientServerAddress (on the DC)', 'Get-WinEvent -LogName "DNS Server" -MaxEvents 20', 'dcdiag /test:advertising'], fix: 'Configure each DC: preferred DNS = another DC, alternate = its own IP, 127.0.0.1 last. Reboot DCs one at a time.', verify: 'dcdiag /test:advertising passes shortly after boot; no new 4013 at the next restart.' },
  ],
  verification: [
    { check: 'All DCs pass the core tests', command: 'dcdiag /q /e', expect: '(no output: every test on every DC passed)' },
    { check: 'Replication is healthy everywhere', command: 'repadmin /replsummary', expect: 'fails/total 0 / N for every source and destination DSA' },
    { check: 'SRV records exist for every DC', command: 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab', expect: 'One SRV answer per DC (dc01, dc02) on port 389' },
    { check: 'Client finds a DC in its site', command: 'nltest /dsgetdc:corp.lab /force', expect: 'DC: \\\\dc01.corp.lab ... Flags: ... KDC TIMESERV ... CLOSE_SITE' },
    { check: 'Time hierarchy is correct', command: 'w32tm /query /source  (client, DC, PDC emulator)', expect: 'client: a DC; DC: the PDC emulator; PDC emulator: external NTP peers' },
    { check: 'Secure channel and Kerberos', command: 'nltest /sc_verify:corp.lab; klist', expect: 'NERR_Success; a TGT for krbtgt/CORP.LAB from a DC' },
    { check: 'Policy applies', command: 'gpresult /r /scope computer', expect: 'Applied Group Policy Objects lists the expected GPOs; "Group Policy was applied from" a DC' },
  ],
  refIds: ['dcdiag', 'repadmin', 'nltest', 'klist', 'setspn', 'gpresult', 'gpupdate', 'w32tm', 'resolve-dnsname', 'nslookup-win', 'get-service', 'restart-service', 'get-winevent', 'tnc', 'ipconfig', 'file:ntds.dit', 'file:sysvol', 'file:netlogon.log', 'file:reg-w32time', 'file:winevt-logs', 'proc:secure-channel-repair', 'proc:time-sync-fix', 'proc:spn-fix', 'proc:dc-service-restart', 'proc:gpo-troubleshoot', 'proc:incident-record'],
};

// --- Lesson -------------------------------------------------------------------------

export const AD_KERBEROS_LESSON: Lesson = {
  id: 'ad-kerberos',
  moduleId: 'C',
  title: 'Active Directory, DNS and Kerberos',
  level: 'intermediate',
  mode: 'simulated',
  summary: 'How domain controllers, AD-integrated DNS, Kerberos, time, secure channels, replication and Group Policy depend on each other, and how to find which link broke without restarting domain controllers at random.',
  concepts: ['ad.dns', 'ad.kerberos', 'ad.gpo', 'win.services', 'dns.resolution', 'dns.zone', 'tcp.handshake', 'ops.recovery'],

  what: `
In a small office, each computer can keep its own list of users and passwords. With hundreds of computers that becomes impossible: every new employee, password change or departure would have to be repeated everywhere. **Active Directory Domain Services (AD DS)** solves this with one central directory.

AD DS is Microsoft's **directory service**: a database of users, groups, computers, service accounts and Group Policy Objects, kept on servers called **domain controllers (DCs)** and copied (replicated) between them. A Windows computer that is **joined** to the domain trusts the DCs to check users' passwords, and the DCs trust the computer through a password of its own, the **machine password**.

Active Directory is built on technologies from earlier lessons: [DNS](#/lesson/transport/what) (clients find domain controllers through special DNS records), [Kerberos](#/lesson/kerberos/what) (for logons and single sign-on), [time synchronisation](#/lesson/ntp/what) (Kerberos refuses clocks more than 5 minutes apart), and plain network reachability to the DC's ports. When any of these breaks, domain logons break with it.

### What a domain gives you
- **One identity everywhere.** \`CORP\\dana\` logs on to any joined PC, opens file shares, intranet sites and RDP sessions without typing her password again (single sign-on through Kerberos).
- **Central authorisation.** Security groups end up in the user's access token and are checked by every server's ACLs and user rights.
- **Central configuration.** Group Policy pushes security baselines, drive mappings, firewall rules and software settings to thousands of machines.

:::practice
Q: dana logs on to a PC in the morning and later opens a file share and an intranet site without typing her password again. Which mechanism makes that possible?
A: **Single sign-on through Kerberos**: her TGT from the logon is used to get service tickets for each server.
Q: A security baseline must reach 800 PCs. Which part of AD delivers it?
A: **Group Policy**: GPOs linked to the domain or OUs push the settings to every computer in scope.
:::

### The services on a domain controller
- **AD DS** (service \`NTDS\`): the database \`ntds.dit\`, LDAP on 389/636, Global Catalog on 3268/3269, multi-master replication.
- **DNS Server** (service \`DNS\`): usually installed on every DC, hosting **AD-integrated zones** (\`corp.lab\` and \`_msdcs.corp.lab\`) stored in the directory and replicated with it.
- **Kerberos Key Distribution Center** (service \`Kdc\`): issues tickets on port 88.
- **Netlogon**: registers the DC's DNS records, answers DC-locator pings, maintains secure channels and handles NTLM pass-through.
- **DFS Replication** (\`DFSR\`): replicates the **SYSVOL** folder that holds GPO files and logon scripts.
- **Windows Time** (\`W32Time\`): the domain time hierarchy. The **PDC emulator** is the root and should be the only DC that syncs to an external NTP source.

:::practice
Q: Which DC service registers the SRV records that clients use to find domain controllers?
A: **Netlogon**.
Q: GPO files on one DC are older than on the others, while users and groups replicate fine. Which service is at fault?
A: **DFS Replication (DFSR)**, which replicates SYSVOL separately from the AD database.
:::

### Where you meet it
Almost every organisation with Windows clients: logons, file servers, Exchange/SQL/IIS with integrated authentication, RDP to servers, VPN and Wi-Fi (RADIUS/NPS) authentication, and Linux servers joined with SSSD.

> Example output in this lesson is representative of **Windows Server 2022** DCs (\`dc01\` 10.0.20.5 holds the FSMO roles, \`dc02\` 10.0.20.6), **Windows 11 23H2** clients, and Ubuntu 24.04 / RHEL 9 members, in the lab plan's domain \`corp.lab\` (NetBIOS name \`CORP\`). Windows Server 2019 behaves the same for everything shown.\n>\n> **In the simulator** the domain is **ad.corp.lab** (NetBIOS \`CORP\`) with one DC, **dc01** (10.0.20.5, AD DS and DNS forwarding to ns1), and the member server **win01**. The sandbox below, the domain tickets and **Lab 2** use it: DC location through SRV records, domain join and the secure channel, Remote Desktop logons (NLA with NTLM pass-through, then the logon with Kerberos tickets from dc01's KDC, falling back to NTLM when no KDC answers), the 5-minute clock skew and the Windows Time service synchronising members from the DC, SPNs, lockout, and the tools (\`Get-ADUser\`, \`Get-DnsServerResourceRecord\`, \`nltest\`, \`Test-ComputerSecureChannel\`, \`klist\` with \`-li 0x3e7\`, \`get\` and \`purge\`, \`setspn\`, \`w32tm /query\`, \`/resync\` and \`/stripchart\`; Security events 4768/4769/4771 on the DC). Replication between DCs, constrained delegation, Kerberos armoring, RC4/DES and sssd members are not simulated.
`,

  internals: `
### 1. DNS and the DC locator
Clients do not have a list of DCs. They **ask DNS**. When a DC starts, Netlogon registers records such as:
- \`_ldap._tcp.dc._msdcs.corp.lab\` SRV → every DC (port 389)
- \`_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.corp.lab\` SRV → DCs in that site
- \`_kerberos._tcp.corp.lab\` and \`_kerberos._udp.corp.lab\` SRV → every KDC (port 88)
- \`_ldap._tcp.gc._msdcs.corp.lab\` SRV → Global Catalog servers (port 3268)
- \`<DSA-GUID>._msdcs.corp.lab\` CNAME → the DC's host name (used by **replication partners** to find each other)

The full list is in \`%SystemRoot%\\System32\\config\\netlogon.dns\` on each DC. The client's Netlogon service (the **DC locator**) queries the site-specific record, then the generic one, sends a **CLDAP ping** (UDP 389) to the DCs returned, and uses the first one that answers. \`nltest /dsgetdc:corp.lab\` runs exactly this process.

> **Rule:** every domain member must use **only** AD DNS servers. A public resolver or a home router as *secondary* DNS does not "add redundancy": it answers NXDOMAIN for \`corp.lab\`, the client caches the negative answer, and logons, Group Policy and file shares fail intermittently. If clients need Internet names, the AD DNS servers forward to the Internet (DNS Server forwarders), not the other way round.

On the DCs themselves: preferred DNS = **another DC**, alternate = its own IP, \`127.0.0.1\` last. A DC that points only to itself may wait at boot for its own DNS, which waits for AD (DNS Server event 4013).

:::practice
Q: Which SRV record would a client in the site "Branch1" query first to find a domain controller of corp.lab?
A: \`_ldap._tcp.Branch1._sites.dc._msdcs.corp.lab\`, the site-specific record; then the generic \`_ldap._tcp.dc._msdcs.corp.lab\`.
Q: A new DC was installed. What should its own DNS client settings be?
A: Preferred DNS = **another DC**, alternate = its own IP, 127.0.0.1 last. Pointing only at itself can make it wait at boot for its own DNS (event 4013).
:::

### 2. Kerberos
Kerberos (RFC 4120) authenticates with **tickets** instead of sending passwords to every server. The Kerberos **realm** of an AD domain is its DNS name in **upper case**: the domain corp.lab is the realm \`CORP.LAB\`. Realm names are case-sensitive, so on a Linux member \`kinit dana@CORP.LAB\` works while \`kinit dana@corp.lab\` asks for a realm that does not exist. Depending on the client's krb5.conf, that fails with "Cannot find KDC for realm" (the lower-case realm is not configured and KDCs are not looked up in DNS) or with "KDC reply did not match expectations" (a DC was found through DNS, which ignores case, and answered for CORP.LAB).
1. **AS exchange** (Authentication Service). At logon the client sends an **AS-REQ** for \`krbtgt/CORP.LAB\`. The first attempt is rejected with \`KDC_ERR_PREAUTH_REQUIRED\` (normal); the client resends it with a timestamp encrypted with the user's password-derived key. The KDC decrypts it: wrong key → bad password (Security 4771, code 0x18); timestamp more than **5 minutes** off → \`KRB_AP_ERR_SKEW\` (0x25). Success → **AS-REP** with a **TGT** (Ticket-Granting Ticket), valid 10 hours, renewable for 7 days. DC logs Security **4768**.
2. **TGS exchange** (Ticket-Granting Service). To open \`\\\\fs01\\data\` the client sends a **TGS-REQ** with its TGT, naming the **SPN** \`cifs/fs01.corp.lab\`. The KDC searches the directory for the account that has that SPN in its \`servicePrincipalName\` attribute and returns a **service ticket** encrypted with **that account's key**. DC logs **4769**. No account → \`KDC_ERR_S_PRINCIPAL_UNKNOWN\` and Windows falls back to NTLM.
3. **AP exchange**. The client sends the service ticket inside the application protocol (SMB, HTTP Negotiate, LDAP, RDP/CredSSP). fs01 decrypts it with its own key; no DC is contacted. If the key does not match (the SPN belongs to another account, e.g. a duplicate), the server cannot decrypt it: \`KRB_AP_ERR_MODIFIED\`.

The ticket contains the **PAC** (Privilege Attribute Certificate): the user's SID and group SIDs, signed by the KDC. The server builds the access token from it, which is why a user added to a group needs a **new TGT** (log off/on, or \`klist purge\` for new service tickets after the TGT is renewed) before the new access works.

**SPNs** (Service Principal Names) are \`service/host[:port]\` strings: \`HOST/app01.corp.lab\` (covers cifs, RPC and many others), \`HTTP/intranet.corp.lab\`, \`MSSQLSvc/sql01.corp.lab:1433\`, \`TERMSRV/app01.corp.lab\`. Computer accounts register their own; a service running as a domain user account needs SPNs on **that** account. An SPN must be unique in the forest.

**NTLM fallback**: when Kerberos cannot be used (access by IP address, unknown SPN, no KDC reachable), Windows uses NTLM challenge/response, which the server validates through its Netlogon secure channel to a DC (DC logs **4776**). It works, but it is weaker and is increasingly blocked by policy, so "it only works by IP" or "it only works with NTLM" is a symptom of a Kerberos problem, not a solution.

:::practice
Q: A user was added to the group "Finance-Share" five minutes ago and still gets "Access denied" on the finance share. Why, and what makes it work?
A: Group membership travels in the **PAC** of the user's tickets, which were issued before the change. The user needs a **new TGT** (log off and on), after which new service tickets carry the group.
Q: A web application runs as \`CORP\svc-intranet\` and users reach it as \`https://portal.corp.lab\`. Which SPN must exist, and on which account?
A: \`HTTP/portal.corp.lab\`, on the **svc-intranet** account (the account the service runs as), and on no other account.
:::

### 3. Time
Kerberos timestamps make **time a hard dependency**. The default "Maximum tolerance for computer clock synchronization" is **5 minutes**. The hierarchy:
- Members (\`Type = NT5DS\`) sync from a DC in their domain.
- DCs sync from the **PDC emulator** of the domain (or a DC higher in the hierarchy).
- The PDC emulator of the forest root syncs from a **reliable external source** (\`Type = NTP\`, \`w32tm /config /manualpeerlist:... /syncfromflags:manual /reliable:yes /update\`).
If the PDC emulator free-runs, the whole domain drifts together (logons still work, but Linux hosts, appliances and other forests using real NTP drift away). If a single client drifts (a VM restored from snapshot), only that client fails. On that client, \`w32tm /query /source\` shows \`Local CMOS Clock\` (or \`Free-running System Clock\`) instead of a DC: it has left the domain hierarchy. Put it back with \`w32tm /config /syncfromflags:domhier /update\` followed by \`w32tm /resync\`, and check that the hypervisor's own time synchronisation is not fighting W32Time. On the DC, its failed logons show as Security event 4771 with failure code **0x25** (clock skew).

:::practice
Q: In a single-domain forest, which DC should sync from external NTP servers, and how do all the others get their time?
A: The DC holding the **PDC emulator** role. Other DCs sync from it (or from a DC higher up), and members sync from a DC in their domain (NT5DS).
Q: Every machine in the domain is 4 minutes behind the real time, but logons work. Why do they work, and what still breaks?
A: Everyone drifts **together**, so Kerberos sees no skew between clients and DCs. Systems that use real NTP (Linux hosts, appliances, other forests) can drift away and fail, and logs no longer match real time. Configure the PDC emulator with an external source.
:::

### 4. Secure channel and machine accounts
Joining a computer creates a computer object (\`WS07$\`) with a **machine password** known to both the computer (stored as an LSA secret) and AD. Netlogon uses it to build a **secure channel** to a DC at boot, and the computer changes it automatically every 30 days. If the two copies diverge (snapshot restore, object reset, duplicate name), the computer can no longer authenticate: "The trust relationship between this workstation and the primary domain failed." The repair resets the password on both sides: \`Test-ComputerSecureChannel -Repair\` or \`Reset-ComputerMachinePassword\`.

:::practice
Q: A VM was rolled back to a snapshot from two months ago. After it starts, domain logons fail with "The trust relationship ... failed". Why?
A: The computer changed its machine password since the snapshot, so its restored copy no longer matches the one in AD. The secure channel cannot be built.
Q: What repairs it without leaving and re-joining the domain?
A: \`Test-ComputerSecureChannel -Repair -Credential DOMAIN\admin\` (or \`Reset-ComputerMachinePassword\`), run with a local administrator logon.
:::

### 5. Replication
Replication partners find each other through DNS too, using the \`<DSA-GUID>._msdcs.corp.lab\` CNAME of each DC. Error **8524** ("The DSA operation is unable to proceed because of a DNS lookup failure") in \`repadmin /replsummary\` means that lookup failed: check the DNS client settings of the DC that reports it, and whether its partner registered its records.

Every DC has a writable copy. Each change increments the DC's **USN**; partners remember the highest USN they have seen from each DC (the *up-to-dateness vector*) and **pull** what is new over RPC. Within a site, change notification triggers replication within about 15 seconds; between sites, on the site-link schedule (default 180 minutes). The **KCC** on each DC builds the connection objects automatically. Deleted objects become **tombstones** kept for the **tombstone lifetime** (180 days in forests created on Server 2003 SP1 or later); a DC that has not replicated for longer than that must not be reconnected (it could reintroduce deleted objects as *lingering objects*), so replication refuses with error 8614 and event 2042.

SYSVOL is replicated separately by **DFSR**. AD replication healthy + DFSR broken = GPO version in AD (\`gPCVersion\`) does not match the files on that DC, and clients see inconsistent policy.

:::practice
Q: A password change made on dc01 is not accepted by dc02 an hour later. \`repadmin /replsummary\` shows failures with error 8524 on dc02. Where do you look?
A: At **DNS**: dc02 cannot resolve dc01's \`<DSA-GUID>._msdcs\` CNAME. Check dc02's DNS client settings and whether dc01 registered its records.
Q: AD replication is healthy but clients get different policy settings depending on which DC they use. What else replicates and may be broken?
A: **SYSVOL**, which is replicated separately by DFSR. A DC with stale SYSVOL serves old GPO files.
:::

### 6. Group Policy
The Group Policy Client service (**gpsvc**) applies **computer** policy at boot and **user** policy at logon, then refreshes in the background every 90 minutes ± up to 30 (DCs every 5 minutes). It asks LDAP which GPOs are linked to the site, domain and OUs of the computer/user (and filtered by security groups and WMI filters), then reads each GPO's files from **SYSVOL** over SMB using Kerberos. Failures: LDAP/Kerberos to the DC (System event **1030**), reading \`gpt.ini\` from SYSVOL (**1058**), or a client-side extension failing (Operational log **7016**).

:::practice
Q: \`gpupdate\` reports event 1030. Which step failed: reading the GPO list or reading the files?
A: Reading the **GPO list**: 1030 means the LDAP/Kerberos query to the DC failed. (1058 would mean reading gpt.ini from SYSVOL failed.)
Q: How often is computer policy refreshed in the background on a member, and on a DC?
A: Every **90 minutes ± up to 30** on members, every **5 minutes** on DCs, plus at boot (computer) and logon (user).
:::

### Services involved, by machine
- **DC**: NTDS, DNS, Kdc, Netlogon, W32Time, DFSR, IsmServ, LanmanServer (shares SYSVOL/NETLOGON), RpcSs.
- **Member**: Netlogon (locator, secure channel), Dnscache (DNS client), W32Time, gpsvc, LanmanWorkstation (SMB client for SYSVOL), lsass (Kerberos).
`,

  deployment: [
    {
      id: 'ws-forest',
      platform: 'Windows Server 2019 / 2022: first DC and new forest',
      summary: 'Promote the first domain controller of a new forest with integrated DNS, then configure its time source. Run in an elevated PowerShell on a real VM (Windows Server 2022 output shown). Use a test domain name you control; `corp.lab` is the lab plan.',
      prerequisites: ['Windows Server 2019 or 2022 VM, fully patched, with a **static IPv4 address** (10.0.20.5/24, gateway 10.0.20.1).', 'A meaningful computer name set before promotion (`Rename-Computer dc01 -Restart`): renaming a DC later is awkward.', 'Console access through the hypervisor (the promotion reboots the server).', 'A planned DSRM (Directory Services Restore Mode) password, stored safely.'],
      steps: [
        { title: 'Set the static IP and temporary DNS', command: 'New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.20.5 -PrefixLength 24 -DefaultGateway 10.0.20.1\nSet-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 127.0.0.1', what: 'Gives the future DC a fixed address. For the very first DC there is no other DC, so it uses itself for now.', why: 'DCs are found through DNS records containing their IP; a DHCP address that changes breaks every client. After the second DC exists you will change the DNS order.', expected: 'IPAddress         : 10.0.20.5\nInterfaceAlias    : Ethernet\nPrefixLength      : 24' },
        { title: 'Install the AD DS role', command: 'Install-WindowsFeature AD-Domain-Services -IncludeManagementTools', what: 'Installs the binaries and the management tools (ADUC, ADAC, PowerShell ActiveDirectory module, dcdiag, repadmin). The server is not a DC yet.', why: 'Role installation and promotion are separate steps.', expected: 'Success Restart Needed Exit Code      Feature Result\n------- -------------- ---------      --------------\nTrue    No             Success        {Active Directory Domain Services, Group P...' },
        { title: 'Create the forest with DNS', command: 'Install-ADDSForest -DomainName corp.lab -DomainNetbiosName CORP -InstallDns -ForestMode WinThreshold -DomainMode WinThreshold -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM password")', what: 'Promotes the server to the first DC of a new forest, creates the AD-integrated zones `corp.lab` and `_msdcs.corp.lab`, creates SYSVOL, and reboots. `WinThreshold` is the Windows Server 2016 functional level, the highest available on 2019/2022.', why: '`-InstallDns` puts DNS on the DC so the zones are stored in AD and replicate automatically. The DSRM password is needed for authoritative restores and is not your domain admin password.', expected: 'WARNING: A delegation for this DNS server cannot be created because the authoritative parent zone cannot be found ...\n(the server restarts)\n\nMessage                           Context           RebootRequired  Status\n-------                           -------           --------------  ------\nOperation completed successfully  DCPromo.General.3          False Success' },
        { title: 'Verify the services and records', command: 'Get-Service NTDS, DNS, Kdc, Netlogon, DFSR, W32Time\nResolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab\ndcdiag /q', what: 'Checks that the DC services run, the SRV records were registered, and dcdiag reports no errors.', why: 'A successful promotion with failing Netlogon registration still leaves clients unable to find the DC.', expected: 'Status   Name               DisplayName\n------   ----               -----------\nRunning  NTDS               Active Directory Domain Services\nRunning  DNS                DNS Server\nRunning  Kdc                Kerberos Key Distribution Center\nRunning  Netlogon           Netlogon\nRunning  DFSR               DFS Replication\nRunning  W32Time            Windows Time' },
        { title: 'Add a DNS forwarder for Internet names', command: 'Add-DnsServerForwarder -IPAddress 1.1.1.1, 9.9.9.9', what: 'Unknown (Internet) names are forwarded upstream by the DC.', why: 'This is how clients get Internet resolution while using only the DCs as DNS servers.', expected: '(no output)' },
        { title: 'Configure the PDC emulator time source', command: 'w32tm /config /manualpeerlist:"0.pool.ntp.org,0x8 1.pool.ntp.org,0x8" /syncfromflags:manual /reliable:yes /update\nw32tm /resync /rediscover\nw32tm /query /source', what: 'Makes the PDC emulator (the first DC) sync from external NTP and announce itself as a reliable time source. `0x8` = client mode.', why: 'The PDC emulator is the root of domain time. Left at defaults it uses the local CMOS clock. On a VM, also disable the hypervisor\'s guest time synchronisation for DCs.', expected: 'The command completed successfully.\nSending resync command to local computer\nThe command completed successfully.\n0.pool.ntp.org,0x8' },
      ],
    },
    {
      id: 'ws-second-dc',
      platform: 'Windows Server 2019 / 2022: second DC and DC DNS settings',
      summary: 'Add dc02 to the existing domain, then set both DCs\' DNS client order. Two DCs are the minimum for any domain you care about.',
      prerequisites: ['Windows Server 2019/2022 VM with static IP 10.0.20.6, DNS pointing to dc01 (10.0.20.5).', 'Domain Admin credentials.', '`repadmin /replsummary` and `dcdiag /q` clean on dc01 first.'],
      steps: [
        { title: 'Install the role and promote', command: 'Install-WindowsFeature AD-Domain-Services -IncludeManagementTools\nInstall-ADDSDomainController -DomainName corp.lab -InstallDns -Credential (Get-Credential CORP\\Administrator) -SiteName Default-First-Site-Name -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM password")', what: 'Promotes dc02 as an additional DC with DNS and Global Catalog (default), replicating the directory and SYSVOL from dc01.', why: 'dc02 must find dc01 through DNS during promotion, which is why its DNS points at dc01.', expected: 'Message                           Context           RebootRequired  Status\n-------                           -------           --------------  ------\nOperation completed successfully  DCPromo.General.3          False Success' },
        { title: 'Set the DNS client order on both DCs', command: '# on dc01\nSet-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.0.20.6, 10.0.20.5, 127.0.0.1\n# on dc02\nSet-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.0.20.5, 10.0.20.6, 127.0.0.1', what: 'Preferred = the other DC, alternate = itself by IP, loopback last.', why: 'Avoids the boot-time "island" where a DC waits for its own DNS, and lets each DC register its records even if its own DNS is still loading. `dcdiag /test:dns` warns about the loopback-first configuration.', expected: '(no output)' },
        { title: 'Verify replication and SYSVOL', command: 'repadmin /replsummary\nGet-SmbShare SYSVOL, NETLOGON\ndcdiag /test:sysvolcheck /test:advertising', what: 'Confirms both DCs replicate and dc02 shares SYSVOL (DFSR initial sync finished: DFS Replication event 4604).', why: 'A DC that advertises without SYSVOL gives clients Group Policy failures.', expected: 'Source DSA          largest delta    fails/total %%   error\n DC01                      01m:04s    0 /   5    0\n DC02                      00m:47s    0 /   5    0' },
        { title: 'Hand out only DC DNS servers to clients', command: 'Set-DhcpServerv4OptionValue -ScopeId 10.0.10.0 -DnsServer 10.0.20.5, 10.0.20.6 -DnsDomain corp.lab', what: 'On a Windows DHCP server: option 006 lists both DCs and nothing else. On other DHCP servers (ISC, pfSense, a router) set the same two addresses.', why: 'Clients with a public secondary DNS fail intermittently in ways that are hard to reproduce.', expected: '(no output)' },
      ],
    },
    {
      id: 'win-client',
      platform: 'Windows 10 / 11: joining the domain',
      summary: 'Join a Pro/Enterprise/Education edition (Home cannot join a domain). Run in an elevated PowerShell.',
      prerequisites: ['Windows 10/11 Pro, Enterprise or Education.', 'Network path to the DCs (TCP/UDP 53, 88, 389, 445, 135 + dynamic RPC, 464, UDP 123).', 'Credentials of an account allowed to join computers (or a pre-created computer object).'],
      steps: [
        { title: 'DNS prerequisite', command: 'Get-DnsClientServerAddress -AddressFamily IPv4\nResolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab', what: 'Confirms the client uses the DCs as DNS servers and can find the SRV records.', why: 'If this fails, the join fails with "The specified domain either does not exist or could not be contacted." Fix DNS first, never by adding a hosts entry.', expected: '_ldap._tcp.dc._msdcs.corp.lab  SRV  600  Answer  dc01.corp.lab  0  100  389\n_ldap._tcp.dc._msdcs.corp.lab  SRV  600  Answer  dc02.corp.lab  0  100  389' },
        { title: 'Join and restart', command: 'Add-Computer -DomainName corp.lab -OUPath "OU=Workstations,DC=corp,DC=lab" -Credential CORP\\adm-alice -Restart', what: 'Creates (or reuses) the computer object, sets the machine password and restarts.', why: '`-OUPath` places the computer where the right GPOs are linked instead of the default Computers container (which cannot have GPOs linked).', expected: 'WARNING: The changes will take effect after you restart the computer WS07.\n(restart)' },
        { title: 'Verify after restart', command: 'nltest /sc_verify:corp.lab\nw32tm /query /source\ngpresult /r /scope computer', what: 'Secure channel, time source and policy.', why: 'A join is complete only when all three are healthy.', expected: 'Trust Verification Status = 0 0x0 NERR_Success\ndc01.corp.lab\n    Group Policy was applied from:      dc01.corp.lab' },
      ],
    },
    {
      id: 'linux-join',
      platform: 'Ubuntu 24.04 / Debian 12 and RHEL 9: joining with realmd and SSSD',
      summary: 'Linux members join AD with realmd (discovery and join, using adcli) and SSSD (identity and Kerberos authentication). Package names differ between the families; the rest is the same. Run on real VMs.',
      prerequisites: ['DNS on the Linux host pointing at the DCs (netplan/systemd-resolved on Ubuntu, NetworkManager on RHEL).', 'Time synchronised to the DCs (chrony `server dc01.corp.lab iburst`).', 'A host name in the domain (`sudo hostnamectl set-hostname ubu01.corp.lab`).'],
      steps: [
        { title: 'Install packages (Ubuntu/Debian)', command: 'sudo apt install realmd sssd sssd-tools libnss-sss libpam-sss adcli samba-common-bin oddjob oddjob-mkhomedir packagekit krb5-user', what: 'realmd + adcli perform the join; sssd provides users/groups and authentication; krb5-user provides kinit/klist.', why: 'realm discover lists the required packages if any are missing.', expected: 'Setting up sssd (2.9.4-1.1ubuntu6) ...' },
        { title: 'Install packages (RHEL 9)', command: 'sudo dnf install realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools krb5-workstation', what: 'Same components with RHEL package names.', why: 'RHEL uses authselect; realm join selects the sssd profile automatically.', expected: 'Complete!' },
        { title: 'Discover the domain', command: 'realm discover corp.lab', what: 'Uses DNS SRV records and CLDAP to find the domain and what software is needed.', why: 'If discovery fails, the join will fail: check DNS first (`resolvectl query -t SRV _ldap._tcp.corp.lab` on Ubuntu).', expected: 'corp.lab\n  type: kerberos\n  realm-name: CORP.LAB\n  domain-name: corp.lab\n  configured: no\n  server-software: active-directory\n  client-software: sssd' },
        { title: 'Join', command: 'sudo realm join -U adm-alice corp.lab', what: 'Creates the computer account `UBU01$`, writes `/etc/krb5.keytab`, generates `/etc/sssd/sssd.conf` and enables sssd in NSS/PAM.', why: 'The keytab holds the machine password, the Linux equivalent of the Windows secure channel secret.', expected: 'Password for adm-alice:\n(no further output on success)' },
        { title: 'Review sssd.conf', command: 'sudo cat /etc/sssd/sssd.conf', what: 'Shows the generated configuration (mode 0600 root).', why: 'Decide on `use_fully_qualified_names` (dana@corp.lab vs dana) and restrict logins with `realm permit -g linux-admins@corp.lab` instead of allowing every domain user.', expected: '[sssd]\ndomains = corp.lab\nconfig_file_version = 2\nservices = nss, pam\n\n[domain/corp.lab]\ndefault_shell = /bin/bash\nkrb5_store_password_if_offline = True\ncache_credentials = True\nkrb5_realm = CORP.LAB\nrealmd_tags = manages-system joined-with-adcli\nid_provider = ad\nfallback_homedir = /home/%u@%d\nad_domain = corp.lab\nuse_fully_qualified_names = True\nldap_id_mapping = True\naccess_provider = ad' },
        { title: 'Home directories', command: '# Ubuntu/Debian\nsudo pam-auth-update --enable mkhomedir\n# RHEL\nsudo authselect enable-feature with-mkhomedir && sudo systemctl enable --now oddjobd', what: 'Creates a home directory at first login.', why: 'Without it, AD users log in to `/` with "Could not chdir to home directory".', expected: '(no output)' },
        { title: 'Test identity and Kerberos', command: 'id dana@corp.lab\nkinit dana@CORP.LAB\nklist', what: 'Checks that sssd resolves the AD user and groups, and that the KDC issues a TGT.', why: 'Kerberos realm names are upper case. "Clock skew too great" here means fix chrony first.', expected: 'uid=1622801105(dana@corp.lab) gid=1622800513(domain users@corp.lab) groups=1622800513(domain users@corp.lab)\nTicket cache: KCM:1000\nDefault principal: dana@CORP.LAB\n\nValid starting       Expires              Service principal\n21/10/26 09:10:02    21/10/26 19:10:02    krbtgt/CORP.LAB@CORP.LAB\n\trenew until 28/10/26 09:10:00' },
      ],
    },
    {
      id: 'not-applicable',
      platform: 'pfSense and Docker/Compose',
      summary: 'Not applicable as deployment targets: AD DS runs only on Windows Server. **pfSense** integrates with AD as a client: add an LDAP (or RADIUS via NPS) authentication server under System > User Manager > Authentication Servers, and add a Domain Override for `corp.lab` → 10.0.20.5/10.0.20.6 in the DNS Resolver so pfSense itself can resolve AD names. **Containers** do not join the domain; they use a keytab or gMSA credential spec (Windows containers) provided by the host.',
      prerequisites: [],
      steps: [],
    },
  ],

  configIntro: `
AD configuration lives in three places: the **directory** itself (users, computers, SPNs, GPO links, site and replication topology), **files** on the DCs (ntds.dit, SYSVOL, netlogon.dns) and **per-machine settings** (DNS client, W32Time registry, sssd.conf on Linux). The settings below cause most incidents. Change them with the supported tools (\`w32tm /config\`, \`setspn -S\`, \`Set-DnsClientServerAddress\`, Group Policy), not by editing the registry or ntds.dit, and verify with the matching query command.
`,

  configFiles: [
    {
      platform: 'Windows Server (domain controller)',
      items: [
        { path: 'C:\\Windows\\NTDS\\ntds.dit', purpose: 'AD database (back up with System State).' },
        { path: 'C:\\Windows\\SYSVOL\\domain\\Policies, \\scripts', purpose: 'GPO files and logon scripts, shared as SYSVOL/NETLOGON, replicated by DFSR.' },
        { path: '%SystemRoot%\\System32\\config\\netlogon.dns', purpose: 'DNS records the DC should register.' },
        { path: '%windir%\\debug\\netlogon.log', purpose: 'Netlogon debug log (enable with nltest /dbflag:0x2080ffff).' },
        { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters', purpose: 'Time source type and peers (use w32tm /config).' },
        { path: 'Event logs: Directory Service, DNS Server, DFS Replication, System, Security', purpose: 'Replication, DNS zone, SYSVOL, Netlogon/Kerberos/W32Time and authentication events.' },
        { path: 'Services: NTDS, DNS, Kdc, Netlogon, DFSR, W32Time, IsmServ, LanmanServer', purpose: 'The DC service set.' },
      ],
    },
    {
      platform: 'Windows 10/11 and member servers',
      items: [
        { path: 'NIC DNS settings (or DHCP option 006)', purpose: 'Must list only AD DNS servers.' },
        { path: 'Microsoft-Windows-GroupPolicy/Operational', purpose: 'Detailed Group Policy processing log.' },
        { path: 'System log (Netlogon 5719, Security-Kerberos 4, GroupPolicy 1058/1030, W32Time)', purpose: 'Client-side failures.' },
        { path: 'Services: Netlogon, gpsvc, W32Time, Dnscache, LanmanWorkstation', purpose: 'Client-side services AD depends on.' },
      ],
    },
    {
      platform: 'Ubuntu/Debian and RHEL members',
      items: [
        { path: '/etc/sssd/sssd.conf', purpose: 'SSSD domain configuration (0600 root).' },
        { path: '/etc/krb5.conf', purpose: 'Kerberos client: default_realm, dns_lookup_kdc.' },
        { path: '/etc/krb5.keytab', purpose: 'Machine account keys (0600 root).' },
        { path: '/var/log/sssd/, journalctl -u sssd', purpose: 'SSSD logs.' },
        { path: '/etc/chrony/chrony.conf (Ubuntu) / /etc/chrony.conf (RHEL)', purpose: 'Time source: point at the DCs.' },
      ],
    },
  ],

  directives: [
    { name: 'Client DNS servers', compiledDefault: 'From DHCP', recommended: 'Only the AD DNS servers (10.0.20.5, 10.0.20.6)', explanation: 'Where the DC locator looks for SRV records. Every listed server must host or forward to the AD zones.', security: 'A public resolver leaks internal names (queries for corp.lab go to the Internet) and breaks logons. Internet resolution belongs on the DCs as forwarders.' },
    { name: 'DC DNS client order', compiledDefault: '127.0.0.1 after Install-ADDSForest', recommended: 'Another DC, then own IP, then 127.0.0.1', explanation: 'How a DC itself resolves its partners and registers its own records.', security: 'Self-only DNS leads to boot-time islands (event 4013) and replication failures after outages.' },
    { name: 'AD-integrated zone dynamic updates', compiledDefault: 'Secure only', recommended: 'Secure only', explanation: 'Lets Netlogon and domain members register their records using Kerberos-authenticated updates.', security: '"Nonsecure and secure" lets any device overwrite records (including DC SRV records). "None" stops DCs registering their SRV records.' },
    { name: 'Maximum tolerance for computer clock synchronization', compiledDefault: '5 minutes', recommended: '5 minutes (fix time instead)', explanation: 'Kerberos policy in the Default Domain Policy: the allowed clock difference.', security: 'Raising it widens the replay window for captured authenticators. Fix the time hierarchy instead.' },
    { name: 'Kerberos ticket lifetimes', compiledDefault: 'User ticket 10 h, renewal 7 days, service ticket 600 min', recommended: 'Defaults', explanation: 'How long tickets (and the group memberships in their PAC) stay valid.', security: 'Group removal takes effect only when the user gets a new ticket; disable the account for urgent revocation.' },
    { name: 'W32Time Type (members / PDC emulator)', compiledDefault: 'NT5DS on members and DCs', recommended: 'NT5DS everywhere except the forest-root PDC emulator: NTP with manual peers', explanation: 'Selects domain hierarchy vs manual NTP peers (`w32tm /config /syncfromflags:domhier|manual`).', security: 'A rogue or wrong time source can break authentication domain-wide and corrupt log timelines.' },
    { name: 'servicePrincipalName (per account)', compiledDefault: 'Computer accounts: HOST/, TERMSRV/, WSMAN/, RestrictedKrbHost/', recommended: 'Each SPN on exactly one account, the one the service runs as', explanation: 'Tells the KDC which key to encrypt service tickets with.', security: 'User accounts with SPNs can be "kerberoasted" (offline password guessing of their tickets): use long random passwords or gMSAs for service accounts.' },
    { name: 'Machine account password change', compiledDefault: 'Every 30 days (client-initiated)', recommended: 'Default', explanation: 'Netlogon rotates the secure channel password automatically.', security: 'Do not disable rotation to "avoid trust errors" after snapshot restores; fix the restore practice instead.' },
    { name: 'Tombstone lifetime', compiledDefault: '180 days (forests created on 2003 SP1+)', recommended: '180 days', explanation: 'How long deleted objects are kept so deletions can replicate. Also the maximum age of a usable backup or offline DC.', security: 'Reconnecting a DC older than this can reintroduce deleted (e.g. disabled admin) objects.' },
    { name: 'Group Policy refresh interval', compiledDefault: '90 min ± 30 (members), 5 min (DCs)', recommended: 'Default', explanation: 'Background refresh of computer and user policy.', security: 'Very short intervals add load on DCs and SYSVOL without real benefit.' },
  ],

  operateIntro: `
> **Record every change** and when you made it (proc:incident-record): AD changes replicate, so a mistake spreads to every DC within minutes. Check replication (\`repadmin /replsummary\`) before restarting anything on a DC.

`,
  troubleshootingIntro: `
### Follow the chain, and stop at the first broken link
A domain logon depends on a chain of other services: DNS to find a DC, the network to reach it, correct time for Kerberos, and a working trust between the computer and the domain. A break anywhere in the chain looks the same to the user ("cannot log on"), so check the links in order.

1. **Network and DNS.** Does the client use **only** the AD DNS servers? Does \`Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab\` return the domain controllers? Without these SRV records the client cannot find any DC.
2. **DC locator and reachability.** \`nltest /dsgetdc:corp.lab /force\` asks Windows to find a DC right now. \`Test-NetConnection dc01 -Port 88\` (Kerberos), \`-Port 389\` (LDAP) and \`-Port 445\` (SMB) test that the DC's key ports answer.
3. **Time.** \`w32tm /query /source\` shows where the computer gets its time; compare its clock with the DC's. More than 5 minutes apart, and Kerberos fails.
4. **Kerberos.** \`klist\` lists the tickets of the current session, and \`klist get <SPN>\` requests a new one. On the DC, Security events 4768 (ticket requested), 4769 (service ticket) and 4771 (pre-authentication failed) show the KDC's side.
5. **Secure channel.** \`nltest /sc_verify:corp.lab\` tests the computer's own trust with the domain (its machine password).
6. **Group Policy.** \`gpupdate /force\`, \`gpresult /r\` and the GroupPolicy Operational log show whether policy applies.
7. **DC health.** \`dcdiag /q\`, \`repadmin /replsummary\` and the DFSR log, on **every** DC, show whether the DCs themselves are healthy and replicating.

:::practice
Q: \`Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab\` fails on a client, but its Internet browsing works. Which link is broken, and what do you check?
A: The first one, **DNS**: the client probably uses a DNS server that is not an AD DNS server (a router or public resolver). Check \`Get-DnsClientServerAddress\`.
Q: DNS and the DC locator work, \`Test-NetConnection dc01 -Port 88\` succeeds, but logons still fail with clock skew errors. Which link, and which command shows the client's time source?
A: **Time**. \`w32tm /query /source\` (and compare the clock with the DC's).
:::

### Workaround versus fix
Some actions hide the symptom without fixing the cause: adding a hosts-file entry for the DC, raising the clock skew tolerance, accessing a share by IP address (which forces the weaker NTLM), removing and rejoining every broken PC to the domain, or restarting all DCs "to clear it". The real fix is the configuration that caused the problem: the DNS settings, the time source, the SPN on the right account, the snapshot practice, or the firewall rule.

:::practice
Q: A file share works by IP address (\`\\10.0.20.40\data\`) but not by name. Why is "use the IP address" a workaround, not a fix?
A: Access by IP address cannot use Kerberos, so Windows falls back to the weaker **NTLM**. The real problem (DNS, the SPN, Kerberos) is still there.
Q: Name the real fix for "logons fail on one VM after every snapshot restore" instead of rejoining it each time.
A: Fix the **practice**: avoid restoring old snapshots of domain members (or repair the secure channel with Test-ComputerSecureChannel -Repair) and make sure time sync comes from the domain hierarchy.
:::

`,

  errorMap: [
    { message: "We can't sign you in with this credential because your domain isn't available.", layer: 'DNS / DC locator', meaning: 'The client could not locate or reach any DC (it may still log on with cached credentials).', firstCheck: 'Get-DnsClientServerAddress; nltest /dsgetdc:corp.lab /force' },
    { message: 'The specified domain either does not exist or could not be contacted.', layer: 'DNS', meaning: 'Join or locator failed: no SRV records through the configured DNS servers.', firstCheck: 'Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.corp.lab' },
    { message: 'Getting DC name failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN', layer: 'DNS / DC locator', meaning: 'nltest found no DC for the domain.', firstCheck: 'DNS servers on the client; SRV records on the DC; firewall to UDP 389' },
    { message: 'KRB_AP_ERR_SKEW / There is a time and/or date difference between the client and server.', layer: 'Time', meaning: 'Clock offset larger than 5 minutes.', firstCheck: 'w32tm /query /source; w32tm /stripchart /computer:dc01 /samples:3 /dataonly' },
    { message: 'Security 4771, Failure Code 0x18', layer: 'Kerberos pre-authentication', meaning: 'Bad password (repeated failures can lock the account; look for a device with an old saved password).', firstCheck: 'Client Address in the event; Get-ADUser dana -Properties badPwdCount,LockedOut' },
    { message: 'KDC_ERR_S_PRINCIPAL_UNKNOWN (0x7) / Security 4769 Failure Code 0x7', layer: 'Kerberos SPN', meaning: 'No account owns the requested SPN; the client falls back to NTLM or fails.', firstCheck: 'setspn -Q <SPN>' },
    { message: 'KRB_AP_ERR_MODIFIED (System event 4, Security-Kerberos)', layer: 'Kerberos SPN / keys', meaning: 'The server could not decrypt the ticket: SPN on the wrong or duplicate account, or a stale machine password.', firstCheck: 'setspn -X; setspn -Q <SPN>; nltest /sc_verify on the server' },
    { message: 'The trust relationship between this workstation and the primary domain failed.', layer: 'Secure channel', meaning: 'Machine password differs between computer and AD.', firstCheck: 'nltest /sc_verify:corp.lab; Test-ComputerSecureChannel' },
    { message: 'NETLOGON 5719: This computer was not able to set up a secure session with a domain controller in domain CORP', layer: 'Secure channel / network', meaning: 'No DC reachable at boot (often the network was not ready yet) or the machine account is invalid.', firstCheck: 'nltest /sc_verify:corp.lab after boot; NIC driver/link timing' },
    { message: 'GroupPolicy 1058: Windows attempted to read the file \\\\corp.lab\\SysVol\\...\\gpt.ini ... and was not successful.', layer: 'SYSVOL / SMB / DFSR', meaning: 'Policy files unreachable or missing on the DC used.', firstCheck: 'dir \\\\corp.lab\\SYSVOL\\corp.lab\\Policies; DFS Replication log on the DCs' },
    { message: 'repadmin: (1722) The RPC server is unavailable.', layer: 'Replication network', meaning: 'Partner DC down, or RPC (135 + dynamic ports) blocked.', firstCheck: 'Test-NetConnection <partner> -Port 135; is the partner up?' },
    { message: 'repadmin: (8524) The DSA operation is unable to proceed because of a DNS lookup failure.', layer: 'Replication DNS', meaning: 'Partner\'s <GUID>._msdcs CNAME or A record cannot be resolved.', firstCheck: 'dcdiag /test:dns on both DCs; DNS client settings of the DCs' },
    { message: 'Directory Service 2042 / repadmin (8614) ... exceeded the tombstone lifetime', layer: 'Replication', meaning: 'A DC has been out of replication longer than 180 days.', firstCheck: 'Do not force replication; plan to demote and rebuild that DC' },
    { message: 'DNS Server 4013: The DNS server is waiting for Active Directory Domain Services (AD DS) to signal that the initial synchronization of the directory has been completed.', layer: 'DC boot', meaning: 'The DC is waiting for a replication partner, usually because its DNS points only at itself or all DCs restarted.', firstCheck: 'DC DNS client order; are other DCs up?' },
  ],

  scenarioIds: ['dom-member-dns', 'dom-dc-firewall', 'dom-trust-broken', 'dom-account-locked', 'dom-group-membership', 'krb-w32time-disabled', 'krb-dc-ntp-blocked', 'krb-dc-kdc-blocked', 'krb-kdc-stopped'],
  assessmentId: 'ad-kerberos',
  references: [
    { title: 'Microsoft Learn: Active Directory Domain Services overview', url: 'https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview' },
    { title: 'Microsoft Learn: How domain controllers are located in Windows (DC locator)', url: 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/how-domain-controllers-are-located' },
    { title: 'Microsoft Learn: Kerberos authentication overview', url: 'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview' },
    { title: 'RFC 4120: The Kerberos Network Authentication Service (V5)', url: 'https://www.rfc-editor.org/rfc/rfc4120' },
    { title: 'Microsoft Learn: Windows Time service tools and settings (w32tm)', url: 'https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings' },
    { title: 'Microsoft Learn: dcdiag', url: 'https://learn.microsoft.com/windows-server/administration/windows-commands/dcdiag' },
    { title: 'Microsoft Learn: Troubleshooting AD replication error 1722 and others', url: 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-1722-rpc-server-unavailable' },
    { title: 'Microsoft Learn: setspn', url: 'https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)' },
    { title: 'Microsoft Learn: Service overview and network port requirements for Windows', url: 'https://learn.microsoft.com/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements' },
    { title: 'Red Hat: Integrating RHEL systems directly with Windows Active Directory', url: 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/integrating_rhel_systems_directly_with_windows_active_directory/index' },
    { title: 'Ubuntu Server documentation: Join a simple domain with the realmd package', url: 'https://documentation.ubuntu.com/server/how-to/sssd/with-active-directory/' },
  ],
  guide: AD_KERBEROS_GUIDE,
  caseStudyIds: ['domain-login', 'rdp-after-change'],
  objectives: ['N10-009:1.4', 'N10-009:3.4', 'N10-009:4.1', 'N10-009:5.3', '200-301:4.2', '200-301:4.3', '200-301:5.8'],
};

// --- Assessment -------------------------------------------------------------------------

export const AD_KERBEROS_ASSESSMENT: Assessment = {
  id: 'ad-kerberos',
  title: 'Active Directory, DNS and Kerberos knowledge check',
  questions: [
    {
      id: 'ad-kerberos-q-dns-secondary',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'A Windows 11 client sometimes fails to apply Group Policy and sometimes cannot map drives; a reboot "fixes" it for a while. Which configuration best explains this?',
      exhibit: 'PS C:\\> Get-DnsClientServerAddress -AddressFamily IPv4\n\nInterfaceAlias  Interface Address ServerAddresses\n                Index     Family\n--------------  --------- ------- ---------------\nEthernet 2             14 IPv4    {10.0.20.5, 8.8.8.8}',
      options: [
        { text: 'The secondary DNS server 8.8.8.8 answers NXDOMAIN for corp.lab records whenever the client uses it', correct: true },
        { text: 'Two DNS servers are too few; add a third public resolver for redundancy', misconception: 'More public resolvers make it worse: every one of them returns NXDOMAIN for the AD zone.' },
        { text: '8.8.8.8 is only used when 10.0.20.5 is down, so it cannot be the cause', misconception: 'The Windows DNS client also moves to other servers when the first one is slow to answer, and caches negative answers. Mixed AD/public DNS causes intermittent failures.' },
        { text: 'Group Policy does not use DNS', misconception: 'Group Policy needs the DC locator (SRV records), LDAP and \\\\corp.lab\\SYSVOL, all found through DNS.' },
      ],
      concepts: ['ad.dns', 'dns.resolution'],
      explanation: 'Domain members must use only AD DNS servers; Internet names are resolved through forwarders on the DCs. A public secondary resolver produces exactly this intermittent pattern.',
    },
    {
      id: 'ad-kerberos-q-srv',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'Which DNS record name (type SRV) does the DC locator query to find any domain controller of `corp.lab`?',
      accept: ['_ldap._tcp.dc._msdcs.corp.lab', '_ldap._tcp.dc._msdcs.corp.lab.'],
      placeholder: '_service._proto....',
      concepts: ['ad.dns'],
      explanation: '`_ldap._tcp.dc._msdcs.<domain>` lists every DC (site-specific variants exist under `_sites`). Netlogon on each DC registers it; the list of records a DC should register is in netlogon.dns.',
    },
    {
      id: 'ad-kerberos-q-order',
      kind: 'order',
      level: 'intermediate',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'Put the steps of Dana\'s logon at WS07 and her first access to `\\\\fs01\\data` in order.',
      items: [
        'DNS SRV query for _ldap._tcp.dc._msdcs.corp.lab',
        'CLDAP ping to the DCs returned; the first to answer is used',
        'AS-REQ with an encrypted timestamp (pre-authentication)',
        'AS-REP containing a TGT for krbtgt/CORP.LAB',
        'TGS-REQ for the SPN cifs/fs01.corp.lab',
        'TGS-REP with a service ticket encrypted with fs01\'s key',
        'AP-REQ inside SMB session setup; fs01 decrypts the ticket',
      ],
      concepts: ['ad.dns', 'ad.kerberos'],
      explanation: 'Locate (DNS, then CLDAP), authenticate (AS exchange for a TGT), then request a service ticket per SPN (TGS exchange) and present it to the service (AP exchange). The file server never contacts the DC to validate a Kerberos ticket.',
    },
    {
      id: 'ad-kerberos-q-skew',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'Only one virtual desktop, restored from a snapshot yesterday, cannot authenticate. The DC logs this event for its logons. What do you fix?',
      exhibit: 'Event 4771, Microsoft-Windows-Security-Auditing\nKerberos pre-authentication failed.\nAccount Name:   dana\nService Name:   krbtgt/CORP.LAB\nClient Address: ::ffff:10.0.10.57\nFailure Code:   0x25\n\nPS C:\\> w32tm /query /source     (on the desktop)\nLocal CMOS Clock',
      options: [
        { text: 'Restore the domain time hierarchy on the desktop (w32tm /config /syncfromflags:domhier /update, then w32tm /resync)', correct: true },
        { text: 'Reset Dana\'s password', misconception: 'A bad password is failure code 0x18. 0x25 is KRB_AP_ERR_SKEW: clock skew too great.' },
        { text: 'Raise "Maximum tolerance for computer clock synchronization" to 60 minutes in the Default Domain Policy', misconception: 'That weakens replay protection for the whole domain and leaves the desktop drifting. Fix its time source.' },
        { text: 'Restart the Kdc service on all DCs', misconception: 'Every other client works, so the KDC is fine. Restarting DC services interrupts everyone and changes nothing about the desktop clock.' },
      ],
      concepts: ['ad.kerberos'],
      explanation: 'Failure code 0x25 is clock skew. "Local CMOS Clock" means the machine is not syncing from the domain hierarchy, typical after a snapshot restore or when hypervisor time sync and W32Time disagree.',
    },
    {
      id: 'ad-kerberos-q-dupspn',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'After the intranet application was moved to run as `CORP\\svc-web`, users get password prompts and the client System log shows KRB_AP_ERR_MODIFIED for HTTP/intranet.corp.lab. What is the correct fix?',
      exhibit: 'C:\\> setspn -X\nChecking domain DC=corp,DC=lab\nProcessing entry 7\nHTTP/intranet.corp.lab is registered on these accounts:\n        CN=svc-web,OU=Service Accounts,DC=corp,DC=lab\n        CN=APP01,OU=Servers,DC=corp,DC=lab\n\nfound 1 group of duplicate SPNs.',
      options: [
        { text: 'Remove the SPN from APP01 (setspn -D HTTP/intranet.corp.lab APP01), keep it on svc-web, then klist purge on clients', correct: true },
        { text: 'Remove the SPN from svc-web and keep it on APP01', misconception: 'The service now runs as svc-web, so tickets must be encrypted with svc-web\'s key. The SPN belongs on the account the service runs as.' },
        { text: 'Add the SPN a third time with setspn -A to force the right one', misconception: 'That creates another duplicate. setspn -S checks for duplicates; the fix is to have exactly one owner.' },
        { text: 'Repair the secure channel of APP01', misconception: 'The secure channel is not involved: the KDC encrypted the ticket for one of two accounts, and the service holds the other key.' },
      ],
      concepts: ['ad.kerberos'],
      explanation: 'With a duplicate SPN the KDC may encrypt the service ticket with the wrong account\'s key, so the service cannot decrypt it (KRB_AP_ERR_MODIFIED). One SPN, one account: the one the service runs as.',
    },
    {
      id: 'ad-kerberos-q-trust',
      kind: 'multi',
      level: 'intermediate',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'Users at WS12 see "The trust relationship between this workstation and the primary domain failed." Which actions are appropriate? (Select all that apply.)',
      options: [
        { text: 'Log on with a local administrator and run nltest /sc_verify:corp.lab to confirm', correct: true },
        { text: 'Run Test-ComputerSecureChannel -Repair -Credential CORP\\adm-alice in Windows PowerShell', correct: true },
        { text: 'Find out why the machine password diverged (snapshot restore? duplicate computer name?) so it does not recur', correct: true },
        { text: 'Restart Netlogon on every domain controller', misconception: 'The problem is this computer\'s password, stored on the client and in its AD object. DC services are healthy for every other machine.' },
        { text: 'Delete the computer object and let the PC recreate it automatically', misconception: 'Deleting the object loses group memberships and does not repair anything by itself; the PC would have to be rejoined. Resetting the password is the targeted fix.' },
      ],
      concepts: ['ad.kerberos', 'ops.recovery'],
      explanation: 'The secure channel uses a machine password stored on both sides. Test-ComputerSecureChannel -Repair (or Reset-ComputerMachinePassword) resets it on both sides without rejoining. Then fix the cause.',
    },
    {
      id: 'ad-kerberos-q-repl',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'A user created on dc01 an hour ago cannot log on at a branch PC that uses dc02. What does this output tell you to do first?',
      exhibit: 'C:\\> repadmin /replsummary\nSource DSA          largest delta    fails/total %%   error\n DC01                      01h:12m    5 /   5  100  (8524) The DSA operation is unable to proceed because of a DNS lookup failure.\n\nDestination DSA     largest delta    fails/total %%   error\n DC02                      01h:12m    5 /   5  100  (8524) The DSA operation is unable to proceed because of a DNS lookup failure.',
      options: [
        { text: 'Investigate why dc02 cannot resolve dc01 (dcdiag /test:dns on both, dc02\'s DNS client settings, dc01\'s _msdcs CNAME registration)', correct: true },
        { text: 'Seize all FSMO roles to dc02', misconception: 'Role seizure is for a DC that is permanently gone and does not fix replication. dc01 is alive; dc02 just cannot find it by name.' },
        { text: 'Restart NTDS on both DCs at the same time', misconception: 'That interrupts authentication everywhere and does not change DNS. Error 8524 names the cause: a DNS lookup failure.' },
        { text: 'Create the user again on dc02', misconception: 'That creates a conflicting object once replication resumes. Fix replication instead.' },
      ],
      concepts: ['ad.dns', 'ops.recovery'],
      explanation: 'Replication partners find each other through the `<DSA-GUID>._msdcs.corp.lab` CNAME. 8524 means that lookup failed: wrong DNS client settings on dc02, or dc01\'s records not registered (nltest /dsregdns on dc01).',
    },
    {
      id: 'ad-kerberos-q-gpo1058',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: '`gpupdate /force` on WS07 reports event 1058 for `\\\\corp.lab\\SysVol\\corp.lab\\Policies\\{6AC1786C-...}\\gpt.ini`. User logon and Kerberos work. Which component is most likely at fault?',
      options: [
        { text: 'The Kerberos KDC', misconception: 'Kerberos works (logon succeeds); 1030 would indicate the policy query itself failed.' },
        { text: 'SYSVOL access or SYSVOL replication (SMB 445 to the DC, DFSR state on the DC that answered)', correct: true },
        { text: 'W32Time', misconception: 'Time problems break Kerberos first, and logon works.' },
        { text: 'The client\'s DHCP lease', misconception: 'The client found the DC and authenticated; the failure is reading a file from SYSVOL.' },
      ],
      concepts: ['ad.gpo'],
      explanation: '1058 means the client could not read gpt.ini from SYSVOL: SMB blocked, DFS client issue, or the GPO folder missing on that DC because DFSR has not replicated it (check the DFS Replication log for 2213/4012).',
    },
    {
      id: 'ad-kerberos-q-restart',
      kind: 'multi',
      level: 'advanced',
      learn: ['lesson/ad-kerberos/internals', 'lesson/ad-kerberos/operate'],
      prompt: 'dc01\'s SRV records disappeared from DNS after a network change; dc02 is healthy. Which actions are appropriate and proportionate? (Select all that apply.)',
      options: [
        { text: 'Check repadmin /replsummary and dcdiag /test:dns before changing anything', correct: true },
        { text: 'Run nltest /dsregdns on dc01 to re-register the records listed in netlogon.dns', correct: true },
        { text: 'If registration still fails, Restart-Service Netlogon on dc01 only, after confirming dc02 serves clients', correct: true },
        { text: 'Reboot dc01 and dc02 together so they come back consistent', misconception: 'Rebooting all DCs at once removes every logon server and can cause the DNS 4013 boot wait. One DC at a time, only if needed.' },
        { text: 'Stop-Service NTDS -Force on dc01 to "reset AD"', misconception: 'Stopping NTDS also stops Kdc, DFSR and DNS on that DC and does nothing for DNS registration, which is Netlogon\'s job.' },
      ],
      concepts: ['ad.dns', 'win.services', 'ops.recovery'],
      explanation: 'Netlogon registers DC records. Start with the narrowest action (nltest /dsregdns), escalate to restarting Netlogon on that one DC, and check replication first so you know the other DC can carry the load.',
    },
    {
      id: 'ad-kerberos-q-pdc-time',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'Which machine in a single-domain forest should be configured to synchronise its time from external NTP servers?',
      options: [
        { text: 'Every DC', misconception: 'DCs follow the domain hierarchy (NT5DS) from the PDC emulator; independent external sources can make DCs disagree.' },
        { text: 'The DC holding the PDC emulator role', correct: true },
        { text: 'Every client, from pool.ntp.org', misconception: 'Clients must follow the domain hierarchy so they agree with the KDC; what matters for Kerberos is agreement within 5 minutes.' },
        { text: 'The DHCP server', misconception: 'The DHCP server role has nothing to do with the Windows time hierarchy.' },
      ],
      concepts: ['ad.kerberos'],
      explanation: 'The forest-root PDC emulator is the root of the W32Time hierarchy; configure it with w32tm /config /manualpeerlist:... /syncfromflags:manual /reliable:yes /update. Everything else uses NT5DS.',
    },
    {
      id: 'ad-kerberos-q-linux',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/ad-kerberos/internals'],
      prompt: 'On an Ubuntu 24.04 member, `kinit dana@corp.lab` fails with "Cannot find KDC for realm "corp.lab" while getting initial credentials". `kinit dana@CORP.LAB` works. Why?',
      options: [
        { text: 'Kerberos realm names are case-sensitive and AD realms are the upper-case DNS domain name', correct: true },
        { text: 'sssd is not running', misconception: 'kinit talks to the KDC directly using krb5.conf and DNS; the upper-case form works, so the KDC is reachable.' },
        { text: 'Port 88 is blocked', misconception: 'Then CORP.LAB would fail as well.' },
      ],
      concepts: ['ad.kerberos'],
      explanation: 'The realm of the AD domain corp.lab is CORP.LAB. The lower-case realm does not exist, so no KDC is found for it.',
    },
  ],
};
