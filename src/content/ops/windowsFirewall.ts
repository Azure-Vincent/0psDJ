// Windows Defender Firewall. Examples follow the lab: win01 (10.0.20.30) is a
// Windows Server 2022 member of the server VLAN running IIS, Remote Desktop,
// SMB and WinRM; ws01 (10.0.10.25) is the admin workstation and the
// monitoring host; dc01 (10.0.20.5) is the domain controller once the domain
// lessons are done. The sandbox and the tickets run there.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const WINDOWS_FIREWALL_GUIDE: ServiceGuide = {
  purpose:
    'Windows Defender Firewall is the host firewall built into every Windows version since Vista. It filters each packet a Windows machine receives or sends, using **profiles** (Domain, Private, Public, chosen by the network the adapter is on) and **rules** that match direction, protocol, ports, addresses and the program that owns the connection. It is stateful: replies to a connection that was allowed pass without a rule. On servers it is the last filter before the application, and the one that admins change most often.',
  architecture: [
    { q: 'What does it accomplish?', a: 'It lets in only the traffic a machine\'s roles need, so a service that should not be exposed (or a vulnerable one) cannot be reached from the network. Outbound filtering, when enabled, limits what a compromised server can connect to.' },
    { q: 'How does it work internally?', a: 'The firewall service (**MpsSvc**) reads the rules and profile settings from the local store and from Group Policy, and turns them into filters in the **Windows Filtering Platform** (WFP), managed by the **Base Filtering Engine** (BFE). WFP filters run in the kernel TCP/IP stack. For a new connection they are evaluated at the **ALE** (Application Layer Enforcement) layers, where Windows knows which process owns the socket: that is why a rule can match a program. Later packets of an allowed connection match its state and pass.' },
    { q: 'Which protocols does it use?', a: 'It filters IPv4 and IPv6 traffic (TCP, UDP, ICMP, ICMPv6 and other IP protocols). It does not talk on the network itself; management uses local APIs, or WinRM/RPC when you manage a remote machine, and Group Policy delivers rules from a domain controller (LDAP, SMB).' },
    { q: 'Which ports and transport?', a: 'None of its own. Rules name the ports of other services: 3389 (RDP), 445 (SMB), 5985/5986 (WinRM), 80/443 (IIS), 135 plus the dynamic RPC range 49152-65535 for RPC-based tools.' },
    { q: 'Which processes and OS components implement it?', a: 'MpsSvc (Windows Defender Firewall service, in svchost.exe), BFE (Base Filtering Engine, in svchost.exe), the WFP filter engine in the kernel (tcpip.sys), Network Location Awareness (NlaSvc, which decides each adapter\'s network category). Tools: wf.msc, the NetSecurity PowerShell module, netsh advfirewall.' },
    { q: 'Which other services does it depend on?', a: 'MpsSvc depends on BFE; both are protected services that cannot be stopped normally. The Domain profile depends on Network Location Awareness reaching a domain controller (DNS, LDAP). Rules from Group Policy depend on Group Policy processing (see the [Group Policy lesson](#/lesson/gpo/what)).' },
    { q: 'How do requests travel?', a: 'A SYN from ws01 to win01:80 arrives → WFP finds the active profile of the receiving adapter → if the profile is off, it passes; otherwise it looks for matching rules: any Block rule → drop; else any Allow rule → pass (and the connection is remembered); else the profile\'s default inbound action (Block). Replies and later packets of the connection pass because of the state. Outbound packets go through the same steps with the outbound rules and the default outbound action (Allow by default).' },
    { q: 'How do authentication and authorisation work?', a: 'The firewall does not authenticate users. Changing it needs administrator rights; reading most settings does not. Rules can be scoped to remote addresses and, with IPsec, to authenticated computers and users (not covered here). Rules from Group Policy cannot be changed locally.' },
    { q: 'How does it start at boot?', a: 'BFE and MpsSvc start early (Automatic). Until MpsSvc has loaded the policy, WFP applies a boot-time policy that blocks unsolicited inbound traffic. Then the profile of each adapter is chosen (a domain member waits for Network Location Awareness to find a DC), and Group Policy rules arrive at computer policy processing.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'The filters already in WFP stay in place, and the service is restarted by the Service Control Manager. Stopping MpsSvc is not a supported way to "turn off" the firewall: turn off a profile (and expect it to be logged) or, better, fix the rule.' },
  ],
  ports: [
    { port: '(none)', proto: '-', purpose: 'The firewall has no port of its own: rules name the ports of the services they protect' },
    { port: '3389', proto: 'TCP/UDP', purpose: 'Remote Desktop (built-in group "Remote Desktop")' },
    { port: '445', proto: 'TCP', purpose: 'SMB (built-in "File and Printer Sharing (SMB-In)")' },
    { port: '5985 / 5986', proto: 'TCP', purpose: 'WinRM HTTP / HTTPS (built-in "Windows Remote Management")' },
    { port: '80 / 443', proto: 'TCP', purpose: 'IIS (built-in "World Wide Web Services"), received by http.sys (process System)' },
  ],
  processes: [
    { name: 'MpsSvc (Windows Defender Firewall)', platform: 'Windows (svchost.exe)', role: 'Reads local and Group Policy settings, keeps the WFP filters in sync, writes pfirewall.log and the Firewall event log' },
    { name: 'BFE (Base Filtering Engine)', platform: 'Windows (svchost.exe)', role: 'Manages the WFP filters that MpsSvc (and IPsec, and third-party products) add' },
    { name: 'WFP filter engine', platform: 'Windows kernel (tcpip.sys)', role: 'Evaluates each packet and new connection against the filters' },
    { name: 'NlaSvc (Network Location Awareness)', platform: 'Windows (svchost.exe)', role: 'Identifies each network and sets its category: DomainAuthenticated, Private or Public' },
    { name: 'wf.msc, NetSecurity module, netsh advfirewall', platform: 'Windows', role: 'Management: GUI, PowerShell (Get-NetFirewallRule ...), legacy command line' },
  ],
  dependencies: {
    title: 'What "ws01 reaches the intranet site on win01" needs from the firewall (top needs everything below it)',
    caption: 'Each layer can drop the connection on its own; the log and the rule filters show which one did.',
    rows: [
      { label: 'Application', nodes: [{ id: 'iis', label: 'IIS site', sub: 'http.sys, process System', kind: 'service' }] },
      { label: 'Rule', nodes: [{ id: 'allow', label: 'Allow rule matches', sub: 'port, address, program', kind: 'data' }, { id: 'noblock', label: 'No Block rule matches', sub: 'Block beats Allow', kind: 'data' }] },
      { label: 'Rule set', nodes: [{ id: 'merge', label: 'Local + Group Policy rules', sub: 'AllowLocalFirewallRules', kind: 'data' }] },
      { label: 'Profile', nodes: [{ id: 'profile', label: 'Active profile', sub: 'category of Ethernet0', kind: 'os' }, { id: 'state', label: 'Profile on, default Block', sub: 'Get-NetFirewallProfile', kind: 'os' }] },
      { label: 'Engine', nodes: [{ id: 'mps', label: 'MpsSvc + BFE', sub: 'WFP filters', kind: 'service' }] },
    ],
    edges: [['iis', 'allow'], ['iis', 'noblock'], ['allow', 'merge'], ['noblock', 'merge'], ['merge', 'profile'], ['merge', 'state'], ['profile', 'mps'], ['state', 'mps']],
  },
  sequence: {
    title: 'ws01 opens http://win01/: how win01\'s firewall decides',
    caption: 'One new TCP connection; where each ticket stops it is noted.',
    lanes: [{ id: 'c', label: 'ws01', sub: '10.0.10.25' }, { id: 'f', label: 'win01 firewall', sub: 'WFP, active profile' }, { id: 's', label: 'IIS', sub: 'http.sys (System)' }],
    steps: [
      { from: 'c', to: 'f', label: 'SYN 10.0.10.25:51544 → 10.0.20.30:80', note: 'Profile chosen from the adapter (Private here; Domain on a domain network).' },
      { from: 'f', to: 'f', label: 'Block rules: any match? → DROP', note: 'A Block rule for port 80 from any address wins over every Allow rule (wfw-block-precedence).', fail: true },
      { from: 'f', to: 'f', label: 'Allow rules: every condition must match', note: 'Wrong Program (wfw-program-mismatch), RemoteAddress without 10.0.10.25 (wfw-remote-scope), local rules switched off by policy (wfw-local-rules-ignored): no match.' },
      { from: 'f', to: 'f', label: 'No match: default inbound action (Block) → DROP, logged if LogBlocked', fail: true },
      { from: 'f', to: 's', label: 'Allowed: SYN delivered; the connection is remembered' },
      { from: 's', to: 'c', label: 'SYN-ACK and the HTTP response pass as replies (state), even with outbound Block' },
    ],
  },
  files: [
    { path: '%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log', platform: 'Windows', kind: 'log', perms: 'Written by NT SERVICE\\mpssvc; Administrators read', contains: 'One line per dropped packet (LogBlocked) and per allowed connection (LogAllowed): date, time, action, protocol, addresses, ports, size, TCP flags, ICMP type, path (RECEIVE or SEND).', accessed: 'Appended by MpsSvc when logging is on for the active profile; renamed to pfirewall.log.old at LogMaxSizeKilobytes (4096 by default).', problems: 'Off by default. Logging is per profile: turn it on for the one in force (or all). A custom path needs write permission for NT SERVICE\\mpssvc.' },
    { path: 'Event log: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', platform: 'Windows', kind: 'eventlog', contains: 'Rule added (2004), modified (2005), deleted (2006), profile setting changed (2003) in the lab; the ids differ between Windows builds, the messages do not.', accessed: 'Written by MpsSvc at every change.', problems: 'Records changes, not dropped packets: use pfirewall.log (or the Security log\'s Filtering Platform audit events 5152/5157 when that auditing is enabled) for drops.' },
    { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy', platform: 'Windows', kind: 'registry', contains: 'The local store (PersistentStore): profile settings and FirewallRules as encoded strings.', accessed: 'Read by MpsSvc at start and when the store changes.', problems: 'Do not edit it by hand: use the cmdlets, wf.msc or netsh, which validate and apply at once.' },
    { path: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall', platform: 'Windows (domain members)', kind: 'registry', contains: 'Settings and rules delivered by Group Policy (the RSOP store).', accessed: 'Written at each Group Policy processing.', problems: 'Local changes cannot override it; a GPO that stops applying removes its rules at the next processing.' },
  ],
  management: [
    {
      platform: 'The server itself (NetSecurity module)',
      tasks: [
        { task: 'Which profile is in force?', command: 'Get-NetConnectionProfile\nGet-NetFirewallProfile -PolicyStore ActiveStore | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked', explain: 'The adapter\'s network category picks the profile; ActiveStore shows the settings in force, including Group Policy.', sim: true },
        { task: 'Rules that are on, by direction', command: 'Get-NetFirewallRule -Enabled True -Direction Inbound | Format-Table DisplayName, Profile, Action', explain: 'Enabled rules only; add -Action Block to find the rules that win.', sim: true },
        { task: 'Every condition of one rule', command: 'Get-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP | Get-NetFirewallPortFilter\nGet-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP | Get-NetFirewallAddressFilter\nGet-NetFirewallRule -Name IIS-WebServerRole-HTTP-In-TCP | Get-NetFirewallApplicationFilter', explain: 'Ports, addresses and program live in separate filter objects: a rule that "looks right" in the main view can still not match.', sim: true },
        { task: 'Create a scoped rule', command: 'New-NetFirewallRule -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.10.0/24 -Action Allow', explain: 'Allow exactly the traffic needed, from exactly the senders that need it.', sim: true },
        { task: 'Change a rule', command: 'Set-NetFirewallRule -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -RemoteAddress 10.0.10.25', explain: 'Changes take effect at once and are logged in the Firewall event log.', sim: true },
        { task: 'Log dropped packets', command: 'Set-NetFirewallProfile -All -LogBlocked True\nGet-Content C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log -Tail 20', explain: 'The proof that the host firewall dropped something, with the real source address and port.', sim: true },
        { task: 'Which process owns a port?', command: 'Get-NetTCPConnection -LocalPort 80 -State Listen\nnetstat -ano | findstr :80', explain: 'OwningProcess 4 is System: kernel listeners such as http.sys (IIS, WinRM) and SMB.', sim: true },
        { task: 'Legacy command line', command: 'netsh advfirewall show currentprofile\nnetsh advfirewall set allprofiles logging droppedconnections enable\nnetsh advfirewall firewall show rule name="World Wide Web Services (HTTP Traffic-In)"', explain: 'Still common in scripts and older documentation.', sim: true },
      ],
    },
    {
      platform: 'Domain controller / management host (Group Policy)',
      tasks: [
        { task: 'Rules in a GPO', command: 'Get-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Firewall" | Format-Table DisplayName, Enabled, Action', explain: 'What the GPO will deliver to every computer in its scope.', sim: true },
        { task: 'Add a rule to a GPO', command: 'New-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Firewall" -DisplayName "Web (HTTP-In)" -Protocol TCP -LocalPort 80 -Action Allow -Profile Domain', explain: 'Members get it at their next policy processing (gpupdate /force to test).', sim: true },
        { task: 'Profile settings in a GPO', command: 'Set-NetFirewallProfile -PolicyStore "ad.corp.lab\\Server Firewall" -Profile Domain -Enabled True -DefaultInboundAction Block -AllowLocalFirewallRules False -LogBlocked True', explain: 'Policy settings override the local ones; AllowLocalFirewallRules False makes only GPO rules count.', sim: true },
      ],
    },
  ],
  actions: [
    { action: 'Change one rule (Set-/Enable-/Disable-NetFirewallRule)', when: 'Almost always: the fix for a firewall ticket is one rule.', effect: 'Immediate; existing connections that are already allowed keep working.', risk: 'Changing the rule that carries your own session (RDP, WinRM) can cut you off: keep a console or a second path.' },
    { action: 'Set-NetFirewallProfile -LogBlocked True', when: 'To prove a drop, during a change, or permanently on servers (with a size limit).', effect: 'Drops are written to pfirewall.log from now on.', risk: 'LogAllowed on a busy server fills the file quickly; keep it short.' },
    { action: 'Turn a profile off (Set-NetFirewallProfile -Enabled False)', when: 'Never as a fix. At most for seconds, to test whether the firewall is involved at all, with someone watching.', effect: 'Every port of every service is reachable on that network.', risk: 'It hides the real cause and is easily forgotten; most security baselines alert on it.' },
    { action: 'Restart MpsSvc', when: 'Practically never: it is protected and its filters stay in place anyway.', effect: 'Reloads policy.', risk: 'None useful; fix the policy instead.' },
  ],
  workflow: [
    { question: 'Timeout or refused?', why: 'A dropped packet makes the client wait (timeout); a packet that reaches a port where nothing listens is refused at once. Only a timeout points at a firewall.', command: 'nc -zv -w 3 win01 80   (from ws01)\nTest-NetConnection win01 -Port 80   (from Windows)', healthy: 'succeeded / TcpTestSucceeded : True', broken: 'Timed out: dropped (this firewall, a network firewall, routing). Refused: the firewall let it through and nothing listens: look at the service, not the firewall.', next: 'On a timeout, check the server side.', sim: true },
    { question: 'Is the service listening, and which process owns the port?', why: 'A rule can only let traffic reach a socket that exists; and a Program condition compares against the owner of that socket.', command: 'Get-NetTCPConnection -LocalPort 80 -State Listen', healthy: 'A Listen entry; OwningProcess (4 = System for http.sys).', broken: 'Nothing listens: a service problem (refused, not a timeout).', next: 'If it listens, find the profile in force.', sim: true },
    { question: 'Which profile is in force, with which settings?', why: 'Only rules for the active profile count, and the profile\'s default action decides when no rule matches.', command: 'Get-NetConnectionProfile\nGet-NetFirewallProfile -PolicyStore ActiveStore', healthy: 'The expected category; Enabled True, DefaultInboundAction Block.', broken: 'Public on a trusted network (the Private/Domain rules do not count); AllowLocalFirewallRules False (local rules do not count).', next: 'Then find the rules that should match.', sim: true },
    { question: 'Which rules match this packet, and does a Block rule match?', why: 'A rule matches only when every condition matches; any matching Block rule wins.', command: 'Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block\nGet-NetFirewallRule -DisplayName "..." | Get-NetFirewallPortFilter / Get-NetFirewallAddressFilter / Get-NetFirewallApplicationFilter', healthy: 'An Allow rule whose port, address, program and profile all match; no matching Block rule.', broken: 'A condition that does not match the real packet (address, program, profile), or a Block rule that matches it.', next: 'Prove it with the log.', sim: true },
    { question: 'What does the firewall log say?', why: 'pfirewall.log shows the real packet: source address, port, and direction. It settles every "but the rule is right" discussion.', command: 'Set-NetFirewallProfile -All -LogBlocked True\nGet-Content C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log -Tail 20', healthy: 'No DROP lines for the traffic in question.', broken: 'DROP ... RECEIVE: dropped inbound by this host. DROP ... SEND: the host dropped its own outbound packet (outbound filtering).', next: 'Fix the one rule (or add the missing one), test from the client, and turn verbose logging back off.', sim: true },
  ],
  failures: [
    { symptom: 'Timeout to one port; the service listens; the allow rule "is right there"', causes: ['A condition of the rule does not match the packet: RemoteAddress, Program, Profile', 'A Block rule matches the same traffic', 'Group Policy turned off local rules (AllowLocalFirewallRules False)'], diagnose: ['pfirewall.log with LogBlocked on', 'Get-NetFirewallRule ... | Get-NetFirewall*Filter', 'Get-NetFirewallRule -Action Block -Enabled True', 'Get-NetFirewallProfile -PolicyStore ActiveStore'], fix: 'Correct the condition, scope or remove the Block rule, or put the rule in the GPO.', verify: 'Test from the client; no new DROP lines.' },
    { symptom: 'The server cannot connect out; everything inbound works', causes: ['DefaultOutboundAction Block with no outbound rule for that destination/port'], diagnose: ['Get-NetFirewallProfile', 'Get-NetFirewallRule -Direction Outbound -Enabled True | Get-NetFirewallPortFilter', 'pfirewall.log DROP ... SEND'], fix: 'Add the outbound rule the role needs, scoped to the destination.', verify: 'Test-NetConnection dest -Port n' },
    { symptom: 'Works from one network, not from another', causes: ['RemoteAddress scope (LocalSubnet, a prefix) excludes the second network', 'Rule limited to a profile that is not active on that adapter'], diagnose: ['Get-NetFirewallAddressFilter', 'Get-NetConnectionProfile'], fix: 'Widen the scope to the network that needs it (not to Any).', verify: 'Test from both networks.' },
  ],
  verification: [
    { check: 'Firewall on, inbound blocked by default', command: 'Get-NetFirewallProfile -PolicyStore ActiveStore | Format-Table Name, Enabled, DefaultInboundAction', expect: 'True / Block for Domain, Private, Public' },
    { check: 'The service is reachable from its clients', command: 'nc -zv -w 3 win01 80 (from ws01)', expect: 'succeeded' },
    { check: 'Nothing else opened', command: 'Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Get-NetFirewallAddressFilter', expect: 'Every allow rule scoped as intended' },
    { check: 'Survives restart', command: 'Restart-Computer, then test again', expect: 'Same result' },
  ],
  refIds: ['get-netfirewallrule', 'get-netfirewallprofile', 'file:windows-firewall-log', 'proc:windows-firewall-drop', 'gpupdate', 'netsh-advfirewall'],
};

// --- Lesson -------------------------------------------------------------------------

export const WINDOWS_FIREWALL_LESSON: Lesson = {
  id: 'windows-firewall',
  moduleId: 'D',
  title: 'Windows Defender Firewall',
  level: 'intermediate',
  summary: 'How the Windows host firewall decides: network profiles, rule conditions (ports, addresses, program), Block over Allow, the default actions in both directions, the firewall log, and rules and settings from Group Policy; diagnosed and fixed on win01 from its PowerShell console.',
  concepts: ['win.firewall', 'fw.stateful', 'ad.gpo'],

  what: `
**Windows Defender Firewall** is the firewall built into Windows. It runs on every Windows machine, servers included, and decides for each packet the machine receives or sends whether it may pass. It does the same job as [nftables](#/lesson/nftables/what) on a Linux server: it protects this one machine, not a whole network (that is the job of a perimeter firewall such as [pfSense](#/lesson/pfsense/what)).

Out of the box it **blocks every incoming connection** that no rule allows, and **allows every outgoing connection**. Installing a role (IIS, File Server, Remote Desktop) adds and enables the rules that role needs. Most firewall tickets are about one of those rules: a rule that is off, that matches less than it seems to, that is beaten by another rule, or that does not count at all.

### Problems it solves
- **Exposure**: a server offers many services (RPC, SMB, WinRM, management agents). The firewall lets the network reach only the ones its role needs, from the clients that need them.
- **Untrusted networks**: a laptop or server on an unknown network (the Public profile) closes almost everything automatically.
- **Containment**: outbound filtering limits what a compromised server can connect to.

### The pieces
- **Profiles**: Domain, Private and Public. Each network adapter is in one of them, chosen by the network it is connected to. Each profile has its own on/off switch, default actions and logging.
- **Rules**: inbound or outbound, Allow or Block, with **conditions** (protocol, local port, remote address, program, profile). A rule acts on a packet only when all its conditions match.
- **Default actions**: what happens when no rule matches: Block inbound, Allow outbound.
- **The log** (pfirewall.log): which packets were dropped (and, if you ask, which connections were allowed). Off by default.
- **Group Policy**: in a domain, rules and settings can come from GPOs, and can switch local rules off altogether.

:::practice
Q: A new Windows Server has IIS installed and nothing else changed. A client connects to port 80 and to port 8080 (where a test application listens). What happens to each, and why?
A: **Port 80 works**: installing IIS enabled its built-in allow rule. **Port 8080 times out**: no rule allows it, so the default inbound action (Block) drops the SYN.
Q: Which piece decides what happens to a packet that no rule matches?
A: The **default action** of the active profile: Block for inbound, Allow for outbound unless someone changed it.
:::

### In the lab
> **win01** (10.0.20.30) is a Windows Server 2022 member of the server VLAN with IIS, Remote Desktop, SMB and WinRM, in a workgroup; its adapter Ethernet0 is in the **Private** profile. **ws01** (10.0.10.25) is the admin workstation and the monitoring host. The tickets run on win01's PowerShell console; one of them uses **dc01** (10.0.20.5) and Group Policy. Simulated: profiles and network categories, rules with protocol, local and remote ports, remote and local addresses (IPv4 addresses, prefixes and LocalSubnet), ICMP types, program (owner of the listening socket), Block over Allow, default actions in both directions, pfirewall.log (LogBlocked, LogAllowed), the Firewall event log, -PolicyStore (PersistentStore, ActiveStore, RSOP, a GPO), AllowLocalFirewallRules from Group Policy, netsh advfirewall. Not simulated: IPsec and connection security rules, edge traversal, service-name conditions, interface-type conditions, wf.msc.

`,

  internals: `
### 1. Profiles: which rules count on this network
Windows gives every network adapter a **network category**, and the category selects the firewall **profile**:
| Category | Profile | When |
|---|---|---|
| DomainAuthenticated | **Domain** | The machine is joined to a domain and can reach one of its domain controllers on this adapter |
| Private | **Private** | An administrator (or the user, on a client) marked the network as trusted |
| Public | **Public** | Every other network: the default for a network Windows has not seen before |

Each profile has its own switch (Enabled), default inbound and outbound actions, and logging. Each rule lists the profiles it applies to (or Any). A rule that is enabled only for Domain and Private **does nothing** while the adapter is in Public.

Network Location Awareness re-evaluates the category when the network changes: a new switch port, a new VLAN or a DC that cannot be reached at boot can move a server into a different profile. \`Get-NetConnectionProfile\` shows the category; \`Set-NetConnectionProfile -NetworkCategory Private\` changes it (Domain cannot be set by hand: it is earned by reaching a DC).

:::practice
Q: win01 is in a workgroup and its adapter shows NetworkCategory Private. A rule is enabled with Profile Domain. Does it apply?
A: **No.** The active profile is Private; a rule applies only in the profiles it lists. A workgroup machine never has the Domain profile.
Q: A domain member boots while its DC is down. Its adapter was Domain yesterday. Which profile does it get, and what changes for rules scoped to Domain?
A: It cannot authenticate to a DC, so it gets **Private or Public** (the category of that network). Rules scoped to Domain only stop applying until the DC is reachable again.
:::

### 2. A rule matches only when every condition matches
A rule has a direction and an action, and up to these conditions:
| Condition | Matches | Typical values |
|---|---|---|
| Profile | the active profile | Any, Domain, Private, Public |
| Protocol | the IP protocol | TCP, UDP, ICMPv4, ICMPv6, Any |
| LocalPort | this machine's port (the destination of inbound packets) | 80, 3389, 49152-65535, RPC |
| RemotePort | the other side's port (the destination of outbound packets) | 53, 445 |
| RemoteAddress | the other side's address | Any, 10.0.10.0/24, 10.0.10.25, LocalSubnet |
| LocalAddress | which of this machine's addresses | Any, 10.0.20.30 |
| Program | the process that owns the socket | %SystemRoot%\\system32\\svchost.exe, System |
| IcmpType | ICMP type (and code) | 8 (echo request), 3:4 (fragmentation needed) |

The conditions are combined with AND: **one** condition that does not match the real packet and the rule is skipped, however right the others are. Disabled rules (Enabled False) are skipped entirely.

\`Get-NetFirewallRule\` shows name, direction, action, enabled and profile. The other conditions live in separate **filter** objects: pipe the rule into \`Get-NetFirewallPortFilter\` (protocol, ports, ICMP type), \`Get-NetFirewallAddressFilter\` (addresses) and \`Get-NetFirewallApplicationFilter\` (program).

**LocalSubnet** means "the networks of this machine's own adapters". On win01 that is 10.0.20.0/24, so a rule scoped to LocalSubnet does **not** match ws01 (10.0.10.25): ws01 is on another subnet behind a router.

:::practice
Q: A rule allows TCP LocalPort 5985 with RemoteAddress LocalSubnet. win01 is 10.0.20.30/24. Which of these clients can connect: 10.0.20.10, 10.0.10.25, 10.0.20.200?
A: **10.0.20.10 and 10.0.20.200** (both in 10.0.20.0/24, win01's own subnet). 10.0.10.25 is on another subnet, so the RemoteAddress condition does not match.
Q: A rule shows Enabled True, Action Allow, Profile Any, and Get-NetFirewallPortFilter shows TCP 8443. Clients still time out on 8443. Which two filters do you look at next?
A: **Get-NetFirewallAddressFilter** (is the client's address in RemoteAddress? is LocalAddress right?) and **Get-NetFirewallApplicationFilter** (does the program own the socket?).
:::

### 3. The program condition is the owner of the socket
For a new connection, the firewall knows which process owns the socket the packet is going to (inbound) or coming from (outbound). A rule with a **Program** matches only that process's sockets. This is how a rule can say "allow port 8080, but only for this application".

The process that owns a listening socket is not always the one you think:
- **http.sys**, the kernel HTTP listener used by IIS and WinRM, owns ports 80/443 and 5985/5986. Windows shows it as the process **System** (PID 4). The IIS worker process **w3wp.exe** never owns the socket: http.sys passes it the requests.
- **SMB** (port 445) is also in the kernel: System.
- Services hosted in **svchost.exe** (Remote Desktop, for example) have svchost.exe as their program; real Windows rules add a **Service** condition to tell them apart.

Find the owner with \`Get-NetTCPConnection -LocalPort 80 -State Listen\` (OwningProcess) or \`netstat -ano\`, then compare with the rule's program.

:::practice
Q: Get-NetTCPConnection -LocalPort 5985 -State Listen shows OwningProcess 4. A rule allows TCP 5985 for Program C:\\Windows\\System32\\svchost.exe. Does WinRM get through?
A: **No.** PID 4 is System (http.sys owns 5985). The rule names svchost.exe, so its program condition does not match. Program **System** (or no program) would.
Q: Why is a program condition stronger than a port alone?
A: A port-only rule lets **any** process that listens on that port receive traffic. With a program, a second application that grabs the port (or malware) is not reachable through the rule.
:::

### 4. Block beats Allow; there is no rule order
Unlike a router ACL, a pfSense rule list or an nftables chain, Windows Defender Firewall has **no rule order**. For each packet it collects all matching rules and decides by **action**:
1. Allow rules marked "override block rules" (authenticated bypass, IPsec only: rare).
2. **Block** rules: if any matches, the packet is dropped.
3. **Allow** rules: if any matches, the packet passes.
4. Otherwise the profile's **default action**.

So "allow the internal networks first, then block everyone" does not work on Windows: the Block rule matches the internal networks too, and wins. The Windows way is an **allow list**: default inbound Block, Allow rules scoped by RemoteAddress, and Block rules only for a narrow exception (for example one known-bad address inside an allowed range).

:::practice
Q: Two enabled rules: Allow TCP 445 from 10.0.0.0/8, and Block TCP 445 from 10.0.99.0/24. Client 10.0.99.5 connects to port 445. What happens? And client 10.0.10.25?
A: **10.0.99.5 is dropped**: both rules match and Block wins. **10.0.10.25 gets through**: only the Allow rule matches it.
Q: You want RDP from 10.0.0.0/16 only. Which rules do you need, given the default inbound action is Block?
A: **One Allow rule** for TCP 3389 with RemoteAddress 10.0.0.0/16. No Block rule is needed: the default action already drops everyone else.
:::

### 5. Default actions, state, and outbound filtering
When no rule matches, the profile's **default action** applies: \`DefaultInboundAction\` (Block) and \`DefaultOutboundAction\` (Allow). The firewall is **stateful**: once a connection is allowed in one direction, its replies pass in the other without a rule. With outbound Block, a server still answers the connections clients make to it; what stops working is every connection the **server itself** starts (to DNS, a file share, an update server, a DC) unless an outbound rule allows it.

Outbound filtering is an **allow list for the server's own connections**: inventory them first (\`LogAllowed\` for a few days helps), then add one outbound rule per destination, usually scoped with RemotePort and RemoteAddress. Real Windows ships Core Networking outbound rules (DNS, DHCP, ...) that the lab does not model.

Loopback traffic (the machine talking to itself) is not filtered: a site that loads on the server itself proves nothing about the firewall.

:::practice
Q: DefaultOutboundAction is Block and there is no outbound rule for port 80. Clients browse to IIS on this server. Does the HTTP response reach them?
A: **Yes.** The response is a reply on a connection the inbound rule allowed; the firewall is stateful. Only connections the server starts are blocked.
Q: With DefaultOutboundAction Block, which outbound rule lets win01 map a share on fs01 (10.0.20.60), and why scope it?
A: Outbound, TCP, **RemotePort 445**, **RemoteAddress 10.0.20.60**, Allow. Scoped to the file server so the exception does not open SMB to every address (a classic path for data theft and worms).
:::

### 6. The firewall log: pfirewall.log
With \`LogBlocked True\` on a profile, every packet that profile drops is written to \`C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log\`; with \`LogAllowed True\`, every allowed new connection too. Logging is **per profile** and **off by default**. The file starts with a header naming the fields:
\`\`\`
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
2026-10-21 09:31:07 DROP TCP 10.0.10.25 10.0.20.30 51544 80 52 S 1874625310 0 64240 - - - RECEIVE
2026-10-21 09:31:20 DROP ICMP 10.0.10.25 10.0.20.30 - - 84 - - - - 8 0 - RECEIVE
2026-10-21 09:32:02 DROP TCP 10.0.20.30 10.0.20.60 50113 445 52 S 2208815544 0 64240 - - - SEND
\`\`\`
Read a line from left to right: **when**, **what** (DROP or ALLOW), **protocol**, **from where to where** (source then destination address, then ports), and **path**: RECEIVE is a packet arriving at this machine (inbound), SEND a packet this machine was sending (outbound). Line 1: ws01 tried to open port 80 (flags S = SYN, a new connection) and was dropped on arrival. Line 2: an echo request (ICMP type 8) from ws01, dropped. Line 3: win01 itself tried to reach SMB on fs01 and its own outbound filter dropped it.

The log is the evidence that settles "the rule is right": it shows the **real** source address and port of the packet that was dropped. The Firewall event log, by contrast, records **changes** to rules and settings (who changed what, when), not packets.

:::practice
Q: Read this line: \`DROP UDP 10.0.10.25 10.0.20.30 41000 161 78 - - - - - - - RECEIVE\`. What was dropped, and where do you look next?
A: An **inbound** UDP packet from 10.0.10.25 to win01 **port 161** (SNMP). Look for a rule allowing UDP 161 and check its address filter, or confirm with the owner that SNMP should be allowed at all.
Q: The log shows nothing at all although clients time out. Name two reasons.
A: Logging is off for the **active profile** (it is per profile), or the packets are dropped **before** win01: by a network firewall or a router (the host log only shows what this host drops).
:::

### 7. Where rules come from: local stores and Group Policy
Rules and profile settings live in **stores**; \`-PolicyStore\` picks one:
| Store | Contains |
|---|---|
| **PersistentStore** | The local rules and settings (what New-NetFirewallRule writes by default) |
| **RSOP** | What Group Policy delivered (read-only on the member) |
| **ActiveStore** | What is **in force**: the local store merged with policy |
| "ad.corp.lab\\GPO name" | The rules and settings inside one GPO (edited on a DC or management host) |

When policy and the local store set the same profile setting, **policy wins**. A GPO can also set **AllowLocalFirewallRules False** (in the GPO editor: "Apply local firewall rules: No"): then **only** rules from Group Policy are enforced, and every local rule, however correct and enabled, is ignored. The local store does not show that switch (\`Get-NetFirewallProfile\` without a store says NotConfigured); \`-PolicyStore ActiveStore\` does.

Rules from a GPO arrive at the member's next policy processing (startup, every ~90 minutes, \`gpupdate /force\`) and disappear when the GPO stops applying. See the [Group Policy lesson](#/lesson/gpo/internals) for scope and filtering.

:::practice
Q: On a domain member, Get-NetFirewallRule shows a local Allow rule for TCP 8080, enabled, profile Any. Clients time out on 8080, and the same rule works on a workgroup server. Which command shows whether local rules count here?
A: \`Get-NetFirewallProfile -PolicyStore ActiveStore\`: look for **AllowLocalFirewallRules False** (set by a GPO). Then only GPO rules count, so the rule belongs in the GPO.
Q: A GPO sets DefaultInboundAction Block for the Domain profile; an admin sets Allow locally. Which value is in force?
A: **Block.** When policy configures a setting, it overrides the local value.
:::

`,

  deployment: [
    {
      id: 'windows',
      platform: 'Windows Server 2022 (NetSecurity module)',
      summary: 'Baseline a server\'s firewall: check the profile, turn on drop logging, replace broad rules with scoped ones, and verify from a client. Steps marked simulated work in the sandbox on win01.',
      prerequisites: ['Console or hypervisor access to the server (a firewall mistake can cut off RDP).', 'The list of services the role needs and who uses them (ports and client networks).'],
      steps: [
        { title: 'Check the profile and the defaults', command: 'Get-NetConnectionProfile\nGet-NetFirewallProfile -PolicyStore ActiveStore | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction', what: 'The network category of each adapter and the settings in force.', why: 'Rules only count in their profiles; the defaults decide everything else.', expected: 'Name    Enabled DefaultInboundAction DefaultOutboundAction\n----    ------- -------------------- ---------------------\nDomain     True                Block                 Allow\nPrivate    True                Block                 Allow\nPublic     True                Block                 Allow', simulated: true },
        { title: 'Turn on drop logging', command: 'Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384', what: 'Dropped packets go to pfirewall.log, up to 16 MB before it rolls over.', why: 'Without the log you cannot prove what the firewall dropped.', expected: '', simulated: true },
        { title: 'List what is open', command: 'Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Format-Table DisplayName, Profile\nGet-NetTCPConnection -State Listen', what: 'Compare enabled allow rules with what actually listens.', why: 'Rules for roles that are not used, and listeners nobody knew about, both show up here.', expected: '', simulated: true },
        { title: 'Scope a rule to its clients', command: 'Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress 10.0.0.0/16\nNew-NetFirewallRule -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.10.0/24 -Action Allow', what: 'RDP from the internal networks only; ping from the monitoring network only.', why: 'An allow rule should name who needs the service, not Any.', expected: '', simulated: true },
        { title: 'Verify from a client, then check the log', command: 'nc -zv -w 3 win01 3389   (on ws01)\nGet-Content C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log -Tail 10', what: 'Test the real path; look for unexpected DROP lines.', why: 'Tests on the server itself go through loopback, which is never filtered.', expected: 'Connection to win01 (10.0.20.30) 3389 port [tcp/ms-wbt-server] succeeded!', simulated: true },
      ],
    },
    {
      id: 'gpo',
      platform: 'Active Directory (Group Policy)',
      summary: 'Manage server firewalls centrally: a GPO with the rules every server needs, profile settings, and (optionally) local rules switched off. Steps marked simulated work on dc01 after the domain lessons\' setup (win01 joined, OU=Servers).',
      prerequisites: ['A domain (dc01, ad.corp.lab) with the servers in an OU.', 'Every port each server role needs, collected first: with local rules off, anything not in the GPO is closed.'],
      steps: [
        { title: 'Create the GPO and its rules', command: 'New-GPO -Name "Server Firewall"\nNew-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Firewall" -DisplayName "Remote Desktop (TCP-In)" -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/16 -Action Allow -Profile Domain', what: 'The rules live in the GPO (SYSVOL), not on dc01.', why: 'One change reaches every server in scope.', expected: '', simulated: true },
        { title: 'Profile settings', command: 'Set-NetFirewallProfile -PolicyStore "ad.corp.lab\\Server Firewall" -Profile Domain -Enabled True -DefaultInboundAction Block -LogBlocked True -AllowLocalFirewallRules False', what: 'Firewall on, inbound blocked, drops logged, local rules ignored.', why: 'Servers cannot be opened outside change control; the settings cannot be turned off locally.', expected: '', simulated: true },
        { title: 'Link and apply', command: 'New-GPLink -Name "Server Firewall" -Target "OU=Servers,DC=ad,DC=corp,DC=lab"\ngpupdate /force   (on win01)', what: 'Scope: every computer in OU=Servers.', why: 'Unlinked GPOs do nothing.', expected: 'Computer Policy update has completed successfully.', simulated: true },
        { title: 'Verify on the member', command: 'Get-NetFirewallProfile -Name Domain -PolicyStore ActiveStore | Format-List AllowLocalFirewallRules, LogBlocked\nGet-NetFirewallRule -PolicyStore RSOP | Format-Table DisplayName, Action', what: 'Settings and rules in force.', why: 'Proves the GPO reached the server and shows what is open.', expected: 'AllowLocalFirewallRules : False\nLogBlocked              : True', simulated: true },
      ],
    },
    {
      id: 'not-applicable',
      platform: 'Linux',
      summary: 'Linux has no Windows Defender Firewall. The host firewall there is nftables (or ufw/firewalld on top of it): see the [nftables lesson](#/lesson/nftables/deploy). The ideas carry over: default deny inbound, scoped allow rules, state, logging of drops; but nftables evaluates rules **in order** (first match wins), unlike Windows.',
      prerequisites: [],
      steps: [],
    },
  ],

  configIntro: `
Windows Defender Firewall is configured per machine (local store) or centrally (Group Policy). What you configure:
- **Profiles**: on/off, default inbound and outbound actions, logging (LogBlocked, LogAllowed, file size) per profile.
- **Rules**: direction, action, profile, protocol, ports, addresses, program; enabled or not.
- **The network category** of each adapter (Get-/Set-NetConnectionProfile), which picks the profile.
- **Group Policy**: rules and settings in a GPO, and whether local rules are merged.

### Writing a rule that matches what you mean
Build each rule from the question "who needs to reach what?":
1. **Direction**: Inbound for a service on this machine; Outbound for a connection this machine makes.
2. **Protocol and port**: the service's port as **LocalPort** (inbound) or the destination's port as **RemotePort** (outbound).
3. **RemoteAddress**: the clients (inbound) or the destination (outbound), as narrow as practical. Never leave Any on management ports.
4. **Program**: optional; if you set it, check the socket's owner first.
5. **Profile**: where the rule should count; servers usually Domain (domain members) or Private (workgroup).
6. **Action**: Allow. Use Block only for a narrow exception inside a wider allow.

\`\`\`
New-NetFirewallRule -DisplayName "Intranet app (TCP-In)" -Direction Inbound -Protocol TCP -LocalPort 8080 -RemoteAddress 10.0.10.0/24 -Program "C:\\Apps\\Intranet\\intranet.exe" -Profile Private -Action Allow
\`\`\`

:::practice
Q: Write the rule that lets win01 send syslog to log01 (10.0.20.50, UDP 514) when DefaultOutboundAction is Block.
A: \`New-NetFirewallRule -DisplayName "Syslog to log01 (UDP-Out)" -Direction Outbound -Protocol UDP -RemotePort 514 -RemoteAddress 10.0.20.50 -Action Allow\`. Outbound, so the server's destination port is the **RemotePort**.
Q: A colleague writes \`New-NetFirewallRule -DisplayName "App" -Protocol TCP -RemotePort 8080 -Action Allow\` to let clients reach an app on port 8080 of this server. Why does it not work?
A: For an inbound connection, 8080 is **this machine's** port, so it must be **LocalPort 8080**. RemotePort is the client's (random) source port. (The direction defaults to Inbound, which is right.)
:::

`,

  configFiles: [
    { platform: 'Windows', items: [
      { path: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy', purpose: 'Local store (PersistentStore): profiles and rules. Manage with the cmdlets, not regedit.' },
      { path: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall', purpose: 'Settings and rules from Group Policy (RSOP).' },
      { path: '%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log', purpose: 'Packet log, when LogBlocked/LogAllowed is on.' },
    ] },
    { platform: 'Domain controllers', items: [
      { path: '\\\\DOMAIN\\SYSVOL\\DOMAIN\\Policies\\{GUID}\\Machine\\Registry.pol', purpose: 'A GPO\'s firewall rules and profile settings, delivered to members.' },
    ] },
  ],

  directives: [
    { name: 'Enabled (per profile)', compiledDefault: 'True for Domain, Private and Public', recommended: 'True everywhere, enforced by Group Policy in a domain', explanation: 'The profile\'s firewall on or off.', security: 'Off means every listening port is reachable on that network. Fix rules instead.' },
    { name: 'DefaultInboundAction', compiledDefault: 'Block', recommended: 'Block', explanation: 'What happens to inbound packets no rule matches.', security: 'Allow turns the firewall into a block list: everything not explicitly blocked is open.' },
    { name: 'DefaultOutboundAction', compiledDefault: 'Allow', recommended: 'Allow on most servers; Block (with an inventoried allow list) where egress control is required', explanation: 'What happens to outbound packets no rule matches.', security: 'Block limits what malware can reach, but every connection the server needs must have a rule.' },
    { name: 'LogBlocked / LogAllowed', compiledDefault: 'False / False', recommended: 'LogBlocked True on servers with LogMaxSizeKilobytes 16384; LogAllowed only while investigating', explanation: 'Write dropped packets / allowed connections to pfirewall.log.', security: 'The only local proof of what the host firewall dropped; keep it to investigate incidents.' },
    { name: 'AllowLocalFirewallRules (Group Policy)', compiledDefault: 'NotConfigured (local rules are merged)', recommended: 'False on servers managed by policy, once the GPO carries every needed rule', explanation: 'Whether local rules count in addition to policy rules.', security: 'False stops local admins and installers from opening ports outside change control.' },
    { name: 'Rule RemoteAddress', compiledDefault: 'Any', recommended: 'The client networks that need the service', explanation: 'Who may connect.', security: 'Any on RDP, WinRM or SMB exposes them to every network that can reach the server.' },
  ],

  operateIntro: `
### Changing a firewall safely
- **Keep a second way in.** Changing the rule that carries your RDP or WinRM session can disconnect you. Work from the console (hypervisor) or keep a second session open, and test before you log off.
- **Change one rule, test from a client.** Not from the server itself: loopback is never filtered.
- **Log while you change.** \`LogBlocked True\` shows at once whether the new policy drops something it should not.
- **Never "fix" by turning a profile off**, and never widen a rule to Any to make a ticket go away: find the condition that does not match.
- **In a domain, change the GPO**, not the server: local changes are overwritten or ignored.
- **Record the change.** The Firewall event log keeps who changed what; the ticket should say why.

:::practice
Q: You are connected to win01 over RDP and need to narrow the Remote Desktop rules to 10.0.0.0/16. Your workstation is 10.0.10.25. What do you check before running Set-NetFirewallRule?
A: That **your own address is inside** the new scope (10.0.10.25 is in 10.0.0.0/16), and that you have a **second way in** (console or a second session) in case it is not. Existing connections keep working because of the state, so test with a new connection before you log off.
Q: A ticket is solved by setting the web rule's RemoteAddress to Any. Why is that not an acceptable fix if the site worked before with 10.0.0.0/16?
A: It widens the exposure to every network instead of finding **what changed**: the client's real address (from pfirewall.log) is outside the scope, or another condition does not match. Fix that one condition.
:::

`,
  troubleshootingIntro: `
### Timeout, then server side, then the rules, then the log
A firewall drop shows up on the client as a **timeout**. Work from the outside in and stop at the first answer that does not fit:

1. **Timeout or refused?** From the client: \`nc -zv -w 3 win01 80\` or \`Test-NetConnection win01 -Port 80\`. Refused means the packet got through and nothing listens: a service problem. Timeout means dropped: continue.
2. **Does it listen, and who owns the port?** \`Get-NetTCPConnection -LocalPort 80 -State Listen\` on the server: no listener means a service problem; note OwningProcess for program conditions.
3. **Which profile, with which settings?** \`Get-NetConnectionProfile\` and \`Get-NetFirewallProfile -PolicyStore ActiveStore\`: the category, default actions, and AllowLocalFirewallRules.
4. **Which rules should match, and does a Block rule match?** \`Get-NetFirewallRule -Enabled True -Direction Inbound\` (and \`-Action Block\`), then each candidate rule's port, address and application filters.
5. **What does the log say?** Turn on \`LogBlocked\`, reproduce, read \`pfirewall.log\`: the real source address, the port, RECEIVE or SEND.

For a connection the **server** makes (to a share, a DC, an update server), steps 1 and 2 happen on the server (\`Test-NetConnection fs01 -Port 445\`), step 3 looks at **DefaultOutboundAction**, step 4 at the **outbound** rules, and the log shows **SEND**.

:::practice
Q: From ws01, \`nc -zv -w 3 win01 8080\` prints "Connection refused". The web team asks you to open the firewall. What do you tell them?
A: The firewall is **not** blocking it: the SYN reached win01, and TCP refused it because **nothing listens on 8080**. Check that their application is running and bound to that port.
Q: The server cannot reach fs01 on 445; other machines can. pfirewall.log has DROP lines with dst-port 445. Which word at the end of the line tells you it is win01's outbound filter, and which setting do you check?
A: **SEND**: a packet win01 was sending. Check \`DefaultOutboundAction\` (Get-NetFirewallProfile) and the **outbound** rules.
:::

`,

  errorMap: [
    { message: 'curl: (28) Failed to connect to win01.corp.lab port 80 after 10000 ms: Couldn\'t connect to server', layer: 'Firewall (drop)', meaning: 'The SYN got no answer: dropped by win01\'s firewall (or another firewall on the path).', firstCheck: 'Get-NetTCPConnection -LocalPort 80 -State Listen; then rules and pfirewall.log' },
    { message: 'nc: connect to win01 port 8080 (tcp) failed: Connection refused', layer: 'Service (not the firewall)', meaning: 'The packet passed the firewall and nothing listens on the port.', firstCheck: 'Get-NetTCPConnection -State Listen; the application' },
    { message: 'WARNING: TCP connect to (10.0.20.60 : 445) failed', layer: 'Outbound (or the destination)', meaning: 'Test-NetConnection from the server could not open the connection.', firstCheck: 'Get-NetFirewallProfile (DefaultOutboundAction); outbound rules; the same test from another machine' },
    { message: 'System error 53 has occurred. The network path was not found.', layer: 'SMB client path', meaning: 'net use could not reach the server on 445 (outbound block, network, name) or the server is down.', firstCheck: 'Test-NetConnection fs01 -Port 445 on the client' },
    { message: 'New-NetFirewallRule : The port is invalid. When Protocol is TCP or UDP, individual ports or ranges are allowed.', layer: 'Rule syntax', meaning: 'A port was given without -Protocol TCP/UDP, or for ICMP.', firstCheck: 'Add -Protocol TCP (or UDP)' },
    { message: 'Enable-NetFirewallRule : Access is denied.', layer: 'Permissions', meaning: 'Changing the firewall needs an elevated administrator session.', firstCheck: 'Run PowerShell as Administrator' },
    { message: 'Set-NetFirewallProfile : The request is not supported.', layer: 'Policy store', meaning: 'RSOP (policy) cannot be changed on the member: change the GPO.', firstCheck: 'gpresult /r: which GPO sets it' },
    { message: 'DROP TCP 10.0.10.25 10.0.20.30 51544 80 52 S ... RECEIVE', layer: 'pfirewall.log', meaning: 'An inbound new connection (SYN) from 10.0.10.25 to port 80 was dropped by this host.', firstCheck: 'Rules for TCP 80 and their address/program filters; Block rules' },
  ],

  scenarioIds: ['wfw-remote-scope', 'wfw-program-mismatch', 'wfw-block-precedence', 'wfw-outbound-default', 'wfw-local-rules-ignored'],
  assessmentId: 'windows-firewall',
  references: [
    { title: 'Microsoft Learn: Windows Firewall overview', url: 'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/' },
    { title: 'Microsoft Learn: Windows Firewall rules (precedence, conditions)', url: 'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/rules' },
    { title: 'Microsoft Learn: Configure Windows Firewall logging', url: 'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/configure-logging' },
    { title: 'Microsoft Learn: NetSecurity PowerShell module', url: 'https://learn.microsoft.com/powershell/module/netsecurity/' },
    { title: 'Microsoft Learn: Windows Filtering Platform', url: 'https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page' },
  ],
  guide: WINDOWS_FIREWALL_GUIDE,
  objectives: ['N10-009:4.3', 'N10-009:5.3'],
};

// --- Primer -------------------------------------------------------------------------

export const WINDOWS_FIREWALL_PRIMER: Primer = {
  oneLiner: 'Windows Defender Firewall checks every packet a Windows machine receives or sends against **rules**. By default it **blocks** every incoming connection no rule allows and **allows** every outgoing one; a rule acts only when **all** its conditions match, and a **Block** rule always beats an **Allow** rule.',
  analogy: `
A reception desk with a list of expected visitors. Visitors not on the list are turned away (default inbound Block); staff walking out are not stopped (default outbound Allow). A list entry is precise: "Mr Smith, from Acme, for the 3rd floor" lets in Mr Smith from Acme going to the 3rd floor, not Mr Smith from another company. And a "never let in" notice beats any invitation, whatever order they were pinned up in.

The comparison stops at the log: a real receptionist remembers who was turned away; the firewall only writes it down if you switch logging on.`,
  ideas: [
    {
      title: 'Profiles: the network decides which rules count',
      explain: 'Each adapter is in the Domain, Private or Public profile. A rule lists the profiles it applies to; in any other profile it does nothing.',
      example: 'The RDP rules are limited to Domain and Private. When win01\'s network is classified as Public after a switch change, RDP times out although the rules are enabled.',
    },
    {
      title: 'Every condition must match',
      explain: 'Port, remote address, program and profile are combined with AND. One wrong condition and the rule is skipped.',
      example: 'The monitoring rule allows ping from 10.0.1.0/24; the monitoring host is now 10.0.10.25, so its pings are dropped.',
    },
    {
      title: 'Block beats Allow; there is no order',
      explain: 'If a Block rule and an Allow rule both match, the packet is dropped. Rule order does not matter.',
      example: '"Allow RDP from 10.0.0.0/16" plus "Block RDP from Any" blocks RDP for everyone.',
    },
    {
      title: 'The log proves the drop',
      explain: 'With LogBlocked on, pfirewall.log lists every dropped packet with its real source, port and direction.',
      example: 'DROP TCP 10.0.10.25 10.0.20.30 51544 80 ... RECEIVE: ws01\'s connection to port 80 was dropped on arrival.',
    },
  ],
  walkthrough: {
    title: 'ws01 cannot reach the intranet site on win01',
    steps: [
      { label: 'Symptom', detail: 'curl from ws01 times out: dropped, not refused.' },
      { label: 'Listener', detail: 'On win01, Get-NetTCPConnection -LocalPort 80 -State Listen: IIS (http.sys, process System) listens.' },
      { label: 'Profile', detail: 'Get-NetFirewallProfile -PolicyStore ActiveStore: Private, on, inbound Block.' },
      { label: 'Rule', detail: 'The web rule is enabled for TCP 80, but Get-NetFirewallApplicationFilter shows Program w3wp.exe, which does not own the socket.' },
      { label: 'Log', detail: 'pfirewall.log: DROP TCP 10.0.10.25 10.0.20.30 ... 80 ... RECEIVE.' },
      { label: 'Fix', detail: 'Set-NetFirewallRule -Program System; curl from ws01 returns 200.' },
    ],
  },
  misconceptions: [
    { myth: 'The rule I added first takes precedence.', truth: 'There is no rule order: a matching Block rule always wins over a matching Allow rule.' },
    { myth: 'The site works on the server, so the firewall is fine.', truth: 'Loopback traffic is never filtered. Test from a client.' },
    { myth: 'Turning the firewall off for a minute is a harmless test.', truth: 'It opens every port on that network and is easily forgotten. Read the log and the rule\'s filters instead.' },
    { myth: 'If Get-NetFirewallRule shows my local rule enabled, it is enforced.', truth: 'Not if Group Policy sets AllowLocalFirewallRules False: check -PolicyStore ActiveStore.' },
  ],
  checks: [
    { q: 'What happens to an inbound packet that no rule matches?', a: 'The profile\'s default inbound action applies: Block, unless someone changed it.' },
    { q: 'Which process owns IIS\'s port 80?', a: 'System (PID 4): http.sys, the kernel HTTP listener.' },
    { q: 'What does SEND at the end of a pfirewall.log line mean?', a: 'The packet was leaving this machine: the outbound filter dropped it.' },
    { q: 'Where do you add a rule when local rules are switched off by policy?', a: 'In the GPO, then gpupdate /force on the member.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const WINDOWS_FIREWALL_ASSESSMENT: Assessment = {
  id: 'windows-firewall',
  title: 'Windows Defender Firewall knowledge check',
  questions: [
    {
      id: 'wfw-q-precedence',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/windows-firewall/internals'],
      prompt: 'On a file server, rule A allows TCP 445 from 10.0.0.0/8 and rule B blocks TCP 445 from 10.0.50.0/24. Rule A was created first. Client 10.0.50.7 opens \\\\server\\share. What happens?',
      options: [
        { text: 'It is blocked: both rules match and a Block rule wins over an Allow rule', correct: true },
        { text: 'It is allowed: rule A was created first, so it is evaluated first', misconception: 'Windows Defender Firewall has no rule order; precedence is by action.' },
        { text: 'It is allowed: the more specific rule always wins', misconception: 'Specificity does not matter either: Block beats Allow.' },
        { text: 'It depends on the default inbound action', misconception: 'The default action only applies when no rule matches; here two rules match.' },
      ],
      concepts: ['win.firewall'],
      explanation: 'Matching Block rules are applied before Allow rules (only authenticated-bypass allow rules beat them).',
    },
    {
      id: 'wfw-q-log',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-firewall/internals', 'lesson/windows-firewall/troubleshoot'],
      prompt: 'An application on app01 (10.0.20.21) cannot reach its database. app01\'s pfirewall.log shows the line in the exhibit. What does it tell you?',
      exhibit: '2026-10-22 14:05:51 DROP TCP 10.0.20.21 10.0.20.40 50812 1433 52 S 3301928810 0 64240 - - - SEND',
      options: [
        { text: 'app01\'s own firewall dropped its outbound connection to 10.0.20.40 port 1433: check DefaultOutboundAction and the outbound rules on app01', correct: true },
        { text: 'The database server dropped the connection from app01', misconception: 'This is app01\'s log; the source is app01 and the path is SEND (leaving app01).' },
        { text: 'A client at 10.0.20.40 was blocked from reaching SQL Server on app01', misconception: 'Read source then destination: 10.0.20.21 (app01) is the source, 10.0.20.40 the destination.' },
        { text: 'The connection was established and then reset', misconception: 'Flags S means a SYN, the first packet of a new connection, and DROP means it never left.' },
      ],
      concepts: ['win.firewall'],
      explanation: 'Fields: action, protocol, src-ip, dst-ip, src-port, dst-port, ..., path. SEND is outbound from the machine that wrote the log.',
    },
    {
      id: 'wfw-q-program',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-firewall/internals'],
      prompt: 'WinRM (port 5985) on a server times out from the management network. The only rule for 5985 is enabled, Allow, Profile Any, RemoteAddress 10.0.0.0/16, Program %SystemRoot%\\system32\\svchost.exe. Get-NetTCPConnection -LocalPort 5985 -State Listen shows OwningProcess 4. What is the fix?',
      options: [
        { text: 'Set the rule\'s Program to System (or remove the program condition): http.sys, shown as PID 4, owns the socket', correct: true },
        { text: 'Restart the WinRM service so that svchost.exe owns the port again', misconception: 'WinRM always listens through http.sys; the socket owner is System.' },
        { text: 'Add a second Allow rule for TCP 5985 with Program Any; keep the first one', misconception: 'It works, but leaves a misleading rule behind and drops the program scoping the policy asked for.' },
        { text: 'Set the default inbound action to Allow for the Domain profile', misconception: 'That opens every port on the server.' },
      ],
      concepts: ['win.firewall', 'svc.listening'],
      explanation: 'A program condition is compared with the owner of the listening socket. Kernel listeners (http.sys, SMB) are System.',
    },
    {
      id: 'wfw-q-conditions',
      kind: 'multi',
      level: 'beginner',
      learn: ['lesson/windows-firewall/internals'],
      prompt: 'An enabled inbound Allow rule should let an SNMP poller at 10.0.10.40 reach UDP 161 on a server in the Private profile. Which of these would make the rule not match the poller\'s packets? (choose all that apply)',
      options: [
        { text: 'Profile is set to Domain only', correct: true },
        { text: 'RemoteAddress is LocalSubnet and the server is 10.0.20.30/24', correct: true },
        { text: 'Protocol is TCP', correct: true },
        { text: 'The rule was created after several other rules', misconception: 'Rule order plays no part in Windows Defender Firewall.' },
        { text: 'LocalPort is 161 and RemotePort is Any', misconception: 'That is exactly right for an inbound service on 161.' },
      ],
      concepts: ['win.firewall'],
      explanation: 'Every condition must match: profile, protocol, ports, addresses and program.',
    },
    {
      id: 'wfw-q-stateful',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-firewall/internals'],
      prompt: 'Security sets DefaultOutboundAction Block on a web server and adds no outbound rules. Which of these stops working?',
      options: [
        { text: 'The server\'s own connections, such as downloading updates or writing to a file share', correct: true },
        { text: 'Responses to clients browsing the website', misconception: 'Responses are replies on connections the inbound rule allowed: the firewall is stateful.' },
        { text: 'Remote Desktop sessions to the server', misconception: 'RDP is an inbound connection; its replies pass because of the state.' },
        { text: 'Nothing, because outbound rules are only checked in the Public profile', misconception: 'The default outbound action applies in the active profile, whichever it is.' },
      ],
      concepts: ['win.firewall', 'fw.stateful'],
      explanation: 'Outbound filtering only affects connections the server starts; replies to allowed inbound connections pass.',
    },
    {
      id: 'wfw-q-local-merge',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/windows-firewall/internals', 'lesson/windows-firewall/config'],
      prompt: 'On a domain member in the Domain profile, a local Allow rule for TCP 8443 is enabled and correct, yet clients time out, while rules for RDP and SMB work. gpresult lists the GPO "Member Server Firewall". What explains it, and where should the rule go?',
      options: [
        { text: 'The GPO sets AllowLocalFirewallRules False, so local rules are ignored: add the rule to the GPO and run gpupdate /force', correct: true },
        { text: 'Local rules are always ignored on domain members: delete the local rule and add it on each server again with netsh', misconception: 'Local rules are merged by default; only the GPO setting turns that off, and netsh writes to the same local store.' },
        { text: 'The GPO has a Block rule for 8443: remove Block rules from the GPO', misconception: 'Possible in general, but RDP/SMB working and a correct local rule point at local merging; check -PolicyStore ActiveStore.' },
        { text: 'Domain profile rules need a restart to apply', misconception: 'Rule changes apply at once.' },
      ],
      concepts: ['win.firewall', 'ad.gpo'],
      explanation: 'Get-NetFirewallProfile -PolicyStore ActiveStore shows AllowLocalFirewallRules False; only GPO rules (RSOP) count.',
    },
    {
      id: 'wfw-q-order',
      kind: 'order',
      level: 'intermediate',
      learn: ['lesson/windows-firewall/troubleshoot'],
      prompt: 'A client times out connecting to TCP 9000 on a Windows server. Order the checks from first to last.',
      items: [
        'From the client: is it a timeout or a refusal?',
        'On the server: does something listen on 9000, and which process owns it?',
        'Which profile is active, and what are its settings in force?',
        'Which rules should match, and does a Block rule match?',
        'Turn on LogBlocked, reproduce, and read pfirewall.log',
      ],
      concepts: ['win.firewall'],
      explanation: 'Outside in: symptom type, listener, profile, rules, then the log as proof.',
    },
    {
      id: 'wfw-q-refused',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/windows-firewall/troubleshoot'],
      prompt: 'Test-NetConnection srv-app -Port 7070 fails immediately, and a packet capture shows the server answering the SYN with RST. What does this say about the server\'s firewall?',
      options: [
        { text: 'It let the SYN through; nothing listens on 7070, so look at the application, not the firewall', correct: true },
        { text: 'A Block rule for 7070 rejected the connection', misconception: 'Windows Defender Firewall drops blocked packets silently: the client sees a timeout, not a reset.' },
        { text: 'The firewall profile is Public', misconception: 'A profile problem leads to drops (timeouts), not resets.' },
      ],
      concepts: ['win.firewall', 'svc.listening'],
      explanation: 'Drop = timeout; refused (RST) = passed the firewall but no listener.',
    },
    {
      id: 'wfw-q-scope',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/windows-firewall/internals', 'lesson/windows-firewall/operate'],
      prompt: 'Backups from the backup server (10.0.30.15) to a Windows host over TCP 10000 time out since the backup server moved from 10.0.20.15. The host\'s rule for 10000 has RemoteAddress 10.0.20.0/24. Which change fixes it without widening exposure?',
      options: [
        { text: 'Set the rule\'s RemoteAddress to 10.0.30.15', correct: true },
        { text: 'Set RemoteAddress to Any', misconception: 'Every network could then reach the backup agent.' },
        { text: 'Add a Block rule for everything except 10.0.30.15', misconception: 'Block rules cannot express "except", and a Block that matches 10.0.30.15 would win.' },
        { text: 'Switch the adapter to the Public profile', misconception: 'The profile is not the problem: the address condition is.' },
      ],
      concepts: ['win.firewall'],
      explanation: 'Fix the one condition that no longer matches the real sender.',
    },
    {
      id: 'wfw-q-logging-cmd',
      kind: 'text',
      level: 'beginner',
      learn: ['lesson/windows-firewall/internals'],
      prompt: 'Type the PowerShell command that turns on logging of dropped packets for all three profiles.',
      accept: [/^set-netfirewallprofile\s+(-all|-(name|profile)\s+["']?domain["']?\s*,\s*["']?private["']?\s*,\s*["']?public["']?)\s+-logblocked\s+(\$?true|1)$/i, /^set-netfirewallprofile\s+-logblocked\s+(\$?true|1)\s+(-all|-(name|profile)\s+domain\s*,\s*private\s*,\s*public)$/i],
      placeholder: 'Set-NetFirewallProfile ...',
      concepts: ['win.firewall'],
      explanation: 'Set-NetFirewallProfile -All -LogBlocked True (or -Profile Domain,Private,Public). The log goes to %SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log.',
    },
  ],
};
