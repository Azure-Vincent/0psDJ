// Group Policy. Examples follow the lab: dc01 is the domain controller of
// ad.corp.lab (CORP); win01 is a member server; GPOs carry Computer
// Configuration settings (registry policies, firewall rules) to the computers
// in the OUs they are linked to. The sandbox and the tickets run there.

import type { Assessment, Lesson, Primer, ServiceGuide } from '../types';

// --- Operate & recover guide ---------------------------------------------------------

export const GPO_GUIDE: ServiceGuide = {
  purpose:
    'Group Policy is how an Active Directory domain configures its Windows computers centrally: a **Group Policy Object** (GPO) holds settings (security options, firewall rules, registry-based policies, scripts, software), and **linking** it to the domain or to an **organizational unit** (OU) makes every computer (and user) in that container apply it, at startup and every 90 minutes. One change on the domain controller reaches hundreds of machines; gpresult shows, per machine, what applied and why something did not.',
  architecture: [
    { q: 'What does it accomplish?', a: 'Consistent configuration for every domain member, enforced continuously: a local change is overwritten at the next refresh, and a new computer receives the baseline as soon as it is in the right OU.' },
    { q: 'How does it work internally?', a: 'A GPO has two halves: the **Group Policy container** in AD (name, status, version, permissions) and the **Group Policy template** in **SYSVOL** (`\\\\ad.corp.lab\\SYSVOL\\ad.corp.lab\\Policies\\{GUID}`: gpt.ini, Registry.pol, firewall and security settings). Links are an attribute (gPLink) on the domain or OU. The client-side engine (the Group Policy service) finds a DC, reads its own DN and the links above it, filters the GPOs, downloads the templates and lets each client-side extension (registry, security, firewall...) apply its part.' },
    { q: 'Which protocols does it use?', a: 'DNS (SRV records) to find a DC, LDAP (389) to read the containers and links, Kerberos (88) with the computer account to authenticate, SMB (445) to read SYSVOL. DFS-R replicates SYSVOL between DCs.' },
    { q: 'Which ports and transport?', a: 'From members to the DC: 53, 88, 389, 445 (and 135 + dynamic RPC for some tools). A DC that blocks 445 still authenticates logons but delivers no policy.' },
    { q: 'Which processes and OS components implement it?', a: 'The Group Policy Client service (gpsvc) on every member, client-side extensions in it, and on the DC: AD DS (the containers), the SYSVOL share, DFS Replication. Management: GPMC (gpmc.msc) and the GroupPolicy PowerShell module.' },
    { q: 'Which other services does it depend on?', a: 'DNS for the domain, a working secure channel (the computer account), time within Kerberos tolerance, network access to the DC on 389 and 445, healthy SYSVOL replication when there are several DCs.' },
    { q: 'How do requests travel?', a: 'win01 starts → finds dc01 via _ldap._tcp.dc._msdcs.ad.corp.lab → binds with WIN01$ (Kerberos) → reads its DN (CN=WIN01,OU=Servers,DC=ad,DC=corp,DC=lab) and the gPLinks of DC=ad,DC=corp,DC=lab and OU=Servers → keeps the GPOs it may read and apply → reads each gpt.ini and Registry.pol from \\\\ad.corp.lab\\SYSVOL over SMB → applies the settings in order (domain first, OU last, so the OU wins), enforced links last.' },
    { q: 'How do authentication and authorisation work?', a: 'The computer processes Computer Configuration as itself (its account and groups, from its Kerberos ticket obtained at startup). **Security filtering** is the GPO\'s permissions: a principal needs **Read and Apply** (GpoApply). Since MS16-072, user policy is also read with the computer\'s credentials, so every GPO must stay readable by the computers (Authenticated Users or Domain Computers: GpoRead).' },
    { q: 'How does it start at boot?', a: 'Computer policy runs during startup (before logon), user policy at logon; then both refresh in the background every 90 minutes plus a random offset (DCs every 5 minutes). Some settings (software installation, folder redirection) apply only at startup/logon.' },
    { q: 'What happens if it terminates unexpectedly?', a: 'The last applied settings stay in place (they are written into the registry and the firewall store). Processing errors are logged (System log, GroupPolicy events 1058, 1129, 1055, 1006) and retried at the next refresh.' },
  ],
  ports: [
    { port: '389', proto: 'TCP/UDP', purpose: 'LDAP: GPO containers, links and the computer\'s DN' },
    { port: '445', proto: 'TCP', purpose: 'SMB: the GPO templates in SYSVOL (and NETLOGON scripts)' },
    { port: '88', proto: 'TCP/UDP', purpose: 'Kerberos: the computer account authenticates' },
    { port: '53', proto: 'TCP/UDP', purpose: 'DNS: locating a domain controller' },
  ],
  processes: [
    { name: 'gpsvc (Group Policy Client)', platform: 'Windows (every member)', role: 'Processes policy at startup, logon and every 90 minutes; runs the client-side extensions' },
    { name: 'gpupdate / gpresult', platform: 'Windows', role: 'Force a refresh / show the resultant set of policy' },
    { name: 'GPMC (gpmc.msc), GroupPolicy module', platform: 'Windows Server, RSAT', role: 'Create, edit, link, filter and report on GPOs' },
    { name: 'DFS Replication', platform: 'Domain controllers', role: 'Replicates SYSVOL (the templates) between DCs' },
  ],
  dependencies: {
    title: 'What "the Server Baseline firewall rule is on win01" depends on (top needs everything below it)',
    caption: 'Scope, filtering and download must all succeed; gpresult shows which step stopped it.',
    rows: [
      { label: 'Result', nodes: [{ id: 'rule', label: 'Firewall rule on win01', sub: 'PolicyStoreSource GPO', kind: 'service' }] },
      { label: 'Download', nodes: [{ id: 'sysvol', label: 'SYSVOL on dc01', sub: 'SMB 445', kind: 'network' }] },
      { label: 'Filtering', nodes: [{ id: 'perm', label: 'GPO permissions', sub: 'Read + Apply', kind: 'data' }, { id: 'token', label: 'WIN01$ groups', sub: 'ticket from startup', kind: 'data' }] },
      { label: 'Scope', nodes: [{ id: 'ou', label: 'WIN01 in OU=Servers', sub: 'Move-ADObject', kind: 'data' }, { id: 'link', label: 'Link on OU=Servers', sub: 'enabled; inheritance', kind: 'data' }] },
      { label: 'Domain', nodes: [{ id: 'dc', label: 'DC location + secure channel', sub: 'DNS, LDAP, Kerberos', kind: 'service' }] },
    ],
    edges: [['rule', 'sysvol'], ['sysvol', 'perm'], ['perm', 'token'], ['perm', 'ou'], ['ou', 'link'], ['link', 'dc']],
  },
  sequence: {
    title: 'win01 processes Computer Configuration (gpupdate /force)',
    caption: 'One DC (dc01); where each ticket breaks the processing is noted.',
    lanes: [{ id: 'm', label: 'win01', sub: 'Group Policy Client' }, { id: 'd', label: 'dc01', sub: 'AD DS + SYSVOL' }],
    steps: [
      { from: 'm', to: 'd', label: 'DNS SRV + LDAP bind as WIN01$ (Kerberos)', note: 'No DC: event 1129. No KDC (port 88): event 1055. Broken trust or clock skew: LDAP bind fails, event 1006.' },
      { from: 'm', to: 'd', label: 'LDAP: my DN? gPLink of the domain and of each OU above me', note: 'WIN01 in CN=Computers: OU links never apply. Block Inheritance drops the domain\'s non-enforced links.' },
      { from: 'd', to: 'm', label: 'GPO containers: status, version, permissions', note: 'No Apply for WIN01$\'s groups (as of its last startup): "Denied (Security)". No Read at all: "Inaccessible".' },
      { from: 'm', to: 'd', label: 'SMB: \\\\ad.corp.lab\\SYSVOL\\...\\{GUID}\\gpt.ini, Registry.pol', note: '445 blocked: event 1058 "Windows attempted to read the file ... gpt.ini ... not successful"; nothing changes.' },
      { from: 'm', to: 'm', label: 'Apply: registry policies, firewall rules (domain first, OU last, enforced at the end)' },
    ],
  },
  files: [
    { path: '\\\\ad.corp.lab\\SYSVOL\\ad.corp.lab\\Policies\\{GUID}\\', platform: 'Domain controllers (SYSVOL)', kind: 'config', perms: 'Authenticated Users: read', contains: 'gpt.ini (version), Machine\\Registry.pol (registry policies), Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf (security settings).', accessed: 'By every member at each processing.', problems: 'Unreachable (445 blocked, DNS) or not replicated between DCs: version mismatch, event 1058.' },
    { path: 'HKLM\\SOFTWARE\\Policies\\...', platform: 'Windows members', kind: 'config', contains: 'Registry-based policies written by Group Policy (they override the matching local settings).', accessed: 'Written at each processing; read by the components (Terminal Services, firewall, Windows Update...).', problems: 'Local edits are overwritten at the next refresh; a GPO that stops applying removes its values.' },
    { path: 'System log: Microsoft-Windows-GroupPolicy (1500-1503, 1058, 1129, 1055, 1006, 1030)', platform: 'Windows members', kind: 'log', contains: 'Success and failure of each processing, with the reason.', accessed: 'At each processing.', problems: 'Look here first when gpupdate prints an error.' },
  ],
  management: [
    {
      platform: 'Domain controller / management host (GroupPolicy module)',
      tasks: [
        { task: 'List GPOs', command: 'Get-GPO -All | Format-Table DisplayName,GpoStatus,ModificationTime', explain: 'Every GPO in the domain and whether its halves are enabled.', sim: true },
        { task: 'What reaches an OU?', command: 'Get-GPInheritance -Target "OU=Servers,DC=ad,DC=corp,DC=lab"', explain: 'Links on the OU, inherited links (highest precedence first), and Block Inheritance.', sim: true },
        { task: 'Create, fill and link a GPO', command: 'New-GPO -Name "Server Baseline"\nNew-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" -DisplayName "Monitoring ping" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.0.0/16\nNew-GPLink -Name "Server Baseline" -Target "OU=Servers,DC=ad,DC=corp,DC=lab"', explain: 'The settings live in the GPO; the link decides who gets them.', sim: true },
        { task: 'Security filtering', command: 'Get-GPPermission -Name "Server Baseline" -All\nSet-GPPermission -Name "Server Baseline" -TargetName "Baseline Servers" -TargetType Group -PermissionLevel GpoApply', explain: 'Apply for the target group; Read (not Apply) for Authenticated Users keeps the GPO readable.', sim: true },
        { task: 'Put a computer in scope', command: 'Move-ADObject -Identity "CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab" -TargetPath "OU=Servers,DC=ad,DC=corp,DC=lab"', explain: 'CN=Computers cannot have GPO links: servers belong in an OU.', sim: true },
      ],
    },
    {
      platform: 'Member (win01)',
      tasks: [
        { task: 'Apply now', command: 'gpupdate /force', explain: 'Processes Computer and User Configuration; errors name the failing step.', sim: true },
        { task: 'What applied and why not?', command: 'gpresult /r /scope computer', explain: 'The computer\'s DN, applied GPOs, filtered GPOs with the reason, and its security groups.', sim: true },
        { task: 'Rules from policy', command: 'Get-NetFirewallRule -PolicyStore RSOP', explain: 'Firewall rules that came from GPOs (PolicyStoreSourceType GroupPolicy).', sim: true },
        { task: 'Why did processing fail?', command: 'Get-WinEvent -LogName System -MaxEvents 10', explain: 'GroupPolicy events 1058 (SYSVOL), 1129 (no DC), 1055 (no Kerberos ticket), 1006 (LDAP bind).', sim: true },
      ],
    },
  ],
  actions: [
    { action: 'gpupdate /force', when: 'After changing a GPO, a link or the computer\'s OU.', effect: 'Processes policy now instead of within 90 minutes.', risk: 'Reapplies everything, including security settings; some settings ask to restart or log off.' },
    { action: 'Restart the computer', when: 'After changing the computer\'s group memberships (security filtering), or for startup-only settings.', effect: 'New Kerberos ticket with the new groups; startup policy.', risk: 'Service interruption: plan it.' },
    { action: 'Set-GPLink -Enforced Yes', when: 'A baseline must reach every OU, including those that block inheritance.', effect: 'The link passes Block Inheritance and wins conflicts.', risk: 'OU owners can no longer override it.' },
  ],
  workflow: [
    { question: 'Does processing work at all?', why: 'Nothing else matters if the computer cannot fetch policy: the error event names the failing dependency (DC location, Kerberos, LDAP or SYSVOL).', command: 'gpupdate /force', healthy: 'Computer Policy update has completed successfully.', broken: '"lack of network connectivity to a domain controller" / event 1129: DC location (DNS, LDAP). "could not resolve the computer name" / 1055: no Kerberos ticket (KDC, port 88). "LDAP Bind function call failed" / 1006: trust or clock skew. "attempted to read the file ... gpt.ini" / 1058: SYSVOL (SMB 445, replication).', next: 'If it works, check scope.', sim: true },
    { question: 'Is the GPO in scope?', why: 'A GPO only applies to computers in or below the container it is linked to. A computer left in CN=Computers misses OU-linked GPOs.', command: 'gpresult /r /scope computer\nGet-GPInheritance -Target "OU=Servers,DC=ad,DC=corp,DC=lab"', healthy: 'The computer\'s DN is in the OU the GPO is linked to (or below), and the GPO is in InheritedGpoLinks.', broken: 'DN in CN=Computers; link on another OU; link disabled; Block Inheritance above a non-enforced link.', next: 'If in scope, check filtering.', sim: true },
    { question: 'Is it filtered out?', why: 'Security filtering can exclude a computer even when the GPO is in scope, and it uses the groups from the computer\'s last restart.', command: 'gpresult /r (The following GPOs were not applied...)\nGet-GPPermission -Name "..." -All', healthy: 'Listed under Applied Group Policy Objects.', broken: 'Denied (Security): no Apply for the computer\'s groups (new group membership needs a restart). Inaccessible: no Read for the computer. Disabled (GPO): computer settings disabled. Not Applied (Empty): no computer settings.', next: 'If applied, check the setting itself.', sim: true },
    { question: 'Did the setting land?', why: 'The final proof is the setting itself on the computer. When GPOs conflict, precedence decides which value wins.', command: 'Get-NetFirewallRule -PolicyStore RSOP\nGet-ItemProperty "HKLM:\\SOFTWARE\\Policies\\..."', healthy: 'The rule / value from the GPO.', broken: 'Another GPO with higher precedence sets the opposite value, or a local setting is shadowed by policy.', next: 'Compare precedence in gpresult.', sim: true },
  ],
  failures: [
    { symptom: 'gpupdate succeeds but the setting never arrives', causes: ['Computer not in the linked OU', 'Link disabled', 'Block Inheritance (link not enforced)', 'Filtered out (security)'], diagnose: ['gpresult /r (DN, applied, filtered)', 'Get-GPInheritance on the OU'], fix: 'Move the computer, enable/enforce the link, or fix filtering.', verify: 'gpresult lists the GPO as applied; the setting is present.' },
    { symptom: 'Denied (Security) although the computer is in the filter group', causes: ['The computer has not restarted since it was added: its ticket has the old groups'], diagnose: ['gpresult /r security group list', 'Get-ADGroupMember'], fix: 'Restart the computer (or purge its tickets).', verify: 'The group appears in gpresult; the GPO applies.' },
    { symptom: 'gpupdate: "attempted to read the file ... gpt.ini"', causes: ['SMB 445 to the DC blocked', 'SYSVOL not replicated to this DC', 'DNS for the domain name'], diagnose: ['Test-NetConnection DC -Port 445', 'Event 1058', 'dir \\\\ad.corp.lab\\SYSVOL'], fix: 'Allow File and Printer Sharing (SMB-In) on DCs; fix replication.', verify: 'gpupdate /force succeeds.' },
  ],
  verification: [
    { check: 'Processing works', command: 'gpupdate /force', expect: 'Computer Policy update has completed successfully.' },
    { check: 'GPO applied', command: 'gpresult /r /scope computer', expect: 'The GPO under Applied Group Policy Objects' },
    { check: 'Setting present', command: 'Get-NetFirewallRule -PolicyStore RSOP', expect: 'The GPO\'s rules' },
    { check: 'Survives restart', command: 'Restart-Computer, then gpresult /r', expect: 'Same result at startup' },
  ],
  refIds: ['gpupdate', 'gpresult', 'grouppolicy-module', 'move-adobject', 'get-netfirewallrule'],
};

// --- Lesson -------------------------------------------------------------------------

export const GPO_LESSON: Lesson = {
  id: 'gpo',
  moduleId: 'C',
  title: 'Group Policy',
  level: 'intermediate',
  summary: 'How GPOs, links and OUs decide which computers get which settings; LSDOU order, Block Inheritance and Enforced; security filtering with the computer\'s token; SYSVOL; and how gpupdate and gpresult tell you what applied and why something did not.',
  concepts: ['ad.gpo', 'ad.dns', 'fw.path'],

  what: `
**Group Policy** configures the computers and users of an [Active Directory](#/lesson/ad-kerberos/what) domain from one place. Instead of logging on to 200 servers to set the same firewall rule, you define it once and every server applies it by itself.

A **Group Policy Object** (GPO) is a named set of settings. An **organizational unit** (OU) is a folder in the directory that holds computers or users, for example OU=Servers. **Linking** a GPO to the domain or to an OU makes every computer in that container apply it. Computers fetch their policy from a domain controller, so Group Policy depends on DC location (DNS), Kerberos and file sharing (SMB) all working.

### Problems it solves
- **Consistency**: every server gets the same security baseline, firewall rules and update settings.
- **Scale**: one change on the DC reaches every member within 90 minutes (or immediately with gpupdate).
- **Drift control**: local changes are overwritten at the next refresh.

### The pieces
- **GPOs**: settings (here: registry-based policies and firewall rules), stored partly in AD and partly in **SYSVOL** on every DC.
- **OUs and links**: where a GPO is linked decides who gets it; computers in the default **CN=Computers** container can only get domain-linked GPOs.
- **Security filtering**: who may read and apply a GPO.
- **The client**: every member processes its policy at startup, every 90 minutes and on \`gpupdate\`; \`gpresult\` shows the result.

> In the lab, **dc01** is the DC of ad.corp.lab and has the Group Policy Management tools (GroupPolicy module); **win01** becomes a member. The tickets add OU=Servers and GPOs such as "Server Baseline" (a firewall rule allowing monitoring pings). Simulated: OUs and Move-ADObject, Add-Computer -OUPath, GPOs with registry policies (Set-GPRegistryValue) and firewall rules (New-NetFirewallRule -PolicyStore), links (enabled, enforced, order), Block Inheritance, security filtering (Get-/Set-GPPermission) evaluated with the computer's groups from its last startup, processing at startup and on gpupdate (DC location, LDAP bind, SYSVOL over SMB 445, events 1500/1502/1058/1129/1055/1006), removal of settings when a GPO stops applying, gpresult /r, Get-NetFirewallRule -PolicyStore RSOP. Not simulated: User Configuration, WMI filters, sites, loopback processing, security templates, software installation, GPMC's GUI.

:::practice
Q: A new server joined without -OUPath gets no settings from the "Server Baseline" GPO linked to OU=Servers. Which piece explains it?
A: **OUs and links**: it sits in CN=Computers, which is not an OU and only receives domain-linked GPOs.
Q: When does a domain member process computer policy?
A: At **startup**, every **90 minutes** (with a random offset) and when you run \`gpupdate\`.
:::

`,

  internals: `
### 1. Two halves of a GPO
The **Group Policy container** is an AD object (CN={GUID},CN=Policies,CN=System,DC=ad,DC=corp,DC=lab) with the name, status, version and permissions. The **Group Policy template** is a folder in SYSVOL (\\\\ad.corp.lab\\SYSVOL\\ad.corp.lab\\Policies\\{GUID}) with gpt.ini and the settings files. Clients read the first over LDAP and the second over **SMB (445)**.

:::practice
Q: Clients can read the list of GPOs, but processing fails reading gpt.ini. Which half of the GPO could not be read, and over which protocol?
A: The **Group Policy template** in SYSVOL, read over **SMB (445)**. The container half (read over LDAP) worked.
Q: Where is a GPO's version number stored?
A: In both halves: in the AD container object and in gpt.ini in SYSVOL. When they differ, SYSVOL replication is behind.
:::

### 2. Scope: links and OUs
A GPO does nothing until it is **linked** (gPLink) to a site, the domain or an OU. A computer gets the GPOs linked to the containers **above it**. Its location is its DN:
\`\`\`
CN=WIN01,OU=Servers,DC=ad,DC=corp,DC=lab   → domain links + OU=Servers links
CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab → domain links only (CN=Computers is not an OU)
\`\`\`
Joining without \`-OUPath\` leaves computers in CN=Computers: \`Move-ADObject\` (or \`Add-Computer -OUPath\`) puts them where their policy is.

:::practice
Q: A computer's DN is \`CN=PC22,OU=Sales,OU=Staff,DC=ad,DC=corp,DC=lab\`. Links on which containers can apply to it?
A: The domain, **OU=Staff** and **OU=Sales** (plus local policy and the site).
Q: A new server was joined without -OUPath. Which GPOs can it receive?
A: Only **domain-linked** ones: it sits in CN=Computers, which is not an OU and cannot have links.
:::

### 3. Order and precedence: LSDOU
Policy is applied **L**ocal, **S**ite, **D**omain, then each **O**U from the top down: later wins, so the closest OU has the last word. Within one container, link order 1 has the highest precedence. Two exceptions:
- **Block Inheritance** on an OU drops the links of the containers above it...
- ...except **Enforced** links, which pass Block Inheritance and win over everything below them.

\`Get-GPInheritance -Target OU\` shows the links that reach an OU, highest precedence first.

:::practice
Q: The domain GPO sets the screen lock to 10 minutes; a GPO on OU=Staff sets 5 minutes. A PC is in OU=Staff. Which value wins?
A: **5 minutes**: the OU is applied after the domain, and later wins.
Q: OU=Lab blocks inheritance. The domain has GPO A (normal link) and GPO B (enforced link). Which of them reach computers in OU=Lab?
A: Only **GPO B**: Block Inheritance drops A, but enforced links pass it.
:::

### 4. Security filtering and the computer's token
A GPO applies to a computer only if the computer has **Read and Apply** (GpoApply) on it, through any of its groups. By default Authenticated Users has Apply. To target a group: give the group GpoApply and lower Authenticated Users to **GpoRead** (do not remove it: since MS16-072 computers must be able to read every GPO, or it becomes "Inaccessible").

The computer's groups are taken from its **Kerberos ticket**, obtained when it starts. Adding a computer to a group takes effect at its **next restart** (or after purging its tickets: \`klist -li 0x3e7 purge\`): gpupdate alone keeps saying "Denied (Security)".

:::practice
Q: You removed Authenticated Users from a GPO's permissions entirely and gave Apply to one group. What happens on computers outside that group?
A: They cannot **read** the GPO, so it shows as "Inaccessible" (since MS16-072 computers must be able to read every GPO). Give Authenticated Users **GpoRead** instead of removing it.
Q: A computer was added to a filtering group. Without rebooting it, how can it get a ticket with the new group?
A: Purge the computer's tickets: \`klist -li 0x3e7 purge\`, then \`gpupdate /force\`.
:::

### 5. Processing and its failures
At startup, every ~90 minutes and on \`gpupdate\`:
| Step | Failure | Shows as |
|---|---|---|
| Find a DC (DNS SRV), bind (Kerberos) | DNS, network, KDC, clock, trust | event 1129, 1055, 1006; "lack of network connectivity", "could not resolve", "LDAP Bind" |
| Read the computer's DN and the gPLinks | wrong OU, disabled link, Block Inheritance | GPO not listed at all |
| Filtering | no Apply / no Read / disabled / empty | "Denied (Security)", "Inaccessible", "Disabled (GPO)", "Not Applied (Empty)" |
| Read gpt.ini, Registry.pol from SYSVOL | SMB 445 blocked, replication | event 1058 "attempted to read the file ... gpt.ini" |
| Apply | conflicts | gpresult precedence |

When processing fails, the settings of the last successful run stay in place. When a GPO **stops** applying (unlinked, filtered, moved out of scope), its registry policies and firewall rules are **removed** at the next processing.

:::practice
Q: A GPO that set a firewall rule was unlinked. What happens to the rule on the computers?
A: It is **removed** at their next processing, because the GPO no longer applies.
Q: Group Policy processing fails because the DC cannot be reached. Do the computers lose their policy settings?
A: **No.** The settings from the last successful run stay in place until processing works again.
:::

### 6. Reading gpresult
\`gpresult /r /scope computer\` shows the computer's DN, the DC that delivered policy, the **applied** GPOs (highest precedence first), the GPOs **filtered out** with the reason, and the computer's security groups (as of its last startup). That is usually enough to place the fault in one of the rows above.

:::practice
Q: In \`gpresult /r /scope computer\`, a GPO is listed under "filtered out" with "Denied (Security)". What does it tell you?
A: The GPO is in scope (linked above the computer), but **security filtering** excludes it: the computer's groups do not have Apply.
Q: A GPO you expect does not appear in gpresult at all, neither applied nor filtered. Where do you look?
A: At **scope**: the computer is in the wrong OU, the link is disabled, or Block Inheritance removes it.
:::

`,

  deployment: [
    {
      id: 'windows',
      platform: 'Windows Server 2022 (GroupPolicy module, GPMC)',
      summary: 'Create an OU for servers, a baseline GPO with a firewall rule, link it, move a member into the OU, and verify on the member. Steps marked simulated work in the sandbox (join win01 first).',
      prerequisites: ['A domain (dc01, ad.corp.lab) and a joined member (win01).', 'Domain Admins (or delegated GPO rights).'],
      steps: [
        { title: 'Create the OU', command: 'New-ADOrganizationalUnit -Name Servers -Path "DC=ad,DC=corp,DC=lab"', what: 'A place to link server policy.', why: 'CN=Computers cannot carry GPO links.', expected: '', simulated: true },
        { title: 'Create the GPO and its setting', command: 'New-GPO -Name "Server Baseline"\nNew-NetFirewallRule -PolicyStore "ad.corp.lab\\Server Baseline" -DisplayName "Monitoring - Echo Request (ICMPv4-In)" -Protocol ICMPv4 -IcmpType 8 -RemoteAddress 10.0.0.0/16 -Action Allow -Profile Domain', what: 'The rule is stored in the GPO, not on dc01.', why: 'Every server in the OU will receive it.', expected: 'DisplayName      : Server Baseline', simulated: true },
        { title: 'Link it', command: 'New-GPLink -Name "Server Baseline" -Target "OU=Servers,DC=ad,DC=corp,DC=lab"', what: 'Scope: the OU.', why: 'Unlinked GPOs do nothing.', expected: 'Enabled     : True', simulated: true },
        { title: 'Move the member into scope', command: 'Move-ADObject -Identity "CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab" -TargetPath "OU=Servers,DC=ad,DC=corp,DC=lab"', what: 'win01 now gets the OU\'s GPOs.', why: 'Joining put it in CN=Computers.', expected: '', simulated: true },
        { title: 'Verify on the member', command: 'gpupdate /force\ngpresult /r /scope computer\nGet-NetFirewallRule -PolicyStore RSOP', what: 'Process now and read the result.', why: 'Prove scope, filtering and download.', expected: 'Applied Group Policy Objects\n    -----------------------------\n        Server Baseline\n        Default Domain Policy', simulated: true },
      ],
    },
    {
      id: 'not-applicable',
      platform: 'Linux',
      summary: 'Linux has no Group Policy. Configuration management (Ansible, Puppet, Salt) plays the same role; sssd on domain-joined Linux can enforce GPO-based access control (ad_gpo_access_control) for logons only.',
      prerequisites: [],
      steps: [],
    },
  ],

  configIntro: `
Group Policy is configured on the DC (or any host with GPMC / the GroupPolicy module) and takes effect on members:
- **GPOs**: the settings.
- **Links** (domain, OU), their order, Enforced, and Block Inheritance on OUs: the scope.
- **Permissions**: security filtering.
- **Object placement** (OUs): which computers are in scope.
`,

  configFiles: [
    { platform: 'Domain controllers', items: [
      { path: '\\\\DOMAIN\\SYSVOL\\DOMAIN\\Policies\\{GUID}\\', purpose: 'GPO templates (gpt.ini, Machine\\Registry.pol, security templates).' },
      { path: 'CN=Policies,CN=System,DC=...', purpose: 'GPO containers in AD; gPLink attributes on the domain and OUs.' },
    ] },
    { platform: 'Members', items: [
      { path: 'HKLM\\SOFTWARE\\Policies\\', purpose: 'Registry policies written by Group Policy.' },
      { path: 'System log (GroupPolicy events)', purpose: 'Processing results.' },
    ] },
  ],

  directives: [
    { name: 'Link (domain / OU)', compiledDefault: 'Default Domain Policy on the domain; Default Domain Controllers Policy on OU=Domain Controllers', recommended: 'Link baselines to OUs that group machines by role', explanation: 'Decides which objects receive the GPO.', security: 'A domain-root link reaches every computer, including DCs.' },
    { name: 'Enforced', compiledDefault: 'No', recommended: 'Only for baselines that must reach everything', explanation: 'Passes Block Inheritance and wins conflicts below.', security: 'Use for security baselines that OU admins must not bypass.' },
    { name: 'Block Inheritance (OU)', compiledDefault: 'No', recommended: 'Rarely: prefer targeted links', explanation: 'Drops all non-enforced links from above.', security: 'Easily removes wanted baselines along with unwanted ones.' },
    { name: 'Security filtering', compiledDefault: 'Authenticated Users: Apply', recommended: 'Target group: Apply; Authenticated Users: Read', explanation: 'Who receives the GPO.', security: 'Removing Read for computers makes the GPO inaccessible (MS16-072).' },
    { name: 'GPO status', compiledDefault: 'All settings enabled', recommended: 'Disable the unused half only when sure', explanation: 'Computer/User Configuration processing on or off.', security: 'Disabling computer settings silently removes them from every member.' },
  ],

  operateIntro: `
### Before you change Group Policy
- Know the scope: \`Get-GPInheritance\` on the OUs involved, and which computers are in them.
- Test on one computer (\`gpupdate /force\`, \`gpresult /r\`) before linking to a wide OU.
- Group membership changes for computers need a restart; plan it.

:::practice
Q: You plan to link a new GPO to OU=Workstations with 600 PCs. What do you do first?
A: Check the **scope** (Get-GPInheritance, which computers are in the OU) and **test on one computer** (\`gpupdate /force\`, \`gpresult /r\`) before linking it widely.
Q: A filtering group was changed for 30 servers. Why do you need to plan restarts?
A: Computers take their group memberships from the Kerberos ticket obtained at **startup**; the change applies only after a restart (or a ticket purge).
:::

`,
  troubleshootingIntro: `
### Processing, scope, filtering, setting
A setting from a GPO reaches a computer only after four things succeed, in this order. Find the first one that fails.

1. **Processing: can the computer fetch policy at all?** Run \`gpupdate /force\` and read the System log. Event 1058 means it could not read SYSVOL (SMB to the DC); 1129 means it found no DC; 1055 means it got no Kerberos ticket; 1006 means its LDAP bind to the DC failed.
2. **Scope: is the GPO linked where this computer is?** \`gpresult /r\` shows the computer's place in the directory (its DN). \`Get-GPInheritance\` on its OU shows which GPOs are linked there, whether the OU blocks inheritance from above, and which links are enforced.
3. **Filtering: is the computer allowed to apply it?** \`gpresult /r\` lists "The following GPOs were not applied because they were filtered out", with the reason. \`Get-GPPermission -All\` shows who may apply the GPO. The computer's groups are the ones it had at its last restart.
4. **Setting: did the setting actually land?** \`Get-NetFirewallRule -PolicyStore RSOP\` shows firewall rules delivered by policy; the HKLM\\SOFTWARE\\Policies registry values show registry settings. If several GPOs set the same thing, precedence decides which one wins.

:::practice
Q: \`gpupdate /force\` logs event 1129. Which of the four steps failed, and what do you check?
A: Step 1, **processing**: the computer found **no DC**. Check its DNS servers and the SRV records, and network access to the DC.
Q: \`gpresult /r\` lists the GPO under "filtered out" with "Inaccessible". Which step, and what is the fix?
A: Step 3, **filtering**: the computer cannot even **read** the GPO. Give Authenticated Users (or Domain Computers) at least GpoRead.
:::

`,

  errorMap: [
    { message: 'Windows attempted to read the file \\\\ad.corp.lab\\sysvol\\ad.corp.lab\\Policies\\{...}\\gpt.ini from a domain controller and was not successful.', layer: 'SYSVOL (SMB)', meaning: 'The GPO\'s files could not be read: 445 blocked, replication, DNS for the domain name.', firstCheck: 'Test-NetConnection DC -Port 445; event 1058' },
    { message: 'The processing of Group Policy failed because of lack of network connectivity to a domain controller.', layer: 'DC location', meaning: 'No DC found or reachable (event 1129).', firstCheck: 'nltest /dsgetdc:ad.corp.lab; DNS settings' },
    { message: 'The processing of Group Policy failed. Windows could not resolve the computer name.', layer: 'Kerberos', meaning: 'The computer could not get a Kerberos ticket for LDAP on the DC (event 1055): the KDC (port 88, service Kdc) is not reachable.', firstCheck: 'klist -li 0x3e7 get krbtgt; Test-NetConnection dc01 -Port 88' },
    { message: 'Windows could not authenticate to the Active Directory service on a domain controller. (LDAP Bind function call failed)', layer: 'Secure channel / Kerberos', meaning: 'The computer account cannot bind (event 1006).', firstCheck: 'Test-ComputerSecureChannel; time skew' },
    { message: 'Filtering:  Denied (Security)', layer: 'Security filtering', meaning: 'The computer\'s groups have no Apply on the GPO (new memberships need a restart).', firstCheck: 'Get-GPPermission -All; gpresult security groups' },
    { message: 'Filtering:  Inaccessible', layer: 'Security filtering', meaning: 'The computer cannot even read the GPO.', firstCheck: 'Give Authenticated Users or Domain Computers GpoRead' },
    { message: 'Filtering:  Not Applied (Empty)', layer: 'GPO content', meaning: 'The GPO has no Computer Configuration settings.', firstCheck: 'The GPO\'s settings' },
  ],

  scenarioIds: ['gpo-wrong-ou', 'gpo-filter-token', 'gpo-blocked-inheritance', 'gpo-sysvol-blocked'],
  assessmentId: 'gpo',
  references: [
    { title: 'Microsoft Learn: Group Policy overview', url: 'https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview' },
    { title: 'Microsoft Learn: GroupPolicy PowerShell module', url: 'https://learn.microsoft.com/powershell/module/grouppolicy/' },
    { title: 'Microsoft Learn: gpresult', url: 'https://learn.microsoft.com/windows-server/administration/windows-commands/gpresult' },
    { title: 'Microsoft Learn: Group Policy processing and precedence', url: 'https://learn.microsoft.com/previous-versions/windows/desktop/policy/group-policy-hierarchy' },
    { title: 'MS16-072: security update for Group Policy (computers read GPOs)', url: 'https://support.microsoft.com/help/3163622' },
  ],
  guide: GPO_GUIDE,
};

// --- Primer -------------------------------------------------------------------------

export const GPO_PRIMER: Primer = {
  oneLiner: 'A **GPO** is a named set of settings; **linking** it to the domain or an **OU** makes every computer in that container apply it at startup and every 90 minutes. **gpresult** shows what applied and why something did not.',
  analogy: `
A company handbook with chapters. Head office (the domain) issues general rules; each department (an OU) adds its own chapter, and the department's chapter wins where they disagree. A chapter can be addressed "for the network team only" (security filtering), a department can refuse head office's chapters (Block Inheritance), except the ones marked mandatory (Enforced).

Staff only read the handbook of the department they sit in: someone still sitting in reception (CN=Computers) never gets the department's chapter, however many times they re-read it. And their badge, which lists their teams, is only reprinted when they come in in the morning (the computer's ticket at startup).`,
  ideas: [
    {
      title: 'Settings live in GPOs; links decide who gets them',
      explain: 'A GPO does nothing until it is linked to the domain or an OU. Computers get the GPOs linked above them.',
      example: '"Server Baseline" linked to OU=Servers reaches CN=WIN01,OU=Servers,... but not CN=WIN01,CN=Computers,....',
    },
    {
      title: 'Domain first, OU last; Block Inheritance and Enforced',
      explain: 'Policy is applied domain, then OUs top-down, so the closest OU wins. Block Inheritance drops what comes from above, except Enforced links.',
      example: 'OU=Servers blocks Workstation Lockdown from the domain root; the domain\'s Corp Security Baseline must then be Enforced to still reach the servers.',
    },
    {
      title: 'Security filtering uses the computer\'s groups from its last startup',
      explain: 'A GPO applies to a computer that can Read and Apply it. Group changes for computers count after a restart.',
      example: 'WIN01$ added to Baseline Servers: gpresult says "Denied (Security)" until win01 restarts.',
    },
    {
      title: 'Settings come from SYSVOL over SMB',
      explain: 'Members download each GPO\'s files from \\\\domain\\SYSVOL on a DC (TCP 445).',
      example: 'With SMB-In blocked on dc01, gpupdate fails with "attempted to read the file ... gpt.ini" (event 1058).',
    },
  ],
  walkthrough: {
    title: 'win01 gets the monitoring rule',
    steps: [
      { label: 'Link', detail: 'On dc01: New-GPO "Server Baseline", a firewall rule in it, New-GPLink to OU=Servers.' },
      { label: 'Scope', detail: 'Move-ADObject WIN01 from CN=Computers into OU=Servers.' },
      { label: 'Process', detail: 'gpupdate /force on win01: DC found, links read, Server Baseline allowed (Authenticated Users: Apply), files read from SYSVOL.' },
      { label: 'Apply', detail: 'The rule is added to win01\'s firewall (PolicyStoreSource ad.corp.lab\\Server Baseline).' },
      { label: 'Check', detail: 'gpresult /r lists Server Baseline; ws01 can ping win01.' },
    ],
  },
  misconceptions: [
    { myth: 'A GPO applies to computers in CN=Computers if it is linked to a server OU.', truth: 'Only to objects in (or below) the linked OU; CN=Computers is not an OU.' },
    { myth: 'gpupdate /force refreshes everything, including group memberships.', truth: 'The computer\'s groups come from its startup ticket: restart after group changes.' },
    { myth: 'To target a group, remove Authenticated Users from the GPO.', truth: 'Lower it to Read; without Read the GPO becomes inaccessible to computers.' },
    { myth: 'If logons work, Group Policy works.', truth: 'Policy also needs SYSVOL over SMB (445).' },
  ],
  checks: [
    { q: 'In which order are GPOs applied, and which wins?', a: 'Local, site, domain, OUs top-down (LSDOU); the last applied (closest OU) wins, except Enforced links.' },
    { q: 'A computer was added to the filter group but gpresult says Denied (Security). Why?', a: 'Its token still has the old groups: restart it.' },
    { q: 'Which port must members reach on the DC to download GPO settings?', a: 'TCP 445 (SMB, SYSVOL).' },
    { q: 'What does Block Inheritance not block?', a: 'Enforced links.' },
  ],
};

// --- Assessment -------------------------------------------------------------------------

export const GPO_ASSESSMENT: Assessment = {
  id: 'gpo',
  title: 'Group Policy knowledge check',
  questions: [
    {
      id: 'gpo-q-order',
      kind: 'order',
      level: 'beginner',
      learn: ['lesson/gpo/internals'],
      prompt: 'Order the containers in the sequence Group Policy applies them (the last one wins).',
      items: ['Local policy', 'Site', 'Domain', 'Parent OU', 'Child OU (where the computer is)'],
      concepts: ['ad.gpo'],
      explanation: 'LSDOU: local, site, domain, then OUs from the top down; Enforced links are the exception.',
    },
    {
      id: 'gpo-q-scope',
      kind: 'single',
      level: 'beginner',
      learn: ['lesson/gpo/internals'],
      prompt: 'gpresult on win01 shows "CN=WIN01,CN=Computers,DC=ad,DC=corp,DC=lab" and only Default Domain Policy. "Server Baseline" is linked to OU=Servers. What do you do?',
      options: [
        { text: 'Move WIN01 into OU=Servers (Move-ADObject), then gpupdate /force', correct: true },
        { text: 'Link Server Baseline to CN=Computers', misconception: 'Containers such as CN=Computers cannot carry GPO links.' },
        { text: 'Run gpupdate /force again', misconception: 'The GPO is not in scope; refreshing changes nothing.' },
        { text: 'Give WIN01$ GpoApply on the GPO', misconception: 'Filtering only matters for GPOs in scope.' },
      ],
      concepts: ['ad.gpo'],
      explanation: 'A computer gets the GPOs linked to the containers above it: move it into the OU.',
    },
    {
      id: 'gpo-q-token',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/gpo/internals'],
      prompt: 'A GPO is filtered to "Baseline Servers". WIN01$ was added to the group an hour ago; gpupdate /force runs fine but gpresult says "Denied (Security)". Why?',
      options: [
        { text: 'win01\'s Kerberos ticket, obtained at startup, does not contain the new group yet', correct: true },
        { text: 'The group change has not replicated', misconception: 'With one DC there is no replication; and gpresult shows the DC\'s answer.' },
        { text: 'GpoApply is not enough; the group needs GpoEdit', misconception: 'GpoApply (Read + Apply) is exactly what filtering needs.' },
      ],
      concepts: ['ad.gpo', 'ad.kerberos'],
      explanation: 'Restart the computer (or purge its tickets) to get a ticket with the new group.',
    },
    {
      id: 'gpo-q-sysvol',
      kind: 'single',
      level: 'intermediate',
      learn: ['lesson/gpo/internals'],
      prompt: 'gpupdate on members fails with "Windows attempted to read the file \\\\ad.corp.lab\\sysvol\\...\\gpt.ini ... not successful", while domain logons work. What is the likely cause?',
      options: [
        { text: 'Members cannot reach SMB (TCP 445) on the DC', correct: true },
        { text: 'DNS for the domain is broken', misconception: 'Logons and DC location work; the failure is reading a file.' },
        { text: 'The GPO is filtered', misconception: 'Filtering is shown in gpresult, not as a read error.' },
      ],
      concepts: ['ad.gpo', 'fw.path'],
      explanation: 'SYSVOL is an SMB share; event 1058 names the file that could not be read.',
    },
    {
      id: 'gpo-q-enforced',
      kind: 'single',
      level: 'advanced',
      learn: ['lesson/gpo/internals'],
      prompt: 'OU=Servers blocks inheritance to keep "Workstation Lockdown" (domain-linked) off servers. "Corp Security Baseline", also domain-linked, must still reach them. What is the right change?',
      options: [
        { text: 'Set the Corp Security Baseline link to Enforced', correct: true },
        { text: 'Remove Block Inheritance on OU=Servers', misconception: 'Workstation Lockdown would reach the servers again.' },
        { text: 'Unlink Workstation Lockdown', misconception: 'The workstations need it.' },
      ],
      concepts: ['ad.gpo'],
      explanation: 'Enforced links pass Block Inheritance.',
    },
    {
      id: 'gpo-q-filter',
      kind: 'multi',
      level: 'advanced',
      learn: ['lesson/gpo/internals'],
      prompt: 'You want a GPO to apply only to the computers in the group "Baseline Servers". Which permission changes are right? (choose all that apply)',
      options: [
        { text: 'Baseline Servers: GpoApply', correct: true },
        { text: 'Authenticated Users: GpoRead (instead of GpoApply)', correct: true },
        { text: 'Remove Authenticated Users entirely', misconception: 'Computers must keep Read on every GPO (MS16-072), or it becomes Inaccessible.' },
        { text: 'Baseline Servers: GpoEdit', misconception: 'Edit is for administrators; it does not make a GPO apply.' },
      ],
      concepts: ['ad.gpo'],
      explanation: 'Apply for the target, Read for everyone else.',
    },
  ],
};
